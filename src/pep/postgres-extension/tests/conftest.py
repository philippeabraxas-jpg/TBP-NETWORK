# Fixtures T17 — instance PostgreSQL 15 jetable + extension tbp_pg préchargée.
#
# Recette T16 : initdb + shared_preload_libraries, GUC via ALTER SYSTEM +
# pg_ctl reload (pg_reload_conf() serait elle-même refusée par le hook 1 —
# fonction volatile — dès que tbp.enforce=on ; la politique ne doit pas se
# mordre la queue).
#
# Doctrine (tests/p2_redteam/README.md) : un blocage qui ne laisse pas de
# feuille vérifiable n'a rien prouvé — chaque helper de blocage asserte la
# ligne TBP_LEAF correspondante (JSON parsé, sceau inclus).
#
# Lancement :
#   TBP_PG_CONFIG=/chemin/pg_config python3 -m pytest tests/
# Variables d'environnement :
#   TBP_PG_CONFIG   pg_config du PostgreSQL 15 cible (défaut : pg_config)
#   TBP_TEST_PORT   port de l'instance jetable (défaut : 55444)
#   TBP_PGBOUNCER   chemin du binaire pgbouncer (sinon : scénarios pooler
#                   sautés avec un message explicite)
#   TBP_PGB_LIB     LD_LIBRARY_PATH pour pgbouncer (dépendances extraites)
import json
import os
import re
import subprocess
import time

import psycopg2
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PG_CONFIG = os.environ.get("TBP_PG_CONFIG", "pg_config")
BASE_PORT = int(os.environ.get("TBP_TEST_PORT", "55444"))


def _pg_config(opt):
    return subprocess.check_output([PG_CONFIG, opt], text=True).strip()


BINDIR = _pg_config("--bindir")
PKGLIBDIR = _pg_config("--pkglibdir")
VERSION = subprocess.check_output(
    [os.path.join(BINDIR, "postgres"), "--version"], text=True).strip()

if " 15." not in VERSION:
    pytest.exit(f"T17 épingle PostgreSQL 15 (D3) — trouvé : {VERSION}",
                returncode=2)

LEAF_RE = re.compile(r"TBP_LEAF (\{.*\})")


class Pg:
    """Instance jetable + accès aux feuilles du journal."""

    def __init__(self, work):
        self.work = str(work)
        self.data = os.path.join(self.work, "data")
        self.sock = os.path.join(self.work, "sock")
        self.port = BASE_PORT
        self.log = os.path.join(self.work, "pg.log")

    # -- connexions ---------------------------------------------------------
    def connect(self, autocommit=True, host=None, port=None, dbname="postgres"):
        conn = psycopg2.connect(host=host or self.sock,
                                port=port or self.port,
                                user="tbp", dbname=dbname)
        conn.autocommit = autocommit
        return conn

    def sql(self, query, params=None):
        """Exécute en autocommit ; retourne les lignes ou lève l'erreur."""
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall() if cur.description else []
        finally:
            conn.close()

    # -- feuilles (§4.1) ------------------------------------------------------
    def mark(self):
        """Position courante du journal (octets)."""
        return os.path.getsize(self.log)

    def leaves(self, since=0):
        """Feuilles TBP_LEAF apparues après l'octet `since`, JSON parsé."""
        with open(self.log, "rb") as fh:
            fh.seek(since)
            chunk = fh.read().decode("utf-8", "replace")
        return [json.loads(m.group(1)) for m in LEAF_RE.finditer(chunk)]

    def seals(self, since=0, phase="exec", reason="seal-unauthorized"):
        """Sceaux (uniques, ordre d'apparition) des feuilles filtrées."""
        out = []
        for leaf in self.leaves(since):
            if (leaf.get("phase") == phase and leaf.get("reason") == reason
                    and leaf.get("seal") and leaf["seal"] not in out):
                out.append(leaf["seal"])
        return out

    def assert_leaf(self, since, phase, reason, seal=None, cmd=None):
        """Prouve qu'une feuille postérieure à `since` existe avec ces
        champs exacts — un blocage sans feuille n'a rien prouvé."""
        for leaf in self.leaves(since):
            if (leaf.get("phase") == phase and leaf.get("reason") == reason
                    and (seal is None or leaf.get("seal") == seal)
                    and (cmd is None or leaf.get("cmd") == cmd)):
                return leaf
        raise AssertionError(
            f"pas de feuille phase={phase} reason={reason} seal={seal} "
            f"après l'octet {since} — action dangereuse non tracée (§4.1)")

    # -- gouvernance ----------------------------------------------------------
    def alter_system(self, guc, value):
        self.sql(f"ALTER SYSTEM SET {guc} = '{value}';")

    def reload_conf(self, guc, expected):
        """SIGHUP hors SQL + sondage jusqu'à bascule effective."""
        subprocess.run([os.path.join(BINDIR, "pg_ctl"), "-D", self.data,
                        "reload"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if self.sql(f"SHOW {guc};")[0][0] == expected:
                return
            time.sleep(0.1)
        raise AssertionError(f"{guc} ne bascule pas vers « {expected} »")

    def set_guc(self, guc, value):
        self.alter_system(guc, value)
        self.reload_conf(guc, value)

    def authorize(self, seal):
        assert self.sql("SELECT tbp_authorize(%s);", (seal,))[0][0]

    def provision_driver(self, exercise, rounds=4):
        """Recette de provisionnement pilote/ORM (§5.3 : monitor d'abord).

        `exercise()` = le flux complet du pilote (connexion + sondes +
        requête métier), joué en mode monitor. Le walker du hook 1 s'arrête
        au PREMIER refus structurel : chaque passe ne révèle que la table ou
        la fonction manquante suivante — d'où la boucle, jusqu'à convergence
        (une passe sans nouveau refus). Les sceaux des plans refusés sont
        autorisés au cache D7 à chaque passe (idempotent).

        Retourne (tables, fonctions, sceaux) provisionnés — à asserter."""
        tables, functions, seals = set(), set(), []
        for _ in range(rounds):
            since = self.mark()
            exercise()
            new_t, new_f = set(), set()
            for leaf in self.leaves(since):
                if leaf["phase"] == "parse" and leaf["would_deny"]:
                    if leaf["reason"] == "structural-deny-table":
                        new_t.update(leaf["tables"])
                    elif leaf["reason"] == "structural-deny-function":
                        m = re.search(r"fonction (\w+) non immuable",
                                      leaf.get("detail", ""))
                        if m:
                            new_f.add(m.group(1))
            for seal in self.seals(since):
                if seal not in seals:
                    self.authorize(seal)
                    seals.append(seal)
            if not (new_t - tables) and not (new_f - functions):
                break
            tables |= new_t
            functions |= new_f
            if new_t:
                base = self.sql("SHOW tbp.allowed_tables;")[0][0]
                self.set_guc("tbp.allowed_tables",
                             ",".join(filter(None, [base] + sorted(new_t))))
            if new_f:
                base = self.sql("SHOW tbp.allowed_functions;")[0][0]
                self.set_guc("tbp.allowed_functions",
                             ",".join(filter(None, [base] + sorted(new_f))))
        return sorted(tables), sorted(functions), seals

    def authorize_new_seals(self, since, **flt):
        """Cycle monitor → autorisation : retourne les sceaux autorisés."""
        seals = self.seals(since, **flt)
        assert seals, "aucun sceau à récolter (la passe monitor n'a rien tracé ?)"
        for seal in seals:
            self.authorize(seal)
        return seals


@pytest.fixture(scope="session")
def pg(tmp_path_factory):
    work = tmp_path_factory.mktemp("tbp_pg_t17")
    inst = Pg(work)
    os.makedirs(inst.sock)
    subprocess.run([os.path.join(BINDIR, "initdb"), "-D", inst.data,
                    "--no-locale", "-E", "UTF8", "-U", "tbp"],
                   check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    with open(os.path.join(inst.data, "postgresql.conf"), "a") as fh:
        fh.write("shared_preload_libraries = 'tbp_pg'\n"
                 f"dynamic_library_path = '{PKGLIBDIR}'\n"
                 "log_min_messages = log\n"
                 "log_line_prefix = ''\n")
    subprocess.run([os.path.join(BINDIR, "pg_ctl"), "-D", inst.data,
                    "-l", inst.log,
                    "-o", f"-k {inst.sock} -p {inst.port} -c listen_addresses=''",
                    "-w", "start"],
                   check=True, stdout=subprocess.DEVNULL)
    try:
        # Fonctions SQL de l'extension (chemin explicite : pas besoin du
        # .control dans un sharedir jetable).
        with open(os.path.join(HERE, "..", "sql", "tbp_pg--0.1.sql")) as fh:
            ddl = fh.read().replace("'MODULE_PATHNAME'",
                                    f"'{PKGLIBDIR}/tbp_pg.so'")
        conn = inst.connect()
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.close()

        # Schéma de test : comptes (scénario PREPARE/EXECUTE), secrets
        # (table interdite), fx_log (preuve d'absence d'effet de bord),
        # fonction volatile à effet de bord (PostgreSQL interdit de toute
        # façon le DML dans une fonction non volatile — vérifié : le mensonge
        # IMMUTABLE n'existe pas pour le DML ; le wrapper volatile, si).
        inst.sql("""
            CREATE TABLE accounts(id int PRIMARY KEY, balance int, owner text);
            INSERT INTO accounts VALUES (1, 100, 'alice'), (2, 200, 'bob');
            CREATE TABLE secrets(id int PRIMARY KEY, val text);
            INSERT INTO secrets VALUES (1, 's3cr3t');
            CREATE TABLE fx_log(mark text);
            CREATE FUNCTION side_effect() RETURNS int LANGUAGE sql VOLATILE
                AS $$ INSERT INTO fx_log VALUES ('volatile-hit'); SELECT 1 $$;
        """)
        # Politique de base : SELECT+UPDATE sur accounts et fx_log (fx_log
        # sert à PROUVER l'absence d'effet de bord — il faut pouvoir le
        # relire en mode closed).
        inst.set_guc("tbp.allowed_commands", "SELECT,UPDATE")
        inst.set_guc("tbp.allowed_tables", "public.accounts,public.fx_log")
        inst.set_guc("tbp.cell_id", "tbp/registry/cell-alpha-01")
        yield inst
    finally:
        subprocess.run([os.path.join(BINDIR, "pg_ctl"), "-D", inst.data,
                        "-m", "immediate", "stop"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.fixture()
def enforce_on(pg):
    """Mode closed pour la durée du test, retour monitor à la sortie (§5.3)."""
    pg.set_guc("tbp.enforce", "on")
    yield pg
    pg.set_guc("tbp.enforce", "off")
