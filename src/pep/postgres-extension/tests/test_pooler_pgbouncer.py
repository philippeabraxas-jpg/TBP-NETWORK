# Scénarios pooler de l'issue #20 : l'extension derrière pgbouncer.
#
# D9 — derrière un pooler, le canal d'autorisation légitime est le cache de
# décision partagé (D7, mémoire partagée de l'instance), PAS le sceau
# présenté : tbp_present_seal pose sa capacité PAR BACKEND PostgreSQL
# (object-capability §4.4(2), usage unique). En pool_mode=session, le client
# garde son backend : la présentation fonctionne. En pool_mode=transaction,
# chaque transaction peut toucher un backend différent : le sceau présenté
# ne traverse PAS — fail-closed, feuille écrite — tandis que le cache D7
# sert tous les backends indifféremment. Ces tests le DÉMONTRENT, ils ne le
# contournent pas.
import os
import shutil
import signal
import subprocess
import time

import psycopg2
import pytest

PGB = os.environ.get("TBP_PGBOUNCER")
PGB_LIB = os.environ.get("TBP_PGB_LIB", "")
BASE_PORT = int(os.environ.get("TBP_TEST_PORT", "55444"))

pytestmark = pytest.mark.skipif(
    not PGB or not os.path.exists(PGB),
    reason="TBP_PGBOUNCER non fourni — scénarios pooler sautés (docker-compose "
           "ou paquet pgbouncer de la distribution)")


class Bouncer:
    def __init__(self, work, port):
        self.work = str(work)
        self.port = port

    def connect(self, autocommit=True):
        conn = psycopg2.connect(host="127.0.0.1", port=self.port,
                                user="tbp", dbname="tbp")
        conn.autocommit = autocommit
        return conn

    def stop(self):
        with open(os.path.join(self.work, "pgbouncer.pid")) as fh:
            os.kill(int(fh.read().strip()), signal.SIGTERM)


def make_bouncer(pg, work, pool_mode, port):
    work = str(work)
    userlist = os.path.join(work, "userlist.txt")
    with open(userlist, "w") as fh:
        fh.write('"tbp" ""\n')
    ini = os.path.join(work, "pgbouncer.ini")
    with open(ini, "w") as fh:
        fh.write(f"""\
[databases]
tbp = host={pg.sock} port={pg.port} dbname=postgres

[pgbouncer]
pool_mode = {pool_mode}
listen_addr = 127.0.0.1
listen_port = {port}
unix_socket_dir = {work}
auth_type = trust
auth_file = {userlist}
admin_users = tbp
default_pool_size = 3
max_client_conn = 50
logfile = {work}/pgbouncer.log
pidfile = {work}/pgbouncer.pid
""")
    env = dict(os.environ)
    if PGB_LIB:
        env["LD_LIBRARY_PATH"] = PGB_LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    subprocess.run([PGB, "-d", ini], check=True, env=env)
    deadline = time.time() + 15
    while True:
        try:
            conn = psycopg2.connect(host="127.0.0.1", port=port, user="tbp",
                                    dbname="tbp", connect_timeout=2)
            conn.close()
            break
        except Exception:
            if time.time() > deadline:
                raise RuntimeError(f"pgbouncer ({pool_mode}) ne démarre pas — "
                                   f"voir {work}/pgbouncer.log")
            time.sleep(0.2)
    return Bouncer(work, port)


@pytest.fixture(scope="module")
def bouncer_session(pg, tmp_path_factory):
    b = make_bouncer(pg, tmp_path_factory.mktemp("pgb_sess"),
                     "session", BASE_PORT + 10)
    yield b
    b.stop()


@pytest.fixture(scope="module")
def bouncer_tx(pg, tmp_path_factory):
    b = make_bouncer(pg, tmp_path_factory.mktemp("pgb_tx"),
                     "transaction", BASE_PORT + 11)
    yield b
    b.stop()


def _warm_pool(b, n=3):
    """Force pgbouncer à ouvrir n connexions serveur (idle, réutilisables)."""
    for _ in range(n):
        conn = b.connect()
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        conn.close()


def test_presented_seal_works_in_session_mode(pg, bouncer_session):
    """pool_mode=session : le client garde son backend — présentation +
    exécution dans la même session empruntée, capacité à usage unique."""
    q = "SELECT balance FROM accounts WHERE id = 1"
    m = pg.mark()
    expected = pg.sql(q)[0][0]
    seal = pg.seals(m)[-1]          # récolté, NON autorisé au cache
    pg.set_guc("tbp.enforce", "on")
    try:
        conn = bouncer_session.connect()
        with conn.cursor() as cur:
            cur.execute("SELECT tbp_present_seal(%s);", (seal,))
            cur.execute(q)
            assert cur.fetchall()[0][0] == expected
            # usage unique : rejouer sans re-présenter ⇒ bloqué + feuille
            m2 = pg.mark()
            with pytest.raises(psycopg2.errors.InsufficientPrivilege,
                               match="sceau de plan non autorisé"):
                cur.execute(q)
        conn.close()
        pg.assert_leaf(m2, "exec", "seal-unauthorized", cmd="SELECT")
    finally:
        pg.set_guc("tbp.enforce", "off")


def test_presented_seal_does_not_cross_backends_in_transaction_mode(pg, bouncer_tx):
    """pool_mode=transaction : le sceau présenté vit sur UN backend. Un autre
    backend refuse (fail-closed + feuille) ; le backend détenteur accepte une
    fois. Démonstration orchestrée : identifier le backend (pg_backend_pid),
    le monopoliser en transaction ouverte, exécuter depuis un autre."""
    q = "SELECT balance FROM accounts WHERE id = 2"
    m = pg.mark()
    expected = pg.sql(q)[0][0]
    seal = pg.seals(m)[-1]          # NON autorisé au cache : canal présenté seul
    # pg_backend_pid (STABLE) sert à identifier les backends : liste blanche
    # explicite, comme toute fonction non immuable (hook 1).
    pg.set_guc("tbp.allowed_functions", "pg_backend_pid")
    pg.set_guc("tbp.enforce", "on")
    try:
        _warm_pool(bouncer_tx)
        # présentation (transaction courte : on sait sur quel backend on est)
        conn_p = bouncer_tx.connect(autocommit=False)
        with conn_p.cursor() as cur:
            cur.execute("SELECT pg_backend_pid();")
            pid_p = cur.fetchall()[0][0]
            cur.execute("SELECT tbp_present_seal(%s);", (seal,))
        conn_p.commit()             # backend relâché, sceau posé sur pid_p
        # pgbouncer réutilise la connexion serveur la plus récente : la
        # prochaine session hérite de pid_p — on le MONOPOLISE.
        conn_q = bouncer_tx.connect(autocommit=False)
        with conn_q.cursor() as cur:
            cur.execute("SELECT pg_backend_pid();")
            pid_q = cur.fetchall()[0][0]
        assert pid_q == pid_p, "hypothèse de réutilisation LIFO du pooler non vérifiée"
        # un AUTRE backend exécute la requête scellée : le sceau n'y est pas.
        conn_r = bouncer_tx.connect(autocommit=False)
        m2 = pg.mark()
        with conn_r.cursor() as cur:
            cur.execute("SELECT pg_backend_pid();")
            pid_r = cur.fetchall()[0][0]
            assert pid_r != pid_p
            with pytest.raises(psycopg2.errors.InsufficientPrivilege,
                               match="sceau de plan non autorisé"):
                cur.execute(q)
        conn_r.rollback()
        pg.assert_leaf(m2, "exec", "seal-unauthorized", cmd="SELECT")
        # le backend détenteur (pid_p, tenu par conn_q) : admis UNE fois.
        with conn_q.cursor() as cur:
            cur.execute(q)
            assert cur.fetchall()[0][0] == expected
            with pytest.raises(psycopg2.errors.InsufficientPrivilege,
                               match="sceau de plan non autorisé"):
                cur.execute(q)
        conn_q.rollback()
        for conn in (conn_p, conn_q, conn_r):
            conn.close()
    finally:
        pg.set_guc("tbp.enforce", "off")
        pg.set_guc("tbp.allowed_functions", "")


def test_authorized_seal_crosses_backends_in_transaction_mode(pg, bouncer_tx):
    """Le cache de décision D7 est en mémoire partagée de l'instance : un
    sceau autorisé UNE fois (depuis une connexion directe, hors pooler) est
    servi par TOUS les backends du pool — c'est le canal légitime derrière
    un pooler en mode transaction."""
    q = "SELECT balance FROM accounts WHERE id = 1"
    m = pg.mark()
    expected = pg.sql(q)[0][0]
    pg.authorize_new_seals(m)
    pg.set_guc("tbp.allowed_functions", "pg_backend_pid")
    pg.set_guc("tbp.enforce", "on")
    try:
        _warm_pool(bouncer_tx)
        conns, pids = [], set()
        for _ in range(3):
            conn = bouncer_tx.connect(autocommit=False)
            with conn.cursor() as cur:
                cur.execute("SELECT pg_backend_pid();")
                pids.add(cur.fetchall()[0][0])
                cur.execute(q)
                assert cur.fetchall()[0][0] == expected
            conns.append(conn)      # transactions ouvertes : backend retenu
        assert len(pids) == 3, \
            "les 3 connexions devraient tenir 3 backends distincts du pool"
        for conn in conns:
            conn.rollback()
            conn.close()
    finally:
        pg.set_guc("tbp.enforce", "off")
        pg.set_guc("tbp.allowed_functions", "")


def test_sqlalchemy_through_transaction_pooler(pg, bouncer_tx):
    """Housekeeping du pilote À TRAVERS le pooler en mode closed : la recette
    de provisionnement (monitor → récolte → autorisation) s'applique à
    l'identique — connexion, sondes et requêtes métier sous la même politique."""
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from sqlalchemy import create_engine, text

    bal = "SELECT id, balance FROM accounts ORDER BY id"

    def engine():
        return create_engine(
            f"postgresql+psycopg2://tbp@127.0.0.1:{bouncer_tx.port}/tbp")

    captured = {}

    def exercise():
        eng = engine()
        with eng.connect() as conn:
            captured["rows"] = conn.execute(text(bal)).all()
        eng.dispose()

    pg.provision_driver(exercise)       # recette partagée (conftest)
    rows = captured["rows"]
    pg.set_guc("tbp.enforce", "on")
    try:
        eng = engine()
        with eng.connect() as conn:
            assert conn.execute(text(bal)).all() == rows
            m2 = pg.mark()
            with pytest.raises(Exception, match="sceau de plan non autorisé"):
                conn.execute(
                    text("UPDATE accounts SET balance = :b WHERE id = :i"),
                    {"b": -1, "i": 2})
            conn.rollback()
        eng.dispose()
        pg.assert_leaf(m2, "exec", "seal-unauthorized", cmd="UPDATE")
    finally:
        pg.set_guc("tbp.enforce", "off")
        pg.set_guc("tbp.allowed_tables", "public.accounts,public.fx_log")
        pg.set_guc("tbp.allowed_functions", "")
