#!/usr/bin/env python3
"""Test d'acceptation ORM (T16) — SQLAlchemy contre l'extension tbp_pg.

Pourquoi ce test existe : les ORM parlent le protocole de requêtes
ÉTENDU (Parse/Bind/Execute) — le parse n'arrive qu'une fois avec des
placeholders, chaque exécution lie des valeurs concrètes. C'est le trou
que le hook unique ne voit pas (cf. README). Ce script vérifie, via
SQLAlchemy + psycopg2 :

1. monitor : la requête ORM passe, feuille would_deny + sceau récolté ;
2. enforce  : la MÊME requête ORM avec la MÊME valeur est admise une
   fois le sceau autorisé (D7) ;
3. enforce  : la même requête ORM avec une AUTRE valeur liée est
   bloquée (seal-unauthorized) — le cœur du critère ;
4. enforce  : une table hors liste blanche via l'ORM est bloquée au
   parse (structural-deny-table) ;
5. enforce  : une fonction volatile via l'ORM est bloquée au parse
   (structural-deny-function).

Variables d'environnement :
    TBP_SOCK    répertoire du socket unix de l'instance de test
    TBP_PORT    port de l'instance
    TBP_LOG     journal PostgreSQL (récolte des sceaux)
    TBP_BINDIR  bin PostgreSQL (pg_ctl reload)
    TBP_DATA    datadir de l'instance (pg_ctl reload)

Sortie non nulle si un scénario échoue.
"""

import os
import re
import subprocess
import sys
import time

from sqlalchemy import Column, Integer, String, create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

SOCK = os.environ["TBP_SOCK"]
PORT = os.environ["TBP_PORT"]
LOG = os.environ["TBP_LOG"]
BINDIR = os.environ["TBP_BINDIR"]
DATA = os.environ["TBP_DATA"]

engine = create_engine(
    f"postgresql+psycopg2://tbp@/postgres?host={SOCK}&port={PORT}",
    poolclass=None,  # pas de pool : chaque test maîtrise sa session
)
Session = sessionmaker(bind=engine)
Base = declarative_base()


class Doc(Base):
    __tablename__ = "docs"
    id = Column(Integer, primary_key=True)
    val = Column(String)


class Secret(Base):
    __tablename__ = "secrets"
    id = Column(Integer, primary_key=True)
    val = Column(String)


failures = []


def ok(msg):
    print(f"ok: {msg}")


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    failures.append(msg)


def reload_conf(guc, expected):
    """ALTER SYSTEM a déjà été joué ; on recharge et on SONDE la bascule
    (pg_reload_conf() serait refusée par le hook 1 dès enforce=on)."""
    subprocess.run([f"{BINDIR}/pg_ctl", "-D", DATA, "reload"],
                   check=True, capture_output=True)
    for _ in range(50):
        with engine.connect() as c:
            got = c.execute(text(f"SHOW {guc};")).scalar()
        if got == expected:
            return
        time.sleep(0.1)
    fail(f"reload_conf: {guc} ne bascule pas vers « {expected} »")


def alter_system(stmt):
    """ALTER SYSTEM refuse tout bloc transactionnel : connexion AUTOCOMMIT
    dédiée (psycopg2 transactionne par défaut)."""
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
        c.execute(text(stmt))


def setup():
    with engine.begin() as c:
        c.execute(text(
            "CREATE TABLE IF NOT EXISTS docs(id int PRIMARY KEY, val text);"))
        c.execute(text(
            "CREATE TABLE IF NOT EXISTS secrets(id int PRIMARY KEY, val text);"))
        c.execute(text(
            "INSERT INTO docs VALUES (1,'alpha'),(2,'beta') ON CONFLICT DO NOTHING;"))
        c.execute(text(
            "INSERT INTO secrets VALUES (1,'s3cr3t') ON CONFLICT DO NOTHING;"))
        c.execute(text(
            "CREATE OR REPLACE FUNCTION side_effect() RETURNS int "
            "LANGUAGE sql VOLATILE AS $$ SELECT 1 $$;"))
    for stmt in (
        "ALTER SYSTEM SET tbp.allowed_commands = 'SELECT';",
        "ALTER SYSTEM SET tbp.allowed_tables = 'public.docs';",
        "ALTER SYSTEM SET tbp.cell_id = 'tbp/registry/cell-alpha-01';",
        "ALTER SYSTEM SET tbp.enforce = off;",
    ):
        alter_system(stmt)
    reload_conf("tbp.enforce", "off")
    reload_conf("tbp.allowed_commands", "SELECT")


def harvest_seal():
    """Dernier sceau seal-unauthorized du journal (feuilles hash-only)."""
    pat = re.compile(r'"phase":"exec".*"reason":"seal-unauthorized".*'
                     r'"seal":"([0-9a-f]{64})"')
    seal = None
    with open(LOG, encoding="utf-8") as f:
        for line in f:
            m = pat.search(line)
            if m:
                seal = m.group(1)
    return seal


def main():
    setup()

    # --- 1. monitor : l'ORM passe, le sceau est récolté ---------------------
    s = Session()
    rows = s.query(Doc).filter(Doc.id == 1).all()
    if [(r.id, r.val) for r in rows] != [(1, "alpha")]:
        fail(f"monitor: requête ORM bloquée ou fausse: {rows!r}")
        return
    seal1 = harvest_seal()
    if not seal1:
        fail("monitor: aucun sceau récolté dans le journal")
        return
    ok(f"ORM monitor: SELECT via SQLAlchemy forwardé, sceau {seal1[:16]}… récolté")
    s.close()

    with engine.begin() as c:
        c.execute(text("SELECT tbp_authorize(:s);"), {"s": seal1})
    alter_system("ALTER SYSTEM SET tbp.enforce = on;")
    reload_conf("tbp.enforce", "on")

    # --- 2. enforce : même requête ORM, même valeur ⇒ admise -----------------
    s = Session()
    rows = s.query(Doc).filter(Doc.id == 1).all()
    if [(r.id, r.val) for r in rows] != [(1, "alpha")]:
        fail(f"enforce: requête ORM autorisée refusée: {rows!r}")
    else:
        ok("ORM enforce: requête autorisée (même valeur liée) admise")
    s.close()

    # --- 3. enforce : même requête ORM, AUTRE valeur liée ⇒ bloquée ----------
    s = Session()
    try:
        s.query(Doc).filter(Doc.id == 2).all()
        fail("enforce: valeur liée hostile acceptée par l'ORM")
    except Exception as e:  # ProgrammingError psycopg2 wrappée
        if "seal-unauthorized" in str(e):
            ok("CRITÈRE (ORM): même requête, valeur liée hostile ⇒ bloquée "
               "(seal-unauthorized)")
        else:
            fail(f"refus inattendu: {e}")
    finally:
        s.rollback()
        s.close()

    # --- 4. enforce : table hors liste blanche via l'ORM ⇒ parse --------------
    s = Session()
    try:
        s.query(Secret).all()
        fail("enforce: table hors liste blanche acceptée par l'ORM")
    except Exception as e:
        if "structural-deny-table" in str(e):
            ok("ORM: table hors liste blanche bloquée au parse")
        else:
            fail(f"refus table inattendu: {e}")
    finally:
        s.rollback()
        s.close()

    # --- 5. enforce : fonction volatile via l'ORM ⇒ parse ---------------------
    s = Session()
    try:
        s.execute(text("SELECT side_effect();")).all()
        fail("enforce: fonction volatile acceptée")
    except Exception as e:
        if "structural-deny-function" in str(e):
            ok("ORM: fonction volatile bloquée au parse (hook 1)")
        else:
            fail(f"refus fonction inattendu: {e}")
    finally:
        s.rollback()
        s.close()

    if failures:
        sys.exit(1)
    print("SCÉNARIO ORM SQLALCHEMY: TOUS LES CONTRÔLES PASSENT")


if __name__ == "__main__":
    main()
