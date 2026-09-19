# Scénario 3 de l'issue #20 : ORM réel (SQLAlchemy, psycopg2) + recette de
# provisionnement des requêtes maison du pilote — dès la CONNEXION, le
# dialecte émet ses sondes (version, standard_conforming_strings, détection
# hstore → pg_catalog.pg_type / pg_namespace). En mode closed elles sont
# soumises à la même politique (fail-closed voulu, §1) : la recette
# « monitor → récolte → autorisation → enforce » est le provisionnement.
import pytest

sqlalchemy = pytest.importorskip("sqlalchemy",
                                 reason="SQLAlchemy requis (pip install sqlalchemy)")
from sqlalchemy import create_engine, text  # noqa: E402

BALANCES_Q = "SELECT id, balance FROM accounts ORDER BY id"


def engine_for(pg):
    return create_engine(
        f"postgresql+psycopg2://tbp@/postgres?host={pg.sock}&port={pg.port}")


def test_sqlalchemy_session_and_driver_housekeeping(pg):
    """Cycle complet : la même politique gouverne les sondes du pilote ET
    les requêtes métier — connexion refusée sans provisionnement, admise
    après, requête déviante bloquée avec feuille."""
    # 1.+2. passes monitor + provisionnement itératif (le hook 1 s'arrête
    # au premier refus : une passe ne révèle qu'une entrée manquante)
    captured = {}

    def exercise():
        eng = engine_for(pg)
        with eng.connect() as conn:
            captured["rows"] = conn.execute(text(BALANCES_Q)).all()
        eng.dispose()

    tables, functions, seals = pg.provision_driver(exercise)
    rows = captured["rows"]
    assert rows == pg.sql(BALANCES_Q), "l'ORM et la connexion directe divergent"
    assert "pg_catalog.pg_type" in tables, \
        "la sonde hstore du pilote devrait avoir touché pg_catalog.pg_type"
    assert "version" in functions, \
        "la sonde version() (STABLE) du pilote devrait être provisionnée"
    assert seals, "aucun sceau récolté pendant la passe monitor"

    # 3. sanity check : SANS provisionnement la connexion serait refusée —
    #    démontré en retirant temporairement les listes du hook 1.
    prov_tables = pg.sql("SHOW tbp.allowed_tables;")[0][0]
    prov_functions = pg.sql("SHOW tbp.allowed_functions;")[0][0]
    pg.set_guc("tbp.enforce", "on")
    pg.set_guc("tbp.allowed_tables", "public.accounts,public.fx_log")
    pg.set_guc("tbp.allowed_functions", "")
    try:
        with pytest.raises(Exception, match="TBP: refus structurel"):
            eng = engine_for(pg)
            with eng.connect():
                pass
    finally:
        pg.set_guc("tbp.enforce", "off")
        pg.set_guc("tbp.allowed_tables", prov_tables)
        pg.set_guc("tbp.allowed_functions", prov_functions)

    # 4. mode closed provisionné : connexion OK, métier OK, déviant bloqué
    pg.set_guc("tbp.enforce", "on")
    try:
        eng = engine_for(pg)
        with eng.connect() as conn:
            assert conn.execute(text(BALANCES_Q)).all() == rows
            # requête déviante : autre valeur liée, sceau jamais autorisé
            m2 = pg.mark()
            with pytest.raises(Exception, match="sceau de plan non autorisé"):
                conn.execute(
                    text("UPDATE accounts SET balance = :b WHERE id = :i"),
                    {"b": -1, "i": 2})
            pg.assert_leaf(m2, "exec", "seal-unauthorized", cmd="UPDATE")
            conn.rollback()  # la transaction est avortée par le refus
            # table hors liste blanche via l'ORM : refus structurel + feuille
            m3 = pg.mark()
            with pytest.raises(Exception, match="structural-deny-table"):
                conn.execute(text("SELECT * FROM secrets"))
            pg.assert_leaf(m3, "parse", "structural-deny-table")
            conn.rollback()
            # fonction volatile via l'ORM : refus au parse + feuille
            m4 = pg.mark()
            with pytest.raises(Exception, match="structural-deny-function"):
                conn.execute(text("SELECT side_effect()"))
            pg.assert_leaf(m4, "parse", "structural-deny-function")
            conn.rollback()
            # intégrité : rien n'a bougé
            assert conn.execute(text(BALANCES_Q)).all() == rows
        eng.dispose()
    finally:
        pg.set_guc("tbp.enforce", "off")
        pg.set_guc("tbp.allowed_tables", "public.accounts,public.fx_log")
        pg.set_guc("tbp.allowed_functions", "")
