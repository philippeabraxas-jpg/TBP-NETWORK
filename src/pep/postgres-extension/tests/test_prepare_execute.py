# Scénarios 1 et 2 de l'issue #20 : le trou du hook unique (PREPARE/EXECUTE
# à valeur liée hostile) et la fonction volatile à effet de bord — chaque
# blocage prouvé par sa feuille registre (§4.1), jamais par la seule erreur.
import json
import os

import psycopg2
import pytest

UPDATE_Q = "UPDATE accounts SET balance = $1 WHERE id = $2"
BALANCES_Q = "SELECT id, balance FROM accounts ORDER BY id"
COUNT_FX_Q = "SELECT count(*) FROM fx_log"


@pytest.fixture(scope="module", autouse=True)
def control_seals(pg):
    """Autorise une fois (monitor) les sceaux des requêtes de CONTRÔLE —
    relire l'état sous enforce est soi-même soumis au sceau (§4.4)."""
    m = pg.mark()
    pg.sql(BALANCES_Q)
    pg.sql(COUNT_FX_Q)
    pg.authorize_new_seals(m)


def prep_exec(pg, balance, acct):
    """PREPARE + EXECUTE dans une session neuve (premier EXECUTE de la
    session ⇒ plan custom ⇒ sceau déterministe, cf. plan_cache_mode)."""
    conn = pg.connect()
    try:
        with conn.cursor() as cur:
            cur.execute(f"PREPARE upd AS {UPDATE_Q};")
            cur.execute("EXECUTE upd(%s, %s);" % (balance, acct))
    finally:
        conn.close()


def test_prepared_statement_bound_value_attack(pg):
    """Scénario 1 : la validation structurelle du PREPARE (placeholders)
    ne prouve rien sur la valeur liée à l'EXECUTE — seul le hook 2 la voit."""
    m = pg.mark()
    prep_exec(pg, 1000, 1)          # monitor : exécution légitime tracée
    pg.sql(BALANCES_Q)              # lecture de contrôle, à ré-autoriser aussi
    seal_ok = pg.authorize_new_seals(m)[0]
    pg.set_guc("tbp.enforce", "on")
    try:
        prep_exec(pg, 1000, 1)      # valeur propre : admise (sceau autorisé)
        assert pg.sql(BALANCES_Q) == [(1, 1000), (2, 200)]

        # Valeur hostile : MÊME structure validée au PREPARE, autre valeur liée.
        m2 = pg.mark()
        with pytest.raises(psycopg2.errors.InsufficientPrivilege,
                           match="sceau de plan non autorisé"):
            prep_exec(pg, -9999, 2)
        leaf = pg.assert_leaf(m2, "exec", "seal-unauthorized", cmd="UPDATE")
        assert leaf["seal"] != seal_ok, \
            "le sceau doit lier les valeurs : valeur hostile ≠ sceau autorisé"
        assert pg.sql(BALANCES_Q) == [(1, 1000), (2, 200)], \
            "la ligne visée par la valeur hostile a bougé"

        # §6.2 : hash-only — la valeur hostile n'apparaît dans AUCUNE feuille,
        # seulement son sceau. (Le journal PostgreSQL lui-même peut échoûter le
        # texte de la requête en erreur via STATEMENT: — canal hors feuille,
        # voir la note de déploiement dans tests/README.md.)
        for leaf in pg.leaves(m2):
            assert "-9999" not in json.dumps(leaf), \
                "une valeur liée en clair dans une feuille (§6.2)"
    finally:
        pg.set_guc("tbp.enforce", "off")


def test_volatile_function_blocked_at_parse_never_executed(pg, enforce_on):
    """Scénario 2 : la fonction volatile est interceptée à post_parse_analyze,
    AVANT que la planification ne l'évalue (const-folding) — preuve par
    l'absence d'effet de bord, pas seulement par l'erreur."""
    fxlog_before = pg.sql(COUNT_FX_Q)[0][0]   # sceau autorisé par le test 1
    m = pg.mark()
    with pytest.raises(psycopg2.errors.InsufficientPrivilege,
                       match="structural-deny-function"):
        pg.sql("SELECT side_effect();")
    pg.assert_leaf(m, "parse", "structural-deny-function", cmd="SELECT")
    assert [l for l in pg.leaves(m)
            if l["phase"] == "exec" and l["cmd"] == "SELECT"] == [], \
        "une feuille exec existe : le refus n'a pas eu lieu au parse"
    assert pg.sql(COUNT_FX_Q)[0][0] == fxlog_before, \
        "la fonction volatile a laissé un effet de bord malgré le refus"


def test_immutable_wrapper_around_volatile_blocked(pg, enforce_on):
    """Défense en profondeur : PostgreSQL interdit le DML dans une fonction
    non volatile, mais une fonction IMMUTABLE peut ENROBER une fonction
    volatile (const-foldée dès la planification). Le corps des fonctions SQL
    est analysé — et donc gouverné — à sa première compilation : le hook 1
    y voit la fonction volatile et refuse, même dans le CREATE FUNCTION."""
    fxlog_before = pg.sql(COUNT_FX_Q)[0][0]
    m = pg.mark()
    with pytest.raises(psycopg2.errors.InsufficientPrivilege,
                       match="structural-deny-function"):
        pg.sql("CREATE FUNCTION wrapper_volatile() RETURNS int "
               "LANGUAGE sql IMMUTABLE AS $$ SELECT side_effect() $$;")
    pg.assert_leaf(m, "parse", "structural-deny-function")
    # l'appel direct reste bloqué au parse, même sous enforce
    m2 = pg.mark()
    with pytest.raises(psycopg2.errors.InsufficientPrivilege,
                       match="structural-deny-function"):
        pg.sql("SELECT side_effect() FROM accounts WHERE id = 1;")
    pg.assert_leaf(m2, "parse", "structural-deny-function", cmd="SELECT")
    assert pg.sql(COUNT_FX_Q)[0][0] == fxlog_before


def test_psycopg2_client_side_params_distinct_seals(pg):
    """Réalité des pilotes : psycopg2 interpole les paramètres côté client
    (protocole simple) — chaque valeur produit un SQL distinct, donc un plan
    distinct, donc un sceau distinct. La valeur hostile est bloquée à
    l'exécution même sans PREPARE explicite."""
    m = pg.mark()
    pg.sql("UPDATE accounts SET balance = %s WHERE id = %s;", (1000, 1))
    pg.sql(BALANCES_Q)
    pg.authorize_new_seals(m)
    pg.set_guc("tbp.enforce", "on")
    try:
        pg.sql("UPDATE accounts SET balance = %s WHERE id = %s;", (1000, 1))
        m2 = pg.mark()
        with pytest.raises(psycopg2.errors.InsufficientPrivilege,
                           match="sceau de plan non autorisé"):
            pg.sql("UPDATE accounts SET balance = %s WHERE id = %s;",
                   (777, 1))          # autre valeur ⇒ autre sceau
        pg.assert_leaf(m2, "exec", "seal-unauthorized", cmd="UPDATE")
        assert pg.sql(BALANCES_Q) == [(1, 1000), (2, 200)]
    finally:
        pg.set_guc("tbp.enforce", "off")
