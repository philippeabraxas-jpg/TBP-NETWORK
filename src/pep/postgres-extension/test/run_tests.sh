#!/bin/sh
# Tests d'acceptance T16 — extension PostgreSQL à deux hooks (§4.4).
#
# Pré-requis : extension compilée ET installée contre le PostgreSQL cible :
#
#	make PG_CONFIG=/chemin/pg_config
#	make PG_CONFIG=/chemin/pg_config install
#
# Lancement :
#
#	PG_CONFIG=/chemin/pg_config sh test/run_tests.sh
#
# Le script crée une instance jetable (initdb), la démarre avec
# shared_preload_libraries='tbp_pg' en mode monitor (défaut §5.3), joue
# les scénarios du critère d'acceptation de l'issue, puis l'arrête.
# Sortie non nulle si un scénario échoue.
set -eu

PG_CONFIG="${PG_CONFIG:-pg_config}"
BINDIR="$("$PG_CONFIG" --bindir)"
PKGLIBDIR="$("$PG_CONFIG" --pkglibdir)"
SHAREDIR="$("$PG_CONFIG" --sharedir)"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d /tmp/tbp_pg_test.XXXXXX)"
SOCK="$WORK/sock"
PORT="${TBP_TEST_PORT:-55444}"
LOG="$WORK/pg.log"
PSQL="$BINDIR/psql -h $SOCK -p $PORT -U tbp -d postgres -X -A -t"

mkdir -p "$SOCK"
trap '"$BINDIR/pg_ctl" -D "$WORK/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
# reload hors SQL : pg_reload_conf() serait elle-même refusée par le hook 1
# (fonction volatile) dès que tbp.enforce=on — la politique se mordrait la queue.
# On sonde le GUC concerné jusqu'à bascule effective (le SIGHUP est asynchrone).
reload_conf() {
	"$BINDIR/pg_ctl" -D "$WORK/data" reload >/dev/null
	for _ in $(seq 1 50); do
		[ "$($PSQL -c "SHOW $1;")" = "$2" ] && return 0
		sleep 0.1
	done
	fail "reload_conf: $1 ne bascule pas vers « $2 »"
}

# --- instance jetable -------------------------------------------------------
"$BINDIR/initdb" -D "$WORK/data" --no-locale -E UTF8 -U tbp >"$WORK/initdb.log" 2>&1
{
	echo "shared_preload_libraries = 'tbp_pg'"
	echo "dynamic_library_path = '$PKGLIBDIR'"
	echo "log_min_messages = log"
	echo "log_line_prefix = ''"
} >>"$WORK/data/postgresql.conf"
"$BINDIR/pg_ctl" -D "$WORK/data" -l "$LOG" -o "-k $SOCK -p $PORT -c listen_addresses=''" -w start >/dev/null

# Fonctions SQL de l'extension (chemin explicite : pas besoin du .control
# dans un sharedir en lecture seule ; un vrai déploiement fait
# CREATE EXTENSION tbp_pg).
sed "s|'MODULE_PATHNAME'|'$PKGLIBDIR/tbp_pg.so'|g" "$HERE/../sql/tbp_pg--0.1.sql" | $PSQL -q -f - >/dev/null

$PSQL -q <<'SQL'
CREATE TABLE docs(id int PRIMARY KEY, val text);
INSERT INTO docs VALUES (1, 'alpha'), (2, 'beta');
CREATE TABLE secrets(id int PRIMARY KEY, val text);
INSERT INTO secrets VALUES (1, 's3cr3t');
CREATE FUNCTION side_effect() RETURNS int LANGUAGE sql VOLATILE AS $$ SELECT 1 $$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY; -- sans rapport : vérifie que le DDL utilitaire passe
SQL

# GUC de base : SELECT seul, tables docs seule, enforce off (monitor).
$PSQL -q <<'SQL'
ALTER SYSTEM SET tbp.allowed_commands = 'SELECT';
ALTER SYSTEM SET tbp.allowed_tables = 'public.docs';
ALTER SYSTEM SET tbp.cell_id = 'tbp/registry/cell-alpha-01';
SQL
reload_conf tbp.allowed_commands SELECT

# --- J. vecteur de test SHA-256 embarqué ------------------------------------
got=$($PSQL -c "SELECT tbp_sha256('abc');")
[ "$got" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ] \
	|| fail "tbp_sha256('abc') = $got"
ok "SHA-256 embarqué conforme (vecteur FIPS)"

# --- B. monitor : rien bloqué, tout tracé -----------------------------------
out=$($PSQL -c "SELECT * FROM docs ORDER BY id;")
[ "$out" = "1|alpha
2|beta" ] || fail "monitor a bloqué un SELECT: $out"
grep -q '"phase":"exec".*"would_deny":true.*"reason":"seal-unauthorized"' "$LOG" \
	|| fail "monitor: pas de feuille would_deny seal-unauthorized"
ok "monitor: SELECT forwardé, would_deny tracé (§5.3)"

seal_docs=$(grep '"phase":"exec"' "$LOG" | grep '"seal":"' | tail -1 | sed 's/.*"seal":"\([0-9a-f]\{64\}\)".*/\1/')
[ ${#seal_docs} -eq 64 ] || fail "sceau non récolté depuis le journal"
ok "sceau de plan récolté depuis la feuille: $(printf %s "$seal_docs" | cut -c1-16)…"

# CTE licite (WITH sur table autorisée) : admise en monitor
out=$($PSQL -c "WITH x AS (SELECT val FROM docs WHERE id = 1) SELECT * FROM x;")
[ "$out" = "alpha" ] || fail "CTE licite refusée en monitor: $out"
ok "CTE licite admise (WITH sur table autorisée)"

# --- C. enforce : refus fail-closed tant que non autorisé --------------------
$PSQL -q -c "ALTER SYSTEM SET tbp.enforce = on;" >/dev/null
reload_conf tbp.enforce on
if $PSQL -c "SELECT * FROM docs;" 2>"$WORK/err"; then
	fail "enforce: SELECT non autorisé accepté"
fi
grep -q "TBP: sceau de plan non autorisé" "$WORK/err" || fail "message de refus inattendu: $(cat "$WORK/err")"
grep -q '"phase":"exec".*"would_deny":false.*"reason":"seal-unauthorized"' "$LOG" \
	|| fail "feuille deny enforce manquante"
ok "enforce: SELECT non autorisé bloqué (fail-closed, feuille écrite)"

# --- D. autorisation par le cache de décision (D7) ---------------------------
$PSQL -q -c "SELECT tbp_authorize('$seal_docs');" >/dev/null
out=$($PSQL -c "SELECT * FROM docs ORDER BY id;")
[ "$out" = "1|alpha
2|beta" ] || fail "SELECT autorisé refusé: $out"
ok "cache de décision: sceau autorisé ⇒ exécution admise"
# le sceau lie le plan : une requête différente reste refusée
if $PSQL -c "SELECT count(*) FROM docs;" 2>"$WORK/err"; then
	fail "plan distinct admis avec le sceau d'un autre plan"
fi
grep -q "seal-unauthorized" "$WORK/err" || fail "refus inattendu: $(cat "$WORK/err")"
ok "sceau lié au plan: requête différente toujours refusée"

# --- E. LE trou du hook unique : PREPARE/EXECUTE avec valeur hostile ---------
# (les prepared statements vivent dans la session : PREPARE et EXECUTE
# partagent le même psql)
PREP_Q="PREPARE q(int) AS SELECT val FROM docs WHERE id = \$1;"
if $PSQL -q -c "$PREP_Q" -c "EXECUTE q(1);" 2>"$WORK/err"; then
	fail "EXECUTE q(1) accepté sans autorisation"
fi
seal_q1=$(grep '"phase":"exec"' "$LOG" | grep '"reason":"seal-unauthorized"' | tail -1 | sed 's/.*"seal":"\([0-9a-f]\{64\}\)".*/\1/')
[ ${#seal_q1} -eq 64 ] || fail "sceau q(1) non récolté"
$PSQL -q -c "SELECT tbp_authorize('$seal_q1');" >/dev/null
out=$($PSQL -q -c "$PREP_Q" -c "EXECUTE q(1);")
[ "$out" = "alpha" ] || fail "EXECUTE q(1) autorisé refusé: $out"
ok "prepared statement: valeur autorisée admise"

# La valeur hostile : même structure, autre valeur liée — le hook 1 l'a
# validée UNE fois au PREPARE (placeholders) ; seul le hook 2 la voit.
if $PSQL -q -c "$PREP_Q" -c "EXECUTE q(2);" 2>"$WORK/err"; then
	fail "EXECUTE q(2) — valeur hostile — acceptée"
fi
grep -q "TBP: sceau de plan non autorisé" "$WORK/err" \
	|| fail "refus valeur hostile inattendu: $(cat "$WORK/err")"
ok "CRITÈRE D'ACCEPTATION: EXECUTE avec valeur hostile liée bloqué (le trou que le hook unique ne voit pas)"

# --- F. object-capability : sceau présenté, usage unique (§4.4(2)) -----------
# (tbp_present_seal pose un sceau « en attente » PAR BACKEND : présentation
# et exécution partagent la même session psql)
seal_q2=$(grep '"phase":"exec"' "$LOG" | grep '"reason":"seal-unauthorized"' | tail -1 | sed 's/.*"seal":"\([0-9a-f]\{64\}\)".*/\1/')
[ "$seal_q2" != "$seal_q1" ] || fail "les sceaux de q(1) et q(2) devraient différer (valeurs liées distinctes)"
out=$($PSQL -q -c "SELECT tbp_present_seal('$seal_q2');" -c "$PREP_Q" -c "EXECUTE q(2);" 2>"$WORK/err")
[ "$out" = "t
beta" ] || fail "EXECUTE q(2) avec sceau présenté refusé: $out $(cat "$WORK/err")"
# usage unique : le sceau est consommé et n'a PAS élargi le cache (D7 reste
# aux mains de la gouvernance) — la même exécution est refusée ensuite.
if $PSQL -q -c "$PREP_Q" -c "EXECUTE q(2);" 2>"$WORK/err"; then
	fail "sceau présenté réutilisé (usage unique + cache non élargi)"
fi
grep -q "seal-unauthorized" "$WORK/err" || fail "refus inattendu: $(cat "$WORK/err")"
ok "sceau présenté: admis une fois, consommé, cache de décision non élargi"

# Sceau présenté non conforme ⇒ seal-mismatch explicite.
if $PSQL -q -c "SELECT tbp_present_seal('$seal_q1');" -c "$PREP_Q" -c "EXECUTE q(2);" >"$WORK/out" 2>"$WORK/err"; then
	fail "sceau non conforme accepté"
fi
grep -q "TBP: valeurs liées non conformes au sceau présenté" "$WORK/err" \
	|| fail "refus seal-mismatch inattendu: $(cat "$WORK/err")"
ok "sceau présenté non conforme ⇒ seal-mismatch"

# --- G. fonction volatile à effet de bord : bloquée au PARSE (hook 1) --------
if $PSQL -c "SELECT side_effect();" 2>"$WORK/err"; then
	fail "fonction volatile acceptée"
fi
grep -q "TBP: refus structurel (structural-deny-function)" "$WORK/err" \
	|| fail "refus volatile inattendu: $(cat "$WORK/err")"
grep -q '"phase":"parse".*"reason":"structural-deny-function"' "$LOG" \
	|| fail "feuille parse structural-deny-function manquante"
ok "CRITÈRE D'ACCEPTATION: fonction volatile bloquée par le hook 1 (au parse, avant toute planification)"

# --- H. table non autorisée ---------------------------------------------------
if $PSQL -c "SELECT * FROM secrets;" 2>"$WORK/err"; then
	fail "table non autorisée acceptée"
fi
grep -q "structural-deny-table" "$WORK/err" || fail "refus table inattendu: $(cat "$WORK/err")"
ok "table hors liste blanche bloquée (structural-deny-table)"

# --- I. commande non autorisée ------------------------------------------------
if $PSQL -c "INSERT INTO docs VALUES (3, 'gamma');" 2>"$WORK/err"; then
	fail "INSERT non autorisé accepté"
fi
grep -q "structural-deny-command" "$WORK/err" || fail "refus commande inattendu: $(cat "$WORK/err")"
ok "commande hors liste blanche bloquée (structural-deny-command)"

# --- L. CTE : le WITH n'est pas un trou de contournement ---------------------
# table interdite cachée dans un WITH ⇒ refus structurel (le walker descend
# dans cteList)
if $PSQL -c "WITH x AS (SELECT * FROM secrets) SELECT * FROM x;" 2>"$WORK/err"; then
	fail "CTE sur table non autorisée acceptée"
fi
grep -q "structural-deny-table" "$WORK/err" || fail "refus CTE inattendu: $(cat "$WORK/err")"
# fonction volatile cachée dans un WITH ⇒ refus structurel au parse
if $PSQL -c "WITH x AS (SELECT side_effect() AS v) SELECT * FROM x;" 2>"$WORK/err"; then
	fail "fonction volatile en CTE acceptée"
fi
grep -q "structural-deny-function" "$WORK/err" || fail "refus CTE volatile inattendu: $(cat "$WORK/err")"
# sous-requête du FROM (RTE_SUBQUERY) : même traitement
if $PSQL -c "SELECT * FROM (SELECT * FROM secrets) t;" 2>"$WORK/err"; then
	fail "sous-requête du FROM sur table non autorisée acceptée"
fi
grep -q "structural-deny-table" "$WORK/err" || fail "refus sous-requête FROM inattendu: $(cat "$WORK/err")"
ok "CTE et sous-requêtes du FROM: pas de contournement du contrôle structurel"

# --- K. latence §9.1 : surcharge du hook mesurée sur les feuilles ------------
# (PREPARE en tête du fichier : la préparation vit dans la session du bench)
{
	echo 'PREPARE q2(int) AS SELECT val FROM docs WHERE id = $1;'
	for i in $(seq 1 200); do echo "EXECUTE q2($((i % 2 + 1)));"; done
} > "$WORK/bench.sql"
# autorise les deux sceaux de q2 (id 1 et 2) — récoltés en une passe monitor
$PSQL -q -c "ALTER SYSTEM SET tbp.enforce = off;" >/dev/null
reload_conf tbp.enforce off
$PSQL -q -f "$WORK/bench.sql" >/dev/null
# TOUTES les variantes de sceaux : plan_cache_mode=auto bascule du plan
# custom (5 premières exécutions) au générique — deux plans, deux sceaux,
# le sceau lie le plan exact (comportement voulu, cf. README).
grep '"phase":"exec"' "$LOG" | grep '"reason":"seal-unauthorized"' | \
	sed 's/.*"seal":"\([0-9a-f]\{64\}\)".*/\1/' | sort -u > "$WORK/seals.txt"
$PSQL -q -c "ALTER SYSTEM SET tbp.enforce = on;" >/dev/null
reload_conf tbp.enforce on
while read -r s; do $PSQL -q -c "SELECT tbp_authorize('$s');" >/dev/null; done < "$WORK/seals.txt"
before=$(wc -l < "$LOG")
$PSQL -q -f "$WORK/bench.sql" >"$WORK/bench2.out" 2>"$WORK/bench2.err"
if grep -q ERROR "$WORK/bench2.err"; then
	fail "bench enforce: exécutions autorisées refusées: $(head -3 "$WORK/bench2.err")"
fi
sed -n "$((before + 1)),\$p" "$LOG" | grep '"phase":"exec"' | \
	sed 's/.*"elapsed_us":\([0-9]*\).*/\1/' > "$WORK/lat.txt"
n=$(wc -l < "$WORK/lat.txt")
[ "$n" -ge 150 ] || fail "pas assez de mesures de latence ($n)"
awk '{s+=$1; if($1>m)m=$1} END {printf "latence hook2: n=%d moy=%.0f us max=%d us\n", NR, s/NR, m}' "$WORK/lat.txt"
max=$(sort -n "$WORK/lat.txt" | tail -1)
[ "$max" -lt 5000 ] || fail "latence hook2 max ${max} us ≥ budget tier 1 (5000 us, §9.1)"
ok "CRITÈRE D'ACCEPTATION: latence hook2 dans le budget tier 1 (max ${max} us < 5000 us, §9.1)"

# --- M. ORM SQLAlchemy (protocole étendu, critère d'acceptation) -------------
# Le script ORM mène son propre cycle monitor → enforce ; on repasse en
# monitor avant de le lancer : dès la CONNEXION, le pilote émet des requêtes
# maison (sonde hstore → pg_catalog.pg_type) qu'un enforce résiduel nierait.
$PSQL -q -c "ALTER SYSTEM SET tbp.enforce = off;" >/dev/null
reload_conf tbp.enforce off
if PYTHONPATH="${TBP_ORM_PYTHONPATH:-}" python3 -c "import sqlalchemy, psycopg2" 2>/dev/null; then
	TBP_SOCK="$SOCK" TBP_PORT="$PORT" TBP_LOG="$LOG" \
	TBP_BINDIR="$BINDIR" TBP_DATA="$WORK/data" \
	PYTHONPATH="${TBP_ORM_PYTHONPATH:-}" \
		python3 "$HERE/orm_sqlalchemy.py" || fail "scénario ORM SQLAlchemy"
	ok "ORM SQLAlchemy: prepared statements implicites sous contrôle (monitor → enforce)"
else
	echo "info: sqlalchemy/psycopg2 non importables — scénario ORM sauté"
	echo "      (pip install sqlalchemy psycopg2-binary, voire TBP_ORM_PYTHONPATH)"
fi

echo
echo "TOUS LES TESTS T16 PASSENT"
