/*-------------------------------------------------------------------------
 * tbp_pg.c — PEP in-process TBP pour PostgreSQL (T16, §4.4).
 *
 * DEUX HOOKS, pour deux raisons distinctes (voir README.md) :
 *
 *  1. post_parse_analyze_hook — validation STRUCTURELLE contre le parse
 *     tree : commande, tables, fonctions. ExecutorStart seul est
 *     post-planification : une fonction volatile à effet de bord peut
 *     déjà avoir été évaluée (const-folding du planificateur) quand il
 *     tire — la décision structurelle reste donc au parse.
 *
 *  2. ExecutorStart_hook — validation d'un SCEAU : hash SHA-256 du plan
 *     finalisé (nodeToString du PlannedStmt) incluant les VALEURS LIÉES
 *     des paramètres ($1, $2 concrets). post_parse_analyze seul ne tire
 *     qu'au parse : un PREPARE … EXECUTE ($1,$2) — le défaut des poolers
 *     et ORM — n'est validé qu'une fois avec des placeholders ; chaque
 *     EXECUTE ultérieur le saute entièrement. Le sceau ferme ce trou
 *     sans rouvrir le risque du hook unique : la décision structurelle
 *     est déjà prise au parse ; ici on ne vérifie que la concordance des
 *     valeurs exécutées avec ce qui a été autorisé.
 *
 * Décisions d'implémentation (voir README) :
 *  - D3 : C natif + PGXS (pas de pgrx), PostgreSQL 15 ÉPINGLÉ (les
 *    signatures de hooks bougent entre versions majeures).
 *  - D7 : le sceau est calculé PAR L'EXTENSION, en synchrone, juste avant
 *    exécution ; l'autorisation passe par un CACHE DE DÉCISION borné en
 *    mémoire partagée (§4.3 : jamais de croissance, jamais d'éviction —
 *    saturation ⇒ refus fail-closed + alarme), alimenté par
 *    tbp_authorize() (rôle autorisé) ou par présentation du sceau
 *    (tbp_present_seal(), object-capability §4.4(2), usage unique).
 *
 * Doctrine §5.3 — MONITOR D'ABORD : tbp.enforce = off par défaut. Chaque
 * décision (parse ET exec) laisse une FEUILLE structurée dans le journal
 * PostgreSQL (ligne "TBP_LEAF {json}", hash-only : commande, tables,
 * sceau, jamais les valeurs) ; en monitor un refus est would_deny:true
 * et l'exécution continue. La latence du hook est mesurée à chaque
 * exécution (elapsed_us dans la feuille — §9.1, mesuré dès le prototype).
 *
 * Chargement : shared_preload_libraries = 'tbp_pg' (le cache de décision
 * vit en mémoire partagée). Sans préchargement, l'extension se charge
 * mais le cache est indisponible : seule la présentation de sceau peut
 * autoriser — journalisé au démarrage.
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/pg_proc.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/nodes.h"
#include "nodes/params.h"
#include "nodes/parsenodes.h"
#include "nodes/pg_list.h"
#include "parser/analyze.h"
#include "portability/instr_time.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/lsyscache.h"
#include "utils/palloc.h"

#include <openssl/evp.h>
#include <string.h>
#include <time.h>

PG_MODULE_MAGIC;

#define TBP_SEAL_HEX_LEN 64		/* SHA-256 en hex */
#define TBP_SEAL_KEY_LEN (TBP_SEAL_HEX_LEN + 1)
#define TBP_MAX_TABLES_IN_LEAF 8

/* ------------------------------------------------------------------------
 * GUC — fail-closed par construction : listes vides = tout refusé quand
 * enforce est on ; enforce off (monitor) par défaut (doctrine §5.3).
 * ------------------------------------------------------------------------
 */
static bool tbp_enforce = false;	/* off = monitor (défaut §5.3) */
static char *tbp_allowed_commands = NULL;	/* ex. "SELECT,INSERT" */
static char *tbp_allowed_tables = NULL;		/* ex. "public.docs, app.*" */
static char *tbp_allowed_functions = NULL;	/* ex. "now, count" */
static char *tbp_cell_id = NULL;		/* identité de la cellule (feuilles) */
static char *tbp_authorizer_role = NULL;	/* rôle autorisé à tbp_authorize */
static int	tbp_cache_entries = 4096;	/* borne §4.3, redémarrage */

/* Sceau présenté (object-capability §4.4(2)) — statique au backend,
 * USAGE UNIQUE : consommé par la prochaine exécution, match ou non. */
static char tbp_pending_seal[TBP_SEAL_KEY_LEN];
static bool tbp_pending_seal_set = false;

/* Cache de décision partagé (D7) : sceau hex → première autorisation. */
typedef struct TbpSealEntry
{
	char		seal[TBP_SEAL_KEY_LEN]; /* clé */
	pg_time_t	first_seen;
} TbpSealEntry;

static HTAB *tbp_seals = NULL;	/* NULL si non préchargé */
static LWLock *tbp_lock = NULL;

/* Hooks chaînés. */
static post_parse_analyze_hook_type prev_ppa_hook = NULL;
static ExecutorStart_hook_type prev_exec_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

void		_PG_init(void);

static void tbp_shmem_request(void);
static void tbp_shmem_startup(void);
static void tbp_post_parse_analyze(ParseState *pstate, Query *query, JumbleState *jstate);
static void tbp_ExecutorStart(QueryDesc *queryDesc, int eflags);

/* ------------------------------------------------------------------------
 * Initialisation — GUC + hooks + mémoire partagée.
 * ------------------------------------------------------------------------
 */
void
_PG_init(void)
{
	DefineCustomBoolVariable("tbp.enforce",
								 "on = les refus TBP bloquent (closed) ; off = monitor "
								 "(log would_deny, rien bloqué — doctrine §5.3).",
								 NULL,
								 &tbp_enforce,
								 false,
								 PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("tbp.allowed_commands",
								   "Commandes autorisées, séparées par des virgules "
								   "(SELECT,INSERT,UPDATE,DELETE,MERGE). Vide = toutes refusées.",
								   NULL,
								   &tbp_allowed_commands,
								   "",
								   PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("tbp.allowed_tables",
								   "Tables autorisées (schema.table), séparées par des "
								   "virgules. Vide = toutes refusées (fail-closed).",
								   NULL,
								   &tbp_allowed_tables,
								   "",
								   PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("tbp.allowed_functions",
								   "Fonctions non immutables explicitement autorisées "
								   "(noms), séparées par des virgules.",
								   NULL,
								   &tbp_allowed_functions,
								   "",
								   PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("tbp.cell_id",
								   "Identité de la cellule TBP portée par les feuilles (§6.2).",
								   NULL,
								   &tbp_cell_id,
								   "",
								   PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("tbp.authorizer_role",
								   "Rôle autorisé à appeler tbp_authorize/tbp_forget_all "
								   "(le superuser l'est toujours). Vide = superuser seul.",
								   NULL,
								   &tbp_authorizer_role,
								   "",
								   PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomIntVariable("tbp.cache_entries",
								"Capacité du cache de décision (§4.3 : borné, jamais "
								"d'éviction — saturation = refus fail-closed + alarme).",
								NULL,
								&tbp_cache_entries,
								4096, 16, 1048576,
								PGC_POSTMASTER, 0, NULL, NULL, NULL);

	shmem_request_hook = tbp_shmem_request;
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = tbp_shmem_startup;

	prev_ppa_hook = post_parse_analyze_hook;
	post_parse_analyze_hook = tbp_post_parse_analyze;
	prev_exec_hook = ExecutorStart_hook;
	ExecutorStart_hook = tbp_ExecutorStart;

	if (!process_shared_preload_libraries_in_progress)
		ereport(LOG,
				(errmsg("TBP: chargé sans shared_preload_libraries — "
						"le cache de décision (D7) est indisponible ; seule "
						"tbp_present_seal() peut autoriser une exécution")));
}

static void
tbp_shmem_request(void)
{
	RequestAddinShmemSpace(hash_estimate_size(tbp_cache_entries,
											  sizeof(TbpSealEntry)));
	RequestNamedLWLockTranche("tbp_pg", 1);
}

static void
tbp_shmem_startup(void)
{
	HASHCTL		info;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	memset(&info, 0, sizeof(info));
	info.keysize = TBP_SEAL_KEY_LEN;
	info.entrysize = sizeof(TbpSealEntry);
	tbp_seals = ShmemInitHash("tbp_pg decision cache",
							  tbp_cache_entries, tbp_cache_entries,
							  &info, HASH_ELEM | HASH_BLOBS);
	tbp_lock = &(GetNamedLWLockTranche("tbp_pg")->lock);
}

/* ------------------------------------------------------------------------
 * Listes blanches : "a, b ,c" — comparaison exacte, insensible à la casse
 * pour les commandes, sensible pour les noms d'objets (un identifiant
 * PostgreSQL entre guillemets est sensible à la casse ; on reste exact).
 * ------------------------------------------------------------------------
 */
static bool
tbp_list_contains(const char *list, const char *name, bool fold_case)
{
	const char *p;

	if (list == NULL || *list == '\0')
		return false;
	p = list;
	while (*p)
	{
		const char *start;
		size_t		len;

		while (*p == ' ' || *p == '\t' || *p == ',')
			p++;
		start = p;
		while (*p && *p != ',')
			p++;
		len = (size_t) (p - start);
		while (len > 0 && (start[len - 1] == ' ' || start[len - 1] == '\t'))
			len--;
		if (len == 0)
			continue;
		if (strlen(name) == len)
		{
			if (fold_case)
			{
				if (pg_strncasecmp(start, name, len) == 0)
					return true;
			}
			else if (strncmp(start, name, len) == 0)
				return true;
		}
	}
	return false;
}

/* ------------------------------------------------------------------------
 * Feuille (§4.1/§6.2) : une ligne "TBP_LEAF {json}" par décision, dans le
 * journal PostgreSQL — le pipeline de la cellule l'ingère vers le registre
 * (hash-only : jamais de valeur liée, seulement le sceau). Le sel ne
 * quitte pas la cellule : le hash de la feuille est apposé en amont du
 * registre, pas ici.
 * ------------------------------------------------------------------------
 */
static void
tbp_json_escape(StringInfo buf, const char *s)
{
	const unsigned char *p;

	if (s == NULL)
		return;
	for (p = (const unsigned char *) s; *p; p++)
	{
		if (*p == '"' || *p == '\\')
		{
			appendStringInfoChar(buf, '\\');
			appendStringInfoChar(buf, (char) *p);
		}
		else if (*p < 0x20)
			appendStringInfo(buf, "\\u%04x", *p);
		else
			appendStringInfoChar(buf, (char) *p);
	}
}

static void
tbp_emit_leaf(const char *phase, const char *cmd, List *tables,
				  const char *seal, const char *reason, const char *detail,
				  uint64 elapsed_us, bool denied)
{
	StringInfoData buf;
	ListCell   *lc;
	int			n = 0;
	bool		first = true;

	initStringInfo(&buf);
	appendStringInfoString(&buf, "{\"v\":1,\"phase\":\"");
	tbp_json_escape(&buf, phase);
	appendStringInfoString(&buf, "\",\"cell\":\"");
	tbp_json_escape(&buf, (tbp_cell_id && *tbp_cell_id) ? tbp_cell_id : "unset");
	appendStringInfoString(&buf, "\",\"allow\":");
	appendStringInfoString(&buf, denied ? "false" : "true");
	appendStringInfoString(&buf, ",\"would_deny\":");
	appendStringInfoString(&buf, (denied && !tbp_enforce) ? "true" : "false");
	appendStringInfoString(&buf, ",\"reason\":\"");
	tbp_json_escape(&buf, reason);
	appendStringInfoString(&buf, "\",\"cmd\":\"");
	tbp_json_escape(&buf, cmd ? cmd : "?");
	appendStringInfoString(&buf, "\",\"tables\":[");
	foreach(lc, tables)
	{
		if (n++ >= TBP_MAX_TABLES_IN_LEAF)
		{
			appendStringInfoString(&buf, ",\"…\"");
			break;
		}
		if (!first)
			appendStringInfoChar(&buf, ',');
		appendStringInfoChar(&buf, '"');
		tbp_json_escape(&buf, (const char *) lfirst(lc));
		appendStringInfoChar(&buf, '"');
		first = false;
	}
	appendStringInfoString(&buf, "]");
	if (seal && *seal)
	{
		appendStringInfoString(&buf, ",\"seal\":\"");
		appendStringInfoString(&buf, seal);
		appendStringInfoChar(&buf, '"');
	}
	if (detail && *detail)
	{
		appendStringInfoString(&buf, ",\"detail\":\"");
		tbp_json_escape(&buf, detail);
		appendStringInfoChar(&buf, '"');
	}
	appendStringInfo(&buf, ",\"elapsed_us\":" UINT64_FORMAT "}", elapsed_us);

	/* Feuille AVANT le refus : la coupure ne précède jamais sa preuve. */
	elog(LOG, "TBP_LEAF %s", buf.data);
	pfree(buf.data);
}

/* ------------------------------------------------------------------------
 * Sceau (hook 2) : SHA-256( nodeToString(PlannedStmt) ‖ pour chaque
 * paramètre lié : 0x1F ‖ oid ‖ 0x1F ‖ (valeur en texte | "NULL") ).
 * Les valeurs ne sont JAMAIS journalisées — elles n'entrent que dans le
 * hash (§6.2 : hash-only).
 * ------------------------------------------------------------------------
 */
static void
tbp_compute_seal(QueryDesc *queryDesc, char out_hex[TBP_SEAL_KEY_LEN])
{
	StringInfoData data;
	char	   *plan;
	unsigned char digest[EVP_MAX_MD_SIZE];
	size_t digest_len = 0;
	int			i;
	static const char hexchars[] = "0123456789abcdef";

	initStringInfo(&data);

	/*
	 * nodeToString ne sérialise PAS les RangeTblEntry (outfuncs ne les
	 * couvre pas) : on sérialise une copie superficielle du PlannedStmt
	 * avec rtable = NIL, puis on ajoute les relations au digest sous
	 * forme canonique (schema.table, dans l'ordre de la rtable) — les
	 * relations restent ainsi liées au sceau, et c'est exactement ce
	 * que le hook 1 autorise structurellement.
	 */
	{
		PlannedStmt copy = *queryDesc->plannedstmt;
		ListCell   *lc;

		copy.rtable = NIL;
		plan = nodeToString(&copy);
		appendStringInfoString(&data, plan);
		pfree(plan);

		foreach(lc, queryDesc->plannedstmt->rtable)
		{
			RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);
			char	   *nsp;
			char	   *rel;

			if (rte->rtekind != RTE_RELATION)
				continue;
			nsp = get_namespace_name(get_rel_namespace(rte->relid));
			rel = get_rel_name(rte->relid);
			appendStringInfoChar(&data, '\x1e');
			appendStringInfoString(&data, nsp ? nsp : "?");
			appendStringInfoChar(&data, '.');
			appendStringInfoString(&data, rel ? rel : "?");
		}
	}

	if (queryDesc->params != NULL)
	{
		ParamListInfo params = queryDesc->params;

		for (i = 0; i < params->numParams; i++)
		{
			ParamExternData *prm = &params->params[i];
			Oid			typout;
			bool		typvarlena;
			char	   *val;

			if (prm->ptype == InvalidOid)
				continue;
			appendStringInfoChar(&data, '\x1f');
			appendStringInfo(&data, "%u", prm->ptype);
			appendStringInfoChar(&data, '\x1f');
			if (prm->isnull)
			{
				appendStringInfoString(&data, "NULL");
				continue;
			}
			getTypeOutputInfo(prm->ptype, &typout, &typvarlena);
			val = OidOutputFunctionCall(typout, prm->value);
			appendStringInfoString(&data, val);
			pfree(val);
		}
	}

	if (EVP_Q_digest(NULL, "SHA256", NULL,
						 data.data, (size_t) data.len,
						 digest, &digest_len) != 1 ||
		digest_len != 32)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TBP: échec du calcul SHA-256 du sceau")));
	pfree(data.data);

	for (i = 0; i < 32; i++)
	{
		out_hex[i * 2] = hexchars[(digest[i] >> 4) & 0xF];
		out_hex[i * 2 + 1] = hexchars[digest[i] & 0xF];
	}
	out_hex[TBP_SEAL_HEX_LEN] = '\0';
}

/* ------------------------------------------------------------------------
 * Cache de décision (D7) — borné, jamais d'éviction (§4.3) :
 * saturation ⇒ échec de l'insertion ⇒ refus fail-closed + alarme.
 * ------------------------------------------------------------------------
 */
static bool
tbp_cache_lookup(const char *seal)
{
	bool		found;

	if (tbp_seals == NULL)
		return false;
	LWLockAcquire(tbp_lock, LW_SHARED);
	found = (hash_search(tbp_seals, seal, HASH_FIND, NULL) != NULL);
	LWLockRelease(tbp_lock);
	return found;
}

static bool
tbp_cache_insert(const char *seal)
{
	TbpSealEntry *entry;
	bool		found;

	if (tbp_seals == NULL)
		return false;
	LWLockAcquire(tbp_lock, LW_EXCLUSIVE);
	entry = (TbpSealEntry *) hash_search(tbp_seals, seal, HASH_ENTER, &found);
	if (entry != NULL && !found)
		entry->first_seen = (pg_time_t) time(NULL);
	LWLockRelease(tbp_lock);
	if (entry == NULL)
	{
		/* Saturation : fail-closed, alarmé — jamais d'éviction. */
		ereport(LOG,
				(errmsg("TBP: ALARME cache de décision saturé (%d entrées, §4.3) — nouveau sceau refusé",
						tbp_cache_entries)));
		return false;
	}
	return true;
}

/* ------------------------------------------------------------------------
 * Hook 1 — validation structurelle au parse (commande, tables, fonctions).
 * ------------------------------------------------------------------------
 */
typedef struct TbpStructCtx
{
	const char *deny_reason;	/* code stable, NULL tant que rien */
	char		deny_detail[2 * NAMEDATALEN + 64];
	List	   *tables;			/* noms qualifiés, pour la feuille */
} TbpStructCtx;

static const char *
tbp_command_name(CmdType cmd)
{
	switch (cmd)
	{
		case CMD_SELECT:
			return "SELECT";
		case CMD_INSERT:
			return "INSERT";
		case CMD_UPDATE:
			return "UPDATE";
		case CMD_DELETE:
			return "DELETE";
		case CMD_MERGE:
			return "MERGE";
		default:
			return "OTHER";
	}
}

/* Une fonction non immuable est un effet de bord potentiel DÈS LA
 * PLANIFICATION (const-folding) : refusée au parse, sauf liste blanche
 * explicite ou namespace de l'extension (tbp_* : nos propres fonctions
 * de gouvernance doivent rester appelables — sinon plus moyen
 * d'autoriser quoi que ce soit en mode closed). */
static bool
tbp_function_allowed(Oid funcid, TbpStructCtx *ctx)
{
	char		volatileflag;
	char	   *name;

	volatileflag = func_volatile(funcid);
	if (volatileflag == PROVOLATILE_IMMUTABLE)
		return true;
	name = get_func_name(funcid);
	if (name != NULL)
	{
		if (strncmp(name, "tbp_", 4) == 0)
			return true;
		if (tbp_list_contains(tbp_allowed_functions, name, false))
			return true;
	}
	if (ctx->deny_reason == NULL)
	{
		ctx->deny_reason = "structural-deny-function";
		snprintf(ctx->deny_detail, sizeof(ctx->deny_detail),
				 "fonction %s non immuable (%c) hors liste blanche — "
				 "un effet de bord peut être évalué dès la planification",
				 name ? name : "?", volatileflag);
	}
	return false;
}

static bool
tbp_struct_walker(Node *node, TbpStructCtx *ctx)
{
	if (node == NULL)
		return false;
	if (ctx->deny_reason != NULL)
		return true;			/* stop : déjà refusé */

	/* Avec QTW_EXAMINE_RTES_BEFORE, le walker reçoit les RangeTblEntry :
	 * expression_tree_walker ne les connaît pas (erreur « unrecognized
	 * node type »). Les RELATION sont déjà contrôlées dans la branche
	 * Query ci-dessous ; on ne descend que dans les sous-requêtes du
	 * FROM — sinon une sous-requête échapperait au contrôle structurel. */
	if (IsA(node, RangeTblEntry))
	{
		RangeTblEntry *rte = (RangeTblEntry *) node;

		if (rte->rtekind == RTE_SUBQUERY && rte->subquery != NULL)
			return tbp_struct_walker((Node *) rte->subquery, ctx);
		return false;
	}

	if (IsA(node, Query))
	{
		Query	   *q = (Query *) node;
		ListCell   *lc;

		foreach(lc, q->rtable)
		{
			RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);
			char	   *nsp;
			char	   *rel;
			char	   *qual;

			if (rte->rtekind != RTE_RELATION)
				continue;
			nsp = get_namespace_name(get_rel_namespace(rte->relid));
			rel = get_rel_name(rte->relid);
			qual = psprintf("%s.%s", nsp ? nsp : "?", rel ? rel : "?");
			ctx->tables = lappend(ctx->tables, qual);
			if (!tbp_list_contains(tbp_allowed_tables, qual, false))
			{
				ctx->deny_reason = "structural-deny-table";
				snprintf(ctx->deny_detail, sizeof(ctx->deny_detail),
						 "table %s hors liste blanche", qual);
				return true;
			}
		}
		return query_tree_walker(q, (bool (*)()) tbp_struct_walker, ctx,
								 QTW_EXAMINE_RTES_BEFORE);
	}

	if (IsA(node, FuncExpr))
	{
		if (!tbp_function_allowed(((FuncExpr *) node)->funcid, ctx))
			return true;
	}
	else if (IsA(node, OpExpr))
	{
		if (!tbp_function_allowed(get_opcode(((OpExpr *) node)->opno), ctx))
			return true;
	}
	else if (IsA(node, WindowFunc))
	{
		if (!tbp_function_allowed(((WindowFunc *) node)->winfnoid, ctx))
			return true;
	}
	return expression_tree_walker(node, (bool (*)()) tbp_struct_walker, ctx);
}

static void
tbp_post_parse_analyze(ParseState *pstate, Query *query, JumbleState *jstate)
{
	instr_time	t0;
	instr_time	t1;
	TbpStructCtx ctx;
	const char *cmd;

	if (prev_ppa_hook)
		prev_ppa_hook(pstate, query, jstate);

	/* Les utilitaires (DDL, SET, VACUUM…) n'ont ni parse tree de
	 * requête ni passage par ExecutorStart : hors périmètre T16 (voir
	 * README — la gouvernance DDL est une tâche à part). */
	if (query->commandType == CMD_UTILITY)
		return;

	INSTR_TIME_SET_CURRENT(t0);

	memset(&ctx, 0, sizeof(ctx));
	cmd = tbp_command_name(query->commandType);

	if (!tbp_list_contains(tbp_allowed_commands, cmd, true))
	{
		ctx.deny_reason = "structural-deny-command";
		snprintf(ctx.deny_detail, sizeof(ctx.deny_detail),
				 "commande %s hors liste blanche", cmd);
	}
	else
		(void) tbp_struct_walker((Node *) query, &ctx);

	INSTR_TIME_SET_CURRENT(t1);
	INSTR_TIME_SUBTRACT(t1, t0);

	tbp_emit_leaf("parse", cmd, ctx.tables, NULL,
				  ctx.deny_reason ? ctx.deny_reason : "ok",
				  ctx.deny_detail,
				  INSTR_TIME_GET_MICROSEC(t1),
				  ctx.deny_reason != NULL);

	if (ctx.deny_reason != NULL && tbp_enforce)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("TBP: refus structurel (%s)", ctx.deny_reason),
				 errdetail("%s", ctx.deny_detail)));
}

/* ------------------------------------------------------------------------
 * Hook 2 — sceau du plan finalisé + valeurs liées, juste avant exécution.
 * Ne s'applique qu'aux requêtes qui touchent au moins une relation : sans
 * objet, pas d'object-capability à vérifier (§4.4(2)) — la couverture
 * des requêtes sans table reste le hook 1 (structure + fonctions).
 * ------------------------------------------------------------------------
 */
static bool
tbp_plan_touches_relation(PlannedStmt *pstmt, List **tables)
{
	ListCell   *lc;
	bool		touched = false;

	foreach(lc, pstmt->rtable)
	{
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);

		if (rte->rtekind != RTE_RELATION)
			continue;
		touched = true;
		if (tables != NULL && list_length(*tables) < TBP_MAX_TABLES_IN_LEAF)
		{
			char	   *nsp = get_namespace_name(get_rel_namespace(rte->relid));
			char	   *rel = get_rel_name(rte->relid);

			*tables = lappend(*tables,
							  psprintf("%s.%s", nsp ? nsp : "?", rel ? rel : "?"));
		}
	}
	return touched;
}

static void
tbp_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	instr_time	t0;
	instr_time	t1;
	const char *reason = "ok";
	char		detail[160];
	char		seal[TBP_SEAL_KEY_LEN];
	List	   *tables = NIL;
	bool		denied;

	INSTR_TIME_SET_CURRENT(t0);
	detail[0] = '\0';
	seal[0] = '\0';
	if (tbp_plan_touches_relation(queryDesc->plannedstmt, &tables))
	{
		tbp_compute_seal(queryDesc, seal);

		if (tbp_pending_seal_set)
		{
			/* Object-capability §4.4(2) : le sceau présenté autorise
			 * CETTE exécution si et seulement s'il correspond — usage
			 * unique, consommé match ou non. Il n'élargit PAS le cache
			 * de décision : celui-ci ne se peuple que par la
			 * gouvernance (tbp_authorize, D7) — sinon tout backend
			 * partageant l'instance hériterait de la capacité sans
			 * la présenter (confused deputy). */
			if (strcmp(tbp_pending_seal, seal) != 0)
			{
				reason = "seal-mismatch";
				snprintf(detail, sizeof(detail),
						 "sceau présenté %.16s… != sceau calculé %.16s…",
						 tbp_pending_seal, seal);
			}
			tbp_pending_seal_set = false;
			tbp_pending_seal[0] = '\0';
		}
		else if (!tbp_cache_lookup(seal))
		{
			reason = "seal-unauthorized";
			snprintf(detail, sizeof(detail),
					 "ni cache de décision ni sceau présenté pour %.16s…",
					 seal);
		}
	}

	INSTR_TIME_SET_CURRENT(t1);
	INSTR_TIME_SUBTRACT(t1, t0);
	denied = (strcmp(reason, "ok") != 0);
	tbp_emit_leaf("exec", tbp_command_name(queryDesc->plannedstmt->commandType),
				  tables, seal, reason, detail,
				  INSTR_TIME_GET_MICROSEC(t1), denied);

	if (denied && tbp_enforce)
	{
		if (strcmp(reason, "seal-mismatch") == 0)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("TBP: valeurs liées non conformes au sceau présenté (seal-mismatch)"),
					 errdetail("%s", detail)));
		else if (strcmp(reason, "cache-saturated") == 0)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("TBP: cache de décision saturé (§4.3) — refus fail-closed"),
					 errdetail("%s", detail)));
		else
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("TBP: sceau de plan non autorisé (seal-unauthorized)"),
					 errdetail("%s", detail),
					 errhint("Autoriser via tbp_authorize(sceau) (décision D7) "
							 "ou présenter le sceau du jeton via tbp_present_seal(sceau) (§4.4(2)).")));
	}

	if (prev_exec_hook)
		prev_exec_hook(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);
}

/* ------------------------------------------------------------------------
 * Fonctions SQL — la surface de gouvernance de l'extension.
 * ------------------------------------------------------------------------
 */

/* Validation d'un sceau hex SHA-256 (64 caractères [0-9a-f]). */
static bool
tbp_seal_hex_valid(const char *s)
{
	int			i;

	if (strlen(s) != TBP_SEAL_HEX_LEN)
		return false;
	for (i = 0; i < TBP_SEAL_HEX_LEN; i++)
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
			return false;
	return true;
}

static void
tbp_check_authorizer(const char *funcname)
{
	Oid			role;

	if (superuser())
		return;
	if (tbp_authorizer_role != NULL && *tbp_authorizer_role != '\0')
	{
		role = get_role_oid(tbp_authorizer_role, true);
		if (OidIsValid(role) && has_privs_of_role(GetUserId(), role))
			return;
	}
	ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 errmsg("TBP: %s réservé au superuser ou au rôle tbp.authorizer_role",
					funcname)));
}

PG_FUNCTION_INFO_V1(tbp_present_seal);
PG_FUNCTION_INFO_V1(tbp_authorize);
PG_FUNCTION_INFO_V1(tbp_cache_count);
PG_FUNCTION_INFO_V1(tbp_forget_all);
PG_FUNCTION_INFO_V1(tbp_sha256);

/* tbp_present_seal(seal) — object-capability §4.4(2) : le jeton (T8)
 * porte le sceau de l'objet autorisé ; l'appelant le présente avant
 * d'exécuter. USAGE UNIQUE : consommé à la prochaine exécution touchant
 * une relation, que le sceau corresponde ou non. Tout rôle peut présenter
 * — c'est une capability : la possession du sceau EST l'autorisation
 * (il lie structure + valeurs ; le hook 2 ne fait que vérifier la
 * concordance). */
Datum
tbp_present_seal(PG_FUNCTION_ARGS)
{
	text	   *arg = PG_GETARG_TEXT_PP(0);
	char	   *seal = text_to_cstring(arg);

	if (!tbp_seal_hex_valid(seal))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("TBP: sceau invalide — 64 caractères hex attendus")));
	memcpy(tbp_pending_seal, seal, TBP_SEAL_KEY_LEN);
	tbp_pending_seal_set = true;
	pfree(seal);
	PG_RETURN_BOOL(true);
}

/* tbp_authorize(seal) — insère le sceau dans le cache de décision (D7).
 * Acte de gouvernance : superuser ou tbp.authorizer_role. */
Datum
tbp_authorize(PG_FUNCTION_ARGS)
{
	text	   *arg = PG_GETARG_TEXT_PP(0);
	char	   *seal = text_to_cstring(arg);
	bool		inserted;

	tbp_check_authorizer("tbp_authorize");
	if (!tbp_seal_hex_valid(seal))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("TBP: sceau invalide — 64 caractères hex attendus")));
	inserted = tbp_cache_insert(seal);
	pfree(seal);
	if (!inserted && tbp_seals == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("TBP: cache de décision indisponible — "
						"chargement via shared_preload_libraries requis")));
	if (!inserted)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_RESOURCES),
				 errmsg("TBP: cache de décision saturé (§4.3) — refus fail-closed")));
	PG_RETURN_BOOL(true);
}

/* tbp_cache_count() — observabilité du cache de décision. */
Datum
tbp_cache_count(PG_FUNCTION_ARGS)
{
	int64		n;

	if (tbp_seals == NULL)
		PG_RETURN_INT64(0);
	LWLockAcquire(tbp_lock, LW_SHARED);
	n = (int64) hash_get_num_entries(tbp_seals);
	LWLockRelease(tbp_lock);
	PG_RETURN_INT64(n);
}

/* tbp_forget_all() — révocation locale : vide le cache de décision. */
Datum
tbp_forget_all(PG_FUNCTION_ARGS)
{
	HASH_SEQ_STATUS status;
	TbpSealEntry *entry;

	tbp_check_authorizer("tbp_forget_all");
	if (tbp_seals == NULL)
		PG_RETURN_VOID();
	LWLockAcquire(tbp_lock, LW_EXCLUSIVE);
	hash_seq_init(&status, tbp_seals);
	while ((entry = (TbpSealEntry *) hash_seq_search(&status)) != NULL)
		(void) hash_search(tbp_seals, entry->seal, HASH_REMOVE, NULL);
	LWLockRelease(tbp_lock);
	PG_RETURN_VOID();
}

/* tbp_sha256(text) — exposé pour les tests (vecteurs FIPS) et pour les
 * outils hors bande qui pré-calculent des engagements. */
Datum
tbp_sha256(PG_FUNCTION_ARGS)
{
	text	   *arg = PG_GETARG_TEXT_PP(0);
	unsigned char digest[EVP_MAX_MD_SIZE];
	size_t digest_len = 0;
	char		hex[TBP_SEAL_KEY_LEN];
	int			i;
	static const char hexchars[] = "0123456789abcdef";

	if (EVP_Q_digest(NULL, "SHA256", NULL,
						 VARDATA_ANY(arg), (size_t) VARSIZE_ANY_EXHDR(arg),
						 digest, &digest_len) != 1 || digest_len != 32)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TBP: échec SHA-256")));
	for (i = 0; i < 32; i++)
	{
		hex[i * 2] = hexchars[(digest[i] >> 4) & 0xF];
		hex[i * 2 + 1] = hexchars[digest[i] & 0xF];
	}
	hex[TBP_SEAL_HEX_LEN] = '\0';
	PG_RETURN_TEXT_P(cstring_to_text(hex));
}
