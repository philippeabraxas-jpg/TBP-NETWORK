-- tbp_pg 0.1 — surface SQL de gouvernance (T16, §4.4).
-- Chargement : shared_preload_libraries = 'tbp_pg' puis CREATE EXTENSION tbp_pg.

-- Object-capability §4.4(2) : présente le sceau du jeton avant l'exécution
-- qu'il autorise. Usage unique (consommé match ou non). Tout rôle.
CREATE FUNCTION tbp_present_seal(text)
RETURNS bool
AS 'MODULE_PATHNAME', 'tbp_present_seal'
LANGUAGE C STRICT;

-- Insère un sceau dans le cache de décision (D7). Gouvernance :
-- superuser ou tbp.authorizer_role.
CREATE FUNCTION tbp_authorize(text)
RETURNS bool
AS 'MODULE_PATHNAME', 'tbp_authorize'
LANGUAGE C STRICT;

-- Observabilité : nombre d'entrées du cache de décision.
CREATE FUNCTION tbp_cache_count()
RETURNS bigint
AS 'MODULE_PATHNAME', 'tbp_cache_count'
LANGUAGE C STRICT;

-- Révocation locale : vide le cache de décision. Gouvernance.
CREATE FUNCTION tbp_forget_all()
RETURNS void
AS 'MODULE_PATHNAME', 'tbp_forget_all'
LANGUAGE C STRICT;

-- Utilitaire (tests vecteurs FIPS, pré-calculs hors bande).
CREATE FUNCTION tbp_sha256(text)
RETURNS text
AS 'MODULE_PATHNAME', 'tbp_sha256'
LANGUAGE C STRICT;
