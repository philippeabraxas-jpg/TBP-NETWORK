# T16 — PEP in-process PostgreSQL (§4.4), C natif + PGXS (décision D3).
#
# PostgreSQL 15 ÉPINGLÉ pour le pilote : les signatures de hooks bougent
# entre versions majeures (post_parse_analyze a gagné JumbleState* en 14).
# Construire contre les headers serveur de LA version ciblée :
#
#   make PG_CONFIG=/usr/lib/postgresql/15/bin/pg_config
#   make PG_CONFIG=/usr/lib/postgresql/15/bin/pg_config install
#
# Chargement OBLIGATOIRE via shared_preload_libraries = 'tbp_pg' (le
# cache de décision D7 vit en mémoire partagée), puis :
#
#   CREATE EXTENSION tbp_pg;
#
# Tests d'acceptance (instance jetable créée par le script) :
#
#   PG_CONFIG=/usr/lib/postgresql/15/bin/pg_config sh test/run_tests.sh

MODULE_big = tbp_pg
OBJS = tbp_pg.o
EXTENSION = tbp_pg
DATA = sql/tbp_pg--0.1.sql

# SHA-256 du sceau via OpenSSL (déjà lié au backend PostgreSQL).
SHLIB_LINK += -lcrypto

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
