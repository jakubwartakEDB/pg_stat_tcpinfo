MODULES = pg_stat_tcpinfo

EXTENSION = pg_stat_tcpinfo
DATA = pg_stat_tcpinfo--1.0.sql
PGFILEDESC = "pg_stat_tcpinfo - detailed TCP connection information on Linux"

# Use pg_config to find the PGXS makefile
PG_CONFIG = pg_config
PGXS = $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
