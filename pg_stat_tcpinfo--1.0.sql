-- pg_stat_tcpinfo--1.0.sql
-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_stat_tcpinfo" to load this file. \quit

CREATE FUNCTION pg_stat_get_tcpinfo(
	OUT pid integer,
	OUT uid integer,
	OUT src_addr inet,
	OUT src_port integer,
	OUT dst_addr inet,
	OUT dst_port integer,
	OUT state text,
	OUT recvq integer,
	OUT sendq integer,
	OUT tcpinfo jsonb
)
RETURNS SETOF record
AS '$libdir/pg_stat_tcpinfo', 'pg_stat_get_tcpinfo'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION pg_stat_get_tcpinfo()
IS 'Shows detailed TCP connection information for sockets owned by the server''s OS user on Linux.';

CREATE VIEW pg_stat_tcpinfo AS
	SELECT * FROM pg_stat_get_tcpinfo();

COMMENT ON VIEW pg_stat_tcpinfo
IS 'Shows detailed TCP connection information for sockets owned by the server''s OS user on Linux.';

-- Functions are executable by PUBLIC by default; this one exposes every TCP
-- connection on the host, so restrict it to the monitoring roles.
REVOKE ALL ON FUNCTION pg_stat_get_tcpinfo() FROM PUBLIC;
-- pg_monitor is a member of pg_read_all_stats and inherits these grants.
GRANT EXECUTE ON FUNCTION pg_stat_get_tcpinfo() TO pg_read_all_stats;
GRANT SELECT ON pg_stat_tcpinfo TO pg_read_all_stats;
