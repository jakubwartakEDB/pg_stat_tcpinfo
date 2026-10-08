# pg_stat_tcpinfo

A Linux-only PostgreSQL extension that exposes `ss`/`netstat`-style TCP
socket details as a view. It reports every TCP socket owned by the OS user
the server runs as, with the kernel's full info (RTT, congestion window,
retransmits, queues, socket memory, timers, congestion control) as
`jsonb`.

Useful for diagnosing slow or stalled client connections, replication links,
and `postgres_fdw`/`dblink` traffic without shell access to the host.

## How it works

1. Scans `/proc/net/tcp` and `/proc/net/tcp6` for sockets owned by the
   server's effective UID.
2. Maps socket inodes to PIDs via `/proc/[PID]/fd`.
3. Fetches per-socket details over the `NETLINK_INET_DIAG` interface.
4. Joins the three and returns one row per socket.

TIME-WAIT sockets are not shown because the kernel keeps no owner for them.

## Requirements

* Linux (uses `/proc` and netlink `sock_diag`), at least 4.18.x to compile/run.

## Install

```sh
export PATH=/path/to/specific/PG/path/VERSION:$PATH
make
sudo make install
```

```sql
CREATE EXTENSION pg_stat_tcpinfo;
```

## Usage

```sql
SELECT pid, src_addr, src_port, dst_addr, dst_port, state, recvq, sendq,
       tcpinfo->>'rtt'        AS rtt_ms,
       tcpinfo->>'congestion' AS cc
FROM pg_stat_tcpinfo
WHERE state = 'ESTABLISHED';
```

Join on `pid` with `pg_stat_activity` to attach TCP metrics to backends:

```sql
SELECT a.pid, a.usename, a.client_addr, t.state,
       t.tcpinfo->>'rtt' AS rtt_ms, t.tcpinfo->>'retrans' AS retrans
FROM pg_stat_activity a
JOIN pg_stat_tcpinfo t ON t.pid = a.pid;
```

## Columns

| Column     | Type    | Description                                              |
|------------|---------|----------------------------------------------------------|
| `pid`      | integer | Owning process                                           |
| `uid`      | integer | OS user ID that owns the socket                          |
| `src_addr` | inet    | Local address                                            |
| `src_port` | integer | Local port                                               |
| `dst_addr` | inet    | Remote address                                           |
| `dst_port` | integer | Remote port                                              |
| `state`    | text    | TCP state (`ESTABLISHED`, `LISTEN`, `CLOSE-WAIT`, ...)   |
| `recvq`    | integer | Receive queue in bytes                                   |
| `sendq`    | integer | Send queue in bytes                                      |
| `tcpinfo`  | jsonb   | Full `struct tcp_info`                                     |

Keys inside `tcpinfo` follow the `tcpi_*` field names without the prefix
(for example `rtt`, `retrans` and so on). 

## Security

The view exposes every TCP connection of the server's OS user, so access is
restricted to `pg_read_all_stats` (and therefore `pg_monitor`) at install
time. Grant it to other roles explicitly if needed.

## License

See [LICENSE](LICENSE).
