/*-------------------------------------------------------------------------
 *
 * pg_stat_tcpinfo.c
 *		A netstat/ss-like Linux-only function and view for PostgreSQL.
 *
 * Copyright (c) 2025-2026, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */

/*
 * It works in four steps:
 * 1. Scans /proc/net/tcp* for the TCP sockets owned by the server's user and
 *    their inode numbers.
 * 2. Scans /proc/[PID]/fd/ directories to map socket inodes to PIDs.
 * 3. Queries the netlink INET_DIAG interface for detailed TCP information
 *    (RTT, queues, memory, timers, congestion control) on those sockets.
 * 4. Joins the three by socket inode and returns one row per socket.
 *
 * Only sockets owned by the OS user the server runs as (its effective UID)
 * are reported.  That covers the postmaster, every backend and auxiliary
 * process, and anything else running under the same account, and it is also
 * exactly the set of processes whose /proc/[PID]/fd directories the server
 * is allowed to read, so the 'pid' column can normally be resolved for every
 * row.  TIME-WAIT entries are not shown: the kernel keeps no owner for them,
 * so they cannot be attributed to any UID.
 */

#include "postgres.h"

#ifndef __linux__
#error "pg_stat_tcpinfo requires Linux: it reads /proc/net/tcp* and uses the NETLINK_INET_DIAG interface"
#endif

#include "fmgr.h"
#include "funcapi.h"
#include "utils/builtins.h"
#include "utils/hsearch.h"
#include "utils/tuplestore.h"
#include "storage/fd.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"

#include <arpa/inet.h>
#include <asm/types.h>
#include <ctype.h>
#include <dirent.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stddef.h>

#include "pg_tcp_info.h"

/* PG_MODULE_MAGIC_EXT, which records the module's own version, is new in 18 */
#ifdef PG_MODULE_MAGIC_EXT
PG_MODULE_MAGIC_EXT(
					.name = "pg_stat_tcpinfo",
					.version = "1.0"
);
#else
PG_MODULE_MAGIC;
#endif

/* Linux kernel TCP states, see linux/include/net/tcp_states.h */
enum
{
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING
};

/* Map of TCP states to strings */
static const char *tcp_states_map[] = {
	[TCP_ESTABLISHED] = "ESTABLISHED",
	[TCP_SYN_SENT] = "SYN-SENT",
	[TCP_SYN_RECV] = "SYN-RECV",
	[TCP_FIN_WAIT1] = "FIN-WAIT-1",
	[TCP_FIN_WAIT2] = "FIN-WAIT-2",
	[TCP_TIME_WAIT] = "TIME-WAIT",
	[TCP_CLOSE] = "CLOSE",
	[TCP_CLOSE_WAIT] = "CLOSE-WAIT",
	[TCP_LAST_ACK] = "LAST-ACK",
	[TCP_LISTEN] = "LISTEN",
	[TCP_CLOSING] = "CLOSING"
};

/* See enum in netinet/tcp.h, TCP_CLOSING seems to be the last one */
#define TCP_MAX_STATE TCP_CLOSING + 1

/* see sock_diag(7) nearby idiag_timer */
static const char *tcptimer_names_map[] = {
	"off",
	"on",
	"keepalive",
	"timewait",
	"persist",					/* zero probe window */
	"unknown"
};

/* There are currently 11 states, but the first state is stored in pos. 1. */
/* Therefore, I need a 12 bit bitmask */
#define TCPF_ALL 0xFFF

/* Kernel limit on congestion control algorithm names (net/tcp.h) */
#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX 16
#endif

/*
 * Netlink socket receive buffer size.  The kernel sizes dump replies to the
 * largest buffer it has seen us read with, capped at 32 KiB, so match that
 * like ss(8) does.
 */
#define NL_SOCKET_BUFFER_SIZE 32768

/* Stores stuff from /proc/net/tcp */
typedef struct TcpConnection
{
	char		local_ip_str[INET6_ADDRSTRLEN]; /* IP */
	char		remote_ip_str[INET6_ADDRSTRLEN];	/* IP */
	int			local_port;
	int			remote_port;
	int			state;
	int			uid;
	unsigned long long inode;
	struct TcpConnection *next;
}			TcpConnection;

typedef struct InodePid
{
	unsigned long long inode;
	int			pid;
}			InodePid;

typedef struct NlDiagInfo
{
	unsigned long long inode;	/* hash key = socket inode (idiag_inode) */
	struct pg_tcp_info tcpi;
	size_t		tcpi_len;		/* how many bytes the kernel filled copied
								 * into tcpi */
	__u32		skmem[SK_MEMINFO_VARS];

	char		cong[TCP_CA_NAME_MAX + 1];
	int			has_tcpi;
	int			has_skmem;
	int			has_cong;
	struct tcp_bbr_info bbr;
	int			has_bbr;
	struct tcpvegas_info vegas;
	int			has_vegas;
	char		tcp_timer_str[64];
	__u32		rqueue;			/* idiag_rqueue */
	__u32		wqueue;			/* idiag_wqueue */
}			NlDiagInfo;

/* insert inode+PID into the hash map */
static void
insert_pid(HTAB *pid_map, unsigned long long inode, int pid)
{
	InodePid   *entry;
	bool		found;

	entry = (InodePid *) hash_search(pid_map, &inode, HASH_ENTER, &found);
	entry->pid = pid;
}

/* locate PID in the hash map given an inode : return pid or -1 */
static int
find_pid(HTAB *pid_map, unsigned long long inode)
{
	InodePid   *entry;

	entry = (InodePid *) hash_search(pid_map, &inode, HASH_FIND, NULL);
	if (entry)
		return entry->pid;

	return -1;
}

/*
 * Look up the netlink entry for a socket by its inode (both /proc/net/tcp*
 * and inet_diag have it unique).
 *
 * When create==true, if it is missing create it.
 */
static NlDiagInfo *
lookup_netlink_info(HTAB *nldiag_map, unsigned long long inode, bool create)
{
	NlDiagInfo *entry;
	bool		found = false;

	entry = (NlDiagInfo *) hash_search(nldiag_map, &inode,
									   create ? HASH_ENTER : HASH_FIND, &found);
	elog(DEBUG5, "nldiag_map lookup of inode %llu --> %p (found=%d)", inode, entry, found);

	if (entry && create && !found)
	{
		/*
		 * New entry. hash_search() copied the key, but the rest of the struct
		 * is uninitialized.  Zero the payload.
		 */
		memset((char *) entry + offsetof(NlDiagInfo, tcpi), 0,
			   sizeof(NlDiagInfo) - offsetof(NlDiagInfo, tcpi));
	}

	return entry;
}

/*
 * See sock_diag(7)
 */
static int
send_diag_msg(int sockfd, __u8 family)
{
	struct msghdr msg;
	struct nlmsghdr nlh;
	struct inet_diag_req_v2 conn_req;
	struct sockaddr_nl sa;
	struct iovec iov[2];

	elog(DEBUG1, "quering netlink socket for low-level TCP stats");

	memset(&msg, 0, sizeof(msg));
	memset(&sa, 0, sizeof(sa));
	memset(&nlh, 0, sizeof(nlh));
	memset(&conn_req, 0, sizeof(conn_req));

	sa.nl_family = AF_NETLINK;
	conn_req.sdiag_family = family;
	conn_req.sdiag_protocol = IPPROTO_TCP;

	/* Dump TCP flags too */
	conn_req.idiag_states = TCPF_ALL;

	/* Dump extended information too */
	conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
	conn_req.idiag_ext |= (1 << (INET_DIAG_SKMEMINFO - 1));
	conn_req.idiag_ext |= (1 << (INET_DIAG_CONG - 1));

	/* Dump BBR and VEGAS congestion data too */
	conn_req.idiag_ext |= (1 << (INET_DIAG_VEGASINFO - 1));

	nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
	nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	iov[0].iov_base = (void *) &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = (void *) &conn_req;
	iov[1].iov_len = sizeof(conn_req);

	msg.msg_name = (void *) &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	return sendmsg(sockfd, &msg, 0);
}

/* Mimic ss utility time formatting, e.g. "1min30sec" */
static const char *
print_ms_timer(unsigned int timeout)
{
	static char buf[64];
	int			secs,
				msecs,
				minutes;

	secs = timeout / 1000;
	minutes = secs / 60;
	secs = secs % 60;
	msecs = timeout % 1000;
	buf[0] = 0;
	if (minutes)
	{
		msecs = 0;
		snprintf(buf, sizeof(buf) - 16, "%dmin", minutes);
		if (minutes > 9)
			secs = 0;
	}
	if (secs)
	{
		if (secs > 9)
			msecs = 0;
		sprintf(buf + strlen(buf), "%d%s", secs, msecs ? "." : "sec");
	}
	if (msecs)
		sprintf(buf + strlen(buf), "%03d%s", msecs, secs ? "sec" : "ms");
	return buf;
}


static void
parse_diag_msg(HTAB *nldiag_map, struct inet_diag_msg *diag_msg, int rtalen,
			   uid_t my_uid)
{
	struct rtattr *attr;
	char		tcp_timer_str[64];
	unsigned int timer_idx;
	NlDiagInfo *entry;

	/* Show just socket state for our UIDs */
	if (diag_msg->idiag_uid != (__u32) my_uid || diag_msg->idiag_inode == 0)
		return;

	timer_idx = diag_msg->idiag_timer;
	if (timer_idx == 0)
		tcp_timer_str[0] = '\0';
	else
	{
		if (timer_idx >= lengthof(tcptimer_names_map))
			timer_idx = lengthof(tcptimer_names_map) - 1;
		snprintf(tcp_timer_str, sizeof(tcp_timer_str), "%s,%s,%d",
				 tcptimer_names_map[timer_idx],
				 print_ms_timer(diag_msg->idiag_expires),
				 diag_msg->idiag_retrans);
	}

	entry = lookup_netlink_info(nldiag_map, diag_msg->idiag_inode, true);
	memcpy(entry->tcp_timer_str, tcp_timer_str, sizeof(entry->tcp_timer_str));
	entry->rqueue = diag_msg->idiag_rqueue;
	entry->wqueue = diag_msg->idiag_wqueue;

	/* Loop over attributes returned by kernel */
	if (rtalen > 0)
	{
		attr = (struct rtattr *) (diag_msg + 1);

		while (RTA_OK(attr, rtalen))
		{
			size_t		len = RTA_PAYLOAD(attr);

			switch (attr->rta_type)
			{
				case INET_DIAG_INFO:
					memset(&entry->tcpi, 0, sizeof(entry->tcpi));
					memcpy(&entry->tcpi, RTA_DATA(attr), Min(len, sizeof(entry->tcpi)));
					entry->tcpi_len = len;
					entry->has_tcpi = 1;
					break;
				case INET_DIAG_SKMEMINFO:
					memset(entry->skmem, 0, sizeof(entry->skmem));
					memcpy(entry->skmem, RTA_DATA(attr), Min(len, sizeof(entry->skmem)));
					entry->has_skmem = 1;
					break;
				case INET_DIAG_CONG:
					{
						size_t		n = Min(len, sizeof(entry->cong) - 1);

						memcpy(entry->cong, RTA_DATA(attr), n);
						entry->cong[n] = '\0';
						entry->has_cong = 1;
						break;
					}
				case INET_DIAG_BBRINFO:
					memset(&entry->bbr, 0, sizeof(entry->bbr));
					memcpy(&entry->bbr, RTA_DATA(attr), Min(len, sizeof(entry->bbr)));
					entry->has_bbr = 1;
					break;
				case INET_DIAG_VEGASINFO:
					memset(&entry->vegas, 0, sizeof(entry->vegas));
					memcpy(&entry->vegas, RTA_DATA(attr), Min(len, sizeof(entry->vegas)));
					entry->has_vegas = 1;
					break;
				default:
					/* other attributes (meminfo, shutdown, ...) are not used */
					break;
			}

			attr = RTA_NEXT(attr, rtalen);
		}
	}
}


/* If kernel is too old, we just return "null" */
static void
append_tcpi_field(StringInfo buf, const char *key, bool present, uint64 value)
{
	if (present)
		appendStringInfo(buf, ", \"%s\": " UINT64_FORMAT, key, value);
	else
		appendStringInfo(buf, ", \"%s\": null", key);
}


/*
 * Scans all /proc/[PID]/fd/ entries to map socket inodes to PIDs. Fill
 * the provided pid_map hash table.
 */
static void
scan_proc_fds(HTAB *pid_map)
{
	DIR		   *proc_dir,
			   *fd_dir;
	struct dirent *pid_entry,
			   *fd_entry;
	char		fd_path[MAXPGPATH];
	char		link_path[MAXPGPATH];
	char		link_target[MAXPGPATH];
	ssize_t		link_len;
	unsigned long long inode;

	elog(DEBUG1, "scanning /proc for PIDs");

	/*
	 * Use the resource-owner tracked directory routines so that an ERROR
	 * raised while scanning, e.g. a query cancel, cannot leak descriptors.
	 */
	proc_dir = AllocateDir("/proc");
	if (!proc_dir)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open directory \"%s\": %m", "/proc")));

	/* Iterate over each entry in /proc */
	while ((pid_entry = ReadDir(proc_dir, "/proc")) != NULL)
	{
		CHECK_FOR_INTERRUPTS();

		/* Check if the directory name is a number (a PID) */
		if (pid_entry->d_type == DT_DIR && isdigit((unsigned char) pid_entry->d_name[0]))
		{
			int			pid = atoi(pid_entry->d_name);

			snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
			fd_dir = AllocateDir(fd_path);
			if (!fd_dir)
			{
				if (errno != EACCES && errno != EPERM)
					ereport(DEBUG4,
							(errcode_for_file_access(),
							 errmsg("could not open directory \"%s\": %m", fd_path)));
				continue;
			}

			/*
			 * Iterate over each file descriptor in /proc/[PID]/fd (read
			 * symlink)
			 */
			while ((fd_entry = ReadDirExtended(fd_dir, fd_path, DEBUG4)) != NULL)
			{
				if (strcmp(fd_entry->d_name, ".") || strcmp(fd_entry->d_name, ".."))
					continue;

				snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
				link_len = readlink(link_path, link_target, sizeof(link_target) - 1);
				/* Ignore symlinks we cannot read */
				if (link_len == -1)
					continue;
				link_target[link_len] = '\0';

				/* special symlink */
				if (strncmp(link_target, "socket:[", strlen("socket:[")) == 0)
				{
					if (sscanf(link_target, "socket:[%llu]", &inode) == 1)
					{
						/* Add this inode->PID mapping to our hash table */
						insert_pid(pid_map, inode, pid);
					}
				}
			}
			FreeDir(fd_dir);
		}
	}
	FreeDir(proc_dir);
}


/*
 * Reads /proc/net/tcp* and builds a linked list of connections.
 * Returns pointer to the head of the TcpConnection linked list.
 */
static TcpConnection * read_tcp_connections(__u8 family)
{
	FILE	   *fp;
	char		line[1024],
			   *tcp_file_name;
	TcpConnection *head = NULL;
	int			local_port,
				remote_port,
				state,
				uid;
	uint32		local_ip_hex,
				remote_ip_hex;
	struct in6_addr local_ip6_hex,
				remote_ip6_hex;
	unsigned long long inode;
	TcpConnection *conn;
	uid_t		my_uid = geteuid();

	tcp_file_name = family == AF_INET ? "/proc/net/tcp" : "/proc/net/tcp6";
	elog(DEBUG1, "scanning %s for TCP connections and inodes", tcp_file_name);

	fp = AllocateFile(tcp_file_name, "r");
	if (fp == NULL)
	{
		/* /proc/net/tcp6 might not exist and that is fine */
		if (errno == ENOENT && family == AF_INET6)
		{
			elog(DEBUG1, "%s does not exist, assuming no IPv6 support", tcp_file_name);
			return NULL;
		}

		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open %s: %m", tcp_file_name)));
		return NULL;
	}

	/* Skip the header line */
	if (fgets(line, sizeof(line), fp) == NULL)
	{
		FreeFile(fp);
		ereport(ERROR,
				(errcode(ERRCODE_IO_ERROR),
				 errmsg("could not read header from %s", tcp_file_name)));
		return NULL;
	}

	/* Read each line */
	while (fgets(line, sizeof(line), fp) != NULL)
	{
		int			num_matched,
					proper_matches;

		CHECK_FOR_INTERRUPTS();

		if (family == AF_INET)
		{
			num_matched = sscanf(line, "%*d: %08X:%04X %08X:%04X %02X %*s %*s %*s %d %*s %llu",
								 &local_ip_hex, &local_port, &remote_ip_hex, &remote_port, &state, &uid, &inode);
			proper_matches = 7;
		}
		else
		{
			/*
			 * Madness? This ... is ... sparta!
			 *
			 * /proc files for IPv6 tend to use 32-char hex representation of
			 * IPv6 address
			 */
			num_matched = sscanf(line, "%*d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X %02X %*s %*s %*s %d %*s %llu",
								 &local_ip6_hex.s6_addr32[0],
								 &local_ip6_hex.s6_addr32[1],
								 &local_ip6_hex.s6_addr32[2],
								 &local_ip6_hex.s6_addr32[3],
								 &local_port,
								 &remote_ip6_hex.s6_addr32[0],
								 &remote_ip6_hex.s6_addr32[1],
								 &remote_ip6_hex.s6_addr32[2],
								 &remote_ip6_hex.s6_addr32[3],
								 &remote_port,
								 &state,
								 &uid,
								 &inode);
			proper_matches = 13;
		}

		if (num_matched < proper_matches)
		{
			/* Failed to parse, so chomp last new line character and show it */
			line[strlen(line) - 1] = 0;
			ereport(WARNING, (errmsg("failed to parse line from %s (got just %d matches): %s", tcp_file_name, num_matched, line)));
			continue;
		}

		/* Report only sockets owned by the user the server runs as */
		if ((uid_t) uid != my_uid)
			continue;

		conn = palloc(sizeof(TcpConnection));
		conn->local_port = local_port;
		conn->remote_port = remote_port;

		/* Convert to network byte order */
		if (family == AF_INET)
		{
			if (inet_ntop(AF_INET, &local_ip_hex, conn->local_ip_str, sizeof(conn->local_ip_str)) == NULL ||
				inet_ntop(AF_INET, &remote_ip_hex, conn->remote_ip_str, sizeof(conn->remote_ip_str)) == NULL)
				elog(ERROR, "inet_ntop() failed: %m");
		}
		else
		{
			if (inet_ntop(AF_INET6, &local_ip6_hex, conn->local_ip_str, sizeof(conn->local_ip_str)) == NULL ||
				inet_ntop(AF_INET6, &remote_ip6_hex, conn->remote_ip_str, sizeof(conn->remote_ip_str)) == NULL)
				elog(ERROR, "inet_ntop() failed: %m");
		}

		conn->state = state;
		conn->uid = uid;
		conn->inode = inode;

		/* Put as head of the linked list */
		conn->next = head;
		head = conn;
	}

	FreeFile(fp);
	return head;
}


/* Receive and parse all netlink data, populating nldiag_map */
static void
recv_diag_msgs(int nl_sock, HTAB *nldiag_map, uid_t my_uid)
{
	uint8_t		recv_buf[NL_SOCKET_BUFFER_SIZE];
	ssize_t		numbytes;
	int			done = 0,
				rtalen = 0;
	struct inet_diag_msg *diag_msg;
	struct nlmsghdr *nlh;

	while (!done)
	{
		/*
		 * With MSG_TRUNC, recv() on a netlink socket returns the full length
		 * of the datagram even when it did not fit in our buffer, so we can
		 * detect a truncated dump instead of silently dropping the tail.
		 */
		numbytes = recv(nl_sock, recv_buf, sizeof(recv_buf), MSG_TRUNC);
		if (numbytes < 0)
		{
			int			save_errno = errno;

			close(nl_sock);
			errno = save_errno;
			ereport(ERROR,
					(errcode(ERRCODE_IO_ERROR),
					 errmsg("could not receive netlink message: %m")));
		}
		if (numbytes == 0)
		{
			close(nl_sock);
			ereport(ERROR,
					(errcode(ERRCODE_IO_ERROR),
					 errmsg("netlink socket closed prematurely")));
		}
		if ((size_t) numbytes > sizeof(recv_buf))
		{
			close(nl_sock);
			ereport(ERROR,
					(errcode(ERRCODE_IO_ERROR),
					 errmsg("netlink message of %zd bytes exceeds receive buffer of %zu bytes",
							numbytes, sizeof(recv_buf))));
		}

		nlh = (struct nlmsghdr *) recv_buf;

		while (NLMSG_OK(nlh, numbytes))
		{
			if (nlh->nlmsg_type == NLMSG_DONE)
			{
				done = 1;
				break;
			}

			if (nlh->nlmsg_type == NLMSG_ERROR)
			{
				struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(nlh);
				int			nl_errno = -err->error;

				close(nl_sock);
				ereport(ERROR,
						(errcode(ERRCODE_IO_ERROR),
						 errmsg("error in netlink message: %s", strerror(nl_errno))));
			}

			diag_msg = (struct inet_diag_msg *) NLMSG_DATA(nlh);
			rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));

			/* Populate nldiag_map */
			parse_diag_msg(nldiag_map, diag_msg, rtalen, my_uid);

			nlh = NLMSG_NEXT(nlh, numbytes);
		}
	}
}


PG_FUNCTION_INFO_V1(pg_stat_get_tcpinfo);
Datum
pg_stat_get_tcpinfo(PG_FUNCTION_ARGS)
{
	Datum		values[10];
	bool		nulls[10];
	HTAB	   *pid_map;
	MemoryContext oldcontext;
	MemoryContext per_query_ctx;
	NlDiagInfo *diag_info;
	HTAB	   *nldiag_map;
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	StringInfoData json_buf;
	TcpConnection *tcp_connections;
	TcpConnection *current;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	__u32	   *skmem,
				recvq = 0,
				sendq = 0;
	bool		has_data;
	const char *state_str;
	int			nl_sock = 0,
				pid;
	HASHCTL		ctl;
	uid_t		my_uid = geteuid();

	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;
	MemoryContextSwitchTo(oldcontext);

	/*
	 * Allocate the hash maps as children of CurrentMemoryContext so they are
	 * released with the per-call context, including on error.  Without
	 * HASH_CONTEXT dynahash would parent them to TopMemoryContext and they
	 * would leak for the life of the backend.
	 */
	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(unsigned long long);
	ctl.entrysize = sizeof(InodePid);
	ctl.hcxt = CurrentMemoryContext;
	pid_map = hash_create("Inode to PID Map", 1024, &ctl,
						  HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(unsigned long long);
	ctl.entrysize = sizeof(NlDiagInfo);
	ctl.hcxt = CurrentMemoryContext;
	nldiag_map = hash_create("Netlink Diag Map", 1024, &ctl,
							 HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	/* Load the inode->PID hash map while scanning /proc/PIDs */
	scan_proc_fds(pid_map);

	/* Read all TCP connections from /proc/net/tcp (IPv4) */
	tcp_connections = read_tcp_connections(AF_INET);

	/*
	 * Append the IPv6 connections from /proc/net/tcp6.  The IPv4 list may be
	 * empty on an IPv6-only host, in which case the IPv6 list becomes the
	 * whole result.
	 */
	if (tcp_connections == NULL)
		tcp_connections = read_tcp_connections(AF_INET6);
	else
	{
		current = tcp_connections;
		while (current->next != NULL)
			current = current->next;
		current->next = read_tcp_connections(AF_INET6);
	}

	if (tcp_connections == NULL)
		PG_RETURN_VOID();

	/* Open netlink */
	if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1)
	{
		ereport(ERROR, (errcode(ERRCODE_IO_ERROR),
						errmsg("could not create netlink socket: %m")));
	}

	/* IPv4 netlink message */
	if (send_diag_msg(nl_sock, AF_INET) < 0)
	{
		close(nl_sock);
		ereport(ERROR, (errcode(ERRCODE_IO_ERROR),
						errmsg("could not send AF_INET netlink message: %m")));
	}
	recv_diag_msgs(nl_sock, nldiag_map, my_uid);

	/* IPv6 netlink message */
	if (send_diag_msg(nl_sock, AF_INET6) < 0)
	{
		close(nl_sock);
		ereport(ERROR, (errcode(ERRCODE_IO_ERROR),
						errmsg("could not send AF_INET6 netlink message: %m")));
	}

	recv_diag_msgs(nl_sock, nldiag_map, my_uid);
	close(nl_sock);

	/* Start populating the main result */
	initStringInfo(&json_buf);

	/* For each TCP connection from linked list: */
	current = tcp_connections;
	while (current != NULL)
	{
		int			i = 0;

		CHECK_FOR_INTERRUPTS();

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		/* pid */
		pid = find_pid(pid_map, current->inode);
		if (pid == -1)
			nulls[i++] = true;
		else
			values[i++] = Int32GetDatum(pid);

		/* uid (always the server's own, see read_tcp_connections()) */
		values[i++] = Int32GetDatum(current->uid);

		/* local ip */
		values[i++] = DirectFunctionCall1(inet_in, CStringGetDatum(current->local_ip_str));

		/* local port */
		values[i++] = Int32GetDatum(current->local_port);

		/* remote ip */
		values[i++] = DirectFunctionCall1(inet_in, CStringGetDatum(current->remote_ip_str));

		/* remote port */
		values[i++] = Int32GetDatum(current->remote_port);

		/* state */
		state_str = "UNKNOWN";
		if (current->state > 0 && current->state < TCP_MAX_STATE)
			state_str = tcp_states_map[current->state];
		values[i++] = CStringGetTextDatum(state_str);

		/* build big JSON with detailed information */
		resetStringInfo(&json_buf);
		appendStringInfoChar(&json_buf, '{');
		has_data = false;

		diag_info = lookup_netlink_info(nldiag_map, current->inode, false);
		if (diag_info)
		{
			/* add TCP timer information, if a timer is pending */
			if (diag_info->tcp_timer_str[0] != '\0')
			{
				appendStringInfo(&json_buf, "\"timer\": \"(%s)\"", diag_info->tcp_timer_str);
				has_data = true;
			}

			/* Recv-Q and Send-Q */
			recvq = diag_info->rqueue;
			sendq = diag_info->wqueue;

			/* add low-level TCP stats */
			if (diag_info->has_tcpi)
			{
				struct pg_tcp_info *tcpi = &diag_info->tcpi;
				size_t		tcpi_len = diag_info->tcpi_len;

				if (has_data)
					appendStringInfoString(&json_buf, ", ");

				/* ss(1) style! */
				appendStringInfo(&json_buf,
								 "\"rtt\": %.3f, "
								 "\"rttvar\": %.3f, "
								 "\"rcv_rtt\": %.3f, "
								 "\"unacked\": %u, "
								 "\"snd_cwnd\": %u, "
								 "\"sndbuf_limited\": %.3f, "
								 "\"rwnd_limited\": %.3f, "
								 "\"state\": %u, "
								 "\"ca_state\": %u, "
								 "\"retransmits\": %u, "
								 "\"probes\": %u, "
								 "\"backoff\": %u, "
								 "\"options\": %u, "
								 "\"snd_wscale\": %u, "
								 "\"rcv_wscale\": %u, "
								 "\"rto\": %.3f, "
								 "\"ato\": %.3f, "
								 "\"snd_mss\": %u, "
								 "\"rcv_mss\": %u, "
								 "\"sacked\": %u, "
								 "\"lost\": %u, "
								 "\"retrans\": %u, "
								 "\"fackets\": %u, "
								 "\"last_data_sent\": %u, "
								 "\"last_ack_sent\": %u, "
								 "\"last_data_recv\": %u, "
								 "\"last_ack_recv\": %u, "
								 "\"pmtu\": %u, "
								 "\"rcv_ssthresh\": %u, "
								 "\"snd_ssthresh\": %u, "
								 "\"advmss\": %u, "
								 "\"reordering\": %u, "
								 "\"rcv_space\": %u, "
								 "\"total_retrans\": %u, "
								 "\"segs_out\": %u, "
								 "\"segs_in\": %u, "
								 "\"notsent_bytes\": %u, "
								 "\"min_rtt\": %.3f, "
								 "\"data_segs_in\": %u, "
								 "\"data_segs_out\": %u, "
								 "\"bytes_acked\": %llu, "
								 "\"bytes_received\": %llu, "
								 "\"busy_time\": %.3f",
								 (double) tcpi->tcpi_rtt / 1000.0,
								 (double) tcpi->tcpi_rttvar / 1000.0,
								 (double) tcpi->tcpi_rcv_rtt / 1000.0,
								 tcpi->tcpi_unacked,
								 tcpi->tcpi_snd_cwnd,
								 (double) tcpi->tcpi_sndbuf_limited / 1000.0,
								 (double) tcpi->tcpi_rwnd_limited / 1000.0,
								 tcpi->tcpi_state,
								 tcpi->tcpi_ca_state,
								 tcpi->tcpi_retransmits,
								 tcpi->tcpi_probes,
								 tcpi->tcpi_backoff,
								 tcpi->tcpi_options,
								 tcpi->tcpi_snd_wscale,
								 tcpi->tcpi_rcv_wscale,
								 (double) tcpi->tcpi_rto / 1000.0,
								 (double) tcpi->tcpi_ato / 1000.0,
								 tcpi->tcpi_snd_mss,
								 tcpi->tcpi_rcv_mss,
								 tcpi->tcpi_sacked,
								 tcpi->tcpi_lost,
								 tcpi->tcpi_retrans,
								 tcpi->tcpi_fackets,
								 tcpi->tcpi_last_data_sent,
								 tcpi->tcpi_last_ack_sent,
								 tcpi->tcpi_last_data_recv,
								 tcpi->tcpi_last_ack_recv,
								 tcpi->tcpi_pmtu,
								 tcpi->tcpi_rcv_ssthresh,
								 tcpi->tcpi_snd_ssthresh,
								 tcpi->tcpi_advmss,
								 tcpi->tcpi_reordering,
								 tcpi->tcpi_rcv_space,
								 tcpi->tcpi_total_retrans,
								 tcpi->tcpi_segs_out,
								 tcpi->tcpi_segs_in,
								 tcpi->tcpi_notsent_bytes,
								 (double) tcpi->tcpi_min_rtt / 1000.0,
								 tcpi->tcpi_data_segs_in,
								 tcpi->tcpi_data_segs_out,
								 tcpi->tcpi_bytes_acked,
								 tcpi->tcpi_bytes_received,
								 (double) tcpi->tcpi_busy_time / 1000.0
					);

				/* Fields added after the oldest supported kernel (4.18.x) */
				append_tcpi_field(&json_buf, "delivered",
								  TCPI_HAS(tcpi_len, tcpi_delivered),
								  tcpi->tcpi_delivered);
				append_tcpi_field(&json_buf, "delivered_ce",
								  TCPI_HAS(tcpi_len, tcpi_delivered_ce),
								  tcpi->tcpi_delivered_ce);
				append_tcpi_field(&json_buf, "bytes_sent",
								  TCPI_HAS(tcpi_len, tcpi_bytes_sent),
								  tcpi->tcpi_bytes_sent);
				append_tcpi_field(&json_buf, "bytes_retrans",
								  TCPI_HAS(tcpi_len, tcpi_bytes_retrans),
								  tcpi->tcpi_bytes_retrans);
				append_tcpi_field(&json_buf, "dsack_dups",
								  TCPI_HAS(tcpi_len, tcpi_dsack_dups),
								  tcpi->tcpi_dsack_dups);
				append_tcpi_field(&json_buf, "reord_seen",
								  TCPI_HAS(tcpi_len, tcpi_reord_seen),
								  tcpi->tcpi_reord_seen);
				append_tcpi_field(&json_buf, "rcv_ooopack",
								  TCPI_HAS(tcpi_len, tcpi_rcv_ooopack),
								  tcpi->tcpi_rcv_ooopack);
				append_tcpi_field(&json_buf, "snd_wnd",
								  TCPI_HAS(tcpi_len, tcpi_snd_wnd),
								  tcpi->tcpi_snd_wnd);
				append_tcpi_field(&json_buf, "rcv_wnd",
								  TCPI_HAS(tcpi_len, tcpi_rcv_wnd),
								  tcpi->tcpi_rcv_wnd);
				append_tcpi_field(&json_buf, "rehash",
								  TCPI_HAS(tcpi_len, tcpi_rehash),
								  tcpi->tcpi_rehash);
				append_tcpi_field(&json_buf, "total_rto",
								  TCPI_HAS(tcpi_len, tcpi_total_rto),
								  tcpi->tcpi_total_rto);
				append_tcpi_field(&json_buf, "total_rto_recoveries",
								  TCPI_HAS(tcpi_len, tcpi_total_rto_recoveries),
								  tcpi->tcpi_total_rto_recoveries);
				append_tcpi_field(&json_buf, "total_rto_time",
								  TCPI_HAS(tcpi_len, tcpi_total_rto_time),
								  tcpi->tcpi_total_rto_time);

				if (tcpi->tcpi_pacing_rate == ~0ULL)
					appendStringInfoString(&json_buf, ", \"pacing_rate\": null");
				else
					appendStringInfo(&json_buf, ", \"pacing_rate\": %llu",
									 (unsigned long long) tcpi->tcpi_pacing_rate * 8);

				if (tcpi->tcpi_max_pacing_rate == ~0ULL)
					appendStringInfoString(&json_buf, ", \"max_pacing_rate\": null");
				else
					appendStringInfo(&json_buf, ", \"max_pacing_rate\": %llu",
									 (unsigned long long) tcpi->tcpi_max_pacing_rate * 8);

				if (tcpi->tcpi_delivery_rate == 0)
					appendStringInfoString(&json_buf, ", \"delivery_rate\": null");
				else
					appendStringInfo(&json_buf, ", \"delivery_rate\": %llu",
									 (unsigned long long) tcpi->tcpi_delivery_rate * 8);

				/*
				 * ss(1) prints "app_limited" string when the most recent
				 * delivery-rate sample was limited by the application
				 */
				appendStringInfo(&json_buf, ", \"app_limited\": %s",
								 tcpi->tcpi_delivery_rate_app_limited ? "true" : "false");

				has_data = true;
			}

			/* add detailed TCP buffer sizes as seen by the kerne */
			if (diag_info->has_skmem)
			{
				if (has_data)
					appendStringInfoString(&json_buf, ", ");
				skmem = diag_info->skmem;
				appendStringInfo(&json_buf,
								 "\"skmem\": {\"rmem_alloc\": %u, \"rcvbuf\": %u, \"wmem_alloc\": %u, \"sndbuf\": %u, \"fwd_alloc\": %u, \"wmem_queued\": %u, \"optmem\": %u}",
								 skmem[SK_MEMINFO_RMEM_ALLOC],
								 skmem[SK_MEMINFO_RCVBUF],
								 skmem[SK_MEMINFO_WMEM_ALLOC],
								 skmem[SK_MEMINFO_SNDBUF],
								 skmem[SK_MEMINFO_FWD_ALLOC],
								 skmem[SK_MEMINFO_WMEM_QUEUED],
								 skmem[SK_MEMINFO_OPTMEM]);

				has_data = true;
			}

			/* also add TCP congestion used for the connection */
			if (diag_info->has_cong)
			{
				if (has_data)
					appendStringInfoString(&json_buf, ", ");

				/* Check TCP_CONGESTION in tcp(7) */
				appendStringInfo(&json_buf, "\"congestion\": \"%s\"", diag_info->cong);

				has_data = true;
			}

			/* BBR */
			if (diag_info->has_bbr)
			{
				struct tcp_bbr_info *bbr = &diag_info->bbr;
				unsigned long long bw = ((unsigned long long) bbr->bbr_bw_hi << 32) | bbr->bbr_bw_lo;

				bw *= 8;		/* bits per second, as per ss */

				if (has_data)
					appendStringInfoString(&json_buf, ", ");

				appendStringInfo(&json_buf,
								 "\"bbr\": {\"bw\": %llu, \"min_rtt\": %.3f, \"pacing_gain\": %.3f, \"cwnd_gain\": %.3f}",
								 bw,
								 (double) bbr->bbr_min_rtt / 1000.0,
								 (double) bbr->bbr_pacing_gain / 256.0,
								 (double) bbr->bbr_cwnd_gain / 256.0);

				has_data = true;
			}

			/* VEGAS, but also reported for others (mainly RTT) */
			if (diag_info->has_vegas)
			{
				struct tcpvegas_info *vegas = &diag_info->vegas;

				if (has_data)
					appendStringInfoString(&json_buf, ", ");

				appendStringInfo(&json_buf,
								 "\"vegas\": {\"enabled\": %u, \"rtt_cnt\": %u, ",
								 vegas->tcpv_enabled,
								 vegas->tcpv_rttcnt);
				if (vegas->tcpv_rtt == 0 || vegas->tcpv_rtt == 0x7fffffff)
					appendStringInfoString(&json_buf, "\"rtt\": null, ");
				else
					appendStringInfo(&json_buf, "\"rtt\": %.3f, ",
									 (double) vegas->tcpv_rtt / 1000.0);
				if (vegas->tcpv_minrtt == 0 || vegas->tcpv_minrtt == 0x7fffffff)
					appendStringInfoString(&json_buf, "\"min_rtt\": null}");
				else
					appendStringInfo(&json_buf, "\"min_rtt\": %.3f}",
									 (double) vegas->tcpv_minrtt / 1000.0);

				has_data = true;
			}
		}
		appendStringInfoChar(&json_buf, '}');

		if (diag_info == NULL)
		{
			nulls[i++] = true;
			nulls[i++] = true;
		}
		else
		{
			values[i++] = Int32GetDatum(recvq);
			values[i++] = Int32GetDatum(sendq);
		}

		if (!has_data)
			nulls[i++] = true;
		else
			values[i++] = DirectFunctionCall1(jsonb_in, CStringGetDatum(json_buf.data));

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);

		current = current->next;
	}

	PG_RETURN_VOID();
}
