/*-------------------------------------------------------------------------
 *
 * pg_tcp_info.h
 *		Private copy of the Linux struct tcp_info.
 *
 * This is struct tcp_info from the Linux 6.17 UAPI header linux/tcp.h,
 * renamed so that it cannot clash with the definitions in linux/tcp.h or
 * netinet/tcp.h. The kernel headers only ever appends fields to struct
 * tcp_info, so when running older kernels may lack those fields in runtime,
 * but that's OK. The kernel reports - with getsockopt() - how many bytes
 * it copied into struct, so we just assume stuff is "null" if that was not
 * populated.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_TCP_INFO_H
#define PG_TCP_INFO_H

#include <stddef.h>
#include <linux/types.h>

struct pg_tcp_info
{
	__u8		tcpi_state;
	__u8		tcpi_ca_state;
	__u8		tcpi_retransmits;
	__u8		tcpi_probes;
	__u8		tcpi_backoff;
	__u8		tcpi_options;
	__u8		tcpi_snd_wscale:4,
				tcpi_rcv_wscale:4;
	__u8		tcpi_delivery_rate_app_limited:1,
				tcpi_fastopen_client_fail:2;

	__u32		tcpi_rto;
	__u32		tcpi_ato;
	__u32		tcpi_snd_mss;
	__u32		tcpi_rcv_mss;

	__u32		tcpi_unacked;
	__u32		tcpi_sacked;
	__u32		tcpi_lost;
	__u32		tcpi_retrans;
	__u32		tcpi_fackets;

	__u32		tcpi_last_data_sent;
	__u32		tcpi_last_ack_sent;
	__u32		tcpi_last_data_recv;
	__u32		tcpi_last_ack_recv;

	__u32		tcpi_pmtu;
	__u32		tcpi_rcv_ssthresh;
	__u32		tcpi_rtt;
	__u32		tcpi_rttvar;
	__u32		tcpi_snd_ssthresh;
	__u32		tcpi_snd_cwnd;
	__u32		tcpi_advmss;
	__u32		tcpi_reordering;

	__u32		tcpi_rcv_rtt;
	__u32		tcpi_rcv_space;

	__u32		tcpi_total_retrans;

	__u64		tcpi_pacing_rate;
	__u64		tcpi_max_pacing_rate;
	__u64		tcpi_bytes_acked;
	__u64		tcpi_bytes_received;
	__u32		tcpi_segs_out;
	__u32		tcpi_segs_in;

	__u32		tcpi_notsent_bytes;
	__u32		tcpi_min_rtt;
	__u32		tcpi_data_segs_in;
	__u32		tcpi_data_segs_out;

	__u64		tcpi_delivery_rate;

	__u64		tcpi_busy_time;
	__u64		tcpi_rwnd_limited;
	__u64		tcpi_sndbuf_limited;

	/* Stuff added >= 4.18 */
	__u32		tcpi_delivered;
	__u32		tcpi_delivered_ce;

	__u64		tcpi_bytes_sent;
	__u64		tcpi_bytes_retrans;
	__u32		tcpi_dsack_dups;
	__u32		tcpi_reord_seen;

	__u32		tcpi_rcv_ooopack;

	__u32		tcpi_snd_wnd;
	__u32		tcpi_rcv_wnd;
	__u32		tcpi_rehash;
	__u16		tcpi_total_rto;
	__u16		tcpi_total_rto_recoveries;
	__u32		tcpi_total_rto_time;
};

/* Return true if struct contains specific 'field' (member) */
#define TCPI_HAS(len, field) \
	((size_t) (len) >= offsetof(struct pg_tcp_info, field) + \
	 sizeof(((struct pg_tcp_info *) 0)->field))

#endif
