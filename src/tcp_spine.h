#ifndef TCP_SPINE_H
#define TCP_SPINE_H

#include "spine.h"
#include <linux/net.h>
#include <linux/tcp.h>
#include <net/tcp.h>

#define MAX_SKB_STORED 50

#define MAX_ACTIVE_FLOWS 1024
#define MAX_DATAPATH_PROGRAMS 10

struct skb_info {
	u64 first_tx_mstamp; // choose the correct skb so the timestamp for first packet
	u32 interval_us; // interval us as calculated from this SKB
};

struct spine {
	// control
	u32 last_snd_una; // 4 B
	u32 last_bytes_acked; // 8 B
	u32 last_sacked_out; // 12 B
	struct skb_info *skb_array; // array of future skb information

	// communication
    struct spine_connection *conn;
    // inner congestion control algorithm
    char inner_alg[MAX_CONG_ALG_SIZE];
    struct tcp_congestion_ops *inner_cong_ops;
};

#define MTU 1500
#define S_TO_US 1000000

void spine_set_pacing_rate(struct sock *sk, uint32_t rate);

#endif
