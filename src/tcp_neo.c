#define pr_fmt(fmt) "[spine]: " fmt

#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>

#include "lib/spine.h"
#include "spine_nl.h"
#include "tcp_spine.h"

/* all parameters are devided by 1024 */
#define NEO_SCALE 1024
#define NEO_PARAM_NUM 4

#define NEO_INTERVALS 20
#define MONITOR_INTERVAL 30000
#define NEO_RATE_MIN 1024u

extern struct spine_datapath *kernel_datapath;
extern struct timespec64 tzero;

struct neo_interval {
	u64 rate; /* sending rate of this interval, bytes/sec */

	s64 recv_start; /* timestamps for when interval was waiting for acks */
	s64 recv_end;

	s64 send_start; /* timestamps for when interval data was being sent */
	s64 send_end;

	s64 start_rtt; /* smoothed RTT at start and end of this interval */
	s64 end_rtt;

	u32 packets_sent_base; /* packets sent when this interval started */
	u32 packets_ended; /* packets sent when this interval ended */

	u32 lost; /* packets sent during this interval that were lost */
	u32 delivered; /* packets sent during this interval that were delivered */
};

/* TCP NEO Parameters */
struct neo_data {
	int cnt; /*  cwnd change */
	u8 prev_ca_state; /* prev ca state */
	bool in_recovery;
	u32 prior_cwnd; /* cwnd before loss */
	u32 r_cwnd; /* cwnd in loss or recovery */

	u8 slow_start_passed;

	/* neo parameters */
	struct neo_interval *intervals; /* containts stats for 1 RTT */

	int send_index; /* index of interval currently being sent */
	int receive_index; /* index of interval currently receiving acks */

	s64 rate; /* current sending rate */
	s64 ready_rate; /* rate updated by RL model, used in the next MI */

	u32 lost_base; /* previously lost packets */
	u32 delivered_base; /* previously delivered packets */

	u32 packets_counted; /* packets received or loss confirmed*/

	/* CA state on previous ACK */
	u32 prev_ca_state : 3;
	/* prior cwnd upon entering loss recovery */
	u32 prior_cwnd;

	bool first_circle;

	int id;
	/* communication */
	struct spine_connection *conn;
};

/*****************
 * Util functions *
 * ************/

static u32 get_next_index(u32 index)
{
	if (index < NEO_INTERVALS - 1)
		return index + 1;
	return 0;
}

static u32 get_previous_index(u32 index)
{
	if (index > 0)
		return index - 1;
	return NEO_INTERVALS - 1;
}

/*********************
 * Getters / Setters *
 * ******************/
static u32 neo_get_rtt(struct tcp_sock *tp)
{
	/* Get initial RTT - as measured by SYN -> SYN-ACK.
	 * If information does not exist - use 1ms as a "LAN RTT".
	 * (originally from BBR).
	 */
	if (tp->srtt_us) {
		return max(tp->srtt_us >> 3, 1U);
	} else {
		return USEC_PER_MSEC;
	}
}

/**
 * With the ready_cwnd given by the RL agent. Calculate the real cwnd so that the average CWND/rate of all the unreceived MIs is the ready_cwnd.
 * rate1+rate2+rate3+new_rate = ready_rate * n
 * Used after send_index++ (new interval created.)
 * */

void neo_calculate_and_set_rate(struct sock *sk, struct neo_data *neo,
				struct neo_interval *interval)
{
	u64 new_rate;
	u64 rate_sum;
	int recv_idx = neo->receive_index;
	int send_idx = neo->send_index;
	int idx = recv_idx;
	int num = 0;

	do {
		rate_sum += neo->intervals[idx].rate;
		idx = get_next_index(idx);
		num++;
	} while (idx != send_idx) new_rate =
		neo->ready_rate * (num + 1) - rate_sum;

	new_rate = max(new_rate, NEO_RATE_MIN);
	new_rate = new_rate(rate, sk->sk_max_pacing_rate);
	interval.rate = new_rate;
	sk->sk_pacing_rate = new_rate;
}

static void neo_set_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u64 cwnd = sk->sk_pacing_rate;
	cwnd *= neo_get_rtt(tcp_sk(sk));
	cwnd /= tp->mss_cache;

	cwnd /= USEC_PER_SEC;
	cwnd *= 2;

	cwnd = max(4ULL, cwnd);
	cwnd = min((u32)cwnd, tp->snd_cwnd_clamp); /* apply cap */
	tp->snd_cwnd = cwnd;
}

bool neo_valid(struct neo_data *neo)
{
	return (neo && neo->intervals);
}

/* Set the pacing rate and cwnd base on the currently-sending interval */
void start_interval(struct sock *sk, struct neo_data *neo)
{
	struct neo_interval *interval = &neo->intervals[neo->send_index];
	interval->packets_ended = 0;
	interval->lost = 0;
	interval->delivered = 0;
	interval->packets_sent_base = tcp_sk(sk)->data_segs_out;
	interval->packets_sent_base = max(interval->packets_sent_base, 1U);
	interval->send_start = tcp_sk(sk)->tcp_mstamp;
	neo_calculate_and_set_rate(sk, neo, interval);
	neo_set_cwnd(sk);
}

/**************************
 * intervals & sample:
 * was started, was ended,
 * find interval per sample
 * ************************/

/* Have we sent all the data we need to for this interval? Must have at least a MONITER_INTERVAL.*/
bool send_interval_ended(struct neo_interval *interval, struct tcp_sock *tsk,
			 struct neo_data *neo)
{
	s64 now = tsk->tcp_mstamp;
	if (now - interval->send_start >= MONITOR_INTERVAL) {
		interval->packets_ended = tsk->data_segs_out;
		return true;
	} else
		return false;
}

/* Have we accounted for (acked or lost) enough of the packets that we sent to
 * calculate summary statistics?
 */
bool receive_interval_ended(struct neo_interval *interval, struct tcp_sock *tsk,
			    struct neo_data *neo)
{
	return interval->packets_ended &&
	       interval->packets_ended - 10 < neo->packets_counted;
}

/* Start the next interval's sending stage.
 */
void start_next_send_interval(struct sock *sk, struct neo_data *neo)
{
	neo->send_index = get_next_index(neo->send_index);
	if (neo->send_index == neo->receive_index) {
		printk(KERN_INFO "Fail: not enough interval slots.\n");
		return;
	}
	start_interval(sk, neo);
}

/* Update the receiving time window and the number of packets lost/delivered
 * based on socket statistics.
 */
void neo_update_interval(struct neo_interval *interval, struct neo_data *neo,
			 struct sock *sk)
{
	interval->recv_end = tcp_sk(sk)->tcp_mstamp;
	interval->end_rtt = tcp_sk(sk)->srtt_us >> 3;
	if (interval->lost + interval->delivered == 0) {
		interval->recv_start = tcp_sk(sk)->tcp_mstamp;
		interval->start_rtt = tcp_sk(sk)->srtt_us >> 3;
	}

	interval->lost += tcp_sk(sk)->lost - neo->lost_base;
	interval->delivered += tcp_sk(sk)->delivered - neo->delivered_base;
}

/* Updates the NEO model */
void neo_process(struct sock *sk)
{
	struct neo_data *neo = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	struct neo_interval *interval;
	int index;
	u32 before;

	if (!neo_valid(neo))
		return;
	neo_set_cwnd(sk);
	/* update send intervals */
	interval = &neo->intervals[neo->send_index];
	if (send_interval_ended(interval, tsk, neo)) {
		interval->send_end = tcp_sk(sk)->tcp_mstamp;
		start_next_send_interval(sk, neo);
	}
	/* update recv intervals */
	index = neo->receive_index;
	interval = &neo->intervals[index];
	before = neo->packets_counted;
	neo->packets_counted = tsk->data_segs_out;

	if (before > 10 + interval->packets_sent_base) {
		neo_update_interval(interval, neo, sk);
	}
	if (receive_interval_ended(interval, tsk, neo)) {
		neo->receive_index = get_next_index(neo->receive_index);
		if (neo->receive_index == 0)
			neo->first_circle = false;
	}
	neo->lost_base = tsk->lost;
	neo->delivered_base = tsk->delivered;
}

/** 
 * Spine call this to push updated parameters.
 * The state features we need:
 *    rate: for the RL agent to calculate the next rate.
 *    thr_gradient: (thr_t - thr_{t-1})/thr_{t-1}
 *    rtt_gradient: (RTT_t - RTT_{t-1})/MI
 *    loss_gradient: (1-loss...)
 *    rate_gradient: rate_t/rate_{t-1}
 * 
 * The state the kernel can provide as integers:
 *     delivered, last_delivered, lost, last_loss, rate, last_rate, RTT diff, 
 *
 */

static *s64 get_state(struct spine_connection *conn, u64 *params, u8 num_fields)
{
	struct sock *sk;
	get_sock_from_spine(&sk, conn);
	struct tcp_sock *tp = tcp_sk(sk);
	struct neo_data *neo = inet_csk_ca(sk);
	if (neo->first_circle and neo->receive_index < 2) {
		params[0] = 0;
		params[1] = 0;
		params[2] = 0;
		params[3] = 0;
		params[4] = 0;
		params[5] = 0;
		params[6] = 0;
		params[7] = 0;
		return;
	}
	int last_received_id = get_previous_index(
		neo->receive_index) int last_last_received_id =
		get_previous_index(last_received_id)

			params[0] = neo->intervals[last_received_id].delivered;
	params[1] = neo->intervals[last_last_received_id].delivered;
	params[2] = neo->intervals[last_received_id].loss;
	params[3] = neo->intervals[last_last_received_id].loss;
	params[4] = neo->intervals[last_received_id].rate;
	params[5] = neo->intervals[last_last_received_id].rate;
	params[6] = neo->intervals[last_received_id].end_rtt -
		    neo->intervals[last_received_id].start_rtt;
	params[7] = neo->intervals[last_received_id].send_end -
		    neo->intervals[last_received_id].send_start;
}

/**
 * Spine call this to fetch updated parameters.
 */
void neo_set_params(struct spine_connection *conn, u64 *params, u8 num_fields)
{
	struct sock *sk;
	// struct tcp_sock *tp = tcp_sk(sk);
	get_sock_from_spine(&sk, conn);
	struct neo_data *ca = inet_csk_ca(sk);

	if (conn == NULL || params == NULL) {
		pr_info("%s:conn/params is NULL\n", __FUNCTION__);
		return;
	}

	if (unlikely(conn->flow_info.alg != SPINE_NEO) ||
	    unlikely(num_fields != NEO_PARAM_NUM)) {
		pr_info("Unknown internal congestion control algorithm, do nothing. %d",
			num_fields);
		return;
	}

	ca->ready_rate = params[0];
}

static void neo_update_pacing_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u64 rate;
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);

	rate = tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache); //

	rate *= USEC_PER_SEC;

	rate *= max(tp->snd_cwnd, tp->packets_out);

	rate = rate >> 1;

	if (likely(tp->srtt_us >> 3))
		do_div(rate, tp->srtt_us >> 3);

	/* WRITE_ONCE() is needed because sch_fq fetches sk_pacing_rate
   * without any lock. We want to make sure compiler wont store
   * intermediate values in this location.
   */
	WRITE_ONCE(sk->sk_pacing_rate,
		   min_t(u64, rate, sk->sk_max_pacing_rate));
}

static void neo_release(struct sock *sk)
{
	struct neo_data *ca = inet_csk_ca(sk);
	if (ca->conn != NULL) {
		pr_info("freeing connection %d", ca->conn->index);
		spine_connection_free(kernel_datapath, ca->conn->index);
	} else {
		pr_info("already freed");
	}

	kfree(ca->intervals);
}

static inline void neo_reset(struct neo_data *ca)
{
	ca->cnt = 0;
	ca->prev_ca_state = TCP_CA_Open;
	ca->in_recovery = false;
	ca->prior_cwnd = 0;
	ca->r_cwnd = 0;
	ca->slow_start_passed = 0;
}

static void neo_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct neo_data *ca = inet_csk_ca(sk);
	neo_reset(ca);

	ca->intervals = kzalloc(sizeof(struct neo_interval) * NEO_INTERVALS,
				GFP_KERNEL);
	if (!ca->intervals) {
		printk(KERN_INFO "init fails\n");
		return;
	}

	id++;
	ca->id = id;
	ca->rate = NEO_RATE_MIN * 512;
	ca->ready_rate = NEO_RATE_MIN * 512;

	ca->send_index = 0;
	ca->receive_index = 0;
	ca->first_circle = true;

	start_interval(sk, ca);

	/* create spine flow and register parameters */
	struct spine_datapath_info dp_info = {
		.init_cwnd = tp->snd_cwnd * tp->mss_cache,
		.mss = tp->mss_cache,
		.src_ip = tp->inet_conn.icsk_inet.inet_saddr,
		.src_port = tp->inet_conn.icsk_inet.inet_sport,
		.dst_ip = tp->inet_conn.icsk_inet.inet_daddr,
		.dst_port = tp->inet_conn.icsk_inet.inet_dport,
		.congAlg = "neo",
		.alg = SPINE_NEO,
	};
	// pr_info("New spine flow, from: %u:%u to %u:%u", dp_info.src_ip,
	// 	dp_info.src_port, dp_info.dst_ip, dp_info.dst_port);
	ca->conn =
		spine_connection_start(kernel_datapath, (void *)sk, &dp_info);
	if (ca->conn == NULL) {
		pr_info("start connection failed\n");
	} else {
		pr_info("starting spine connection %d", ca->conn->index);
	}

	// if no ecn support
	if (!(tp->ecn_flags & TCP_ECN_OK)) {
		INET_ECN_dontxmit(sk);
	}

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static void neo_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
}

static u32 neo_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	// we want RL to take more efficient control
	struct neo_data *ca = inet_csk_ca(sk);
	ca->prior_cwnd = tp->snd_cwnd;
	return max(tp->snd_cwnd, 10U);
}

static void neo_set_state(struct sock *sk, u8 new_state)
{
	struct neo_data *ca = inet_csk_ca(sk);
	if (new_state == TCP_CA_Loss) {
		ca->prev_ca_state = TCP_CA_Loss;
	}
}

static void neo_pkt_acked(struct sock *sk, const struct ack_sample *sample)
{
}

static u32 neo_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

static void slow_set_cwnd(struct sock *sk, u32 acked)
{
	// do_div(change, NEO_SCALE);
	struct tcp_sock *tp = tcp_sk(sk);
	struct neo_data *ca = inet_csk_ca(sk);
	u32 cwnd = tp->snd_cwnd;
	int delta = ca->cnt;
	// printk(KERN_INFO "Delta before division: %d.\n", delta);

	delta = delta / NEO_SCALE;

	if (delta != 0) {
		ca->cnt -= delta * NEO_SCALE;
		// printk(KERN_INFO "[NEO] Old CWND %d, New CWND %d.\n", cwnd, cwnd + delta);
		cwnd += delta;
	}
}

u32 neo_slow_start(struct sock *sk, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct neo_data *ca = inet_csk_ca(sk);
	ca->cnt += acked * 500;
	slow_set_cwnd(sk, acked);
	neo_update_pacing_rate(sk);
}

static void neo_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct neo_data *ca = inet_csk_ca(sk);
	struct spine_connection *conn = ca->conn;
	u32 acked = rs->acked_sacked; //rs->delivered;
	int ok = 0;

	// we only do slow start when flow starts
	if (tcp_in_slow_start(tp) && !ca->slow_start_passed) {
		// printk(KERN_INFO "[NEO] acked: %d, delivered %d.\n, ",  rs->acked_sacked, rs->delivered);
		neo_slow_start(sk, acked);
		return;
	}

	if (rs->delivered < 0 || rs->interval_us < 0) {
		return;
	}

	neo_process(sk);
	// printk(KERN_INFO "[NEO] Get into control1.\n");
	// call spine to update parameters if needed
	if (conn != NULL) {
		// if there are staged parameters update, then
		// corressponding params inside ca would be updated
		ok = spine_invoke(conn);
		if (ok < 0) {
			pr_info("fail to call spine_invoke: %d\n", ok);
		}
	}
}

static struct tcp_congestion_ops neo __read_mostly = {
	.init = neo_init,
	.release = neo_release,
	.ssthresh = neo_ssthresh,
	// .cong_avoid = neo_cong_avoid,
	.cong_control = neo_cong_control,
	.set_state = neo_set_state,
	.undo_cwnd = neo_undo_cwnd,
	// .cwnd_event = neo_cwnd_event,
	.pkts_acked = neo_pkt_acked,
	.owner = THIS_MODULE,
	.name = "neo",
};

static int __init neo_register(void)
{
	int ret;
	BUILD_BUG_ON(sizeof(struct neo_data) > ICSK_CA_PRIV_SIZE);
	ktime_get_real_ts64(&tzero);

	/* Init spine-related structs inspired by CCP
	 * kernel_datapath
	 * spine connections
	 */
	kernel_datapath = (struct spine_datapath *)kmalloc(
		sizeof(struct spine_datapath), GFP_KERNEL);
	if (!kernel_datapath) {
		pr_info("could not allocate spine_datapath\n");
		return -1;
	}
	kernel_datapath->now = &spine_now;
	kernel_datapath->since_usecs = &spine_since;
	kernel_datapath->after_usecs = &spine_after;
	kernel_datapath->log = &spine_log;
	kernel_datapath->fto_us = 1000;
	kernel_datapath->max_connections = MAX_ACTIVE_FLOWS;
	kernel_datapath->spine_active_connections =
		(struct spine_connection *)kzalloc(
			sizeof(struct spine_connection) * MAX_ACTIVE_FLOWS,
			GFP_KERNEL);
	if (!kernel_datapath->spine_active_connections) {
		pr_info("could not allocate spine_connections\n");
		return -2;
	}
	kernel_datapath->log = &spine_log;
	kernel_datapath->set_params = &neo_set_params;
	kernel_datapath->send_msg = &nl_sendmsg;

	/* Here we need to add a IPC for receiving messages from user space 
	 * RL controller.
	 */
	ret = spine_nl_sk(spine_read_msg);
	if (ret < 0) {
		pr_info("cannot init spine ipc\n");
		return -3;
	}
	pr_info("spine ipc init\n");
	// register current sock in spine datapath
	ret = spine_init(kernel_datapath, 0);
	if (ret < 0) {
		pr_info("fail to init spine datapath\n");
		free_spine_nl_sk();
		return -4;
	}
	pr_info("spine %s init\n", neo.name);

	return tcp_register_congestion_control(&neo);
}

static void __exit neo_unregister(void)
{
	free_spine_nl_sk();
	kfree(kernel_datapath->spine_active_connections);
	kfree(kernel_datapath);
	pr_info("spine exit\n");
	tcp_unregister_congestion_control(&neo);
}

module_init(neo_register);
module_exit(neo_unregister);

MODULE_AUTHOR("Han Tian");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP Neo");
MODULE_VERSION("1.0");
