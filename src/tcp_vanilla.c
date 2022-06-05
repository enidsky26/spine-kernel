#define pr_fmt(fmt) "[spine]: " fmt

#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>

#include "lib/spine.h"
#include "spine_nl.h"
#include "tcp_spine.h"

/* all parameters are devided by 1024 */
#define VANILLA_SCALE 1024
#define VANILLA_PARAM_NUM 4

extern struct spine_datapath *kernel_datapath;
extern struct timespec64 tzero;

/* TCP Vanilla Parameters */
struct vanilla {
	u32 min_rtt_us; /* minimum observed RTT */

	int cnt; /*  cwnd change */

	/* control parameters, which would be modified by user-space RL algorithm 
     * these variables are all bounds in [0, 1024]
     */
	u16 alpha;
	u16 beta;
	u16 gamma;
	u16 delta; /* control how much the ssthresh should be from current cwnd */

	/* communication */
	struct spine_connection *conn;
};

/* sanity check on fecthed parameters
 * return true when parameters are OK
 */
static inline bool check_param(u16 val)
{
	return !(unlikely(val <= 0) || unlikely(val > 1024));
}

/**
 * Spine call this to fetch updated parameters.
 */
void vanilla_set_params(struct spine_connection *conn, u64 *params,
			u8 num_fields)
{
	struct sock *sk;
	// struct tcp_sock *tp = tcp_sk(sk);
	struct vanilla *ca = inet_csk_ca(sk);
	get_sock_from_spine(&sk, conn);

	if (conn == NULL || params == NULL) {
		pr_info("%s:conn/params is NULL\n", __FUNCTION__);
		return;
	}

	if (unlikely(conn->flow_info.alg != SPINE_VANILLA) ||
	    unlikely(num_fields != VANILLA_PARAM_NUM)) {
		pr_info("Unknown internal congestion control algorithm, do nothing");
		return;
	}
	for (int j = 0; j < num_fields; j++) {
		if (!check_param(params[j])) {
			pr_info("warning: invalid parameters on idx:%d, ignore this run\n",
				j);
			return;
		}
	}
	ca->alpha = params[0];
	ca->beta = params[1];
	ca->gamma = params[2];
	ca->delta = params[3];
    // pr_info("update alpha: %u, beta: %u, gamma: %u, delta: %u\n", ca->alpha, ca->beta, ca->gamma, ca->delta);
    // pr_info("current cwnd: %d\n", tcp_sk(sk)->snd_cwnd);
}

static void vanilla_update_pacing_rate(struct sock* sk) {
  const struct tcp_sock* tp = tcp_sk(sk);
  u64 rate;
  cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);

  rate = tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);  //

  rate *= USEC_PER_SEC;

  rate *= max(tp->snd_cwnd, tp->packets_out);

  if (likely(tp->srtt_us >> 3)) do_div(rate, tp->srtt_us >> 3);

  /* WRITE_ONCE() is needed because sch_fq fetches sk_pacing_rate
   * without any lock. We want to make sure compiler wont store
   * intermediate values in this location.
   */
  WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate, sk->sk_max_pacing_rate));
}

void vanilla_release(struct sock *sk)
{
	struct vanilla *ca = inet_csk_ca(sk);
	if (ca->conn != NULL) {
		pr_info("freeing connection %d", ca->conn->index);
		spine_connection_free(kernel_datapath, ca->conn->index);
	} else {
		pr_info("already freed");
	}
}

static inline void vanilla_reset(struct vanilla *ca)
{
	ca->alpha = 50;
	ca->beta = 200;
	ca->gamma = 200;
	ca->delta = 717;
	ca->cnt = 0;
	ca->min_rtt_us = 0x7fffffff;
}

static void vanilla_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct vanilla *ca = inet_csk_ca(sk);
	vanilla_reset(ca);

	/* create spine flow and register parameters */
	struct spine_datapath_info dp_info = {
		.init_cwnd = tp->snd_cwnd * tp->mss_cache,
		.mss = tp->mss_cache,
		.src_ip = tp->inet_conn.icsk_inet.inet_saddr,
		.src_port = tp->inet_conn.icsk_inet.inet_sport,
		.dst_ip = tp->inet_conn.icsk_inet.inet_daddr,
		.dst_port = tp->inet_conn.icsk_inet.inet_dport,
		.congAlg = "vanilla",
		.alg = SPINE_VANILLA,
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

static void vanilla_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
}

static u32 vanilla_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct vanilla *ca = inet_csk_ca(sk);

	// TODO: We may have some sanity check here
	u32 target = ca->delta * tp->snd_cwnd;
	printk(KERN_INFO "[VANILLA] new CWND before loss event: %d.\n",  tp->snd_cwnd);
	do_div(target, VANILLA_SCALE);
	printk(KERN_INFO "[VANILLA] new CWND after loss event: %d.\n", target);
	return target;
}

static void vanilla_state(struct sock *sk, u8 new_state)
{
}

static void vanilla_pkt_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct vanilla *ca = inet_csk_ca(sk);
	u32 vrtt;

	if (sample->rtt_us < 0)
		return;

	/* follow vegas's min rtt estimation */
	vrtt = sample->rtt_us + 1;

	if (vrtt < ca->min_rtt_us)
		ca->min_rtt_us = vrtt;
}

static u32 vanilla_undo_cwnd(struct sock *sk)
{
	return tcp_reno_undo_cwnd(sk);
}

static void vanilla_set_cwnd(struct sock *sk)
{
	// do_div(change, VANILLA_SCALE);
	struct tcp_sock *tp = tcp_sk(sk);
	struct vanilla *ca = inet_csk_ca(sk);
	u32 cwnd = tp->snd_cwnd;
	int delta = ca->cnt / VANILLA_SCALE;

	if (delta != 0) {
		ca->cnt -= delta * VANILLA_SCALE;
		cwnd += delta;
	}
	/* apply global cap */
	cwnd = max(cwnd, 10U);
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);

	printk(KERN_INFO "[VANILLA] New CWND %d.\n", tp->snd_cwnd);
    vanilla_update_pacing_rate(sk);
}

static void vanilla_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct vanilla *ca = inet_csk_ca(sk);
	struct spine_connection *conn = ca->conn;
	u32 acked = rs->delivered;
	int ok = 0;

	// if (tcp_in_slow_start(tp)) {
	// 	acked = tcp_slow_start(tp, acked);
	// 	if (!acked)
	// 		return;
	// 	/* otherwise, we can send more ... */
	// }

	/* TODO: 
     * 1. TCP slow start
     * 2. how to change cwnd in loss recovery
     */

	if (rs->delivered < 0 || rs->interval_us < 0){
		printk(KERN_INFO "[VANILLA] Get out of control %d %d.\n", rs->delivered, rs->interval_us);
		return;
	}

	//printk(KERN_INFO "[VANILLA] Get into control1.\n");
	/* call spine to update parameters if needed */
	if (conn != NULL) {
		// if there are staged parameters update, then
		// corressponding params inside ca would be updated
		ok = spine_invoke(conn);
		if (ok < 0) {
			pr_info("fail to call spine_invoke: %d\n", ok);
		}
	}
	/* calculate how much current cwnd should change 
     * change = alpha / 1024 - (beta / 1024) * (rtt / min_rtt - 1 - gamma / 1024)
     * target = change + tp->cwnd
     */
	int change;
	u64 lat_inflation;

	//printk(KERN_INFO "[VANILLA] Get into control2.\n");
	lat_inflation = rs->rtt_us * VANILLA_SCALE;
	do_div(lat_inflation, ca->min_rtt_us);
	if (lat_inflation > VANILLA_SCALE + ca->gamma){
		lat_inflation = lat_inflation - VANILLA_SCALE - ca->gamma;
    	do_div(lat_inflation, VANILLA_SCALE);
		change = ca->alpha - ca->beta * lat_inflation;
	}
	else{
		change = ca->alpha;
	}
	// bound the change
	change = min(change, 1024);
	change = max(change, -512);
	ca->cnt += change;

	// try to enforce cwnd changes
	//printk(KERN_INFO "[VANILLA] Get into control3.\n");
	vanilla_set_cwnd(sk);
}

static struct tcp_congestion_ops vanilla __read_mostly = {
	.init = vanilla_init,
	.release = vanilla_release,
	.ssthresh = vanilla_ssthresh,
	// .cong_avoid = vanilla_cong_avoid,
	.cong_control = vanilla_cong_control,
	.set_state = vanilla_state,
	.undo_cwnd = vanilla_undo_cwnd,
	// .cwnd_event = vanilla_cwnd_event,
	.pkts_acked = vanilla_pkt_acked,
	.owner = THIS_MODULE,
	.name = "vanilla",
};

static int __init vanilla_register(void)
{
	int ret;
	BUILD_BUG_ON(sizeof(struct vanilla) > ICSK_CA_PRIV_SIZE);
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
	kernel_datapath->set_params = &vanilla_set_params;
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
	pr_info("spine %s init\n", vanilla.name);

	return tcp_register_congestion_control(&vanilla);
}

static void __exit vanilla_unregister(void)
{
	free_spine_nl_sk();
	kfree(kernel_datapath->spine_active_connections);
	kfree(kernel_datapath);
	pr_info("spine exit\n");
	tcp_unregister_congestion_control(&vanilla);
}

module_init(vanilla_register);
module_exit(vanilla_unregister);

MODULE_AUTHOR("Xudong Liao");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP Vanilla");
MODULE_VERSION("1.0");
