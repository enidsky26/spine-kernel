#include "tcp_spine.h"
#include "spine.h"
#include "spine_nl.h"

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <net/tcp.h>

// Global internal state -- allocated during init and freed in free.
struct spine_datapath *kernel_datapath;

void spine_log(struct spine_datapath *dp, enum spine_log_level level,
	       const char *msg, int msg_size)
{
	switch (level) {
	case ERROR:
	case WARN:
	case INFO:
	case DEBUG:
	case TRACE:
		pr_info("%s\n", msg);
		break;
	default:
		break;
	}
}

inline void spine_set_pacing_rate(struct sock *sk, uint32_t rate)
{
	sk->sk_pacing_rate = rate;
}
