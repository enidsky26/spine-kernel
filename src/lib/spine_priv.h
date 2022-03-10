#ifndef SPINE_PRIV_H
#define SPINE_PRIV_H

#include "ccp.h"
#include "serialize.h"

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <stdio.h>
#endif

#ifdef __KERNEL__
#define __INLINE__ inline
#define __CALLOC__(num_elements, block_size)                                   \
	kcalloc(num_elements, block_size, GFP_KERNEL)
#define __FREE__(ptr) kfree(ptr)
#define CAS(a, o, n) cmpxchg(a, o, n) == o
#else
#define __INLINE__
#define __CALLOC__(num_elements, block_size) calloc(num_elements, block_size)
#define __FREE__(ptr) free(ptr)
#define CAS(a, o, n) __sync_bool_compare_and_swap(a, o, n)
#endif

#define log_fmt(level, fmt, args...)                                           \
	{                                                                      \
		char msg[80];                                                  \
		int __ok = snprintf((char *)&msg, 80, fmt, ##args);            \
		if (__ok >= 0) {                                               \
			datapath->log(datapath, level, (const char *)&msg,     \
				      __ok);                                   \
		}                                                              \
	}

// __LOG_INFO__ is default
#define spine_trace(fmt, args...)
#define spine_debug(fmt, args...)
#define spine_info(fmt, args...) log_fmt(INFO, fmt, ##args)
#define spine_warn(fmt, args...) log_fmt(WARN, fmt, ##args)
#define spine_error(fmt, args...) log_fmt(ERROR, fmt, ##args)

#ifdef __LOG_TRACE__
#undef spine_trace
#define spine_trace(fmt, args...) log_fmt(TRACE, fmt, ##args)
#undef spine_debug
#define spine_debug(fmt, args...) log_fmt(DEBUG, fmt, ##args)
#endif

#ifdef __LOG_DEBUG__
#undef spine_debug
#define spine_debug(fmt, args...) log_fmt(DEBUG, fmt, ##args)
#endif

#ifdef __LOG_WARN__
#undef spine_info
#define spine_info(fmt, args...)
#endif
#ifdef __LOG_ERROR__
#undef spine_info
#define spine_info(fmt, args...)
#undef spine_warn
#define spine_warn(fmt, args...)
#endif

struct staged_update {
	bool control_is_pending[MAX_CONTROL_REG];
	u64 control_registers[MAX_CONTROL_REG];
};

struct spine_priv_state {
	bool sent_create, struct staged_update pending_update;
};

__INLINE__ struct spine_priv_state *
get_spine_priv_state(struct spine_connection *conn)
{
	return (struct spine_priv_state *)conn->state;
}

int send_conn_create(struct spine_datapath *datapath,
		     struct spine_connection *conn);

void free_spine_priv_state(struct spine_connection *conn);

// types of registers
#define NONVOLATILE_CONTROL_REG 0
#define IMMEDIATE_REG 1
#define IMPLICIT_REG 2
#define LOCAL_REG 3
#define PRIMITIVE_REG 4
#define VOLATILE_REPORT_REG 5
#define NONVOLATILE_REPORT_REG 6
#define TMP_REG 7
#define VOLATILE_CONTROL_REG 8

#endif