#ifndef SPINE_H
#define SPINE_H

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/types.h>
#else
#include <stdint.h>
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* --- return code --- */
#define SPINE_OK 0
#define SPINE_ERROR 4

enum spine_log_level {
	TRACE,
	DEBUG,
	INFO,
	WARN,
	ERROR,
};

// maximum string length for congAlg
#define MAX_CONG_ALG_SIZE 64
/* Datapaths provide connection information to ccp_connection_start
 */
struct spine_datapath_info {
	u32 init_cwnd;
	u32 mss;
	u32 src_ip;
	u32 src_port;
	u32 dst_ip;
	u32 dst_port;
	char congAlg[MAX_CONG_ALG_SIZE];
};

struct spine_connection {
	// the index of this array element
	u16 index;

	u64 last_create_msg_sent;

	// struct spine_primitives is large; as a result, we store it inside spine_connection to avoid
	// potential limitations in the datapath
	// datapath should update this before calling spine_invoke()
	// struct spine_primitives prims;

	// constant flow-level information
	struct spine_datapath_info flow_info;

	// private libspine state for the send machine and measurement machine
	void *state;

	// datapath-specific per-connection state
	void *impl;

	// pointer back to parent datapath that owns this connection
	struct spine_datapath *datapath;
};

struct spine_datapath {
	// control primitives
	void (*set_cwnd)(struct spine_connection *conn, u32 cwnd);
	void (*set_rate_abs)(struct spine_connection *conn, u32 rate);

	// IPC communication
	int (*send_msg)(struct spine_datapath *dp, char *msg, int msg_size);

	// logging
	void (*log)(struct spine_datapath *dp, enum spine_log_level level,
		    const char *msg, int msg_size);
};

#endif