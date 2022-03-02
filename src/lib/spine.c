#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "spine.h"

int spine_read_msg(struct spine_datapath *datapath, char *buf, int bufsize)
{
	return SPINE_OK;
}

int spine_init(struct spine_datapath *datapath, u32 id)
{
	return SPINE_OK;
}

struct ccp_connection *ccp_connection_start(struct spine_datapath *datapath, void *impl, struct spine_datapath_info *flow_info) {
    int ret;
    u16 sid;
    struct spine_connection *conn;

    // scan to find empty place
    // index = 0 means free/unused
    for (sid = 0; sid < datapath->max_connections; sid++) {
        conn = &datapath->spine_active_connections[sid];
        if (CAS(&(conn->index), 0, sid+1)) {
            sid = sid + 1;
            break;
        }
    }
    
    if (sid >= datapath->max_connections) {
        return NULL;
    }

    conn->impl = impl;
    memcpy(&conn->flow_info, flow_info, sizeof(struct spine_datapath_info));

    init_ccp_priv_state(datapath, conn);

    // send to CCP:
    // index of pointer back to this sock for IPC callback
    ret = send_conn_create(datapath, conn);
    if (ret < 0) {
        if (!datapath->_in_fallback) {
            libccp_warn("failed to send create message: %d\n", ret);
        }
        return conn;
    }

    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    ccp_conn_create_success(state);

    return conn;
}