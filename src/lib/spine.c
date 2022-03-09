#ifdef __KERNEL__
#include <linux/slab.h> // kmalloc
#include <linux/string.h> // memcpy
#include <linux/types.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "spine.h"
#include "spine_err.h"
#include "spine_priv.h"

__INLINE__ void *ccp_get_impl(struct ccp_connection *conn)
{
	return conn->impl;
}

__INLINE__ void ccp_set_impl(struct ccp_connection *conn, void *ptr)
{
	conn->impl = ptr;
}

/* Read parameters from user-space RL algorithm
 * first save these parameters to staged registers
 */
int spine_read_msg(struct spine_datapath *datapath, char *buf, int bufsize)
{
	// TODO: Implement semantics to read control message from user space
	return SPINE_OK;
}

int spine_init(struct spine_datapath *datapath, u32 id)
{
	if (datapath == NULL || datapath->set_params == NULL) {
		return -1;
	}
	return SPINE_OK;
}

struct spine_connection *
spine_connection_start(struct spine_datapath *datapath, void *impl,
		       struct spine_datapath_info *flow_info)
{
	int ret;
	u16 sid;
	struct spine_connection *conn;

	// scan to find empty place
	// index = 0 means free/unused
	for (sid = 0; sid < datapath->max_connections; sid++) {
		conn = &datapath->spine_active_connections[sid];
		if (CAS(&(conn->index), 0, sid + 1)) {
			sid = sid + 1;
			break;
		}
	}

	if (sid >= datapath->max_connections) {
		return NULL;
	}

	conn->impl = impl;
	memcpy(&conn->flow_info, flow_info, sizeof(struct spine_datapath_info));

	// send to CCP:
	// index of pointer back to this sock for IPC callback
	// TODO implement this function
	ret = send_conn_create(datapath, conn);
	if (ret < 0) {
		if (!datapath->_in_fallback) {
			spine_warn("failed to send create message: %d\n", ret);
		}
		return conn;
	}
	return conn;
}

struct spine_connection *spine_connection_lookup(struct ccp_datapath *datapath,
						 u16 sid)
{
	struct ccp_connection *conn;
	// bounds check
	if (sid == 0 || sid > datapath->max_connections) {
		libccp_warn("index out of bounds: %d", sid);
		return NULL;
	}

	conn = &datapath->ccp_active_connections[sid - 1];
	if (conn->index != sid) {
		libccp_trace("index mismatch: sid %d, index %d", sid,
			     conn->index);
		return NULL;
	}

	return conn;
}

void spine_connection_free(struct spine_datapath *datapath, u16 sid)
{
	int msg_size, ret;
	struct spine_connection *conn;
	char msg[REPORT_MSG_SIZE];

	libccp_trace("Entering %s\n", __FUNCTION__);
	// bounds check
	if (sid == 0 || sid > datapath->max_connections) {
		libccp_warn("index out of bounds: %d", sid);
		return;
	}

	conn = &datapath->spine_active_connections[sid - 1];
	if (conn->index != sid) {
		libccp_warn("index mismatch: sid %d, index %d", sid,
			    conn->index);
		return;
	}

	free_ccp_priv_state(conn);

	msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, sid, 0, 0, 0);
	ret = datapath->send_msg(datapath, msg, msg_size);
	if (ret < 0) {
		if (!datapath->_in_fallback) {
			libccp_warn("error sending close message: %d", ret);
		}
	}

	// ccp_connection_start will look for an array entry with index 0
	// to indicate that it's available for a new flow's information.
	// So, we set index to 0 here to reuse the memory.
	conn->index = 0;
	return;
}

int spine_invoke(struct spine_connection *conn)
{
	int ret;
	int i;
	struct spine_priv_state *state;
	struct spine_datapath *datapath;
	u8 num_params = 0;
	u64 params[MAX_CONTROL_REG];

	if (conn == NULL) {
		return SPINE_NULL;
	}
	datapath = conn->datapath;
	state = get_spine_priv_state(conn);
	// we assume consequent parameters
	for (i = 0; i < MAX_CONTROL_REG; i++) {
		if (state->pending_update.control_is_pending[i]) {
			params[i] = state->pending_update.control_registers[i];
			num_params += 1;
		} else {
			// there are no remaining staged parameters, we stop here
			break;
		}
	}
	// enforce parameters to datapath
	if (datapath->set_params) {
		datapath->set_params(conn, &params, num_params);
	}
	// clear staged status
	memset(&state->pending_update, 0, sizeof(struct staged_update));
	return SPINE_OK;
}

int send_conn_create(struct spine_datapath *datapath,
		     struct spine_connection *conn)
{
	// TODO: send user message to indicate spine connection created
	return SPINE_OK;
}