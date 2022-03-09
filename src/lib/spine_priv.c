#include "spine_priv.h"

__INLINE__ void free_spine_priv_state(struct spine_connection *conn) {
	struct spine_priv_state *state = get_spine_priv_state(conn);
	__FREE__(state);
}