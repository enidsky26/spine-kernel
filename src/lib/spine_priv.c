#include "spine_priv.h"

#ifdef __KERNEL__
#include <linux/slab.h> // kmalloc
#include <linux/string.h> // memcpy,memset
#else
#include <stdlib.h>
#include <string.h>
#endif

__INLINE__ void free_spine_priv_state(struct spine_connection *conn)
{
	struct spine_priv_state *state = get_spine_priv_state(conn);
	__FREE__(state);
}
__INLINE__ struct spine_priv_state *
get_spine_priv_state(struct spine_connection *conn)
{
	return (struct spine_priv_state *)conn->state;
}