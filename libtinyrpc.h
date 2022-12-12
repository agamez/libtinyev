#ifndef __libtinyrpc_h__
#define __libtinyrpc_h__

#include <inttypes.h>
#include "libtinyev.h"

#define LTINY_EV_RPC_MARKER "TNY_RPC"

#ifndef LTINY_EV_RPC_MAX_PAYLOAD_LENGTH
#define LTINY_EV_RPC_MAX_PAYLOAD_LENGTH 8192
#endif

struct ltiny_ev_rpc_header {
	char rpc_marker[8];
	uint64_t payload_length;
};


struct ltiny_ev_rpc_msg {
	struct ltiny_ev_rpc_header;
	char data[0];
};

/**
 * @brief Event callback. The user will write one or more functions with this prototype and pass them to the library when registering an event.
 * @param[in] ctx ltiny_ev context
 * @param[in] ev ltiny_ev event that triggered the callback
 * @param[in] data Data received via file descriptor
 * @param[in] data_length Size of the data received
 *
 * Whenever the event happens, this user provided function will be called
 */
typedef void (*ltiny_ev_rpc_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, struct ltiny_ev_rpc_msg *msg);

void *ltiny_ev_rpc_get_user_data(struct ltiny_event *ev);
struct ltiny_event *ltiny_ev_new_rpc_event(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_rpc_cb callback, void *user_data);

#endif /* __libtinyrpc_h__ */
