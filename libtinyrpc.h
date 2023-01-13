#ifndef __libtinyrpc_h__
#define __libtinyrpc_h__

#include <inttypes.h>
#include "libtinyev.h"

#define LTINY_EV_RPC_MARKER "TINY_RPC"

struct ltiny_event_rpc;
struct ltiny_event_rpc_receiver;
struct ltiny_event_rpc_receiver *ltiny_ev_new_rpc_receiver();

void ltiny_ev_rpc_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *ev_buf, void *buf, size_t count);

#endif /* __libtinyrpc_h__ */
