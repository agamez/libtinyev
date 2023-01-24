#ifndef __libtinyrpc_h__
#define __libtinyrpc_h__

#include <inttypes.h>
#include "libtinyev.h"
#include "libtinybuf.h"

#define LTINY_EV_RPC_MARKER_REQ "TINY_RPC_R"
#define LTINY_EV_RPC_MARKER_ANS "TINY_RPC_A"

enum liny_ev_rpc_type {
	LT_EV_RPC_TYPE_REQ,
	LT_EV_RPC_TYPE_ANS
};

struct ltiny_ev_rpc_server;
struct ltiny_ev_rpc_server *ltiny_ev_new_rpc_server();
void ltiny_ev_rpc_server_free(struct ltiny_ev_rpc_server *s);

typedef void *(*rpc_call_cb)(void *data, size_t data_size, void **response, size_t *response_size);

void ltiny_ev_rpc_server_register(struct ltiny_ev_rpc_server *s, const char *name, rpc_call_cb call);

struct ltiny_ev_rpc_receiver;
struct ltiny_ev_rpc_receiver *ltiny_ev_new_rpc_receiver();

void ltiny_ev_rpc_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *buf, size_t count);
void ltiny_ev_rpc_close_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *b, void *data);

struct ltiny_ev_buf *ltiny_ev_new_rpc_event(struct ltiny_ev_ctx *ctx, struct ltiny_ev_rpc_server *server, int fd);

#endif /* __libtinyrpc_h__ */
