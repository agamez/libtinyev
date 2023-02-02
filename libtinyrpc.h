#ifndef __libtinyrpc_h__
#define __libtinyrpc_h__

#include <inttypes.h>
#include "libtinyev.h"
#include "libtinybuf.h"

/**
 * Types of RPC calls
 * @LT_EV_RPC_TYPE_REQ RPC request
 * @LT_EV_RPC_TYPE_ANS RPC answer
 */
enum liny_ev_rpc_type {
	LT_EV_RPC_TYPE_REQ,
	LT_EV_RPC_TYPE_ANS
};

/**
 * RPC server opaque structure
 */
struct ltiny_ev_rpc_server;

/**
 * Generates a new RPC server structure
 */
struct ltiny_ev_rpc_server *ltiny_ev_new_rpc_server();

/**
 * Frees an RPC server structure
 */
void ltiny_ev_rpc_server_free(struct ltiny_ev_rpc_server *s);

/**
 * Function type to process RPC requests
 */
typedef ssize_t (*rpc_req_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *data, size_t data_size, void **response);
/**
 * Function type to process RPC answers
 */
typedef void (*rpc_ans_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *data, size_t data_size);


/**
 * Registers a particular RPC call within given server.
 * Since the callback function rpc_req_cb call may allocate some data to return via its **response parameter, a pointer to a destructor function can be given
 * so that the RPC subsystem calls it whenever it has finished processing the response
 */
void ltiny_ev_rpc_server_register_req(struct ltiny_ev_rpc_server *s, const char *name, rpc_req_cb call, void (*free_cb)(void *ptr));

/**
 * Registers a particular RPC answer within given server.
 */
void ltiny_ev_rpc_server_register_ans(struct ltiny_ev_rpc_server *s, const char *name, rpc_ans_cb call);

/**
 * Attaches an RPC server to a given file descriptor, associating some user_data so it's available on RPC requests and answers callbacks
 */
struct ltiny_ev_buf *ltiny_ev_new_rpc_event(struct ltiny_ev_ctx *ctx, struct ltiny_ev_rpc_server *server, int fd, ltiny_ev_buf_close_cb close_cb, void *user_data);

/**
 * Returns previously associated user pointer data to the RPC event
 */
void *ltiny_ev_rpc_get_user_data(struct ltiny_ev_buf *ev_buf);

/**
 * Sends an RPC request/answer with the given data and data_size
 */
int ltiny_ev_rpc_send_msg(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, enum liny_ev_rpc_type type, const char *call, const void *data, size_t data_size);

/**
 * Sends a synchronous RPC request with the given data and data_size and waits for its response
 */
int ltiny_ev_rpc_sync_msg(int fd, const char *call, void *data, size_t data_size, void **response, size_t *response_size);

#endif /* __libtinyrpc_h__ */
