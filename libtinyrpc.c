#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libtinybuf.h"
#include "libtinyrpc.h"

#include "freebsd-queue.h"

struct ltiny_ev_rpc_call {
	const char *name;
	rpc_call_cb call;
	LIST_ENTRY(ltiny_ev_rpc_call) rpc_calls;
};

struct ltiny_ev_rpc_server {
	LIST_HEAD(rpc_calls_list, ltiny_ev_rpc_call) rpc_calls;
};

struct ltiny_ev_rpc_server *ltiny_ev_new_rpc_server()
{
	return calloc(1, sizeof(struct ltiny_ev_rpc_server));
}

void ltiny_ev_rpc_server_register(struct ltiny_ev_rpc_server *s, const char *name, rpc_call_cb call)
{
	struct ltiny_ev_rpc_call *c = calloc(1, sizeof(*c));
	c->name = name;
	c->call = call;

	LIST_INSERT_HEAD(&s->rpc_calls, c, rpc_calls);
}

void ltiny_ev_rpc_server_free(struct ltiny_ev_rpc_server *s)
{
	struct ltiny_ev_rpc_call *r, *nr;
	LIST_FOREACH_SAFE(r, &s->rpc_calls, rpc_calls, nr)
		free(r);
	free(s);
}

struct ltiny_ev_rpc_receiver {
	struct ltiny_ev_rpc_server *server;

	enum {
		LT_EV_RPC_IDLE,
		LT_EV_RPC_MARKER,
		LT_EV_RPC_COMMAND,
		LT_EV_RPC_DATA_SIZE,
		LT_EV_RPC_DATA,
		LT_EV_RPC_EXEC
	} state;
	uint32_t bytes_before_data;
	size_t data_size;
	char *call;
	char *data;
};

struct ltiny_ev_rpc_receiver *ltiny_ev_new_rpc_receiver(struct ltiny_ev_rpc_server *server)
{
	struct ltiny_ev_rpc_receiver *rpc_rx;
	rpc_rx = calloc(1, sizeof(struct ltiny_ev_rpc_receiver));
	rpc_rx->server = server;
	return rpc_rx;
}


void ltiny_ev_rpc_close_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *b, void *data)
{
	struct ltiny_ev_rpc_receiver *rpc = data;
	free(rpc);
}

void ltiny_ev_rpc_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *buf, size_t count)
{
	struct ltiny_ev_rpc_receiver *r = ltiny_ev_buf_get_user_data(ev_buf);
	struct ltiny_ev_rpc_call *rpc_call;

	char *line = NULL;
	size_t length;

	r->bytes_before_data = 0;

	switch (r->state) {
	case LT_EV_RPC_IDLE:
		line = ltiny_ev_buf_consume_line(ctx, ev_buf, &length);
		if (!strcmp(line, LTINY_EV_RPC_MARKER))
			r->state = LT_EV_RPC_MARKER;
		else // Error
			break;
		r->bytes_before_data += length + 1; /* + \0 */
		/* Fallthrough */

	case LT_EV_RPC_MARKER:
		line = ltiny_ev_buf_consume_line(ctx, ev_buf, &length);
		if (line) {
			r->state = LT_EV_RPC_COMMAND;
			free(r->call);
			r->call = strdup(line);
			r->bytes_before_data += length + 1; /* + \0 */
		} else
			return;
		/* Fallthrough */

	case LT_EV_RPC_COMMAND:
		line = ltiny_ev_buf_consume_line(ctx, ev_buf, &length);
				
		if (line) {
			if (sscanf(line, "%"PRIu32, &r->data_size) < 0)
				return;
			r->state = LT_EV_RPC_DATA_SIZE;
			r->bytes_before_data += length + 1; /* + \0 */
		} else {
			return;
		}
		/* Fallthrough */

	case LT_EV_RPC_DATA_SIZE:
		if (r->data_size)
			if (count - r->bytes_before_data >= r->data_size)
				r->data = ltiny_ev_buf_consume(ctx, ev_buf, &r->data_size);
			else
				return;
		/* Fallthrough */

	case LT_EV_RPC_EXEC:
		LIST_FOREACH(rpc_call, &r->server->rpc_calls, rpc_calls) {
			if(!strcmp(rpc_call->name, r->call)) {
				void *response = NULL;
				size_t response_size = 0;

				rpc_call->call(r->data, r->data_size, &response, &response_size);
				ltiny_ev_buf_send(ctx, ev_buf, response, response_size);
			}
		}
		break;
	}

	free(r->call);
	r->call = NULL;
	r->state = LT_EV_RPC_IDLE;
	r->bytes_before_data = 0;
	r->data_size = 0;
	r->data = NULL;
}

struct ltiny_ev_buf *ltiny_ev_new_rpc_event(struct ltiny_ev_ctx *ctx, struct ltiny_ev_rpc_server *server, int fd)
{
	struct ltiny_ev_rpc_receiver *rpc = ltiny_ev_new_rpc_receiver(server);

	return ltiny_ev_buf_new(ctx, fd, ltiny_ev_rpc_read_cb, NULL, ltiny_ev_rpc_close_cb, rpc);
}
