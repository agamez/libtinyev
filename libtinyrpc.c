#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libtinybuf.h"
#include "libtinyrpc.h"

struct ltiny_event_rpc_receiver {
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

struct ltiny_event_rpc_receiver *ltiny_ev_new_rpc_receiver()
{
	struct ltiny_event_rpc_receiver *rpc_rx;
	rpc_rx = calloc(1, sizeof(struct ltiny_event_rpc_receiver));
	return rpc_rx;
}

struct ltiny_event_rpc {
};


void ltiny_ev_rpc_close_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *b, void *data)
{
	struct ltiny_event_rpc_receiver *rpc = data;
	free(rpc);
}

void ltiny_ev_rpc_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *ev_buf, void *buf, size_t count)
{
	struct ltiny_event_rpc_receiver *r = ltiny_evbuf_get_user_data(ev_buf);

	char *line = NULL;
	size_t length;

	r->bytes_before_data = 0;

	switch (r->state) {
	case LT_EV_RPC_IDLE:
		line = ltiny_event_buf_consume_line(ctx, ev_buf, &length);
		if (!strcmp(line, LTINY_EV_RPC_MARKER))
			r->state = LT_EV_RPC_MARKER;
		else // Error
			break;
		r->bytes_before_data += length + 1; /* + \0 */
		/* Fallthrough */

	case LT_EV_RPC_MARKER:
		line = ltiny_event_buf_consume_line(ctx, ev_buf, &length);
		if (line) {
			r->state = LT_EV_RPC_COMMAND;
			free(r->call);
			r->call = strdup(line);
			r->bytes_before_data += length + 1; /* + \0 */
		} else
			return;
		/* Fallthrough */

	case LT_EV_RPC_COMMAND:
		line = ltiny_event_buf_consume_line(ctx, ev_buf, &length);
				
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
				r->data = ltiny_event_buf_consume(ctx, ev_buf, &r->data_size);
			else
				return;
		/* Fallthrough */

	case LT_EV_RPC_EXEC:
		printf("Executing call '%s' with data '%s'\n", r->call, r->data);
		break;
	}

	free(r->call);
	bzero(r, sizeof(*r));
}
