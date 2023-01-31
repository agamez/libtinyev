#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libtinybuf.h"
#include "libtinyrpc.h"

#include "freebsd-queue.h"

struct ltiny_ev_rpc_req {
	const char *name;
	rpc_req_cb call;
	LIST_ENTRY(ltiny_ev_rpc_req) rpc_reqs;
};

struct ltiny_ev_rpc_ans {
	const char *name;
	rpc_ans_cb call;
	LIST_ENTRY(ltiny_ev_rpc_ans) rpc_ans;
};

struct ltiny_ev_rpc_server {
	LIST_HEAD(rpc_reqs_list, ltiny_ev_rpc_req) rpc_reqs;
	LIST_HEAD(rpc_ans_list, ltiny_ev_rpc_ans) rpc_ans;
};

struct ltiny_ev_rpc_server *ltiny_ev_new_rpc_server()
{
	return calloc(1, sizeof(struct ltiny_ev_rpc_server));
}

void ltiny_ev_rpc_server_register_req(struct ltiny_ev_rpc_server *s, const char *name, rpc_req_cb call)
{
	struct ltiny_ev_rpc_req *c = calloc(1, sizeof(*c));
	c->name = name;
	c->call = call;

	LIST_INSERT_HEAD(&s->rpc_reqs, c, rpc_reqs);
}

void ltiny_ev_rpc_server_register_ans(struct ltiny_ev_rpc_server *s, const char *name, rpc_ans_cb call)
{
	struct ltiny_ev_rpc_ans *c = calloc(1, sizeof(*c));
	c->name = name;
	c->call = call;

	LIST_INSERT_HEAD(&s->rpc_ans, c, rpc_ans);
}

void ltiny_ev_rpc_server_free(struct ltiny_ev_rpc_server *s)
{
	struct ltiny_ev_rpc_req *r, *nr;
	LIST_FOREACH_SAFE(r, &s->rpc_reqs, rpc_reqs, nr)
		free(r);

	struct ltiny_ev_rpc_ans *a, *na;
	LIST_FOREACH_SAFE(a, &s->rpc_ans, rpc_ans, na)
		free(a);
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

	enum liny_ev_rpc_type type;

	uint32_t bytes_before_data;
	size_t data_size;
	char *call;
	char *data;
};

static struct ltiny_ev_rpc_receiver *ltiny_ev_new_rpc_receiver(struct ltiny_ev_rpc_server *server)
{
	struct ltiny_ev_rpc_receiver *rpc_rx;
	rpc_rx = calloc(1, sizeof(struct ltiny_ev_rpc_receiver));
	rpc_rx->server = server;
	return rpc_rx;
}


static void ltiny_ev_rpc_close_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *b, void *data)
{
	struct ltiny_ev_rpc_receiver *rpc = data;
	free(rpc);
}

int ltiny_ev_rpc_send_msg(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, enum liny_ev_rpc_type type, const char *call, const void *data, size_t data_size)
{
	if (type == LT_EV_RPC_TYPE_REQ)
		ltiny_ev_buf_printf(ctx, ev_buf, LTINY_EV_RPC_MARKER_REQ "\n");
	else if (type == LT_EV_RPC_TYPE_ANS)
		ltiny_ev_buf_printf(ctx, ev_buf, LTINY_EV_RPC_MARKER_ANS "\n");
	ltiny_ev_buf_printf(ctx, ev_buf, "%s\n", call);
	ltiny_ev_buf_printf(ctx, ev_buf, "%d\n", data_size);
	ltiny_ev_buf_send(ctx, ev_buf, data, data_size);
}


static void ltiny_ev_rpc_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *buf, size_t count)
{
	struct ltiny_ev_rpc_receiver *r = ltiny_ev_buf_get_user_data(ev_buf);

	char *line = NULL;
	size_t length;

	r->bytes_before_data = 0;

	switch (r->state) {
	case LT_EV_RPC_IDLE:
		line = ltiny_ev_buf_consume_line(ctx, ev_buf, &length);
		if (!strcmp(line, LTINY_EV_RPC_MARKER_REQ)) {
			r->state = LT_EV_RPC_MARKER;
			r->type = LT_EV_RPC_TYPE_REQ;
		} else if (!strcmp(line, LTINY_EV_RPC_MARKER_ANS)) {
			r->state = LT_EV_RPC_MARKER;
			r->type = LT_EV_RPC_TYPE_ANS;
		} else { // Error
			break;
		}
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
			if (count - r->bytes_before_data >= r->data_size) {
				r->data = ltiny_ev_buf_consume(ctx, ev_buf, &r->data_size);
				r->state = LT_EV_RPC_EXEC;
			} else {
				return;
			}
		/* Fallthrough */

	case LT_EV_RPC_EXEC:
		if (r->type == LT_EV_RPC_TYPE_REQ) {
			struct ltiny_ev_rpc_req *rpc_req;
			LIST_FOREACH(rpc_req, &r->server->rpc_reqs, rpc_reqs) {
				if(!strcmp(rpc_req->name, r->call)) {
					void *response = NULL;
					size_t response_size = 0;

					rpc_req->call(ctx, ev_buf, r->data, r->data_size, &response, &response_size);
					ltiny_ev_rpc_send_msg(ctx, ev_buf, LT_EV_RPC_TYPE_ANS, r->call, response, response_size);
				}
			}
		} else if (r->type == LT_EV_RPC_TYPE_ANS) {
			struct ltiny_ev_rpc_ans *rpc_ans;
			LIST_FOREACH(rpc_ans, &r->server->rpc_ans, rpc_ans)
				if(!strcmp(rpc_ans->name, r->call))
					rpc_ans->call(ctx, ev_buf, r->data, r->data_size);
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

struct ltiny_ev_rpc_data_length {
	void *response;
	size_t response_size;
};

static void *ltiny_ev_rpc_sync_ans_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *request, size_t request_size)
{
	struct ltiny_ev_rpc_data_length *dl = ltiny_ev_get_ctx_user_data(ctx);
	dl->response = request;
	dl->response_size = request_size;
	ltiny_ev_exit_loop(ctx);
}

int ltiny_ev_rpc_sync_msg(int fd, const char *call, void *data, size_t data_size, void **response, size_t *response_size)
{
	struct ltiny_ev_rpc_data_length dl;
	int ret = -1;


	struct ltiny_ev_rpc_server *server = ltiny_ev_new_rpc_server();
	ltiny_ev_rpc_server_register_ans(server, call, ltiny_ev_rpc_sync_ans_cb);

	struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(&dl);
	struct ltiny_ev_buf *ev_buf = ltiny_ev_new_rpc_event(ctx, server, fd);
	if (!ev_buf)
		goto out;

	ltiny_ev_rpc_send_msg(ctx, ev_buf, LT_EV_RPC_TYPE_REQ, (const char *)call, data, data_size);

	ltiny_ev_loop(ctx);

	*response = malloc(dl.response_size);
	memcpy(*response, dl.response, dl.response_size);
	*response_size = dl.response_size;

	ret = 0;

out:
	ltiny_ev_ctx_del(ctx);
	ltiny_ev_rpc_server_free(server);

	return 0;
}
