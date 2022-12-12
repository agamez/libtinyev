#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "libtinyev.h"
#include "libtinyrpc.h"

struct ltiny_ev_rpc {
	ltiny_ev_rpc_cb callback;
	void *user_data;

	int header_received;
	uint64_t received_data;

	struct ltiny_ev_rpc_msg *recv_msg;
};

static void ltiny_ev_rpc_clear(struct ltiny_ev_rpc *b)
{
	free(b->recv_msg);
	b->recv_msg = NULL;

	b->received_data = 0;
	b->header_received = 0;
}

static void ltiny_ev_rpc_close_rpc(struct ltiny_ev_ctx *ctx, struct ltiny_ev_rpc *b, struct ltiny_event *ev)
{
	ltiny_ev_rpc_clear(b);
	free(b);

	int fd = ltiny_ev_get_fd(ev);
	ltiny_ev_del_event(ctx, ev);
	close(fd);
}

static void ltiny_ev_rpc_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
{
	struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);
	int fd = ltiny_ev_get_fd(ev);

	if (triggered_events & EPOLLIN) {
		if (!ev_rpc_buf->header_received) {
			struct ltiny_ev_rpc_header h;

			ssize_t ret;
			ret = read(fd, &h, sizeof(h));
			if (ret == 0) {
				ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

				return;
			}

			if (ret != sizeof(h)) {
				//fprintf(stderr, "Not even a full's size header was been read. Something is surely wrong\n");
				ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

				return;
			}
			ev_rpc_buf->header_received = 1;

			if (h.payload_length > LTINY_EV_RPC_MAX_PAYLOAD_LENGTH) {
				//fprintf(stderr, "Requested payload length too large\n");
				return;
			}

			ev_rpc_buf->recv_msg = malloc(sizeof(struct ltiny_ev_rpc_msg) + h.payload_length);
			if (!ev_rpc_buf->recv_msg) {
				//fprintf(stderr, "Can't allocate memory\n");
				ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

				return;
			}
			*(struct ltiny_ev_rpc_header *)ev_rpc_buf->recv_msg = h;

		} else {
			ssize_t ret;
			ret = read(fd, ev_rpc_buf->recv_msg->data + ev_rpc_buf->received_data, ev_rpc_buf->recv_msg->payload_length - ev_rpc_buf->received_data);
			if (ret > 0) {
				ev_rpc_buf->received_data += ret;
			} else if (ret < 0) {
				//fprintf(stderr, "Error reading data\n");
				ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

				return;
			}

			if (ev_rpc_buf->received_data == ev_rpc_buf->recv_msg->payload_length) {
				if (ev_rpc_buf->callback)
					ev_rpc_buf->callback(ctx, ev, ev_rpc_buf->recv_msg);
				ltiny_ev_rpc_clear(ev_rpc_buf);
			}
		}
	} else if (triggered_events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
		ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);
		return;
	}
}

void *ltiny_ev_rpc_get_user_data(struct ltiny_event *ev)
{
	struct ltiny_ev_rpc *b = ltiny_ev_get_user_data(ev);
	return b->user_data;
}

struct ltiny_event *ltiny_ev_new_rpc_event(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_rpc_cb callback, void *user_data)
{
	struct ltiny_ev_rpc *rpc = calloc(1, sizeof(*rpc));
	rpc->callback = callback;
	rpc->user_data = user_data;

	return ltiny_ev_new_event(ctx, fd, ltiny_ev_rpc_read_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, rpc);
}
