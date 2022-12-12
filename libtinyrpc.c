#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include "libtinyev.h"
#include "libtinyrpc.h"

struct ltiny_ev_buf {
	int header_ok;
	uint64_t transmitted_size;
	uint64_t requested_size;
	struct ltiny_ev_rpc_msg *msg;
};

struct ltiny_ev_rpc {
	ltiny_ev_rpc_cb callback;
	void *user_data;

	struct ltiny_ev_buf recv, send;
};

static void ltiny_ev_buf_clear(struct ltiny_ev_buf *b)
{
	free(b->msg);
	b->msg = NULL;

	b->transmitted_size = 0;
	b->header_ok = 0;
}

static void ltiny_ev_rpc_close_rpc(struct ltiny_ev_ctx *ctx, struct ltiny_ev_rpc *b, struct ltiny_event *ev)
{
	int fd = ltiny_ev_get_fd(ev);

	ltiny_ev_buf_clear(&b->recv);
	ltiny_ev_buf_clear(&b->send);
	
	ltiny_ev_del_event(ctx, ev);

	close(fd);
}

static void ltiny_ev_rpc_write_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
{
	struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);
	int fd = ltiny_ev_get_fd(ev);

	if (!ev_rpc_buf->send.header_ok) {
		ssize_t ret;
		ret = write(fd, ev_rpc_buf->send.msg, sizeof(struct ltiny_ev_rpc_header));
		if (ret != sizeof(struct ltiny_ev_rpc_header)) {
			//fprintf(stderr, "Not even a full's size header was written. Something is surely wrong\n");
			ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);
			return;
		}
		ev_rpc_buf->send.header_ok = 1;
	} else {
		ssize_t ret;
		ret = write(fd, ev_rpc_buf->send.msg->data + ev_rpc_buf->send.transmitted_size, ev_rpc_buf->send.requested_size - ev_rpc_buf->send.transmitted_size);
		if (ret > 0) {
			ev_rpc_buf->send.transmitted_size += ret;
		} else if (ret < 0) {
			//fprintf(stderr, "Error writing data\n");
			ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

			return;
		}

		if (ev_rpc_buf->send.transmitted_size == ev_rpc_buf->send.requested_size) {
			ltiny_ev_mod_events(ctx, ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP);
			ltiny_ev_buf_clear(&ev_rpc_buf->send);
		}
	}
}

static void ltiny_ev_rpc_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
{
	struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);
	int fd = ltiny_ev_get_fd(ev);

	if (!ev_rpc_buf->recv.header_ok) {
		struct ltiny_ev_rpc_header h;

		ssize_t ret;
		ret = read(fd, &h, sizeof(h));
		if (ret == 0) {
			ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

			return;
		}

		if (ret != sizeof(h)) {
			//fprintf(stderr, "Not even a full's size header was read. Something is surely wrong\n");
			ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

			return;
		}
		ev_rpc_buf->recv.header_ok = 1;

		if (h.payload_length > LTINY_EV_RPC_MAX_PAYLOAD_LENGTH) {
			//fprintf(stderr, "Requested payload length too large\n");
			return;
		}

		ev_rpc_buf->recv.msg = malloc(sizeof(struct ltiny_ev_rpc_msg) + h.payload_length);
		if (!ev_rpc_buf->recv.msg) {
			//fprintf(stderr, "Can't allocate memory\n");
			ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

			return;
		}
		*(struct ltiny_ev_rpc_header *)ev_rpc_buf->recv.msg = h;
		ev_rpc_buf->recv.requested_size = h.payload_length;
	}

	/* We may have turned this on the previous block, so try again */
	if (ev_rpc_buf->recv.header_ok) {
		ssize_t ret;
		ret = read(fd, ev_rpc_buf->recv.msg->data + ev_rpc_buf->send.transmitted_size, ev_rpc_buf->recv.requested_size - ev_rpc_buf->send.transmitted_size);
		if (ret > 0) {
			ev_rpc_buf->send.transmitted_size += ret;
		} else if (ret < 0) {
			//fprintf(stderr, "Error reading data\n");
			ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);

			return;
		}

		if (ev_rpc_buf->send.transmitted_size == ev_rpc_buf->recv.requested_size) {
			if (ev_rpc_buf->callback)
				ev_rpc_buf->callback(ctx, ev, ev_rpc_buf->recv.msg);
			ltiny_ev_buf_clear(&ev_rpc_buf->recv);
		}
	}
}

static void ltiny_ev_rpc_process_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
{
	if (triggered_events & EPOLLIN) {
		ltiny_ev_rpc_read_cb(ctx, ev, triggered_events);
	} else if (triggered_events & EPOLLOUT) {
		ltiny_ev_rpc_write_cb(ctx, ev, triggered_events);
	} else if (triggered_events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
		struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);
		ltiny_ev_rpc_close_rpc(ctx, ev_rpc_buf, ev);
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

	struct ltiny_event *ev = ltiny_ev_new_event(ctx, fd, ltiny_ev_rpc_process_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, rpc);

	ltiny_ev_set_free_data(ev, free);

	return ev;
}

int ltiny_ev_rpc_send(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, struct ltiny_ev_rpc_msg *msg)
{
	struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);

	if (ev_rpc_buf->send.header_ok)
		return -EAGAIN;

	ev_rpc_buf->send.header_ok = 0;
	ev_rpc_buf->send.transmitted_size = 0;
	ev_rpc_buf->send.requested_size = msg->payload_length;
	ev_rpc_buf->send.msg = malloc(ev_rpc_buf->send.requested_size);
	memcpy(ev_rpc_buf->send.msg, msg, ev_rpc_buf->send.requested_size);

	ltiny_ev_mod_events(ctx, ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLOUT);
}
