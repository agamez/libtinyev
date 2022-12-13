#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include "libtinyev.h"
#include "libtinybuf.h"

struct ltiny_ev_buf {
	int header_ok;
	uint64_t transmitted_size;
	uint64_t requested_size;

	char *data;
	FILE *fd;
};

struct ltiny_ev_rpc {
	ltiny_ev_buf_cb callback;
	void *user_data;

	struct ltiny_ev_buf recv, send;
};

static void ltiny_ev_buf_clear(struct ltiny_ev_buf *b)
{
	if (b->fd)
		fclose(b->fd);
	b->fd = NULL;

	free(b->data);
	b->data = NULL;

	b->transmitted_size = 0;
	b->requested_size = 0;
	b->header_ok = 0;
}

static void ltiny_ev_buf_close(struct ltiny_ev_ctx *ctx, struct ltiny_ev_rpc *b, struct ltiny_event *ev)
{
	int fd = ltiny_ev_get_fd(ev);

	ltiny_ev_buf_clear(&b->recv);
	ltiny_ev_buf_clear(&b->send);
	
	ltiny_ev_del_event(ctx, ev);

	close(fd);
}

static void ltiny_ev_buf_write_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
{
	struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);
	int fd = ltiny_ev_get_fd(ev);

	ssize_t ret;
	ret = write(fd, ev_rpc_buf->send.data + ev_rpc_buf->send.transmitted_size, ev_rpc_buf->send.requested_size - ev_rpc_buf->send.transmitted_size);
	if (ret > 0) {
		ev_rpc_buf->send.transmitted_size += ret;
	} else if (ret < 0) {
		//fprintf(stderr, "Error writing data\n");
		ltiny_ev_buf_close(ctx, ev_rpc_buf, ev);

		return;
	}

	if (ev_rpc_buf->send.transmitted_size == ev_rpc_buf->send.requested_size) {
		ltiny_ev_mod_events(ctx, ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP);
		ltiny_ev_buf_clear(&ev_rpc_buf->send);
	}
}

static void ltiny_ev_buf_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
{
	struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);
	int fd = ltiny_ev_get_fd(ev);

	if (!ev_rpc_buf->recv.data)
		ev_rpc_buf->recv.fd = open_memstream(&ev_rpc_buf->recv.data, &ev_rpc_buf->recv.requested_size);

	ssize_t ret;
	char tmpbuf[4096];
	ret = read(fd, tmpbuf, sizeof(tmpbuf));
	if (ret > 0) {
		fwrite(tmpbuf, ret, 1, ev_rpc_buf->recv.fd);
		fflush(ev_rpc_buf->recv.fd);
		if (ev_rpc_buf->callback)
			ev_rpc_buf->callback(ctx, ev, ev_rpc_buf->recv.data, ev_rpc_buf->recv.requested_size);
	} else if (ret < 0) {
		//fprintf(stderr, "Error reading data\n");
		ltiny_ev_buf_close(ctx, ev_rpc_buf, ev);

		return;
	}
}

static void ltiny_ev_buf_process_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
{
	if (triggered_events & EPOLLIN)
		ltiny_ev_buf_read_cb(ctx, ev, triggered_events);

	if (triggered_events & EPOLLOUT)
		ltiny_ev_buf_write_cb(ctx, ev, triggered_events);
	
	if (triggered_events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
		struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);
		ltiny_ev_buf_close(ctx, ev_rpc_buf, ev);
	}
}


void *ltiny_ev_buf_get_user_data(struct ltiny_event *ev)
{
	struct ltiny_ev_rpc *b = ltiny_ev_get_user_data(ev);
	return b->user_data;
}

struct ltiny_event *ltiny_ev_new_buf_event(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_buf_cb callback, void *user_data)
{
	struct ltiny_ev_rpc *rpc = calloc(1, sizeof(*rpc));
	rpc->callback = callback;
	rpc->user_data = user_data;

	struct ltiny_event *ev = ltiny_ev_new_event(ctx, fd, ltiny_ev_buf_process_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, rpc);

	ltiny_ev_set_free_data(ev, free);

	return ev;
}

int ltiny_ev_buf_send(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, void *buf, size_t count)
{
	struct ltiny_ev_rpc *ev_rpc_buf = ltiny_ev_get_user_data(ev);

	if (!ev_rpc_buf->send.data)
		ev_rpc_buf->send.fd = open_memstream(&ev_rpc_buf->send.data, &ev_rpc_buf->send.requested_size);

	fwrite(buf, count, 1, ev_rpc_buf->send.fd);
	fflush(ev_rpc_buf->send.fd);

	return ltiny_ev_mod_events(ctx, ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLOUT);
}
