#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include "libtinyev.h"
#include "libtinybuf.h"

struct ltiny_buf {
	uint64_t transmitted_size;
	uint64_t requested_size;

	char *data;
	FILE *fd;
};

struct ltiny_ev_buf {
	struct ltiny_ev *ev;
	ltiny_ev_buf_read_cb read_cb;
	ltiny_ev_buf_write_cb write_cb;
	ltiny_ev_buf_close_cb close_cb;
	void *user_data;

	struct ltiny_buf recv, send;
};

static void ltiny_buf_clear(struct ltiny_buf *b)
{
	if (b->fd)
		fclose(b->fd);
	b->fd = NULL;

	free(b->data);
	b->data = NULL;

	b->transmitted_size = 0;
	b->requested_size = 0;
}

void ltiny_ev_buf_close(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *b)
{
	int fd = ltiny_ev_get_fd(b->ev);

	if (b->close_cb)
		b->close_cb(ctx, b, b->user_data);
	b->user_data = NULL;
	b->close_cb = NULL;

	ltiny_buf_clear(&b->recv);
	ltiny_buf_clear(&b->send);

	ltiny_ev_set_free_data(b->ev, NULL);
	ltiny_ev_del(ctx, b->ev);

	close(fd);

	free(b);
}

static void buf_write_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	struct ltiny_ev_buf *ev_buf = ltiny_ev_get_user_data(ev);
	int fd = ltiny_ev_get_fd(ev);

	ssize_t ret;
	ret = write(fd, ev_buf->send.data + ev_buf->send.transmitted_size, ev_buf->send.requested_size - ev_buf->send.transmitted_size);
	if (ret > 0)
		ev_buf->send.transmitted_size += ret;
	else if (ret < 0)
		return;

	if (ev_buf->send.transmitted_size == ev_buf->send.requested_size) {
		ltiny_ev_mod_events(ctx, ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP);
		ltiny_buf_clear(&ev_buf->send);
		if (ev_buf->write_cb)
			ev_buf->write_cb(ctx, ev_buf);
	}
}

static void buf_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	struct ltiny_ev_buf *ev_buf = ltiny_ev_get_user_data(ev);
	int fd = ltiny_ev_get_fd(ev);

	if (ev_buf->recv.transmitted_size == ev_buf->recv.requested_size)
		ltiny_buf_clear(&ev_buf->recv);

	if (!ev_buf->recv.data)
		ev_buf->recv.fd = open_memstream(&ev_buf->recv.data, &ev_buf->recv.requested_size);

	ssize_t ret;
	char tmpbuf[4096];
	ret = read(fd, tmpbuf, sizeof(tmpbuf));
	if (ret > 0) {
		fwrite(tmpbuf, ret, 1, ev_buf->recv.fd);
		fflush(ev_buf->recv.fd);
		if (ev_buf->read_cb)
			ev_buf->read_cb(ctx, ev_buf, ev_buf->recv.data, ev_buf->recv.requested_size);
	} else if (ret < 0) {
		return;
	}
}

void *ltiny_ev_buf_consume(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, size_t *count)
{
	if (ev_buf->recv.transmitted_size == ev_buf->recv.requested_size) {
		ltiny_buf_clear(&ev_buf->recv);
		return NULL;
	}

	if (ev_buf->recv.transmitted_size + *count > ev_buf->recv.requested_size)
		*count = ev_buf->recv.requested_size - ev_buf->recv.transmitted_size;

	void *ret = ev_buf->recv.data + ev_buf->recv.transmitted_size;
	ev_buf->recv.transmitted_size += *count;

	return ret;
}

void *ltiny_ev_buf_consume_line(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, size_t *len)
{
	if (ev_buf->recv.transmitted_size == ev_buf->recv.requested_size) {
		ltiny_buf_clear(&ev_buf->recv);
		return NULL;
	}

	for (int i = ev_buf->recv.transmitted_size; i < ev_buf->recv.requested_size; i++) {
		if (ev_buf->recv.data[i] == '\n') {
			ev_buf->recv.data[i] = '\0';
			*len = i - ev_buf->recv.transmitted_size;
			void *ret = ev_buf->recv.data + ev_buf->recv.transmitted_size;
			ev_buf->recv.transmitted_size = i + 1;
			return ret;
		}
	}

	return NULL;
}

static void buf_process_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	if (triggered_events & EPOLLIN)
		buf_read_cb(ctx, ev, triggered_events);

	if (triggered_events & EPOLLOUT)
		buf_write_cb(ctx, ev, triggered_events);
	
	if (triggered_events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
		struct ltiny_ev_buf *ev_buf = ltiny_ev_get_user_data(ev);
		ltiny_ev_buf_close(ctx, ev_buf);
	}
}

void *ltiny_ev_buf_get_user_data(struct ltiny_ev_buf *ev_buf)
{
	return ev_buf->user_data;
}

struct ltiny_ev_buf *ltiny_ev_buf_new(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_buf_read_cb read_cb, ltiny_ev_buf_write_cb write_cb, ltiny_ev_buf_close_cb close_cb, void *user_data)
{
	struct ltiny_ev_buf *ev_buf = calloc(1, sizeof(*ev_buf));
	ev_buf->read_cb = read_cb;
	ev_buf->write_cb = write_cb;
	ev_buf->close_cb = close_cb;
	ev_buf->user_data = user_data;

	ev_buf->ev = ltiny_ev_new(ctx, fd, buf_process_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, ev_buf);

	ltiny_ev_set_free_data(ev_buf->ev, (ltiny_ev_free_data_cb)ltiny_ev_buf_close);

	return ev_buf;
}

int ltiny_ev_buf_send(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, const void *buf, size_t count)
{
	if (!ev_buf->send.data)
		ev_buf->send.fd = open_memstream(&ev_buf->send.data, &ev_buf->send.requested_size);

	fwrite(buf, count, 1, ev_buf->send.fd);
	fflush(ev_buf->send.fd);

	return ltiny_ev_mod_events(ctx, ev_buf->ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLOUT);
}

int ltiny_ev_buf_printf(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (!ev_buf->send.data)
		ev_buf->send.fd = open_memstream(&ev_buf->send.data, &ev_buf->send.requested_size);

	vfprintf(ev_buf->send.fd, format, args);
	fflush(ev_buf->send.fd);

	return ltiny_ev_mod_events(ctx, ev_buf->ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLOUT);
}
