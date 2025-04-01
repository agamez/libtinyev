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
	size_t transmitted_size; /** Number of bytes in the buffer that have already been transmitted */
	size_t requested_size; /** Number of bytes that have been requested to be transmitted */

	char *data; /** Buffer */
	FILE *fd; /** Associated memstream file descriptor attached to data */
};

struct ltiny_ev_buf {
	struct ltiny_ev *ev; /** Underlying libtiny event */
	ltiny_ev_buf_read_cb read_cb; /** Read callback (when there's data available on the buffer) */
	ltiny_ev_buf_write_cb write_cb; /** Write callback (when all data in the buffer has been written) */
	ltiny_ev_buf_close_cb close_cb; /** Close callback (when underlying fd has been closed) */
	ltiny_ev_buf_error_cb error_cb; /** Error callback (when read or write return error) */
	void *user_data; /** Associated data provided by the user */

	struct ltiny_buf recv, send; /** Internal buffer structures */
};

static void ltiny_buf_clear(struct ltiny_buf *b)
{
	if (!b)
		return;

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
	if (!ctx || !b)
		return;

	if (b->close_cb)
		b->close_cb(ctx, b);
	b->user_data = NULL;
	b->close_cb = NULL;

	ltiny_buf_clear(&b->recv);
	ltiny_buf_clear(&b->send);

	ltiny_ev_set_free_data(b->ev, NULL);
	ltiny_ev_del(ctx, b->ev);

	free(b);
}

int ltiny_ev_buf_get_fd(struct ltiny_ev_buf *ev_buf)
{
	if (!ev_buf)
		return -1;

	return ltiny_ev_get_fd(ev_buf->ev);
}

static void buf_close_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	if (!ctx || !ev)
		return;

	struct ltiny_ev_buf *ev_buf = ltiny_ev_get_user_data(ev);
	if (!ev_buf)
		return;

	ltiny_ev_buf_close(ctx, ev_buf);
}

static void buf_write_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	if (!ctx || !ev)
		return;

	struct ltiny_ev_buf *ev_buf = ltiny_ev_get_user_data(ev);
	if (!ev_buf)
		return;

	int fd = ltiny_ev_get_fd(ev);

	ssize_t ret;
	ret = write(fd, ev_buf->send.data + ev_buf->send.transmitted_size, ev_buf->send.requested_size - ev_buf->send.transmitted_size);
	if (ret > 0)
		ev_buf->send.transmitted_size += ret;

	if (ev_buf->send.transmitted_size == ev_buf->send.requested_size) {
		ltiny_ev_mod_events(ctx, ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP);
		ltiny_buf_clear(&ev_buf->send);
		if (ev_buf->write_cb)
			ev_buf->write_cb(ctx, ev_buf);
	}

	if (ret < 0 && ev_buf->error_cb)
		ev_buf->error_cb(ctx, ev_buf);
}

static void buf_read_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	if (!ctx || !ev)
		return;

	struct ltiny_ev_buf *ev_buf = ltiny_ev_get_user_data(ev);
	if (!ev_buf)
		return;

	int fd = ltiny_ev_get_fd(ev);

	if (ev_buf->recv.transmitted_size == ev_buf->recv.requested_size)
		ltiny_buf_clear(&ev_buf->recv);

	if (!ev_buf->recv.data)
		ev_buf->recv.fd = open_memstream(&ev_buf->recv.data, &ev_buf->recv.requested_size);

	ssize_t ret;
	ssize_t total_ret = 0;
	char tmpbuf[4096];

	/* Read all that we can in a loop */
	do {
		ret = read(fd, tmpbuf, sizeof(tmpbuf));
		/* And store it if there's someone to call back */
		if (ret > 0 && ev_buf->read_cb) {
			total_ret += ret;
			fwrite(tmpbuf, ret, 1, ev_buf->recv.fd);
		}
	} while (ret == sizeof(tmpbuf));

	if (total_ret > 0 && ev_buf->read_cb) {
		fflush(ev_buf->recv.fd);
		ev_buf->read_cb(ctx, ev_buf, ev_buf->recv.data, ev_buf->recv.requested_size);
	} else if (ret < 0 && ev_buf->error_cb)
		ev_buf->error_cb(ctx, ev_buf);
}

void *ltiny_ev_buf_consume(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, size_t *count)
{
	if (!ctx || !ev_buf || !count)
		return NULL;

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
	if (!ctx || !ev_buf || !len)
		return NULL;

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

static void ltiny_ev_buf_default_error_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf)
{
	if (!ctx || !ev_buf)
		return;

	/* Clear output buffer and do not listen to EPOLLOUT */
	ltiny_ev_mod_events(ctx, ev_buf->ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP);
	ltiny_buf_clear(&ev_buf->send);
	if (ev_buf->write_cb)
		ev_buf->write_cb(ctx, ev_buf);

	/* Call readback function with whatever data there's on the buffer right now and clear it */
	fflush(ev_buf->recv.fd);
	if (ev_buf->read_cb)
		ev_buf->read_cb(ctx, ev_buf, ev_buf->recv.data, ev_buf->recv.transmitted_size);
	ltiny_buf_clear(&ev_buf->recv);
}

static void buf_process_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	if (!ctx || !ev)
		return;

	if (triggered_events & EPOLLIN)
		buf_read_cb(ctx, ev, triggered_events);

	if (triggered_events & EPOLLOUT)
		buf_write_cb(ctx, ev, triggered_events);
	
	if (triggered_events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP))
		buf_close_cb(ctx, ev, triggered_events);
}

void *ltiny_ev_buf_get_user_data(struct ltiny_ev_buf *ev_buf)
{
	if (!ev_buf)
		return NULL;

	return ev_buf->user_data;
}

void ltiny_ev_buf_set_free_data(struct ltiny_ev_buf *ev_buf, ltiny_ev_free_data_cb free_user_data)
{
	if (!ev_buf)
		return;

	ltiny_ev_set_free_data(ev_buf->ev, free_user_data);
}

struct ltiny_ev_buf *ltiny_ev_buf_new(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_buf_read_cb read_cb, ltiny_ev_buf_write_cb write_cb, ltiny_ev_buf_close_cb close_cb, ltiny_ev_buf_error_cb error_cb, void *user_data)
{
	if (!ctx)
		return NULL;

	struct ltiny_ev_buf *ev_buf = calloc(1, sizeof(*ev_buf));
	if (!ev_buf)
		return NULL;

	ev_buf->read_cb = read_cb;
	ev_buf->write_cb = write_cb;
	ev_buf->close_cb = close_cb;
	if (error_cb)
		ev_buf->error_cb = error_cb;
	else
		ev_buf->error_cb = ltiny_ev_buf_default_error_cb;
	ev_buf->user_data = user_data;

	ev_buf->ev = ltiny_ev_new(ctx, fd, buf_process_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, ev_buf);
	if (!ev_buf->ev) {
		free(ev_buf);
		return NULL;
	}

	ltiny_ev_set_free_data(ev_buf->ev, (ltiny_ev_free_data_cb)ltiny_ev_buf_close);

	return ev_buf;
}

int ltiny_ev_buf_send(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, const void *buf, size_t count)
{
	if (!ctx || !ev_buf || !buf)
		return -1;

	if (!ev_buf->send.data)
		ev_buf->send.fd = open_memstream(&ev_buf->send.data, &ev_buf->send.requested_size);

	fwrite(buf, count, 1, ev_buf->send.fd);
	fflush(ev_buf->send.fd);

	return ltiny_ev_mod_events(ctx, ev_buf->ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLOUT);
}

int ltiny_ev_buf_printf(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, const char *format, ...)
{
	if (!ctx || !ev_buf)
		return -1;

	va_list args;
	va_start(args, format);

	if (!ev_buf->send.data)
		ev_buf->send.fd = open_memstream(&ev_buf->send.data, &ev_buf->send.requested_size);

	vfprintf(ev_buf->send.fd, format, args);
	fflush(ev_buf->send.fd);

	return ltiny_ev_mod_events(ctx, ev_buf->ev, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLOUT);
}

void ltiny_ev_buf_set_timeout(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, ltiny_ev_cb read_timeout_cb, ltiny_ev_cb write_timeout_cb, int read_timeout_ms, int write_timeout_ms)
{
	if (!ctx || !ev_buf)
		return;

	ltiny_ev_set_timeout(ctx, ev_buf->ev, read_timeout_cb, write_timeout_cb, read_timeout_ms, write_timeout_ms);
}
