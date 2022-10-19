#include <sys/epoll.h>
#include <stdlib.h>
#include <errno.h>

#include "freebsd-queue.h"
#include "libtinyev.h"

struct ltiny_ev_ctx {
	LIST_HEAD(events_list, ltiny_event) events;
	int epollfd;
	int terminate;

	void *user_data;
};

void *ltiny_ev_get_ctx_user_data(struct ltiny_ev_ctx *ctx)
{
	return ctx->user_data;
}

struct ltiny_event;

typedef void (*event_callback)(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events);

struct ltiny_event {
	int fd;
	void *user_data;
	event_callback cb;

	LIST_ENTRY(ltiny_event) events;
};

int ltiny_ev_get_fd(struct ltiny_event *ev)
{
	return ev->fd;
}

void *ltiny_ev_get_user_data(struct ltiny_event *ev)
{
	return ev->user_data;
}

void ltiny_ev_set_user_data(struct ltiny_event *ev, void *user_data)
{
	ev->user_data = user_data;
}

struct ltiny_ev_ctx *ltiny_ev_new_ctx(void *user_data)
{
	struct ltiny_ev_ctx *ctx = calloc(1, sizeof(*ctx));
	ctx->epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (ctx->epollfd < 0)
		goto error;

	ctx->user_data = user_data;

	return ctx;

error:
	free(ctx);
	return NULL;
}

struct ltiny_event *ltiny_ev_new_event(struct ltiny_ev_ctx *ctx, int fd, event_callback cb, uint32_t events, void *data)
{
	struct ltiny_event *e = calloc(1, sizeof(*e));

	e->fd = fd;
	e->cb = cb;
	e->user_data = data;


	struct epoll_event epoll_event = {
		.events = events,
		.data.ptr = e,
	};

	if (epoll_ctl(ctx->epollfd, EPOLL_CTL_ADD, e->fd, &epoll_event) < 0) {
		free(e);
		return NULL;
	}

	LIST_INSERT_HEAD(&ctx->events, e, events);

	return e;
}

void ltiny_ev_del_event(struct ltiny_ev_ctx *ctx, struct ltiny_event *e)
{
	epoll_ctl(ctx->epollfd, EPOLL_CTL_DEL, e->fd, NULL);
	LIST_REMOVE(e, events);
	free(e);
}

int ltiny_ev_loop(struct ltiny_ev_ctx *ctx)
{
	struct epoll_event event;

	while (1) {
		int polled = epoll_wait(ctx->epollfd, &event, 1, -1);
		if (polled < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		if (polled == 0)
			continue;

		struct ltiny_event *ltiny_event = event.data.ptr;
		if (ltiny_event->cb)
			ltiny_event->cb(ctx, ltiny_event, event.events);

		if (ctx->terminate) {
			ctx->terminate = 0; /* Clear flag in case the user reuses the object */
			return 0;
		}
	}

	return 0;
}

void ltiny_ev_exit_loop(struct ltiny_ev_ctx *ctx)
{
	ctx->terminate = 1;
}

void ltiny_ev_free_ctx(struct ltiny_ev_ctx *ctx)
{
	struct ltiny_event *e, *ne;
	LIST_FOREACH_SAFE(e, &ctx->events, events, ne) {
		ltiny_ev_del_event(ctx, e);
	}

	free(ctx);
}

