#include <sys/epoll.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include "freebsd-queue.h"
#include "libtinyev.h"

struct ltiny_ev_ctx {
	pthread_mutex_t events_mutex;
	LIST_HEAD(events_list, ltiny_ev) events;
	int epollfd;
	int terminate;

	void *user_data;
};

void *ltiny_ev_get_ctx_user_data(struct ltiny_ev_ctx *ctx)
{
	return ctx->user_data;
}

struct ltiny_ev;

typedef void (*event_callback)(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events);

struct ltiny_ev {
	int fd;
	void *user_data;
	ltiny_ev_free_data_cb free_user_data;

	event_callback cb;
	int run_on_thread;

	struct epoll_event epoll_event;

	LIST_ENTRY(ltiny_ev) events;
};

struct ltiny_ev_cb_thread_params {
	struct ltiny_ev_ctx *ctx;
	struct ltiny_ev *ev;
	uint32_t triggered_events;
};

void *ltiny_ev_run_cb(void *args)
{
	struct ltiny_ev_cb_thread_params *tp = args;

	tp->ev->cb(tp->ctx, tp->ev, tp->triggered_events);

	return NULL;
}

int ltiny_ev_get_fd(struct ltiny_ev *ev)
{
	return ev->fd;
}

void *ltiny_ev_get_user_data(struct ltiny_ev *ev)
{
	return ev->user_data;
}

void ltiny_ev_set_user_data(struct ltiny_ev *ev, void *user_data)
{
	ev->user_data = user_data;
}

void ltiny_ev_set_free_data(struct ltiny_ev *ev, ltiny_ev_free_data_cb free_user_data)
{
	ev->free_user_data = free_user_data;
}

void ltiny_ev_set_flags(struct ltiny_ev *ev, uint32_t flags)
{
	ev->run_on_thread = flags & LTINY_EV_RUN_ON_THREAD;
}

struct ltiny_ev_ctx *ltiny_ev_new_ctx(void *user_data)
{
	struct ltiny_ev_ctx *ctx = calloc(1, sizeof(*ctx));
	ctx->epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (ctx->epollfd < 0)
		goto error;

	ctx->user_data = user_data;

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

	pthread_mutex_init(&ctx->events_mutex, &attr);

	return ctx;

error:
	free(ctx);
	return NULL;
}

int ltiny_ev_mod_events(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t events)
{
	ev->epoll_event.events = events;

	return epoll_ctl(ctx->epollfd, EPOLL_CTL_MOD, ev->fd, &ev->epoll_event);
}

struct ltiny_ev *ltiny_ev_new_event(struct ltiny_ev_ctx *ctx, int fd, event_callback cb, uint32_t events, void *data)
{
	struct ltiny_ev *e = calloc(1, sizeof(*e));

	e->fd = fd;
	e->cb = cb;
	e->user_data = data;

	e->epoll_event.events = events;
	e->epoll_event.data.ptr = e;

	if (epoll_ctl(ctx->epollfd, EPOLL_CTL_ADD, e->fd, &e->epoll_event) < 0) {
		free(e);
		return NULL;
	}

	pthread_mutex_lock(&ctx->events_mutex);
	LIST_INSERT_HEAD(&ctx->events, e, events);
	pthread_mutex_unlock(&ctx->events_mutex);

	return e;
}

void ltiny_ev_del_event(struct ltiny_ev_ctx *ctx, struct ltiny_ev *e)
{
	if (e->free_user_data) {
		e->free_user_data(ctx, e->user_data);
		/* free_user_data must call ltiny_ev_del_event again to finish the deletion procedure */
		return;
	}

	epoll_ctl(ctx->epollfd, EPOLL_CTL_DEL, e->fd, NULL);
	pthread_mutex_lock(&ctx->events_mutex);
	LIST_REMOVE(e, events);
	pthread_mutex_unlock(&ctx->events_mutex);

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

		struct ltiny_ev *ltiny_ev = event.data.ptr;
		if (ltiny_ev->cb) {
			if (ltiny_ev->run_on_thread) {
				struct ltiny_ev_cb_thread_params tp = {
					.ctx = ctx,
					.ev = ltiny_ev,
					.triggered_events = event.events,
				};
				pthread_t thread;

				pthread_attr_t attrs;
				pthread_attr_init(&attrs);
				pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED);

				pthread_create(&thread, NULL, ltiny_ev_run_cb, &tp);
				pthread_attr_destroy(&attrs);
			} else {
				ltiny_ev->cb(ctx, ltiny_ev, event.events);
			}
		}

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
	struct ltiny_ev *e, *ne;
	pthread_mutex_lock(&ctx->events_mutex);
	LIST_FOREACH_SAFE(e, &ctx->events, events, ne) {
		ltiny_ev_del_event(ctx, e);
	}
	pthread_mutex_unlock(&ctx->events_mutex);

	free(ctx);
}

