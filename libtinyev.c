#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

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

struct ltiny_ev_timeout {
	int fd;
	struct ltiny_ev *ev;
	struct itimerspec time;
};

struct ltiny_ev {
	int fd;

	void *user_data;
	ltiny_ev_free_data_cb free_user_data;

	ltiny_ev_cb cb;

	struct ltiny_ev_timeout read_timeout;
	ltiny_ev_cb read_timeout_cb;

	struct ltiny_ev_timeout write_timeout;
	ltiny_ev_cb write_timeout_cb;

	int run_on_thread;
	int marked_for_deletion;

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

	if (!tp || !tp->ev)
		return NULL;

	if (tp->ev->cb)
		tp->ev->cb(tp->ctx, tp->ev, tp->triggered_events);

	free(args);

	return NULL;
}

int ltiny_ev_get_fd(struct ltiny_ev *ev)
{
	if (!ev)
		return -1;

	return ev->fd;
}

void *ltiny_ev_get_user_data(struct ltiny_ev *ev)
{
	if (!ev)
		return NULL;

	return ev->user_data;
}

void ltiny_ev_set_free_data(struct ltiny_ev *ev, ltiny_ev_free_data_cb free_user_data)
{
	if (!ev)
		return;

	ev->free_user_data = free_user_data;
}

void ltiny_ev_set_flags(struct ltiny_ev *ev, uint32_t flags)
{
	if (!ev)
		return;

	ev->run_on_thread = flags & LTINY_EV_RUN_ON_THREAD;
}

struct ltiny_ev_ctx *ltiny_ev_ctx_new(void *user_data)
{
	struct ltiny_ev_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		goto error;

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
	if (!ctx || !ev)
		return -1;

	ev->epoll_event.events = events;

	return epoll_ctl(ctx->epollfd, EPOLL_CTL_MOD, ev->fd, &ev->epoll_event);
}

struct ltiny_ev *ltiny_ev_new(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_cb cb, uint32_t events, void *data)
{
	if (!ctx)
		return NULL;

	struct ltiny_ev *e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	/* Force O_NONBLOCK, otherwise we may face problems */
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	e->read_timeout.fd = -1;
	e->write_timeout.fd = -1;
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

static void ltiny_ev_del_now(struct ltiny_ev_ctx *ctx, struct ltiny_ev *e)
{
	if (!ctx || ! e)
		return;

	if (e->free_user_data)
		e->free_user_data(ctx, e->user_data);

	if (e->read_timeout.fd >= 0) {
		ltiny_ev_del_now(ctx, e->read_timeout.ev);
		close(e->read_timeout.fd);
		e->read_timeout.fd = -1;
	}

	if (e->write_timeout.fd >= 0) {
		ltiny_ev_del_now(ctx, e->write_timeout.ev);
		close(e->write_timeout.fd);
		e->write_timeout.fd = -1;
	}

	epoll_ctl(ctx->epollfd, EPOLL_CTL_DEL, e->fd, NULL);
	pthread_mutex_lock(&ctx->events_mutex);
	LIST_REMOVE(e, events);
	pthread_mutex_unlock(&ctx->events_mutex);

	free(e);
}

void ltiny_ev_del(struct ltiny_ev_ctx *ctx, struct ltiny_ev *e)
{
	if (!ctx || ! e)
		return;
	e->marked_for_deletion = 1;
}

static int ltiny_ev_process_event(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ltiny_ev, uint32_t events)
{
	if (!ctx || !ltiny_ev)
		return -1;

	if (ltiny_ev->cb) {
		if (ltiny_ev->run_on_thread) {
			struct ltiny_ev_cb_thread_params *tp = malloc(sizeof(*tp));
			tp->ctx = ctx;
			tp->ev = ltiny_ev;
			tp->triggered_events = events;

			pthread_t thread;

			pthread_attr_t attrs;
			pthread_attr_init(&attrs);
			pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED);

			pthread_create(&thread, &attrs, ltiny_ev_run_cb, tp);
			pthread_attr_destroy(&attrs);
		} else {
			ltiny_ev->cb(ctx, ltiny_ev, events);
		}
	}

	return 0;
}

static void ltiny_ev_timeout_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	if (!ctx || !ev)
		return;

	uint64_t tmp;
	read(ev->fd, &tmp, sizeof(tmp));

	struct ltiny_ev *ev_parent = ltiny_ev_get_user_data(ev);
	triggered_events = EPOLLERR;
	ltiny_ev_process_event(ctx, ev_parent, triggered_events);
}

int ltiny_ev_loop(struct ltiny_ev_ctx *ctx)
{
	if (!ctx)
		return -1;

 	struct epoll_event event[64];
	int processed[64] = { 0 };

	while (1) {
		int polled = epoll_wait(ctx->epollfd, event, sizeof(event) / sizeof(event[0]), -1);
		if (polled < 0) {
			if (errno == EINTR)
				continue;
			return polled;
		}

		for (int i = 0; i < polled; i++) {
			struct ltiny_ev *ltiny_ev = event[i].data.ptr;
			/* Don't process those events that are waiting to be terminated */
			if (ltiny_ev->marked_for_deletion)
				continue;

			processed[i] = 1;

			/* Reset timeout timers */
			if (event[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP))
				if (ltiny_ev->read_timeout.fd >= 0)
					timerfd_settime(ltiny_ev->read_timeout.fd, 0, &ltiny_ev->read_timeout.time, NULL);

			if (event[i].events & EPOLLOUT)
				if (ltiny_ev->write_timeout.fd >= 0)
					timerfd_settime(ltiny_ev->write_timeout.fd, 0, &ltiny_ev->write_timeout.time, NULL);

			ltiny_ev_process_event(ctx, ltiny_ev, event[i].events);

			if (ctx->terminate)
				break;
		}

		/*
		 * After processing all queued events we can delete those marked for deletion, skipping those that were not
		 * processed because they were already marked for deletion, so we don't try to delete twice the same event
		 */
		for (int i = 0; i < polled; i++) {
			struct ltiny_ev *ltiny_ev = event[i].data.ptr;
			if (processed[i] && ltiny_ev->marked_for_deletion)
				ltiny_ev_del_now(ctx, ltiny_ev);
		}

		if (ctx->terminate) {
			ctx->terminate = 0; /* Clear flag in case the user reuses the object */
			return 0;
		}
	}

	return 0;
}

int ltiny_ev_next_event(struct ltiny_ev_ctx *ctx)
{
	if (!ctx)
		return -1;

	struct epoll_event event;

	int polled = epoll_wait(ctx->epollfd, &event, 1, 0);
	if (polled < 0)
		return polled;

	if (polled == 0)
		return 0;

	struct ltiny_ev *ltiny_ev = event.data.ptr;

	/* Reset timeout timers */
	if (event.events & (EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP))
		if (ltiny_ev->read_timeout.fd >= 0)
			timerfd_settime(ltiny_ev->read_timeout.fd, 0, &ltiny_ev->read_timeout.time, NULL);

	if (event.events & EPOLLOUT)
		if (ltiny_ev->write_timeout.fd >= 0)
			timerfd_settime(ltiny_ev->write_timeout.fd, 0, &ltiny_ev->write_timeout.time, NULL);

	ltiny_ev_process_event(ctx, ltiny_ev, event.events);

	return polled;
}

void ltiny_ev_exit_loop(struct ltiny_ev_ctx *ctx)
{
	if (!ctx)
		return;

	ctx->terminate = 1;
}

void ltiny_ev_ctx_del(struct ltiny_ev_ctx *ctx)
{
	if (!ctx)
		return;

	struct ltiny_ev *e, *ne;
	pthread_mutex_lock(&ctx->events_mutex);
	LIST_FOREACH_SAFE(e, &ctx->events, events, ne) {
		ltiny_ev_del_now(ctx, e);
	}
	pthread_mutex_unlock(&ctx->events_mutex);
	close(ctx->epollfd);
	free(ctx);
}

static void ltiny_ev_set_single_timeout(struct ltiny_ev_ctx *ctx, struct ltiny_ev *e, struct ltiny_ev_timeout *t, ltiny_ev_cb timeout_cb, int timeout_ms)
{
	if (!ctx || !e || !t)
		return;

	if (timeout_ms == 0) {
		if (t->fd >= 0) {
			ltiny_ev_del_now(ctx, t->ev);
			close(t->fd);
			t->fd = -1;
		}
		return;
	}

	if (t->fd < 0) {
		t->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (timeout_cb)
			t->ev = ltiny_ev_new(ctx, t->fd, timeout_cb, EPOLLIN, e);
		else
			t->ev = ltiny_ev_new(ctx, t->fd, ltiny_ev_timeout_cb, EPOLLIN, e);
	}

	t->time.it_value.tv_sec = timeout_ms / 1000;
	t->time.it_value.tv_nsec = (timeout_ms - t->time.it_value.tv_sec * 1000) * 1000000;

	timerfd_settime(t->fd, 0, &t->time, NULL);
}

void ltiny_ev_set_timeout(struct ltiny_ev_ctx *ctx, struct ltiny_ev *e, ltiny_ev_cb read_timeout_cb, ltiny_ev_cb write_timeout_cb, int read_timeout_ms, int write_timeout_ms)
{
	if (!ctx || !e)
		return;

	ltiny_ev_set_single_timeout(ctx, e, &e->read_timeout, read_timeout_cb, read_timeout_ms);
	ltiny_ev_set_single_timeout(ctx, e, &e->write_timeout, write_timeout_cb, write_timeout_ms);
}
