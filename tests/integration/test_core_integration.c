#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <cmocka.h>

#include "libtinyev.h"

/* ── Test helpers ────────────────────────────────────────────── */

/* Counter para verificar que callbacks se invocan */
static atomic_int callback_counter = 0;

static void counting_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t events)
{
    (void)ctx;
    (void)ev;
    (void)events;
    atomic_fetch_add(&callback_counter, 1);
}

static void exit_on_first_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t events)
{
    (void)ev;
    (void)events;
    ltiny_ev_exit_loop(ctx);
}

static void *make_pipe(void)
{
    int fd[2];
    assert_int_equal(pipe(fd), 0);
    /* Devuelve el read end; el caller debe cerrar ambos */
    return (void *)(intptr_t)fd[0];
}

static void close_pipe(int fd_read, int fd_write)
{
    close(fd_read);
    close(fd_write);
}

static void write_to_pipe(int fd, const char *data, size_t len)
{
    ssize_t ret = write(fd, data, len);
    assert_int_equal(ret, (ssize_t)len);
}

/* ── Tests ───────────────────────────────────────────────────── */

/* Context creation: valid context */
static void test_ctx_new_valid(void **state)
{
    (void)state;
    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);
    ltiny_ev_ctx_del(ctx);
}

/* Context creation: with user_data */
static void test_ctx_new_with_user_data(void **state)
{
    (void)state;
    int user_val = 42;
    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(&user_val);
    assert_non_null(ctx);

    void *recovered = ltiny_ev_get_ctx_user_data(ctx);
    assert_int_equal((intptr_t)recovered, (intptr_t)&user_val);

    ltiny_ev_ctx_del(ctx);
}

/* Context delete: NULL safe */
static void test_ctx_del_null_safe(void **state)
{
    (void)state;
    ltiny_ev_ctx_del(NULL);
}

/* Event registration and fd retrieval */
static void test_event_new_and_fd(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    int user_val = 99;
    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev *ev = ltiny_ev_new(ctx, pipefd[0], counting_cb, EPOLLIN, &user_val);
    assert_non_null(ev);

    assert_int_equal(ltiny_ev_get_fd(ev), pipefd[0]);
    assert_int_equal((intptr_t)ltiny_ev_get_user_data(ev), (intptr_t)&user_val);

    ltiny_ev_del(ctx, ev);
    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Event registration: ctx NULL returns NULL */
static void test_event_new_null_ctx(void **state)
{
    (void)state;
    struct ltiny_ev *ev = ltiny_ev_new(NULL, 0, NULL, 0, NULL);
    assert_null(ev);
}

/* Event registration: invalid fd */
static void test_event_new_invalid_fd(void **state)
{
    (void)state;
    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev *ev = ltiny_ev_new(ctx, -1, NULL, EPOLLIN, NULL);
    assert_null(ev);

    ltiny_ev_ctx_del(ctx);
}

/* Mod events: success */
static void test_mod_events_success(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev *ev = ltiny_ev_new(ctx, pipefd[0], NULL, EPOLLIN, NULL);
    assert_non_null(ev);

    int ret = ltiny_ev_mod_events(ctx, ev, EPOLLOUT);
    assert_int_equal(ret, 0);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Mod events: NULL inputs */
static void test_mod_events_null(void **state)
{
    (void)state;
    int ret = ltiny_ev_mod_events(NULL, NULL, 0);
    assert_int_equal(ret, -1);
}

/* Set flags: threaded callback */
static void test_set_flags_threaded(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    atomic_store(&callback_counter, 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev *ev = ltiny_ev_new(ctx, pipefd[0], counting_cb, EPOLLIN, NULL);
    assert_non_null(ev);

    ltiny_ev_set_flags(ev, LTINY_EV_RUN_ON_THREAD);

    /* Write to trigger the callback */
    write_to_pipe(pipefd[1], "x", 1);

    /* Run the event loop to process the event (callback runs in detached thread) */
    ltiny_ev_exit_loop(ctx);
    int ret = ltiny_ev_loop(ctx);
    (void)ret;

    /* Give the detached thread time to finish */
    usleep(50000);

    /* Callback was invoked in a separate thread */
    assert_int_equal(atomic_load(&callback_counter), 1);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Event deletion: marks for deletion */
static void test_event_del_marks_for_deletion(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev *ev = ltiny_ev_new(ctx, pipefd[0], exit_on_first_cb, EPOLLIN, NULL);
    assert_non_null(ev);

    /* Mark for deletion before processing */
    ltiny_ev_del(ctx, ev);

    /* Process — should not crash, event is skipped */
    int ret = ltiny_ev_next_event(ctx);
    assert_true(ret == 0 || ret == 1);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Next event: no event ready */
static void test_next_event_no_event(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    ltiny_ev_new(ctx, pipefd[0], counting_cb, EPOLLIN, NULL);

    /* No data written, should return 0 */
    int ret = ltiny_ev_next_event(ctx);
    assert_int_equal(ret, 0);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Next event: event ready */
static void test_next_event_ready(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    atomic_store(&callback_counter, 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    ltiny_ev_new(ctx, pipefd[0], counting_cb, EPOLLIN, NULL);

    write_to_pipe(pipefd[1], "data", 4);

    int ret = ltiny_ev_next_event(ctx);
    assert_int_equal(ret, 1);
    assert_int_equal(atomic_load(&callback_counter), 1);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Exit loop: triggers loop termination */
static void test_exit_loop(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    ltiny_ev_new(ctx, pipefd[0], exit_on_first_cb, EPOLLIN, NULL);

    write_to_pipe(pipefd[1], "x", 1);

    /* loop should exit after first callback calls ltiny_ev_exit_loop */
    int ret = ltiny_ev_loop(ctx);
    assert_int_equal(ret, 0);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Integration: event loop processes event then exits */
static void test_loop_event_then_exit(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    atomic_store(&callback_counter, 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    ltiny_ev_new(ctx, pipefd[0], exit_on_first_cb, EPOLLIN, NULL);

    write_to_pipe(pipefd[1], "x", 1);
    ltiny_ev_loop(ctx);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Integration: full event loop with read */
static void test_loop_full_read(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    atomic_store(&callback_counter, 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    ltiny_ev_new(ctx, pipefd[0], counting_cb, EPOLLIN, NULL);

    write_to_pipe(pipefd[1], "hello world", 11);

    /* Run loop until we see the event, then exit */
    ltiny_ev_exit_loop(ctx);
    int ret = ltiny_ev_loop(ctx);
    assert_int_equal(ret, 0);

    /* Give detached threads a moment */
    usleep(10000);

    assert_int_equal(atomic_load(&callback_counter), 1);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Integration: multiple events in sequence */
static void test_loop_multiple_events(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    atomic_store(&callback_counter, 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev *ev1 = ltiny_ev_new(ctx, pipefd[0], exit_on_first_cb, EPOLLIN, NULL);
    assert_non_null(ev1);

    /* First event */
    write_to_pipe(pipefd[1], "first", 5);
    ltiny_ev_loop(ctx);

    /* Delete the first event to free the epoll fd */
    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);

    /* Create a new pipe and context for second event */
    assert_int_equal(pipe(pipefd), 0);
    ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    atomic_store(&callback_counter, 0);
    struct ltiny_ev *ev2 = ltiny_ev_new(ctx, pipefd[0], exit_on_first_cb, EPOLLIN, NULL);
    assert_non_null(ev2);

    write_to_pipe(pipefd[1], "second", 6);
    ltiny_ev_loop(ctx);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Integration: free_user_data cleanup on event deletion */
static void test_free_user_data_cleanup(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    void free_user_data_wrapper(struct ltiny_ev_ctx *ctx, void *ud)
    {
        (void)ctx;
        free(ud);
    }

    int *user_ptr = malloc(sizeof(*user_ptr));
    *user_ptr = 777;

    struct ltiny_ev *ev = ltiny_ev_new(ctx, pipefd[0], NULL, EPOLLIN, user_ptr);
    assert_non_null(ev);

    ltiny_ev_set_free_data(ev, free_user_data_wrapper);

    ltiny_ev_del(ctx, ev);
    ltiny_ev_ctx_del(ctx);

    /* If free was called, memory is gone — just verify no crash */
    close_pipe(pipefd[0], pipefd[1]);
}

/* Integration: ctx user_data survives event lifecycle */
static void test_ctx_user_data_lifecycle(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    int global_data = 123;
    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(&global_data);
    assert_non_null(ctx);

    struct ltiny_ev *ev = ltiny_ev_new(ctx, pipefd[0], exit_on_first_cb, EPOLLIN, NULL);
    assert_non_null(ev);

    void *recovered = ltiny_ev_get_ctx_user_data(ctx);
    assert_int_equal((intptr_t)recovered, (intptr_t)&global_data);

    write_to_pipe(pipefd[1], "x", 1);
    ltiny_ev_loop(ctx);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Integration: context deletion with timeouts (demonstrates double-free fix)
 *
 * Before the fix: context teardown would double-free the timerfd event
 * because ltiny_ev_ctx_del iterates all events and calls ltiny_ev_del_now
 * on each one. The timerfd event (read_timeout.ev or write_timeout.ev)
 * is created last (LIST_INSERT_HEAD), so it's first in the list.
 * ltiny_ev_del_now frees it, then later when the parent event's
 * ltiny_ev_del_now runs recursively on read_timeout.ev, a double-free
 * occurs. */
static void test_ctx_del_with_events(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    /* Create an event WITH a timeout — this creates a timerfd child event */
    struct ltiny_ev *ev = ltiny_ev_new(ctx, pipefd[0], exit_on_first_cb, EPOLLIN, NULL);
    assert_non_null(ev);
    ltiny_ev_set_timeout(ctx, ev, NULL, NULL, 100, 100);

    /* Write and process one event */
    write_to_pipe(pipefd[1], "x", 1);
    ltiny_ev_loop(ctx);

    /* This cleanup must NOT double-free.
     * Without the fix, the timerfd event gets freed once by the
     * LIST_FOREACH_SAFE loop and again by the parent's recursive
     * ltiny_ev_del_now call. */
    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* Integration: event marked for deletion BEFORE epoll_wait is cleaned up
 *
 * Bug: events marked marked_for_deletion before epoll_wait returns are
 * skipped (continue) but never cleaned because processed[i] == 0.
 * They remain in epoll forever, leaking timerfd resources. */
static void test_event_del_before_epoll_wait(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev *ev = ltiny_ev_new(ctx, pipefd[0], counting_cb, EPOLLIN, NULL);
    assert_non_null(ev);

    /* Mark for deletion BEFORE any epoll_wait */
    ltiny_ev_del(ctx, ev);

    /* next_event should clean up the event, not leave it as a zombie */
    int ret = ltiny_ev_next_event(ctx);
    assert_int_not_equal(ret, -1);

    ltiny_ev_ctx_del(ctx);
    close_pipe(pipefd[0], pipefd[1]);
}

/* ── Main ────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ctx_new_valid),
        cmocka_unit_test(test_ctx_new_with_user_data),
        cmocka_unit_test(test_ctx_del_null_safe),
        cmocka_unit_test(test_event_new_and_fd),
        cmocka_unit_test(test_event_new_null_ctx),
        cmocka_unit_test(test_event_new_invalid_fd),
        cmocka_unit_test(test_mod_events_success),
        cmocka_unit_test(test_mod_events_null),
        cmocka_unit_test(test_set_flags_threaded),
        cmocka_unit_test(test_event_del_marks_for_deletion),
        cmocka_unit_test(test_next_event_no_event),
        cmocka_unit_test(test_next_event_ready),
        cmocka_unit_test(test_exit_loop),
        cmocka_unit_test(test_loop_event_then_exit),
        cmocka_unit_test(test_loop_full_read),
        cmocka_unit_test(test_loop_multiple_events),
        cmocka_unit_test(test_free_user_data_cleanup),
        cmocka_unit_test(test_ctx_user_data_lifecycle),
        cmocka_unit_test(test_ctx_del_with_events),
        cmocka_unit_test(test_event_del_before_epoll_wait),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
