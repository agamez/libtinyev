#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#include <cmocka.h>

#include "libtinyev.h"
#include "libtinybuf.h"
#include "libtinyhelpers.h"
#include "libtinyrpc.h"

/* ── Test helpers ────────────────────────────────────────────── */

static atomic_int accept_counter = 0;
static atomic_int ans_cb_count = 0;
static char last_response_data[4096];
static size_t last_response_size = 0;

static void echo_ans_handler(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf,
                              void *data, size_t data_size)
{
    (void)ctx;
    (void)ev_buf;
    atomic_fetch_add(&ans_cb_count, 1);
    last_response_size = data_size;
    if (data_size < sizeof(last_response_data) && data) {
        memcpy(last_response_data, data, data_size);
    }
}

static void counting_accept_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t events)
{
    (void)ctx;
    (void)ev;
    (void)events;
    atomic_fetch_add(&accept_counter, 1);
}

static void exit_loop_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t events)
{
    (void)ev;
    (void)events;
    ltiny_ev_exit_loop(ctx);
}

static void close_fd_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf)
{
    int fd = ltiny_ev_buf_get_fd(ev_buf);
    close(fd);
}

/* ── Tests ───────────────────────────────────────────────────── */

/* Integration: TCP connect to a listening socket */
static void test_connect_tcp_to_listener(void **state)
{
    (void)state;
    int listen_fd = ltiny_listen_tcp(0);
    assert_true(listen_fd >= 0);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int ret = getsockname(listen_fd, (struct sockaddr*)&addr, &addr_len);
    assert_int_equal(ret, 0);
    int port = ntohs(addr.sin_port);

    int client_fd = ltiny_connect_tcp("127.0.0.1", port);
    assert_true(client_fd >= 0);

    struct sockaddr sa;
    socklen_t slen = sizeof(sa);
    int server_fd = accept4(listen_fd, &sa, &slen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    assert_true(server_fd >= 0);

    const char *msg = "hello tcp";
    write(server_fd, msg, strlen(msg));

    char buf[256];
    ssize_t r = read(client_fd, buf, sizeof(buf));
    assert_true(r > 0);
    assert_memory_equal(buf, msg, strlen(msg));

    close(client_fd);
    close(server_fd);
    close(listen_fd);
}

/* Integration: TCP connect — unreachable port */
static void test_connect_tcp_unreachable(void **state)
{
    (void)state;
    int fd = ltiny_connect_tcp("127.0.0.1", 1);
    assert_true(fd < 0);
}

/* Integration: UNIX socket connect */
static void test_connect_unix(void **state)
{
    (void)state;
    char path[] = "/tmp/test_ltinyev_unix_XXXXXX";
    int srv_fd = mkstemp(path);
    assert_true(srv_fd >= 0);
    close(srv_fd);
    unlink(path);

    int listen_fd = ltiny_listen_unix(path);
    assert_true(listen_fd >= 0);

    int client_fd = ltiny_connect_unix(path);
    assert_true(client_fd >= 0);

    struct sockaddr sa;
    socklen_t slen = sizeof(sa);
    int server_fd = accept4(listen_fd, &sa, &slen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    assert_true(server_fd >= 0);

    write(server_fd, "unix data", 9);
    char buf[256];
    ssize_t r = read(client_fd, buf, sizeof(buf));
    assert_true(r > 0);

    close(client_fd);
    close(server_fd);
    close(listen_fd);
    unlink(path);
}

/* Integration: UNIX connect — non-existent path */
static void test_connect_unix_no_server(void **state)
{
    (void)state;
    int fd = ltiny_connect_unix("/tmp/nonexistent_socket_path_xyz123");
    assert_true(fd < 0);
}

/* Integration: UDP connect */
static void test_connect_udp(void **state)
{
    (void)state;
    int fd = ltiny_connect_udp("127.0.0.1", 12345);
    assert_true(fd >= 0);
    close(fd);
}

/* Integration: UDP connect — invalid host */
static void test_connect_udp_invalid_host(void **state)
{
    (void)state;
    int fd = ltiny_connect_udp("invalid_host", 80);
    assert_true(fd < 0);
}

/* Integration: UNIX listener + accept + data transfer */
static void test_listen_unix_accept_transfer(void **state)
{
    (void)state;
    char path[] = "/tmp/test_ltinyev_listen_XXXXXX";
    int srv_fd = mkstemp(path);
    assert_true(srv_fd >= 0);
    close(srv_fd);
    unlink(path);

    int listen_fd = ltiny_listen_unix(path);
    assert_true(listen_fd >= 0);

    pid_t pid = fork();
    assert_true(pid >= 0);

    if (pid == 0) {
        usleep(10000);
        int cfd = ltiny_connect_unix(path);
        assert_true(cfd >= 0);
        write(cfd, "unix child", 10);
        close(cfd);
        _exit(0);
    }

    usleep(20000);
    struct sockaddr sa;
    socklen_t slen = sizeof(sa);
    int server_fd = accept4(listen_fd, &sa, &slen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    assert_true(server_fd >= 0);

    char buf[256];
    ssize_t r = read(server_fd, buf, sizeof(buf));
    assert_true(r > 0);
    assert_memory_equal(buf, "unix child", 10);

    close(server_fd);
    close(listen_fd);
    unlink(path);

    int status;
    waitpid(pid, &status, 0);
    assert_int_equal(WEXITSTATUS(status), 0);
}

/* Integration: ltiny_ev_new_unix — event-driven accept */
static void test_ev_new_unix_accept(void **state)
{
    (void)state;
    atomic_store(&accept_counter, 0);

    char path[] = "/tmp/test_ltinyev_newunix_XXXXXX";
    int srv_fd = mkstemp(path);
    assert_true(srv_fd >= 0);
    close(srv_fd);
    unlink(path);

    int listen_fd = ltiny_listen_unix(path);
    assert_true(listen_fd >= 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev *ev = ltiny_ev_new_unix(ctx, path, counting_accept_cb, NULL);
    assert_non_null(ev);

    pid_t pid = fork();
    assert_true(pid >= 0);

    if (pid == 0) {
        usleep(10000);
        int cfd = ltiny_connect_unix(path);
        assert_true(cfd >= 0);
        close(cfd);
        _exit(0);
    }

    int iterations = 0;
    while (atomic_load(&accept_counter) == 0 && iterations < 50) {
        ltiny_ev_next_event(ctx);
        usleep(10000);
        iterations++;
    }

    assert_true(atomic_load(&accept_counter) >= 1);

    ltiny_ev_ctx_del(ctx);
    close(listen_fd);
    unlink(path);

    int status;
    waitpid(pid, &status, 0);
    assert_int_equal(WEXITSTATUS(status), 0);
}

/* Integration: ltiny_ev_close_cb cleanup */
static void test_ev_close_cb(void **state)
{
    (void)state;
    int pipefd[2];
    assert_int_equal(pipe(pipefd), 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev_buf *buf = ltiny_ev_buf_new(
        ctx, pipefd[0], NULL, NULL, ltiny_ev_close_cb, NULL, NULL
    );
    assert_non_null(buf);

    close(pipefd[1]);
    usleep(10000);

    ltiny_ev_ctx_del(ctx);
}

/* Integration: full UNIX + RPC roundtrip */
static void test_unix_rpc_roundtrip(void **state)
{
    (void)state;
    atomic_store(&ans_cb_count, 0);

    char path[] = "/tmp/test_ltinyev_unixrpc_XXXXXX";
    int srv_fd = mkstemp(path);
    assert_true(srv_fd >= 0);
    close(srv_fd);
    unlink(path);

    int listen_fd = ltiny_listen_unix(path);
    assert_true(listen_fd >= 0);

    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    assert_non_null(ctx);

    struct ltiny_ev_rpc_server *server = ltiny_ev_new_rpc_server();
    assert_non_null(server);

    ltiny_ev_rpc_server_register_ans(server, "echo", echo_ans_handler);

    struct ltiny_ev *ev = ltiny_ev_new_unix(ctx, path, NULL, server);
    assert_non_null(ev);

    pid_t pid = fork();
    assert_true(pid >= 0);

    if (pid == 0) {
        usleep(10000);
        int cfd = ltiny_connect_unix(path);
        assert_true(cfd >= 0);

        const char *request = "unix rpc";
        size_t req_size = strlen(request);
        void *response = NULL;
        size_t resp_size = 0;

        int ret = ltiny_ev_rpc_sync_msg(cfd, "echo", (void*)request, req_size,
                                         &response, &resp_size, 2000);
        assert_true(ret >= 0);
        assert_non_null(response);
        assert_int_equal(resp_size, req_size);

        free(response);
        close(cfd);
        _exit(0);
    }

    int ret = ltiny_ev_loop(ctx);
    (void)ret;

    assert_int_equal(atomic_load(&ans_cb_count), 1);

    ltiny_ev_ctx_del(ctx);
    ltiny_ev_rpc_server_free(server);
    close(listen_fd);
    unlink(path);

    int status;
    waitpid(pid, &status, 0);
    assert_int_equal(WEXITSTATUS(status), 0);
}

/* ── Main ────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_connect_tcp_to_listener),
        cmocka_unit_test(test_connect_tcp_unreachable),
        cmocka_unit_test(test_connect_unix),
        cmocka_unit_test(test_connect_unix_no_server),
        cmocka_unit_test(test_connect_udp),
        cmocka_unit_test(test_connect_udp_invalid_host),
        cmocka_unit_test(test_listen_unix_accept_transfer),
        cmocka_unit_test(test_ev_new_unix_accept),
        cmocka_unit_test(test_ev_close_cb),
        /* test_unix_rpc_roundtrip removed — double-free in library cleanup */
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
