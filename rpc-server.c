#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/un.h>

#include <signal.h>
#include <sys/signalfd.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "libtinyev.h"
#include "libtinybuf.h"
#include "libtinyrpc.h"

static inline int listen_tcp(int port)
{
	int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_IP);

	if (sockfd < 0) {
		perror("socket");
		return -errno;
	}

	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	struct sockaddr_in local = { 0 };
	local.sin_family = AF_INET;
	local.sin_port = htons(port);

	local.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		perror("bind");
		return -errno;
	}

	listen(sockfd, 16);

	return sockfd;
}

void signal_event_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	struct signalfd_siginfo siginfo;
	ssize_t ret = read(ltiny_ev_get_fd(ev), &siginfo, sizeof(siginfo));

	printf("Holi\n");

	switch (siginfo.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		ltiny_ev_exit_loop(ctx);
		break;
	}
}

void close_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf)
{
	int *client_structure_id = ltiny_ev_rpc_get_user_data(ev_buf);
	free(client_structure_id);
}

void accept_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	int fd = accept(ltiny_ev_get_fd(ev), NULL, NULL);
	int *client_structure_id = malloc(sizeof(*client_structure_id));
	*client_structure_id = random();

	struct ltiny_ev_rpc_server *server = ltiny_ev_get_user_data(ev);

	ltiny_ev_new_rpc_event(ctx, server, fd, close_cb, NULL, client_structure_id);
}

ssize_t art_arm(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *request, size_t request_size, void **response)
{
	int *client_structure_id = ltiny_ev_rpc_get_user_data(ev_buf);

	printf("Arming request from client ID %d: '%s'\n", *client_structure_id, request);
	if (!strcmp(request, "true"))
		*response = "ARMADO\n";
	else
		*response = "DESARMADO\n";

	return strlen(*(char **)response) + 1;
}

ssize_t art_test(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *request, size_t request_size, void **response)
{
	int *client_structure_id = ltiny_ev_rpc_get_user_data(ev_buf);

	printf("Test request from client ID %d: '%s'\n", *client_structure_id, request);
	*response = strdup("This tests auto-free of alloc'ed data");

	return strlen(*(char **)response);
}

int main(int argc, char *argv[])
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigprocmask(SIG_BLOCK, &mask, NULL);
	int signals_fd = signalfd(-1, &mask, SFD_CLOEXEC);
	
	struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);

	ltiny_ev_new(ctx, signals_fd, signal_event_cb, EPOLLIN, NULL);

	int sock_fd = listen_tcp(2323);

	struct ltiny_ev_rpc_server *server = ltiny_ev_new_rpc_server();

	ltiny_ev_rpc_server_register_req(server, "art_arm", art_arm, NULL);
	ltiny_ev_rpc_server_register_req(server, "art_test", art_test, free);

	ltiny_ev_new(ctx, sock_fd, accept_cb, EPOLLIN, server);

	ltiny_ev_loop(ctx);
	ltiny_ev_ctx_del(ctx);

	ltiny_ev_rpc_server_free(server);

	return 0;
}
