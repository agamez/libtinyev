#include <fcntl.h>
#include <errno.h>

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "libtinyev.h"
#include "libtinybuf.h"
#include "libtinyrpc.h"

static inline int connect_tcp(char *host, int port)
{
	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};

	int ret = inet_aton(host, &local.sin_addr);
	if (!ret) {
		perror("inet_aton");
		return -1;
	}

	if (connect(sockfd, (struct sockaddr*)&local, sizeof(local)) < 0) {
		perror("connect");
		return -1;
	}

	return sockfd;
}

void *art_arm_reply(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *request, size_t request_size)
{
	printf("art_arm reply: '%s'\n", request);
	ltiny_ev_exit_loop(ctx);
}

struct ltiny_ev_rpc_data_length {
	void *response;
	size_t response_size;
};

void *generic_call_reply_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *request, size_t request_size)
{
	struct ltiny_ev_rpc_data_length *dl = ltiny_ev_get_ctx_user_data(ctx);
	dl->response = request;
	dl->response_size = request_size;
	ltiny_ev_exit_loop(ctx);
}

int ltiny_ev_rpc_sync_msg(int fd, const char *call, void *data, size_t data_size, void **response, size_t *response_size)
{
	struct ltiny_ev_rpc_data_length dl;
	int ret = -1;


	struct ltiny_ev_rpc_server *server = ltiny_ev_new_rpc_server();
	ltiny_ev_rpc_server_register_ans(server, call, generic_call_reply_cb);

	struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(&dl);
	struct ltiny_ev_buf *ev_buf = ltiny_ev_new_rpc_event(ctx, server, fd);
	if (!ev_buf)
		goto out;

	ltiny_ev_rpc_send_msg(ctx, ev_buf, LT_EV_RPC_TYPE_REQ, (const char *)call, data, data_size);

	ltiny_ev_loop(ctx);

	*response = dl.response;
	*response_size = dl.response_size;

	ret = 0;

out:
	ltiny_ev_ctx_del(ctx);
	ltiny_ev_rpc_server_free(server);

	return 0;
}

int main(int argc, char *argv[])
{
	int fd = connect_tcp("127.0.0.1", 2323);

	void *response = NULL;
	size_t response_size = 0;
	ltiny_ev_rpc_sync_msg(fd, "art_arm", "true", 4, &response, &response_size);
	if (response_size > 0)
		printf("art_arm_reply ok answer size: '%d' %s\n", response_size, response);

	ltiny_ev_rpc_sync_msg(fd, "art_arm", "false", 5, (void **)&response, &response_size);
	if (response_size > 0)
		printf("art_arm_reply ok: '%s'\n", response);

#if 0
	struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);

	struct ltiny_ev_rpc_server *server = ltiny_ev_new_rpc_server();
	ltiny_ev_rpc_server_register_ans(server, "art_arm", art_arm_reply);

	struct ltiny_ev_buf *ev_buf = ltiny_ev_new_rpc_event(ctx, server, fd);
	
	ltiny_ev_rpc_send_msg(ctx, ev_buf, LT_EV_RPC_TYPE_REQ, "art_arm", "true", 4);

	ltiny_ev_loop(ctx);

	ltiny_ev_ctx_del(ctx);
#endif
	close(fd);

	return 0;
}
