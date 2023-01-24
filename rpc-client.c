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

void *art_arm_reply(void *request, size_t request_size, void **response, size_t *response_size)
{
	printf("art_arm reply: '%s'\n", request);
}

int main(int argc, char *argv[])
{
	struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);

	struct ltiny_ev_rpc_server *server = ltiny_ev_new_rpc_server();
	ltiny_ev_rpc_server_register(server, "art_arm", art_arm_reply);

	int fd = connect_tcp("127.0.0.1", 2323);
	struct ltiny_ev_buf *ev_buf = ltiny_ev_new_rpc_event(ctx, server, fd);
	
	ltiny_ev_rpc_send_msg(ctx, ev_buf, LT_EV_RPC_TYPE_REQ, "art_arm", "true", 4);

	ltiny_ev_loop(ctx);

	ltiny_ev_ctx_del(ctx);

	close(fd);

	return 0;
}
