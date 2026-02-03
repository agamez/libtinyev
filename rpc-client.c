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

void art_arm_reply(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *request, size_t request_size)
{
	printf("art_arm reply: '%s'\n", request);
	ltiny_ev_exit_loop(ctx);
}

int main(int argc, char *argv[])
{
	int fd = ltiny_connect_tcp("127.0.0.1", 2323);
	if (fd < 0)
		return -1;

	void *response = NULL;
	size_t response_size = 0;
	int ret;

	ret = ltiny_ev_rpc_sync_msg(fd, "art_arm", "true", 4, &response, &response_size, 2000);
	if (response_size > 0)
		printf("art_arm_reply ok answer size: '%d' %s\n", response_size, response);
	else if (ret < 0)
		printf("Timeout? answer size: '%d' %s\n", response_size, response);
	free(response);

	ltiny_ev_rpc_sync_msg(fd, "art_test", "true", 4, &response, &response_size, 5000);
	if (response_size > 0)
		printf("art_arm_reply ok answer size: '%d' %s\n", response_size, response);
	else if (ret < 0)
		printf("Timeout? answer size: '%d' %s\n", response_size, response);
	free(response);

	ltiny_ev_rpc_sync_msg(fd, "art_arm", "false", 5, (void **)&response, &response_size, 1000);
	if (response_size > 0)
		printf("art_arm_reply ok: '%s'\n", response);
	else if (ret < 0)
		printf("Timeout? answer size: '%d' %s\n", response_size, response);
	free(response);

	struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);

	struct ltiny_ev_rpc_server *server = ltiny_ev_new_rpc_server();
	ltiny_ev_rpc_server_register_ans(server, "art_arm", art_arm_reply);

	struct ltiny_ev_buf *ev_buf = ltiny_ev_new_rpc_event(ctx, server, fd, NULL, NULL, NULL);
	
	ltiny_ev_rpc_send_msg(ctx, ev_buf, LT_EV_RPC_TYPE_REQ, "art_arm", "true", 4);

	ltiny_ev_loop(ctx);

	ltiny_ev_ctx_del(ctx);
	ltiny_ev_rpc_server_free(server);

	close(fd);

	return 0;
}
