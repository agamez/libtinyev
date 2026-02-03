#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>
#include <linux/un.h>
#include <netinet/tcp.h>

#include "libtinyev.h"
#include "libtinybuf.h"
#include "libtinyrpc.h"


int ltiny_connect_unix(const char *const path)
{
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0)
		return -errno;

	struct sockaddr_un local = { 0 };
	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, path, UNIX_PATH_MAX);

	if (connect(sockfd, (struct sockaddr*)&local, sizeof(local)) < 0)
		goto error;

	return sockfd;

error:
	close(sockfd);
	return -errno;
}


int ltiny_connect_udp(int port)
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0)
		return -errno;

	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

	if (connect(sockfd, (struct sockaddr*)&local, sizeof(local)) < 0)
		goto error;

	return sockfd;

error:
	close(sockfd);
	return -errno;
}

int ltiny_connect_tcp(const char *host, int port)
{
	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		return -errno;

	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};

	int ret = inet_aton(host, &local.sin_addr);
	if (!ret)
		goto error;

	if (connect(sockfd, (struct sockaddr*)&local, sizeof(local)) < 0)
		goto error;

	return sockfd;

error:
	close(sockfd);
	return -errno;
}


int ltiny_listen_unix(const char *path)
{
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sockfd < 0)
		return -errno;

	struct sockaddr_un local = { 0 };
	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, path, UNIX_PATH_MAX);
	unlink(local.sun_path);

	if (bind(sockfd, (struct sockaddr*)&local, sizeof(local)) < 0)
		goto error;

	listen(sockfd, 16);

	return sockfd;

error:
	close(sockfd);
	return -errno;
}

int ltiny_listen_tcp(int port)
{
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

	if (sockfd < 0)
		return -errno;

	struct sockaddr_in local = { 0 };
	local.sin_family = AF_INET;
	local.sin_port = htons(port);

	local.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) < 0)
		goto error;

	listen(sockfd, 16);

	return sockfd;

error:
	close(sockfd);
	return -errno;
}

void ltiny_ev_close_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf)
{
	int fd = ltiny_ev_buf_get_fd(ev_buf);
	close(fd);
}

void ltiny_ev_accept_rpc_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
{
	if (triggered_events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
		ltiny_ev_del(ctx, ev);
		return;
	}

	struct sockaddr sockaddr;
	socklen_t addrlen = sizeof(sockaddr);

	int fd = accept4(ltiny_ev_get_fd(ev), &sockaddr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0)
		return;

	struct ltiny_ev_rpc_server *server = ltiny_ev_get_user_data(ev);
	ltiny_ev_new_rpc_event(ctx, server, fd, ltiny_ev_close_cb, NULL, NULL);
}

struct ltiny_ev *ltiny_ev_new_tcp(struct ltiny_ev_ctx *ctx, int tcp_port, ltiny_ev_cb accept_cb, void *data)
{
	int fd;
	fd = ltiny_listen_tcp(tcp_port);

	if (fd < 0)
		return NULL;

	if (accept_cb)
		return ltiny_ev_new(ctx, fd, accept_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, data);
	else
		return ltiny_ev_new(ctx, fd, ltiny_ev_accept_rpc_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, data);	
}

struct ltiny_ev *ltiny_ev_new_unix(struct ltiny_ev_ctx *ctx, const char *path, ltiny_ev_cb accept_cb, void *data)
{
	int fd;
	fd = ltiny_listen_unix(path);

	if (fd < 0)
		return NULL;

	if (accept_cb)
		return ltiny_ev_new(ctx, fd, accept_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, data);
	else
		return ltiny_ev_new(ctx, fd, ltiny_ev_accept_rpc_cb, EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP, data);	
}
