#ifndef __libtinyhelpers_h__
#define __libtinyhelpers_h__

#include "libtinyev.h"

int ltiny_connect_unix(const char *const path);
int ltiny_connect_udp(int port);
int ltiny_connect_tcp(const char *host, int port);
int ltiny_listen_unix(const char *path);
int ltiny_listen_tcp(int port);
void ltiny_ev_close_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf);
void ltiny_ev_accept_rpc_cb(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events);
struct ltiny_ev *ltiny_ev_new_tcp(struct ltiny_ev_ctx *ctx, int tcp_port, ltiny_ev_cb accept_cb, void *data);
struct ltiny_ev *ltiny_ev_new_unix(struct ltiny_ev_ctx *ctx, const char *path, ltiny_ev_cb accept_cb, void *data);


#endif /* __libtinyhelpers_h__ */
