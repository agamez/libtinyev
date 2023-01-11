#ifndef __libtinybuf_h__
#define __libtinybuf_h__

#include <inttypes.h>
#include "libtinyev.h"

struct ltiny_event_buf;

/**
 * @brief Event callback. The user will write one or more functions with this prototype and pass them to the library when registering an event.
 * @param[in] ctx ltiny_ev context
 * @param[in] ev ltiny_ev event that triggered the callback
 * @param[in] data Data received via file descriptor
 * @param[in] data_length Size of the data received
 *
 * Whenever the event happens, this user provided function will be called
 */
typedef void (*ltiny_event_buf_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *ev_buf, void *data, size_t count);
typedef void (*ltiny_event_buf_close_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *ev_buf, void *data);

struct ltiny_event_buf *ltiny_ev_new_buf_event(struct ltiny_ev_ctx *ctx, int fd, ltiny_event_buf_cb callback, ltiny_event_buf_close_cb close_cb, void *user_data);
void ltiny_buf_close(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *b);

void *ltiny_evbuf_get_user_data(struct ltiny_event_buf *ev_buf);

void *ltiny_event_buf_consume(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *ev_buf, size_t count);
void *ltiny_event_buf_consume_line(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *ev_buf);

int ltiny_event_buf_send(struct ltiny_ev_ctx *ctx, struct ltiny_event_buf *ev_buf, void *buf, size_t count);

#endif /* __libtinybuf_h__ */
