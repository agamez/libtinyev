#ifndef __libtinybuf_h__
#define __libtinybuf_h__

#include "libtinyev.h"

struct ltiny_buf;

struct ltinyev_buf {
	struct ltiny_buf *rbuf;
	struct ltiny_buf *wbuf;
};

struct ltiny_buf *ltiny_new_buf();
void ltiny_free_buf(struct ltiny_buf *b);

ssize_t ltiny_read_buf(struct ltiny_buf *b, struct ltiny_event *ev, void *buf, size_t count);

ssize_t ltiny_append_buf(struct ltiny_buf *b, const void *buf, size_t count);
ssize_t ltiny_write_buf(struct ltiny_buf *b, struct ltiny_event *ev);

#endif /* __libtinybuf_h__ */
