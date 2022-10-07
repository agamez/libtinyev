#include <sys/uio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "libtinyev.h"
#include "libtinybuf.h"

struct ltiny_buf {
	size_t requested_count;
	size_t count;
	FILE *fd;
	char *buf;
};


/**
 * @brief Returns a new allocated struct ltiny_buf to be used with ltiny_readbuf()
 * Must be free'd using ltiny_del_buf();
 */
struct ltiny_buf *ltiny_new_buf()
{
	return calloc(sizeof(struct ltiny_buf), 1);
}

/**
 * @brief Frees memory used by a struct ltiny_buf
 */
void ltiny_free_buf(struct ltiny_buf *b)
{
	if (!b)
		return;

	if (b->fd)
		fclose(b->fd);
	free(b->buf);
	free(b);
}

/**
 * @brief Concatenates/accumulates data in a buffer until it reaches the requested size count
 *
 * This function needs to be called on a loop, with exactly the same parameters,
 * until it returns 'count', meaning that it has read all the data that it was requested to do,
 * or a negative number is received, indicating it has ended all possible reading from the file
 * descriptor but hasn't read all requested data.
 *
 * On returning error or 'count', it will store read data on user provided buf
 *
 * If an error were to occur, all data is discarded and (void *)-1 is returned.
 *
 * @param[in] b Buffer structure used as context for this read
 * @param[in] fd File descriptor to read from
 * @param[in] buf Buffer in which to store read data
 * @param[in] count Number of bytes to read
 *
 * @return (void *)-1 on error, NULL when not enough bytes have been read, or a pointer to a char * with the whole requested 'count' read. Must be freed by the user.
 */
ssize_t ltiny_read_buf(struct ltiny_buf *b, struct ltiny_event *ev)
{
	ssize_t ret;

	if (!b->fd) {
		b->fd = open_memstream(&b->buf, &b->requested_count);
		if (!b->fd)
			return -1;
	}

	if (b->requested_count == 0)
		b->requested_count = count;

	ret = read(ltiny_ev_get_fd(ev), (char *)buf + b->count, b->requested_count - b->count);
	if (ret > 0)
		b->count += ret;
	else if (ret <= 0)
		return -b->count;

	if (b->count == b->requested_count)
		return b->count;

	return 0;
}

ssize_t ltiny_append_buf(struct ltiny_buf *b, const void *buf, size_t count)
{
	ssize_t ret;

	if (!b->fd) {
		b->fd = open_memstream(&b->buf, &b->requested_count);
		if (!b->fd)
			return -1;
	}

	/* Append new data to buffer */
	ret = fwrite(buf, count, 1, b->fd);
	b->requested_count += count;

	return ret * count;
}

ssize_t ltiny_write_buf(struct ltiny_buf *b, struct ltiny_event *ev)
{
	ssize_t ret;

	if (!b->fd)
		return -1;

	fflush(b->fd);

	ret = write(ltiny_ev_get_fd(ev), b->buf + b->count, b->requested_count - b->count);
	if (ret > 0)
		b->count += ret;
	else if (ret <= 0)
		return -b->count;

	if (b->count == b->requested_count)
		return b->count;

	return 0;
}

void ltinybuf_cb(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
{
	struct ltinyev_buf *evbuf = ltiny_ev_get_user_data(ev);

	if (triggered_events & EPOLLIN) {
		char buf[8192] = { 0 };
		int len = sizeof(buf) - 1;

		ssize_t ret;
		do
		{
			ret = ltiny_read_buf(evbuf->rbuf, ev, buf, len);
		} while (ret >= 0 && ret != len);

		if (ret < 0) {
			printf("ERROR ON SOCKET, READ ONLY %d data\n", -ret);
		} else {
			printf("SUCCESS, READ %d data\n", ret);
			printf("%s\n", buf);
		}
	}

	if (triggered_events & EPOLLOUT) {
		ssize_t ret;
		ret = ltiny_write_buf(evbuf->wbuf, ev);
	}

}
