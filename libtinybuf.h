#ifndef __libtinybuf_h__
#define __libtinybuf_h__

#include <inttypes.h>
#include "libtinyev.h"

struct ltiny_ev_buf;

/**
 * @brief Event callback. The user will write one or more functions with this prototype and pass them to the library when registering a buffer event.
 * @param[in] ctx ltiny_ev context
 * @param[in] ev ltiny_ev event that triggered the callback
 * @param[in] data Data received via file descriptor
 * @param[in] count Size of the data received
 *
 * Whenever the event happens, this user provided function will be called
 */
typedef void (*ltiny_ev_buf_read_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, void *data, size_t count);

/**
 * @brief Event callback. The user will write one or more functions with this prototype and pass them to the library when registering a buffer event.
 * @param[in] ctx ltiny_ev context
 * @param[in] ev ltiny_ev event that triggered the callback
 *
 * This user provided function will be called whenever, after a succesful write to the underlying file descriptor, the internal buffer is empty.
 * In other words, this function is called when all data the user requested to write has been written and there's no more thata pending.
 */
typedef void (*ltiny_ev_buf_write_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf);

/**
 * @brief Event callback. The user will write one or more functions with this prototype and pass them to the library when registering a buffer event.
 * @param[in] ctx ltiny_ev context
 * @param[in] ev ltiny_ev event that triggered the callback
 *
 * This user provided function will be called whenever a close operation has happened over the underlying file descriptor.
 */
typedef void (*ltiny_ev_buf_close_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf);

/**
 * @brief Event callback. The user will write one or more functions with this prototype and pass them to the library when registering a buffer event.
 * @param[in] ctx ltiny_ev context
 * @param[in] ev ltiny_ev event that triggered the callback
 *
 * This user provided function will be called whenever a close operation has happened over the underlying file descriptor.
 */
typedef void (*ltiny_ev_buf_error_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf);

/**
 * @brief Creates and registers a buffer event for the given file descriptor
 * @param[in] ctx ltiny_ev context
 * @param[in] fd file descriptor to attach buffer to
 * @param[in] read_cb Callback function that will be called whenever there is data available in the buffer to be read
 * @param[in] write_cb Callback function that will be called whenever all data has been written to the fd and the write buffer is empty
 * @param[in] close_cb Callback function that will be called when the buffer event is closed
 * @param[in] user_data Pointer to any piece of data that the user will be able to recover in the callback functions by using function ltiny_ev_buf_get_user_data()
 *
 */
struct ltiny_ev_buf *ltiny_ev_buf_new(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_buf_read_cb read_cb, ltiny_ev_buf_write_cb write_cb, ltiny_ev_buf_close_cb close_cb, ltiny_ev_buf_error_cb error_cb, void *user_data);

/**
 * @brief Closes and unregisters a buffer event
 * @param[in] ctx ltiny_ev context
 * @param[in] b Buffer event to close. close_cb callback function will be automatically called after this
 */
void ltiny_ev_buf_close(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *b);

/**
 * @brief Get back the underlying event's fd
 */
int ltiny_ev_buf_get_fd(struct ltiny_ev_buf *ev_buf);

/**
 * @brief Returns previously provided pointer to user data as given in function ltiny_ev_buf_new
 * @param[in] ctx ltiny_ev context
 * @param[in] b Buffer event to get user data pointer from
 */
void *ltiny_ev_buf_get_user_data(struct ltiny_ev_buf *ev_buf);

/**
 * @brief Provides buffer event with a pointer to a function that will be
 * automatically called on buffer event close so the user can write a
 * destructor for user provided data pointer that will be automatically
 * called on close events
 * @param[in] ctx ltiny_ev context
 * @param[in] free_user_data Callback function intended to be a destructor for user_data pointer as given in function ltiny_ev_buf_new
 */
void ltiny_ev_buf_set_free_data(struct ltiny_ev_buf *ev_buf, ltiny_ev_free_data_cb free_user_data);

/**
 * @brief Reads and returns data from a buffer event, marking it as read
 * @param[in] ctx ltiny_ev context
 * @param[in] ev_buf Buffer event to get user data pointer from
 * @param[in, out] count Maximum number of bytes to be read. Updates to number of bytes really read
 */
void *ltiny_ev_buf_consume(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, size_t *count);

/**
 * @brief Reads and returns data from a buffer event, marking it as read, until a new line character is returned
 * @param[in] ctx ltiny_ev context
 * @param[in] ev_buf Buffer event to get user data pointer from
 * @param[out] len Length of the returned line
 */
void *ltiny_ev_buf_consume_line(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, size_t *len);

/**
 * @brief Writes data to a buffer event, marking it as read
 * @param[in] ctx ltiny_ev context
 * @param[in] ev_buf Buffer event to get user data pointer from
 * @param[in] buf Data that will be written down to the underlying file descriptor
 * @param[in] count Maximum number of bytes to write.
 */
int ltiny_ev_buf_send(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, const void *buf, size_t count);

/**
 * @brief Writes formatted data to a buffer event
 * @param[in] ctx ltiny_ev context
 * @param[in] ev_buf Buffer event to get user data pointer from
 * @param[in] format A printf like format string
 * @param[in] ... Arguments to be placed in the resulting formatted string
 */
int ltiny_ev_buf_printf(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, const char *format, ...);

/**
 * @brief Sets event timeout
 * @param[in] ctx Pointer to a ltinyev context structure
 * @param[in] e Event to which assign timeout
 * @param[in] read_timeout_cb Callback function to call when read timeout happens
 * @param[in] read_timeout_ms Read timeout in milliseconds
 * @param[in] write_timeout_cb Callback function to call when write timeout happens
 * @param[in] write_timeout_ms Write timeout in milliseconds
 */
void ltiny_ev_buf_set_timeout(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf, ltiny_ev_cb read_timeout_cb, ltiny_ev_cb write_timeout_cb, int read_timeout_ms, int write_timeout_ms);

#endif /* __libtinybuf_h__ */
