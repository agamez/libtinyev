#ifndef __libtinyev_h__
#define __libtinyev_h__

#include <sys/epoll.h>

/**
 * @file libtinyev.h
 * @brief libtinyev main -and only- include file needed to use the library
 *
 * To use libtinyev, simply #include <libtinyev.h> and use the provided functions
 * A brief example follows:
 * @code
 * void my_callback(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events)
 * {
 * 	int *global_data = ltiny_ev_get_ctx_user_data(ctx);
 * 	char *local_data = ltiny_ev_get_user_data(ev);
 * 	if (triggered_events & EPOLLIN)
 * 		printf("Data ready for reading!");
 * 	else if (triggered_events & EPOLLOUT)
 * 		printf("File file_name = '%s' ready for writing!", local_data);
 * }
 * 
 * void tiny_ev_user()
 * {
 *	int global_data = 23;
 * 	struct ltiny_ev_ctx *ev_ctx = ltiny_ev_ctx_new(&global_data);
 * 	char *file_name = "/tmp/test";
 * 	int fd = open(file_name, "rw");
 * 	struct ltiny_ev *new_ev = ltiny_ev_new(ev_ctx, fd, my_callback, EPOLLIN | EPOLLOUT, file_name);
 * 	ltiny_ev_loop(ev_ctx);
 * 	ltiny_ev_free_ctx(ev_ctx);
 * }
 * @endcode
 * 
 */

/**
 * @brief Context struct. Will not be used directly, instead a pointer to the context is always used
 *
 * The structure member's are hidden to the library's user
 */
struct ltiny_ev_ctx;

/**
 * @brief Event struct. Will not be used directly, instead a pointer to the event is always used
 *
 * The structure member's are hidden to the library's user
 */
struct ltiny_ev;

/**
 * @brief Event callback. The user will write one or more functions with this prototype and pass them to the library when registering an event.
 * @param[in] ctx ltiny_ev context
 * @param[in] ev ltiny_ev event that triggered the callback
 * @param[in] triggered_events Epoll events that triggered this callback
 *
 * Whenever the event happens, this user provided function will be called
 */
typedef void (*ltiny_ev_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t triggered_events);

/**
 * @brief Get back user provided data in the call to ltiny_ev_new_ctx
 */
void *ltiny_ev_get_ctx_user_data(struct ltiny_ev_ctx *ctx);

/**
 * @brief Get back the underlying event's fd
 */
int ltiny_ev_get_fd(struct ltiny_ev *ev);

/**
 * @brief Get back user provided data in the call to ltiny_ev_new
 */
void *ltiny_ev_get_user_data(struct ltiny_ev *ev);


typedef void (*ltiny_ev_free_data_cb)(struct ltiny_ev_ctx *ctx, void *user_data);
/**
 * @brief Set function to call on ltiny_ev_del_event to free user data
 */
void ltiny_ev_set_free_data(struct ltiny_ev *ev, ltiny_ev_free_data_cb free_user_data);


/**
 * @brief Set additional flags to provided event
 * 
 */
void ltiny_ev_set_flags(struct ltiny_ev *ev, uint32_t flags);
#define LTINY_EV_RUN_ON_THREAD 0x01

/**
 * @brief Generates a new ltinyev context
 * @param[in] user_data A pointer to any data provided by the user which could recover later on inside the callback functions
 * @return A new context allocated by the library. Must be released by calling ltiny_ev_free_ctx()
 */
struct ltiny_ev_ctx *ltiny_ev_ctx_new(void *user_data);

/**
 * @brief Modifies list of events to listen to for a given object
 * @param[in] ctx Pointer to a ltinyev context structure
 * @param[in] fd File descriptor on which listen for events
 * @param[in] events Or'ed list of EPOLL events to listen to
 * @return 0 on success, -1 otherwise
 */
int ltiny_ev_mod_events(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t events);

/**
 * @brief Creates a new object that can be registered for different epoll events
 * @param[in] ctx Pointer to a ltinyev context structure
 * @param[in] fd File descriptor on which listen for events
 * @param[in] cb Callback function to call whenever an event triggers it
 * @param[in] events Or'ed list of EPOLL events to listen to
 * @param[in] data Pointer to any user provided data for access inside callback function
 * @return A new ltiny_ev object 
 */
struct ltiny_ev *ltiny_ev_new(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_cb cb, uint32_t events, void *data);

/**
 * @brief Deletes an event and frees its memory
 * @param[in] ctx Pointer to a ltinyev context structure
 * @param[in] e Event to delete
 */
void ltiny_ev_del(struct ltiny_ev_ctx *ctx, struct ltiny_ev *e);


/**
 * @brief Initiates event loop
 * This function only finishes when there's an error in the underlaying epoll call or when ltiny_ev_exit_loop() is called inside a callback function
 * @param[in] ctx Pointer to a ltinyev context structure
 * @return 0 on sucess, a negativer number on error
 */
int ltiny_ev_loop(struct ltiny_ev_ctx *ctx);

/**
 * @brief Marks this loop to end after finishing with the current callback
 * @param[in] ctx Pointer to a ltinyev context structure
 */
void ltiny_ev_exit_loop(struct ltiny_ev_ctx *ctx);
 
/**
 * @brief Releases memory associated to a ltinyev context
 * Calling this function will also unregister events and delete them
 * @param[in] ctx Context to be freed. Can be called over a NULL pointer
 */
void ltiny_ev_ctx_del(struct ltiny_ev_ctx *ctx);

#endif /* __libtinyev_h__ */
