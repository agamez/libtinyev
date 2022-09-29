#ifndef __libtinyev_h__
#define __libtinyev_h__

#include <sys/epoll.h>

struct ltiny_ev_ctx;
struct ltiny_event;

/**
 * @file libtinyev.h
 * @brief libtinyev main -and only- include file needed to use the library
 *
 * To use libtinyev, simply #include <libtinyev.h> and use the provided functions
 * A brief example follows:
 * @code
 * void my_callback(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events)
 * {
 * 	if (triggered_events & EPOLLIN)
 * 		printf("Data ready for reading!");
 * 	else if (triggered_events & EPOLLOUT)
 * 		printf("File %s ready for writing!", ltiny_ev_get_user_data(ev));
 * }
 * 
 * void tiny_ev_user()
 * {
 * 	struct ltiny_ev_ctx *ev_ctx = ltiny_ev_new_ctx(NULL);
 * 	char *file_name = "/tmp/test";
 * 	int fd = open(file_name, "rw");
 * 	struct ltiny_event *new_ev = ltiny_ev_new_event(ev_ctx, fd, my_callback, file_name);
 * 	ltiny_ev_register_event(ev_ctx, new_ev, EPOLLIN | EPOLLOUT);
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
struct ltiny_event;

/**
 * @brief Event callback. The user will write one or more functions with this prototype and pass them to the library when registering an event.
 * @param[in] ctx ltiny_ev context
 * @param[in] ev ltiny_ev event that triggered the callback
 * @param[in] triggered_events Epoll events that triggered this callback
 *
 * Whenever the event happens, this user provided function will be called
 */
typedef void (*ltiny_ev_cb)(struct ltiny_ev_ctx *ctx, struct ltiny_event *ev, uint32_t triggered_events);

/**
 * @brief Get back user provided data in the call to ltiny_ev_new_ctx
 */
void *ltiny_ev_get_ctx_user_data(struct ltiny_ev_ctx *ctx);

/**
 * @brief Gathers this event's fd
 */
int ltiny_ev_get_fd(struct ltiny_event *ev);

/**
 * @brief Get back user provided data in the call to ltiny_ev_set_user_data
 */
void *ltiny_ev_get_user_data(struct ltiny_event *ev);

/**
 * @brief Set user provided data in the call to be passed to the event callback
 */
void ltiny_ev_set_user_data(struct ltiny_event *ev, void *user_data);

/**
 * @brief Generates a new ltinyev context
 * @param[in] user_data A pointer to any data provided by the user which could recover later on inside the callback functions
 * @return A new context allocated by the library. Must be released by calling ltiny_ev_free_ctx()
 */
struct ltiny_ev_ctx *ltiny_ev_new_ctx(void *user_data);

/**
 * @brief Creates a new object that can be registered for different epoll events
 * @param[in] ctx Pointer to a ltinyev context structure
 * @param[in] fd File descriptor on which listen for events
 * @param[in] cb Callback function to call whenever an event triggers it
 * @param[in] data Pointer to any user provided data for access inside callback function
 * @return A new ltiny_event object that can be registered or unregistered via ltiny_ev_register_event() and ltiny_ev_unregister_event()
 */
struct ltiny_event *ltiny_ev_new_event(struct ltiny_ev_ctx *ctx, int fd, ltiny_ev_cb cb, void *data);

/**
 * @brief Deletes an event and frees its memory
 * @param[in] c Event to delete
 */
void ltiny_ev_del_event(struct ltiny_event *c);

/**
 * @brief Registers an event for the selected context for given events
 * @param[in] ctx Pointer to a ltinyev context structure
 * @param[in] event Event previously generated with ltiny_ev_new_event()
 * @param[in] events Epoll events to listen to
 * @return 0 on success, a negative number on error
 */
int ltiny_ev_register_event(struct ltiny_ev_ctx *ctx, struct ltiny_event *event, uint32_t events);

/**
 * @brief Unregisters an event from the selected context
 * @param[in] ctx Pointer to a ltinyev context structure
 * @param[in] event Event previously generated with ltiny_ev_new_event() and registered with ltiny_ev_register_event()
 * @return 0 on sucess, a negativer number on error
 */
int ltiny_ev_unregister_event(struct ltiny_ev_ctx *ctx, struct ltiny_event *event);

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
void ltiny_ev_free_ctx(struct ltiny_ev_ctx *ctx);

#endif /* __libtinyev_h__ */
