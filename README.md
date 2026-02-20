# libtinyev

A lightweight, layered event-driven library for Linux that provides a complete stack for building asynchronous network applications. The library wraps Linux `epoll` and `timerfd` APIs to deliver an efficient reactor-pattern event loop, buffered non-blocking I/O, and a complete RPC protocol implementation.

## Features

- **Event Loop**: Reactor-pattern wrapper around `epoll` with support for timeouts via `timerfd`.
- **Buffered I/O**: Automatic buffering using `open_memstream()` for zero-copy-friendly dynamic memory management.
- **RPC Protocol**: Line-based request/response protocol with binary payload support.
- **Modular Build**: Optional components (buffer, RPC, helpers) enabled via CMake options.
- **Threaded Callbacks**: Optional detached pthread execution for CPU-intensive callbacks.
- **Clean Resource Management**: User-data cleanup callbacks prevent leaks.

## Build

```bash
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make -j$(nproc)
sudo make install
```

CMake options:
- `BUF=ON` (default): Build buffered I/O module.
- `RPC=ON` (default): Build RPC module (forces BUF).
- `HELPERS=ON` (default): Build network helpers (forces BUF and RPC).
- `BUILD_DOC=ON` (default): Generate API docs with Doxygen if available.

## Quick Start

Include `<libtinyev.h>` and link against `libtinyev`. Minimal example from the header:

```c
#include <libtinyev.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

void my_callback(struct ltiny_ev_ctx *ctx, struct ltiny_ev *ev, uint32_t events)
{
    if (events & EPOLLIN)
        printf("Data ready for reading!\n");
    else if (events & EPOLLOUT)
        printf("Ready for writing!\n");
}

int main(void)
{
    int fd = open("/tmp/test", O_RDWR | O_NONBLOCK);
    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    struct ltiny_ev *e = ltiny_ev_new(ctx, fd, my_callback, EPOLLIN | EPOLLOUT, NULL);
    ltiny_ev_loop(ctx);
    ltiny_ev_ctx_del(ctx);
    close(fd);
    return 0;
}
```

## RPC Example

### Server (`server.c`)

```c
#include "libtinyev.h"
#include "libtinybuf.h"
#include "libtinyrpc.h"
#include "libtinyhelpers.h"

ssize_t echo_handler(struct ltiny_ev_ctx *ctx, struct ltiny_ev_buf *ev_buf,
                     void *request, size_t request_size, void **response)
{
    *response = request;  // Echo back the request
    return request_size;
}

int main(void)
{
    struct ltiny_ev_ctx *ctx = ltiny_ev_ctx_new(NULL);
    struct ltiny_ev_rpc_server *server = ltiny_ev_new_rpc_server();

    ltiny_ev_rpc_server_register_req(server, "echo", echo_handler, NULL);
    ltiny_ev_new_tcp(ctx, 2323, NULL, server);  // Uses default accept callback

    ltiny_ev_loop(ctx);

    ltiny_ev_ctx_del(ctx);
    ltiny_ev_rpc_server_free(server);
    return 0;
}
```

### Client (`client.c`)

```c
#include "libtinyev.h"
#include "libtinybuf.h"
#include "libtinyrpc.h"
#include "libtinyhelpers.h"

int main(void)
{
    int fd = ltiny_connect_tcp("127.0.0.1", 2323);
    void *response = NULL;
    size_t response_size = 0;

    ltiny_ev_rpc_sync_msg(fd, "echo", "Hello", 5,
                          &response, &response_size, 2000);

    if (response_size > 0)
        printf("Server replied: %s\n", (char *)response);

    free(response);
    close(fd);
    return 0;
}
```

### Build and Run

```bash
# Compile
gcc -o server server.c $(pkg-config --cflags --libs libtinyev)
gcc -o client client.c $(pkg-config --cflags --libs libtinyev)

# Run (in separate terminals)
./server
./client
```

### How It Works

- Server creates an event context and RPC server, registers an `echo` handler, listens on TCP port 2323, and runs the event loop.
- Client connects synchronously, sends an RPC request for method `echo` with payload `"Hello"`, and prints the echoed response.
- `ltiny_ev_new_tcp` with `NULL` accept callback uses the library’s default RPC accept handler.
- `ltiny_ev_rpc_sync_msg` blocks until a response is received or timeout occurs.

## Notes

- The server uses the helper `ltiny_ev_new_tcp` to simplify listening socket setup and automatic RPC attachment.
- The client uses the synchronous helper `ltiny_ev_rpc_sync_msg` for simplicity; for non-blocking use, see the asynchronous client example in the Quick Start wiki.
- The response buffer in `ltiny_ev_rpc_sync_msg` is allocated by the function and must be freed by the caller.

Wiki pages you might want to explore:
- [Quick Start (agamez/libtinyev)](/wiki/agamez/libtinyev#3.1)
- [Writing RPC Servers (agamez/libtinyev)](/wiki/agamez/libtinyev#3.3)

## Architecture

The library is organized in layers:

- **libtinyev**: Core event loop (`ltiny_ev_ctx`, `ltiny_ev`).
- **libtinybuf**: Buffered I/O (`ltiny_ev_buf`, `ltiny_buf`).
- **libtinyrpc**: RPC protocol (`ltiny_ev_rpc_server`, `ltiny_ev_rpc_receiver`).
- **libtinyhelpers**: Network utilities (TCP/UNIX socket helpers).

Each layer depends only on layers below it, enabling modular builds.

## API Highlights

- Event loop: `ltiny_ev_ctx_new()`, `ltiny_ev_new()`, `ltiny_ev_loop()`, `ltiny_ev_exit_loop()`.
- Buffered I/O: `ltiny_ev_buf_new()`, `ltiny_ev_buf_send()`, `ltiny_ev_buf_consume()`.
- RPC: `ltiny_ev_new_rpc_server()`, `ltiny_ev_rpc_server_register_req()`, `ltiny_ev_rpc_send_msg()`, `ltiny_ev_rpc_sync_msg()`.
- Timeouts: `ltiny_ev_set_timeout()` with per-read/write timerfd support.

## Documentation

- Run `make doc` (if Doxygen is available) to generate API documentation.
- See the project wiki for detailed guides and examples.

## License

LGPL v2.1.

## Notes
- This README is generated based on the project's Overview wiki and build files. For the most current details, refer to the source headers and CMakeLists.txt. [1](#0-0) [2](#0-1) [3](#0-2) 

Wiki pages you might want to explore:
- [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/agamez/libtinyev)
