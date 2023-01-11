#ifndef __libtinyrpc_h__
#define __libtinyrpc_h__

#include <inttypes.h>
#include "libtinyev.h"

#define LTINY_EV_RPC_MARKER "TNY_RPC"

#ifndef LTINY_EV_RPC_MAX_PAYLOAD_LENGTH
#define LTINY_EV_RPC_MAX_PAYLOAD_LENGTH 8192
#endif

struct ltiny_ev_rpc_header {
	char rpc_marker[8];
	uint64_t payload_length;
};


struct ltiny_ev_rpc_msg {
	struct ltiny_ev_rpc_header;
	char data[0];
};

#endif /* __libtinyrpc_h__ */
