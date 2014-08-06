/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#ifndef CCI_ROUTER_H
#define CCI_ROUTER_H

#include "cci.h"
#include "cci_router_wire.h"
#include "cci_router_topo.h"
#include "cci_router_e2e.h"
#include "cci_router_debug.h"

#include "bsd/queue.h"

BEGIN_C_DECLS

#define CCIR_URI_MAX_LEN	(255)	/* To fit in a uint8_t */
#define CCIR_MAX_PEERS		(128)	/* Maximum peer routers per subnet */
#define CCIR_CONNECT_TIMEOUT	(360)	/* Seconds */
#define CCIR_BLOCKING_TIMEOUT	(1)	/* Seconds */

/* We are going to pack extra bits at the bottom of the context pointer. Most
 * allocators guarantee 8-byte alignment on 32-bit systems and 16-byte
 * alignment on 64-bit systems. We should be safe using the lower 3 bits and
 * possible the lower 4 bits if needed.
 *
 * The set bit indicates what the context is.
 */
#define CCIR_CTX_PEER		((uintptr_t)1 << 0)
#define CCIR_CTX_RCONN		((uintptr_t)1 << 1)
#define CCIR_CTX_RMA		((uintptr_t)1 << 2)
#define CCIR_CTX_MASK		(((uintptr_t)1 << 3) - 1)

#define CCIR_SET_CTX(ctx,type)	\
	((void *)((uintptr_t)(ctx) | (type)))

#define CCIR_GET_CTX_TYPE(ctx,type)	\
	*((int**)type) = (ctx) & CCIR_CTX_MASK

#define CCIR_CTX_TYPE(ctx)	\
	((int)(((uintptr_t)(ctx) & CCIR_CTX_MASK)))

#define CCIR_IS_PEER_CTX(ctx)	\
	(((uintptr_t)(ctx) & CCIR_CTX_PEER))

#define CCIR_IS_RMA_CTX(ctx)	\
	(((uintptr_t)(ctx) & CCIR_CTX_RMA))

#define CCIR_CTX(ctx)	\
	((void*)((uintptr_t)(ctx) & ~(CCIR_CTX_MASK)))

typedef enum ccir_peer_state {
	CCIR_PEER_CLOSED = -2,	/* Connection invalid */
	CCIR_PEER_CLOSING = -1,	/* Sent bye, waiting on ack */
	CCIR_PEER_INIT = 0,	/* Initial state */
	CCIR_PEER_CONNECTING,	/* Active or passive connect in progress */
	CCIR_PEER_CONNECTED	/* Ready to exchange route info */
} ccir_peer_state_t;

static inline const char *
ccir_peer_state_str(ccir_peer_state_t state)
{
	switch (state) {
	case CCIR_PEER_CLOSED:
		return "CCIR_PEER_CLOSED";
	case CCIR_PEER_CLOSING:
		return "CCIR_PEER_CLOSING";
	case CCIR_PEER_INIT:
		return "CCIR_PEER_INIT";
	case CCIR_PEER_CONNECTING:
		return "CCIR_PEER_CONNECTING";
	case CCIR_PEER_CONNECTED:
		return "CCIR_PEER_CONNECTED";
	}
	/* never reaches here */
	return NULL;
}

typedef struct ccir_globals ccir_globals_t;	/* Global state */

typedef struct ccir_peer {
	cci_connection_t *c;	/* CCI connection */
	char *uri;		/* Peer's CCI URI */
	ccir_router_t *router;	/* Peer's router struct */
	cci_rma_handle_t *h;	/* Peer's RMA handle */
	time_t next_attempt;	/* Absolute seconds for next connect attempt */
	ccir_peer_state_t state; /* Peer's state */
	uint32_t as;		/* Peer's Autonomous System id */
	uint32_t subnet;	/* Peer's subnet id */
	uint32_t id;		/* peer's router id to avoid looping */
	uint32_t rma_mtu;	/* Peer's RMA transfer len */
	uint32_t rma_cnt;	/* Peer's number of RMA buffers */
	uint16_t attempts;	/* Number of connection attempts */
	uint8_t connecting;	/* Waiting on connect event */
	uint8_t accepting;	/* Waiting on accept/reject event */
} ccir_peer_t;

typedef struct ccir_ep {
	cci_endpoint_t *e;	/* CCI endpoint for a device */
	ccir_peer_t **peers;	/* Array of peer routers on subnet - NULL terminated */
	TAILQ_HEAD(rcs, ccir_rconn) rconns; /* List of routed connections */
	const char *uri;	/* The CCI endpoint URI */
	cci_os_handle_t fd;	/* OS handle for blocking for events */
	uint32_t peer_cnt;	/* Number of peer routers */
	uint32_t as;		/* Our autonomous system ID */
	uint32_t subnet;	/* Our subnet ID */
	uint32_t need_connect;	/* Do we need to attempt a peer connect? */
	uint32_t failed;	/* Set to 1 if CCI_EVENT_ENDPOINT_DEVICE_FAILED */
	cci_rma_handle_t *h;	/* RMA handle for globals->rma_buf */
} ccir_ep_t;

struct ccir_globals {
	ccir_topo_t *topo;	/* topology information */
	ccir_ep_t **eps;	/* Array of endpoints - NULL terminated */
	uint32_t ep_cnt;	/* Number of endpoints */
	uint32_t blocking;	/* Should we block (1) or poll (0)? */
	uint32_t nfds;		/* The highest OS handle + 1 for select */
	uint32_t id;		/* our id from hashed ep->uris */
	uint64_t instance;	/* our instance (seconds since epoch) */
	ccir_rma_buffer_t *rma_buf; /* RMA buffer */
	uint32_t shutdown;
};

#define container_of(p,stype,field) ((stype *)(((uint8_t *)(p)) - offsetof(stype, field)))

uint32_t verbose;	/* Level of verbose output */
uint32_t debug;		/* Level of debugging output */

END_C_DECLS
#endif /* CCI_ROUTER_H */
