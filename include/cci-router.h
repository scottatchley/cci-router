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

BEGIN_C_DECLS

#define CCIR_MAX_PEERS	(128)	/* Maximum peer routers per subnet */
#define CCIR_CONNECT_TIMEOUT	(360)	/* Seconds */
#define CCIR_BLOCKING_TIMEOUT	(1)	/* Seconds */

#define CCIR_SET_PEER_CTX(ctx)	\
	((void *)((uintptr_t)(ctx) | (uintptr_t)0x1))

#define CCIR_IS_PEER_CTX(ctx)	\
	(((uintptr_t)(ctx) & (uintptr_t)0x1))

#define CCIR_CTX(ctx)	\
	((void*)((uintptr_t)(ctx) & ~((uintptr_t)0x1)))

typedef enum ccir_peer_state {
	CCIR_PEER_CLOSED = -2,	/* Connection invalid */
	CCIR_PEER_CLOSING = -1,	/* Sent bye, waiting on ack */
	CCIR_PEER_INIT = 0,	/* Initial state */
	CCIR_PEER_ACTIVE,	/* Send connect request */
	CCIR_PEER_PASSIVE,	/* Received connect request */
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
	case CCIR_PEER_ACTIVE:
		return "CCIR_PEER_ACTIVE";
	case CCIR_PEER_PASSIVE:
		return "CCIR_PEER_PASSIVE";
	case CCIR_PEER_CONNECTED:
		return "CCIR_PEER_CONNECTED";
	}
	/* never reaches here */
	return NULL;
}

typedef struct ccir_peer {
	cci_connection_t *c;	/* Active CCI connection */
	cci_connection_t *p;	/* Passive CCI connection */
	char *uri;		/* Peer's CCI URI */
	time_t next_attempt;	/* Absolute seconds for next connect attempt */
	ccir_peer_state_t state; /* Peer's state */
	uint32_t attempts;	/* Number of connection attempts */
} ccir_peer_t;

typedef struct ccir_ep {
	cci_endpoint_t *e;	/* CCI endpoint for a device */
	ccir_peer_t **peers;	/* Array of peer routers on subnet - NULL terminated */
	const char *uri;	/* The CCI endpoint URI */
	cci_os_handle_t fd;	/* OS handle for blocking for events */
	uint32_t peer_cnt;	/* Number of peer routers */
	uint32_t as;		/* Our autonomous system ID */
	uint32_t subnet;	/* Our subnet ID */
	uint32_t need_connect;	/* Do we need to attempt a peer connect? */
	uint32_t failed;	/* Set to 1 if CCI_EVENT_ENDPOINT_DEVICE_FAILED */
} ccir_ep_t;

typedef struct ccir_globals {
	ccir_ep_t **eps;	/* Array of endpoints - NULL terminated */
	uint32_t ep_cnt;	/* Number of endpoints */
	uint32_t blocking;	/* Should we block (1) or poll (0)? */
	uint32_t nfds;		/* The highest OS handle + 1 for select */
	uint32_t verbose;	/* Level of verbose output */
	uint32_t debug;		/* Level of debugging output */
	uint32_t shutdown;
} ccir_globals_t;

typedef enum ccir_rconn_state {
	CCIR_RCONN_CLOSED = -2,	/* Closed ready for cleanup */
	CCIR_RCONN_CLOSING = -1, /* Closing */
	CCIR_RCONN_INIT = 0,	/* Initial state */
	CCIR_RCONN_ACTIVE,	/* Sent dst connect request, waiting on completion */
	CCIR_RCONN_PASSIVE,	/* Received src conn request, waiting on completion */
	CCIR_RCONN_PENDING,	/* Wainting on E2E ACCEPT or REJECT */
	CCIR_RCONN_CONNECTED	/* Forwarding enabled */
} ccir_rconn_state_t;

/* Routed connection */
typedef struct ccir_rconn {
	cci_connection_t *src;
	cci_connection_t *dst;
	ccir_rconn_state_t state;
} ccir_rconn_t;

#define CCIR_DEBUG	(1)	/* Turn on for development */

#define RDB_EP		(1 << 0)	/* endpoint */
#define RDB_PEER	(1 << 1)	/* peer/connections */
#define RDB_INFO	(1 << 2)	/* non-specific, low value */
#define RDB_CONFIG	(1 << 3)	/* configuration info */

#define RDB_ALL		(~0)		/* print all */

#if CCIR_DEBUG
#define debug(lvl,fmt,args...)					\
do {								\
	if ((lvl) & globals->debug)				\
		fprintf(stderr, "router: " fmt "\n", ##args);	\
} while(0)
#else	/* !CCIR_DEBUG */
#define debug(lvl,fmt,args...) do { } while(0)
#endif	/* CCIR_DEBUG */

END_C_DECLS
#endif /* CCI_ROUTER_H */
