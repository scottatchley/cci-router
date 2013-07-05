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

#include "bsd/queue.h"

BEGIN_C_DECLS

#define CCIR_URI_MAX_LEN	(255)	/* To fit in a uint8_t */
#define CCIR_MAX_PEERS		(128)	/* Maximum peer routers per subnet */
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

typedef struct ccir_peer {
	cci_connection_t *c;	/* CCI connection */
	char *uri;		/* Peer's CCI URI */
	time_t next_attempt;	/* Absolute seconds for next connect attempt */
	ccir_peer_state_t state; /* Peer's state */
	uint8_t connecting;	/* Waiting on connect event */
	uint8_t accepting;	/* Waiting on accept/reject event */
	uint16_t attempts;	/* Number of connection attempts */
	uint32_t as;		/* Peer's Autonomous System id */
	uint32_t subnet;	/* Peer's subnet id */
	uint32_t id;		/* peer's router id to avoid looping */
} ccir_peer_t;

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
	TAILQ_ENTRY(ccir_ep) entry; /* For ep->rconns */
	cci_connection_t *src;	/* Source (passive) connection */
	cci_connection_t *dst;	/* Destination (active) connection */
	ccir_rconn_state_t state; /* State */
} ccir_rconn_t;

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
} ccir_ep_t;

typedef struct ccir_router {
	uint32_t id;		/* Router's ID */
	uint64_t instance;	/* Router's instance (seconds since epoch) */
	uint32_t count;		/* Number of subnets served */
} ccir_router_t;

typedef struct ccir_subnet {
	void *routers;		/* Tree of router IDs for this subnet */
	uint32_t id;		/* Subnet id */
	uint32_t count;		/* Number of routers on subnet */
	uint16_t rate;		/* Gb/s */
} ccir_subnet_t;

typedef struct ccir_topo {
	pthread_rwlock_t lock;	/* Read/write lock */
	void *subnets;		/* tree of subnets sorted on subnet ID */
	void *routes;		/* tree of routes originating locally */
} ccir_topo_t;

typedef struct ccir_globals {
	ccir_topo_t *topo;	/* topology information */
	ccir_ep_t **eps;	/* Array of endpoints - NULL terminated */
	uint32_t ep_cnt;	/* Number of endpoints */
	uint32_t blocking;	/* Should we block (1) or poll (0)? */
	uint32_t nfds;		/* The highest OS handle + 1 for select */
	uint32_t id;		/* our id from hashed ep->uris */
	uint64_t instance;	/* our instance (seconds since epoch) */
	uint32_t verbose;	/* Level of verbose output */
	uint32_t debug;		/* Level of debugging output */
	uint32_t shutdown;
} ccir_globals_t;

#define container_of(p,stype,field) ((stype *)(((uint8_t *)(p)) - offsetof(stype, field)))

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
