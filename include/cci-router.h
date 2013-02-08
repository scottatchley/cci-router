/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci.h"

#define CCIR_MAX_PEERS	(128)	/* Maximum peer routers per subnet */
#define CCIR_CONNECT_TIMEOUT	(360)	/* Seconds */
#define CCIR_CONNECT_BACKOFF	(2)	/* Multiplier */
#define CCIR_BLOCKING_TIMEOUT	(1)	/* Seconds */

typedef enum ccir_peer_state {
	CCIR_PEER_CLOSED = -2,	/* Connection invalid */
	CCIR_PEER_CLOSING = -1,	/* Sent bye, waiting on ack */
	CCIR_PEER_INIT = 0,	/* Initial state */
	CCIR_PEER_ACTIVE,	/* Send connect request */
	CCIR_PEER_PASSIVE,	/* Received connect request */
	CCIR_PEER_CONNECTED	/* Ready to exchange route info */
} ccir_peer_state_t;

typedef struct ccir_peer {
	cci_connection_t *c;	/* CCI connection */
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
} ccir_ep_t;

typedef struct ccir_globals {
	ccir_ep_t **eps;	/* Array of endpoints - NULL terminated */
	uint32_t ep_cnt;	/* Number of endpoints */
	uint32_t blocking;	/* Should we block (1) or poll (0)? */
	uint32_t nfds;		/* The highest OS handle + 1 for select */
	uint32_t verbose;	/* Level of debugging output */
} ccir_globals_t;
