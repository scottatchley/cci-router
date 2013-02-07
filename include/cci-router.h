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
	ccir_peer_state_t state; /* Peer's state */
	uint32_t attempts;	/* Number of connection attempts */
	uint32_t delay;		/* Seconds until next attempt */
} ccir_peer_t;

typedef struct ccir_ep {
	cci_endpoint_t *e;
	ccir_peer_t **peers;
	cci_os_handle_t fd;
	uint32_t peer_cnt;
	uint32_t as;
	uint32_t subnet;
} ccir_ep_t;

typedef struct ccir_globals {
	ccir_ep_t **eps;
	uint32_t count;
	uint32_t blocking;
	uint32_t verbose;
} ccir_globals_t;
