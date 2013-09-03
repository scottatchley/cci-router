/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#ifndef CCI_ROUTER_E2E_H
#define CCI_ROUTER_E2E_H

#include "cci.h"
#include "cci/cci_e2e_wire.h"
#include "cci_router_debug.h"

#include "bsd/queue.h"

BEGIN_C_DECLS

typedef enum ccir_rconn_state {
	CCIR_RCONN_CLOSED = -2, /* Closed ready for cleanup */
	CCIR_RCONN_CLOSING = -1, /* Closing */
	CCIR_RCONN_INIT = 0,	/* Initial state */
	CCIR_RCONN_PENDING,	/* Wainting on E2E ACCEPT or REJECT */
	CCIR_RCONN_CONNECTED	/* Forwarding enabled */
} ccir_rconn_state_t;

/* Routed connection */
typedef struct ccir_rconn {
	TAILQ_ENTRY(ccir_ep) entry; /* For ep->rconns */
	cci_connection_t *src;	/* Source (passive) connection */
	cci_connection_t *dst;	/* Destination (active) connection */
	ccir_rconn_state_t state; /* State */
	int src_is_router;	/* Is src a router or routing client? */
	int dst_is_router;	/* Is dst a router or routing client? */
	char *client_uri;	/* E2E client's URI */
	char *server_uri;	/* E2E server's URI */
	int is_connecting;	/* Waiting on CONNECT event */
	int is_accepting;	/* Waiting on ACCEPT event */
} ccir_rconn_t;

END_C_DECLS
#endif /* CCI_ROUTER_E2E_H */
