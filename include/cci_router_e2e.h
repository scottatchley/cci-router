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

#include <stdint.h>

#include "cci.h"
#include "cci/cci_e2e_wire.h"
#include "cci_router_debug.h"

#include "bsd/queue.h"

BEGIN_C_DECLS

typedef struct ccir_rma_request ccir_rma_request_t;
typedef struct ccir_rma_buffer ccir_rma_buffer_t;

typedef enum ccir_rconn_state {
	CCIR_RCONN_CLOSED = -2, /* Closed ready for cleanup */
	CCIR_RCONN_CLOSING = -1, /* Closing */
	CCIR_RCONN_INIT = 0,	/* Initial state */
	CCIR_RCONN_PENDING,	/* Wainting on E2E ACCEPT or REJECT */
	CCIR_RCONN_CONNECTED	/* Forwarding enabled */
} ccir_rconn_state_t;

/* Routed connection */
typedef struct ccir_rconn {
	TAILQ_ENTRY(ccir_rconn) entry; /* For ep->rconns */
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

struct ccir_rma_request {
	cci_e2e_hdr_t		e2e_hdr;	/* E2E header */
	cci_e2e_rma_request_t	e2e_req;	/* E2E RMA request */
	ccir_rconn_t		*rconn;		/* Owning rconn */
	TAILQ_ENTRY(ccir_rma_request) entry;
#define CCIR_RMA_INITIATOR	0
#define CCIR_RMA_TARGET		1
	int			src_role : 1;	/* INITIATOR or TARGET? */
	int			dst_role : 1;	/* INITIATOR or TARGET? */
	int			final    : 1;	/* Set for final RMA op */
	int			idx      :24;	/* Index of RMA buffer */
	int			pad      : 5;
};

struct ccir_rma_buffer {
	void		*base;		/* Pointer to buffer */
	uint64_t	*ids;		/* Bitmask of available fragments */
	void		**rmas;		/* Cache of the pending RMA requests */
	pthread_mutex_t	lock;		/* Lock */
	TAILQ_HEAD(rqs, ccir_rma_request) reqs; /* Queued RMAs waiting on buffer */
	uint32_t	mtu;		/* RMA fragment size */
	uint32_t	cnt;		/* Number of RMA fragments */
	int		num_blocks;	/* Count of ids array */
};

END_C_DECLS
#endif /* CCI_ROUTER_E2E_H */
