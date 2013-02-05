/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci.h"

typedef struct ccir_peer {
	cci_connection_t *c;
	uint32_t status;
	char *uri;
} ccir_peer_t;

typedef struct ccir_ep {
	cci_endpoint_t e;
	ccir_peer_t **peers;
	uint32_t as;
	uint32_t subnet;
} ccir_ep_t;
