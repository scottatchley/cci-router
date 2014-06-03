/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#ifndef CCI_ROUTER_DEBUG_H
#define CCI_ROUTER_DEBUG_H

extern uint32_t debug;
extern uint32_t verbose;

#define CCIR_DEBUG	(1)	/* Turn on for development */

#define RDB_EP		(1 << 0)	/* endpoint */
#define RDB_PEER	(1 << 1)	/* peer/connections */
#define RDB_INFO	(1 << 2)	/* non-specific, low value */
#define RDB_CONFIG	(1 << 3)	/* configuration info */
#define RDB_TOPO	(1 << 4)	/* topology info */
#define RDB_E2E		(1 << 5)	/* E2E protocol info */

#define RDB_ALL		(~0)		/* print all */

#if CCIR_DEBUG
#define debug(lvl,fmt,...)						\
do {									\
	if ((lvl) & debug)						\
		fprintf(stderr, "router: " fmt "\n", __VA_ARGS__);	\
} while(0)
#else	/* !CCIR_DEBUG */
#define debug(lvl,fmt,...) do { } while(0)
#endif	/* CCIR_DEBUG */

#endif /* CCI_ROUTER_DEBUG_H */
