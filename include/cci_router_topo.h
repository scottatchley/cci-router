/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#ifndef CCI_ROUTER_TOPO_H
#define CCI_ROUTER_TOPO_H

/* BEGIN_C_DECLS */

typedef struct ccir_topo ccir_topo_t;		/* Topology state */
typedef struct ccir_router ccir_router_t;	/* Router information */
typedef struct ccir_subnet ccir_subnet_t;	/* Subnet information */
typedef struct ccir_route ccir_route_t;		/* One or more paths between A and B */
typedef struct ccir_path ccir_path_t;		/* One path between A and B using
						   two or more subnets */
typedef struct ccir_pair ccir_pair_t;		/* Two directly connected subnets */

struct ccir_router {
	uint32_t id;		/* Router's ID - tree key */
	uint32_t count;		/* Number of subnets served */
	uint32_t *subnets;	/* Array of subnet IDs for this router */
	uint32_t pair_count;	/* Number of pairs served */
	uint64_t *pairs;	/* Array of pair IDs for this router */
	uint64_t instance;	/* Router's instance (seconds since epoch) */
};

struct ccir_subnet {
	uint32_t id;		/* Subnet id  - tree key */
	uint32_t count;		/* Number of routers on subnet */
	uint32_t *routers;	/* Array of router IDs for this subnet */
	uint32_t pair_count;	/* Number of pairs served */
	uint64_t *pairs;	/* Array of pair IDs for this router */
	uint16_t rate;		/* Gb/s */
};

/* A pair of two directly connected subnets */
struct ccir_pair {
	uint64_t id;		/* ((subnetA << 32) | subnetB) where A < B */
	uint32_t *routers;	/* Array of routers IDs connecting these subnets */
	uint32_t count;		/* Number of routers in array */
};

/* A path is two or more subnets that form a path (route) between subnet A and subnet B.
 * For example: pairs AG, GE, EK, KB traverses subnets AGEKB.
 * The count is the number of subnets.
 * The score is the comparison metric (e.g. inverse bandwidth, hop count, etc. ) */
struct ccir_path {
	uint32_t *subnets;	/* Array of directly connected subnet IDs */
	uint32_t count;		/* Number of pairs in path */
	uint32_t score;		/* Path score */
};

#define CCIR_INVALID_PATH	((uint32_t) -1)

/* A route has all known, non-looping paths between A and B */
struct ccir_route {
	uint64_t id;		/* ((subnetA << 32) | subnetB) where A < B */
	ccir_path_t **paths;	/* Array of pointers for available paths */
	uint32_t count;		/* Number of paths sorted on path->score */
};

/* Routes are sorted using the minimal path scores. */
typedef enum ccir_metric {
	CCIR_METRIC_BW = 1,	/* Inverse bandwidth (1000/subnet->rate) */
	CCIR_METRIC_HOP		/* Hop count */
} ccir_metric_t;

struct ccir_topo {
	ccir_subnet_t **subnets; /* Array of pointers of subnets sorted on subnet ID */
	uint32_t num_subnets;	/* number of subnets */
	ccir_router_t **routers; /* Array of pointers of routers sorted in router ID */
	uint32_t num_routers;	/* number of routers */
	ccir_pair_t **pairs;	/* Array of pointers of all directly connected subnets */
	uint32_t num_pairs;	/* number of pairs */
	ccir_route_t **routes;	/* Array of pointers for all routes */
	uint32_t num_routes;	/* Number of routes */
	ccir_metric_t metric;	/* Used to rank paths within a route */
};

static inline uint64_t
pack_id(uint32_t a, uint32_t b)
{
	uint64_t id = 0;

	if (a < b)
		id = ((uint64_t) a << 32) | (uint64_t) b;
	else
		id = ((uint64_t) b << 32) | (uint64_t) a;

	return id;
}

static inline void
parse_id(uint64_t id, uint32_t *lo, uint32_t *hi)
{
	*lo = (uint32_t)(id >> 32);
	*hi = (uint32_t)id;
	return;
}

int find_router(ccir_topo_t *topo, uint32_t router_id, ccir_router_t **r);
int add_router_to_topo(ccir_topo_t *topo, uint32_t router_id, uint64_t router_instance,
			uint32_t subnet_id, ccir_router_t **r, int *new);
void delete_router_from_topo(ccir_topo_t *topo, uint32_t router_id);

void add_subnet_to_router(ccir_topo_t *topo, ccir_router_t *router, uint32_t subnet_id);
void delete_subnet_from_router(ccir_router_t *router, uint32_t subnet_id);
void print_routers(ccir_topo_t *topo);


int find_subnet(ccir_topo_t *topo, uint32_t subnet_id, ccir_subnet_t **s);
int add_subnet_to_topo(ccir_topo_t *topo, uint32_t subnet_id, uint32_t subnet_rate,
			uint32_t router_id, ccir_subnet_t **sn, int *new);
void delete_subnet_from_topo(ccir_topo_t *topo, uint32_t subnet_id);
void add_router_to_subnet(ccir_topo_t *topo, ccir_subnet_t *subnet, uint32_t router_id);
void delete_router_from_subnet(ccir_subnet_t *subnet, uint32_t router_id);
void print_subnets(ccir_topo_t *topo);

int add_pairs(ccir_topo_t *topo, ccir_subnet_t *subnet, ccir_router_t *router);
inline void print_routes(ccir_topo_t *topo);


/* END_C_DECLS */
#endif /* CCI_ROUTER_TOPO_H */
