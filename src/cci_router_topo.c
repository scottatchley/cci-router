/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "cci_router_topo.h"
#include "cci_router_debug.h"

static int
compare_u32(const void *pa, const void *pb)
{
	uint32_t *a = (uint32_t *)pa, *b = (uint32_t *)pb;

	return *a > *b ? 1 : *a < *b ? -1 : 0;
}

#if 0
static int
compare_u64(const void *pa, const void *pb)
{
	uint64_t *a = (uint64_t *)pa, *b = (uint64_t *)pb;

	return *a > *b ? 1 : *a < *b ? -1 : 0;
}
#endif

/****** router *********************************************************************/
static inline void
print_router(ccir_router_t *r)
{
	uint32_t i = 0, lo = 0, hi = 0;

	debug(RDB_TOPO, "    router 0x%x count %u instance 0x%"PRIx64,
			r->id, r->count, r->instance);

	if (r->count)
		debug(RDB_TOPO, "        %u subnets:", r->count);
	for (i = 0; i < r->count; i++)
		debug(RDB_TOPO, "            subnet 0x%x", r->subnets[i]);

	if (r->pair_count) {
		debug(RDB_TOPO, "        %u pairs:", r->pair_count);
		for (i = 0; i < r->pair_count; i++) {
			parse_id(r->pairs[i], &lo, &hi);
			debug(RDB_TOPO, "            pair 0x%x_%x", lo, hi);
		}
	}

	return;
}

void
print_routers(ccir_topo_t *topo)
{
	uint32_t i = 0;

	debug(RDB_TOPO, "%s: count = %u", __func__, topo->num_routers);

	for (i = 0; i < topo->num_routers; i++)
		print_router(topo->routers[i]);

	return;
}

static int
compare_routers(const void *rp1, const void *rp2)
{
	ccir_router_t *r1 = *((ccir_router_t **)rp1);
	ccir_router_t *r2 = *((ccir_router_t **)rp2);

	return r1->id > r2->id ? 1 : r1->id < r2->id ? -1 : 0;
}

int
find_router(ccir_topo_t *topo, uint32_t router_id, ccir_router_t **r)
{
	int ret = 0;
	ccir_router_t *router = NULL, **rp = NULL, tmp, *key = &tmp;

	tmp.id = router_id;

	rp = bsearch(&key, topo->routers, topo->num_routers, sizeof(router), compare_routers);
	if (rp) {
		*r = *rp;
	} else {
		*r = NULL;
		ret = ENOENT;
	}

	return ret;
}

int
add_router_to_topo(ccir_topo_t *topo, uint32_t router_id, uint64_t router_instance,
		uint32_t subnet_id, ccir_router_t **r, int *new)
{
	int ret = 0;
	ccir_router_t *router = NULL;


	find_router(topo, router_id, &router);
	if (router) {
		if (verbose) {
			debug(RDB_TOPO, "%s: already have router 0x%x", __func__, router->id);
		}

		/* TODO */
		debug(RDB_TOPO, "%s: router 0x%x new instance 0x%"PRIx64" (old 0x%"PRIx64")",
				__func__, router->id, router_instance, router->instance);
		router->instance = router_instance;

		*new = 0;
	} else {
		ccir_router_t **routers = NULL;

		router = calloc(1, sizeof(*router));
		if (!router) {
			/* TODO */
			ret = ENOMEM;
			if (verbose)
				debug(RDB_TOPO, "%s: no memory for router 0x%x",
						__func__, router_id);
			goto out;
		}
		router->id = router_id;
		router->count = 0;
		router->instance = router_instance;

		if (verbose)
			debug(RDB_TOPO, "%s: adding router 0x%x", __func__, router->id);

		topo->num_routers++;
		routers = realloc(topo->routers, topo->num_routers * sizeof(router));
		if (!routers) {
			topo->num_routers--;
			free(router);
			ret = ENOMEM;
			if (verbose)
				debug(RDB_TOPO, "%s: no memory for router 0x%x",
						__func__, router_id);
			goto out;
		}
		topo->routers = routers;
		topo->routers[topo->num_routers - 1] = router;

		qsort(topo->routers, topo->num_routers, sizeof(router), compare_routers);

		*new = 1;
	}

	add_subnet_to_router(topo, router, subnet_id);

	if (verbose)
		print_routers(topo);

	*r = router;
out:
	return ret;
}

void
delete_router_from_topo(ccir_topo_t *topo, uint32_t router_id)
{
	ccir_router_t *router = NULL;

	find_router(topo, router_id, &router);
	if (router) {
		ccir_router_t **routers = NULL;

		router->id = UINT32_MAX;
		qsort(topo->routers, topo->num_routers, sizeof(router), compare_routers);

		topo->num_routers--;
		routers = realloc(topo->routers, topo->num_routers * sizeof(router));
		if (routers) {
			/* If the realloc fails, we still have the old, larger
			 * array but num_routers will ensure that we ignore the
			 * last, unwanted router pointer.
			 */
			topo->routers = routers;
		}
		free(router->subnets);
		free(router->pairs);
		free(router);

		if (verbose)
			debug(RDB_TOPO, "%s: deleted router 0x%x from topo",
					__func__, router_id);
	} else {
		if (verbose)
			debug(RDB_TOPO, "%s: router 0x%x not found", __func__, router_id);
	}
	return;
}

void
add_subnet_to_router(ccir_topo_t *topo, ccir_router_t *router, uint32_t subnet_id)
{
	uint32_t *s = NULL;

	s = bsearch(&subnet_id, router->subnets, router->count, sizeof(*s), compare_u32);
	if (s) {
		assert(*s == subnet_id);
		debug(RDB_TOPO, "%s: router 0x%x already has subnet 0x%x",
			__func__, router->id, subnet_id);
	} else {
		uint32_t *subnets = NULL;

		if (verbose)
			debug(RDB_TOPO, "%s: router 0x%x adding subnet 0x%x",
				__func__, router->id, subnet_id);

		router->count++;
		subnets = realloc(router->subnets, sizeof(*s) * router->count);
		if (!subnets) {
			debug(RDB_TOPO, "%s: no memory to add subnet 0x%x to router 0x%x",
					__func__, subnet_id, router->id);
			router->count--;
			return;
		}
		router->subnets = subnets;
		router->subnets[router->count - 1] = subnet_id;

		qsort(router->subnets, router->count, sizeof(*s), compare_u32);
	}

	if (verbose)
		print_router(router);

	return;
}

void
delete_subnet_from_router(ccir_router_t *router, uint32_t subnet_id)
{
	uint32_t *s = NULL;

	s = bsearch(&subnet_id, router->subnets, router->count, sizeof(*s), compare_u32);
	if (s) {
		uint32_t *subnets = NULL;

		if (verbose) {
			debug(RDB_TOPO, "%s: router 0x%x removing subnet 0x%x",
					__func__, router->id, subnet_id);
		}
		*s = UINT32_MAX;
		qsort(router->subnets, router->count, sizeof(*s), compare_u32);
		router->count--;
		if (router->count) {
			qsort(router->subnets, router->count, sizeof(*s), compare_u32);
			subnets = realloc(router->subnets, router->count * sizeof(*s));
			if (subnets)
				router->subnets = subnets;
		} else {
			free(router->subnets);
			router->subnets = NULL;
		}
	}

	if (verbose)
		print_router(router);

	return;
}

/***** subnet **********************************************************************/
static inline void
print_subnet(ccir_subnet_t *s)
{
	uint32_t i = 0;

	debug(RDB_TOPO, "    subnet 0x%x count %u rate %hu",
			s->id, s->count, s->rate);

	for (i = 0; i < s->count; i++)
		debug(RDB_TOPO, "        router 0x%x", s->routers[i]);

	return;
}

void
print_subnets(ccir_topo_t *topo)
{
	uint32_t i = 0;

	debug(RDB_TOPO, "%s: count = %u", __func__, topo->num_subnets);

	for (i = 0; i < topo->num_subnets; i++)
		print_subnet(topo->subnets[i]);
}

static int
compare_subnets(const void *sp1, const void *sp2)
{
	ccir_subnet_t *s1 = *((ccir_subnet_t **)sp1);
	ccir_subnet_t *s2 = *((ccir_subnet_t **)sp2);

	return s1->id > s2->id ? 1 : s1->id < s2->id ? -2 : 0;
}

int
find_subnet(ccir_topo_t *topo, uint32_t subnet_id, ccir_subnet_t **s)
{
	int ret = 0;
	ccir_subnet_t *subnet = NULL, **sp = NULL, tmp, *key = &tmp;

	tmp.id = subnet_id;

	sp = bsearch(&key, topo->subnets, topo->num_subnets, sizeof(subnet), compare_subnets);
	if (sp) {
		*s = *sp;
	} else {
		*s = NULL;
		ret = ENOENT;
	}

	return ret;
}

int
add_subnet_to_topo(ccir_topo_t *topo, uint32_t subnet_id, uint32_t subnet_rate,
		uint32_t router_id, ccir_subnet_t **sn, int *new)
{
	int ret = 0;
	ccir_subnet_t **sp = NULL, *subnet = NULL, *key = NULL, tmp;

	tmp.id = subnet_id;
	key = &tmp;

	sp = bsearch(&key, topo->subnets, topo->num_subnets, sizeof(subnet),
			compare_subnets);
	if (sp)
		subnet = *sp;

	if (subnet) {
		if (verbose) {
			debug(RDB_TOPO, "%s: found subnet 0x%x", __func__, subnet->id);
		}
		*new = 0;
	} else {
		ccir_subnet_t **subnets = NULL;

		subnet = calloc(1, sizeof(*subnet));
		if (!subnet) {
			/* TODO */
			assert(0);
		}
		subnet->id = subnet_id;
		subnet->count = 0;
		subnet->rate = subnet_rate;

		if (verbose) {
			debug(RDB_TOPO, "%s: adding subnet 0x%x", __func__, subnet->id);
		}

		topo->num_subnets++;
		subnets = realloc(topo->subnets, sizeof(subnet) * topo->num_subnets);
		if (!subnets) {
			debug(RDB_TOPO, "%s: no memory for subnet 0x%x", __func__,
					subnet_id);
			free(subnet);
			topo->num_subnets--;
			ret = ENOMEM;
			goto out;
		}
		topo->subnets = subnets;
		topo->subnets[topo->num_subnets - 1] = subnet;

		qsort(topo->subnets, topo->num_subnets, sizeof(subnet), compare_subnets);
		*new = 1;
	}

	add_router_to_subnet(topo, subnet, router_id);

	if (verbose)
		print_subnets(topo);

	*sn = subnet;
out:
	return ret;
}

void
delete_subnet_from_topo(ccir_topo_t *topo, uint32_t subnet_id)
{
	ccir_subnet_t *subnet = NULL, **sp = NULL, tmp, *key = &tmp;

	tmp.id = subnet_id;

	sp = bsearch(&key, topo->subnets, topo->num_subnets, sizeof(subnet), compare_subnets);
	if (sp) {
		ccir_subnet_t **subnets = NULL;

		subnet = *sp;

		subnet->id = UINT32_MAX;
		qsort(topo->subnets, topo->num_subnets, sizeof(subnet), compare_subnets);

		topo->num_subnets--;
		subnets = realloc(topo->subnets, topo->num_subnets * sizeof(subnet));
		if (subnets) {
			/* If the realloc fails, we still have the old, larger
			 * array but num_subnets will ensure that we ignore the
			 * last, unwanted subnet pointer.
			 */
			topo->subnets = subnets;
		}
		free(subnet->routers);
		free(subnet->pairs);
		free(subnet);

		if (verbose)
			debug(RDB_TOPO, "%s: deleted subnet 0x%x from topo",
					__func__, subnet_id);
	} else {
		if (verbose)
			debug(RDB_TOPO, "%s: subnet 0x%x not found", __func__, subnet_id);
	}
	return;
}

void
add_router_to_subnet(ccir_topo_t *topo, ccir_subnet_t *subnet, uint32_t router_id)
{
	uint32_t *r = NULL;

	r = bsearch(&router_id, subnet->routers, subnet->count, sizeof(*r), compare_u32);
	if (r) {
		assert(*r == router_id);
		if (verbose)
			debug(RDB_TOPO, "%s: subnet 0x%x already has router 0x%x",
				__func__, subnet->id, router_id);
	} else {
		uint32_t *routers = NULL;

		if (verbose)
			debug(RDB_TOPO, "%s: subnet 0x%x adding router 0x%x",
				__func__, subnet->id, router_id);

		subnet->count++;
		routers = realloc(subnet->routers, sizeof(*r) * subnet->count);
		if (!routers) {
			debug(RDB_TOPO, "%s: no memory to add router 0x%x to subnet 0x%x",
					__func__, router_id, subnet->id);
			subnet->count--;
			return;
		}
		subnet->routers = routers;
		subnet->routers[subnet->count - 1] = router_id;

		qsort(subnet->routers, subnet->count, sizeof(*r), compare_u32);
	}

	if (verbose)
		print_subnet(subnet);

	return;
}

void
delete_router_from_subnet(ccir_subnet_t *subnet, uint32_t router_id)
{
	uint32_t *r = NULL;

	r = bsearch(&router_id, subnet->routers, subnet->count, sizeof(*r), compare_u32);
	if (r) {
		uint32_t *routers = NULL;

		if (verbose) {
			debug(RDB_TOPO, "%s: subnet 0x%x removing router 0x%x",
					__func__, subnet->id, router_id);
		}
		*r = UINT32_MAX;
		qsort(subnet->routers, subnet->count, sizeof(*r), compare_u32);
		subnet->count--;
		if (subnet->count) {
			qsort(subnet->routers, subnet->count, sizeof(*r), compare_u32);
			routers = realloc(subnet->routers, subnet->count * sizeof(*r));
			if (routers)
				subnet->routers = routers;
		} else {
			free(subnet->routers);
			subnet->routers = NULL;
		}
	}

	if (verbose)
		print_subnet(subnet);

	return;
}

/****** pair ***********************************************************************/
static inline void
print_pair(ccir_pair_t *p)
{
	int i = 0;
	uint32_t lo = 0, hi = 0;

	parse_id(p->id, &lo, &hi);

	debug(RDB_TOPO, "    pair 0x%x_%x count %u", lo, hi, p->count);

	for (i = 0; i < (int) p->count; i++)
		debug(RDB_TOPO, "        router 0x%x", p->routers[i]);

	return;
}

static void
print_pairs(ccir_topo_t *topo)
{
	uint32_t i = 0;

	for (i = 0; i < topo->num_pairs; i++)
		print_pair(topo->pairs[i]);
}

static int
compare_pairs(const void *pp1, const void *pp2)
{
	ccir_pair_t *p1 = *((ccir_pair_t **)pp1);
	ccir_pair_t *p2 = *((ccir_pair_t **)pp2);

	return p1->id > p2->id ? 1 : p1->id < p2->id ? -1 : 0;
}

static inline uint32_t
score_path_bw(ccir_topo_t *topo, ccir_path_t *path)
{
	uint32_t i = 0, score = 0;

	for (i = 0; i < path->count; i++) {
		uint32_t subnet_id = path->subnets[i];
		ccir_subnet_t **sp = NULL, *subnet = NULL, *key = NULL, tmp;

		tmp.id = subnet_id;
		key = &tmp;

		sp = bsearch(&key, topo->subnets, topo->num_subnets, sizeof(subnet),
				compare_subnets);
		if (sp)
			subnet = *sp;

		if (subnet) {
			score += 1000 / subnet->rate;
		} else {
			/* TODO */
			debug(RDB_TOPO, "%s: unknown subnet 0x%x", __func__, subnet_id);
		}
	}

	return score;
}

static inline uint32_t
score_path_hop(ccir_topo_t *topo, ccir_path_t *path)
{
	return path->count;
}

/* A valid path is one or more pairs that form a path (route) between subnet A
 * and subnet B without looping.
 *
 * For example, a path for route AB could include: AG, GE, EK, and KB. This path
 * traverses subnets AGEKB. Because we store pair IDs in low/high order,
 * the pairs are would be AG,EG,EK, and BK.
 *
 * Return 0 on success, errno on error
 */
static inline int
valid_path(ccir_topo_t *topo, ccir_path_t *path)
{
	int ret = 0;
	uint32_t i = 0, a = 0, b = 0;
	uint64_t ab = 0;
	ccir_pair_t **pp, tmp, *key = &tmp;

	if (verbose) {
		debug(RDB_TOPO, "%s: validating path %p count %u", __func__,
				(void*)path, path->count);
		for (i = 0; i < path->count; i++)
			debug(RDB_TOPO, "%s:    0x%x", __func__, path->subnets[i]);
	}

	a = path->subnets[0];

	for (i = 1; i < path->count; i++) {
		uint32_t j = 0;

		b = path->subnets[i];

		for (j = 0; j < i; j++) {
			if (b == path->subnets[j]) {
				if (verbose) {
					debug(RDB_TOPO, "%s: path loops on subnet 0x%x",
							__func__, b);
				}

				ret = EINVAL;
				goto out;
			}
		}

		ab = pack_id(a, b);

		tmp.id = ab;

		pp = bsearch(&key, topo->pairs, topo->num_pairs, sizeof(key), compare_pairs);
		if (!pp) {
			if (verbose)
				debug(RDB_TOPO, "%s: subnets 0x%x and 0x%x not directly "
						"routed", __func__, a, b);
			ret = EINVAL;
			goto out;
		}
		a = b;
	}

out:
	return ret;
}

static inline uint32_t
score_path(ccir_topo_t *topo, ccir_path_t *path)
{
	int ret = 0;
	uint32_t score = 0;

	ret = valid_path(topo, path);
	if (ret) return CCIR_INVALID_PATH;

	switch (topo->metric) {
		case CCIR_METRIC_BW:
			score = score_path_bw(topo, path);
			break;
		case CCIR_METRIC_HOP:
			score = score_path_hop(topo, path);
			break;
		default:
			debug(RDB_TOPO, "%s: unkown metric %d", __func__, topo->metric);
			break;
	}

	return score;
}

/* Compare two paths by score
 *
 * Return 0 is identical
 */
static int
compare_paths(const void *pr1, const void *pr2)
{
	ccir_path_t *p1 = (ccir_path_t *)pr1;
	ccir_path_t *p2 = (ccir_path_t *)pr2;

	if (!p1) return -1;
	if (!p2) return 1;

	return p1->score > p2->score ? 1 : p1->score < p2->score ? -1 : 0;
}

/* Are the two paths identical?
 *
 * Return 0 if true, else -1
 */
static inline int
identical_paths(ccir_path_t *a, ccir_path_t *b)
{
	uint32_t i = 0;

	if (!a || !b) return -1;
	if (a->count != b->count) return -1;

	for (i = 0; i < a->count; i++) {
		if (a->subnets[i] != b->subnets[i])
			return -1;
	}

	return 0;
}

/***** route ***********************************************************************/
static void
print_route(ccir_route_t *route)
{
	uint32_t i = 0, lo = 0, hi = 0;

	parse_id(route->id, &lo, &hi);
	debug(RDB_TOPO, "    route 0x%x_%x count %u:", lo, hi, route->count);

	for (i = 0; i < route->count; i++) {
		uint32_t j = 0;
		ccir_path_t *path = route->paths[i];

		debug(RDB_TOPO, "        path %u with %u pairs and score %u:",
				i, path->count, path->score);

		for (j = 0; j < path->count; j++) {
			debug(RDB_TOPO, "            0x%x", path->subnets[j]);
		}
	}

	return;
}

inline void
print_routes(ccir_topo_t *topo)
{
	uint32_t i = 0;

	debug(RDB_TOPO, "%s: count = %u", __func__, topo->num_routes);

	for (i = 0; i < topo->num_routes; i++)
		print_route(topo->routes[i]);

	return;
}

static int
compare_routes(const void *rp1, const void *rp2)
{
	ccir_route_t *r1 = *((ccir_route_t **)rp1);
	ccir_route_t *r2 = *((ccir_route_t **)rp2);

	return r1->id > r2->id ? 1 : r1->id < r2->id ? -1 : 0;
}

static inline int
add_route(ccir_topo_t *topo, ccir_route_t *route)
{
	int ret = 0;
	ccir_route_t **routes = NULL;

	topo->num_routes++;
	routes = realloc(topo->routes, sizeof(route) * topo->num_routes);
	if (!routes) {
		uint32_t lo = 0, hi = 0;
		parse_id(route->id, &lo, &hi);
		debug(RDB_TOPO, "%s: no memory for topo->routes 0x%x_%x", __func__, lo, hi);
		topo->num_routes--;
		ret = ENOMEM;
		goto out;
	}
	topo->routes = routes;
	topo->routes[topo->num_routes - 1] = route;

	qsort(topo->routes, topo->num_routes, sizeof(route), compare_routes);

out:
	return ret;
}

static inline void
del_route(ccir_topo_t *topo, ccir_route_t *route)
{
	ccir_route_t **routes = NULL;

	if (verbose) {
		uint32_t lo = 0, hi = 0;

		parse_id(route->id, &lo, &hi);
		debug(RDB_TOPO, "%s: removing route 0x%x_%x", __func__, lo, hi);
	}

	/* Move route to end of array */
	route->id = UINT64_MAX;
	qsort(topo->routes, topo->num_routes, sizeof(route), compare_routes);

	topo->num_routes--;
	if (topo->num_routes) {
		routes = realloc(topo->routes, sizeof(route) * topo->num_routes);
		if (routes)
			topo->routes = routes;
	} else {
		free(topo->routes);
		topo->routes = NULL;
	}

	return;
}

/* Given new pair AB and route BN, add route AN and calculate new paths
 * AN for each path in BN. */
static inline void
prepend_pair(ccir_topo_t *topo, ccir_pair_t *pair, ccir_route_t *bn)
{
	int reverse = 0;
	uint32_t a = 0, b = 0, bn_lo = 0, bn_hi = 0;
	uint64_t route_id = 0, ab = pair->id;
	ccir_route_t **rp = NULL, *an = NULL, *key = NULL, tmp;

	parse_id(pair->id, &a, &b);

	/* If the route is the same as the pair, we have already handled it */
	if (pair->id == bn->id) {
		if (verbose) {
			debug(RDB_TOPO, "%s: ignoring identical route 0x%x_%x",
					__func__, a, b);
		}
		return;
	}

	parse_id(bn->id, &bn_lo, &bn_hi);

	/* We only want BN... */
	if (bn_lo != b && bn_lo != a) {
		if (verbose) {
			debug(RDB_TOPO, "%s: cannot prepend pair 0x%x_%x to "
					"route 0x%x_%x", __func__, a, b,
					bn_lo, bn_hi);
		}
		return;
	}

	if (bn_lo == a) {
		uint32_t tmp = a;

		a = b;
		b = tmp;
		ab = pack_id(a, b);
	}

	if (a > bn_hi)
		reverse = 1;

	/* Route id for AN... */
	route_id = pack_id(a, bn_hi);
	tmp.id = route_id;
	key = &tmp;

	rp = bsearch(&key, topo->routes, topo->num_routes, sizeof(an), compare_routes);
	if (rp)
		an = *rp;

	if (!an) {
		int loop_found = 0, ret = 0;
		uint32_t i = 0;

		/* Route AN does not exist, create it and copy the paths
		 * from BN and prepend pair AB. */

		if (verbose) {
			debug(RDB_TOPO, "%s: create route for 0x%x_%x",
					__func__, a, bn_hi);
		}

		an = calloc(1, sizeof(*an));
		if (!an) {
			debug(RDB_TOPO, "%s: no memory for new route 0x%x_%x",
					__func__, a, bn_hi);
			return;
		}
		an->id = route_id;
		an->count = bn->count;
		an->paths = calloc(bn->count, sizeof(*an->paths));
		if (!an->paths) {
			debug(RDB_TOPO, "%s: no memory for new route 0x%x_%x paths",
					__func__, a, bn_hi);
			free(an);
			return;
		}

		/* copy paths from BN and prepend pair AB */
		for (i = 0; i < bn->count; i++) {
			uint32_t sn = a;
			int append = 0;
			ccir_path_t *pan = NULL, *pbn = bn->paths[i];

			debug(RDB_TOPO, "%s: pbn->subnets[0]   = 0x%x", __func__,
					pbn->subnets[0]);
			debug(RDB_TOPO, "%s: pbn->subnets[n-1] = 0x%x", __func__,
					pbn->subnets[pbn->count - 1]);

			if (!pbn->subnets[0] == a && !pbn->subnets[0] == b)
				append = 1;

			pan = calloc(1, sizeof(*pan));
			if (!pan) {
				/* TODO */
				assert(pan);
			}
			an->paths[i] = pan;

			pan->count = pbn->count + 1;
			pan->subnets = calloc(pan->count, sizeof(uint32_t));
			if (!pan->subnets) {
				/* TODO */
				assert(pan->subnets);
			}
			if (append) {
				if (pan->subnets[pan->count - 1] == a)
					sn = b;
				memcpy(&pan->subnets[0], pbn->subnets,
						pbn->count * sizeof(uint32_t));
				pan->subnets[pbn->count] = sn;
			} else {
				if (pan->subnets[0] == a)
					sn = b;
				pan->subnets[0] = sn;
				memcpy(&pan->subnets[1], pbn->subnets,
						pbn->count * sizeof(uint32_t));
			}

			if (reverse) {
				uint32_t j = 0;

				for (j = 0; j < pan->count / 2; j++) {
					uint32_t tmp = pan->subnets[j];

					pan->subnets[j] = pan->subnets[pan->count - 1 - j];
					pan->subnets[pan->count - 1 - j] = tmp;
				}
			}

			pan->score = score_path(topo, pan);
			if (pan->score == CCIR_INVALID_PATH)
				loop_found = 1;
		}

		qsort(an->paths, an->count, sizeof(*an->paths), compare_paths);

again:
		if (loop_found) {
			uint32_t bad = 0;
			for (i = 0; i < an->count; i++) {
				ccir_path_t *pan = an->paths[i];

				if (pan->score == (uint32_t) -1) {
					free(pan->subnets);
					free(pan);
					an->count--;
					bad = 1;
				}
			}
			an->paths = realloc(an->paths, an->count * sizeof(*an->paths));
			qsort(an->paths, an->count, sizeof(*an->paths), compare_paths);
			if (bad)
				goto again;
		}

		/* insert in tree */
		if (an->count) {
			ret = add_route(topo, an);
		} else {
			free(an->paths);
			free(an);
		}
	} else {
		/* The route AN exists, compare its paths to route BN's paths.
		 * If any are missing (ignoring leading AB pair),
		 * add to AN's paths. */

		if (verbose) {
			debug(RDB_TOPO, "%s: route 0x%x_%x exists",
					__func__, a, bn_hi);
		}
		/* TODO */
	}

	return;
}

/* Given new pair AB and route NA, add route NB and calculate new paths
 * NB for each path in NA. */
static inline void
append_pair(ccir_topo_t *topo, ccir_pair_t *pair, ccir_route_t *na)
{
	int reverse = 0;
	int ret = 0;
	uint32_t a = 0, b = 0, na_lo = 0, na_hi = 0;
	uint64_t route_id = 0, ab = pair->id;
	ccir_route_t *nb = NULL, **rp = NULL, *key = NULL, tmp;

	parse_id(pair->id, &a, &b);

	/* If the route is the same as the pair, we have already handled it */
	if (pair->id == na->id) {
		if (verbose) {
			debug(RDB_TOPO, "%s: ignoring identical route 0x%x_%x",
					__func__, a, b);
		}
		return;
	}

	parse_id(na->id, &na_lo, &na_hi);

	/* We only want NB... */
	if (na_hi != a && na_hi != b) {
		if (verbose) {
			debug(RDB_TOPO, "%s: cannot append pair 0x%x_%x to "
					"route 0x%x_%x", __func__, a, b,
					na_lo, na_hi);
		}
		return;
	}

	if (na_hi == b) {
		uint32_t tmp = b;

		b = a;
		a = tmp;
		ab = pack_id(a, b);
	}

	if (na_lo > b)
		reverse = 1;

	/* Route id for NB... */
	route_id = pack_id(na_lo, b);
	tmp.id = route_id;
	key = &tmp;

	rp = bsearch(&key, topo->routes, topo->num_routes, sizeof(nb),
			compare_routes);

	if (rp)
		nb = *rp;

	if (!nb) {
		int loop_found = 0;
		uint32_t i = 0;

		/* Route NB does not exist, create it and copy the paths
		 * from NA and append pair AB. */

		if (verbose) {
			debug(RDB_TOPO, "%s: create route for 0x%x_%x",
					__func__, na_lo, b);
		}

		nb = calloc(1, sizeof(*nb));
		if (!nb) {
			debug(RDB_TOPO, "%s: no memory for new route 0x%x_%x",
					__func__, na_lo, b);
			return;
		}
		nb->id = route_id;
		nb->count = na->count;
		nb->paths = calloc(na->count, sizeof(*nb->paths));
		if (!nb->paths) {
			debug(RDB_TOPO, "%s: no memory for new route 0x%x_%x paths",
					__func__, na_lo, b);
			free(nb);
			assert(nb->paths);
			return;
		}

		/* copy paths from NA and append pair AB */
		for (i = 0; i < na->count; i++) {
			uint32_t sn = a;
			int prepend = 0;
			ccir_path_t *pnb = NULL, *pna = na->paths[i];

			debug(RDB_TOPO, "%s: pna->subnets[0]   = 0x%x", __func__,
					pna->subnets[0]);
			debug(RDB_TOPO, "%s: pna->subnets[n-1] = 0x%x", __func__,
					pna->subnets[pna->count - 1]);

			if (!pna->subnets[pna->count - 1] == a
					&& !pna->subnets[pna->count - 1] == b)
				prepend = 1;

			pnb = calloc(1, sizeof(*pnb));
			if (!pnb) {
				/* TODO */
				assert(pnb);
			}
			nb->paths[i] = pnb;

			pnb->count = pna->count + 1;
			pnb->subnets = calloc(pnb->count, sizeof(uint32_t));
			if (!pnb->subnets) {
				/* TODO */
				assert(pnb->subnets);
			}
			if (prepend) {
				if (pna->subnets[0] == a)
					sn = b;
				pnb->subnets[0] = sn;
				memcpy(&pnb->subnets[1], pna->subnets,
						pna->count * sizeof(uint32_t));
			} else {
				if (pna->subnets[pna->count - 1] == a)
					sn = b;
				memcpy(pnb->subnets, pna->subnets,
						pna->count * sizeof(uint32_t));
				pnb->subnets[pna->count] = sn;
			}

			if (reverse) {
				uint32_t j = 0;

				for (j = 0; j < pnb->count / 2; j++) {
					uint32_t tmp = pnb->subnets[j];

					pnb->subnets[j] = pnb->subnets[pnb->count - 1 - j];
					pnb->subnets[pnb->count - 1 - j] = tmp;
				}
			}
			pnb->score = score_path(topo, pnb);
			if (pnb->score == CCIR_INVALID_PATH)
				loop_found = 1;
		}

		qsort(nb->paths, nb->count, sizeof(*nb->paths), compare_paths);

again:
		if (loop_found) {
			uint32_t bad = 0;
			for (i = 0; i < nb->count; i++) {
				ccir_path_t *pnb = nb->paths[i];

				if (pnb->score == (uint32_t) -1) {
					free(pnb->subnets);
					free(pnb);
					nb->count--;
					bad = 1;
				}
			}
			nb->paths = realloc(nb->paths, nb->count * sizeof(*nb->paths));
			qsort(nb->paths, nb->count, sizeof(*nb->paths), compare_paths);
			if (bad)
				goto again;
		}

		if (nb->count) {
			ret = add_route(topo, nb);
		} else {
			free(nb->paths);
			free(nb);
		}
	} else {
		/* The route NB exists, compare its paths to route NA's paths.
		 * If any are missing (ignoring leading AB pair),
		 * add to NB's paths. */

		if (verbose) {
			debug(RDB_TOPO, "%s: route 0x%x_%x exists",
					__func__, na_lo, b);
		}
		/* TODO */
	}

	return;
}

/* Given new pair AB and routes MA and BN, add route MN and calculate new paths
 * MN for each path in MA + AB + BN. */
static void
join_ma_ab_bn(ccir_topo_t *topo, uint64_t pair_id, ccir_route_t *ma, ccir_route_t *bn)
{
	int ret = 0;
	uint32_t pair_lo = 0, pair_hi = 0, ma_lo = 0, ma_hi = 0, bn_lo = 0, bn_hi = 0;
	uint32_t i = 0;
	uint64_t mn_id = 0;
	ccir_route_t *mn = NULL, **rp = NULL, *key = NULL, tmp;
	ccir_path_t *pma = NULL, *pbn = NULL, *pmn = NULL;

	parse_id(pair_id, &pair_lo, &pair_hi);
	parse_id(ma->id, &ma_lo, &ma_hi);
	parse_id(bn->id, &bn_lo, &bn_hi);

	if (verbose) {
		debug(RDB_TOPO, "%s: check if route MA (0x%x_%x) + AB (0x%x_%x) + "
				"BN (0x%x_%x) is joinable", __func__, ma_lo, ma_hi,
				pair_lo, pair_hi, bn_lo, bn_hi);
	}

	if (ma_hi != pair_lo) {
		if (verbose) {
			debug(RDB_TOPO, "%s: MA route 0x%x_%x does not connect to pair "
				"0x%x_%x", __func__, ma_lo, ma_hi, pair_lo, pair_hi);
		}
		return;
	} else if (pair_hi != bn_lo) {
		if (verbose) {
			debug(RDB_TOPO, "%s: NB route 0x%x_%x does not connect to "
				"pair 0x%x_%x", __func__, pair_lo, pair_hi, bn_lo, bn_hi);
		}
		return;
	}

	if (verbose) {
		debug(RDB_TOPO, "%s: checking for route 0x%x_%x", __func__,
			ma_lo, bn_hi);
	}

	mn_id = pack_id(ma_lo, bn_hi);
	tmp.id = mn_id;
	key = &tmp;

	rp = bsearch(&key, topo->routes, topo->num_routes, sizeof(mn), compare_routes);
	if (rp)
		mn = *rp;

	if (!mn) {
		/* new route, create it */
		mn = calloc(1, sizeof(*mn));
		if (!mn) {
			debug(RDB_TOPO, "%s: no memory for the new route 0x%x_%x",
				__func__, ma_lo, bn_hi);
			return;
		}
		mn->id = mn_id;
		ret = add_route(topo, mn);
		if (ret) {
			free(mn);
			return;
		}

		if (verbose) {
			debug(RDB_TOPO, "%s: joining route 0x%x_%x to 0x%x_%x to 0x%x_%x "
				"to create new route 0x%x_%x", __func__, ma_lo, ma_hi,
				pair_lo, pair_hi, bn_lo, bn_hi, ma_lo, bn_hi);
		}
	} else {
		if (verbose)
			debug(RDB_TOPO, "%s: found route 0x%x_%x", __func__, ma_lo, bn_hi);
	}

	/* combine and validate the paths */
	for (i = 0; i < ma->count; i++) {
		uint32_t j = 0;

		pma = ma->paths[i];

		for (j = 0; j < bn->count; j++) {
			pbn = bn->paths[j];

			pmn = calloc(1, sizeof(*pmn));
			if (!pmn) {
				debug(RDB_TOPO, "%s: no memory for new path for x0%x_%x",
					__func__, ma_lo, bn_hi);
				continue;
			}
			/* Number of pairs if MA count + AB + BN count */
			pmn->count = pma->count + pbn->count;
			pmn->subnets = calloc(pmn->count, sizeof(*pmn->subnets));
			if (!pmn->subnets) {
				debug(RDB_TOPO, "%s: no memory for new path's subnets for x0%x_%x",
					__func__, ma_lo, bn_hi);
				free(pmn);
				continue;
			}
			/* concatenate MA + AB + BN */
			memcpy(pmn->subnets, pma->subnets, pma->count * sizeof(*pmn->subnets));
			memcpy(&pmn->subnets[pma->count], pbn->subnets,
					pbn->count * sizeof(*pmn->subnets));
			pmn->score = score_path(topo, pmn);
			if (pmn->score == CCIR_INVALID_PATH) {
				if (verbose) {
					debug(RDB_TOPO, "%s: freeing invalid path joining "
						"ma[%u] bn[%u]", __func__, i, j);
				}
				free(pmn->subnets);
				free(pmn);
				continue;
			} else {
				int add_path = 1;
				uint32_t k = 0;

				/* check if the path already exists in MN */
				for (k = 0; k < mn->count; k++) {
					ccir_path_t *pk = mn->paths[k];

					ret = identical_paths(pmn, pk);
					if (ret == 0) {
						add_path = 0;
						free(pmn->subnets);
						free(pmn);
						break;
					}
				}
				if (add_path) {
					ccir_path_t **paths = NULL;

					mn->count++;
					paths = realloc(mn->paths,
							sizeof(*mn->paths) * mn->count);

					if (!paths) {
						mn--;
						free(pmn->subnets);
						free(pmn);
						debug(RDB_TOPO, "%s: no memory for new path",
								__func__);
						continue;
					}
					if (verbose) {
						debug(RDB_TOPO, "%s: adding new path", __func__);
					}
					mn->paths = paths;
					qsort(mn->paths, mn->count, sizeof(pmn), compare_paths);
				}
			}
		}
	}

	if (mn->count == 0) {
		/* This route has no valid paths, remove and free it */
		del_route(topo, mn);
		free(mn->paths);
		free(mn);
	}

	return;
}

/* We have a new pair AB, which may be a new route as well and
 * we need to append, prepend, and join existing routes:
 *
 * 1) AB (add pair to existing route or add new route)
 * 2) *A + AB
 * 3) AB + B*
 * 4) *A + AB + B* (i.e. the join of (1) and (2))
 *
 * Need to add routes and calculate paths
 */
static int
add_routes(ccir_topo_t *topo, ccir_pair_t *pair)
{
	int ret = 0, new = 0, found = 0;
	uint32_t lo = 0, hi = 0, i = 0;
	ccir_route_t *route = NULL, **rp = NULL, *key = NULL, tmp;
	ccir_path_t *path = NULL;

	parse_id(pair->id, &lo, &hi);

	/* Create a path for this pair */
	path = calloc(1, sizeof(*path));
	if (!path) {
		debug(RDB_TOPO, "%s: no memory to check for route 0x%x_%x for path",
				__func__, lo, hi);
		ret = ENOMEM;
		assert(path);
		goto out;
	}
	path->count = 2;
	path->subnets = calloc(path->count, sizeof(uint32_t));
	if (!path->subnets) {
		ret = ENOMEM;
		assert(path->subnets);
		goto out;
	}
	path->subnets[0] = lo;
	path->subnets[1] = hi;
	path->score = score_path(topo, path);

	tmp.id = pair->id;
	key = &tmp;

	/* Does route exist? Does it have this pair? */
	rp = bsearch(&key, topo->routes, topo->num_routes, sizeof(route),
			compare_routes);

	if (rp)
		route = *rp;

	if (route) {
		for (i = 0; i < route->count; i++) {
			ret = identical_paths(path, route->paths[i]);
			if (ret == 0) {
				found = 1;
				break;
			}
		}
	} else {
		route = calloc(1, sizeof(*route));
		if (!route) {
			debug(RDB_TOPO, "%s: no memory for new route 0x%x_%x",
					__func__, lo, hi);
			ret =  ENOMEM;
			assert(route);
			goto out;
		}

		route->id = pair->id;
		new = 1;

		/* insert in tree */
		ret = add_route(topo, route);
	}

	if (!found) {
		route->count++;
		route->paths = realloc(route->paths, sizeof(path) * route->count);
		route->paths[route->count - 1] = path;

		qsort(route->paths, route->count, sizeof(path), compare_paths);
	} else {
		free(path->subnets);
		free(path);
	}

	for (i = 0; i < topo->num_routes; i++) {
		uint32_t j = 0;
		ccir_route_t *route = topo->routes[i];

		/* add routes for AB + B* */
		prepend_pair(topo, pair, route);

		/* add routes for *A + AB */
		append_pair(topo, pair, route);

		for (j = 0; j < topo->num_routes; j++) {
			ccir_route_t *route2 = topo->routes[j];

			if (i == j)
				continue;

			/* join routes *A + AB + B* */
			join_ma_ab_bn(topo, pair->id, route, route2);
		}
	}

out:
	if (ret) {
		if (path)
			free(path->subnets);
		free(path);
		if (new)
			free(route);
	}
	return ret;
}

int
add_pairs(ccir_topo_t *topo, ccir_subnet_t *subnet, ccir_router_t *router)
{
	int ret = 0, i = 0;

	/* for each subnet, check pair, add if needed, add router to pair */
	for (i = 0; i < (int) router->count; i++) {
		uint32_t lo = 0, hi = 0;
		uint32_t old = router->subnets[i], *r = NULL;
		uint64_t pair_id = pack_id(old, subnet->id);
		ccir_pair_t *pair = NULL, **pp = NULL ,tmp, *key = &tmp;

		if (old == subnet->id)
			continue;

		/* get subnets in the low-high order */
		if (verbose)
			parse_id(pair_id, &lo, &hi);

		/* Find the pair or create it */
		tmp.id = pair_id;

		pp = bsearch(&key, topo->pairs, topo->num_pairs, sizeof(pair), compare_pairs);
		if (pp) {
			pair = *pp;
		} else {
			ccir_pair_t **pairs = NULL;

			pair = calloc(1, sizeof(*pair));

			if (!pair) {
				/* TODO */
				assert(pair);
			}
			pair->id = pair_id;
			pair->count = 0;

			topo->num_pairs++;
			pairs = realloc(topo->pairs, sizeof(pair) * topo->num_pairs);
			if (!pairs) {
				free(pair);
				topo->num_pairs--;
				debug(RDB_TOPO, "%s: no memory for new pair 0x%x_%x",
					__func__, lo, hi);
				ret = ENOMEM;
				goto out;
			}
			topo->pairs = pairs;
			topo->pairs[topo->num_pairs - 1] = pair;

			qsort(topo->pairs, topo->num_pairs, sizeof(pair), compare_pairs);

			if (verbose) {
				debug(RDB_TOPO, "*** added pair 0x%x_%x", lo, hi);
			}

			/* calculate new routes for pair */
			ret = add_routes(topo, pair);
		}

		/* add router to pair */
		r = bsearch(&router->id, pair->routers, pair->count, sizeof(*r), compare_u32);
		if (r) {
			if (verbose) {
				debug(RDB_TOPO, "%s: pair 0x%x_%x already has router 0x%x",
					__func__, lo, hi, router->id);
			}
		} else {
			if (verbose) {
				debug(RDB_TOPO, "%s: pair 0x%x_%x adding router 0x%x",
					__func__, lo, hi, router->id);
			}

			pair->count++;
			pair->routers = realloc(pair->routers, sizeof(*r) * pair->count);
			pair->routers[pair->count - 1] = router->id;

			qsort(pair->routers, pair->count, sizeof(*r), compare_u32);
		}
	}

	if (verbose)
		print_pairs(topo);

out:
	return ret;
}
