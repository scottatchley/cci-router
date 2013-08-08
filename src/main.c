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
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include <sys/param.h>
#include <signal.h>
#include <sys/select.h>
#include <assert.h>
#include <search.h>
#include <sys/time.h>

#include "cci-router.h"
#include "bsd/murmur3.h"

static void
usage(char *procname)
{
	fprintf(stderr, "usage: %s [-f <config_file>] [-v] [-b]\n", procname);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-f\tUse this configuration file.\n");
	fprintf(stderr, "\t-v\tVerbose output (-v[v[v]])\n");
	fprintf(stderr, "\t-b\tBlocking mode instead of polling mode\n");
	exit(EXIT_FAILURE);
}

volatile int running = 0;

static void handle_sigs(int signum)
{
	running = 0;
	return;
}

static int install_sig_handlers(ccir_globals_t *globals)
{
	int ret = 0;
	struct sigaction sa;

	sa.sa_handler = handle_sigs;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	ret = sigaction(SIGINT, &sa, NULL);
	if (ret == -1) {
		ret = errno;
		goto out;
	}

	ret = sigaction(SIGHUP, &sa, NULL);
	if (ret == -1) {
		ret = errno;
		goto out;
	}
out:
	if (ret && globals->verbose)
		debug(RDB_INFO, "%s: sigaction failed with %s",
				__func__, strerror(ret));
	return ret;
}

static void
handle_peer_recv_del(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer,
			cci_event_t *event);

static void
disconnect_peers(ccir_globals_t *globals)
{
	int ret = 0, i = 0, len = 0;
	char *buf = NULL;
	ccir_peer_hdr_t *hdr = NULL;
	ccir_del_data_t *del = NULL;

	/* the sizeof(*del) includes one uint32_t subnet already so we
	 * only need to add ep_cnt - 1 more */
	len = sizeof(hdr->del_size) +
		sizeof(*del) +
		((globals->ep_cnt - 1) * sizeof(uint32_t));

	buf = calloc(1, len);
	if (!buf) {
		/* TODO */
		assert(buf);
	}

	hdr = (ccir_peer_hdr_t *)buf;
	del = (ccir_del_data_t *)hdr->del.data;

	ccir_pack_del(hdr, 1, (uint8_t)globals->ep_cnt);
	del->instance = ccir_htonll(globals->instance);
	del->router = htonl(globals->id);

	debug(RDB_PEER, "%s: preparing DEL msg for router 0x%x with %u endpoints",
		__func__, globals->id, globals->ep_cnt);

	for (i = 0; i < (int) globals->ep_cnt; i++) {
		del->subnet[i] = htonl(globals->eps[i]->subnet);
		debug(RDB_PEER, "%s: deleting subnet %u (0x%x)", __func__,
			globals->eps[i]->subnet, globals->eps[i]->subnet);
	}

	for (i = 0; i < (int) globals->ep_cnt; i++) {
		int j = 0, waiting = 0;
		ccir_ep_t *ep = globals->eps[i];

		waiting = (int) ep->peer_cnt;

		for (j = 0; j < waiting; j++) {
			ccir_peer_t *peer = ep->peers[j];
			cci_connection_t *c = peer->c;

			if (c) {
				ret = cci_send(c, buf, len,
						CCIR_SET_PEER_CTX(peer), 0);
				if (ret) {
					debug(RDB_PEER, "%s: sending del to %s failed with %s",
						__func__, peer->uri, cci_strerror(ep->e, ret));
					/* clean up now */
					waiting--;
					cci_disconnect(c);
					peer->state = CCIR_PEER_CLOSING;
				}
			} else {
				debug(RDB_PEER, "%s: peer %s has already disconnected",
					__func__, peer->uri);
				waiting--;
			}
		}

		while (waiting) {
			cci_event_t *event = NULL;

			ret = cci_get_event(ep->e, &event);
			if (ret == CCI_SUCCESS) {
				int is_peer = 0;
				cci_connection_t *c = NULL;
				ccir_peer_hdr_t *h = NULL;

				switch (event->type) {
				default:
					break;
				case CCI_EVENT_SEND:
					c = event->send.connection;
					if (event->send.context == c->context) {
						waiting--;
						cci_disconnect(c);
					}
					break;
				case CCI_EVENT_RECV:
					c = event->recv.connection;
					h = (void*) event->recv.ptr;
					h->net = ntohl(h->net);
					is_peer = CCIR_IS_PEER_HDR(h->generic.type);
					if (is_peer) {
						ccir_peer_hdr_type_t t =
							CCIR_PEER_HDR_TYPE(h->generic.type);

						if (t == CCIR_PEER_MSG_DEL) {
							void *ctx = CCIR_CTX(c->context);
							ccir_peer_t *peer = (ccir_peer_t*)ctx;
							uint32_t *id = (uint32_t*)hdr->del.data;

							handle_peer_recv_del(globals, ep,
									peer, event);

							waiting--;
							cci_disconnect(c);
							if (globals->verbose) {
								debug(RDB_PEER,
									"%s: EP %p: "
									"router 0x%x "
									"leaving",
									__func__,
									(void*)ep,
									ntohl(*id));
							}
						}
					}
					break;
				}
				cci_return_event(event);
			}
		}
	}
	free(buf);
	return;
}

static int
connect_peers(ccir_globals_t *globals)
{
	int ret = 0;
	uint32_t i = 0;
	struct timeval t = { CCIR_CONNECT_TIMEOUT, 0 }, now = { 0, 0 };

	ret = gettimeofday(&now, NULL);
	if (ret) {
		ret = errno;
		goto out;
	}

	for (i = 0; i < globals->ep_cnt; i++) {
		ccir_ep_t *ep = globals->eps[i];
		ccir_peer_t **p = NULL;

		if (!ep->need_connect)
			continue;

		for (p = ep->peers; *p; p++) {
			ccir_peer_t *peer = *p;
			ccir_peer_hdr_t *hdr = NULL;
			char buffer[256 + sizeof(*hdr)];
			uint32_t len = strlen(ep->uri);

			if (peer->connecting)
				continue;

			hdr = (void*)buffer;

			assert(len < 256); /* NOTE: magic number
					      len must fit in a uint8_t */
			assert((len + sizeof(hdr->connect_size)) <= sizeof(buffer));

			if (peer->state != CCIR_PEER_INIT ||
				peer->next_attempt > now.tv_sec)
				continue;

			if (globals->verbose)
				debug(RDB_PEER, "%s: ep %s to peer %s",
					__func__, ep->uri, peer->uri);

			peer->state = CCIR_PEER_CONNECTING;
			peer->attempts++;
			peer->connecting++;

			ccir_pack_connect(hdr, ep->uri);

			len += sizeof(hdr->connect_size);

			ret = cci_connect(ep->e, peer->uri,
					buffer,
					len,
					CCI_CONN_ATTR_RO,
					CCIR_SET_PEER_CTX(peer),
					0, &t);
			if (ret) {
				peer->connecting--;
				if (!peer->accepting)
					peer->state = CCIR_PEER_INIT;

				/* Set the next attempt to now + 2^N
				 * where N is the number of attempts.
				 * This provides an exponential backoff.
				 */
				peer->next_attempt = now.tv_sec +
					(1 << peer->attempts);
			}
		}
	}
out:
	return ret;
}

static void
handle_peer_connect_request(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int ret = 0, found = 0;
	uint32_t i = 0;
	char uri[256];
	const ccir_peer_hdr_t *hdr = (void*)event->request.data_ptr; /* already host order */

	memset(uri, 0, 256);
	memcpy(uri, hdr->connect.data, hdr->connect.len);

	if (event->request.attribute != CCI_CONN_ATTR_RO) {
		debug(RDB_INFO, "%s: received request with connection "
				"attribute %d from %s", __func__,
				event->request.attribute, uri);
		goto out;
	}

	if (globals->verbose)
		debug(RDB_PEER, "%s: received connection request "
				"from %s", __func__, uri);

	/* Find matching peer */
	for (i = 0; i < ep->peer_cnt; i++) {
		ccir_peer_t *peer = ep->peers[i];

		if (!strcmp(uri, peer->uri)) {
			int accept = strcmp(peer->uri, ep->uri);
			if (accept == 0) {
				debug(RDB_PEER, "%s: connect request from "
						"this endpoint (%s)?", __func__,
						ep->uri);
				accept = 1;
			}

			/* accept if their URI is less than ours */
			accept = accept < 0;

			found++;

			if (peer->state == CCIR_PEER_CONNECTING && peer->connecting) {
				debug(RDB_PEER, "%s: connection race detected with "
						"%s", __func__, peer->uri);
			}

			if (accept) {
				/* Accept the connection request */
				peer->state = CCIR_PEER_CONNECTING;
				peer->accepting++;
				assert(peer->accepting == 1);

				if (globals->verbose) {
					debug(RDB_PEER, "%s: accepting passive conn "
							"from %s", __func__,
							peer->uri);
				}
				ret = cci_accept(event, CCIR_SET_PEER_CTX(peer));
				if (ret) {
					debug(RDB_PEER, "%s: cci_accept() failed %s",
							__func__, cci_strerror(ep->e, ret));
				}
			} else {
				if (globals->verbose) {
					debug(RDB_PEER, "%s: rejecting passive conn "
							"from %s", __func__,
							peer->uri);
				}
				ret = cci_reject(event);
				if (ret) {
					debug(RDB_PEER, "%s: cci_reject() failed %s",
							__func__, cci_strerror(ep->e, ret));
				}
				if (!peer->connecting)
					peer->state = CCIR_PEER_INIT;
			}
		}
		else {
			debug(RDB_PEER, "%s: uri \"%s\" does not match "
					"peer->uri \"%s\"", __func__, uri, peer->uri);
		}
	}

	if (!found) {
		debug(RDB_PEER, "%s: no matching endpoint for this request.\n"
				"\tFrom ep %s for ep %s.", __func__,
				uri, ep->uri);
		ret = cci_reject(event);
		if (ret) {
			debug(RDB_PEER, "%s: cci_reject() failed %s",
					__func__, cci_strerror(ep->e, ret));
		}
	}
out:
	return;
}

/* Handle a connection request event.
 *
 * Need to determine if the event if for router-to-router use or
 * for a client.
 *
 * CCI connect_request event includes:
 *     type
 *     data_len
 *     data_ptr
 *     attribute
 */
static void
handle_connect_request(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	ccir_peer_hdr_t *hdr = (void*)event->request.data_ptr;
	int is_peer = 0;

	hdr->net = ntohl(hdr->net);

	is_peer = CCIR_IS_PEER_HDR(hdr->connect.type);

	if (is_peer) {
		handle_peer_connect_request(globals, ep, event);
	} else {
		assert(0);
	}

	return;
}

static void
send_rir(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer)
{
	int len = 0, ret = 0;
	ccir_peer_hdr_t *hdr = NULL;
	ccir_rir_data_t *rir = NULL;
	char buf[sizeof(hdr->rir_size) + sizeof(*rir)];

	hdr = (ccir_peer_hdr_t *)buf;
	rir = (ccir_rir_data_t *)hdr->rir.data;
	len = sizeof(hdr->rir_size) + sizeof(*rir);

	assert(len < (int) peer->c->max_send_size);
	assert(len == (int) sizeof(buf));

	memset(buf, 0, sizeof(buf));
	ccir_pack_rir(hdr, 1);
	rir->instance = ccir_htonll(globals->instance);
	rir->router = htonl(globals->id);
	rir->as = htonl(ep->as);
	rir->subnet[0].id = htonl(ep->subnet);
	rir->subnet[0].rate = htons(ep->e->device->rate / 1000000000);
	if (!rir->subnet[0].rate) rir->subnet[0].rate = htons(1);

	debug(RDB_PEER, "%s: EP %p: sending RIR to %s len %u (header 0x%02x%02x%02x%02x)",
			__func__, (void*)ep, peer->uri, len,
			hdr->rir.type, hdr->rir.count, hdr->rir.a[0], hdr->rir.a[1]);
	debug(RDB_PEER, "\t%"PRIx64" %08x %08x %08x %04x %02x",
			ccir_ntohll(rir->instance), ntohl(rir->router),
			ntohl(rir->as), ntohl(rir->subnet[0].id),
			ntohs(rir->subnet[0].rate), rir->subnet[0].caps);
	ret = cci_send(peer->c, buf, len, NULL, 0);
	if (ret)
		debug(RDB_PEER, "%s: send RIR to %s "
			"failed with %s", __func__,
			peer->uri, cci_strerror(ep->e, ret));

	return;
}

/* For each peer on each endpoint, send all endpoint RIRs */
static void
send_all_rir(ccir_globals_t *globals)
{
	ccir_ep_t **e = NULL;

	for (e = globals->eps; *e != NULL; e++) {
		ccir_peer_t **p = NULL;

		for (p = (*e)->peers; *p != NULL; p++) {
			ccir_ep_t **ee = NULL;

			for (ee = globals->eps; *ee != NULL; ee++) {
				if ((*p)->c)
					send_rir(globals, *ee, *p);
			}
		}
	}
}

/* Handle an accept event.
 *
 * Need to determine if the event if for router-to-router use or
 * for a client.
 *
 * CCI connect_request event includes:
 *     type
 *     status
 *     context
 *     connection
 */
static void
handle_accept(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	uint32_t peer_accept = CCIR_IS_PEER_CTX(event->accept.context);
	void *ctx = CCIR_CTX(event->accept.context);

	if (peer_accept) {
		ccir_peer_t *peer = ctx;

		peer->accepting--;
		assert(peer->accepting == 0);
		if (event->accept.status == CCI_SUCCESS) {
			ccir_ep_t **e = NULL;

			peer->state = CCIR_PEER_CONNECTED;
#if 0
			/* TODO disconnect? */
			if (peer->c) {
				cci_disconnect(peer->c);
				peer->c = NULL;
			}
			assert(peer->c == NULL);
#endif
			peer->c = event->accept.connection;
			ep->need_connect--;

			if (globals->verbose)
				debug(RDB_PEER, "%s: accepted %s on endpoint %s (%s) "
						"(c=%p)",
						__func__, peer->uri, ep->uri,
						ccir_peer_state_str(peer->state),
						(void*)peer->c);
			/* TODO exchange routing table */
			for (e = globals->eps; *e != NULL; e++)
				send_rir(globals, *e, peer);
		} else {
			debug(RDB_PEER, "%s: accept event for %s returned %s",
				__func__, peer->uri,
				cci_strerror(ep->e, event->accept.status));
			if (!peer->connecting)
				peer->state = CCIR_PEER_INIT;
		}
	} else {
		/* e2e accept */
		assert(0);
	}

	return;
}

/* Handle a accept completion event.
 *
 * Need to determine if the event if for router-to-router use or
 * for a client.
 */
static void
handle_connect(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	uint32_t peer_connect = CCIR_IS_PEER_CTX(event->connect.context);
	void *ctx = CCIR_CTX(event->connect.context);

	if (peer_connect) {
		ccir_peer_t *peer = ctx;

		peer->connecting--;

		if (event->connect.status == CCI_SUCCESS) {
			ccir_ep_t **e = NULL;

			assert(peer->c == NULL);
			peer->c = event->connect.connection;
			peer->state = CCIR_PEER_CONNECTED;

			ep->need_connect--;

			if (globals->verbose)
				debug(RDB_PEER, "%s: connected to %s on endpoint %s (%s) "
						"(c=%p)",
						__func__, peer->uri, ep->uri,
						ccir_peer_state_str(peer->state),
						(void*)peer->c);

			/* TODO exchange routing table */
			/* send our rir */
			for (e = globals->eps; *e != NULL; e++)
				send_rir(globals, *e, peer);
			/* send forwarded rir */
		} else {
			struct timeval now = { 0, 0 };

			if (!peer->accepting)
				peer->state = CCIR_PEER_INIT;

			if (peer->state != CCIR_PEER_CONNECTED) {
				gettimeofday(&now, NULL);
				/* Set the next attempt to now + 2^N
				 * where N is the number of attempts.
				 * This provides an exponential backoff.
				 */
				peer->next_attempt = now.tv_sec + (1 << peer->attempts);

				if (event->connect.status == CCI_ECONNREFUSED) {
					debug(RDB_PEER, "%s: peer %s refused a connection "
							"from endpoint %s", __func__,
							peer->uri, ep->uri);
				}
			}
		}
	} else {
		/* Connect completed for routed connection. Wait for end-to-end
		 * ACCEPT or REJECT.
		 */
		/* TODO add connection to routed connection struct */
	}

	return;
}

static int
compare_u32(const void *pa, const void *pb)
{
	if (*(uint32_t *) pa < *(uint32_t *) pb)
		return -1;
	if (*(uint32_t *) pa > *(uint32_t *) pb)
		return 1;

	return 0; /* match */
}

static int
compare_u64(const void *pa, const void *pb)
{
	if (!pa) return -1;
	if (!pb) return 1;

	if (*(uint64_t *) pa < *(uint64_t *) pb)
		return -1;
	if (*(uint64_t *) pa > *(uint64_t *) pb)
		return 1;

	return 0; /* match */
}

static inline void
print_router(ccir_globals_t *globals, ccir_router_t *r)
{
	int i = 0;
	uint32_t lo = 0, hi = 0;

	debug(RDB_TOPO, "    router 0x%x count %u instance 0x%"PRIx64" peer %s",
			r->id, r->count, r->instance,
			r->peer ? r->peer->uri : "no");

	if (r->count)
		debug(RDB_TOPO, "        %u subnets:", r->count);
	for (i = 0; i < (int) r->count; i++)
		debug(RDB_TOPO, "            subnet 0x%x", r->subnets[i]);

	if (r->pair_count) {
		debug(RDB_TOPO, "        %u pairs:", r->pair_count);
		for (i = 0; i < (int) r->pair_count; i++) {
			parse_pair_id(r->pairs[i], &lo, &hi);
			debug(RDB_TOPO, "            pair 0x%x_%x", lo, hi);
		}
	}

	return;
}

static void
print_routers(ccir_globals_t *globals)
{
	uint32_t i = 0;

	for (i = 0; i < globals->topo->num_routers; i++)
		print_router(globals, globals->topo->routers[i]);

	return;
}

static inline void
print_subnet(ccir_globals_t *globals, ccir_subnet_t *s)
{
	int i = 0;

	debug(RDB_TOPO, "    subnet 0x%x count %u rate %hu",
			s->id, s->count, s->rate);

	for (i = 0; i < (int) s->count; i++)
		debug(RDB_TOPO, "        router 0x%x", s->routers[i]);

	return;
}

static void
print_subnets(ccir_globals_t *globals)
{
	uint32_t i = 0;

	for (i = 0; i < globals->topo->num_subnets; i++)
		print_subnet(globals, globals->topo->subnets[i]);
}

static inline void
print_pair(ccir_globals_t *globals, ccir_pair_t *p)
{
	int i = 0;
	uint32_t lo = 0, hi = 0;

	parse_pair_id(p->id, &lo, &hi);

	debug(RDB_TOPO, "    pair 0x%x_%x count %u", lo, hi, p->count);

	for (i = 0; i < (int) p->count; i++)
		debug(RDB_TOPO, "        router 0x%x", p->routers[i]);

	return;
}

static void
print_pair_tree(const void *nodep, const VISIT which, const int depth)
{
	uint32_t *id = *(uint32_t **) nodep;
	ccir_pair_t *pair = container_of(id, ccir_pair_t, id);
	ccir_globals_t *globals = pair->g;

	switch (which) {
	case preorder:
		break;
	case postorder:
		print_pair(globals, pair);
		break;
	case endorder:
		break;
	case leaf:
		print_pair(globals, pair);
		break;
	}
}

static void
add_router_to_subnet(ccir_globals_t *globals, ccir_subnet_t *subnet, uint32_t router_id)
{
	int i = 0;
	uint32_t *r = NULL;

	r = bsearch(&router_id, subnet->routers, subnet->count, sizeof(*r), compare_u32);
	if (r) {
		assert(*r == router_id);
		debug(RDB_TOPO, "%s: subnet 0x%x already has router 0x%x",
			__func__, subnet->id, router_id);
	} else {
		debug(RDB_TOPO, "%s: subnet 0x%x adding router 0x%x",
			__func__, subnet->id, router_id);

		subnet->count++;
		subnet->routers = realloc(subnet->routers, sizeof(*r) * subnet->count);
		subnet->routers[subnet->count - 1] = router_id;

		qsort(subnet->routers, subnet->count, sizeof(*r), compare_u32);
	}

	if (globals->verbose) {
		debug(RDB_TOPO, "%s: ** subnet 0x%x has routers:", __func__, subnet->id);
		for (i = 0; i < (int) subnet->count; i++)
			debug(RDB_TOPO, "%s: **** router 0x%x", __func__, subnet->routers[i]);
	}

	return;
}

static int
compare_subnets(const void *sp1, const void *sp2)
{
	ccir_subnet_t *s1 = *((ccir_subnet_t **)sp1);
	ccir_subnet_t *s2 = *((ccir_subnet_t **)sp2);

	return (int)(s1->id) - (int)(s2->id);
}

static int
add_subnet_to_topo(ccir_globals_t *globals, ccir_ep_t *ep, uint32_t subnet_id,
		uint32_t subnet_rate, uint32_t router_id, ccir_subnet_t **sn, int *new)
{
	int ret = 0;
	ccir_subnet_t **sp = NULL, *subnet = NULL, *key = NULL, tmp;
	ccir_topo_t *topo = globals->topo;

	tmp.id = subnet_id;
	key = &tmp;

	sp = bsearch(&key, topo->subnets, topo->num_subnets, sizeof(subnet),
			compare_subnets);
	if (sp)
		subnet = *sp;

	if (subnet) {
		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: adding ref to subnet %u "
				"(count was %u)", __func__, (void*)ep,
				subnet->id, subnet->count);
		}
		subnet->count++;
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
		subnet->g = globals;
		subnet->rate = subnet_rate;

		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: adding subnet 0x%x",
				__func__, (void*)ep, subnet->id);
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

	add_router_to_subnet(globals, subnet, router_id);

	if (globals->verbose)
		print_subnets(globals);

	*sn = subnet;
out:
	return ret;
}

static void
add_subnet_to_router(ccir_globals_t *globals, ccir_router_t *router, uint32_t subnet_id)
{
	int i = 0;
	uint32_t *s = NULL;

	s = bsearch(&subnet_id, router->subnets, router->count, sizeof(*s), compare_u32);
	if (s) {
		assert(*s == subnet_id);
		debug(RDB_TOPO, "%s: router 0x%x already has subnet 0x%x",
			__func__, router->id, subnet_id);
	} else {
		debug(RDB_TOPO, "%s: router 0x%x adding subnet 0x%x",
			__func__, router->id, subnet_id);

		router->count++;
		router->subnets = realloc(router->subnets, sizeof(*s) * router->count);
		router->subnets[router->count - 1] = subnet_id;

		qsort(router->subnets, router->count, sizeof(*s), compare_u32);
	}

	if (globals->verbose) {
		print_router(globals, router);
		debug(RDB_TOPO, "%s: ** router 0x%x has subnets:", __func__, router->id);
		for (i = 0; i < (int) router->count; i++)
			debug(RDB_TOPO, "%s: **** subnet 0x%x", __func__, router->subnets[i]);
	}
	return;
}

static int
compare_routers(const void *rp1, const void *rp2)
{
	ccir_router_t *r1 = *((ccir_router_t **)rp1);
	ccir_router_t *r2 = *((ccir_router_t **)rp2);

	return (int)(r1->id) - (int)(r2->id);
}

static int
add_router_to_topo(ccir_globals_t *globals, ccir_ep_t *ep, uint32_t router_id,
		uint64_t router_instance, uint32_t subnet_id, ccir_peer_t *peer,
		ccir_router_t **r, int *new)
{
	int ret = 0;
	ccir_topo_t *topo = globals->topo;
	ccir_router_t *router = NULL, **rp = NULL, tmp, *key = &tmp;

	tmp.id = router_id;

	rp = bsearch(&key, topo->routers, topo->num_routers, sizeof(router), compare_routers);
	if (rp)
		router = *rp;

	if (router) {
		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: adding ref to router 0x%x "
				"(count was %u)", __func__, (void*)ep,
				router->id, router->count);
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
			assert(router);
			ret = ENOMEM;
		}
		router->id = router_id;
		router->count = 0;
		router->instance = router_instance;
		router->g = globals;

		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: adding router 0x%x",
				__func__, (void*)ep, router->id);
		}

		topo->num_routers++;
		routers = realloc(topo->routers, topo->num_routers * sizeof(router));
		if (!routers) {
			topo->num_routers--;
			free(router);
			ret = ENOMEM;
			goto out;
		}
		topo->routers = routers;
		topo->routers[topo->num_routers - 1] = router;

		qsort(topo->routers, topo->num_routers, sizeof(router), compare_routers);

		*new = 1;
	}

	add_subnet_to_router(globals, router, subnet_id);

	if (globals->verbose)
		print_routers(globals);

	*r = router;
out:
	return ret;
}

static int
delete_router_from_subnet(ccir_globals_t *globals, ccir_ep_t *ep, ccir_subnet_t *subnet,
		uint32_t router_id, uint64_t instance)
{
	int ret = 0;
	uint32_t *r = NULL;

	r = bsearch(&router_id, subnet->routers, subnet->count, sizeof(r), compare_u32);
	if (r) {
		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: decref subnet %u (0x%x)"
				"(count was %u)", __func__, (void*)ep,
				subnet->id, subnet->id, subnet->count);
		}
		subnet->count--;
		*r = subnet->routers[subnet->count];
		subnet->routers[subnet->count] = 0;
		qsort(subnet->routers, subnet->count, sizeof(*r), compare_u32);
		subnet->routers = realloc(subnet->routers, subnet->count * sizeof(r));
	}

	if (globals->verbose) {
		int i = 0;

		if (subnet->count) {
			debug(RDB_TOPO, "%s: ** subnet 0x%x has routers:", __func__,
					subnet->id);
			for (i = 0; i < (int) subnet->count; i++)
				debug(RDB_TOPO, "%s: **** router 0x%x", __func__,
						subnet->routers[i]);
		}
	}

	return ret;
}

static int
compare_routes(const void *rp1, const void *rp2)
{
	ccir_route_t *r1 = *((ccir_route_t **)rp1);
	ccir_route_t *r2 = *((ccir_route_t **)rp2);

	/* if r1 > r2, return 1
	 * else if r1 < r2, return -1
	 * else return 0
	 */
	return (r1->id > r2->id) ? 1 : (r1->id < r2->id) ? -1 : 0;
}

static inline uint32_t
score_path_bw(ccir_globals_t *globals, ccir_path_t *path)
{
	uint32_t i = 0, score = 0;

	for (i = 0; i < path->count; i++) {
		uint32_t subnet_id = path->subnets[i];
		ccir_subnet_t **sp = NULL, *subnet = NULL, *key = NULL, tmp;

		tmp.id = subnet_id;
		key = &tmp;

		sp = bsearch(&key, globals->topo->subnets,
				globals->topo->num_subnets, sizeof(subnet),
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
score_path_hop(ccir_globals_t *globals, ccir_path_t *path)
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
valid_path(ccir_globals_t *globals, ccir_path_t *path)
{
	int ret = 0;
	uint32_t i = 0, a = 0, b = 0;
	uint64_t ab = 0;
	void *node = NULL;

	if (globals->verbose) {
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
				if (globals->verbose) {
					debug(RDB_TOPO, "%s: path loops on subnet 0x%x",
							__func__, b);
				}

				ret = EINVAL;
				goto out;
			}
		}

		ab = pack_pair_id(a, b);

		node = tfind(&ab, &(globals->topo->pairs), compare_u64);
		if (!node) {
			if (globals->verbose)
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
score_path(ccir_globals_t *globals, ccir_path_t *path)
{
	int ret = 0;
	uint32_t score = 0;

	ret = valid_path(globals, path);
	if (ret) return CCIR_INVALID_PATH;

	switch (globals->topo->metric) {
		case CCIR_METRIC_BW:
			score = score_path_bw(globals, path);
			break;
		case CCIR_METRIC_HOP:
			score = score_path_hop(globals, path);
			break;
		default:
			debug(RDB_TOPO, "%s: unkown metric %d", __func__,
					globals->topo->metric);
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

	return p1->score - p2->score;
}

/* Are the two paths identical?
 *
 * Return 0 if true, else -1
 */
static inline int
identical_paths(ccir_globals_t *globals, ccir_path_t *a, ccir_path_t *b)
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

static void
print_route(ccir_globals_t *globals, ccir_route_t *route)
{
	uint32_t i = 0, lo = 0, hi = 0;

	parse_pair_id(route->id, &lo, &hi);
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

static inline void
print_routes(ccir_globals_t *globals)
{
	uint32_t i = 0;

	debug(RDB_TOPO, "%s:", __func__);

	for (i = 0; i < globals->topo->num_routes; i++)
		print_route(globals, globals->topo->routes[i]);

	return;
}

static inline int
add_route(ccir_globals_t *globals, ccir_route_t *route)
{
	int ret = 0;
	ccir_topo_t *topo = globals->topo;
	ccir_route_t **routes = NULL;

	topo->num_routes++;
	routes = realloc(topo->routes, sizeof(route) * topo->num_routes);
	if (!routes) {
		uint32_t lo = 0, hi = 0;
		parse_pair_id(route->id, &lo, &hi);
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
del_route(ccir_globals_t *globals, ccir_route_t *route)
{
	ccir_topo_t *topo = globals->topo;
	ccir_route_t **routes = NULL;

	if (globals->verbose) {
		uint32_t lo = 0, hi = 0;

		parse_pair_id(route->id, &lo, &hi);
		debug(RDB_TOPO, "%s: removing route 0x%x_%x", __func__, lo, hi);
	}

	/* Move route to end of array */
	route->id = ~((uint64_t)0);
	qsort(topo->routes, topo->num_routes, sizeof(route), compare_routes);

	topo->num_routes--;
	routes = realloc(topo->routes, sizeof(route) * topo->num_routes);
	if (routes)
		topo->routes = routes;

	qsort(topo->routes, topo->num_routes, sizeof(route), compare_routes);

	return;
}

/* Given new pair AB and route BN, add route AN and calculate new paths
 * AN for each path in BN. */
static inline void
prepend_pair(ccir_globals_t *globals, ccir_pair_t *pair, ccir_route_t *bn)
{
	int reverse = 0;
	uint32_t a = 0, b = 0, bn_lo = 0, bn_hi = 0;
	uint64_t route_id = 0, ab = pair->id;
	ccir_route_t **rp = NULL, *an = NULL, *key = NULL, tmp;
	ccir_topo_t *topo = globals->topo;

	parse_pair_id(pair->id, &a, &b);

	/* If the route is the same as the pair, we have already handled it */
	if (pair->id == bn->id) {
		if (globals->verbose) {
			debug(RDB_TOPO, "%s: ignoring identical route 0x%x_%x",
					__func__, a, b);
		}
		return;
	}

	parse_pair_id(bn->id, &bn_lo, &bn_hi);

	/* We only want BN... */
	if (bn_lo != b && bn_lo != a) {
		if (globals->verbose) {
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
		ab = pack_pair_id(a, b);
	}

	if (a > bn_hi)
		reverse = 1;

	/* Route id for AN... */
	route_id = pack_pair_id(a, bn_hi);
	tmp.id = route_id;
	key = &tmp;

	rp = bsearch(&key, topo->routes, topo->num_routes, sizeof(an),
			compare_routes);
	if (rp)
		an = *rp;

	if (!an) {
		int loop_found = 0, ret = 0;
		uint32_t i = 0;

		/* Route AN does not exist, create it and copy the paths
		 * from BN and prepend pair AB. */

		if (globals->verbose) {
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
		an->g = globals;
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

			pan->score = score_path(globals, pan);
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
			ret = add_route(globals, an);
		} else {
			free(an->paths);
			free(an);
		}
	} else {
		/* The route AN exists, compare its paths to route BN's paths.
		 * If any are missing (ignoring leading AB pair),
		 * add to AN's paths. */

		if (globals->verbose) {
			debug(RDB_TOPO, "%s: route 0x%x_%x exists",
					__func__, a, bn_hi);
		}
		/* TODO */
	}

	print_routes(globals);

	return;
}

/* Given new pair AB and route NA, add route NB and calculate new paths
 * NB for each path in NA. */
static inline void
append_pair(ccir_globals_t *globals, ccir_pair_t *pair, ccir_route_t *na)
{
	int reverse = 0;
	int ret = 0;
	uint32_t a = 0, b = 0, na_lo = 0, na_hi = 0;
	uint64_t route_id = 0, ab = pair->id;
	ccir_route_t *nb = NULL, **rp = NULL, *key = NULL, tmp;
	ccir_topo_t *topo = globals->topo;

	parse_pair_id(pair->id, &a, &b);

	/* If the route is the same as the pair, we have already handled it */
	if (pair->id == na->id) {
		if (globals->verbose) {
			debug(RDB_TOPO, "%s: ignoring identical route 0x%x_%x",
					__func__, a, b);
		}
		return;
	}

	parse_pair_id(na->id, &na_lo, &na_hi);

	/* We only want NB... */
	if (na_hi != a && na_hi != b) {
		if (globals->verbose) {
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
		ab = pack_pair_id(a, b);
	}

	if (na_lo > b)
		reverse = 1;

	/* Route id for NB... */
	route_id = pack_pair_id(na_lo, b);
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

		if (globals->verbose) {
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
		nb->g = globals;
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
			pnb->score = score_path(globals, pnb);
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
			ret = add_route(globals, nb);
		} else {
			free(nb->paths);
			free(nb);
		}
	} else {
		/* The route NB exists, compare its paths to route NA's paths.
		 * If any are missing (ignoring leading AB pair),
		 * add to NB's paths. */

		if (globals->verbose) {
			debug(RDB_TOPO, "%s: route 0x%x_%x exists",
					__func__, na_lo, b);
		}
		/* TODO */
	}

	print_routes(globals);

	return;
}

/* Given new pair AB and routes MA and BN, add route MN and calculate new paths
 * MN for each path in MA + AB + BN. */
static void
join_ma_ab_bn(ccir_globals_t *globals, uint64_t pair_id,
		ccir_route_t *ma, ccir_route_t *bn)
{
	int ret = 0;
	uint32_t pair_lo = 0, pair_hi = 0, ma_lo = 0, ma_hi = 0, bn_lo = 0, bn_hi = 0;
	uint32_t i = 0;
	uint64_t mn_id = 0;
	ccir_route_t *mn = NULL, **rp = NULL, *key = NULL, tmp;
	ccir_topo_t *topo = globals->topo;
	ccir_path_t *pma = NULL, *pbn = NULL, *pmn = NULL;

	parse_pair_id(pair_id, &pair_lo, &pair_hi);
	parse_pair_id(ma->id, &ma_lo, &ma_hi);
	parse_pair_id(bn->id, &bn_lo, &bn_hi);

	if (globals->verbose) {
		debug(RDB_TOPO, "%s: check if route MA (0x%x_%x) + AB (0x%x_%x) + "
				"BN (0x%x_%x) is joinable", __func__, ma_lo, ma_hi,
				pair_lo, pair_hi, bn_lo, bn_hi);
	}

	if (ma_hi != pair_lo) {
		if (globals->verbose) {
			debug(RDB_TOPO, "%s: MA route 0x%x_%x does not connect to pair "
				"0x%x_%x", __func__, ma_lo, ma_hi, pair_lo, pair_hi);
		}
		return;
	} else if (pair_hi != bn_lo) {
		if (globals->verbose) {
			debug(RDB_TOPO, "%s: NB route 0x%x_%x does not connect to "
				"pair 0x%x_%x", __func__, pair_lo, pair_hi, bn_lo, bn_hi);
		}
		return;
	}

	if (globals->verbose) {
		debug(RDB_TOPO, "%s: checking for route 0x%x_%x", __func__,
			ma_lo, bn_hi);
	}

	mn_id = pack_pair_id(ma_lo, bn_hi);
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
		ret = add_route(globals, mn);
		if (ret) {
			free(mn);
			return;
		}

		if (globals->verbose) {
			debug(RDB_TOPO, "%s: joining route 0x%x_%x to 0x%x_%x to 0x%x_%x "
				"to create new route 0x%x_%x", __func__, ma_lo, ma_hi,
				pair_lo, pair_hi, bn_lo, bn_hi, ma_lo, bn_hi);
		}
	} else {
		if (globals->verbose)
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
			pmn->score = score_path(globals, pmn);
			if (pmn->score == CCIR_INVALID_PATH) {
				if (globals->verbose) {
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

					ret = identical_paths(globals, pmn, pk);
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
					if (globals->verbose) {
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
		del_route(globals, mn);
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
add_routes(ccir_globals_t *globals, ccir_pair_t *pair)
{
	int ret = 0, new = 0, found = 0;
	uint32_t lo = 0, hi = 0, i = 0;
	ccir_route_t *route = NULL, **rp = NULL, *key = NULL, tmp;
	ccir_path_t *path = NULL;
	ccir_topo_t *topo = globals->topo;

	parse_pair_id(pair->id, &lo, &hi);

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
	path->score = score_path(globals, path);

	tmp.id = pair->id;
	key = &tmp;

	/* Does route exist? Does it have this pair? */
	rp = bsearch(&key, topo->routes, topo->num_routes, sizeof(route),
			compare_routes);

	if (rp)
		route = *rp;

	if (route) {
		for (i = 0; i < route->count; i++) {
			ret = identical_paths(globals, path, route->paths[i]);
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
		route->g = globals;
		new = 1;

		/* insert in tree */
		ret = add_route(globals, route);
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
		prepend_pair(globals, pair, route);

		/* add routes for *A + AB */
		append_pair(globals, pair, route);

		for (j = 0; j < topo->num_routes; j++) {
			ccir_route_t *route2 = topo->routes[j];

			if (i == j)
				continue;

			/* join routes *A + AB + B* */
			join_ma_ab_bn(globals, pair->id, route, route2);
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

static int
add_pairs(ccir_globals_t *globals, ccir_subnet_t *subnet, ccir_router_t *router)
{
	int ret = 0, i = 0;

	/* for each subnet, check pair, add if needed, add router to pair */
	for (i = 0; i < (int) router->count; i++) {
		uint32_t lo = 0, hi = 0;
		uint32_t old = router->subnets[i], *r = NULL;
		void *node = NULL;
		uint64_t pair_id = pack_pair_id(old, subnet->id);
		ccir_pair_t *pair = NULL;

		if (old == subnet->id)
			continue;

		/* get subnets in the low-high order */
		if (globals->verbose)
			parse_pair_id(pair_id, &lo, &hi);

		/* Find the pair or create it */
		node = tfind(&pair_id, &(globals->topo->pairs), compare_u64);
		if (node) {
			uint64_t *id = *((uint64_t**)node);
			pair = container_of(id, ccir_pair_t, id);
		} else {
			pair = calloc(1, sizeof(*pair));

			if (!pair) {
				/* TODO */
				assert(pair);
			}
			pair->id = pair_id;
			pair->count = 0;
			pair->g = globals;

			node = tsearch(&pair->id, &(globals->topo->pairs), compare_u64);
			if (!node) {
				free(pair);
				/* TODO */
				assert(node);
			}
			globals->topo->num_pairs++;
			if (globals->verbose) {
				debug(RDB_TOPO, "*** added pair 0x%x_%x", lo, hi);
			}

			/* calculate new routes for pair */
			ret = add_routes(globals, pair);
		}

		/* add router to pair */
		r = bsearch(&router->id, pair->routers, pair->count, sizeof(*r), compare_u32);
		if (r) {
			if (globals->verbose) {
				debug(RDB_TOPO, "%s: pair 0x%x_%x already has router 0x%x",
					__func__, lo, hi, router->id);
			}
		} else {
			if (globals->verbose) {
				debug(RDB_TOPO, "%s: pair 0x%x_%x adding router 0x%x",
					__func__, lo, hi, router->id);
			}

			pair->count++;
			pair->routers = realloc(pair->routers, sizeof(*r) * pair->count);
			pair->routers[pair->count - 1] = router->id;

			qsort(pair->routers, pair->count, sizeof(*r), compare_u32);
		}
	}

	if (globals->verbose)
		twalk(globals->topo->pairs, print_pair_tree);

	return ret;
}

static void
handle_peer_recv_rir(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer,
		cci_event_t *event)
{
	int ret = 0, new_router = 0, new_subnet = 0;
	uint32_t i = 0;
	ccir_peer_hdr_t *hdr = (ccir_peer_hdr_t*)event->recv.ptr; /* in host order */
	ccir_rir_data_t *rir = (ccir_rir_data_t*)hdr->rir.data;
	ccir_router_t *router = NULL;
	ccir_subnet_t *subnet = NULL;

	rir->instance = ccir_ntohll(rir->instance);
	rir->router = ntohl(rir->router);
	rir->as = ntohl(rir->as);
	rir->subnet[0].id = ntohl(rir->subnet[0].id);
	rir->subnet[0].rate = ntohs(rir->subnet[0].rate);

	if (globals->verbose) {
		debug(RDB_PEER, "%s: EP %p: received RIR from %s:",
				__func__, (void*)ep, peer->uri);
		debug(RDB_PEER, "%s: EP %p:      instance = %"PRIu64" (0x%"PRIx64")",
				__func__, (void*)ep, rir->instance, rir->instance);
		debug(RDB_PEER, "%s: EP %p:      router = %u (0x%x)",
				__func__, (void*)ep, rir->router, rir->router);
		debug(RDB_PEER, "%s: EP %p:      as     = %u (0x%x)",
				__func__, (void*)ep, rir->as, rir->as);
		debug(RDB_PEER, "%s: EP %p:      subnet = %u (0x%x)",
				__func__, (void*)ep, rir->subnet[0].id, rir->subnet[0].id);
		debug(RDB_PEER, "%s: EP %p:      rate   = %hu (0x%x)",
				__func__, (void*)ep, rir->subnet[0].rate, rir->subnet[0].rate);
	}

	if (peer->id == 0)
		peer->id = rir->router;

	ret = add_router_to_topo(globals, ep, rir->router, rir->instance, rir->subnet[0].id,
			peer, &router, &new_router);
	assert(ret == 0);

	ret = add_subnet_to_topo(globals, ep, rir->subnet[0].id, rir->subnet[0].rate,
			router->id, &subnet, &new_subnet);
	assert(ret == 0);

	if (peer->id == router->id && peer->subnet == subnet->id) {
		router->peer = peer;
		peer->router = router;
	} else {
		debug(RDB_TOPO, "peer->id 0x%x router->id 0x%x peer->subnet 0x%x "
				"subnet->id 0x%x", peer->id, router->id,
				peer->subnet, subnet->id);
	}

	ret = add_pairs(globals, subnet, router);
	assert(ret == 0);

	print_routes(globals);

	/* TODO forward to N-1 endpoints */
	/* forward_rir(globals, ep, peer, event->recv.ptr, event->recv.len); */
	/* for each peer P,
	 *   if P->id != router
	 *       send RIR
	 */

	hdr->net = htonl(hdr->net);
	rir->instance = ccir_htonll(rir->instance);
	rir->router = htonl(rir->router);
	rir->as = htonl(rir->as);
	rir->subnet[0].id = htonl(rir->subnet[0].id);
	rir->subnet[0].rate = htons(rir->subnet[0].rate);

	for (i = 0; i < globals->ep_cnt; i++) {
		ccir_ep_t *e = globals->eps[i];
		ccir_peer_t **p = NULL;

		for (p = e->peers; *p; p++) {
			if (e == ep) continue;
			if ((*p)->c && (*p)->id && (*p)->id != ntohl(rir->router)) {
				debug(RDB_PEER, "%s: EP %p: forwarding RIR to %s",
					__func__, (void*)p, (*p)->uri);
				cci_send((*p)->c, event->recv.ptr, event->recv.len, NULL, CCI_FLAG_SILENT);
			}
		}
	}

	return;
}

static void
handle_peer_recv_del(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer,
		cci_event_t *event)
{
	ccir_topo_t *topo = globals->topo;
	ccir_peer_hdr_t *hdr = (ccir_peer_hdr_t*) event->recv.ptr; /* in host order */
	ccir_del_data_t *del = (ccir_del_data_t *)hdr->del.data;
	ccir_subnet_t *subnet = NULL;
	ccir_router_t *router = NULL, **rp = NULL, tmp, *key = &tmp;
	int i = 0, bye = hdr->del.bye;

	del->instance = ccir_ntohll(del->instance);
	del->router = ntohl(del->router);

	if (globals->verbose) {
		debug(RDB_PEER, "%s: EP %p: peer %s (router 0x%x) (instance %"PRIu64") "
			"with %u endpoints leaving",  __func__, (void*)ep,
			peer->uri, del->router, del->instance, hdr->del.count);
		for (i = 0; i < hdr->del.count; i++)
			debug(RDB_PEER, "%s: EP %p: peer %s deleting subnet 0x%x",
				__func__, (void*)ep, peer->uri, ntohl(del->subnet[i]));
	}

	/* find subnets, if find router, remove router && decref subnet */
	for (i = 0; i < hdr->del.count; i++) {
		uint32_t subnet_id = 0;
		ccir_subnet_t **sp = NULL, *key = NULL, tmp;

		subnet_id = ntohl(del->subnet[i]);
		tmp.id = subnet_id;
		key = &tmp;

		sp = bsearch(&key, topo->subnets,
				topo->num_subnets, sizeof(subnet),
				compare_subnets);
		if (sp)
			subnet = *sp;

		if (subnet) {
			delete_router_from_subnet(globals, ep, subnet, del->router,
				del->instance);

			if (subnet->count == 0) {
				ccir_subnet_t **subnets = NULL;

				subnet->id = ~0;
				qsort(topo->subnets, topo->num_subnets,
						sizeof(subnet), compare_subnets);
				free(subnet->routers);
				free(subnet);
				topo->num_subnets--;
				subnets = realloc(topo->subnets,
							topo->num_subnets * sizeof(subnet));
				if (subnets)
					topo->subnets = subnets;

				debug(RDB_PEER, "%s: EP %p: deleted subnet id 0x%x",
					__func__, (void*)ep, subnet_id);
			}
		} else {
			debug(RDB_PEER, "%s: EP %p: DEL msg for subnet 0x%x router 0x%x "
				"and no matching subnet found", __func__, (void*)ep,
				subnet_id, del->router);
		}
	}

	tmp.id = del->router;

	rp = bsearch(&key, topo->routers, topo->num_routers, sizeof(router), compare_routers);

	if (rp)
		router = *rp;

	if (router) {
		router->count -= hdr->del.count;
		if (router->count == 0) {
			ccir_router_t **routers = NULL;

			router->id = ~0;
			qsort(topo->routers, topo->num_routers,
					sizeof(router), compare_routers);
			routers = realloc(topo->routers,
					topo->num_subnets * sizeof(router));
			if (routers)
				topo->routers = routers;

			free(router->subnets);
			free(router->pairs);
			free(router);
			debug(RDB_PEER, "%s: EP %p: deleted router id 0x%x",
				__func__, (void*)ep, del->router);
		}
	}

	if (bye) {
		void *ctx = CCIR_CTX(((cci_connection_t*)(event->recv.connection))->context);
		ccir_peer_t *peer = (ccir_peer_t*)ctx;

		cci_disconnect(peer->c);
		peer->c = NULL;
		peer->state = CCIR_PEER_CLOSED;
		ep->need_connect++;
	}

	if (globals->verbose) {
		print_subnets(globals);
	}

	return;
}

static void
handle_peer_recv(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer,
		cci_event_t *event)
{
	ccir_peer_hdr_t *hdr = (void*)event->recv.ptr; /* in net order */

	hdr->net = ntohl(hdr->net);

	debug(RDB_PEER, "%s: EP %p: recv'd %s msg %d bytes (header 0x%02x%02x%02x%02x)",
			__func__, (void*)ep,
			ccir_peer_hdr_str(CCIR_PEER_HDR_TYPE(hdr->generic.type)),
			event->recv.len, hdr->generic.a[0], hdr->generic.a[1],
			hdr->generic.a[2], hdr->generic.a[3]);

	switch (CCIR_PEER_HDR_TYPE(hdr->generic.type)) {
		case CCIR_PEER_MSG_RIR:
			handle_peer_recv_rir(globals, ep, peer, event);
			break;
		case CCIR_PEER_MSG_DEL:
			handle_peer_recv_del(globals, ep, peer, event);
			break;
		default:
			debug(RDB_PEER, "%s: EP %p: unknown message type %d from "
					"%s with %d bytes", __func__, (void*)ep,
					CCIR_PEER_HDR_TYPE(hdr->generic.type),
					peer->uri, event->recv.len);
			break;
	}
}

/* Handle a receive completion event.
 *
 * Need to determine if the event if for router-to-router use or
 * for a client.
 */
static void
handle_recv(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	cci_connection_t *connection = event->recv.connection;
	int is_peer = 0;

	is_peer = CCIR_IS_PEER_CTX(connection->context);

	if (is_peer) {
		void *ctx = CCIR_CTX(connection->context);
		ccir_peer_t *peer = (ccir_peer_t*)ctx;

		assert(peer->c == connection);

		handle_peer_recv(globals, ep, peer, event);
	} else {
		/* TODO */
		assert(0);
	}
	return;
}

static int
handle_event(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int ret = 0, up = 0;
	uint32_t i = 0;

	debug(RDB_EP, "%s: EP %p: got %s", __func__, (void*)ep,
			cci_event_type_str(event->type));

	switch (event->type) {
	case CCI_EVENT_SEND:
		break;
	case CCI_EVENT_RECV:
		handle_recv(globals, ep, event);
		break;
	case CCI_EVENT_CONNECT_REQUEST:
		handle_connect_request(globals, ep, event);
		break;
	case CCI_EVENT_ACCEPT:
		handle_accept(globals, ep, event);
		break;
	case CCI_EVENT_CONNECT:
		handle_connect(globals, ep, event);
		break;
	case CCI_EVENT_KEEPALIVE_TIMEDOUT:
		break;
	case CCI_EVENT_ENDPOINT_DEVICE_FAILED:
		/* We cannot recover - stop using this endpoint */
		ret = CCI_ERROR;
		ep->failed = 1;

		debug(RDB_EP, "%s: endpoint %s on device %s returned "
				"device failed event.\nUnable to continue "
				"routing using this endpoint.", __func__,
				ep->uri, ep->e->device->name);

		/* Try to keep routing if >=2 endpoints are still up */
		for (i = 0; i < globals->ep_cnt; i++) {
			ccir_ep_t *e = globals->eps[i];
			if (!e->failed)
				up++;
		}
		if (up < 2) {
			globals->shutdown = 1;
			debug(RDB_ALL, "%s: Unable to route with %d endpoint%s up.\n"
					"Shutting down.", __func__,
					up, up == 0 ? "s" : "");
		}
		break;
	case CCI_EVENT_NONE:
		break;
	}

	return ret;
}

static int
get_event(ccir_globals_t *globals)
{
	int ret = 0, found = 0;
	uint32_t i = 0;
	ccir_ep_t **eps = globals->eps;
	ccir_ep_t *ep = NULL;
	struct timeval ts = { CCIR_BLOCKING_TIMEOUT, 0 };

	if (globals->blocking) {
		fd_set fds;
		FD_ZERO(&fds);

		for (i = 0; i < globals->ep_cnt; i++) {
			ep = eps[i];
			if (!ep->failed)
				FD_SET(ep->fd, &fds);
		}

		do {
			ret = select(globals->nfds, &fds, NULL, NULL, &ts);
			if (ret == 1 && errno == EINTR)
				ret = 0;
		} while (!ret && running);
	}

	do {
		found = 0;

		for (i = 0; i < globals->ep_cnt; i++) {
			cci_event_t *event = NULL;

			ep = eps[i];

			if (ep->failed)
				continue;

			ret = cci_get_event(ep->e, &event);
			if (ret) {
				if (ret == CCI_EAGAIN) {
					continue;
				} else if (ret == CCI_ENOBUFS) {
					if (globals->verbose) {
						debug(RDB_EP, "%s: Need to return "
								"recv events for CCI "
								"endpoint %s",
								__func__,
								ep->uri);
					}
					continue;
				} else {
					/* TODO */
					goto out;
				}
			}
			found++;

			ret = handle_event(globals, ep, event);

			ret = cci_return_event(event);
			if (ret && globals->verbose)
				debug(RDB_EP, "%s: cci_return_event() failed with %s",
						__func__, cci_strerror(ep->e, ret));
		}
	} while (found && !globals->shutdown);
out:
	return ret;
}

#define CCIR_SEND_RIR_TIME	(30)	/* seconds */

static void
event_loop(ccir_globals_t *globals)
{
	int ret = 0;
	struct timeval old, current;

	running = 1;

	ret = install_sig_handlers(globals);
	if (ret)
		goto out;

	gettimeofday(&old, NULL);

	while (running) {
		connect_peers(globals);
		get_event(globals);
		gettimeofday(&current, NULL);

		if ((current.tv_sec - old.tv_sec) > CCIR_SEND_RIR_TIME) {
			old = current;
			send_all_rir(globals);
		}
	}

	/* Notify peers we are no longer routing */
	disconnect_peers(globals);

	if (globals->verbose)
		debug(RDB_ALL, "Exiting %s", __func__);
out:
	return;
}

/* Return 0 on success, errno otherwise */
static int
check_file(ccir_globals_t *globals, char *fname)
{
	int ret = 0;
	struct stat buf;

	ret = stat(fname, &buf);
	if (ret) {
		ret = errno;
		if (globals->verbose)
			debug(RDB_CONFIG, "Cannot access config file %s due to \"%s\".",
				fname, strerror(ret));
	} else if (buf.st_size == 0) {
		ret = EINVAL;
		if (globals->verbose)
			debug(RDB_CONFIG, "Config file %s is empty.", fname);
	}
	return ret;
}

/* Hierarchy of config processing:
 * 1. Command line options
 * 2. Command line config file
 * 3. CCI_CONFIG environment variable
 * 4. Local config file ($PWD/ccir_config)
 * 5. CCIR installed config file (/$INSTALL_PATH/etc/ccir/ccir_config)
 * 6. Global config file (/etc/ccir/ccir_config)
 */
static int
get_config(ccir_globals_t *globals, char *procname, char *config_option)
{
	int ret = 0, done = 0;
	char *cci_config = NULL;

	if (config_option) {
		/* see if it exists and is not empty, if so use it */
		ret = check_file(globals, config_option);
		if (ret) {
			config_option = NULL;
		} else {
			done = 1;
		}
	}

	cci_config = getenv("CCI_CONFIG");
	if (cci_config) {
		ret = check_file(globals, cci_config);
		if (ret) {
			cci_config = NULL;
		} else {
			done = 1;
		}
	}

	/* we have a valid config_option, cci_config, or both */
	if (done) {
		int overwrite = 0;

		if (config_option) {
			if (cci_config) {
				overwrite = 1;
				if (globals->verbose)
					debug(RDB_CONFIG, "Replacing CCI_CONFIG=%s with %s",
						cci_config, config_option);
			}
			ret = setenv("CCI_CONFIG", config_option, overwrite);
			if (ret) {
				ret = errno; /* ENOMEM */
				if (globals->verbose)
					debug(RDB_CONFIG, "Unable to setenv(CCI_CONFIG) (%s)",
						strerror(ret));
			}
		}
	}

	/* check for local config */
	if (!done) {
		char *fname = "ccir_config";

		ret = check_file(globals, fname);
		if (!ret) {
			ret = setenv("CCI_CONFIG", fname, 0);
			if (ret) {
				ret = errno; /* ENOMEM */
				if (globals->verbose)
					debug(RDB_CONFIG, "Unable to setenv(CCI_CONFIG) (%s)",
						strerror(ret));
			}
			done = 1;
		}
	}

	/* check for installed config */
	if (!done) {
		char *installdir = NULL, *bindir = NULL, fname[MAXPATHLEN];
		char *etcdir = "/etc/ccir/ccir_config";

		installdir = dirname(procname);

		bindir = strstr(installdir, "/bin");
		if (bindir) {
			*bindir = '\0';
			memset(fname, 0, MAXPATHLEN);
			if ((strlen(installdir) + strlen(etcdir)) < MAXPATHLEN) {
				strcat(fname, installdir);
				strcat(fname, etcdir);
				ret = check_file(globals, fname);
				if (!ret) {
					ret = setenv("CCI_CONFIG", fname, 0);
					if (ret) {
						ret = errno; /* ENOMEM */
						if (globals->verbose)
							debug(RDB_CONFIG, "Unable to setenv"
								"(CCI_CONFIG) (%s)",
								strerror(ret));
					}
					done = 1;
				}
			}
		}
	}

	/* check for global config */
	if (!done) {
		char *fname = "/etc/ccir/ccir_config";

		ret = check_file(globals, fname);
		if (!ret) {
			ret = setenv("CCI_CONFIG", fname, 0);
			if (ret) {
				ret = errno; /* ENOMEM */
				if (globals->verbose)
					debug(RDB_CONFIG, "Unable to setenv(CCI_CONFIG) (%s)",
						strerror(ret));
			}
			done = 1;
		}
	}

	if (!done || ret) {
		debug(RDB_CONFIG, "%s", "Unable to find configuration file.");
		debug(RDB_CONFIG, "%s", "Precedence of config file processing:");
		debug(RDB_CONFIG, "%s", "1. Command line config file option -f <file>");
		debug(RDB_CONFIG, "%s", "2. CCI_CONFIG environment variable");
		debug(RDB_CONFIG, "%s", "3. Local config file ($PWD/ccir_config)");
		debug(RDB_CONFIG, "%s", "4. CCIR installed config file "
				"(/$INSTALL_PATH/etc/ccir/ccir_config)");
		debug(RDB_CONFIG, "%s", "5. Global config file (/etc/ccir/ccir_config)");
	}

	return ret;
}

static void
close_endpoints(ccir_globals_t *globals)
{
	uint32_t i = 0;

	if (globals->verbose)
		debug(RDB_EP, "Entering %s", __func__);

	if (!globals->eps)
		return;

	for (i = 0; i < globals->ep_cnt; i++) {
		ccir_ep_t *ep = globals->eps[i];

		if (!ep)
			break;

		if (ep->e) {
			int rc = 0;

			rc = cci_destroy_endpoint(ep->e);
			if (rc) {
				debug(RDB_EP, "%s: cci_destroy_endpoint() "
						"failed with %s",
						__func__, cci_strerror(NULL, rc));
			}
		}

		if (ep->peers) {
			uint32_t j = 0;

			for (j = 0; j < ep->peer_cnt; j++) {
				ccir_peer_t *p = ep->peers[j];
				if (!p)
					break;
				free(p->uri);
				free(p);
			}
			free(ep->peers);
		}
		free((void*)ep->uri);
		free(ep);
	}
	free(globals->eps);

	if (globals->verbose)
		debug(RDB_EP, "Leaving %s", __func__);

	return;
}

static int
open_endpoints(ccir_globals_t *globals)
{
	int ret = 0, i = 0, cnt = 0;
	cci_device_t * const *devs = NULL;
	ccir_ep_t **es = NULL;
	uint32_t hash = 0;

	ret = cci_get_devices(&devs);
	if (ret) {
		debug(RDB_EP, "Failed to get devices with %s",
				cci_strerror(NULL, ret));
		goto out;
	}

	/* Count devices */
	for (cnt = 0; ; cnt++) {
		if (!devs[cnt])
			break;
	}

	/* NULL terminated array */
	es = calloc(cnt + 1, sizeof(*es));
	if (!es) {
		debug(RDB_EP, "%s: Failed to alloc endpoints", __func__);
		ret = ENOMEM;
		goto out;
	}

	/* Make sure that the devices have specified  as and subnet.
	 * Devices may have zero, one or more routers */
	for (i = 0; i < cnt; i++) {
		int j = 0, as = 0, subnet = 0, router = 0, unused = 0;
		uint32_t rate = 0;
		const char *arg = NULL;
		cci_device_t *d = devs[i];
		ccir_ep_t *ep = NULL;
		ccir_peer_t *peer = NULL;
		cci_os_handle_t *fd = NULL;
		ccir_router_t *rp = NULL;
		ccir_subnet_t *sp = NULL;

		if (!d)
			break;

		ep = calloc(1, sizeof(*ep));
		if (!ep) {
			ret = ENOMEM;
			goto out;
		}
		es[i] = ep;

		ep->peers = calloc(CCIR_MAX_PEERS, sizeof(*ep->peers));
		if (!ep->peers) {
			ret = ENOMEM;
			goto out;
		}

		for (j = 0; ;j++) {
			arg = d->conf_argv[j];
			if (!arg)
				break;
			if (0 == strncmp("as=", arg, 3)) {
				ep->as = strtol(arg + 3, NULL, 0);
				as++;
			} else if (0 == strncmp("subnet=", arg, 7)) {
				ep->subnet = strtol(arg + 7, NULL, 0);
				subnet++;
			} else if (0 == strncmp("router=", arg, 7)) {
				if (router == CCIR_MAX_PEERS) {
					debug((RDB_CONFIG|RDB_PEER),
						"%s: Device [%s] has more "
						"than %d router= keyword/values. "
						"Ignoring %s.",
						__func__, d->name, router, arg);
					continue;
				}

				peer = calloc(1, sizeof(*peer));
				if (!peer) {
					ret = ENOMEM;
					goto out;
				}
				peer->uri = strdup(arg + 7);
				if (!peer->uri) {
					ret = ENOMEM;
					goto out;
				}
				ep->peers[router++] = peer;
			}
		}

		if (!as || !subnet) {
			debug(RDB_EP, "Device [%s] is missing keyword/values "
					"for as= and/or subnet=", d->name);
			ret = EINVAL;
			goto out;
		} else if ((as > 1) || (subnet > 1)) {
			debug(RDB_EP, "Device [%s] has more than one keyword/value "
					"for as= or subnet=", d->name);
			ret = EINVAL;
			goto out;
		}
		if (peer) {
			peer->as = ep->as;
			peer->subnet = ep->subnet;
		}

		if (router < CCIR_MAX_PEERS) {
			void *tmp = realloc(ep->peers, (router + 1)*sizeof(*peer));

			if (tmp) {
				ep->peers = tmp;
				ep->peers[router] = NULL;
			}
			ep->peer_cnt = ep->need_connect = router;
		}

		if (globals->blocking)
			fd = &ep->fd;

		ret = cci_create_endpoint(d, 0, &(ep->e), fd);
		if (ret) {
			debug(RDB_EP, "Unable to create endpoint "
					"on device %s (%s)",
					devs[i]->name,
					cci_strerror(NULL, ret));
			goto out;
		}

		if (globals->blocking) {
			if (*fd >= (int) globals->nfds)
				globals->nfds = *fd + 1;
		}

		ret = cci_get_opt((cci_opt_handle_t *)ep->e, CCI_OPT_ENDPT_URI, &ep->uri);
		if (ret) {
			debug(RDB_EP, "%s: cci_get_opt() returned %s",
					__func__, cci_strerror(ep->e, ret));
			goto out;
		}
		if (strlen(ep->uri) > CCIR_URI_MAX_LEN) {
			debug(RDB_EP, "%s: Device [%s] endpoint URI [%s] is too long. "
					"Closing endpoint.",
				__func__, d->name, ep->uri);
			ret = EINVAL;
			goto out;
		}

		MurmurHash3_x86_32(ep->uri, strlen(ep->uri), hash, (void *) &hash);

		if (globals->verbose)
			debug(RDB_EP, "%s: opened %s on device %s", __func__,
					ep->uri, d->name);

		ret = add_router_to_topo(globals, ep, 0, 0, ep->subnet, NULL, &rp, &unused);
		assert(ret == 0);

		rate = ep->e->device->rate / 1000000000;
		if (!rate)
			rate = 1;

		ret = add_subnet_to_topo(globals, ep, ep->subnet, rate, 0, &sp, &unused);
		assert(ret == 0);

		ret = add_pairs(globals, sp, rp);
		assert(ret == 0);
	}

	if (cnt < 2)
		debug(RDB_ALL, "Unable to route with %d endpoint%s.",
				cnt, cnt == 0 ? "s" : "");

	if (globals->verbose) {
		debug(RDB_EP, "%s: globals->id = 0x%x", __func__, hash);
		print_routes(globals);
	}

	globals->eps = es;
	globals->ep_cnt = cnt;
	globals->id = hash;
out:
	if (ret)
		close_endpoints(globals);

	return ret;
}

int
main(int argc, char *argv[])
{
	int ret = 0, c;
	char *config_file = NULL;
	uint32_t caps = 0;
	ccir_globals_t *globals = NULL;
	ccir_topo_t *topo = NULL;
	struct timeval t;

	globals = calloc(1, sizeof(*globals));
	if (!globals) {
		ret = ENOMEM;
		goto out;
	}

	gettimeofday(&t, NULL);
	globals->instance = t.tv_sec;

	topo = calloc(1, sizeof(*topo));
	if (!topo) {
		free(globals);
		ret = ENOMEM;
		goto out;
	}
	globals->topo = topo;

	globals->topo->metric = CCIR_METRIC_BW; /* FIXME: make configurable */

	while ((c = getopt(argc, argv, "f:vb")) != -1) {
		switch (c) {
		case 'f':
			config_file = strdup(optarg);
			if (!config_file) {
				debug(RDB_CONFIG, "%s", "Unable to store file name "
						"- no memory");
				exit(EXIT_FAILURE);
			}
			break;
		case 'v':
			globals->verbose++;
			break;
		case 'b':
			globals->blocking = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	globals->debug = RDB_ALL;

	ret = get_config(globals, argv[0], config_file);
	if (ret) {
		exit(EXIT_FAILURE);
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret != CCI_SUCCESS) {
		debug(RDB_ALL, "%s", "Unable to init CCI");
		exit(EXIT_FAILURE);
	}

	ret = open_endpoints(globals);
	if (ret) {
		debug(RDB_ALL, "%s", "Unable to open CCI endpoints.");
		goto out_w_init;
	}

	/* We have the endpoints, start discovery and routing */
	event_loop(globals);

	close_endpoints(globals);

out_w_init:
	ret = cci_finalize();
	if (ret) {
		debug(RDB_ALL, "%s", "Unable to finalize CCI");
		exit(EXIT_FAILURE);
	}

	if (globals->verbose)
		debug(RDB_ALL, "%s is done", argv[0]);

	if (globals->topo) {
		if (globals->topo->pairs) {
			void *node = globals->topo->pairs;

			while (node) {
				uint64_t *id = *((uint64_t**)node);
				ccir_pair_t *pair = container_of(id, ccir_pair_t, id);

				tdelete(id, &(globals->topo->pairs), compare_u64);
				free(pair->routers);
				free(pair);
				node = globals->topo->pairs;
			}
		}
		if (globals->topo->num_subnets) {
			uint32_t i = 0;

			for (i = 0; i < globals->topo->num_subnets; i++) {
				ccir_subnet_t *subnet = globals->topo->subnets[i];

				free(subnet->routers);
				free(subnet);
			}
			free(globals->topo->subnets);
		}
		if (globals->topo->routers) {
			uint32_t i = 0;

			for (i = 0; i < globals->topo->num_routers; i++) {
				ccir_router_t *router = globals->topo->routers[i];

				free(router->subnets);
				free(router->pairs);
				free(router);
			}
			free(globals->topo->routers);
		}
	}
	free(globals->topo);
	free(globals);
out:
	return ret;
}
