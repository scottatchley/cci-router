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

	len = sizeof(hdr->del_size) +
		sizeof(del->data_size) +
		(globals->ep_cnt * sizeof(uint32_t));

	buf = calloc(1, len);
	if (!buf) {
		/* TODO */
		assert(buf);
	}

	hdr = (ccir_peer_hdr_t *)buf;
	del = (ccir_del_data_t *)hdr->del.data;

	ccir_pack_del(hdr, 1, (uint8_t)globals->ep_cnt);
	del->data.router = htonl(globals->id);
	del->data.instance = htonl(globals->instance);

	debug(RDB_PEER, "%s: preparing DEL msg for router 0x%x with %u endpoints",
		__func__, globals->id, globals->ep_cnt);

	for (i = 0; i < (int) globals->ep_cnt; i++) {
		del->data.subnet[i] = htonl(globals->eps[i]->subnet);
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
			char buffer[256];
			ccir_peer_t *peer = *p;
			ccir_peer_hdr_t *hdr = (void*)buffer;
			uint32_t len = strlen(ep->uri);

			if (peer->connecting)
				continue;

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

			hdr = (void*)buffer;
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
	char buf[24]; /* FIXME Magic number */
	int len = 0, ret = 0;
	ccir_peer_hdr_t *hdr = (ccir_peer_hdr_t *)buf;
	ccir_rir_data_t *rir = (ccir_rir_data_t *)hdr->rir.data;

	len = sizeof(hdr->rir_size) + sizeof(*rir);

	assert(len < (int) peer->c->max_send_size);
	assert(len == (int) sizeof(buf));

	memset(buf, 0, sizeof(buf));
	ccir_pack_rir(hdr);
	rir->as = htonl(ep->as);
	rir->subnet = htonl(ep->subnet);
	rir->router = htonl(globals->id);
	rir->instance = 0; /* FIXME */
	rir->rate = htons(ep->e->device->rate / 1000000000);
	if (!rir->rate) rir->rate = htons(1);

	debug(RDB_PEER, "%s: EP %p: sending RIR to %s len %u (header 0x%02x%02x%02x%02x)",
			__func__, (void*)ep, peer->uri, len,
			hdr->rir.type, hdr->rir.count, hdr->rir.a[0], hdr->rir.a[1]);
	debug(RDB_PEER, "\t%08x %08x %08x %08x %04x %02x",
			ntohl(rir->as), ntohl(rir->subnet),
			ntohl(rir->router), ntohl(rir->instance),
			ntohs(rir->rate), rir->caps);
	ret = cci_send(peer->c, buf, len, NULL, 0);
	if (ret)
		debug(RDB_PEER, "%s: send RIR to %s "
			"failed with %s", __func__,
			peer->uri, cci_strerror(ep->e, ret));

	return;
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
			assert(peer->c == NULL);
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

static void
print_router_tree(const void *nodep, const VISIT which, const int depth)
{
	uint32_t *id = *(uint32_t **) nodep;
	ccir_router_t *router = container_of(id, ccir_router_t, id);

	switch (which) {
	case preorder:
		break;
	case postorder:
		fprintf(stderr, "router id 0x%x instance %u count %u\n", router->id,
				router->instance, router->count);
		break;
	case endorder:
		break;
	case leaf:
		fprintf(stderr, "router id 0x%x instance %u count %u\n", router->id,
				router->instance, router->count);
		break;
	}
}

static void
print_subnet_tree(const void *nodep, const VISIT which, const int depth)
{
	uint32_t *id = *(uint32_t **) nodep;
	ccir_subnet_t *subnet = container_of(id, ccir_subnet_t, id);

	switch (which) {
	case preorder:
		break;
	case postorder:
		fprintf(stderr, "subnet id 0x%x rate %hu count %u\n", subnet->id,
				subnet->rate, subnet->count);
		break;
	case endorder:
		break;
	case leaf:
		fprintf(stderr, "subnet id 0x%x rate %hu count %u\n", subnet->id,
				subnet->rate, subnet->count);
		break;
	}
}

static int
add_router_to_subnet(ccir_globals_t *globals, ccir_ep_t *ep, ccir_subnet_t *subnet,
		ccir_rir_data_t *rir)
{
	int ret = 0;
	void *node = NULL;
	uint32_t *id = &(rir->router);
	ccir_router_t *router = NULL;

	node = tfind(id, &(subnet->routers), compare_u32);
	if (node) {
		id = *((uint32_t**)node);
		router = container_of(id, ccir_router_t, id);

		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: adding ref to router 0x%x "
				"(count was %u)", __func__, (void*)ep,
				router->id, router->count);
		}

		if (router->instance == rir->instance) {
			router->count++;
		} else {
			/* TODO */
			assert(0);
		}
	} else {
		int empty = subnet->routers == NULL;

		router = calloc(1, sizeof(*router));
		if (!router) {
			/* TODO */
			assert(router);
			ret = ENOMEM;
		}
		router->id = rir->router;
		router->instance = rir->instance;
		router->count = 1;

		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: adding router 0x%x",
				__func__, (void*)ep, router->id);
		}

		node = tsearch(&router->id, &(subnet->routers), compare_u32);
		if (!node && !empty) {
			/* TODO */
			assert(0);
		}
	}

	if (globals->verbose)
		twalk(subnet->routers, print_router_tree);

	return ret;
}

static int
delete_router_from_subnet(ccir_globals_t *globals, ccir_ep_t *ep, ccir_subnet_t *subnet,
		uint32_t router_id, uint32_t instance)
{
	int ret = 0;
	void *node = NULL;
	uint32_t *id = &router_id;
	ccir_router_t *router = NULL;

	node = tfind(id, &(subnet->routers), compare_u32);
	if (node) {
		id = *((uint32_t**)node);
		router = container_of(id, ccir_router_t, id);

		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: deleting ref to router 0x%x "
				"(count was %u)", __func__, (void*)ep,
				router->id, router->count);
		}

		if (router->instance == instance) {
			router->count--;
			if (router->count == 0) {
				tdelete(&router_id, &(subnet->routers), compare_u32);
				free(router);
				debug(RDB_PEER, "%s: EP %p: deleted router id 0x%x",
					__func__, (void*)ep, router_id);
			}
		} else {
			/* TODO */
			assert(0);
		}
	} else {
		debug(RDB_PEER, "%s: EP %p: DEL msg for subnet 0x%x router 0x%x "
			"and no matching router found", __func__, (void*)ep,
			subnet->id, router_id);
	}

	if (globals->verbose) {
		if (subnet->routers != NULL)
			twalk(subnet->routers, print_router_tree);
		else
			debug(RDB_PEER, "%s: EP %p: subnet 0x%x has no routers",
				__func__, (void*)ep, subnet->id);
	}

	return ret;
}

static void
handle_peer_recv_rir(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer,
		cci_event_t *event)
{
	ccir_peer_hdr_t *hdr = (ccir_peer_hdr_t*)event->recv.ptr; /* in host order */
	ccir_rir_data_t *rir = (ccir_rir_data_t*)hdr->rir.data;
	ccir_subnet_t *subnet = NULL;
	void *node = NULL;

	rir->as = ntohl(rir->as);
	rir->subnet = ntohl(rir->subnet);
	rir->router = ntohl(rir->router);
	rir->instance = ntohl(rir->instance);
	rir->rate = ntohs(rir->rate);

	if (globals->verbose) {
		debug(RDB_PEER, "%s: EP %p: received RIR from %s:",
				__func__, (void*)ep, peer->uri);
		debug(RDB_PEER, "%s: EP %p:      as     = %u (0x%08x)",
				__func__, (void*)ep, rir->as, rir->as);
		debug(RDB_PEER, "%s: EP %p:      subnet = %u (0x%08x)",
				__func__, (void*)ep, rir->subnet, rir->subnet);
		debug(RDB_PEER, "%s: EP %p:      router = %u (0x%08x)",
				__func__, (void*)ep, rir->router, rir->router);
		debug(RDB_PEER, "%s: EP %p:      instance = %u (0x%08x)",
				__func__, (void*)ep, rir->instance, rir->instance);
		debug(RDB_PEER, "%s: EP %p:      rate   = %hu (0x%04x)",
				__func__, (void*)ep, rir->rate, rir->rate);
	}

	node = tfind(&rir->subnet, &(globals->topo->subnets), compare_u32);
	if (node) {
		uint32_t *id = *((uint32_t**)node);
		subnet = container_of(id, ccir_subnet_t, id);

		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: adding ref to subnet %u "
				"(count was %u)", __func__, (void*)ep,
				subnet->id, subnet->count);
		}
		subnet->count++;
	} else {
		int empty = globals->topo->subnets == NULL;

		subnet = calloc(1, sizeof(*subnet));
		if (!subnet) {
			/* TODO */
			assert(0);
		}
		subnet->id = rir->subnet;
		subnet->count = 1;
		subnet->rate = rir->rate;

		if (globals->verbose) {
			debug(RDB_PEER, "%s: EP %p: adding subnet %u",
				__func__, (void*)ep, subnet->id);
		}

		node = tsearch(&subnet->id, &(globals->topo->subnets), compare_u32);
		if (!node && !empty) {
			/* TODO */
			assert(0);
		}

		if (globals->verbose)
			twalk(globals->topo->subnets, print_subnet_tree);
	}


	add_router_to_subnet(globals, ep, subnet, rir);

	return;
}

static void
handle_peer_recv_del(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer,
		cci_event_t *event)
{
	ccir_peer_hdr_t *hdr = (ccir_peer_hdr_t*) event->recv.ptr; /* in host order */
	ccir_del_data_t *del = (ccir_del_data_t *)hdr->del.data;
	ccir_subnet_t *subnet = NULL;
	int i = 0, bye = hdr->del.bye;
	void *node = NULL;

	del->data.router = ntohl(del->data.router);
	del->data.instance = ntohl(del->data.instance);

	if (globals->verbose) {
		debug(RDB_PEER, "%s: EP %p: peer %s (router 0x%x) with %u "
			"endpoints leaving",  __func__, (void*)ep,
			peer->uri, del->data.router, hdr->del.count);
		for (i = 0; i < hdr->del.count; i++)
			debug(RDB_PEER, "%s: EP %p: peer %s deleting subnet 0x%x",
				__func__, (void*)ep, peer->uri, ntohl(del->data.subnet[i]));
	}

	/* find subnets, if find router, remove router && decref subnet */
	for (i = 0; i < hdr->del.count; i++) {
		uint32_t subnet_id = 0;

		subnet_id = ntohl(del->data.subnet[i]);

		node = tfind(&subnet_id, &(globals->topo->subnets), compare_u32);
		if (node) {
			uint32_t *id = *((uint32_t**)node);
			subnet = container_of(id, ccir_subnet_t, id);

			delete_router_from_subnet(globals, ep, subnet, del->data.router,
				del->data.instance);

			if (globals->verbose) {
				debug(RDB_PEER, "%s: EP %p: decref subnet %u (0x%x)"
					"(count was %u)", __func__, (void*)ep,
					subnet->id, subnet->id, subnet->count);
			}
			subnet->count--;
			if (subnet->count == 0) {
				tdelete(&subnet_id, &(globals->topo->subnets), compare_u32);
				free(subnet);
				debug(RDB_PEER, "%s: EP %p: deleted subnet id 0x%x",
					__func__, (void*)ep, subnet_id);
			}
		} else {
			debug(RDB_PEER, "%s: EP %p: DEL msg for subnet 0x%x router 0x%x "
				"and no matching subnet found", __func__, (void*)ep,
				subnet_id, del->data.router);
		}
	}

	if (bye) {
		void *ctx = CCIR_CTX(((cci_connection_t*)(event->recv.connection))->context);
		ccir_peer_t *peer = (ccir_peer_t*)ctx;

		cci_disconnect(peer->c);
		peer->c = NULL;
	}

	if (globals->verbose) {
		if (globals->topo->subnets != NULL)
			twalk(globals->topo->subnets, print_subnet_tree);
		else
			debug(RDB_PEER, "%s: EP %p: no more subnets",
				__func__, (void*)ep);
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

static void
event_loop(ccir_globals_t *globals)
{
	int ret = 0;

	running = 1;

	ret = install_sig_handlers(globals);
	if (ret)
		goto out;

	while (running) {
		connect_peers(globals);
		get_event(globals);
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

	/* Make sure that the devices have specified
	 * as, subnet, and at least one router */
	for (i = 0; i < cnt; i++) {
		int j = 0, as = 0, subnet = 0, router = 0;
		const char *arg = NULL;
		cci_device_t *d = devs[i];
		ccir_ep_t *ep = NULL;
		ccir_peer_t *peer = NULL;
		cci_os_handle_t *fd = NULL;

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

		if (!as || !subnet || !router) {
			debug(RDB_EP, "Device [%s] is missing keyword/values "
					"for as=, subnet=, and/or router=", d->name);
			ret = EINVAL;
			goto out;
		} else if ((as > 1) || (subnet > 1)) {
			debug(RDB_EP, "Device [%s] has more than one keyword/value "
					"for as= or subnet=", d->name);
			ret = EINVAL;
			goto out;
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

		if (globals->verbose > 2)
			debug(RDB_EP, "%s: opened %s on device %s", __func__,
					ep->uri, d->name);
	}

	if (cnt < 2)
		debug(RDB_ALL, "Unable to route with %d endpoint%s.",
				cnt, cnt == 0 ? "s" : "");

	if (globals->verbose)
		debug(RDB_EP, "%s: globals->id = 0x%x", __func__, hash);

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

	globals = calloc(1, sizeof(*globals));
	if (!globals) {
		ret = ENOMEM;
		goto out;
	}

	topo = calloc(1, sizeof(*topo));
	if (!topo) {
		free(globals);
		ret = ENOMEM;
		goto out;
	}
	globals->topo = topo;

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

	free(globals->topo);
	free(globals);
out:
	return ret;
}
