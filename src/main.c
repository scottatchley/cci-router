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
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include <sys/param.h>
#include <signal.h>
#include <sys/select.h>
#include <assert.h>
#include <sys/time.h>
#include <pthread.h>

#include "cci-router.h"
#include "bsd/murmur3.h"

#define CCIR_RMA_MTU	(1024*1024)
#define CCIR_RMA_CNT	(256)

static void
usage(char *procname)
{
	fprintf(stderr, "usage: %s [-f <config_file>] [-v] [-b]\n", procname);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-f\tUse this configuration file.\n");
	fprintf(stderr, "\t-l\tLength of a RMA buffer (default %d)\n", CCIR_RMA_MTU);
	fprintf(stderr, "\t-n\tNumber of RMA buffers (default %d)\n", CCIR_RMA_CNT);
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
	if (ret && verbose)
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
				ret = cci_send(c, buf, len, NULL, CCI_FLAG_BLOCKING);
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
							if (verbose) {
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

			if (verbose)
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
					CCIR_SET_CTX(peer, CCIR_CTX_PEER),
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

	if (verbose)
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

				if (verbose) {
					debug(RDB_PEER, "%s: accepting passive conn "
							"from %s", __func__,
							peer->uri);
				}
				ret = cci_accept(event, CCIR_SET_CTX(peer, CCIR_CTX_PEER));
				if (ret) {
					debug(RDB_PEER, "%s: cci_accept() failed %s",
							__func__, cci_strerror(ep->e, ret));
				}
			} else {
				if (verbose) {
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

static void
shutdown_rconn(ccir_rconn_t *rconn)
{
	cci_e2e_hdr_t hdr;

	rconn->state = CCIR_RCONN_CLOSING;

	memset(&hdr, 0, sizeof(hdr));
	hdr.bye.type = CCI_E2E_MSG_BYE;

	if (rconn->src) {
		cci_send(rconn->src, &hdr, sizeof(hdr.bye), NULL, CCI_FLAG_BLOCKING);
		cci_disconnect(rconn->src);
		rconn->src = NULL;
	}

	if (rconn->dst) {
		cci_send(rconn->dst, &hdr, sizeof(hdr.bye), NULL, CCI_FLAG_BLOCKING);
		cci_disconnect(rconn->dst);
		rconn->dst = NULL;
	}

	if (!rconn->is_connecting && !rconn->is_accepting) {
		free(rconn->client_uri);
		free(rconn->server_uri);
		/* poison it */
		memset(rconn, 0xf, sizeof(*rconn));
		free(rconn);
	}

	return;
}

static void
handle_e2e_connect_request(ccir_globals_t *globals, ccir_ep_t *src_ep, cci_event_t *event)
{
	int ret = 0, src_is_router = 0, dst_is_router = 0;
	char *client = NULL, *server = NULL, *uri = NULL, *local_uri = NULL;
	const char *base = NULL;
	cci_e2e_hdr_t *hdr = (void*)event->request.data_ptr; /* already in host order */
	cci_e2e_connect_t *connect = (void*)hdr->connect.data;
	ccir_rconn_t *rconn = NULL;
	ccir_ep_t *dst_ep = NULL;
	ccir_peer_t *peer = NULL;
	uint32_t i = 0, src_subnet = 0, dst_subnet = 0, next_subnet = 0;
	void *ptr = connect->request.data;

	for (i = 0; i < 2; i++)
		connect->net[i] = ntohl(connect->net[i]);

	/* The URIs are packed without NULL bytes, need to memcpy() them */
	server = calloc(1, connect->request.dst_len + 1 /* \0 */);
	if (!server) {
		ret = ENOMEM;
		goto out;
	}
	memcpy(server, ptr, connect->request.dst_len);
	ptr = (void*)((uintptr_t)ptr + (uintptr_t)connect->request.dst_len);

	client = calloc(1, connect->request.src_len + 1 /* \0 */);
	if (!client) {
		ret = ENOMEM;
		goto out;
	}
	memcpy(client, ptr, connect->request.src_len);

	/* are the src or dst routers or e2e clients?
	 * if the client or server URIs contain connected subnets,
	 * they are not routers.
	 */
	ret = cci_e2e_parse_uri(client, NULL, &src_subnet, NULL);
	if (ret)
		goto out;

	if (src_subnet != src_ep->subnet)
		src_is_router = 1;

	ret = cci_e2e_parse_uri(server, NULL, &dst_subnet, &base);
	if (ret)
		goto out;

	/* can we route this request (from ep->subnet to dst)?
	 * find ep for next hop, choose peer if more than one. */

	ret = find_next_subnet(globals->topo, src_ep->subnet, dst_subnet, &next_subnet);
	if (ret)
		goto out;

	/* find ep for this subnet */

	/* TODO make this a function that uses a static int
	 * to round-robin the choice of endpoints if more than one.
	 */
	for (i = 0; i < globals->ep_cnt; i++) {
		if (globals->eps[i]->subnet == next_subnet) {
			dst_ep = globals->eps[i];
			break;
		}
	}

	if (!dst_ep) {
		ret = EHOSTUNREACH;
		goto out;
	}

	if (dst_subnet != dst_ep->subnet)
		dst_is_router = 1;

	/* Are we connected to the dst subnet? If so, convert uri
	 * to native and connect to e2e client.
	 *
	 * If not, forward to next router.
	 */

	if (!dst_is_router) {
		int prefix_len = 0, base_len = 0, len = 0;

		ret = cci_e2e_uri_prefix_len(dst_ep->uri, &prefix_len);
		if (ret)
			goto out;

		base_len = strlen(base);
		len = prefix_len + base_len;

		local_uri = calloc(1, len + 1); /* len + \0 */
		if (!local_uri) {
			ret = ENOMEM;
			goto out;
		}
		snprintf(local_uri, prefix_len + 1, "%s", dst_ep->uri);
		snprintf(local_uri + prefix_len, base_len + 1, "%s", base);

		uri = local_uri;
	} else {
		/* find peer for this subnet */

		/* TODO make this a function that uses a static int
		 * to round-robin the choice of peers if more than one.
		 */
		peer = dst_ep->peers[0];
		uri = peer->uri;
	}

	rconn = calloc(1, sizeof(*rconn));
	if (!rconn) {
		ret = ENOMEM;
		goto out;
	}
	rconn->state = CCIR_RCONN_PENDING;
	rconn->client_uri = client;
	rconn->server_uri = server;
	rconn->sh = src_ep->h;
	rconn->dh = dst_ep->h;

	/* put back in network order */
	hdr->net[0] = htonl(hdr->net[0]);
	for (i = 0; i < 2; i++)
		connect->net[i] = htonl(connect->net[i]);

	rconn->is_connecting = 1;
	ret = cci_connect(dst_ep->e, uri, event->request.data_ptr,
			event->request.data_len, event->request.attribute,
			rconn, 0, NULL);
	if (ret) {
		rconn->is_connecting = 0;
		goto out;
	}

	rconn->is_accepting = 1;
	/* if we made it here, accept() */
	ret = cci_accept(event, rconn);
	if (ret) {
		rconn->is_accepting = 0;
	}

    out:
	free(local_uri);

	if (ret) {
		cci_reject(event);
		if (rconn) {
			shutdown_rconn(rconn);
		} else {
			free(client);
			free(server);
		}
	}
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
		handle_e2e_connect_request(globals, ep, event);
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
	ret = cci_send(peer->c, buf, len, NULL, CCI_FLAG_SILENT);
	if (ret)
		debug(RDB_PEER, "%s: send RIR to %s "
			"failed with %s", __func__,
			peer->uri, cci_strerror(ep->e, ret));

	return;
}

static void
send_rma_info(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer)
{
	ccir_peer_hdr_t *hdr = NULL;
	char buf[sizeof(hdr->rma_size) + sizeof(ccir_rma_info_t)];
	int ret = 0, len = sizeof(hdr->rma_size) + sizeof(ccir_rma_info_t);

	hdr = (ccir_peer_hdr_t *)buf;

	ccir_pack_rma_info(hdr, (void*)ep->h, sizeof(*(ep->h)),
			globals->rma_buf->mtu, globals->rma_buf->cnt);

	if (verbose)
		debug(RDB_PEER, "%s: EP %p: sending RMA info to %s len %u "
				"rma_mtu %u rma_cnt %u", __func__, (void*)ep,
				peer->uri, len, globals->rma_buf->mtu,
				globals->rma_buf->cnt);

	ret = cci_send(peer->c, buf, len, NULL, CCI_FLAG_SILENT);
	if (ret)
		debug(RDB_PEER, "%s: send RMA info to %s "
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

static void
handle_peer_accept(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	void *ctx = CCIR_CTX(event->accept.context);
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

		if (verbose)
			debug(RDB_PEER, "%s: accepted %s on endpoint %s (%s) "
					"(c=%p)",
					__func__, peer->uri, ep->uri,
					ccir_peer_state_str(peer->state),
					(void*)peer->c);

		send_rma_info(globals, ep, peer);

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
	return;
}

static void
handle_e2e_accept(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	ccir_rconn_t *rconn = event->accept.context;

	rconn->is_accepting = 0;
	rconn->src = event->accept.connection; /* may be NULL */

	if (event->accept.status != CCI_SUCCESS ||
		rconn->state == CCIR_RCONN_CLOSING) {

		debug(RDB_PEER, "%s: accept() failed with %s for connection "
				"from %s to %s", __func__,
				cci_strerror(ep->e, event->accept.status),
				rconn->client_uri, rconn->server_uri);

		shutdown_rconn(rconn);
	} else if (!rconn->is_connecting) {
		rconn->state = CCIR_RCONN_CONNECTED;
	}

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

	if (peer_accept) {
		handle_peer_accept(globals, ep, event);
	} else {
		handle_e2e_accept(globals, ep, event);
	}

	return;
}

static void
handle_peer_connect(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	void *ctx = CCIR_CTX(event->connect.context);
	ccir_peer_t *peer = ctx;

	peer->connecting--;

	if (event->connect.status == CCI_SUCCESS) {
		ccir_ep_t **e = NULL;

		assert(peer->c == NULL);
		peer->c = event->connect.connection;
		peer->state = CCIR_PEER_CONNECTED;

		ep->need_connect--;

		if (verbose)
			debug(RDB_PEER, "%s: connected to %s on endpoint %s (%s) "
					"(c=%p)",
					__func__, peer->uri, ep->uri,
					ccir_peer_state_str(peer->state),
					(void*)peer->c);

		send_rma_info(globals, ep, peer);

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
	return;
}

static void
handle_e2e_connect(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	ccir_rconn_t *rconn = event->connect.context;

	rconn->is_connecting = 0;
	rconn->dst = event->connect.connection; /* may be NULL */

	if (event->connect.status != 0 ||
		rconn->state == CCIR_RCONN_CLOSING) {

		debug(RDB_PEER, "%s: connect() failed with %s for connection "
				"from %s to %s", __func__,
				cci_strerror(ep->e, event->connect.status),
				rconn->client_uri, rconn->server_uri);

		shutdown_rconn(rconn);
	} else if (!rconn->is_accepting) {
		rconn->state = CCIR_RCONN_CONNECTED;
	}

	return;
}

/* Handle a connect completion event.
 *
 * Need to determine if the event if for router-to-router use or
 * for a client.
 */
static void
handle_connect(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	uint32_t peer_connect = CCIR_IS_PEER_CTX(event->connect.context);

	if (peer_connect) {
		handle_peer_connect(globals, ep, event);
	} else {
		handle_e2e_connect(globals, ep, event);
	}

	return;
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

	if (rir->router == globals->id) {
		if (verbose)
			debug(RDB_PEER, "%s: received our own RIR msg - ignoring", __func__);
		goto out;
	}

	if (verbose) {
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

	ret = add_router_to_topo(globals->topo, rir->router, rir->instance, rir->subnet[0].id,
			&router, &new_router);
	assert(ret == 0);

	/* NOTE: If this is a new_router and not a direct peer, we could send our
	 *       RIR msgs to this peer who would forward them on. If a lot of routers
	 *       start at the same time though, it could lead to a lot of traffic
	 *       all at once.
	 *
	 *       For now, let the periodic resend mechanism send the RIR msgs. At worst,
	 *       new peers will wait for CCIR_SEND_RIR_TIME seconds +- 25%.
	 */

	ret = add_subnet_to_topo(globals->topo, rir->subnet[0].id, rir->subnet[0].rate,
			router->id, &subnet, &new_subnet);
	assert(ret == 0);

	if (peer->id == router->id && peer->subnet == subnet->id) {
		/* router->peer = peer; */
		/* peer->router = router; */
	} else {
		debug(RDB_TOPO, "peer->id 0x%x router->id 0x%x peer->subnet 0x%x "
				"subnet->id 0x%x", peer->id, router->id,
				peer->subnet, subnet->id);
	}

	ret = add_pairs(globals->topo, subnet, router);
	assert(ret == 0);

	print_routers(globals->topo);
	print_subnets(globals->topo);
	print_routes(globals->topo);

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

    out:
	return;
}

static void
handle_peer_recv_rma_info(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer,
		cci_event_t *event)
{
	int ret = 0;
	ccir_peer_hdr_t *hdr = (ccir_peer_hdr_t*)event->recv.ptr; /* in host order */

	ret = ccir_parse_rma_info(hdr, (void**)&(peer->h), sizeof(*(peer->h)),
			&(peer->rma_mtu), &(peer->rma_cnt));
	if (ret) {
		debug(RDB_PEER, "%s: EP %p: unable to parse RMA info from %s",
				__func__, (void*)ep, peer->uri);
	}

	if (verbose)
		debug(RDB_PEER, "%s: EP %p: from %s with rma_mtu %u rma_cnt %u",
			__func__, (void*)ep, peer->uri, peer->rma_mtu, peer->rma_cnt);

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
	ccir_router_t *router = NULL;
	int i = 0, bye = hdr->del.bye;

	del->instance = ccir_ntohll(del->instance);
	del->router = ntohl(del->router);

	if (verbose) {
		debug(RDB_PEER, "%s: EP %p: peer %s (router 0x%x) (instance %"PRIu64") "
			"with %u endpoints leaving",  __func__, (void*)ep,
			peer->uri, del->router, del->instance, hdr->del.count);
		for (i = 0; i < hdr->del.count; i++)
			debug(RDB_PEER, "%s: EP %p: peer %s deleting subnet 0x%x",
				__func__, (void*)ep, peer->uri, ntohl(del->subnet[i]));
	}

	/* TODO if we remove a router and/or subnet, we need to remove
	 *      the affected pairs. If we lose a pair, then we may lose
	 *      paths and/or routes.
	 */

	/* find subnets, if find router, remove router && decref subnet */
	for (i = 0; i < hdr->del.count; i++) {
		uint32_t subnet_id = 0;

		subnet_id = ntohl(del->subnet[i]);

		find_subnet(globals->topo, subnet_id, &subnet);
		if (subnet) {
			delete_router_from_subnet(subnet, del->router);

			if (subnet->count == 0) {
				delete_subnet_from_topo(globals->topo, subnet->id);

				debug(RDB_PEER, "%s: EP %p: deleted subnet id 0x%x",
					__func__, (void*)ep, subnet_id);
			}
		} else {
			debug(RDB_PEER, "%s: EP %p: DEL msg for subnet 0x%x router 0x%x "
				"and no matching subnet found", __func__, (void*)ep,
				subnet_id, del->router);
		}
	}

	find_router(globals->topo, del->router, &router);
	if (router) {
		router->count -= hdr->del.count;
		if (router->count == 0) {
			delete_router_from_topo(topo, router->id);
			debug(RDB_PEER, "%s: EP %p: deleted router id 0x%x (num_routers = %u)",
				__func__, (void*)ep, del->router, topo->num_routers);
		} else {
			assert(router->count == 0);
		}
	}

	if (bye) {
		void *ctx = CCIR_CTX(((cci_connection_t*)(event->recv.connection))->context);
		ccir_peer_t *peer = (ccir_peer_t*)ctx;

		/* peer->router = NULL; */
		peer->id = 0;

		cci_disconnect(peer->c);
		peer->c = NULL;
		peer->state = CCIR_PEER_CLOSED;
		ep->need_connect++;
	}

	if (verbose) {
		print_routers(globals->topo);
		print_subnets(globals->topo);
	}

	return;
}

/* Caller holds rma_buf->lock.
 *
 * If the rma is new, the idx must be -1. In this case, we will look for an
 * available slot. If the rma is reusing an existing slot, idx must be set
 * to that index and we will simply update the rma_buf->rmas. */
static inline int
reserve_rma_buffer_locked(ccir_rma_buffer_t *rma_buf, ccir_rma_request_t *rma)
{
	int ret = EAGAIN, i = 0, idx = 0;

	if (rma->idx == -1) {
		for (i = 0; i < rma_buf->num_blocks; i++) {
			idx = ffsl(rma_buf->ids[i]);
			if (idx == 0)
				continue;

			idx--;
			rma_buf->ids[i] &= ~((uint64_t)1 << idx);
			idx += i * 64;
			rma->idx = idx;
			ret = 0;
			break;
		}
	} else {
		idx = rma->idx;
		ret = 0;
	}

	if (!ret)
		rma_buf->rmas[idx] = rma;

	return ret;
}

/* Caller holds rma_buf->lock */
static inline void
release_rma_buffer_locked(ccir_rma_buffer_t *rma_buf, ccir_rma_request_t *rma)
{
	int i = 0, idx = 0;

	i = rma->idx / 64;
	idx = rma->idx % 64;

	rma_buf->ids[i] |= ((uint64_t) 1) << idx;
	rma_buf->rmas[idx] = NULL;
	rma->idx = -1;

	return;
}

static int
post_rma(ccir_globals_t *globals, ccir_ep_t *ep, ccir_rma_request_t *rma);

static void
handle_peer_recv_rma_done(ccir_globals_t *globals, ccir_ep_t *ep, ccir_peer_t *peer,
		cci_event_t *event)
{
	ccir_peer_hdr_t *hdr = (ccir_peer_hdr_t*)event->recv.ptr; /* in host order */
	int idx = hdr->done.idx;
	ccir_rma_buffer_t *rma_buf = globals->rma_buf;
	ccir_rma_request_t *rma = rma_buf->rmas[idx], *new = NULL;

	assert(rma);
	assert(idx == rma->idx);

	pthread_mutex_lock(&rma_buf->lock);
	release_rma_buffer_locked(rma_buf, rma);

	new = TAILQ_FIRST(&rma_buf->reqs);
	if (new) {
		TAILQ_REMOVE(&rma_buf->reqs, new, entry);
		new->idx = idx;
		reserve_rma_buffer_locked(rma_buf, new);
	}
	pthread_mutex_unlock(&rma_buf->lock);
	free(rma);

	if (new) {
		int ret = 0;

		ret = post_rma(globals, ep, new);
		if (ret) {
			/* The RMA failed, release the buffer and queue for later */
			pthread_mutex_lock(&rma_buf->lock);
			release_rma_buffer_locked(rma_buf, new);
			TAILQ_INSERT_HEAD(&rma_buf->reqs, new, entry);
			pthread_mutex_unlock(&rma_buf->lock);
		}
	}

	if (verbose)
		debug(RDB_PEER, "%s: EP %p: from %s with index %u",
			__func__, (void*)ep, peer->uri, hdr->done.idx);

	return;
}

static void
handle_peer_recv(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	cci_connection_t *connection = event->recv.connection;
	void *ctx = CCIR_CTX(connection->context);
	ccir_peer_t *peer = (ccir_peer_t*)ctx;
	ccir_peer_hdr_t *hdr = (void*)event->recv.ptr; /* in net order */

	assert(peer->c == connection);

	hdr->net = ntohl(hdr->net);

	debug(RDB_PEER, "%s: EP %p: recv'd %s msg %d bytes (header 0x%02x%02x%02x%02x)",
			__func__, (void*)ep,
			ccir_peer_hdr_str(CCIR_PEER_HDR_TYPE(hdr->generic.type)),
			event->recv.len, hdr->generic.type, hdr->generic.a[0],
			hdr->generic.a[1], hdr->generic.a[2]);

	switch (CCIR_PEER_HDR_TYPE(hdr->generic.type)) {
		case CCIR_PEER_MSG_RIR:
			handle_peer_recv_rir(globals, ep, peer, event);
			break;
		case CCIR_PEER_MSG_RMA_INFO:
			handle_peer_recv_rma_info(globals, ep, peer, event);
			break;
		case CCIR_PEER_MSG_DEL:
			handle_peer_recv_del(globals, ep, peer, event);
			break;
		case CCIR_PEER_MSG_RMA_DONE:
			handle_peer_recv_rma_done(globals, ep, peer, event);
			break;
		default:
			debug(RDB_PEER, "%s: EP %p: unknown message type %d from "
					"%s with %d bytes", __func__, (void*)ep,
					CCIR_PEER_HDR_TYPE(hdr->generic.type),
					peer->uri, event->recv.len);
			break;
	}
}

static void
handle_e2e_recv_msg(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event, int flags)
{
	int ret = 0;
	cci_connection_t *c = NULL, *connection = event->recv.connection;
	ccir_rconn_t *rconn = connection->context;
	void *ctx = NULL;

	if (connection == rconn->src)
		c = rconn->dst;
	else
		c = rconn->src;

	if (!flags) {
		ctx = (void*)rconn;
		ctx = CCIR_SET_CTX(ctx, CCIR_CTX_RCONN);
	}

	ret = cci_send(c, event->recv.ptr, event->recv.len, ctx, flags);
	if (ret || flags == CCI_FLAG_BLOCKING)
		shutdown_rconn(rconn);

	return;
}

/* First stage of a RMA Write is to RMA Read the data to the first router */
static int
rma_read_from_initiator(ccir_globals_t *globals, ccir_ep_t *ep, ccir_rma_request_t *rma)
{
	int ret = 0;
	ccir_rconn_t *rconn = rma->rconn;
	cci_connection_t *c = NULL;
	cci_e2e_rma_request_t req = rma->e2e_req;

	req.net[8] = cci_e2e_ntohll(req.net[8]);
	req.net[9] = cci_e2e_ntohll(req.net[9]);
	req.net[10] = cci_e2e_ntohll(req.net[10]);

	if (rma->src_role == CCIR_RMA_INITIATOR)
		c = rconn->src;
	else
		c = rconn->dst;

	ret = cci_rma(c, NULL, 0,
			ep->h, (uint64_t) rma->idx * (uint64_t) globals->rma_buf->mtu,
			&rma->e2e_req.request.initiator, req.request.initiator_offset,
			req.request.len, CCIR_SET_CTX(rma, CCIR_CTX_RMA),
			CCI_FLAG_READ);

	return ret;
}

static int
rma_read_from_target(ccir_globals_t *globals, ccir_ep_t *ep, ccir_rma_request_t *rma)
{
	int ret = 0;
	ccir_rconn_t *rconn = rma->rconn;
	cci_connection_t *c = NULL;
	cci_rma_handle_t *h = NULL;
	cci_e2e_rma_request_t req = rma->e2e_req;

	req.net[8] = cci_e2e_ntohll(req.net[8]);
	req.net[9] = cci_e2e_ntohll(req.net[9]);
	req.net[10] = cci_e2e_ntohll(req.net[10]);

	if (rma->src_role == CCIR_RMA_TARGET) {
		c = rconn->src;
		h = rconn->sh;
	} else {
		c = rconn->dst;
		h = rconn->dh;
	}

	ret = cci_rma(c, NULL, 0,
			h, (uint64_t) rma->idx * (uint64_t) globals->rma_buf->mtu,
			&rma->e2e_req.request.target, req.request.target_offset,
			req.request.len, CCIR_SET_CTX(rma, CCIR_CTX_RMA),
			CCI_FLAG_READ);

	return ret;
}

/* Intermediate stage of a RMA Write is reading from the the preceding router */
static int
rma_read_from_router(ccir_globals_t *globals, ccir_ep_t *ep, ccir_rma_request_t *rma)
{
	int ret = 0;
	ccir_rconn_t *rconn = rma->rconn;
	ccir_peer_t *peer = NULL;
	cci_connection_t *c = NULL;
	ccir_peer_hdr_t hdr;
	uint32_t remote_index = 0;
	uint64_t remote_offset = 0;
	cci_e2e_rma_request_t req = rma->e2e_req;

	req.net[8] = cci_e2e_ntohll(req.net[8]);
	req.net[9] = cci_e2e_ntohll(req.net[9]);
	req.net[10] = cci_e2e_ntohll(req.net[10]);

	if (rma->src_role == CCIR_RMA_INITIATOR)
		c = rconn->src;
	else
		c = rconn->dst;

	peer = CCIR_CTX(c->context);

	remote_index = req.request.index;
	remote_offset = (uint64_t) peer->rma_mtu * (uint64_t) remote_index;

	ccir_pack_rma_done(&hdr, remote_index);

	ret = cci_rma(c, &hdr, sizeof(hdr),
			ep->h, (uint64_t) rma->idx * (uint64_t) globals->rma_buf->mtu,
			peer->h, remote_offset,
			req.request.len, CCIR_SET_CTX(rma, CCIR_CTX_RMA),
			CCI_FLAG_READ);

	return ret;
}

static int
rma_write(ccir_globals_t *globals, ccir_ep_t *ep, ccir_rma_request_t *rma)
{
	int ret = 0;

	debug(RDB_E2E, "%s: *** TODO ***", __func__);

	return ret;
}

static int
post_rma(ccir_globals_t *globals, ccir_ep_t *ep, ccir_rma_request_t *rma)
{
	int ret = 0;
	cci_e2e_hdr_t hdr;

	hdr.net[0] = ntohl(rma->e2e_hdr.net[0]);

	switch (hdr.rma.type) {
	case CCI_E2E_MSG_RMA_WRITE_REQ:
		if (!rma->final) {
			if ((rma->src_role == CCIR_RMA_INITIATOR &&
				(!CCIR_IS_PEER_CTX(rma->rconn->src->context))) ||
				(rma->dst_role == CCIR_RMA_INITIATOR &&
				 !CCIR_IS_PEER_CTX(rma->rconn->dst->context))) {

				ret = rma_read_from_initiator(globals, ep, rma);
			} else {
				ret = rma_read_from_router(globals, ep, rma);
			}
		} else { /* Final RMA to E2E client */
			ret = rma_write(globals, ep, rma);
		}
		break;
	case CCI_E2E_MSG_RMA_READ_REQ:
		ret = rma_read_from_target(globals, ep, rma);
		break;
	case CCI_E2E_MSG_RMA_READ_REPLY:
		if (!rma->final) {
			ret = rma_read_from_router(globals, ep, rma);
		} else {
			ret = rma_write(globals, ep, rma);
		}
		break;
	default:
		debug(RDB_E2E, "%s: rma has invalid type %s (%d)", __func__,
			cci_e2e_msg_type_str(hdr.rma.type), hdr.rma.type);
		ret = EINVAL;
		break;
	}

	return ret;
}

static void
handle_e2e_recv_rma_write_request(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int ret = 0;
	cci_connection_t *connection = event->recv.connection;
	ccir_rconn_t *rconn = connection->context;
	ccir_rma_buffer_t *rma_buf = globals->rma_buf;
	ccir_rma_request_t *rma = NULL;
	cci_e2e_hdr_t *e2e_hdr = (cci_e2e_hdr_t *) event->recv.ptr;
	cci_e2e_rma_request_t *e2e_req = (cci_e2e_rma_request_t *) &e2e_hdr->rma.data[0];

	/* Allocate request and store state */
	rma = calloc(1, sizeof(*rma));
	if (!rma) {
		/* TODO reply with RNR or disconnect? */
		return;
	}

	rma->e2e_hdr.net[0] = e2e_hdr->net[0];
	rma->e2e_req.request = e2e_req->request;
	rma->rconn = rconn;
	rma->idx = -1;

	if (connection == rconn->src) {
		rma->src_role = CCIR_RMA_INITIATOR;
		rma->dst_role = CCIR_RMA_TARGET;
	} else {
		rma->src_role = CCIR_RMA_TARGET;
		rma->dst_role = CCIR_RMA_INITIATOR;
	}

	/* Try to reserve a RMA buffer */
	pthread_mutex_lock(&rma_buf->lock);
	ret = reserve_rma_buffer_locked(rma_buf, rma);
	if (!ret) {
		/* Successful, issue RMA Read */
		pthread_mutex_unlock(&rma_buf->lock);

		ret = post_rma(globals, ep, rma);
		if (ret) {
			/* The RMA failed, release the buffer and queue for later */
			pthread_mutex_lock(&rma_buf->lock);
			release_rma_buffer_locked(rma_buf, rma);
			TAILQ_INSERT_TAIL(&rma_buf->reqs, rma, entry);
			pthread_mutex_unlock(&rma_buf->lock);
		}
	} else {
		/* None available, queue for later */
		TAILQ_INSERT_TAIL(&rma_buf->reqs, rma, entry);
		pthread_mutex_unlock(&rma_buf->lock);
		debug(RDB_E2E, "%s: no buffer for rma %p", __func__, rma);
	}

	return;
}

static void
handle_e2e_recv_rma_read_request(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int ret = 0, forward = 0;
	cci_connection_t *connection = event->recv.connection, *c = NULL;
	ccir_rconn_t *rconn = connection->context;
	ccir_rma_buffer_t *rma_buf = globals->rma_buf;
	ccir_rma_request_t *rma = NULL;
	cci_e2e_hdr_t *e2e_hdr = (cci_e2e_hdr_t *) event->recv.ptr;
	cci_e2e_rma_request_t *e2e_req = (cci_e2e_rma_request_t *) &e2e_hdr->rma.data[0];

	/* if next is router, then...
	 *   send RMA_READ_REQ
	 * else next is target, then...
	 *   reserve buffer
	 *   read from target's buffer
	 */

	if (connection == rconn->src) {
		if (CCIR_IS_PEER_CTX(rconn->dst->context)) {
			c = rconn->dst;
			forward = 1;
		}
	} else {
		if (CCIR_IS_PEER_CTX(rconn->src->context)) {
			c = rconn->src;
			forward = 1;
		}
	}

	if (forward) {
		ret = cci_send(c, event->recv.ptr, event->recv.len, NULL, 0);
		if (ret) {
			/* send NAK or disconnect? */
		}
		goto out;
	}

	/* Allocate request and store state */
	rma = calloc(1, sizeof(*rma));
	if (!rma) {
		/* TODO reply with RNR or disconnect? */
		return;
	}

	rma->e2e_hdr.net[0] = e2e_hdr->net[0];
	rma->e2e_req.request = e2e_req->request;
	rma->rconn = rconn;
	rma->idx = -1;

	if (connection == rconn->src) {
		rma->src_role = CCIR_RMA_INITIATOR;
		rma->dst_role = CCIR_RMA_TARGET;
	} else {
		rma->src_role = CCIR_RMA_TARGET;
		rma->dst_role = CCIR_RMA_INITIATOR;
	}

	/* Try to reserve a RMA buffer */
	pthread_mutex_lock(&rma_buf->lock);
	ret = reserve_rma_buffer_locked(rma_buf, rma);
	if (!ret) {
		/* Successful, issue RMA Read */
		pthread_mutex_unlock(&rma_buf->lock);

		ret = post_rma(globals, ep, rma);
		if (ret) {
			/* The RMA failed, release the buffer and queue for later */
			pthread_mutex_lock(&rma_buf->lock);
			release_rma_buffer_locked(rma_buf, rma);
			TAILQ_INSERT_TAIL(&rma_buf->reqs, rma, entry);
			pthread_mutex_unlock(&rma_buf->lock);
		}
	} else {
		/* None available, queue for later */
		TAILQ_INSERT_TAIL(&rma_buf->reqs, rma, entry);
		pthread_mutex_unlock(&rma_buf->lock);
		debug(RDB_E2E, "%s: no buffer for rma %p", __func__, rma);
	}

    out:
	return;
}

static void
adjust_e2e_mss_rma_mtu(ccir_globals_t *globals, ccir_rconn_t *rconn, cci_e2e_hdr_t *hdr)
{
	uint16_t mss = 0;
	uint32_t mtu = 0;

	hdr->net[0] = ntohl(hdr->net[0]);
	hdr->net[1] = ntohl(hdr->net[1]);
	mss = hdr->conn_reply.mss;
	if (rconn->src->max_send_size < mss)
		mss = rconn->src->max_send_size;
	if (rconn->dst->max_send_size < mss)
		mss = rconn->dst->max_send_size;
	mtu = hdr->conn_reply.rma_mtu;
	if (globals->rma_buf->mtu < mtu)
		mtu = globals->rma_buf->mtu;
	hdr->conn_reply.mss = mss;
	hdr->conn_reply.rma_mtu = mtu;
	hdr->net[0] = htonl(hdr->net[0]);
	hdr->net[1] = htonl(hdr->net[1]);

	return;
}

static void
handle_e2e_recv(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	cci_connection_t *connection = event->recv.connection;
	ccir_rconn_t *rconn = connection->context;
	cci_e2e_hdr_t *hdr = (void*) event->recv.ptr;
	cci_e2e_msg_type_t type = 0;

	hdr->net[0] = ntohl(hdr->net[0]);
	type = hdr->generic.type;
	hdr->net[0] = htonl(hdr->net[0]);

	if (verbose)
		debug(RDB_E2E, "%s: got %s from %s", __func__, cci_e2e_msg_type_str(type),
			connection == rconn->src ? rconn->client_uri : rconn->server_uri);

	switch (type) {
	case CCI_E2E_MSG_CONN_REPLY:
		adjust_e2e_mss_rma_mtu(globals, rconn, hdr);
	case CCI_E2E_MSG_CONN_ACK:
	case CCI_E2E_MSG_SEND:
	case CCI_E2E_MSG_SEND_ACK:
	case CCI_E2E_MSG_SEND_ACK_MANY:
	case CCI_E2E_MSG_SEND_SACK:
	case CCI_E2E_MSG_SEND_NACK:
		/* arrive on src, forward to dst or
		 * arrive on dst, forward to src */
		handle_e2e_recv_msg(globals, ep, event, 0);
		break;
	case CCI_E2E_MSG_BYE:
		/* forward it, block, then shutdown */
		handle_e2e_recv_msg(globals, ep, event, CCI_FLAG_BLOCKING);
		break;
	case CCI_E2E_MSG_RMA_WRITE_REQ:
		handle_e2e_recv_rma_write_request(globals, ep, event);
		break;
	case CCI_E2E_MSG_RMA_READ_REQ:
		handle_e2e_recv_rma_read_request(globals, ep, event);
		break;
	default:
		debug(RDB_E2E, "%s: unhandled %s msg", __func__,
				cci_e2e_msg_type_str(type));
		break;
	}

	return;
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
	int is_peer = CCIR_IS_PEER_CTX(connection->context);

	if (is_peer) {
		handle_peer_recv(globals, ep, event);
	} else {
		handle_e2e_recv(globals, ep, event);
	}
	return;
}

static void
handle_e2e_send_msg(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	ccir_rconn_t *rconn = CCIR_CTX(event->send.context);

	if (event->send.status != CCI_SUCCESS) {
		char *uri = NULL;

		if (rconn) {
			if (event->send.connection == rconn->src)
				uri = rconn->client_uri;
			else
				uri = rconn->server_uri;
		}

		debug(RDB_E2E, "%s: EP %p: MSG to %s failed with %s", __func__,
			(void*)ep, uri, cci_strerror(ep->e, event->send.status));

		if (rconn)
			shutdown_rconn(rconn);
	}
	return;
}

/* The RMA Read from the initiator or previous router has completed,
 * progress this E2E RMA Write.
 */
static void
handle_e2e_send_rma_write(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int ret = 0, next_is_router = 0;
	ccir_rma_request_t *rma = CCIR_CTX(event->send.context);
	cci_e2e_rma_request_t *e2e_req = &rma->e2e_req;
	cci_connection_t *c = NULL;
	cci_rma_handle_t *h = NULL;
	const char *init = NULL, *target = NULL;
	struct iovec iov[2];

	/* if next is router, then...
	 *   send RMA_WRITE_REQ
	 * else next is target, then...
	 *   if !final, then...
	 *     write to target's buffer
	 *     set final
	 *   else is final, then...
	 *     send RMA_ACK with status
	 */

	if (rma->src_role == CCIR_RMA_TARGET) {
		target = rma->rconn->client_uri;
		init = rma->rconn->server_uri;

		if (CCIR_IS_PEER_CTX(rma->rconn->src->context)) {
			next_is_router = 1;
			c = rma->rconn->src;
		} else {
			if (!rma->final) {
				c = rma->rconn->src;
				h = rma->rconn->sh;
			} else {
				c = rma->rconn->dst;
				h = rma->rconn->dh;
			}
		}
	} else {
		init = rma->rconn->client_uri;
		target = rma->rconn->server_uri;

		if (CCIR_IS_PEER_CTX(rma->rconn->dst->context)) {
			next_is_router = 1;
			c = rma->rconn->dst;
		} else {
			if (!rma->final) {
				c = rma->rconn->dst;
				h = rma->rconn->dh;
			} else {
				c = rma->rconn->src;
				h = rma->rconn->sh;
			}
		}
	}

	if (next_is_router) {
		/* Send RMA_WRITE_REQ to router */

		iov[0].iov_base = &rma->e2e_hdr;
		iov[0].iov_len = sizeof(rma->e2e_hdr);
		iov[1].iov_base = &e2e_req->request;
		iov[1].iov_len = sizeof(e2e_req->request);

		e2e_req->net[10] = cci_e2e_ntohll(e2e_req->net[10]);
		e2e_req->request.index = rma->idx;
		e2e_req->net[10] = cci_e2e_htonll(e2e_req->net[10]);
		ret = cci_sendv(c, iov, 2, CCIR_SET_CTX(rma, CCIR_CTX_RMA), 0);
		if (ret) {
			debug(RDB_E2E, "%s: forwarding RMA Write request for rconn %p "
				"(init/target %s/%s) failed with %s", __func__,
				(void*)rma->rconn, init, target, cci_strerror(ep->e, ret));
		}
	} else {
		if (!rma->final) {
			/* RMA Write to E2E target's buffer */

			uint64_t offset = (uint64_t)rma->idx *
				(uint64_t) globals->rma_buf->mtu;
			cci_e2e_rma_request_t req = *e2e_req;

			req.net[8] = cci_e2e_ntohll(req.net[8]);
			req.net[9] = cci_e2e_ntohll(req.net[9]);
			req.net[10] = cci_e2e_ntohll(req.net[10]);

			rma->final = 1;

			ret = cci_rma(c, NULL, 0, h, offset,
					&e2e_req->request.target,
					req.request.target_offset,
					req.request.len,
					CCIR_SET_CTX(rma, CCIR_CTX_RMA), CCI_FLAG_WRITE);
			if (ret) {
				/* TODO
				 * debug()
				 * free(rma)
				 * disconnect()?
				 */
			}
		} else {
			/* Send RMA_ACK to E2E initiator */

			cci_e2e_hdr_t *hdr = &rma->e2e_hdr;

			pthread_mutex_lock(&globals->rma_buf->lock);
			release_rma_buffer_locked(globals->rma_buf, rma);
			pthread_mutex_unlock(&globals->rma_buf->lock);

			hdr->net[0] = ntohl(hdr->net[0]);
			hdr->rma.type = CCI_E2E_MSG_RMA_ACK;
			hdr->net[0] = htonl(hdr->net[0]);

			e2e_req->net[10] = cci_e2e_ntohll(e2e_req->net[10]);
			e2e_req->request.index = 0;
			e2e_req->net[10] = cci_e2e_htonll(e2e_req->net[10]);

			iov[0].iov_base = &rma->e2e_hdr;
			iov[0].iov_len = sizeof(rma->e2e_hdr.rma_size);
			iov[1].iov_base = &e2e_req->request;
			iov[1].iov_len = sizeof(e2e_req->request);

			ret = cci_sendv(c, iov, 2, NULL, CCI_FLAG_SILENT);
			if (ret) {
				debug(RDB_E2E, "%s: sending RMA_ACK for rconn %p "
					"(init/target %s/%s) failed with %s", __func__,
					(void*)rma->rconn, init, target,
					cci_strerror(ep->e, ret));
			}
			/* TODO cleanup */
			free(rma);
		}
	}
	return;
}

/* The RMA Read from the target or previous router has completed,
 * progress the E2E RMA Read.
 */
static void
handle_e2e_send_rma_read(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int ret = 0, next_is_router = 0;
	ccir_rma_request_t *rma = CCIR_CTX(event->send.context);
	cci_e2e_hdr_t *e2e_hdr = &rma->e2e_hdr;
	cci_e2e_rma_request_t *e2e_req = &rma->e2e_req;
	cci_connection_t *c = NULL;
	cci_rma_handle_t *h = NULL;
	const char *init = NULL, *target = NULL;
	struct iovec iov[2];

	/* if next is router, then...
	 *   send RMA_READ_REPLY
	 * else next is inititator, then...
	 *   write to initiator's buffer with RMA_ACK
	 */

	if (rma->src_role == CCIR_RMA_INITIATOR) {
		init = rma->rconn->client_uri;
		target = rma->rconn->server_uri;

		if (CCIR_IS_PEER_CTX(rma->rconn->src->context))
			next_is_router = 1;

		c = rma->rconn->src;
		h = rma->rconn->sh;
	} else {
		init = rma->rconn->server_uri;
		target = rma->rconn->client_uri;

		if (CCIR_IS_PEER_CTX(rma->rconn->dst->context))
			next_is_router = 1;

		c = rma->rconn->dst;
		h = rma->rconn->dh;
	}

	if (rma->final) {
		/* We are done, free and exit */
		free(rma);
		goto out;
	}

	if (next_is_router) {
		/* Send RMA_READ_REPLY to router */

		iov[0].iov_base = &rma->e2e_hdr;
		iov[0].iov_len = sizeof(rma->e2e_hdr);
		iov[1].iov_base = &e2e_req->request;
		iov[1].iov_len = sizeof(e2e_req->request);

		e2e_hdr->net[0] = ntohl(e2e_hdr->net[0]);
		e2e_hdr->rma.type = CCI_E2E_MSG_RMA_READ_REPLY;
		e2e_hdr->net[0] = htonl(e2e_hdr->net[0]);

		e2e_req->net[10] = cci_e2e_ntohll(e2e_req->net[10]);
		e2e_req->request.index = rma->idx;
		e2e_req->net[10] = cci_e2e_htonll(e2e_req->net[10]);
		ret = cci_sendv(c, iov, 2, NULL, 0);
		if (ret) {
			debug(RDB_E2E, "%s: forwarding RMA Read Reply for rconn %p "
				"(init/target %s/%s) failed with %s", __func__,
				(void*)rma->rconn, init, target, cci_strerror(ep->e, ret));
		}
		free(rma);
	} else {
		/* RMA Write to E2E initiator's buffer */
		uint64_t offset = (uint64_t)rma->idx * (uint64_t) globals->rma_buf->mtu;
		cci_e2e_rma_request_t req = *e2e_req;
		char ack[96];
		int len = 0;

		req.net[8] = cci_e2e_ntohll(req.net[8]);
		req.net[9] = cci_e2e_ntohll(req.net[9]);
		req.net[10] = cci_e2e_ntohll(req.net[10]);

		rma->final = 1;

		memcpy(ack, &e2e_hdr->net[0], sizeof(e2e_hdr->net[0]));
		e2e_hdr = (void*) ack;
		e2e_hdr->net[0] = ntohl(e2e_hdr->net[0]);
		e2e_hdr->rma.type = CCI_E2E_MSG_RMA_ACK;
		e2e_hdr->net[0] = htonl(e2e_hdr->net[0]);

		len = sizeof(e2e_hdr->rma_size);

		memcpy(&e2e_hdr->rma.data, e2e_req, sizeof(*e2e_req));

		len += sizeof(*e2e_req);

		ret = cci_rma(c, ack, len, h, offset,
				&e2e_req->request.initiator,
				req.request.initiator_offset,
				req.request.len,
				CCIR_SET_CTX(rma, CCIR_CTX_RMA), CCI_FLAG_WRITE);
		if (ret) {
			/* TODO
			 * debug()
			 * free(rma)
			 * disconnect()?
			 */
		}
	}

    out:
	return;
}

static void
handle_e2e_send_rma(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	ccir_rma_request_t *rma = CCIR_CTX(event->send.context);
	cci_e2e_hdr_t hdr;
	char *uri = NULL;

	hdr.net[0] = ntohl(rma->e2e_hdr.net[0]);

	if (rma->rconn) {
		if (event->send.connection == rma->rconn->src)
			uri = rma->rconn->client_uri;
		else
			uri = rma->rconn->server_uri;
	}

	if (event->send.status != CCI_SUCCESS) {
		/* TODO free RMA op */

		debug(RDB_E2E, "%s: EP %p: %s from %s failed with %s", __func__,
			(void*)ep, cci_e2e_msg_type_str(hdr.rma.type),
			uri, cci_strerror(ep->e, event->send.status));

		shutdown_rconn(rma->rconn);

		free(rma);
		goto out;
	}

	switch (hdr.rma.type) {
	case CCI_E2E_MSG_RMA_WRITE_REQ:
		handle_e2e_send_rma_write(globals, ep, event);
		break;
	case CCI_E2E_MSG_RMA_READ_REQ:
	case CCI_E2E_MSG_RMA_READ_REPLY:
		handle_e2e_send_rma_read(globals, ep, event);
		break;
	default:
		debug(RDB_E2E, "%s: EP %p: Unhandled %s from %s", __func__,
			(void*)ep, cci_e2e_msg_type_str(hdr.rma.type), uri);
	}

    out:
	return;
}

static void
handle_send(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int type = CCIR_CTX_TYPE(event->send.context);

	switch (type) {
	case CCIR_CTX_RCONN:
		handle_e2e_send_msg(globals, ep, event);
		break;
	case CCIR_CTX_RMA:
		handle_e2e_send_rma(globals, ep, event);
		break;
	default:
		debug(RDB_E2E, "%s: EP %p: unknown send type %d", __func__,
			(void*)ep, type);
		abort();
		break;
	}

	return;
}

static int
handle_event(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int ret = 0, up = 0;
	uint32_t i = 0;

	if (verbose)
		debug(RDB_EP, "%s: EP %p: got %s", __func__, (void*)ep,
			cci_event_type_str(event->type));

	switch (event->type) {
	case CCI_EVENT_SEND:
		handle_send(globals, ep, event);
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
					if (verbose) {
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
			if (ret && verbose)
				debug(RDB_EP, "%s: cci_return_event() failed with %s",
						__func__, cci_strerror(ep->e, ret));
		}
	} while (found && !globals->shutdown);
    out:
	return ret;
}

#define CCIR_SEND_RIR_TIME	(300)	/* seconds */

static void
event_loop(ccir_globals_t *globals)
{
	int ret = 0, resend_period = 0;
	struct timeval old, current;

	running = 1;

	/* add variation to resend time to avoid resent storms.
	 * resend_period up to +-25% of CCIR_SEND_RIR_TIME
	 */
	resend_period = (int) random() % (CCIR_SEND_RIR_TIME / 2);
	resend_period -= CCIR_SEND_RIR_TIME / 4;

	ret = install_sig_handlers(globals);
	if (ret)
		goto out;

	gettimeofday(&old, NULL);

	while (running) {
		connect_peers(globals);
		get_event(globals);
		gettimeofday(&current, NULL);

		if ((int)(current.tv_sec - old.tv_sec) >
				(CCIR_SEND_RIR_TIME + resend_period)) {
			old = current;
			send_all_rir(globals);

			resend_period = (int) random() % (CCIR_SEND_RIR_TIME / 2);
			resend_period -= CCIR_SEND_RIR_TIME / 4;
		}
	}

	/* Notify peers we are no longer routing */
	disconnect_peers(globals);

	if (verbose)
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
		if (verbose)
			debug(RDB_CONFIG, "Cannot access config file %s due to \"%s\".",
				fname, strerror(ret));
	} else if (buf.st_size == 0) {
		ret = EINVAL;
		if (verbose)
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
				if (verbose)
					debug(RDB_CONFIG, "Replacing CCI_CONFIG=%s with %s",
						cci_config, config_option);
			}
			ret = setenv("CCI_CONFIG", config_option, overwrite);
			if (ret) {
				ret = errno; /* ENOMEM */
				if (verbose)
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
				if (verbose)
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
						if (verbose)
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
				if (verbose)
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

	if (verbose)
		debug(RDB_EP, "Entering %s", __func__);

	if (!globals->eps)
		return;

	for (i = 0; i < globals->ep_cnt; i++) {
		ccir_ep_t *ep = globals->eps[i];

		if (!ep)
			break;

		if (ep->e) {
			int rc = 0;

			if (ep->h) {
				rc = cci_rma_deregister(ep->e, ep->h);
				if (rc) {
					debug(RDB_EP, "%s: cci_rma_deregister() "
							"failed with %s",
							__func__, cci_strerror(ep->e, rc));
				}
			}

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

	if (verbose)
		debug(RDB_EP, "Leaving %s", __func__);

	return;
}

static int
open_endpoints(ccir_globals_t *globals)
{
	int ret = 0, i = 0, cnt = 0;
	cci_device_t * const *devs = NULL, * const *d = NULL;
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
	for (d = devs; *d; d++) {
		int j = 0, as = 0, subnet = 0, router = 0;
		const char *arg = NULL;
		ccir_ep_t *ep = NULL;
		ccir_peer_t *peer = NULL;
		cci_os_handle_t *fd = NULL;

		if (0 == strcmp((*d)->transport, "e2e"))
			continue;

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

		if ((*d)->conf_argv) {
		for (j = 0; ;j++) {
			arg = (*d)->conf_argv[j];
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
						__func__, (*d)->name, router, arg);
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
		}

		if (!as || !subnet) {
			debug(RDB_EP, "Device [%s] is missing keyword/values "
					"for as= and/or subnet=", (*d)->name);
			ret = EINVAL;
			goto out;
		} else if ((as > 1) || (subnet > 1)) {
			debug(RDB_EP, "Device [%s] has more than one keyword/value "
					"for as= or subnet=", (*d)->name);
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

		ret = cci_create_endpoint(*d, 0, &(ep->e), fd);
		if (ret) {
			debug(RDB_EP, "Unable to create endpoint "
					"on device %s (%s)",
					(*d)->name,
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
				__func__, (*d)->name, ep->uri);
			ret = EINVAL;
			goto out;
		}

		/* Register rma_buf */
		ret = cci_rma_register(ep->e, globals->rma_buf->base,
				(uint64_t)globals->rma_buf->mtu *
				(uint64_t)globals->rma_buf->cnt,
				CCI_FLAG_READ|CCI_FLAG_WRITE, &(ep->h));
		if (ret)
			goto out;

		MurmurHash3_x86_32(ep->uri, strlen(ep->uri), hash, (void *) &hash);

		if (verbose)
			debug(RDB_EP, "%s: opened %s on device %s", __func__,
					ep->uri, (*d)->name);

		i++;
	}

	cnt = i;
	for (i = 0; i < cnt; i++) {
		ccir_ep_t *ep = es[i];
		uint32_t rate = 0;
		ccir_router_t *rp = NULL;
		ccir_subnet_t *sp = NULL;
		int unused = 0;

		ret = add_router_to_topo(globals->topo, hash, globals->instance,
				ep->subnet, &rp, &unused);
		assert(ret == 0);

		rate = ep->e->device->rate / 1000000000;
		if (!rate)
			rate = 1;

		ret = add_subnet_to_topo(globals->topo, ep->subnet, rate,
				hash, &sp, &unused);
		assert(ret == 0);

		ret = add_pairs(globals->topo, sp, rp);
		assert(ret == 0);
	}

	if (cnt < 2)
		debug(RDB_ALL, "Unable to route with %d endpoint%s.",
				cnt, cnt == 0 ? "s" : "");

	if (verbose) {
		debug(RDB_EP, "%s: globals->id = 0x%x", __func__, hash);
		print_routes(globals->topo);
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
	int ret = 0, c = 0, i = 0;
	char *config_file = NULL;
	uint32_t caps = 0;
	ccir_globals_t *globals = NULL;
	ccir_topo_t *topo = NULL;
	ccir_rma_buffer_t *rma_buf = NULL;
	struct timeval t;

	globals = calloc(1, sizeof(*globals));
	if (!globals) {
		ret = ENOMEM;
		goto out;
	}

	srandom(getpid());

	gettimeofday(&t, NULL);
	globals->instance = t.tv_sec;

	topo = calloc(1, sizeof(*topo));
	if (!topo) {
		ret = ENOMEM;
		goto out;
	}
	globals->topo = topo;

	globals->topo->metric = CCIR_METRIC_BW; /* FIXME: make configurable */

	rma_buf = calloc(1, sizeof(*rma_buf));
	if (!rma_buf) {
		ret = ENOMEM;
		goto out;
	}
	globals->rma_buf = rma_buf;

	pthread_mutex_init(&rma_buf->lock, NULL);
	TAILQ_INIT(&rma_buf->reqs);
	rma_buf->mtu = CCIR_RMA_MTU;
	rma_buf->cnt = CCIR_RMA_CNT;

	while ((c = getopt(argc, argv, "f:vbl:n:")) != -1) {
		switch (c) {
		case 'f':
			config_file = strdup(optarg);
			if (!config_file) {
				debug(RDB_CONFIG, "%s", "Unable to store file name "
						"- no memory");
				exit(EXIT_FAILURE);
			}
			break;
		case 'l':
			rma_buf->mtu = strtol(optarg, NULL, 0);
			break;
		case 'n':
			rma_buf->cnt = strtol(optarg, NULL, 0);
			break;
		case 'v':
			verbose++;
			break;
		case 'b':
			globals->blocking = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	debug = RDB_ALL;

	ret = get_config(globals, argv[0], config_file);
	if (ret) {
		exit(EXIT_FAILURE);
	}

	ret = posix_memalign(&rma_buf->base, sysconf(_SC_PAGESIZE),
			rma_buf->mtu * rma_buf->cnt);
	if (ret) {
		debug(RDB_ALL, "Unable to allocate RMA buffer because %s", strerror(ret));
		goto out;
	}

	rma_buf->num_blocks = rma_buf->cnt / (sizeof(*rma_buf->ids) * 8);
	if ((rma_buf->num_blocks * (sizeof(*rma_buf->ids) * 8)) != rma_buf->cnt)
		rma_buf->num_blocks++;

	rma_buf->ids = calloc(rma_buf->num_blocks, sizeof(*rma_buf->ids));
	if (!rma_buf->ids) {
		ret = ENOMEM;
		goto out;
	}

	/* Set bits for available fragments - use ffsll() to  find available */
	for (i = 0; i < rma_buf->num_blocks; i++) {
		memset(&rma_buf->ids[i], ~0ULL, sizeof(rma_buf->ids[i]));
		if ((i == rma_buf->num_blocks - 1) && (rma_buf->cnt !=
			(rma_buf->num_blocks * sizeof(rma_buf->ids[i]) * 8))) {

			/* The count is not a multiple of the block size,
			 * shift off the bits to unset them.
			 */

			int shift = rma_buf->num_blocks * sizeof(*rma_buf->ids) * 8;

			shift -= rma_buf->cnt;
			rma_buf->ids[i] <<= shift; /* shift bits off the high end */
			rma_buf->ids[i] >>= shift; /* shift back */
		}
	}

	rma_buf->rmas = calloc(rma_buf->cnt, sizeof(*rma_buf->rmas));
	if (!rma_buf->rmas) {
		ret = ENOMEM;
		goto out;
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

	if (verbose)
		debug(RDB_ALL, "%s is done", argv[0]);

    out:
	if (rma_buf) {
		free(rma_buf->rmas);
		free(rma_buf->ids);
		free(rma_buf->base);
		pthread_mutex_destroy(&rma_buf->lock);
		free(rma_buf);
	}

	if (topo) {
		if (topo->num_pairs) {
			uint32_t i = 0;

			for (i = 0; i < topo->num_pairs; i++) {
				ccir_pair_t *pair = topo->pairs[i];

				free(pair->routers);
				free(pair);
			}
			free(topo->pairs);
		}
		if (topo->num_subnets) {
			uint32_t i = 0;

			for (i = 0; i < topo->num_subnets; i++) {
				ccir_subnet_t *subnet = topo->subnets[i];

				free(subnet->routers);
				free(subnet);
			}
			free(topo->subnets);
		}
		if (topo->num_routers) {
			uint32_t i = 0;

			for (i = 0; i < topo->num_routers; i++) {
				ccir_router_t *router = topo->routers[i];

				free(router->subnets);
				free(router->pairs);
				free(router);
			}
			free(topo->routers);
			topo->num_routers = 0;
		}
		free(topo);
	}
	free(globals);

	return ret;
}
