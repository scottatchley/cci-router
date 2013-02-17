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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include <sys/param.h>
#include <signal.h>
#include <sys/select.h>

#include "cci-router.h"

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
		fprintf(stderr, "%s: sigaction failed with %s\n",
				__func__, strerror(ret));
	return ret;
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
			uint8_t len = strlen(ep->uri);

			if (peer->state != CCIR_PEER_INIT ||
				peer->next_attempt > now.tv_sec)
				continue;

			if (globals->verbose)
				fprintf(stderr, "%s: ep %s to peer %s\n",
					__func__, ep->uri, peer->uri);

			peer->state = CCIR_PEER_ACTIVE;
			peer->attempts++;

			hdr = (void*)buffer;
			hdr->connect.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_CONNECT);
			hdr->connect.version = 1;
			hdr->connect.len = len;
			hdr->connect.cookie = ep->cookie;
			memcpy(hdr->connect.data, ep->uri, hdr->connect.len);

			len += sizeof(hdr->_connect);

			ret = cci_connect(ep->e, peer->uri,
					buffer,
					len,
					CCI_CONN_ATTR_RO,
					CCIR_SET_PEER_CTX(peer),
					0, &t);
			if (ret) {
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
	int ret = 0;
	uint32_t i = 0;
	char uri[256];
	const ccir_peer_hdr_t *hdr = (void*)event->request.data_ptr;

	memset(uri, 0, 256);
	memcpy(uri, hdr->connect.data, hdr->connect.len);

	if (event->request.attribute != CCI_CONN_ATTR_RO) {
		fprintf(stderr, "%s: received request with connection "
				"attribute %d from %s\n", __func__,
				event->request.attribute, uri);
		goto out;
	}

	if (globals->verbose)
		fprintf(stderr, "%s: received connection request "
				"from %s\n", __func__, uri);

	/* Find matching peer */
	for (i = 0; i < ep->peer_cnt; i++) {
		ccir_peer_t *peer = ep->peers[i];

		if (!strcmp(uri, peer->uri)) {
			if (peer->state == CCIR_PEER_ACTIVE) {
				fprintf(stderr, "%s: connection race detected with "
						"%s\n", __func__, peer->uri);
				/* Accept and we will sort it out later */
			}
			if (peer->cookie && (peer->cookie != hdr->connect.cookie)) {
				fprintf(stderr, "%s: replacing peer %s's ccokie "
						"0x%x with 0x%x\n", __func__,
						peer->uri, peer->cookie,
						hdr->connect.cookie);
			}
			peer->cookie = hdr->connect.cookie;

			if (peer->cookie < ep->cookie) {
				/* Accept the connection request */
				if (globals->verbose) {
					fprintf(stderr, "%s: accepting passive conn "
							"from %s\n", __func__,
							peer->uri);
				}
				ret = cci_accept(event, CCIR_SET_PEER_CTX(peer));
				if (ret) {
					fprintf(stderr, "%s: cci_accept() failed %s\n",
							__func__, cci_strerror(ep->e, ret));
				}
			} else {
				if (globals->verbose) {
					fprintf(stderr, "%s: rejecting passive conn "
							"from %s\n", __func__,
							peer->uri);
				}
				ret = cci_reject(event);
				if (ret) {
					fprintf(stderr, "%s: cci_reject() failed %s\n",
							__func__, cci_strerror(ep->e, ret));
				}
			}
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
	const ccir_peer_hdr_t *hdr = (void*)event->request.data_ptr;
	int is_peer = CCIR_IS_PEER_HDR(hdr->connect.type);

	if (is_peer) {
		handle_peer_connect_request(globals, ep, event);
	} else {
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
	void *ctx = CCIR_CTX(event->accept.context);

	if (peer_accept) {
		ccir_peer_t *peer = ctx;

		if (event->accept.status == CCI_SUCCESS) {
			if (peer->state == CCIR_PEER_PASSIVE)
				peer->state = CCIR_PEER_CONNECTED;
			peer->p = event->accept.connection;
			ep->need_connect--;

			if (globals->verbose)
				fprintf(stderr, "%s: accepted %s on endpoint %s (%s) "
						"(c=%p p=%p)\n",
						__func__, peer->uri, ep->uri,
						ccir_peer_state_str(peer->state),
						(void*)peer->c, (void*)peer->p);
			/* TODO exchange routing table */
		} else {
			fprintf(stderr, "%s: accept event for %s returned %s\n",
				__func__, peer->uri,
				cci_strerror(ep->e, event->accept.status));
		}
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

		if (event->connect.status == CCI_SUCCESS) {
			peer->c = event->connect.connection;
			if (peer->state == CCIR_PEER_ACTIVE)
				peer->state = CCIR_PEER_CONNECTED;
			else
				fprintf(stderr, "%s: peer %s got connect event while "
						"in state %s", __func__, peer->uri,
						ccir_peer_state_str(peer->state));

			ep->need_connect--;

			if (globals->verbose)
				fprintf(stderr, "%s: connected to %s on endpoint %s (%s) "
						"(c=%p p=%p)\n",
						__func__, peer->uri, ep->uri,
						ccir_peer_state_str(peer->state),
						(void*)peer->c, (void*)peer->p);
			/* TODO add to known peers, exchange routing table */
		} else {
			struct timeval now = { 0, 0 };

			if (event->connect.status == CCI_ECONNREFUSED && peer->p) {
				if (peer->state != CCIR_PEER_CONNECTED) {
					fprintf(stderr, "%s: peer %s rejected "
							"active connect and we have "
							"passive conn %p, but "
							"peer->state is %s.***\n",
							__func__, peer->uri,
							(void*)peer->p,
							ccir_peer_state_str(peer->state));
					/* FIXME */
				} else {
					/* Move peer->p to peer->c */
					fprintf(stderr, "%s: moving peer %s's passive conn "
							"to active conn ***\n", __func__,
							peer->uri);
					peer->c = peer->p;
					peer->p = NULL;
				}
			}

			gettimeofday(&now, NULL);
			peer->state = CCIR_PEER_INIT;
			/* Set the next attempt to now + 2^N
			 * where N is the number of attempts.
			 * This provides an exponential backoff.
			 */
			peer->next_attempt = now.tv_sec + (1 << peer->attempts);

			if (event->connect.status == CCI_ECONNREFUSED) {
				fprintf(stderr, "%s: peer %s refused a connection "
						"from endpoint %s\n", __func__,
						peer->uri, ep->uri);
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
handle_event(ccir_globals_t *globals, ccir_ep_t *ep, cci_event_t *event)
{
	int ret = 0, up = 0;
	uint32_t i = 0;

	switch (event->type) {
	case CCI_EVENT_SEND:
		break;
	case CCI_EVENT_RECV:
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

		fprintf(stderr, "%s: endpoint %s on device %s returned "
				"device failed event.\nUnable to continue "
				"routing using this endpoint.\n", __func__,
				ep->uri, ep->e->device->name);

		/* Try to keep routing if >=2 endpoints are still up */
		for (i = 0; i < globals->ep_cnt; i++) {
			ccir_ep_t *e = globals->eps[i];
			if (!e->failed)
				up++;
		}
		if (up < 2) {
			globals->shutdown = 1;
			fprintf(stderr, "%s: Unable to route with %d endpoint%s up.\n"
					"Shutting down.\n", __func__,
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
						fprintf(stderr, "%s: Need to return "
								"recv events for CCI "
								"endpoint %s\n",
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
				fprintf(stderr, "%s: cci_return_event() failed with %s\n",
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

	if (globals->verbose)
		fprintf(stderr, "Exiting %s\n", __func__);
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
			fprintf(stderr, "Cannot access config file %s due to \"%s\".\n",
				fname, strerror(ret));
	} else if (buf.st_size == 0) {
		ret = EINVAL;
		if (globals->verbose)
			fprintf(stderr, "Config file %s is empty.\n", fname);
	}
	return ret;
}

/* Hierarchy of config processing:
 * 1. Command line options
 * 2. Command line config file
 * 3. CCI_CONFIG environment variable
 * 4. Local config file ($PWD/ccir_config)
 * 5. CCIR installed config file (/$INSTALL_PATH/etc/ccir/config)
 * 6. Global config file (/etc/ccir/config)
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
					fprintf(stderr, "Replacing CCI_CONFIG=%s with %s\n",
						cci_config, config_option);
			}
			ret = setenv("CCI_CONFIG", config_option, overwrite);
			if (ret) {
				ret = errno; /* ENOMEM */
				if (globals->verbose)
					fprintf(stderr, "Unable to setenv(CCI_CONFIG) (%s)\n",
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
					fprintf(stderr, "Unable to setenv(CCI_CONFIG) (%s)\n",
						strerror(ret));
			}
			done = 1;
		}
	}

	/* check for installed config */
	if (!done) {
		char *installdir = NULL, *bindir = NULL, fname[MAXPATHLEN];
		char *etcdir = "/etc/ccir/config";

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
							fprintf(stderr, "Unable to setenv"
								"(CCI_CONFIG) (%s)\n",
								strerror(ret));
					}
					done = 1;
				}
			}
		}
	}

	/* check for global config */
	if (!done) {
		char *fname = "/etc/ccir/config";

		ret = check_file(globals, fname);
		if (!ret) {
			ret = setenv("CCI_CONFIG", fname, 0);
			if (ret) {
				ret = errno; /* ENOMEM */
				if (globals->verbose)
					fprintf(stderr, "Unable to setenv(CCI_CONFIG) (%s)\n",
						strerror(ret));
			}
			done = 1;
		}
	}

	if (!done || ret) {
		fprintf(stderr, "Unable to find configuration file.\n");
		fprintf(stderr, "Precedence of config file processing:\n");
		fprintf(stderr, "1. Command line config file option -f <file>\n");
		fprintf(stderr, "2. CCI_CONFIG environment variable\n");
		fprintf(stderr, "3. Local config file ($PWD/ccir_config)\n");
		fprintf(stderr, "4. CCIR installed config file "
				"(/$INSTALL_PATH/etc/ccir/config)\n");
		fprintf(stderr, "5. Global config file (/etc/ccir/config)\n");
	}

	return ret;
}

static void
close_endpoints(ccir_globals_t *globals)
{
	uint32_t i = 0;

	if (globals->verbose)
		fprintf(stderr, "Entering %s\n", __func__);

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
				fprintf(stderr, "%s: cci_destroy_endpoint() "
						"failed with %s\n",
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
		free(ep);
	}
	free(globals->eps);

	if (globals->verbose)
		fprintf(stderr, "Leaving %s\n", __func__);

	return;
}

static int
open_endpoints(ccir_globals_t *globals)
{
	int ret = 0, i = 0, cnt = 0;
	cci_device_t * const *devs = NULL;
	ccir_ep_t **es = NULL;

	ret = cci_get_devices(&devs);
	if (ret) {
		fprintf(stderr, "Failed to get devices with %s\n",
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
		fprintf(stderr, "Failed to alloc endpoints\n");
		ret = ENOMEM;
		goto out;
	}

	srandomdev();

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

		ep->cookie = (uint32_t) random();

		if (!as || !subnet || !router) {
			fprintf(stderr, "Device [%s] is missing keyword/values "
					"for as=, subnet=, and/or router=\n", d->name);
			ret = EINVAL;
			goto out;
		} else if ((as > 1) || (subnet > 1)) {
			fprintf(stderr, "Device [%s] has more than one keyword/value "
					"for as= or subnet=\n", d->name);
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
			fprintf(stderr, "Unable to create endpoint "
					"on device %s (%s)\n",
					devs[i]->name,
					cci_strerror(NULL, ret));
			goto out;
		}
		*((void**)&(ep->e->context)) = (void*)ep;

		if (globals->blocking) {
			if (*fd >= (int) globals->nfds)
				globals->nfds = *fd + 1;
		}

		ret = cci_get_opt((cci_opt_handle_t *)ep->e, CCI_OPT_ENDPT_URI, &ep->uri);
		if (ret) {
			fprintf(stderr, "%s: cci_get_opt() returned %s\n",
					__func__, cci_strerror(ep->e, ret));
			goto out;
		}

		fprintf(stderr, "ep %s has cookie 0x%x\n", ep->uri, ep->cookie);

		if (globals->verbose > 2)
			fprintf(stderr, "%s: opened %s on device %s\n", __func__,
					ep->uri, d->name);
	}

	if (cnt < 2)
		fprintf(stderr, "Unable to route with %d endpoint%s.\n",
				cnt, cnt == 0 ? "s" : "");

	globals->eps = es;
	globals->ep_cnt = cnt;
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

	globals = calloc(1, sizeof(*globals));
	if (!globals) {
		ret = ENOMEM;
		goto out;
	}

	while ((c = getopt(argc, argv, "f:vb")) != -1) {
		switch (c) {
		case 'f':
			config_file = strdup(optarg);
			if (!config_file) {
				fprintf(stderr, "Unable to store file name - no memory\n");
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

	ret = get_config(globals, argv[0], config_file);
	if (ret) {
		exit(EXIT_FAILURE);
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret != CCI_SUCCESS) {
		fprintf(stderr, "Unable to init CCI\n");
		exit(EXIT_FAILURE);
	}

	ret = open_endpoints(globals);
	if (ret) {
		fprintf(stderr, "Unable to open CCI endpoints.\n");
		goto out_w_init;
	}

	/* We have the endpoints, start discovery and routing */
	event_loop(globals);

	close_endpoints(globals);

out_w_init:
	ret = cci_finalize();
	if (ret) {
		fprintf(stderr, "Unable to finalize CCI\n");
		exit(EXIT_FAILURE);
	}

	if (globals->verbose)
		fprintf(stderr, "%s is done\n", argv[0]);
out:
	return ret;
}
