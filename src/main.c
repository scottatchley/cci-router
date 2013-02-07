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

#include "cci-router.h"

int running = 0;


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

static void handle_sigterm(int signum)
{
	running = 0;
	return;
}

static int install_handlers(ccir_globals_t *globals)
{
	int ret = 0;
	struct sigaction sa;

	sa.sa_handler = handle_sigterm;
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
get_event(ccir_globals_t *globals)
{
	int ret = 0;


	return ret;
}

static void
start_routing(ccir_globals_t *globals)
{
	int ret = 0;

	running = 1;

	ret = install_handlers(globals);
	if (ret)
		goto out;

	while (running) {
		get_event(globals);
	}

	if (globals->verbose)
		fprintf(stdout, "Exiting %s\n", __func__);
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
	int i = 0;

	if (globals->verbose)
		fprintf(stdout, "Entering %s\n", __func__);

	if (!globals->eps)
		return;

	for (i = 0; i < globals->count; i++) {
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
			int j = 0;

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
		fprintf(stdout, "Leaving %s\n", __func__);

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
			ep->peer_cnt = router;
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
	}

	if (cnt < 2)
		fprintf(stderr, "Unable to route with %d endpoint%s.\n",
				cnt, cnt == 0 ? "s" : "");

	globals->eps = es;
	globals->count = cnt;
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
	start_routing(globals);

	close_endpoints(globals);

out_w_init:
	ret = cci_finalize();
	if (ret) {
		fprintf(stderr, "Unable to finalize CCI\n");
		exit(EXIT_FAILURE);
	}

	if (globals->verbose)
		fprintf(stdout, "%s is done\n", argv[0]);

out:
	return ret;
}
