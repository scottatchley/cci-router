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

#include "cci.h"

#define MAX_TRANSPORT_LEN	(128)

static void
usage(char *procname)
{
	fprintf(stderr, "usage: %s [-f <config_file>] "
			"[-t <transport1>[,<transport2>[,...]]]\n", procname);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-f\tUse this configuration file.\n");
	fprintf(stderr, "\t-t\tUse this comma separated list of transports\n");
	exit(EXIT_FAILURE);
}

/* Hierarchy of config processing:
 * 1. Command line options
 * 2. Command line config file
 * 3. Local config file ($PWD/ccir_config)
 * 4. Global config file (/etc/ccir/config)
 */
static int
get_config(char *config_file)
{
	int ret = 0;

	return ret;
}

static int
open_endpoints(char *transports, cci_endpoint_t ***eps, int *count)
{
	int ret = 0, i = 0, cnt = 0;
	cci_device_t * const *devs = NULL;
	cci_endpoint_t **es = NULL, **new = NULL;

	ret = cci_get_devices(&devs);
	if (ret) {
		fprintf(stderr, "Failed to get devices with %s\n",
				cci_strerror(NULL, ret));
		goto out;
	}

	for (i = 0; ; i++)
		if (!devs[i])
			break;

	es = calloc(i, sizeof(*es));
	if (!es) {
		fprintf(stderr, "Failed to alloc endpoints\n");
		ret = ENOMEM;
		goto out;
	}

	for (i = 0; ; i++) {
		if (devs[i]) {
			const char *s = devs[i]->transport;
			int len = strnlen(transports, MAX_TRANSPORT_LEN);

			if (strnstr(transports, s, len)) {
				ret = cci_create_endpoint(devs[i], 0, &es[cnt], NULL);
				if (ret) {
					fprintf(stderr, "Unable to create endpoint "
							"on device %s (%s)\n",
							devs[i]->name,
							cci_strerror(NULL, ret));
					continue;
				}
				cnt++;
			}
		} else {
			break;
		}
	}
	new = realloc(es, cnt * sizeof(*es));
	if (new) {
		es = new;
	} else {
		fprintf(stderr, "Unable to shorten the endpoint array\n");
	}

	if (cnt < 2)
		fprintf(stderr, "Unable to route with %d endpoint%s.\n",
				cnt, cnt == 0 ? "s" : "");

	*eps = es;
	*count = cnt;
out:
	return ret;
}

int
main(int argc, char *argv[])
{
	int ret = 0, c, count = 0, i;
	char *config_file = NULL;
	char *transports = NULL;
	uint32_t caps = 0;
	cci_endpoint_t **eps = NULL;

	while ((c = getopt(argc, argv, "f:t:")) != -1) {
		switch (c) {
		case 'f':
			config_file = strdup(optarg);
			if (!config_file) {
				fprintf(stderr, "Unable to store file name - no memory\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 't':
			transports = strdup(optarg);
			if (!transports) {
				fprintf(stderr, "Unable to store list of transports - no memory\n");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			usage(argv[0]);
		}
	}

	ret = get_config(config_file);
	if (ret) {
		fprintf(stderr, "Unable to find configuration file\n");
		exit(EXIT_FAILURE);
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret != CCI_SUCCESS) {
		fprintf(stderr, "Unable to init CCI\n");
		exit(EXIT_FAILURE);
	}

	ret = open_endpoints(transports, &eps, &count);
	if (ret) {
		fprintf(stderr, "Unable to open CCI endpoints.\n");
		goto out_w_init;
	}

	for (i = 0; i < count; i++)
		cci_destroy_endpoint(eps[i]);

out_w_init:
	ret = cci_finalize();
	if (ret) {
		fprintf(stderr, "Unable to finalize CCI\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
