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

#include "cci.h"

static void
usage(char *procname)
{
	fprintf(stderr, "usage: %s [-f <config_file>]\n", procname);
	fprintf(stderr, "where:\n");
	fprintf(stderr, "\t-f\tUse this configuration file.\n");
	exit(EXIT_FAILURE);
}

/* Return 0 on success, errno otherwise */
static int
check_file(char *fname)
{
	int ret = 0;
	struct stat buf;

	ret = stat(fname, &buf);
	if (ret) {
		ret = errno;
		fprintf(stderr, "Cannot access config file %s due to \"%s\".\n",
				fname, strerror(ret));
	} else if (buf.st_size == 0) {
		ret = EINVAL;
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
get_config(char *procname, char *config_option)
{
	int ret = 0, done = 0;
	char *cci_config = NULL;

	if (config_option) {
		/* see if it exists and is not empty, if so use it */
		ret = check_file(config_option);
		if (ret) {
			config_option = NULL;
		} else {
			done = 1;
		}
	}

	cci_config = getenv("CCI_CONFIG");
	if (cci_config) {
		ret = check_file(cci_config);
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
				fprintf(stderr, "Replacing CCI_CONFIG=%s with %s\n",
						cci_config, config_option);
			}
			ret = setenv("CCI_CONFIG", config_option, overwrite);
			if (ret) {
				ret = errno; /* ENOMEM */
				fprintf(stderr, "Unable to setenv(CCI_CONFIG) (%s)\n",
						strerror(ret));
			}
		}
	}

	/* check for local config */
	if (!done) {
		char *fname = "ccir_config";

		ret = check_file(fname);
		if (!ret) {
			ret = setenv("CCI_CONFIG", fname, 0);
			if (ret) {
				ret = errno; /* ENOMEM */
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
				ret = check_file(fname);
				if (!ret) {
					ret = setenv("CCI_CONFIG", fname, 0);
					if (ret) {
						ret = errno; /* ENOMEM */
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

		ret = check_file(fname);
		if (!ret) {
			ret = setenv("CCI_CONFIG", fname, 0);
			if (ret) {
				ret = errno; /* ENOMEM */
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

static int
open_endpoints(cci_endpoint_t ***eps, int *count)
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

	/* Count devices and make sure that they have specified
	 * as, subnet, and at least one router */
	for (i = 0; ; i++) {
		int j = 0, as = 0, subnet = 0, router = 0;
		const char *arg = NULL;
		cci_device_t *d = devs[i];

		if (!d)
			break;

		for (j = 0; ;j++) {
			arg = d->conf_argv[j];
			if (!arg)
				break;
			if (0 == strncmp("as=", arg, 3)) {
				as++;
			} else if (0 == strncmp("subnet=", arg, 7)) {
				subnet++;
			} else if (0 == strncmp("router=", arg, 7)) {
				router++;
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

	}

	es = calloc(i, sizeof(*es));
	if (!es) {
		fprintf(stderr, "Failed to alloc endpoints\n");
		ret = ENOMEM;
		goto out;
	}

	for (i = 0; ; i++) {
		if (devs[i]) {
			ret = cci_create_endpoint(devs[i], 0, &es[cnt], NULL);
			if (ret) {
				fprintf(stderr, "Unable to create endpoint "
						"on device %s (%s)\n",
						devs[i]->name,
						cci_strerror(NULL, ret));
				for (i = i - 1; i >= 0; i--) {
					int ret2 = 0;

					ret2 = cci_destroy_endpoint(es[i]);
					if (ret2) {
						fprintf(stderr, "Unable to destroy "
								"endpoint %d (%s)\n",
								i,
								cci_strerror(NULL, ret2));
					}
				}
				free(es);
				goto out;
			}
			cnt++;
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
	uint32_t caps = 0;
	cci_endpoint_t **eps = NULL;

	while ((c = getopt(argc, argv, "f:")) != -1) {
		switch (c) {
		case 'f':
			config_file = strdup(optarg);
			if (!config_file) {
				fprintf(stderr, "Unable to store file name - no memory\n");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			usage(argv[0]);
		}
	}

	ret = get_config(argv[0], config_file);
	if (ret) {
		exit(EXIT_FAILURE);
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret != CCI_SUCCESS) {
		fprintf(stderr, "Unable to init CCI\n");
		exit(EXIT_FAILURE);
	}

	ret = open_endpoints(&eps, &count);
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
