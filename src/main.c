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

#include "cci.h"

static int
get_config(void)
{
	int ret = 0;
	return ret;
}

int
main(int argc, char *argv[])
{
	int ret = 0;
	uint32_t caps = 0;

	ret = get_config();
	if (ret) {
		fprintf(stderr, "Unable to find configuration file\n");
		exit(EXIT_FAILURE);
	}

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret != CCI_SUCCESS) {
		fprintf(stderr, "Unable to init CCI\n");
		exit(EXIT_FAILURE);
	}

	ret = cci_finalize();
	if (ret) {
		fprintf(stderr, "Unable to finalize CCI\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
