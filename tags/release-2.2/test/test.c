#include "test.h"

#include <string.h>

int get_rand_int(int min, int max)
{
	return min + (int)((float)(max - min + 1) * rand()/ (RAND_MAX + 1.0));
}

/*
 * This processes the global testing command-line arguments. It does not
 * remove items that were processed for simplicity.
 */
void init_tests(int argc, char **argv)
{
	int i;
	if (argc <= 1)
		return;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-c"))
			dump_core = 1;
	}
}
