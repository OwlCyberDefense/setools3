/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h" 
#include "policy.h"
#include "register_list.h"

#include <stdio.h>
#include <string.h>
#include <getopt.h>

/* SECHECKER_VERSION should be defined in the make environment */
#ifndef SECHECKER_VERSION
#define SECHECKER_VERSION "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2005 Tresys Technology, LLC"

extern sechk_register_fn_t sechk_register_list[];

/* command line options struct */
static struct option const longopts[] = 
{
	{"policy", required_argument, NULL, 'p'},
/* TODO: add --profile option */
	{"file_contexts", required_argument, NULL, 'p'},
	{"short", no_argument, NULL, 'S'},
	{"long", no_argument, NULL, 'L'},
	{"quiet", no_argument, NULL, 'q'},
	{"verbose", no_argument, NULL, 'V'},
	{"all", no_argument, NULL, 'a'},
	{"module", required_argument, NULL, 'm'},
	{"list", no_argument, NULL, 'l'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

/* display usage help */
void usage(const char *arg0, bool_t brief) 
{
	printf("%s (sechecker v%s)\n\n", COPYRIGHT_INFO, SECHECKER_VERSION);
	printf("Usage: %s [OPTIONS]\n", arg0);
	if (brief) {
		printf("\n\tTry %s --help for more help.\n\n", arg0);
	} else {
		printf("Perform modular checks on a SELinux policy\n");
		printf("\nConfiguration Options\n");
		printf("   -f file, --file_contexts=file   The location of the file_contexts file to load\n");
		printf("   -p file, --policy=file          The location of the policy file\n");
		printf("\nOutput Options (only one may be specified)\n");
		printf("   -S, --short                     Use short output format for all modules\n");
		printf("   -L, --long                      Use long output format for all modules\n");
		printf("   -V, --verbose                   Use verbose output format for all modules\n");
		printf("   -q, --quiet                     Output only module name and statistics\n");
		printf("\nModule Options\n");
		printf("   -m module, --module=mod_name    Run only specified module (with dependencies)\n");
		printf("   -l, --list                      Print a list of available modules and exit\n");
		printf("   -a, --all                       Run all modules\n");
		printf("\nOther Options\n");
		printf("   -h, --help                      Print this help message and exit\n");
		printf("   -v, --version                   Print version information and exit\n");
	}
}

/* main application */
int main(int argc, char **argv) 
{
	int optc = 0, retv = 0, i;
	char *fcpath = NULL, *polpath = NULL, *modname = NULL;
	unsigned char output_override = 0;
	sechk_lib_t *module_library;
	bool_t list_stop = FALSE;
	sechk_module_t *mod = NULL;
	sechk_run_fn_t run_fn = NULL;

	while ((optc = getopt_long(argc, argv, "f:p:SVLqm:ldsbhv", longopts, NULL)) != -1) {
		switch (optc) {
		case 'f':
			fcpath = optarg;
			break;
		case 'p':
			polpath = optarg;
			break;
		case 'S':
			if (output_override) {
				fprintf(stderr, "Error: Multiple output specifications.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = (SECHK_OUT_LIST|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			}
			break;
		case 'V':
			if (output_override) {
				fprintf(stderr, "Error: Multiple output specifications.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override =(SECHK_OUT_LONG|SECHK_OUT_LIST|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			}
			break;
		case 'L':
			if (output_override) {
				fprintf(stderr, "Error: Multiple output specifications.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override =(SECHK_OUT_LONG|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			}
			break;
		case 'q':
			if (output_override) {
				fprintf(stderr, "Error: Multiple output specifications.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = (SECHK_OUT_STATS|SECHK_OUT_HEADER);
			}
			break;
		case 'a':
			/* handle this */
			break;
		case 'm':
			modname = optarg;
			break;
		case 'l':
			list_stop = TRUE;
			break;
		case 'h':
			usage(argv[0], 0);
			exit(0);
		case 'v':
			printf("\n%s (sechecker v%s)\n\n", COPYRIGHT_INFO, SECHECKER_VERSION);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	/* create the module library */
	module_library = sechk_lib_new(polpath, fcpath);
	if (!module_library)
		goto exit_err;

	/* register modules */
	fprintf(stderr, "registering modules...");
	if ((retv = sechk_lib_register_modules(sechk_register_list, module_library)) != 0)
		goto exit_err;
	fprintf(stderr, " done\n");

	/* just show the available modules and exit */
	if (list_stop) {
		printf("\nAvailable Modules:\n");
		for (i = 0; i < module_library->num_modules; i++) {
			printf("   %s\n", module_library->modules[i].name);
		}
		goto exit;
	}

	/* initialize the modules */
	fprintf(stderr, "initializing modules..\n");
	retv = sechk_lib_init_modules(module_library);
	if (retv) {
		goto exit_err;
	}
	fprintf(stderr, " done\n");

	/* run the modules */
	fprintf(stderr, "running modules...\n");
	if (modname) {
		/* here we are only running one specific module */
		mod = sechk_lib_get_module(modname, module_library);
		if (!mod) {
			goto exit_err;
		}
		run_fn = sechk_lib_get_module_function(modname, "run", module_library);
		if (!run_fn) {
			goto exit_err;
		}
		retv = run_fn(mod, module_library->policy);
		if (retv) {
			goto exit_err;
		}
	} else {
		/* here we are running all the available modules */
		retv = sechk_lib_run_modules(module_library);
		if (retv) {
			goto exit_err;
		}
	}
	fprintf(stderr, " done\n");

exit:
	if (fcpath)
		free(fcpath);
	if (polpath)
		free(polpath);
	if (modname)
		free(modname);
	if (module_library)
		sechk_lib_free(module_library);
	return 0;

exit_err:
	if (fcpath)
		free(fcpath);
	if (polpath)
		free(polpath);
	if (modname)
		free(modname);
	if (module_library)
		sechk_lib_free(module_library);
	fprintf(stderr, "Exiting application.\n");
	return -1;
}
