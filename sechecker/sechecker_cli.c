/* Copyright (C) 2005-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "register_list.h"
#include <apol/policy.h>

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

/* SECHECKER_VERSION should be defined in the make environment */
#ifndef SECHECKER_VERSION
#define SECHECKER_VERSION "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2005-2006 Tresys Technology, LLC"

extern sechk_module_name_reg_t sechk_register_list[];

/* command line options struct */
static struct option const longopts[] = 
{
	{"list", no_argument, NULL, 'l'},
	{"help", optional_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{"quiet", no_argument, NULL, 'q'},
	{"short", no_argument, NULL, 's'},
	{"verbose", no_argument, NULL, 'v'},
	{"profile", required_argument, NULL, 'p'},
	{"policy", required_argument, NULL, 'P'},
#ifdef LIBSEFS
	{"fcfile", required_argument, NULL, 'c'},
#endif
	{"module", required_argument, NULL, 'm'},
	{"min-sev", required_argument, NULL, 'M' },
	{NULL, 0, NULL, 0}
};

/* display usage help */
void usage(const char *arg0, bool_t brief) 
{
	printf("%s (sechecker v%s)\n\n", COPYRIGHT_INFO, SECHECKER_VERSION);
	printf("Usage: sechecker [OPTS] -m module             run module\n");
	printf("   or: sechecker [OPTS] -p profile            run profile\n");
	printf("   or: sechecker [OPTS] -p profile -m module  run module with profile options\n");
	printf("\n");
	if (brief) {
		printf("\n\tTry %s --help for more help.\n", arg0);
	} else {
		printf("Perform modular checks on a SELinux policy\n");
		printf("\n");
		printf("   -l, --list       print a list of profiles and modules\n");
		printf("   -q, --quiet      suppress output\n");
		printf("   -s, --short      print short output\n");
		printf("   -v, --verbose    print verbose output\n");
		printf("   --version        print version and exit\n");
#ifdef LIBSEFS
		printf("   --fcfile=<file>  file_contexts file\n");
#endif
		printf("   --policy=<file>  policy file\n");
		printf("\n");
		printf("   -h[mod],   --help[=module]   print this help or help for a module\n");
		printf("   -m <mod>,  --module=<mod>    module name\n");
		printf("   -p <prof>, --profile=<prof>  profile name or path\n");
		printf("\n");
		printf("   --min-sev=<low|med|high>     the minimum severity to report\n");

	}
	printf("\n");
}

/* print list of modules and installed profiles */
int sechk_print_list(sechk_lib_t *lib)
{
	const sechk_profile_name_reg_t *profiles;
	size_t num_profiles, i;
	sechk_module_t *mod = NULL;

	printf("\nProfiles:\n");
	profiles = sechk_register_list_get_profiles();
	num_profiles = sechk_register_list_get_num_profiles();
	for (i = 0; i < num_profiles; i++) {
		printf("%20s\t%s\n", profiles[i].name, profiles[i].desc);
	}
	if (num_profiles == 0)
		printf("<none>\n");

	printf("Modules:\n");
	for(i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		printf("%20s\t%s\n", mod->name, mod->brief_description);
	}
	if (apol_vector_get_size(lib->modules) == 0)
		printf("<none>\n");
	printf("\n");
	return 0;
}

/* main application */
int main(int argc, char **argv) 
{
	int optc = 0, retv = 0, i;
#ifdef LIBSEFS
	char *fcpath = NULL;
#endif
	char *polpath = NULL, *modname = NULL;
	char *prof_name = NULL;
	char *minsev = NULL;
	unsigned char output_override = 0;
	sechk_lib_t *lib;
	sechk_module_t *mod = NULL;
	bool_t list_stop = FALSE;
	bool_t module_help = FALSE;

	while ((optc = getopt_long(argc, argv, "h::p:m:lqsv", longopts, NULL)) != -1) {
		switch (optc) {
		case 'p':
			prof_name = strdup(optarg);
			break;
#ifdef LIBSEFS
		case 'c':
			fcpath = strdup(optarg);
			break;
#endif
		case 'P':
			polpath = strdup(optarg);
			break;
		case 'M':
			if (modname) {
				fprintf(stderr, "Error: --min-sev does not work with -m\n");
				exit(1);
			}
			minsev = strdup(optarg);
			break;
		case 'v':
			if (output_override) {
				fprintf(stderr, "Error: multiple output formats specified\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_VERBOSE;
			}
			break;
		case 's':
			if (output_override) {
				fprintf(stderr, "Error: multiple output formats specified\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_SHORT;
			}
			break;
		case 'q':
			if (output_override) {
				fprintf(stderr, "Error: multiple output formats specified\n\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_QUIET;
			}
			break;
		case 'm':
			if (minsev) {
				fprintf(stderr, "Error: --min-sev does not work with -m\n");
				exit(1);
			}
			modname = strdup(optarg);
			break;
		case 'l':
			list_stop = TRUE;
			break;
		case 'h':
			if (optarg != NULL) {
				modname = strdup(optarg);
				module_help = TRUE;
				break;
			}
			usage(argv[0], 0);
			exit(0);
		case 'V':
			printf("\nSEChecker v%s\n%s\n\n", SECHECKER_VERSION, COPYRIGHT_INFO);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	if (!prof_name && !modname && !list_stop) {
		fprintf(stderr, "Error: no module or profile specified\n\n");
		usage(argv[0], 1);
		exit(1);
	}

	/* create the module library */
	lib = sechk_lib_new();
	if (!lib)
		goto exit_err;

	/* print the list */
	if (list_stop == TRUE) {
		sechk_print_list(lib);
		goto exit;
	}

	/* print help for a module */
	if (module_help == TRUE) {
		retv = sechk_lib_get_module_idx(modname, lib);
		if (retv < 0) {
			fprintf(stderr, "Error: Module %s does not exist.\n", modname);
			goto exit_err;
		}
		mod = apol_vector_get_element(lib->modules, retv);
		printf("\nModule name: %s\n%s\n%s\n", mod->name, mod->detailed_description, 
		       mod->opt_description);
		goto exit;
	}

	/* load profile if specified */
	if (prof_name) {
		retv = sechk_lib_load_profile(prof_name, lib);
		if (retv) {
			retv = errno;
			if (!output_override || !(output_override & ~(SECHK_OUT_QUIET))) {
				fprintf(stderr, "Error: could not load profile %s\n", prof_name);
				errno = retv;
				perror("Error");
			}
			goto exit_err;
		}
	}
	
	/* set the minimum severity */
	if (minsev && sechk_lib_set_minsev(minsev, lib) < 0)
		goto exit_err;

	/* initialize the policy */
	if (sechk_lib_load_policy(polpath, lib) < 0)
		goto exit_err;

#ifdef LIBSEFS
	/* initialize the file contexts */
	if (sechk_lib_load_fc(fcpath, lib) < 0)
		goto exit_err;
#endif
	/* initialize the output format */
	if (output_override) {
		if (sechk_lib_set_outputformat(output_override, lib) < 0)
			goto exit_err;
	}

	/* if running only one module, deselect all others */
	if (modname) {
		retv = sechk_lib_get_module_idx(modname, lib);
		if (retv == -1 || retv >= apol_vector_get_size(lib->modules)) {
			fprintf(stderr, "Error: module %s not found\n", modname);
			goto exit_err;
		}
		for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
			mod = apol_vector_get_element(lib->modules, i);
			mod->selected = FALSE;
		}
		mod = apol_vector_get_element(lib->modules, retv);
		mod->selected = TRUE;
	}

	/* process dependencies for selected modules */
	if (sechk_lib_check_module_dependencies(lib) < 0)
		goto exit_err;

	/* process requirements for selected modules */
	if (sechk_lib_check_module_requirements(lib) < 0)
		goto exit_err;

	/* initialize the modules */
	if (sechk_lib_init_modules(lib))
		goto exit_err;

	/* run the modules */
	if (sechk_lib_run_modules(lib))
		goto exit_err;

	/* if running only one module, deselect all others again before printing */
	if (modname) {
		retv = sechk_lib_get_module_idx(modname, lib);
		if (retv == -1 || retv >= apol_vector_get_size(lib->modules)) {
			fprintf(stderr, "Error: module %s not found\n", modname);
			goto exit_err;
		}
		for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
			mod = apol_vector_get_element(lib->modules, i);
			mod->selected = FALSE;
		}
		mod = apol_vector_get_element(lib->modules, retv);
		mod->selected = TRUE;
	}

	/* print the report */
	if (sechk_lib_print_modules_report(lib))
		goto exit_err;

exit:
#ifdef LIBSEFS
	free(fcpath);
#endif
	free(minsev);
	free(prof_name);
	free(polpath);
	free(modname);
	sechk_lib_destroy(&lib);
	return 0;

exit_err:
#ifdef LIBSEFS
	free(fcpath);
#endif
	free(minsev);
	free(prof_name);
	free(polpath);
	free(modname);
	sechk_lib_destroy(&lib);
	return 1;
}

