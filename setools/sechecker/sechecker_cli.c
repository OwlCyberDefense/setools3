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
#include <errno.h>

/* SECHECKER_VERSION should be defined in the make environment */
#ifndef SECHECKER_VERSION
#define SECHECKER_VERSION "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2005 Tresys Technology, LLC"

extern sechk_module_name_reg_t sechk_register_list[];

/* command line options struct */
static struct option const longopts[] = 
{
	{"profile", required_argument, NULL, 'P'},
	{"policy", required_argument, NULL, 'p'},
#ifdef LLIBSEFS
	{"file_contexts", required_argument, NULL, 'c'},
#endif
	{"short", no_argument, NULL, 's'},
	{"quiet", no_argument, NULL, 'q'},
	{"verbose", no_argument, NULL, 'V'},
	{"module", required_argument, NULL, 'm'},
	{"mod-list", no_argument, NULL, 'L'},
	{"prof-list", no_argument, NULL, 'l'},
	{"help", no_argument, NULL, 'h'},
	{"mod-help", required_argument, NULL, 'H'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

/* display usage help */
void usage(const char *arg0, bool_t brief) 
{
	printf("%s (sechecker v%s)\n\n", COPYRIGHT_INFO, SECHECKER_VERSION);
	printf("Usage: sechecker [OPTIONS] -P profile            Run the specified profile\n");
	printf("   or: sechecker [OPTIONS] -m module             Run the specified module\n");
	printf("   or: sechecker [OPTIONS] -P profile -m module  Load the specified profile\n");
	printf("                                                 and run the specified module\n");
	if (brief) {
		printf("\n\tTry %s --help for more help.\n", arg0);
	} else {
		printf("Perform modular checks on a SELinux policy\n\n");
		printf("   -l, --prof-list          Print a list of known profiles\n");
		printf("   -L, --mod-list           Print a list of available modules\n");
		printf("   -h, --help               Print this help message\n");
		printf("   -v, --version            Print version information\n");
		printf("   -q, --quiet              Do not print any results\n");
		printf("   -s, --short              Print short output format\n");
		printf("   -V, --verbose            Print verbose output format\n");
		printf("\n");
		printf("   -p file,   --policy=file      The location of the policy file\n");
#ifdef LIBSEFS
		printf("   -c file,   --fcfile=file      The location of the file_contexts file\n");
#endif
		printf("   -H module, --mod-help=module  Print a complete module description\n");
	}
	printf("\n");
}

/* print list of installed profiles */
int sechk_print_profiles_list()
{
	char **profile_names = NULL;
	int num_profiles = 0, i;

	profile_names = sechk_lib_get_profiles(&num_profiles);

	for (i = 0; i < num_profiles; i++) {
		printf("   %s\n", profile_names[i]);
		free(profile_names[i]);
	}
	printf("\n");
	if (num_profiles == 0)
		printf("   <<no profiles installed>>\n");

	free(profile_names);
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
	unsigned char output_override = 0;
	sechk_lib_t *module_library;
	bool_t module_list_stop = FALSE;
	bool_t profile_list_stop = FALSE;
	bool_t module_help = FALSE;
	sechk_module_t *mod = NULL;
	sechk_run_fn_t run_fn = NULL;
	sechk_print_output_fn_t print_fn = NULL;

#ifdef LIBSEFS
	while ((optc = getopt_long(argc, argv, "P:c:p:SVLqm:H:lhvs", longopts, NULL)) != -1) {
#else
	while ((optc = getopt_long(argc, argv, "P:p:SVLqm:H:lhvs", longopts, NULL)) != -1) {
#endif
		switch (optc) {
		case 'P':
			prof_name = strdup(optarg);
			break;
#ifdef LIBSEFS
		case 'c':
			fcpath = strdup(optarg);
			break;
#endif
		case 'p':
			polpath = strdup(optarg);
			break;
		case 'V':
			if (output_override) {
				fprintf(stderr, "Error: Multiple output specifications.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_VERBOSE;
			}
			break;
		case 's':
			if (output_override) {
				fprintf(stderr, "Error: Multiple output specifications.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_SHORT;
			}
			break;
		case 'q':
			if (output_override) {
				fprintf(stderr, "Error: Multiple output specifications.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_QUIET;
			}
			break;
		case 'm':
			modname = strdup(optarg);
			break;
		case 'H':
			modname = strdup(optarg);
			module_help = TRUE;
			break;
		case 'L':
			module_list_stop = TRUE;
			break;
		case 'l':
			profile_list_stop = TRUE;
			break;
		case 'h':
			usage(argv[0], 0);
			exit(0);
		case 'v':
			printf("\nSEChecker v%s\n%s\n\n", SECHECKER_VERSION, COPYRIGHT_INFO);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	if (!prof_name && !modname && !module_list_stop && !profile_list_stop) {
		fprintf(stderr, "Error: no profile specified\n");
		usage(argv[0], 1);
		exit(1);
	}

	/* create the module library */
	module_library = sechk_lib_new();

	if (!module_library)
		goto exit_err;

	if (profile_list_stop) {
		printf("\nAvailable Profiles:\n");
		retv = sechk_print_profiles_list();
	}

	/* if --list, just show the available modules and exit */
	if (module_list_stop) {
		printf("\nAvailable Modules:\n");
		retv = sechk_lib_set_outputformat(SECHK_OUT_BRF_DESCP, module_library);
		if (retv) {
			goto exit_err;
		}
		for(i = 0; i < module_library->num_modules; i++) {
			module_library->module_selection[i] = TRUE;
		}
		retv = sechk_lib_print_modules_output(module_library);
		if (retv) {
			goto exit_err;
		}
	}

	if (module_help == TRUE) {
		/* first get the module and select it*/
		retv = sechk_lib_get_module_idx(modname, module_library);
		if (retv == -1 || retv >= module_library->num_modules) {
			fprintf(stderr, "Error: module %s not found\n", modname);
			goto exit_err;
		}
		for (i = 0; i < module_library->num_modules; i++) {
			module_library->module_selection[i] = FALSE;
		}
		module_library->module_selection[retv] = TRUE;

		/* next set the output to be nice and long */
		retv = sechk_lib_set_outputformat(SECHK_OUT_DET_DESCP, module_library);
		if (retv) {
			goto exit_err;
		}
		/* and print */
		retv = sechk_lib_print_modules_output(module_library);
		if (retv < 0 || (output_override && output_override & SECHK_OUT_QUIET)) {
			goto exit_err;
		}
	}

	if (profile_list_stop || module_list_stop || module_help)
		goto exit;

	/* load profile if specified */
	if (prof_name) {
		retv = sechk_lib_load_profile(prof_name, module_library);
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
	/* if command line specified an output format
	 * use it for all modules in the report */
	if (output_override) {
		retv = sechk_lib_set_outputformat(output_override, module_library);
		if (retv) {
			goto exit_err;
		}
	}


	/* initialize the policy */
	retv = sechk_lib_load_policy(polpath,module_library);
	if (retv < 0)
		goto exit_err;

#ifdef LIBSEFS
	/* initialize the file contexts */
	retv = sechk_lib_load_fc(fcpath,module_library);
	if (retv < 0)
		goto exit_err;
#endif
	/* if command line specified an output format
	 * use it for all modules in the report */
	if (output_override) {
		retv = sechk_lib_set_outputformat(output_override, module_library);
		if (retv) {
			goto exit_err;
		}
	}


	/* if running only one module, deselect all others */
	if (modname) {
		retv = sechk_lib_get_module_idx(modname, module_library);
		if (retv == -1 || retv >= module_library->num_modules) {
			fprintf(stderr, "Error: module %s not found\n", modname);
			goto exit_err;
		}
		for (i = 0; i < module_library->num_modules; i++) {
			module_library->module_selection[i] = FALSE;
		}
		module_library->module_selection[retv] = TRUE;
	}

	/* process dependencies for selected modules */
	retv = sechk_lib_check_module_dependencies(module_library);
	if (retv) {
		goto exit_err;
	}

	/* process requirements for selected modules */
	retv = sechk_lib_check_module_requirements(module_library);
	if (retv) {
		goto exit_err;
	}

	/* initialize the modules */
	retv = sechk_lib_init_modules(module_library);
	if (retv) {
		goto exit_err;
	}

	/* run the modules */
	if (modname) {
		/* check to see if after processing dependencies we should run this module */
		retv = sechk_lib_get_module_idx(modname, module_library);
		if (retv == -1 || retv >= module_library->num_modules) {
			fprintf(stderr, "Error: module %s not found\n", modname);
			goto exit_err;
		}
		if (module_library->module_selection[retv] == FALSE)
			goto exit_err;

		/* here we are only running one specific module */
		mod = sechk_lib_get_module(modname, module_library);
		if (!mod) {
			goto exit_err;
		}		
		run_fn = sechk_lib_get_module_function(modname, SECHK_MOD_FN_RUN, module_library);
		if (!run_fn) {
			goto exit_err;
		}
		retv = run_fn(mod, module_library->policy);
		if (retv) {
			goto exit_err;
		}
	} else {
		/* here we are running all specified modules */
		retv = sechk_lib_run_modules(module_library);
		if (retv) {
			goto exit_err;
		}
	}

	/* print the report */
	if (modname && (!(output_override) || (output_override & ~(SECHK_OUT_QUIET)))) {
		/* here we are only printing results for one specific module */
		mod = sechk_lib_get_module(modname, module_library);
		if (!mod) {
			goto exit_err;
		}
		print_fn = sechk_lib_get_module_function(modname, SECHK_MOD_FN_PRINT, module_library);
		if (!run_fn) {
			goto exit_err;
		}
		if (!mod->outputformat)
			mod->outputformat = SECHK_OUT_SHORT;
		retv = print_fn(mod, module_library->policy);
		if (retv) {
			goto exit_err;
		}
	} else if (!(output_override) || (output_override & ~(SECHK_OUT_QUIET))){
		/* here we are printing results for all the available modules */
		retv = sechk_lib_print_modules_output(module_library);
		if (retv) {
			goto exit_err;
		}
	}

exit:
#ifdef LIBSEFS
	free(fcpath);
#endif
	free(prof_name);
	free(polpath);
	free(modname);
	sechk_lib_free(module_library);
	free(module_library);
	return 0;

exit_err:
#ifdef LIBSEFS
	free(fcpath);
#endif
	free(prof_name);
	free(polpath);
	free(modname);
	sechk_lib_free(module_library);
	free(module_library);
	return 1;
}
