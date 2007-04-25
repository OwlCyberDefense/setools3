/**
 * @file
 * Main function and command line parser for the sechecker program.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include "sechecker.h"
#include "register_list.h"
#include <apol/policy.h>

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#define COPYRIGHT_INFO "Copyright (C) 2005-2007 Tresys Technology, LLC"

extern sechk_module_name_reg_t sechk_register_list[];

enum opt_values
{
	OPT_FCFILE = 256, OPT_MIN_SEV
};

/* command line options struct */
static struct option const longopts[] = {
	{"list", no_argument, NULL, 'l'},
	{"help", optional_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{"quiet", no_argument, NULL, 'q'},
	{"short", no_argument, NULL, 's'},
	{"verbose", no_argument, NULL, 'v'},
	{"profile", required_argument, NULL, 'p'},
#ifdef LIBSEFS
	{"fcfile", required_argument, NULL, OPT_FCFILE},
#endif
	{"module", required_argument, NULL, 'm'},
	{"min-sev", required_argument, NULL, OPT_MIN_SEV},
	{NULL, 0, NULL, 0}
};

/* display usage help */
void usage(const char *arg0, bool_t brief)
{
	printf("Usage: sechecker [OPTIONS] -p profile [POLICY ...]\n");
	printf("       sechecker [OPTIONS] -m module [POLICY ...]\n");
	printf("       sechecker [OPTIONS] -p profile -m module [POLICY ...]\n");
	printf("\n");
	if (brief) {
		printf("\tTry %s --help for more help.\n\n", arg0);
	} else {
		printf("Perform modular checks on a SELinux policy.\n");
		printf("\n");
		printf("   -p PROF, --profile=PROF      name or path of profile to load\n");
		printf("                                if used without -m, run all modules in profile\n");
		printf("   -m MODULE, --module=MODULE   MODULE to run\n");
#ifdef LIBSEFS
		printf("   --fcfile=FILE                file_contexts file to load\n");
#endif
		printf("\n");
		printf("   -q, --quiet                  suppress output\n");
		printf("   -s, --short                  print short output\n");
		printf("   -v, --verbose                print verbose output\n");
		printf("   --min-sev={low|med|high}     set the minimum severity to report\n");
		printf("\n");
		printf("   -l, --list                   print a list of profiles and modules and exit\n");
		printf("   -h[MODULE], --help[=MODULE]  print this help text or help for MODULE\n");
		printf("   -V, --version                print version information and exit\n");
		printf("\n");
	}
}

/* print list of modules and installed profiles */
int sechk_print_list(sechk_lib_t * lib)
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
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
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
	char *modname = NULL;
	char *prof_name = NULL;
	char *base_path = NULL;
	apol_policy_path_t *pol_path = NULL;
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	char *minsev = NULL;
	unsigned char output_override = 0;
	sechk_lib_t *lib;
	sechk_module_t *mod = NULL;
	bool_t list_stop = FALSE;
	bool_t module_help = FALSE;
	apol_vector_t *policy_mods = NULL;

	while ((optc = getopt_long(argc, argv, "p:m:qsvlh::V", longopts, NULL)) != -1) {
		switch (optc) {
		case 'p':
			prof_name = strdup(optarg);
			break;
		case 'm':
			if (minsev) {
				fprintf(stderr, "Error: --min-sev does not work with --module.\n");
				exit(1);
			}
			modname = strdup(optarg);
			break;
#ifdef LIBSEFS
		case OPT_FCFILE:
			fcpath = strdup(optarg);
			break;
#endif
		case 'q':
			if (output_override) {
				fprintf(stderr, "Error: multiple output formats specified.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_QUIET;
			}
			break;
		case 's':
			if (output_override) {
				fprintf(stderr, "Error: multiple output formats specified.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_SHORT;
			}
			break;
		case 'v':
			if (output_override) {
				fprintf(stderr, "Error: multiple output formats specified.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = SECHK_OUT_VERBOSE;
			}
			break;
		case OPT_MIN_SEV:
			if (modname) {
				fprintf(stderr, "Error: --min-sev does not work with --module.\n");
				exit(1);
			}
			minsev = strdup(optarg);
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
			printf("sechecker %s\n%s\n", VERSION, COPYRIGHT_INFO);
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
		printf("\nModule name: %s\n%s\n%s\n", mod->name, mod->detailed_description, mod->opt_description);
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

	/* initialize the policy */
	if (argc - optind) {
		base_path = argv[optind];
		optind++;
		if (argc - optind) {
			if (!(policy_mods = apol_vector_create(NULL)))
				goto exit_err;
			while (argc - optind) {
				if (apol_vector_append(policy_mods, argv[optind++]))
					goto exit_err;
				path_type = APOL_POLICY_PATH_TYPE_MODULAR;
			}
		} else if (apol_file_is_policy_path_list(base_path) > 0) {
			pol_path = apol_policy_path_create_from_file(base_path);
			if (!pol_path) {
				fprintf(stderr, "Error: invalid policy list\n");
				goto exit_err;
			}
		}
		if (!pol_path)
			pol_path = apol_policy_path_create(path_type, base_path, policy_mods);
		if (!pol_path)
			goto exit_err;
		if (sechk_lib_load_policy(pol_path, lib)) {
			pol_path = NULL;
			goto exit_err;
		}
	} else {
		if (sechk_lib_load_policy(NULL, lib))
			goto exit_err;
	}
	/* library now owns path object */
	pol_path = NULL;

	/* set the minimum severity */
	if (minsev && sechk_lib_set_minsev(minsev, lib) < 0)
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
	apol_vector_destroy(&policy_mods);
	free(minsev);
	free(prof_name);
	free(modname);
	sechk_lib_destroy(&lib);
	return 0;

      exit_err:
#ifdef LIBSEFS
	free(fcpath);
#endif
	apol_vector_destroy(&policy_mods);
	free(minsev);
	free(prof_name);
	free(modname);
	apol_policy_path_destroy(&pol_path);
	sechk_lib_destroy(&lib);
	return 1;
}
