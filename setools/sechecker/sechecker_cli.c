/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h" 
#include "policy.h"
#include "modules/register_list.h"

#include <stdio.h>
#include <string.h>
#include <getopt.h>

/* SECHECKER_VERSION should be defined in the make environment */
#ifndef SECHECKER_VERSION
#define SECHECKER_VERSION "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2005 Tresys Technology, LLC"

static struct option const longopts[] = 
{
	{"config", required_argument, NULL, 'c'},
	{"polsrcdir", required_argument, NULL, 'p'},
	{"short", no_argument, NULL, 's'},
	{"quiet", no_argument, NULL, 'q'},
	{"verbose", no_argument, NULL, 'V'},
	{"system", no_argument, NULL, 'y'},
	{"develop", no_argument, NULL, 'd'},
	{"module", required_argument, NULL, 'm'},
	{"list", no_argument, NULL, 'l'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

void usage(const char *arg0, bool_t brief) 
{
	printf("%s (sechecker v%s)\n\n", COPYRIGHT_INFO, SECHECKER_VERSION);
	printf("Usage: %s [OPTIONS]\n", arg0);
	if (brief) {
		printf("\n\tTry %s --help for more help.\n\n", arg0);
	} else {
		printf("Perform modular checks on a SELinux policy\n");
		printf("\nConfiguration Options\n");
		printf("   -c conffile, --config=conffile  The location of the config file to load\n");
		printf("   -p dir, --polsrcdir=dir         The top directory of a policy source tree\n");
		printf("                                   e.g. /etc/selinux/strict  \n");
		printf("                                   Default: loads default policy\n");
		printf("\nOutput Options (only one may be specified)\n");
		printf("   -s, --short                     Use short output format for all modules\n");
		printf("   -V, --verbose                   Use verbose output format for all modules\n");
		printf("   -q, --quiet                     Output only module name and statistics\n");
		printf("\nModule Options\n");
		printf("   -m module, --module=mod_name    Run only specified module (with dependencies)\n");
		printf("   -l, --list                      Print a list of available modules and exit\n");
		printf("   -d, --develop                   Run development mode modules\n");
		printf("   -y, --system                    Run system check mode modules\n");
		printf("\nOther Options\n");
		printf("   -h, --help                      Print this help message and exit\n");
		printf("   -v, --version                   Print version information and exit\n");
	}
}

int main(int argc, char **argv) 
{
	int optc = 0, retv = 0, i;
	char *confpath = NULL, *polpath = NULL, *modname = NULL;
	unsigned char output_override = 0, run_mode = SECHK_MOD_TYPE_NONE;
	sechk_lib_t *module_library;
	bool_t list_stop = FALSE;
/* XXX temporary */sechk_get_output_str_fn_t print_me = NULL;sechk_module_t *mod = NULL;

fprintf(stderr, "parse cmd line\n");
	while ((optc = getopt_long(argc, argv, "c:p:sVqm:ldyhv", longopts, NULL)) != -1) {
		switch (optc) {
		case 'c':
			confpath = optarg;
			break;
		case 'p':
			polpath = optarg;
			break;
		case 's':
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
		case 'q':
			if (output_override) {
				fprintf(stderr, "Error: Multiple output specifications.\n");
				usage(argv[0], 1);
				exit(1);
			} else {
				output_override = (SECHK_OUT_STATS|SECHK_OUT_HEADER);
			}
			break;
		case 'm':
			modname = optarg;
			break;
		case 'l':
			list_stop = TRUE;
			break;
		case 'd':
			run_mode |= SECHK_MOD_TYPE_DEV;
			break;
		case 'y':
			run_mode |= SECHK_MOD_TYPE_SYS;
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

	if (!run_mode)
		run_mode = SECHK_MOD_TYPE_DEV;
fprintf(stderr, "new lib\n");
	module_library = new_sechk_lib(polpath, confpath, output_override);
	if (!module_library) {
		fprintf(stderr, "Error: undable to create module library\n");
		exit(1);
	}

fprintf(stderr, "hacked parse\n");
/* XXX hack start XXX */
	module_library->modules = (sechk_module_t*)calloc(3, sizeof(sechk_module_t));
	module_library->num_modules = 3;
	module_library->modules[0].name = strdup("domain_and_file_type");
	module_library->modules[0].type = SECHK_MOD_TYPE_DEV;
	module_library->modules[0].options = new_sechk_opt();
	module_library->modules[0].options->name = strdup("depend_mod");
	module_library->modules[0].options->value = strdup("domain_type");
	module_library->modules[0].options->next = new_sechk_opt();
	module_library->modules[0].options->next->name = strdup("depend_mod");
	module_library->modules[0].options->next->value = strdup("file_type");
	module_library->modules[1].name = strdup("domain_type");
	module_library->modules[1].type = SECHK_MOD_TYPE_DEV;
	module_library->modules[1].options = new_sechk_opt();
	module_library->modules[1].options->name = strdup("domain_attribute");
	module_library->modules[1].options->value = strdup("domain");
	module_library->modules[2].name = strdup("file_type");
	module_library->modules[2].type = SECHK_MOD_TYPE_DEV;
	module_library->modules[2].options = new_sechk_opt();
	module_library->modules[2].options->name = strdup("file_type_attribute");
	module_library->modules[2].options->value = strdup("file_type");
	module_library->conf->outformat = (output_override ? output_override : 0x0F);
	module_library->conf->selinux_config_path = strdup("/etc/selinux/config");
	module_library->conf->module_selection = (bool_t*)calloc(2, sizeof(bool_t));
	module_library->conf->module_selection[0] = TRUE;
	module_library->conf->module_selection[1] = FALSE;
	module_library->conf->module_selection[2] = FALSE;
/* XXX hack end XXX */

fprintf(stderr, "register\n");
	retv = register_modules(register_list, module_library);
	if (retv) {
		fprintf(stderr, "Error: failed to register modules\n");
		free_sechk_lib(&module_library);
		exit(1);
	}

	if (list_stop) {
		printf("\nAvailable Modules:\n");
		for (i = 0; i < module_library->num_modules; i++) {
			printf("   %s\n", module_library->modules[i].name);
		}
		free_sechk_lib(&module_library);
		exit(0);
	}

fprintf(stderr, "init\n");
	retv = init_modules(module_library);
	if (retv) {
		fprintf(stderr, "Error: failed to initialize modules\n");
		free_sechk_lib(&module_library);
		exit(1);
	}

fprintf(stderr, "run\n");
	retv = run_modules(run_mode, module_library);
	if (retv) {
		fprintf(stderr, "Error: failed running modules\n");
		free_sechk_lib(&module_library);
		exit(1);
	}
	
	/* XXX TODO output */
/* XXX temporary start XXX */
	fprintf(stderr, "set fn ptr\n");
	print_me = get_module_function("domain_type", "get_output_str", module_library);
	fprintf(stderr, "set mod ptr\n");
	mod = get_module("domain_type", module_library);
	fprintf(stderr, "call fn at %p\n", print_me);
	printf("%s", print_me(mod, module_library->policy));
	printf("\n");
	fprintf(stderr, "set fn ptr\n");
	print_me = get_module_function("file_type", "get_output_str", module_library);
	fprintf(stderr, "set mod ptr\n");
	mod = get_module("file_type", module_library);
	fprintf(stderr, "call fn at %p\n", print_me);
	printf("%s", print_me(mod, module_library->policy));
	printf("\n");
	fprintf(stderr, "set fn ptr\n");
	print_me = get_module_function("domain_and_file_type", "get_output_str", module_library);
	fprintf(stderr, "set mod ptr\n");
	mod = get_module("domain_and_file_type", module_library);
	fprintf(stderr, "call fn at %p\n", print_me);
	printf("%s", print_me(mod, module_library->policy));
	fprintf(stderr, "done hack print\n");
/* XXX temporary end XXX*/

fprintf(stderr, "free\n");
	free_sechk_lib(&module_library);
	
fprintf(stderr, "done\n");
	return 0;
}
