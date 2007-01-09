 /* Copyright (C) 2001-2007 Tresys Technology, LLC
  * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com
 */

/* This file contains the tcl/tk initialization code for apol
 */

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tcl.h>
#include <tk.h>
#include "../libapol-tcl/apol_tcl_other.h"
#include <apol/policy-path.h>
#include <apol/util.h>

#define STARTUP_SCRIPT "apol.tcl"
#define COPYRIGHT_INFO "Copyright (C) 2001-2006 Tresys Technology, LLC"

static struct option const opts[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"policy", required_argument, NULL, 'p'},
	{NULL, 0, NULL, 0}
};

static apol_policy_path_t *path = NULL;

int Tcl_AppInit(Tcl_Interp * interp)
{
	char *script;

	if (Tcl_Init(interp) == TCL_ERROR) {
		return TCL_ERROR;
	}
	if (Tk_Init(interp) == TCL_ERROR) {
		return TCL_ERROR;
	}
	/* apolicy packagae initialization */
	if (apol_tcl_init(interp) == TCL_ERROR) {
		return TCL_ERROR;
	}

	/* find and start the TCL scripts */
	if (apol_tcl_get_startup_script(interp, STARTUP_SCRIPT) != TCL_OK) {
		fprintf(stderr, "Error finding TCL script: %s\n", Tcl_GetStringResult(interp));
		Tcl_DeleteInterp(interp);
		Tcl_Exit(1);
	}
        if (asprintf(&script, "%s/%s", interp->result, STARTUP_SCRIPT) < 0) {
            fprintf(stderr, "%s\n", strerror(errno));
		Tcl_DeleteInterp(interp);
		Tcl_Exit(1);
	}
	if (Tcl_EvalFile(interp, script) != TCL_OK) {
		fprintf(stderr, "Error while parsing %s: %s on line %d\n\nIf %s is set, make sure directory is correct.\n",
			script, Tcl_GetStringResult(interp), interp->errorLine, APOL_ENVIRON_VAR_NAME);
		Tcl_DeleteInterp(interp);
		Tcl_Exit(1);
	}
        free(script);

	/* if a policy file was provided on command line, open it */
	if (path != NULL) {
            char *policy_type = "monolithic";
            const char *primary_path = apol_policy_path_get_primary(path);
            Tcl_Obj *command[2], *path_objs[3], *o;
            path_objs[2] = Tcl_NewListObj(0, NULL);
            if (apol_policy_path_get_type(path) == APOL_POLICY_PATH_TYPE_MODULAR) {
                size_t i;
                const apol_vector_t *modules = apol_policy_path_get_modules(path);
                policy_type = "modular";
                for (i = 0; i < apol_vector_get_size(modules); i++) {
                    const char *m = apol_vector_get_element(modules, i);
                    o = Tcl_NewStringObj(m, -1);
                    if (Tcl_ListObjAppendElement(interp, path_objs[2], o) == TCL_ERROR) {
                        fprintf(stderr, "Error building initial load command: %s\n", Tcl_GetStringResult(interp));
                        Tcl_DeleteInterp(interp);
                        Tcl_Exit(1);
                    }
                }
            }
            path_objs[0] = Tcl_NewStringObj(policy_type, -1);
            path_objs[1] = Tcl_NewStringObj(primary_path, -1);
            command[0] = Tcl_NewStringObj("::ApolTop::openPolicyFile", -1);
            command[1] = Tcl_NewListObj(3, path_objs);
            Tcl_EvalObjv(interp, 2, command, TCL_EVAL_GLOBAL);
            apol_policy_path_destroy(&path);
	}
	return TCL_OK;
}

void usage(const char *program_name, bool_t brief)
{
	printf("Usage: %s [OPTIONS] [POLICY ...]\n", program_name);
	if (brief) {
		printf("   Try %s --help for more help.\n\n", program_name);
		return;
	}
	printf("Policy Analysis tool for Security Enhanced Linux.\n\n");
	printf("   POLICY                  open policy from file(s)\n");
	printf("   -v, --version           display version information\n");
	printf("   -h, --help              display this help dialog\n\n");
	return;
}

void print_version_info(void)
{
	printf("apol %s\n", COPYRIGHT_INFO);
	printf("Policy Analysis tool for Security Enhanced Linux.\n\n");
	printf("   GUI version %s\n", VERSION);
	printf("   libapol version %s\n\n", libapol_get_version());
	return;
}

void parse_command_line(int argc, char **argv)
{
	int optc;
	bool_t help, ver;

	help = ver = FALSE;
	while ((optc = getopt_long(argc, argv, "pvh", opts, NULL)) != -1) {
		switch (optc) {
		case 'p':
                    /* flag is deprecated and is now ignored */
			break;
		case 'h':
			help = TRUE;
			break;
		case 'v':
			ver = TRUE;
			break;
		case '?':
			usage(argv[0], FALSE);
			exit(1);
		default:
			break;
		}
	}
	if (help || ver) {
		if (help)
			usage(argv[0], FALSE);
		if (ver)
			print_version_info();
		exit(1);
	}
        if (argc - optind > 0) {
            apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
            char *policy_file = argv[optind];
            apol_vector_t *mod_paths = NULL;
            if (argc - optind > 1) {
                path_type = APOL_POLICY_PATH_TYPE_MODULAR;
		if (!(mod_paths = apol_vector_create())) {
			ERR(NULL, "%s", strerror(ENOMEM));
			exit(1);
		}
		for (optind++; argc - optind; optind++) {
			if (apol_vector_append(mod_paths, argv[optind])) {
				ERR(NULL, "Error loading module %s.", argv[optind]);
				apol_vector_destroy(&mod_paths, NULL);
				exit(1);
			}
		}
            }
            if ((path = apol_policy_path_create(path_type, policy_file, mod_paths)) == NULL) {
				ERR(NULL, "Error loading module %s.", argv[optind]);
				apol_vector_destroy(&mod_paths, NULL);
				exit(1);
            }
            apol_vector_destroy(&mod_paths, NULL);
        }
}

int main(int argc, char *argv[])
{
	Tcl_Interp *interp;

	parse_command_line(argc, argv);
	interp = Tcl_CreateInterp();
	/* Compute the full path name of the executable file from which
	 * the application was invoked and save it for Tcl's internal
	 * use. */
	Tcl_FindExecutable(argv[0]);

	/* Normally, the function 'Tk_MainEx(1, argv, Tcl_AppInit, interp);'
	 * would have been called instead of the following 'if' statement,
	 * however, this would cause apol to run wish in interactive mode,
	 * which is usually used for debugging purposes and this causes a
	 * strange interaction with normal shell operations (backgrounding,
	 * etc).
	 */
	if (Tcl_AppInit(interp) == TCL_OK)
		Tk_MainLoop();

	/* Exit after the event loop returns. */
	exit(0);
}
