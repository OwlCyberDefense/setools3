 /* Copyright (C) 2001-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 */

/* This file contains the tcl/tk initialization code for apol
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tcl.h>
#include <tk.h>
#include <getopt.h>
#include "../libapol/apol_tcl_other.h"
#include "../libapol/util.h"

#ifndef STARTUP_SCRIPT
	#define STARTUP_SCRIPT "apol.tcl"
#endif

/* internal global */
char* policy_conf_file;
static struct option const opts[] = 
{
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"policy", required_argument, NULL, 'p'},
	{NULL, 0, NULL, 0}
};

int Tcl_AppInit(Tcl_Interp *interp)
{
	char *script;
	CONST char *args[2];
	Tcl_DString command;
	int rt;	

	if (Tcl_Init(interp) == TCL_ERROR) {
		return TCL_ERROR;
	}
	if (Tk_Init(interp) == TCL_ERROR) {
		return TCL_ERROR;
	}
	/* apolicy packagae initialization */
	if (Apol_Init(interp) == TCL_ERROR) {
     		return TCL_ERROR;
     	}
     	
     	/* find and start the TCL scripts */
     	args[0] = NULL;
     	args[1] = STARTUP_SCRIPT;
     	if(Apol_GetScriptDir(NULL, interp, 2, args) != TCL_OK) {
     		fprintf(stderr, "Error finding TCL script: %s\n", interp->result);
     		Tcl_DeleteInterp(interp);
     		Tcl_Exit(1);
     	}
     	script = (char *)malloc(strlen(interp->result) + strlen(STARTUP_SCRIPT) + 3);
     	if(script == NULL) {
     		fprintf(stderr, "out of memory\n");
     		Tcl_DeleteInterp(interp);
     		Tcl_Exit(1);
     	}
     	sprintf(script, "%s/%s", interp->result, STARTUP_SCRIPT);
	if(Tcl_EvalFile(interp, script) != TCL_OK) {
		fprintf(stderr, "Error in StartScript (%s): %s on line %d\n\nIf %s is set, make sure directory is correct\n", script, interp->result, interp->errorLine, APOL_ENVIRON_VAR_NAME);
	  	Tcl_DeleteInterp(interp);
	  	Tcl_Exit(1);
	}

	/* If a policy.conf file was provided on command line, open it */
	if(policy_conf_file != NULL) {
		Tcl_DStringInit(&command);
		Tcl_DStringAppend(&command, "ApolTop::openPolicyFile ", strlen("ApolTop::openPolicyFile "));
		Tcl_DStringAppend(&command, policy_conf_file, strlen(policy_conf_file));
		Tcl_DStringAppend(&command, " 0", strlen(" 0"));
		rt = Tcl_Eval(interp, Tcl_DStringValue(&command));
		Tcl_DStringFree(&command);
     	}
	free(script);
    	return TCL_OK;
}

void usage(const char *program_name, bool_t brief) 
{
	printf("Usage: %s [OPTIONS]\n", program_name);
	if (brief) {
		printf("   Try %s --help for more help.\n\n", program_name);
		return;
	}
	printf("Policy Analysis tool for Security Enhanced Linux.\n\n");
	printf("   -p FILE, --policy FILE  open policy file named FILE\n");
	printf("   -v, --version           display version information\n");
	printf("   -h, --help              display this help dialog\n\n");
	return;
}

void print_version_info(void)
{
	printf("Policy Analysis tool for Security Enhanced Linux.\n\n");
	/* printf("   GUI version \n"); 
	 * TODO: can we export a TCL variable to C for GUI version?? */
	printf("   libapol version %s\n\n", libapol_get_version());
	return;
}

void parse_command_line(int argc, char **argv)
{
	int optc;
	bool_t help, ver;

	help = ver = FALSE;
	while ((optc = getopt_long(argc, argv, "p:vh", opts, NULL)) != -1)
	{
		switch(optc) {
		case 'p':
			policy_conf_file = optarg;
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
	if (optind < argc) { /* trailing non-options */
		printf("non-option arguments: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		exit(1);
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
