 /* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* This file contains the main for seuserx
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <tcl.h>
#include <tk.h>
#include "../libapol/apol_tcl.h"
#include "../libseuser/seuser_tcl.h"

#ifndef STARTUP_SCRIPT
	#define STARTUP_SCRIPT "se_user.tcl"
#endif

#define STRING_LENGTH_MAX 255

int Tcl_AppInit(Tcl_Interp *interp)
{
	char *script;
	char *args[2];
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
 
     	/* seuser package init */
     	if(Seuser_Init(interp) == TCL_ERROR) {
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

	free(script);
    	return TCL_OK;
}

int main(int argc, char *argv[])
{
	Tcl_Interp *interp;
	interp = Tcl_CreateInterp();
	Tk_MainEx(1, argv, Tcl_AppInit, interp);
	exit(0);
}



