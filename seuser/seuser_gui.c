 /* Copyright (C) 2002-2005 Tresys Technology, LLC
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



