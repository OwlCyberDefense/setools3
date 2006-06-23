 /* Copyright (C) 2001-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* This file contains the tcl/tk initialization code for awish
 */

#include <stdlib.h>
#include <stdio.h>
#include <tcl.h>
#include <tk.h>
#include "../libapol/apol_tcl_other.h"


int Tcl_AppInit(Tcl_Interp *interp)
{
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

    	return TCL_OK;
}

int main(int argc, char *argv[])
{

	Tk_Main(argc, argv, Tcl_AppInit);
  	return(0);
}




