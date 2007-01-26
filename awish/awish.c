/**
 * @file
 * Initialization code for awish.  This wraps the normal wish
 * interpreter with the hooks to libapol.
 *
 *  @author Frank Mayer mayerf@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2001-2007 Tresys Technology, LLC
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

#include <stdlib.h>
#include <stdio.h>
#include <tcl.h>
#include <tk.h>
#include "../libapol-tcl/apol_tcl_other.h"

int Tcl_AppInit(Tcl_Interp * interp)
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
	return (0);
}
