 /* Copyright (C) 2003-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Jason Tang <jtang@tresys.com>, Kevin Carr <kcarr@tresys.com>
 */

/* tcl_render.h */

/* This file takes various policy stuff and returns formatted Tcl
   lists, suitable for displaying results in Apol. */

#include "policy.h"
#include <tcl.h>

#ifndef AP_TCL_RENDER_H
#define AP_TCL_RENDER_H

int ap_tcl_render_rangetrans(Tcl_Interp *interp, bool_t addlineno, int idx, policy_t *policy);
int ap_tcl_render_addr(Tcl_Interp *interp, int flag, uint32_t addr[4], Tcl_Obj **result);

#endif
