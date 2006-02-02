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

int ap_tcl_render_init(Tcl_Interp *interp);

int ap_tcl_append_type_str(bool_t do_attribs, bool_t do_aliases, bool_t newline, int idx, 
                           policy_t *policy, Tcl_DString *buf);
int ap_tcl_append_attrib_str(bool_t do_types, bool_t do_type_attribs, bool_t use_aliases, 
                             bool_t newline, bool_t upper, int idx, policy_t *policy, Tcl_DString *buf);

#endif
