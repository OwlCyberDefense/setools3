/**
 *  @file apol_tcl_render.h
 *  Apol interface to render parts of a policy.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "policy.h"
#include <tcl.h>

#ifndef APOL_TCL_RENDER_H
#define APOL_TCL_RENDER_H

extern int apol_tcl_render_init(Tcl_Interp *interp);

int ap_tcl_append_type_str(bool_t do_attribs, bool_t do_aliases, bool_t newline, int idx,
                           policy_t *policy, Tcl_DString *buf);
int ap_tcl_append_attrib_str(bool_t do_types, bool_t do_type_attribs, bool_t use_aliases,
                             bool_t newline, bool_t upper, int idx, policy_t *policy, Tcl_DString *buf);

#endif
