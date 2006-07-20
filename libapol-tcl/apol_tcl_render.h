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

#include <tcl.h>

#ifndef APOL_TCL_RENDER_H
#define APOL_TCL_RENDER_H

/**
 * Converts an apol_mls_level_t to a Tcl representation:
 * <code>
 *   { level { cat0 cat1 ... } }
 * </code>
 *
 * @param interp Tcl interpreter object.
 * @param level Level to convert.
 * @param obj Destination to create Tcl object representing level.
 *
 * @return 0 if level was converted, <0 on error.
 */
extern int apol_level_to_tcl_obj(Tcl_Interp *interp,
				 apol_mls_level_t *level,
				 Tcl_Obj **obj);

/**
 * Converts a qpol_avrule_t to a Tcl representation:
 * The tuple consists of:
 * <code>
 *    { rule_type source_type_set target_type_set object_class perm_set
 *      line_number cond_info }
 * </code>
 * The type sets and perm sets are Tcl lists.  If cond_info is an
 * empty list then this rule is unconditional.  Otherwise cond_info is
 * a 2-uple list, where the first element is either "enabled" or
 * "disabled", and the second element is the line number for its
 * conditional expression.
 */
extern int apol_avrule_to_tcl_obj(Tcl_Interp *interp,
				  qpol_avrule_t *avrule,
				  Tcl_Obj **obj);

extern int apol_tcl_render_init(Tcl_Interp *interp);

#endif
