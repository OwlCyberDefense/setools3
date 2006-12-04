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

#ifdef	__cplusplus
extern "C"
{
#endif

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
	extern int apol_level_to_tcl_obj(Tcl_Interp * interp, apol_mls_level_t * level, Tcl_Obj ** obj);

	extern int apol_tcl_render_init(Tcl_Interp * interp);

#ifdef	__cplusplus
}
#endif

#endif
