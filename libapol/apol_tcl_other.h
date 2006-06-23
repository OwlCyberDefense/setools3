/**
 * @file apol_tcl_other.c
 *
 * Miscellaneous routines that translate between apol (a Tcl/Tk
 * application) and libapol.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2002-2006 Tresys Technology, LLC
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

#ifndef APOL_TCL_OTHER_H
#define APOL_TCL_OTHER_H

#include <tcl.h>

#include <qpol/policy_query.h>

#include "policy.h"
#include "policy-query.h"
#include "mls-query.h"

/** Global SELinux policy (either read from source or from binary
 *  policy file, defined in apol_tcl_other.c. */
extern apol_policy_t *policydb;

/**
 * Initializes the libapol-tcl library and registers all of the
 * libapol-tcl commands.
 */
extern int apol_tcl_init(Tcl_Interp *interp);

/**
 * Determines the location of the main apol Tcl file, and assigns it
 * to the Tcl interpreter's result field.
 *
 * @param interp Tcl interpreter, to store result.
 * @param name of the Tcl file
 *
 * @return TCL_OK if apol.tcl was found, TCL_ERROR if not.
 */
extern int apol_tcl_get_startup_script(Tcl_Interp *interp, char *name);

/**
 * If the callback arg embedded within the global apol policy is not
 * NULL, then set the Tcl interpreter's result string to it.  That arg
 * is then reset to NULL afterwards.  If the arg was NULL to begin
 * with then do nothing.
 *
 * @param interp Tcl interpreter object.
 */
void apol_tcl_write_error(Tcl_Interp *interp);

/**
 * Clears and resets the callback arg string within the global apol
 * policy structure, if it is present.
 */
void apol_tcl_clear_error(void);

/**
 * Given a string representing a Tcl level object, fill the passed
 * apol_mls_level_t structure with the level information.  A Tcl level
 * object consists of:
 *
 *  { sens {cat0 cat1 ...} }
 *
 * @param interp Tcl interpreter object.
 * @param level_string Character string representing a Tcl level.
 * @param level Destination to write level data.
 *
 * @return 0 if level converted, 1 if an identifier is not known
 * according to the policy, <0 on error.
 */
extern int apol_tcl_string_to_level(Tcl_Interp *interp, const char *level_string,
				    apol_mls_level_t *level);

/**
 * Given a string representing a Tcl range object, fill the passed
 * apol_mls_range_t structure with the range information.  A Tcl range
 * object consists of:
 *
 *  { sens {cat0 cat1 ...} } [{ sens {cat0 cat1 ...} }]
 *
 * If the string only has one element then treat the range's high
 * level to be equivalent to its low.
 *
 * @param interp Tcl interpreter object.
 * @param range_string Character string representing a Tcl range.
 * @param range Destination to write range data.
 *
 * @return 0 if range converted, 1 if an identifier is not known
 * according to the policy, <0 on error.
 */
extern int apol_tcl_string_to_range(Tcl_Interp *interp, const char *range_string,
				    apol_mls_range_t *range);

/**
 * Given a Tcl string representing a range type ("exact", "subset",
 * "superset", or "intersect"), set the appropriate bits within the
 * flags reference variable.  If the string is not any of the above
 * then do not modify flags at all.
 *
 * @param interp Tcl interpreter object.
 * @param range_match_string String representation of how to match a
 * range.
 * @return 0 on success, < 0 if the string is invalid.
 */
int apol_tcl_string_to_range_match(Tcl_Interp *interp, const char *range_match_string,
                                   unsigned int *flags);


/**
 * Given a string representing a Tcl context object, fill the passed
 * apol_context_t structure with as much information as possible.  A
 * Tcl context object consists of:
 *
 *   { user role type [range] }
 *
 * where the range is optional.	 If it is given, the range a 1-ple or
 * 2-ple list of levels.
 *
 * @param interp Tcl interpreter object.
 * @param context_string Character string represting a Tcl context.
 * @param context Destination to write context data.
 *
 * @return 0 if context converted, 1 if an identifier is not known
 * according to the policy, <0 on error.
 */
extern int apol_tcl_string_to_context(Tcl_Interp *interp,
				      const char *context_string,
				      apol_context_t *context);

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

#endif
