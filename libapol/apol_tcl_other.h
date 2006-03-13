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

#ifndef _APOLICY_TCL_H_
#define _APOLICY_TCL_H_

#include <tcl.h>

#include <sepol/sepol.h>

#include "policy.h"
#include "mls-query.h"

/** Global SELinux policy (either read from source or from binary
 *  policy file. */
extern apol_policy_t *policydb;


extern policy_t *policy;  /* global policy DB, defined in apol_tcl.c */

int Apol_Init(Tcl_Interp *interp);
int Apol_GetScriptDir(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int ap_tcl_level_string_to_level(Tcl_Interp *interp, const char *level_string, ap_mls_level_t *level);

/**
 * If the callback arg embedded within the gloabl apol policy is not
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
 * Takes a Tcl string representing an MLS level and converts it to an
 * apol_mls_level_t object.
 *
 * @param interp Tcl interpreter object.
 * @param level_string String representation of an MLS level.
 * @return 0 on success, 1 if an identifier was not unknown, or < 0 on
 * error.
 */
int apol_tcl_string_to_level(Tcl_Interp *interp, const char *level_string,
                             apol_mls_level_t *level);

/**
 * Takes a Tcl string representing an MLS range and converts it to an
 * apol_mls_range_t object.
 *
 * @param interp Tcl interpreter object.
 * @param range_string String representation of an MLS range.
 * @return 0 on success, 1 if an identifier was not unknown, or < 0 on
 * error.
 */
int apol_tcl_string_to_range(Tcl_Interp *interp, const char *range_string,
                             apol_mls_range_t *range);

/**
 * Given a Tcl string representing a range type ("exact", "subset",
 * "superset", or "intersect"), set the appropriate bit within the
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

#endif /*_APOLICY_TCL_H_*/

