/* Copyright (C) 2002-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 */

/* apol_tcl_other.h
 *
 */
 
#ifndef _APOLICY_TCL_H_
#define _APOLICY_TCL_H_

#include <tcl.h>

#include <sepol/sepol.h>

/** Global policy handle for all of apol. */
extern sepol_handle_t *policy_handle;

/** Global SELinux policy (either read from source or from binary
 *  policy file. */
extern sepol_policydb_t *policydb;



#include "policy.h"

extern policy_t *policy;  /* global policy DB, defined in apol_tcl.c */

/* The tcl functions to support the GUI using TK */
int Apol_Init(Tcl_Interp *interp);
int Apol_GetScriptDir(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int ap_tcl_level_string_to_level(Tcl_Interp *interp, const char *level_string, ap_mls_level_t *level);

#endif /*_APOLICY_TCL_H_*/

