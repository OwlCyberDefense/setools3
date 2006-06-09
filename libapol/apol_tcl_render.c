/**
 * @file apol_tcl_render.c
 * Implementation for the apol interface to render parts of a policy.
 * This file takes various policy stuff and returns formatted Tcl
 * lists, suitable for displaying results in Apol.
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
#include "apol_tcl_other.h"

#include <tcl.h>

/**
 * Take a Tcl string representing a level (level = sensitivity + list
 * of categories) and return a string representation of it.  If the
 * level is nat valid according to the policy then return an empty
 * string.
 *
 * @param argv A MLS level.
 */
static int Apol_RenderLevel(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj;
	apol_mls_level_t *level = NULL;
	char *rendered_level = NULL;
	int retval = TCL_ERROR, retval2;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "Need a level to render.");
		goto cleanup;
	}
	if ((level = apol_mls_level_create()) == NULL) {
		ERR(policydb, "Out of memory.");
		goto cleanup;
	}
	retval2 = apol_tcl_string_to_level(interp, argv[1], level);
	if (retval2 < 0) {
		goto cleanup;
	}
	else if (retval2 == 1) {
		/* no render possible */
		retval = TCL_OK;
		goto cleanup;
	}
	if ((rendered_level = apol_mls_level_render(policydb, level)) == NULL) {
		goto cleanup;
	}
	result_obj = Tcl_NewStringObj(rendered_level, -1);
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_mls_level_destroy(&level);
	free(rendered_level);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl string representing a context and return a string
 * representation of it.  A Tcl context is:
 * <code>
 *   { user role type range }
 * </code>
 *
 * If the policy is non-mls, then the fourth parameter is ignored.
 *
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>Tcl string representing a context
 * </ol>
 */
static int Apol_RenderContext(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj;
	apol_context_t *context = NULL;
	char *rendered_context = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "Need a context.");
		goto cleanup;
	}
	if ((context = apol_context_create()) == NULL) {
		ERR(policydb, "Out of memory!");
		goto cleanup;
	}
	if (apol_tcl_string_to_context(interp, argv[1], context) < 0) {
		goto cleanup;
	}

	/* check that all components exist */
	if (context->user == NULL || context->role == NULL || context->type == NULL ||
	    (apol_policy_is_mls(policydb) && context->range == NULL)) {
		ERR(policydb, "Context string '%s' is not valid.", argv[1]);
		goto cleanup;
	}
	if ((rendered_context = apol_context_render(policydb, context)) == NULL) {
		goto cleanup;
	}
	result_obj = Tcl_NewStringObj(rendered_context, -1);
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_context_destroy(&context);
	free(rendered_context);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

int apol_tcl_render_init(Tcl_Interp *interp) {
        Tcl_CreateCommand(interp, "apol_RenderLevel", Apol_RenderLevel, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderContext", Apol_RenderContext, NULL, NULL);
	return TCL_OK;
}
