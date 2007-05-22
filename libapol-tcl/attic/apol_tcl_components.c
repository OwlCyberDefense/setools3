/**
 *  @file
 *  Implementation for the apol interface to search for policy components.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "apol_tcl_other.h"
#include "apol_tcl_render.h"
#include "apol_tcl_fc.h"

#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>

#include <tcl.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>		       /* needed for portcon's protocol */

/**
 * Takes a qpol_type_t representing a type and appends a tuple
 * of it to result_list.  The tuple consists of:
 * <code>
 *    { attr_name { type0 type1 ... } }
 * </code>
 */
static int append_attr_to_list(Tcl_Interp * interp, qpol_type_t * attr_datum, Tcl_Obj * result_list)
{
	unsigned char is_attr;
	char *attr_name;
	qpol_iterator_t *type_iter = NULL;
	Tcl_Obj *attr_elem[2], *attr_list;
	int retval = TCL_ERROR;
	if (qpol_type_get_isattr(qpolicydb, attr_datum, &is_attr) < 0) {
		goto cleanup;
	}
	if (!is_attr) {
		/* datum is a type or alias, so don't add it */
		return TCL_OK;
	}
	if (qpol_type_get_name(qpolicydb,
			       attr_datum, &attr_name) < 0 || qpol_type_get_type_iter(qpolicydb, attr_datum, &type_iter) < 0) {
		goto cleanup;
	}
	attr_elem[0] = Tcl_NewStringObj(attr_name, -1);
	attr_elem[1] = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(type_iter); qpol_iterator_next(type_iter)) {
		qpol_type_t *type_datum;
		char *type_name;
		Tcl_Obj *type_obj;
		if (qpol_iterator_get_item(type_iter, (void **)&type_datum) < 0 ||
		    qpol_type_get_name(qpolicydb, type_datum, &type_name) < 0) {
			goto cleanup;
		}
		type_obj = Tcl_NewStringObj(type_name, -1);
		if (Tcl_ListObjAppendElement(interp, attr_elem[1], type_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	attr_list = Tcl_NewListObj(2, attr_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, attr_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&type_iter);
	return retval;
}

/**
 * Returns an unordered list of attribute tuples within the policy.
 * Each tuple consists of:
 * <ul>
 *   <li>attribute name
 *   <li>list of types with that attribute
 * </ul>
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>attribute name to look up, or a regular expression, or empty
 *       to get all attributes
 *   <li>(optional) if true then treat argv[1] as a regex
 * </ol>
 */
static int Apol_GetAttribs(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_type_t *attr;
	apol_attr_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "%s", "Need an attribute name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (qpol_policy_get_type_by_name(qpolicydb, argv[1], &attr) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_attr_to_list(interp, attr, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	} else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_attr_query_create()) == NULL) {
				ERR(policydb, "%s", strerror(ENOMEM));
				goto cleanup;
			}
			if (apol_attr_query_set_attr(policydb, query, argv[1]) ||
			    apol_attr_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_attr_get_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			attr = (qpol_type_t *) apol_vector_get_element(v, i);
			if (append_attr_to_list(interp, attr, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	apol_attr_query_destroy(&query);
	apol_vector_destroy(&v);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return TCL_OK;
}

int apol_tcl_components_init(Tcl_Interp * interp)
{
	Tcl_CreateCommand(interp, "apol_GetAttribs", Apol_GetAttribs, NULL, NULL);
	return TCL_OK;
}
