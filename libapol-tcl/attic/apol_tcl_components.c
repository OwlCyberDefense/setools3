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

/**
 * Takes a qpol_class_t representing a class and appends a
 * tuple of it to result_list.	 The tuple consists of:
 * <code>
 *    { class_name common_class {perms0 perms1 ...} }
 * </code>
 *
 * If the object class has no common, then the second element will be
 * an empty string.
 */
static int append_class_to_list(Tcl_Interp * interp, qpol_class_t * class_datum, Tcl_Obj * result_list)
{
	char *class_name, *common_name = "";
	qpol_common_t *common_datum;
	qpol_iterator_t *perm_iter = NULL;
	Tcl_Obj *class_elem[3], *class_list;
	int retval = TCL_ERROR;
	if (qpol_class_get_name(qpolicydb,
				class_datum, &class_name) < 0 ||
	    qpol_class_get_common(qpolicydb,
				  class_datum, &common_datum) < 0 ||
	    (common_datum != NULL &&
	     qpol_common_get_name(qpolicydb,
				  common_datum, &common_name) < 0) ||
	    qpol_class_get_perm_iter(qpolicydb, class_datum, &perm_iter) < 0) {
		goto cleanup;
	}
	class_elem[0] = Tcl_NewStringObj(class_name, -1);
	class_elem[1] = Tcl_NewStringObj(common_name, -1);
	class_elem[2] = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		char *perm_name;
		Tcl_Obj *perm_obj;
		if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0) {
			goto cleanup;
		}
		perm_obj = Tcl_NewStringObj(perm_name, -1);
		if (Tcl_ListObjAppendElement(interp, class_elem[2], perm_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	class_list = Tcl_NewListObj(3, class_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, class_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

/**
 * Returns an unordered list of class tuples within the policy.  Each
 * tuple consists of:
 * <ul>
 *   <li>class name
 *   <li>class's common class, or empty string if none
 *   <li>list of class's permissions
 * </ul>
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>class name to look up, or a regular expression, or empty to
 *       get all classes
 *   <li>(optional) treat argv[1] as a class name or regex
 * </ol>
 */
static int Apol_GetClasses(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_class_t *class_datum;
	apol_class_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "%s", "Need a class name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (qpol_policy_get_class_by_name(qpolicydb, argv[1], &class_datum) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_class_to_list(interp, class_datum, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	} else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_class_query_create()) == NULL) {
				ERR(policydb, "%s", strerror(ENOMEM));
				goto cleanup;
			}
			if (apol_class_query_set_class(policydb, query, argv[1]) ||
			    apol_class_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_class_get_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			class_datum = (qpol_class_t *) apol_vector_get_element(v, i);
			if (append_class_to_list(interp, class_datum, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	apol_class_query_destroy(&query);
	apol_vector_destroy(&v);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a qpol_common_t representing a common and appends a
 * tuple of it to result_list.	 The tuple consists of:
 * <code>
 *    { common_name {perms0 perms1 ...} {class0 class1 ...} }
 * </code>
 *
 * The second list is a list of object classes that inherit from this
 * common.
 */
static int append_common_to_list(Tcl_Interp * interp, qpol_common_t * common_datum, Tcl_Obj * result_list)
{
	char *common_name;
	qpol_iterator_t *perm_iter = NULL;
	apol_class_query_t *query = NULL;
	apol_vector_t *classes = NULL;
	size_t i;
	Tcl_Obj *common_elem[3], *common_list;
	int retval = TCL_ERROR;
	if (qpol_common_get_name(qpolicydb,
				 common_datum, &common_name) < 0 ||
	    qpol_common_get_perm_iter(qpolicydb, common_datum, &perm_iter) < 0) {
		goto cleanup;
	}
	common_elem[0] = Tcl_NewStringObj(common_name, -1);
	common_elem[1] = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		char *perm_name;
		Tcl_Obj *perm_obj;
		if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0) {
			goto cleanup;
		}
		perm_obj = Tcl_NewStringObj(perm_name, -1);
		if (Tcl_ListObjAppendElement(interp, common_elem[1], perm_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	common_elem[2] = Tcl_NewListObj(0, NULL);
	if ((query = apol_class_query_create()) == NULL ||
	    apol_class_query_set_common(policydb, query, common_name) < 0 ||
	    apol_class_get_by_query(policydb, query, &classes) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(classes); i++) {
		qpol_class_t *class_datum = (qpol_class_t *) apol_vector_get_element(classes, i);
		char *class_name;
		Tcl_Obj *class_obj;
		if (qpol_class_get_name(qpolicydb, class_datum, &class_name) < 0) {
			goto cleanup;
		}
		class_obj = Tcl_NewStringObj(class_name, -1);
		if (Tcl_ListObjAppendElement(interp, common_elem[2], class_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	common_list = Tcl_NewListObj(3, common_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, common_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&perm_iter);
	apol_class_query_destroy(&query);
	apol_vector_destroy(&classes);
	return retval;
}

/**
 * Returns an unordered list of common tuples within the policy.  Each
 * tuple consists of:
 * <ul>
 *   <li>common name
 *   <li>list of common's permissions
 *   <li>list of classes that inherit this common
 * </ul>
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>common name to look up, or a regular expression, or empty to
 *       get all common
 *   <li>(optional) treat argv[1] as a common name or regex
 * </ol>
 */
static int Apol_GetCommons(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_common_t *common_datum;
	apol_common_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "%s", "Need a common name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (qpol_policy_get_common_by_name(qpolicydb, argv[1], &common_datum) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_common_to_list(interp, common_datum, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	} else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_common_query_create()) == NULL) {
				ERR(policydb, "%s", strerror(ENOMEM));
				goto cleanup;
			}
			if (apol_common_query_set_common(policydb, query, argv[1]) ||
			    apol_common_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_common_get_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			common_datum = (qpol_common_t *) apol_vector_get_element(v, i);
			if (append_common_to_list(interp, common_datum, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	apol_common_query_destroy(&query);
	apol_vector_destroy(&v);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

int apol_tcl_components_init(Tcl_Interp * interp)
{
	Tcl_CreateCommand(interp, "apol_GetAttribs", Apol_GetAttribs, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetClasses", Apol_GetClasses, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetCommons", Apol_GetCommons, NULL, NULL);
	return TCL_OK;
}
