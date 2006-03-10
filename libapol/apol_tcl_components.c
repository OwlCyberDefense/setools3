/* Copyright (C) 2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 */

#include <tcl.h>
#include <assert.h>

#include "component-query.h"

#include "apol_tcl_other.h"
#include "apol_tcl_render.h"
#include "apol_tcl_fc.h"

/* get a list of policy resource names names. Caller may optionally provide a regular
 * expression to limit the list of returned names.
 *
 * TODO: NOTE: Currently regex option will only work for "types".
 */
/* 
 * argv[1] indicates which name list to return, possible values are:
 * 	types
 * 	attrib
 *	roles
 * 	users
 * 	classes
 *	perms
 *	common_perms
 * 	initial_sids
 * argv[2] (OPTIONAL) regular expression
 */
static int Apol_GetNames(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	int i, rt, sz, num, *idx_array;
	char *name, *err, tmpbuf[APOL_STR_SZ+64];
	bool_t use_regex = FALSE;
	regex_t reg;
	
	if(argc > 3 || argc < 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	Tcl_ResetResult(interp);
	/* handle optional regular expression */
	if(argc == 3) {
		if(strcmp("types", argv[1]) != 0) {
			Tcl_AppendResult(interp, "Regular expressions are currently only supported for types", (char *) NULL);
			return TCL_ERROR;
		} 
		use_regex = TRUE;
		if(!is_valid_str_sz(argv[2])) {
			Tcl_AppendResult(interp, "Regular expression string too large", (char *) NULL);
			return TCL_ERROR;
		}
		rt = regcomp(&reg, argv[2], REG_EXTENDED|REG_NOSUB);
		if(rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				Tcl_AppendResult(interp, "out of memory", (char *) NULL);
				return TCL_ERROR;
			}
			regerror(rt, &reg, err, sz);
			sprintf(tmpbuf, "Invalid regular expression:\n\n     %s\n\n", argv[2]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			Tcl_AppendResult(interp, err, (char *) NULL);
			free(err);
			return TCL_ERROR;
			
		}
	}
	
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(strcmp("types", argv[1]) == 0) {
		if(!use_regex) {
			for(i = 0; get_type_name(i, &name, policy) == 0; i++) {
				Tcl_AppendElement(interp, name);
				free(name);
			}
		} 
		else {
			rt = get_type_idxs_by_regex(&idx_array, &num, &reg, TRUE, policy);
			if(rt < 0) {
				Tcl_AppendResult(interp, "Error searching types\n", (char *) NULL);
				return TCL_ERROR;
			}
			for(i = 0; i < num; i++) {
				if(get_type_name(idx_array[i], &name, policy) != 0) {
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "Unexpected error getting type name\n", (char *) NULL);
					return TCL_ERROR;
				} 
				Tcl_AppendElement(interp, name);
				free(name);
			} 
			if(num > 0) 
				free(idx_array);
		} 
	}
	else if(strcmp("classes", argv[1]) == 0) {
		for(i = 0; get_obj_class_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}
	}
	else if(strcmp("perms", argv[1]) == 0) {
		for(i = 0; get_perm_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}
	}
	else if(strcmp("initial_sids", argv[1]) == 0) {
		for(i = 0; get_initial_sid_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}		
	}
	else {
		if(use_regex) 
			regfree(&reg);
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "invalid name class (types, attribs, roles, users, classes, perms, or common_perms)", (char *) NULL);
		return TCL_ERROR;
	}	
	if(use_regex) 
		regfree(&reg);
			
	return TCL_OK;
}

/* Takes a sepol_type_datum_t and appends a tuple of it to results_list.
 * The tuple consists of:
 *    { type_name {attrib0 attrib1 ...} {alias0 alias1 ...}}
 */
static int append_type_to_list(Tcl_Interp *interp,
			       sepol_type_datum_t *type_datum,
			       Tcl_Obj *result_list)
{
	unsigned char is_attr;
	char *type_name;
	sepol_iterator_t *attr_iter = NULL, *alias_iter = NULL;
	Tcl_Obj *type_elem[3], *type_list;
	int retval = TCL_ERROR;
	if (sepol_type_datum_get_isattr(policydb->sh, policydb->p,
					 type_datum, &is_attr) < 0) {
		Tcl_SetResult(interp, "Could not get isalias.", TCL_STATIC);
		goto cleanup;
	}
	if (is_attr) {
		/* datum is an attribute, so don't add it */
		return TCL_OK;
	}
	if (sepol_type_datum_get_name(policydb->sh, policydb->p,
				      type_datum, &type_name) < 0) {
		Tcl_SetResult(interp, "Could not get type name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_type_datum_get_attr_iter(policydb->sh, policydb->p,
					   type_datum, &attr_iter) < 0) {
		Tcl_SetResult(interp, "Could not get attr iterator.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_type_datum_get_alias_iter(policydb->sh, policydb->p,
					    type_datum, &alias_iter) < 0) {
		Tcl_SetResult(interp, "Could not get alias iterator.", TCL_STATIC);
		goto cleanup;
	}
	type_elem[0] = Tcl_NewStringObj(type_name, -1);
	type_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(attr_iter); sepol_iterator_next(attr_iter)) {
		sepol_type_datum_t *attr_datum;
		char *attr_name;
		Tcl_Obj *attr_obj;
		if (sepol_iterator_get_item(attr_iter, (void **) &attr_datum) < 0 ||
		    sepol_type_datum_get_name(policydb->sh, policydb->p,
					      attr_datum, &attr_name) < 0) {
			Tcl_SetResult(interp, "Could not get attr name.", TCL_STATIC);
			goto cleanup;
		}
		attr_obj = Tcl_NewStringObj(attr_name, -1);
		if (Tcl_ListObjAppendElement(interp, type_elem[1], attr_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	type_elem[2] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(alias_iter); sepol_iterator_next(alias_iter)) {
		char *alias_name;
		Tcl_Obj *alias_obj;
		if (sepol_iterator_get_item(alias_iter, (void **) &alias_name) < 0) {
			Tcl_SetResult(interp, "Could not get alias name.", TCL_STATIC);
			goto cleanup;
		}
		alias_obj = Tcl_NewStringObj(alias_name, -1);
		if (Tcl_ListObjAppendElement(interp, type_elem[2], alias_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	type_list = Tcl_NewListObj(3, type_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, type_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	sepol_iterator_destroy(&attr_iter);
	sepol_iterator_destroy(&alias_iter);
	return retval;
}

/* Returns an unordered list of type tuples within the policy.
 *   elem 0 - type name
 *   elem 1 - list of associated attributes
 *   elem 2 - list of associated aliases
 * argv[1] - type name to look up, or a regular expression, or empty
 *	     to get all types
 * argv[2] - (optional) treat argv[1] as a type name or regex
 */
static int Apol_GetTypes(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_type_datum_t *type;
	
	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a type name and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (sepol_policydb_get_type_by_name(policydb->sh, policydb->p,
						    argv[1], &type) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_type_to_list(interp, type, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[2], -1);
		int regex_flag;
		apol_type_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_type_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_type_query_set_type(query, argv[1]) ||
			    apol_type_query_set_regex(query, regex_flag)) {
				apol_type_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_type_by_query(policydb, query, &v) < 0) {
			apol_type_query_destroy(&query);
			Tcl_SetResult(interp, "Error running type query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_type_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			type = (sepol_type_datum_t *) apol_vector_get_element(v, i);
			if (append_type_to_list(interp, type, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

/* Takes a sepol_type_datum_t representing a type and appends a tuple
 * of it to results_list.  The tuple consists of:
  *    { attr_name { type0 type1 ... } }
 */
static int append_attr_to_list(Tcl_Interp *interp,
			       sepol_type_datum_t *attr_datum,
			       Tcl_Obj *result_list)
{
	unsigned char is_attr;
	char *attr_name;
	sepol_iterator_t *type_iter = NULL;
	Tcl_Obj *attr_elem[2], *attr_list;
	int retval = TCL_ERROR;
	if (sepol_type_datum_get_isattr(policydb->sh, policydb->p,
					 attr_datum, &is_attr) < 0) {
		Tcl_SetResult(interp, "Could not get isalias.", TCL_STATIC);
		goto cleanup;
	}
	if (!is_attr) {
		/* datum is a type or alias, so don't add it */
		return TCL_OK;
	}
	if (sepol_type_datum_get_name(policydb->sh, policydb->p,
				      attr_datum, &attr_name) < 0) {
		Tcl_SetResult(interp, "Could not get attr name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_type_datum_get_type_iter(policydb->sh, policydb->p,
					   attr_datum, &type_iter) < 0) {
		Tcl_SetResult(interp, "Could not get type iterator.", TCL_STATIC);
		goto cleanup;
	}
	attr_elem[0] = Tcl_NewStringObj(attr_name, -1);
	attr_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(type_iter); sepol_iterator_next(type_iter)) {
		sepol_type_datum_t *type_datum;
		char *type_name;
		Tcl_Obj *type_obj;
		if (sepol_iterator_get_item(type_iter, (void **) &type_datum) < 0 ||
		    sepol_type_datum_get_name(policydb->sh, policydb->p,
					      type_datum, &type_name) < 0) {
			Tcl_SetResult(interp, "Could not get type name.", TCL_STATIC);
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
	sepol_iterator_destroy(&type_iter);
	return retval;
}

/* Returns an unordered list of attribute tuples within the policy.
 *   elem 0 - attribute name
 *   elem 1 - list of types with that attribute
 * argv[1] - attribute name to look up, or a regular expression, or
 *	     empty to get all attributes
 * argv[2] - (optional) treat argv[1] as an attribute name or regex
 */
static int Apol_GetAttribs(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_type_datum_t *attr;

	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need an attribute name and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (sepol_policydb_get_type_by_name(policydb->sh, policydb->p,
						    argv[1], &attr) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_attr_to_list(interp, attr, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[2], -1);
		int regex_flag;
		apol_attr_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_attr_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_attr_query_set_attr(query, argv[1]) ||
			    apol_attr_query_set_regex(query, regex_flag)) {
				apol_attr_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_attr_by_query(policydb, query, &v) < 0) {
			apol_attr_query_destroy(&query);
			Tcl_SetResult(interp, "Error running attr query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_attr_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			attr = (sepol_type_datum_t *) apol_vector_get_element(v, i);
			if (append_attr_to_list(interp, attr, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

/* Takes a sepol_class_datum_t representing a class and appends a
 * tuple of it to results_list.	 The tuple consists of:
 *    { class_name common_class {perms0 perms1 ...} }
 * If the object class has no common, then the second element will be
 * an empy string.
 */
static int append_class_to_list(Tcl_Interp *interp,
				sepol_class_datum_t *class_datum,
				Tcl_Obj *result_list)
{
	char *class_name, *common_name = "";
	sepol_common_datum_t *common_datum;
	sepol_iterator_t *perm_iter = NULL;
	Tcl_Obj *class_elem[3], *class_list;
	int retval = TCL_ERROR;
	if (sepol_class_datum_get_name(policydb->sh, policydb->p,
				       class_datum, &class_name) < 0) {
		Tcl_SetResult(interp, "Could not get class name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_class_datum_get_common(policydb->sh, policydb->p,
					 class_datum, &common_datum) < 0 ||
	    (common_datum != NULL &&
	     sepol_common_datum_get_name(policydb->sh, policydb->p,
					 common_datum, &common_name) < 0)) {
		Tcl_SetResult(interp, "Could not get common name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_class_datum_get_perm_iter(policydb->sh, policydb->p,
					    class_datum, &perm_iter) < 0) {
		Tcl_SetResult(interp, "Could not got permissions iterator.", TCL_STATIC);
		goto cleanup;
	}
	class_elem[0] = Tcl_NewStringObj(class_name, -1);
	class_elem[1] = Tcl_NewStringObj(common_name, -1);
	class_elem[2] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(perm_iter); sepol_iterator_next(perm_iter)) {
		char *perm_name;
		Tcl_Obj *perm_obj;
		if (sepol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
			Tcl_SetResult(interp, "Could not get permission name.", TCL_STATIC);
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
	sepol_iterator_destroy(&perm_iter);
	return retval;
}

/* Returns an unordered list of class tuples within the policy.
 *   elem 0 - class name
 *   elem 1 - class's common class, or empty string if none
 *   elem 2 - list of class's permissions
 * argv[1] - class name to look up, or a regular expression, or empty
 *	     to get all classes
 * argv[2] - (optional) treat argv[1] as a class name or regex
 */
static int Apol_GetClasses(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_class_datum_t *class_datum;

	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a class name and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (sepol_policydb_get_class_by_name(policydb->sh, policydb->p,
						     argv[1], &class_datum) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_class_to_list(interp, class_datum, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[2], -1);
		int regex_flag;
		apol_class_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_class_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_class_query_set_class(query, argv[1]) ||
			    apol_class_query_set_regex(query, regex_flag)) {
				apol_class_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_class_by_query(policydb, query, &v) < 0) {
			apol_class_query_destroy(&query);
			Tcl_SetResult(interp, "Error running class query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_class_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			class_datum = (sepol_class_datum_t *) apol_vector_get_element(v, i);
			if (append_class_to_list(interp, class_datum, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}
     
/* Takes a sepol_common_datum_t representing a common and appends a
 * tuple of it to results_list.	 The tuple consists of:
 *    { common_name {perms0 perms1 ...} {class0 class1 ...} }
 * The second list is a list of object classes that inherit from this
 * common.
 */
static int append_common_to_list(Tcl_Interp *interp,
				 sepol_common_datum_t *common_datum,
				 Tcl_Obj *result_list)
{
	char *common_name;
	sepol_iterator_t *perm_iter = NULL;
	apol_class_query_t *query = NULL;
	apol_vector_t *classes = NULL;
	size_t i;
	Tcl_Obj *common_elem[3], *common_list;
	int retval = TCL_ERROR;
	if (sepol_common_datum_get_name(policydb->sh, policydb->p,
					common_datum, &common_name) < 0) {
		Tcl_SetResult(interp, "Could not get common name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_common_datum_get_perm_iter(policydb->sh, policydb->p,
					     common_datum, &perm_iter) < 0) {
		Tcl_SetResult(interp, "Could not got permissions iterator.", TCL_STATIC);
		goto cleanup;
	}
	common_elem[0] = Tcl_NewStringObj(common_name, -1);
	common_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(perm_iter); sepol_iterator_next(perm_iter)) {
		char *perm_name;
		Tcl_Obj *perm_obj;
		if (sepol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
			Tcl_SetResult(interp, "Could not get permission name.", TCL_STATIC);
			goto cleanup;
		}
		perm_obj = Tcl_NewStringObj(perm_name, -1);
		if (Tcl_ListObjAppendElement(interp, common_elem[1], perm_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	common_elem[2] = Tcl_NewListObj(0, NULL);
	if ((query = apol_class_query_create()) == NULL ||
	    apol_class_query_set_common(query, common_name) < 0) {
		Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
		goto cleanup;
	}
	if (apol_get_class_by_query(policydb, query, &classes) < 0) {
		Tcl_SetResult(interp, "Error running class query.", TCL_STATIC);
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(classes); i++) {
		sepol_class_datum_t *class_datum = (sepol_class_datum_t *) apol_vector_get_element(classes, i);
		char *class_name;
		Tcl_Obj *class_obj;
		if (sepol_class_datum_get_name(policydb->sh, policydb->p,
					       class_datum, &class_name) < 0) {
			Tcl_SetResult(interp, "Could not get class name.", TCL_STATIC);
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
	sepol_iterator_destroy(&perm_iter);
	apol_class_query_destroy(&query);
	apol_vector_destroy(&classes, NULL);
	return retval;
}

/* Returns an unordered list of common tuples within the policy.
 *   elem 0 - common name
 *   elem 1 - list of common's permissions
 *   elem 2 - list of classes that inherit this common
 * argv[1] - common name to look up, or a regular expression, or empty
 *	     to get all common
 * argv[2] - (optional) treat argv[1] as a common name or regex
 */
static int Apol_GetCommons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_common_datum_t *common_datum;

	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a common name and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (sepol_policydb_get_common_by_name(policydb->sh, policydb->p,
						      argv[1], &common_datum) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_common_to_list(interp, common_datum, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[2], -1);
		int regex_flag;
		apol_common_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_common_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_common_query_set_common(query, argv[1]) ||
			    apol_common_query_set_regex(query, regex_flag)) {
				apol_common_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_common_by_query(policydb, query, &v) < 0) {
			apol_common_query_destroy(&query);
			Tcl_SetResult(interp, "Error running common query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_common_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			common_datum = (sepol_common_datum_t *) apol_vector_get_element(v, i);
			if (append_common_to_list(interp, common_datum, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}
     
/* Takes a string representing a permission and appends a tuple of it
 * to results_list.  The tuple consists of:
  *    { perm_name {class0 class1 ...} {common0 common1 ...} }
 */
static int append_perm_to_list(Tcl_Interp *interp,
			       char *perm,
			       Tcl_Obj *result_list)
{
	sepol_iterator_t *class_iter = NULL, *common_iter = NULL;
	Tcl_Obj *perm_elem[3], *perm_list;
	int retval = TCL_ERROR;
	if (sepol_perm_get_class_iter(policydb->sh, policydb->p,
					    perm, &class_iter) < 0 ||
	    sepol_perm_get_common_iter(policydb->sh, policydb->p,
					     perm, &common_iter) < 0) {
		Tcl_SetResult(interp, "Could not got classes iterators.", TCL_STATIC);
		goto cleanup;
	}
	perm_elem[0] = Tcl_NewStringObj(perm, -1);
	perm_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(class_iter); sepol_iterator_next(class_iter)) {
		sepol_class_datum_t *class_datum;
		char *class_name;
		Tcl_Obj *class_obj;
		if (sepol_iterator_get_item(class_iter, (void **) &class_datum) < 0 ||
		    sepol_class_datum_get_name(policydb->sh, policydb->p,
					       class_datum, &class_name) < 0) {
			Tcl_SetResult(interp, "Could not get class name.", TCL_STATIC);
			goto cleanup;
		}
		class_obj = Tcl_NewStringObj(class_name, -1);
		if (Tcl_ListObjAppendElement(interp, perm_elem[1], class_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	perm_elem[2] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(common_iter); sepol_iterator_next(common_iter)) {
		sepol_common_datum_t *common_datum;
		char *common_name;
		Tcl_Obj *common_obj;
		if (sepol_iterator_get_item(common_iter, (void **) &common_datum) < 0 ||
		    sepol_common_datum_get_name(policydb->sh, policydb->p,
						common_datum, &common_name) < 0) {
			Tcl_SetResult(interp, "Could not get common name.", TCL_STATIC);
			goto cleanup;
		}
		common_obj = Tcl_NewStringObj(common_name, -1);
		if (Tcl_ListObjAppendElement(interp, perm_elem[2], common_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	perm_list = Tcl_NewListObj(3, perm_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, perm_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	sepol_iterator_destroy(&class_iter);
	sepol_iterator_destroy(&common_iter);
	return retval;
}

/* Returns an unordered list of permission tuples within the policy.
 *   elem 0 - permission name
 *   elem 1 - list of classes that have this permission
 *   elem 2 - list of commons that have this permission
 * argv[1] - permission name to look up, or a regular expression, or
 *	     empty to get all permissions
 * argv[2] - (optional) treat argv[1] as a permission name or regex
 */
static int Apol_GetPerms(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a permission name and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (append_perm_to_list(interp, argv[1], result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[2], -1);
		int regex_flag;
		apol_perm_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		char *perm;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_perm_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_perm_query_set_perm(query, argv[1]) ||
			    apol_perm_query_set_regex(query, regex_flag)) {
				apol_perm_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_perm_by_query(policydb, query, &v) < 0) {
			apol_perm_query_destroy(&query);
			Tcl_SetResult(interp, "Error running permission query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_perm_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			perm = (char *) apol_vector_get_element(v, i);
			if (append_perm_to_list(interp, perm, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

/* Takes a sepol_role_datum_t and appends a tuple of it to results_list.
 * The tuple consists of:
 *    { role_name {types1 types2 ...} {dominated_role1 dominated_role2 ...}}
 */
static int append_role_to_list(Tcl_Interp *interp,
			       sepol_role_datum_t *role_datum,
			       Tcl_Obj *result_list)
{
	char *role_name;
	sepol_iterator_t *type_iter = NULL, *dom_iter = NULL;
	int retval = TCL_ERROR;
	Tcl_Obj *role_elem[3], *role_list;
	if (sepol_role_datum_get_name(policydb->sh, policydb->p,
				      role_datum, &role_name) < 0) {
		Tcl_SetResult(interp, "Could not get role name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_role_datum_get_type_iter(policydb->sh, policydb->p,
					   role_datum, &type_iter) < 0) {
		Tcl_SetResult(interp, "Could not get type iterator.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_role_datum_get_dominate_iter(policydb->sh, policydb->p,
					       role_datum, &dom_iter) < 0) {
		Tcl_SetResult(interp, "Could not get dominate iterator.", TCL_STATIC);
		goto cleanup;
	}
	role_elem[0] = Tcl_NewStringObj(role_name, -1);
	role_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(type_iter); sepol_iterator_next(type_iter)) {
		sepol_type_datum_t *type;
		char *type_name;
		Tcl_Obj *type_obj;
		if (sepol_iterator_get_item(type_iter, (void **) &type) < 0 ||
		    sepol_type_datum_get_name(policydb->sh, policydb->p,
					      type, &type_name) < 0) {
			Tcl_SetResult(interp, "Could not get type name.", TCL_STATIC);
			goto cleanup;
		}
		type_obj = Tcl_NewStringObj(type_name, -1);
		if (Tcl_ListObjAppendElement(interp, role_elem[1], type_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	role_elem[2] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(dom_iter); sepol_iterator_next(dom_iter)) {
		sepol_role_datum_t *dom_role;
		char *dom_role_name;
		Tcl_Obj *dom_role_obj;
		if (sepol_iterator_get_item(dom_iter, (void **) &dom_role) < 0 ||
		    sepol_role_datum_get_name(policydb->sh, policydb->p,
					      dom_role, &dom_role_name) < 0) {
			Tcl_SetResult(interp, "Could not get dominate name.", TCL_STATIC);
			goto cleanup;
		}
		if (strcmp(dom_role_name, role_name) == 0) {
			/* explicitly skip the role dominating itself */
			continue;
		}
		dom_role_obj = Tcl_NewStringObj(dom_role_name, -1);
		if (Tcl_ListObjAppendElement(interp, role_elem[2], dom_role_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	role_list = Tcl_NewListObj(3, role_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, role_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	sepol_iterator_destroy(&type_iter);
	sepol_iterator_destroy(&dom_iter);
	return retval;
}

/* Return a list of all roles within the policy.
 *
 * element 0 - role name
 * element 1 - list of types
 * element 2 - list of roles this one dominates
 *
 * argv[1] - role name to look up, or a regular expression, or empty
 *	     to get all roles
 * argv[2] - (optional) roles containing this type
 * argv[3] - (optional) treat argv[1] and argv[2] as a role name or regex
 */
static int Apol_GetRoles(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_role_datum_t *role;

	if(policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc != 2 && argc < 4) {
		Tcl_SetResult(interp, "Need a role name, ?type?, and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (sepol_policydb_get_role_by_name(policydb->sh, policydb->p,
						    argv[1], &role) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_role_to_list(interp, role, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[3], -1);
		int regex_flag;
		apol_role_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0' || *argv[2] != '\0') {
			if ((query = apol_role_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_role_query_set_role(query, argv[1]) ||
			    apol_role_query_set_type(query, argv[2]) ||
			    apol_role_query_set_regex(query, regex_flag)) {
				apol_role_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_role_by_query(policydb, query, &v) < 0) {
			apol_role_query_destroy(&query);
			Tcl_SetResult(interp, "Error running role query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_role_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			role = (sepol_role_datum_t *) apol_vector_get_element(v, i);
			if (append_role_to_list(interp, role, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

static int level_to_tcl_obj(Tcl_Interp *interp, ap_mls_level_t *level, Tcl_Obj **obj) 
{
        Tcl_Obj *level_elem[2], *cats_obj;
        int i;

        level_elem[0] = Tcl_NewStringObj(policy->sensitivities[level->sensitivity].name, -1);
        level_elem[1] = Tcl_NewListObj(0, NULL);
        for (i = 0; i < level->num_categories; i++) {
                cats_obj = Tcl_NewStringObj(policy->categories[level->categories[i]].name, -1);
                if (Tcl_ListObjAppendElement(interp, level_elem[1], cats_obj) == TCL_ERROR) {
                        return TCL_ERROR;
                }
        }
        *obj = Tcl_NewListObj(2, level_elem);
        return TCL_OK;
}

/* Converts an apol_mls_level_t to a Tcl representation:
 *   { level { cat0 cat1 ... } }
 */
static int apol_level_to_tcl_obj(Tcl_Interp *interp, apol_mls_level_t *level, Tcl_Obj **obj) {
	Tcl_Obj *level_elem[2], *cats_obj;
	size_t i;
	level_elem[0] = Tcl_NewStringObj(level->sens, -1);
	level_elem[1] = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(level->cats); i++) {
		cats_obj = Tcl_NewStringObj((char *) apol_vector_get_element(level->cats, i), -1);
		if (Tcl_ListObjAppendElement(interp, level_elem[1], cats_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	*obj = Tcl_NewListObj(2, level_elem);
	return TCL_OK;
}


/* Takes a sepol_user_datum_t and appends a tuple of it to
 * results_list.  The tuple consists of:
 *    { user_name { role0 role1 ... } default_level { low_range high_range } }
 */
static int append_user_to_list(Tcl_Interp *interp,
			       sepol_user_datum_t *user_datum,
			       Tcl_Obj *result_list)
{
	char *user_name;
	sepol_iterator_t *role_iter = NULL;
	Tcl_Obj *user_elem[4], *user_list;
	apol_mls_level_t *apol_default = NULL;
	apol_mls_range_t *apol_range = NULL;
	int retval = TCL_ERROR;
	if (sepol_user_datum_get_name(policydb->sh, policydb->p,
				      user_datum, &user_name) < 0) {
		Tcl_SetResult(interp, "Could not get user name.", TCL_STATIC);
		goto cleanup;
	}
	user_elem[0] = Tcl_NewStringObj(user_name, -1);
	if (sepol_user_datum_get_role_iter(policydb->sh, policydb->p,
					   user_datum, &role_iter) < 0) {
		Tcl_SetResult(interp, "Could not get role iterator.", TCL_STATIC);
		goto cleanup;
	}
	user_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(role_iter); sepol_iterator_next(role_iter)) {
		sepol_role_datum_t *role_datum;
		char *role_name;
		Tcl_Obj *role_obj;
		if (sepol_iterator_get_item(role_iter, (void **) &role_datum) < 0 ||
		    sepol_role_datum_get_name(policydb->sh, policydb->p,
					      role_datum, &role_name) < 0) {
			Tcl_SetResult(interp, "Could not get role name.", TCL_STATIC);
			goto cleanup;
		}
		role_obj = Tcl_NewStringObj(role_name, -1);
		if (Tcl_ListObjAppendElement(interp, user_elem[1], role_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	if (is_mls_policy(policy)) {
		sepol_mls_level_t *default_level;
		sepol_mls_range_t *range;
		Tcl_Obj *range_elem[2];
		if (sepol_user_datum_get_dfltlevel(policydb->sh, policydb->p, user_datum, &default_level) < 0) {
			Tcl_SetResult(interp, "Could not get default level.", TCL_STATIC);
			goto cleanup;
		}
		if (sepol_user_datum_get_range(policydb->sh, policydb->p, user_datum, &range) < 0) {
			Tcl_SetResult(interp, "Could not get range.", TCL_STATIC);
			goto cleanup;
		}
		if ((apol_default =
		     apol_mls_level_create_from_sepol_mls_level(policydb,
								default_level)) == NULL ||
		    (apol_range =
		     apol_mls_range_create_from_sepol_mls_range(policydb,
								range)) == NULL) {
			Tcl_SetResult(interp, "Could not convert to MLS structs.", TCL_STATIC);
			goto cleanup;
		}
		    
		if (apol_level_to_tcl_obj(interp, apol_default, user_elem + 2) == TCL_ERROR) {
			goto cleanup;
		}
		if (apol_level_to_tcl_obj(interp, apol_range->low, range_elem + 0) == TCL_ERROR ||
		    apol_level_to_tcl_obj(interp, apol_range->high, range_elem + 1) == TCL_ERROR) {
			goto cleanup;
		}
		user_elem[3] = Tcl_NewListObj(2, range_elem);
	}
	else {
		user_elem[2] = Tcl_NewListObj(0, NULL);
		user_elem[3] = Tcl_NewListObj(0, NULL);
	}
	user_list = Tcl_NewListObj(4, user_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, user_list) == TCL_ERROR) {
		goto cleanup;
	}

	retval = TCL_OK;
 cleanup:
	sepol_iterator_destroy(&role_iter);
	apol_mls_level_destroy(&apol_default);
	apol_mls_range_destroy(&apol_range);
	return retval;
}

/* Returns a list of users-tuples.
 *  element 1: user name
 *  element 2: list of role names authorized for user
 *  element 3: default level if MLS, empty otherwise
 *	       (level = sensitivity + list of categories)
 *  element 4: authorized range for user if MLS, empty otherwise
 *	       (range = 2-uple of levels)
 *
 * argv[1] - user name to look up, or a regular expression, or empty
 *	     to get all users
 * argv[2] - (optional) role that user cantains
 * argv[3] - (optional) default MLS level
 * argv[4] - (optional) MLS range
 * argv[5] - (optional) range query type
 * argv[6] - (optional) treat argv[1] as a user name or regex
 */
static int Apol_GetUsers(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj;
	sepol_user_datum_t *user;
	apol_user_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc != 2 && argc < 7) {
		Tcl_SetResult(interp, "Need a user name, ?role?, ?default level?, ?range?, ?range type?, and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	result_obj = Tcl_NewListObj(0, NULL);
	if (argc == 2) {
		if (sepol_policydb_get_user_by_name(policydb->sh, policydb->p,
						    argv[1], &user) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_user_to_list(interp, user, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[6], -1);
		int regex_flag;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0' || *argv[2] != '\0' ||
		    *argv[3] != '\0' || *argv[4] != '\0') {
			if ((query = apol_user_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				goto cleanup;
			}
			if (apol_user_query_set_user(query, argv[1]) ||
			    apol_user_query_set_role(query, argv[2]) ||
			    apol_user_query_set_regex(query, regex_flag)) {
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				goto cleanup;
			}
		}
		if (*argv[3] != '\0') {
			apol_mls_level_t *default_level;
			if ((default_level = apol_mls_level_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory.", TCL_STATIC);
				goto cleanup;
			}
			if (apol_tcl_string_to_level(interp, argv[3], default_level) != 0 ||
			    apol_user_query_set_default_level(query, default_level) < 0) {
				apol_mls_level_destroy(&default_level);
				goto cleanup;
			}
		}
		if (*argv[4] != '\0') {
			apol_mls_range_t *range;
			unsigned int range_match = 0;
			if (apol_tcl_string_to_range_match(interp, argv[5], &range_match) < 0) {
				goto cleanup;
			}
			if ((range = apol_mls_range_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory.", TCL_STATIC);
				goto cleanup;
			}
			if (apol_tcl_string_to_range(interp, argv[4], range) != 0 ||
			    apol_user_query_set_range(query, range, range_match) < 0) {
				apol_mls_range_destroy(&range);
				goto cleanup;
			}
		}
		if (apol_get_user_by_query(policydb, query, &v) < 0) {
			Tcl_SetResult(interp, "Error running user query.", TCL_STATIC);
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			user = (sepol_user_datum_t *) apol_vector_get_element(v, i);
			if (append_user_to_list(interp, user, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_user_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	return retval;
}

/* Takes a sepol_bool_datum_t and appends a tuple of it to results_list.
 * The tuple consists of:
 *    { bool_name current_value}
 */
static int append_bool_to_list(Tcl_Interp *interp,
			       sepol_bool_datum_t *bool_datum,
			       Tcl_Obj *result_list)
{
	char *bool_name;
	int bool_state;
	Tcl_Obj *bool_elem[3], *bool_list;
	if (sepol_bool_datum_get_name(policydb->sh, policydb->p,
				      bool_datum, &bool_name) < 0) {
		Tcl_SetResult(interp, "Could not get boolean name.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (sepol_bool_datum_get_state(policydb->sh, policydb->p,
				       bool_datum, &bool_state) < 0) {
		Tcl_SetResult(interp, "Could not get boolean state.", TCL_STATIC);
		return TCL_ERROR;
	}
	
	bool_elem[0] = Tcl_NewStringObj(bool_name, -1);
	bool_elem[1] = Tcl_NewBooleanObj(bool_state);
	bool_list = Tcl_NewListObj(2, bool_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, bool_list) == TCL_ERROR) {
		return TCL_ERROR;
	}
	return TCL_OK;
}

/* Return a list of all condition booleans within the policy.
 *
 * element 0 - boolean name
 * element 1 - current state of the boolean (either 0 or 1)
 *
 * argv[1] - boolean name to look up, or a regular expression, or empty
 *	     to get all roles
 * argv[2] - (optional) treat argv[1] as a boolean name or regex
 */
static int Apol_GetBools(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_bool_datum_t *bool;

	if(policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc != 2 && argc < 3) {
		Tcl_SetResult(interp, "Need a boolean name and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (sepol_policydb_get_bool_by_name(policydb->sh, policydb->p,
						    argv[1], &bool) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_bool_to_list(interp, bool, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[2], -1);
		int regex_flag;
		apol_bool_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_bool_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_bool_query_set_bool(query, argv[1]) ||
			    apol_bool_query_set_regex(query, regex_flag)) {
				apol_bool_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_bool_by_query(policydb, query, &v) < 0) {
			apol_bool_query_destroy(&query);
			Tcl_SetResult(interp, "Error running boolean query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_bool_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			bool = (sepol_bool_datum_t *) apol_vector_get_element(v, i);
			if (append_bool_to_list(interp, bool, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

/* Sets a boolean value within the policy.
 *
 * argv[1] - boolean name
 * argv[2] - new state for the boolean (either 0 or 1)
 */
static int Apol_SetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	sepol_bool_datum_t *bool;
	Tcl_Obj *value_obj;
	int value;

	if (argc != 3) {
		Tcl_SetResult(interp, "Need a bool name and a value.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (sepol_policydb_get_bool_by_name(policydb->sh, policydb->p,
					    argv[1], &bool) < 0) {
		/* name is not within policy */
		return TCL_OK;
	}
	value_obj = Tcl_NewStringObj(argv[2], -1);
	if (Tcl_GetBooleanFromObj(interp, value_obj, &value) == TCL_ERROR) {
		return TCL_ERROR;
	}
	if (sepol_bool_datum_set_state(policydb->sh, policydb->p, bool, value) < 0) {
		Tcl_SetResult(interp, "Error setting boolean state.", TCL_STATIC);
		return TCL_ERROR;
	}
	return TCL_OK;
}

/* Takes a sepol_level_datum_t and appends a tuple of it to
 * results_list.  The tuple consists of:
 *    { sens_name {alias0 alias1 ...} {cats0 cats1 ...} dominance_value }
 */
static int append_level_to_list(Tcl_Interp *interp,
				sepol_level_datum_t *level_datum,
				Tcl_Obj *result_list)
{
	char *sens_name;
	sepol_iterator_t *alias_iter = NULL, *cat_iter = NULL;
	uint32_t level_value;
	Tcl_Obj *level_elem[4], *level_list;
	int retval = TCL_ERROR;

	if (sepol_level_datum_get_name(policydb->sh, policydb->p,
				       level_datum, &sens_name) < 0) {
		Tcl_SetResult(interp, "Could not get sensitivity name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_level_datum_get_alias_iter(policydb->sh, policydb->p,
					     level_datum, &alias_iter) < 0) {
		Tcl_SetResult(interp, "Could not get alias iterator.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_level_datum_get_cat_iter(policydb->sh, policydb->p,
					   level_datum, &cat_iter) < 0) {
		Tcl_SetResult(interp, "Could not get category iterator.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_level_datum_get_value(policydb->sh, policydb->p,
					level_datum, &level_value) < 0) {
		Tcl_SetResult(interp, "Could not get level value.", TCL_STATIC);
		goto cleanup;
	}
	level_elem[0] = Tcl_NewStringObj(sens_name, -1);
	level_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(alias_iter); sepol_iterator_next(alias_iter)) {
		char *alias_name;
		Tcl_Obj *alias_obj;
		if (sepol_iterator_get_item(alias_iter, (void **) &alias_name) < 0) {
			Tcl_SetResult(interp, "Could not get alias name.", TCL_STATIC);
			goto cleanup;
		}
		alias_obj = Tcl_NewStringObj(alias_name, -1);
		if (Tcl_ListObjAppendElement(interp, level_elem[1], alias_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	level_elem[2] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(cat_iter); sepol_iterator_next(cat_iter)) {
		sepol_cat_datum_t *cat_datum;
		char *cats_name;
		Tcl_Obj *cats_obj;
		if (sepol_iterator_get_item(cat_iter, (void **) &cat_datum) < 0 ||
		    sepol_cat_datum_get_name(policydb->sh, policydb->p,
					     cat_datum, &cats_name) < 0) {
			Tcl_SetResult(interp, "Could not get category name.", TCL_STATIC);
			goto cleanup;
		}
		cats_obj = Tcl_NewStringObj(cats_name, -1);
		if (Tcl_ListObjAppendElement(interp, level_elem[2], cats_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	level_elem[3] = Tcl_NewLongObj((long) level_value);
	level_list = Tcl_NewListObj(4, level_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, level_list) == TCL_ERROR) {
		goto cleanup;
	}

	retval = TCL_OK;
 cleanup:
	sepol_iterator_destroy(&alias_iter);
	sepol_iterator_destroy(&cat_iter);
	return retval;
}

/* Return an unordered list of MLS level tuples, or an empty list if
 * no policy was loaded.
 *   elem 0 - sensitivity name
 *   elem 1 - list of associated aliases
 *   elem 2 - list of categories
 *   elem 3 - level dominance value
 *
 * argv[1] - sensitivity name to look up, or a regular expression, or
 *	     empty to get all levels
 * argv[2] - (optional) treat argv[1] as a sensitivity name or regex
 */
static int Apol_GetLevels(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_level_datum_t *level;

	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a sensitivity name and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (sepol_policydb_get_level_by_name(policydb->sh, policydb->p,
						     argv[1], &level) < 0) {
			/* passed sensitivity is not within the policy */
			return TCL_OK;
		}
		if (append_level_to_list(interp, level, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[2], -1);
		int regex_flag;
		apol_level_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_level_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_level_query_set_sens(query, argv[1]) ||
			    apol_level_query_set_regex(query, regex_flag)) {
				apol_level_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_level_by_query(policydb, query, &v) < 0) {
			apol_level_query_destroy(&query);
			Tcl_SetResult(interp, "Error running level query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_level_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			level = (sepol_level_datum_t *) apol_vector_get_element(v, i);
			if (append_level_to_list(interp, level, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

/* Takes a sepol_cat_datum_t and appends a tuple of it to
 * results_list.  The tuple consists of:
 *    { cat_name {alias0 alias1 ...} {level0 level1 ...} cat_value }
 */
static int append_cat_to_list(Tcl_Interp *interp,
			      sepol_cat_datum_t *cat_datum,
			      Tcl_Obj *result_list)
{
	char *cat_name;
	sepol_iterator_t *alias_iter = NULL;
	apol_level_query_t *query = NULL;
	apol_vector_t *levels = NULL;
	size_t i;
	uint32_t cat_value;
	Tcl_Obj *cat_elem[4], *cat_list;
	int retval = TCL_ERROR;

	if (sepol_cat_datum_get_name(policydb->sh, policydb->p,
				     cat_datum, &cat_name) < 0) {
		Tcl_SetResult(interp, "Could not get category name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_cat_datum_get_alias_iter(policydb->sh, policydb->p,
					   cat_datum, &alias_iter) < 0) {
		Tcl_SetResult(interp, "Could not get alias iterator.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_cat_datum_get_value(policydb->sh, policydb->p,
				      cat_datum, &cat_value) < 0) {
		Tcl_SetResult(interp, "Could not get category value.", TCL_STATIC);
		goto cleanup;
	}
	cat_elem[0] = Tcl_NewStringObj(cat_name, -1);
	cat_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(alias_iter); sepol_iterator_next(alias_iter)) {
		char *alias_name;
		Tcl_Obj *alias_obj;
		if (sepol_iterator_get_item(alias_iter, (void **) &alias_name) < 0) {
			Tcl_SetResult(interp, "Could not get alias name.", TCL_STATIC);
			goto cleanup;
		}
		alias_obj = Tcl_NewStringObj(alias_name, -1);
		if (Tcl_ListObjAppendElement(interp, cat_elem[1], alias_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	cat_elem[2] = Tcl_NewListObj(0, NULL);
	if ((query = apol_level_query_create()) == NULL ||
	    apol_level_query_set_cat(query, cat_name) < 0) {
		Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
		goto cleanup;
	}
	if (apol_get_level_by_query(policydb, query, &levels) < 0) {
		Tcl_SetResult(interp, "Error running level query.", TCL_STATIC);
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(levels); i++) {
		sepol_level_datum_t *level = (sepol_level_datum_t *) apol_vector_get_element(levels, i);
		char *sens_name;
		Tcl_Obj *sens_obj;
		if (sepol_level_datum_get_name(policydb->sh, policydb->p,
					       level, &sens_name) < 0) {
			Tcl_SetResult(interp, "Could not get sensitivity name.", TCL_STATIC);
			goto cleanup;
		}
		sens_obj = Tcl_NewStringObj(sens_name, -1);
		if (Tcl_ListObjAppendElement(interp, cat_elem[2], sens_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	cat_elem[3] = Tcl_NewLongObj((long) cat_value);
	cat_list = Tcl_NewListObj(4, cat_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, cat_list) == TCL_ERROR) {
		goto cleanup;
	}

	retval = TCL_OK;
 cleanup:
	sepol_iterator_destroy(&alias_iter);
	apol_level_query_destroy(&query);
	apol_vector_destroy(&levels, NULL);
	return retval;
}

/* Returns an unordered list of MLS category tuples, or an empty list
 * if no policy was loaded.
 *   elem 0 - category name
 *   elem 1 - list of associated aliases
 *   elem 2 - unordered list of sensitivities that have this category
 *   elme 3 - category value
 *
 * argv[1] - category name to look up, or a regular expression, or
 *	     empty to get all levels
 * argv[2] - (optional) treat argv[1] as a category name or regex
 */
static int Apol_GetCats(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_cat_datum_t *cat;

	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a category name and ?regex flag?.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc == 2) {
		if (sepol_policydb_get_cat_by_name(policydb->sh, policydb->p,
						   argv[1], &cat) < 0) {
			/* passed category is not within the policy */
			return TCL_OK;
		}
		if (append_cat_to_list(interp, cat, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
		Tcl_Obj *regex_obj = Tcl_NewStringObj(argv[2], -1);
		int regex_flag;
		apol_cat_query_t *query = NULL;
		apol_vector_t *v;
		size_t i;
		if (Tcl_GetBooleanFromObj(interp, regex_obj, &regex_flag) == TCL_ERROR) {
			return TCL_ERROR;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_cat_query_create()) == NULL) {
				Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
				return TCL_ERROR;
			}
			if (apol_cat_query_set_cat(query, argv[1]) ||
			    apol_cat_query_set_regex(query, regex_flag)) {
				apol_cat_query_destroy(&query);
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_cat_by_query(policydb, query, &v) < 0) {
			apol_cat_query_destroy(&query);
			Tcl_SetResult(interp, "Error running category query.", TCL_STATIC);
			return TCL_ERROR;
		}
		apol_cat_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			cat = (sepol_cat_datum_t *) apol_vector_get_element(v, i);
			if (append_cat_to_list(interp, cat, result_obj) == TCL_ERROR) {
				apol_vector_destroy(&v, NULL);
				return TCL_ERROR;
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

static int security_con_to_tcl_context_string(Tcl_Interp *interp, security_con_t *context, Tcl_Obj **dest_obj) {
        Tcl_Obj *context_elem[4], *range_elem[2];
        char *name;
        
        if (get_user_name2(context->user, &name, policy) == -1) {
                Tcl_SetResult(interp, "Could not get user name for context.", TCL_STATIC);
                return TCL_ERROR;
        }
        context_elem[0] = Tcl_NewStringObj(name, -1);
        free(name);
        if (get_role_name(context->role, &name, policy) == -1) {
                Tcl_SetResult(interp, "Could not get role name for context.", TCL_STATIC);
                return TCL_ERROR;
        }
        context_elem[1] = Tcl_NewStringObj(name, -1);
        free(name);
        if (get_type_name(context->type, &name, policy) == -1) {
                Tcl_SetResult(interp, "Could not get type name for context.", TCL_STATIC);
                return TCL_ERROR;
        }
        context_elem[2] = Tcl_NewStringObj(name, -1);
        free(name);

        /* convert the MLS range to a Tcl string */
        if (context->range == NULL) {
                context_elem[3] = Tcl_NewListObj(0, NULL);
        }
        else {
                if (level_to_tcl_obj(interp, context->range->low, range_elem) == TCL_ERROR) {
                        return TCL_ERROR;
                }
                if (context->range->low == context->range->high) {
                        context_elem[3] = Tcl_NewListObj(1, range_elem);
                }
                else {
                        if (level_to_tcl_obj(interp, context->range->high, range_elem + 1) == TCL_ERROR) {
                                return TCL_ERROR;
                        }
                        context_elem[3] = Tcl_NewListObj(2, range_elem);
                }
        }
        
        *dest_obj = Tcl_NewListObj(4, context_elem);
        return TCL_OK;
}

/* Returns a list of all initial sids:
 *  elem 0 - sidname
 *  elem 1 - context
 
 * If a parameter is given, only return sids with that name.
 */
static int Apol_GetInitialSIDs(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        int i;
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	if(policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
        for (i = 0; i < policy->num_initial_sids; i++) {
                initial_sid_t *isid = policy->initial_sids + i;
                Tcl_Obj *isid_elem[2], *isid_list;
                if (argc >= 2 && strcmp(argv[1], isid->name) != 0) {
                        continue;
                }
                isid_elem[0] = Tcl_NewStringObj(isid->name, -1);
                if (security_con_to_tcl_context_string(interp, isid->scontext, isid_elem + 1) == TCL_ERROR) {
                        return TCL_ERROR;
                }
                isid_list = Tcl_NewListObj(2, isid_elem);
                if (Tcl_ListObjAppendElement(interp, result_obj, isid_list) == TCL_ERROR) {
                        return TCL_ERROR;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}

/* Return a list of protocols understood by selinux. */
static int Apol_GetPortconProtos(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        Tcl_AppendElement(interp, "tcp");
        Tcl_AppendElement(interp, "udp");
        Tcl_AppendElement(interp, "esp");
        return TCL_OK;
}

/* Return a list of portcon declarations within the current policy.
 * If a parameter is given, only return those with the value as its
 * lower port irrespective of protocol. */
static int Apol_GetPortcons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int i, which_port = -1;
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
        if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
        if (argc > 1) {
            Tcl_Obj *portObj = Tcl_NewStringObj(argv[1], -1);
            if (Tcl_GetIntFromObj(interp, portObj, &which_port) == TCL_ERROR) {
                return TCL_ERROR;
            }
        }
        for (i = 0; i < policy->num_portcon; i++) {
                Tcl_Obj *portcon_elem[4], *portcon_list;
                ap_portcon_t *portcon = policy->portcon + i;
                if (argc > 1 && portcon->lowport != which_port) {
                    continue;
                }
                switch (portcon->protocol) {
                case AP_TCP_PROTO: {
                        portcon_elem[0] = Tcl_NewStringObj("tcp", -1);
                        break;
                }
                case AP_UDP_PROTO: {
                        portcon_elem[0] = Tcl_NewStringObj("udp", -1);
                        break;
                }
                case AP_ESP_PROTO: {
                        portcon_elem[0] = Tcl_NewStringObj("esp", -1);
                        break;
                }
                default: {
                        Tcl_SetResult(interp, "Unrecognized protocol in portcon", TCL_STATIC);
                        return TCL_ERROR;
                }
                }
                portcon_elem[1] = Tcl_NewIntObj(portcon->lowport);
                portcon_elem[2] = Tcl_NewIntObj(portcon->highport);
                if (security_con_to_tcl_context_string(interp, portcon->scontext, portcon_elem + 3) == TCL_ERROR) {
                        return TCL_ERROR;
                }
                portcon_list = Tcl_NewListObj(4, portcon_elem);
                if (Tcl_ListObjAppendElement(interp, result_obj, portcon_list) == TCL_ERROR) {
                        return TCL_ERROR;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}

/* Return an unsorted list of interface namess for the current policy. */
static int Apol_GetNetifconInterfaces(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        int i;
        if (policy == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
                return TCL_ERROR;
        }
        for (i = 0; i < policy->num_netifcon; i++) {
                Tcl_AppendElement(interp, policy->netifcon[i].iface);
        }
        return TCL_OK;
}

/* Return an unsorted list of all netifcon declarations.  If a
 * parameter is given, only return those with the given interface
 * name. */
static int Apol_GetNetifcons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        int i;
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
        if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
        for (i = 0; i < policy->num_netifcon; i++) {
                ap_netifcon_t *netifcon = policy->netifcon + i;
                Tcl_Obj *netifcon_elem[3], *netifcon_list;
                if (argc > 1 && strcmp(argv[1], netifcon->iface) != 0) {
                        continue;
                }
                netifcon_elem[0] = Tcl_NewStringObj(netifcon->iface, -1);
                if (security_con_to_tcl_context_string(interp, netifcon->device_context, netifcon_elem + 1) == TCL_ERROR ||
                    security_con_to_tcl_context_string(interp, netifcon->packet_context, netifcon_elem + 2) == TCL_ERROR) {
                        return TCL_ERROR;
                }
                netifcon_list = Tcl_NewListObj(3., netifcon_elem);
                if (Tcl_ListObjAppendElement(interp, result_obj, netifcon_list) == TCL_ERROR) {
                        return TCL_ERROR;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}

/* Return a list of all nodecon declarations.  If a paramater was
 * passed, only return those that match the addr/mask pair. */
static int Apol_GetNodecons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        int i;
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
        uint32_t addr[4] = {0, 0, 0, 0};
        int user_type = -1;
        if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
        if (argc >= 2) {
                if ((user_type = str_to_internal_ip(argv[1], addr)) == -1) {
                        Tcl_SetResult(interp, "Could not convert address", TCL_STATIC);
                        return TCL_ERROR;
                }
        }
        for (i = 0; i < policy->num_nodecon; i++) {
                ap_nodecon_t *nodecon = policy->nodecon + i;
                Tcl_Obj *nodecon_elem[4], *nodecon_list;
                Tcl_Obj *val_elem[4];
                int i;
                if (user_type >= 0) {
                        int keep = 1;
                        if (user_type != nodecon->flag) {
                                continue;
                        }
                        for (i = 0; i < 4; i++) {
                                if ((addr[i] & nodecon->mask[i]) != nodecon->addr[i]) {
                                        keep = 0;
                                        break;
                                }
                        }
                        if (!keep) {
                                continue;
                        }
                }
                if (nodecon->flag == AP_IPV4) {
                        nodecon_elem[0] = Tcl_NewStringObj("ipv4", -1);
                }
                else if (nodecon->flag == AP_IPV6) {
                        nodecon_elem[0] = Tcl_NewStringObj("ipv6", -1);
                }
                else {
                        Tcl_SetResult(interp, "Unknown nodecon flag.", TCL_STATIC);
                        return TCL_ERROR;
                }
                for (i = 0; i < 4; i++) {
                        val_elem[i] = Tcl_NewLongObj((long) nodecon->addr[i]);
                }
                nodecon_elem[1] = Tcl_NewListObj(4, val_elem);
                for (i = 0; i < 4; i++) {
                        val_elem[i] = Tcl_NewLongObj((long) nodecon->mask[i]);
                }
                nodecon_elem[2] = Tcl_NewListObj(4, val_elem);
                if (security_con_to_tcl_context_string(interp, nodecon->scontext, nodecon_elem + 3) == TCL_ERROR) {
                        return TCL_ERROR;
                }
                nodecon_list = Tcl_NewListObj(4, nodecon_elem);
                if (Tcl_ListObjAppendElement(interp, result_obj, nodecon_list) == TCL_ERROR) {
                        return TCL_ERROR;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}

/* Return an unordered unique list of all filesystems with a genfscon
 * entry. */
static int Apol_GetGenFSConFilesystems(ClientData clientData, Tcl_Interp *interp, int argc, const char *argv[])
{
        int i;
        if (policy == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
                return TCL_ERROR;
        }
        for (i = 0; i < policy->num_genfscon; i++) {
                Tcl_AppendElement(interp, policy->genfscon[i].fstype);
        }
        return TCL_OK;
}

static const char *filetype_to_string(int filetype) {
        switch (filetype) {
        case FILETYPE_BLK:  return "block";
        case FILETYPE_CHR:  return "char";
        case FILETYPE_DIR:  return "dir";
        case FILETYPE_LNK:  return "link";
        case FILETYPE_FIFO: return "fifo";
        case FILETYPE_SOCK: return "sock";
        case FILETYPE_REG:  return "file";
        case FILETYPE_ANY:  return "any";
        }
        return NULL;
}

/* Return a list of all genfscon declarations within the policy.
 * Entries with the same filesystem are reported as separate
 * elements.
 *
 * element 0 - filesystem
 * element 1 - path
 * element 2 - genfs type ("file", "block", etc)
 * element 3 - context
 *
 * If a parameter is given, only return those with that filesystem.
 */
static int Apol_GetGenFSCons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        int i;
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
        if (policy == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
                return TCL_ERROR;
        }
        for (i = 0; i < policy->num_genfscon; i++) {
                ap_genfscon_t *genfscon = policy->genfscon + i;
                ap_genfscon_node_t *node = genfscon->paths;
                if (argc >= 2 && strcmp(genfscon->fstype, argv[1]) != 0) {
                        continue;
                }
                while (node != NULL) {
                        Tcl_Obj *genfs_elem[4], *genfs_list;
                        const char *fstype;
                        genfs_elem[0] = Tcl_NewStringObj(genfscon->fstype, -1);
                        genfs_elem[1] = Tcl_NewStringObj(node->path, -1);
                        if ((fstype = filetype_to_string(node->filetype)) == NULL) {
                                Tcl_SetResult(interp, "Illegal filetype given in genfscon node", TCL_STATIC);
                                return TCL_ERROR;
                        }
                        genfs_elem[2] = Tcl_NewStringObj(fstype, -1);
                        if (security_con_to_tcl_context_string(interp, node->scontext, genfs_elem + 3) == TCL_ERROR) {
                                return TCL_ERROR;
                        }
                        genfs_list = Tcl_NewListObj(4, genfs_elem);
                        if (Tcl_ListObjAppendElement(interp, result_obj, genfs_list) == TCL_ERROR) {
                                return TCL_ERROR;
                        }
                        node = node->next;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}

static const char *fsuse_behavior_to_string(int i) {
        switch (i) {
        case AP_FS_USE_PSID: return "fs_use_psid";
        case AP_FS_USE_XATTR: return "fs_use_xattr";
        case AP_FS_USE_TASK: return "fs_use_task";
        case AP_FS_USE_TRANS: return "fs_use_trans";
        }
        return NULL;
}

/* Return an unordered list of fs_use type statemens. */
static int Apol_GetFSUseBehaviors(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        int i;
        for (i = AP_FS_USE_PSID; i <= AP_FS_USE_TRANS; i++) {
                Tcl_AppendElement(interp, fsuse_behavior_to_string(i));
        }
        return TCL_OK;
}

/* Return a list of all fs_use declarations within the policy.
 *
 * element 0 - fs_use behavior
 * element 1 - filesystem
 * element 2 - context
 *
 * If a parameter is given, only return those for that filesystem.
 */
static int Apol_GetFSUses(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        int i;
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
        if (policy == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
                return TCL_ERROR;
        }
        for (i = 0; i < policy->num_fs_use; i++) {
                ap_fs_use_t *fs_use = policy->fs_use + i;
                Tcl_Obj *fsuse_elem[3], *fsuse_list;
                const char *behavior = fsuse_behavior_to_string(fs_use->behavior);
                if (behavior == NULL) {
                        Tcl_SetResult(interp, "Invalid fs_use behavior.", TCL_STATIC);
                        return TCL_ERROR;
                }
                if (argc >= 2 && strcmp(fs_use->fstype, argv[1]) != 0) {
                        continue;
                }
                fsuse_elem[0] = Tcl_NewStringObj(behavior, -1);
                fsuse_elem[1] = Tcl_NewStringObj(fs_use->fstype, -1);
                if (fs_use->behavior == AP_FS_USE_PSID) {
                        /* PSIDs are special in that they have no context at all */
                        fsuse_elem[2] = Tcl_NewStringObj("", -1);
                } else {
                        if (security_con_to_tcl_context_string(interp, fs_use->scontext, fsuse_elem + 2) == TCL_ERROR) {
                                return TCL_ERROR;
                        }
                }
                fsuse_list = Tcl_NewListObj(3, fsuse_elem);
                if (Tcl_ListObjAppendElement(interp, result_obj, fsuse_list) == TCL_ERROR) {
                        return TCL_ERROR;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}

int ap_tcl_components_init(Tcl_Interp *interp) {
        Tcl_CreateCommand(interp, "apol_GetNames", Apol_GetNames, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetTypes", Apol_GetTypes, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetAttribs", Apol_GetAttribs, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetClasses", Apol_GetClasses, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetCommons", Apol_GetCommons, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPerms", Apol_GetPerms, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetRoles", Apol_GetRoles, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetUsers", Apol_GetUsers, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetBools", Apol_GetBools, NULL, NULL);
        Tcl_CreateCommand(interp, "apol_SetBoolValue", Apol_SetBoolValue, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetLevels", Apol_GetLevels, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetCats", Apol_GetCats, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetInitialSIDs", Apol_GetInitialSIDs, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPortconProtos", Apol_GetPortconProtos, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPortcons", Apol_GetPortcons, NULL, NULL);
 	Tcl_CreateCommand(interp, "apol_GetNetifconInterfaces", Apol_GetNetifconInterfaces, NULL, NULL);
 	Tcl_CreateCommand(interp, "apol_GetNetifcons", Apol_GetNetifcons, NULL, NULL);
 	Tcl_CreateCommand(interp, "apol_GetNodecons", Apol_GetNodecons, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetGenFSConFilesystems", Apol_GetGenFSConFilesystems, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetGenFSCons", Apol_GetGenFSCons, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetFSUseBehaviors", Apol_GetFSUseBehaviors, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetFSUses", Apol_GetFSUses, NULL, NULL);
        return TCL_OK;
}
