/* Copyright (C) 2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 */

#include <tcl.h>
#include <assert.h>
#include <netinet/in.h>    /* needed for portcon's protocol */

#include "component-query.h"

#include "apol_tcl_other.h"
#include "apol_tcl_render.h"
#include "apol_tcl_fc.h"
#include "render.h"

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
	int i, rt, sz;
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
	if(strcmp("initial_sids", argv[1]) == 0) {
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

/**
 * Takes a sepol_type_datum_t and appends a tuple of it to
 * result_list.	 The tuple consists of:
 * <code>
 *    { type_name {attrib0 attrib1 ...} {alias0 alias1 ...} }
 * </code>
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
		goto cleanup;
	}
	if (is_attr) {
		/* datum is an attribute, so don't add it */
		return TCL_OK;
	}
	if (sepol_type_datum_get_name(policydb->sh, policydb->p,
				      type_datum, &type_name) < 0 ||
	    sepol_type_datum_get_attr_iter(policydb->sh, policydb->p,
					   type_datum, &attr_iter) < 0 ||
	    sepol_type_datum_get_alias_iter(policydb->sh, policydb->p,
					    type_datum, &alias_iter) < 0) {
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

/**
 * Returns an unordered list of type tuples within the policy.  Each
 * tuple consists of:
 * <ul>
 *   <li>type name
 *   <li>list of associated attributes
 *   <li>list of associated aliases
 * </ul>
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>type name to look up, or a regular expression, or empty to
 *       get all types
 *   <li>(optional) treat argv[1] as a type name or regex
 * </ol>
 */
static int Apol_GetTypes(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_type_datum_t *type;
	apol_type_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "Need a type name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_type_by_name(policydb->sh, policydb->p,
						    argv[1], &type) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_type_to_list(interp, type, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_type_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_type_query_set_type(policydb, query, argv[1]) ||
			    apol_type_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_type_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			type = (sepol_type_datum_t *) apol_vector_get_element(v, i);
			if (append_type_to_list(interp, type, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_type_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a sepol_type_datum_t representing a type and appends a tuple
 * of it to result_list.  The tuple consists of:
 * <code>
 *    { attr_name { type0 type1 ... } }
 * </code>
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
		goto cleanup;
	}
	if (!is_attr) {
		/* datum is a type or alias, so don't add it */
		return TCL_OK;
	}
	if (sepol_type_datum_get_name(policydb->sh, policydb->p,
				      attr_datum, &attr_name) < 0 ||
	    sepol_type_datum_get_type_iter(policydb->sh, policydb->p,
					   attr_datum, &type_iter) < 0) {
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
 *   <li>(optional) treat argv[1] as an attribute name or regex
 * </ol>
 */
static int Apol_GetAttribs(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_type_datum_t *attr;
	apol_attr_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "Need an attribute name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_type_by_name(policydb->sh, policydb->p,
						    argv[1], &attr) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_attr_to_list(interp, attr, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_attr_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_attr_query_set_attr(policydb, query, argv[1]) ||
			    apol_attr_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_attr_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			attr = (sepol_type_datum_t *) apol_vector_get_element(v, i);
			if (append_attr_to_list(interp, attr, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_attr_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return TCL_OK;
}

/**
 * Takes a sepol_class_datum_t representing a class and appends a
 * tuple of it to result_list.	 The tuple consists of:
 * <code>
 *    { class_name common_class {perms0 perms1 ...} }
 * </code>
 *
 * If the object class has no common, then the second element will be
 * an empty string.
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
				       class_datum, &class_name) < 0 ||
	    sepol_class_datum_get_common(policydb->sh, policydb->p,
					 class_datum, &common_datum) < 0 ||
	    (common_datum != NULL &&
	     sepol_common_datum_get_name(policydb->sh, policydb->p,
					 common_datum, &common_name) < 0) ||
	    sepol_class_datum_get_perm_iter(policydb->sh, policydb->p,
					    class_datum, &perm_iter) < 0) {
		goto cleanup;
	}
	class_elem[0] = Tcl_NewStringObj(class_name, -1);
	class_elem[1] = Tcl_NewStringObj(common_name, -1);
	class_elem[2] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(perm_iter); sepol_iterator_next(perm_iter)) {
		char *perm_name;
		Tcl_Obj *perm_obj;
		if (sepol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
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
static int Apol_GetClasses(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_class_datum_t *class_datum;
	apol_class_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "Need a class name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_class_by_name(policydb->sh, policydb->p,
						     argv[1], &class_datum) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_class_to_list(interp, class_datum, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_class_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_class_query_set_class(policydb, query, argv[1]) ||
			    apol_class_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_class_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			class_datum = (sepol_class_datum_t *) apol_vector_get_element(v, i);
			if (append_class_to_list(interp, class_datum, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_class_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}
     
/**
 * Takes a sepol_common_datum_t representing a common and appends a
 * tuple of it to result_list.	 The tuple consists of:
 * <code>
 *    { common_name {perms0 perms1 ...} {class0 class1 ...} }
 * </code>
 *
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
					common_datum, &common_name) < 0 ||
	    sepol_common_datum_get_perm_iter(policydb->sh, policydb->p,
					     common_datum, &perm_iter) < 0) {
		goto cleanup;
	}
	common_elem[0] = Tcl_NewStringObj(common_name, -1);
	common_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(perm_iter); sepol_iterator_next(perm_iter)) {
		char *perm_name;
		Tcl_Obj *perm_obj;
		if (sepol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
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
	    apol_get_class_by_query(policydb, query, &classes) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(classes); i++) {
		sepol_class_datum_t *class_datum = (sepol_class_datum_t *) apol_vector_get_element(classes, i);
		char *class_name;
		Tcl_Obj *class_obj;
		if (sepol_class_datum_get_name(policydb->sh, policydb->p,
					       class_datum, &class_name) < 0) {
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
static int Apol_GetCommons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_common_datum_t *common_datum;
	apol_common_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "Need a common name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_common_by_name(policydb->sh, policydb->p,
						      argv[1], &common_datum) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_common_to_list(interp, common_datum, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_common_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_common_query_set_common(policydb, query, argv[1]) ||
			    apol_common_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_common_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			common_datum = (sepol_common_datum_t *) apol_vector_get_element(v, i);
			if (append_common_to_list(interp, common_datum, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_common_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}
     
/**
 * Takes a string representing a permission and appends a tuple of it
 * to result_list.  The tuple consists of:
 * <code>
 *    { perm_name {class0 class1 ...} {common0 common1 ...} }
 * </code>
 */
static int append_perm_to_list(Tcl_Interp *interp,
			       const char *perm,
			       Tcl_Obj *result_list)
{
	sepol_iterator_t *class_iter = NULL, *common_iter = NULL;
	Tcl_Obj *perm_elem[3], *perm_list;
	int retval = TCL_ERROR;
	if (sepol_perm_get_class_iter(policydb->sh, policydb->p,
				      perm, &class_iter) < 0 ||
	    sepol_perm_get_common_iter(policydb->sh, policydb->p,
				       perm, &common_iter) < 0) {
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

/**
 * Returns an unordered list of permission tuples within the policy.
 * Each tuple consists of:
 * <ul>
 *   <li>permission name
 *   <li>list of classes that have this permission
 *   <li>list of commons that have this permission
 * </ul>
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>permission name to look up, or a regular expression, or empty
 *       to get all permissions
 *   <li>(optional) treat argv[1] as a permission name or regex
 * </ol>
 */
static int Apol_GetPerms(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	apol_perm_query_t *query = NULL;
	apol_vector_t *v;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "Need a permission name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (append_perm_to_list(interp, argv[1], result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		char *perm;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_perm_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_perm_query_set_perm(policydb, query, argv[1]) ||
			    apol_perm_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_perm_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			perm = (char *) apol_vector_get_element(v, i);
			if (append_perm_to_list(interp, perm, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_perm_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a sepol_role_datum_t and appends a tuple of it to
 * result_list.	 The tuple consists of:
 * <code>
 *    { role_name {types1 types2 ...} {dominated_role1 dominated_role2 ...} }
 * </code>
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
				      role_datum, &role_name) < 0 ||
	    sepol_role_datum_get_type_iter(policydb->sh, policydb->p,
					   role_datum, &type_iter) < 0 ||
	    sepol_role_datum_get_dominate_iter(policydb->sh, policydb->p,
					       role_datum, &dom_iter) < 0) {
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

/**
 * Return an unordered list of all role tuples within the policy.  Each
 * tuple consists of:
 * <ul>
 *   <li>role name
 *   <li>list of types
 *   <li>list of roles this one dominates
 * </ul>
 * @param argv This function takes three parameters:
 * <ol>
 *   <li>role name to look up, or a regular expression, or empty to
 *       get all roles
 *   <li>(optional) roles containing this type
 *   <li>(optional) treat argv[1] and argv[2] as a role name or regex
 * </ol>
 */
static int Apol_GetRoles(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_role_datum_t *role;
	apol_role_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc != 2 && argc != 4) {
		ERR(policydb, "Need a role name, ?type?, and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_role_by_name(policydb->sh, policydb->p,
						    argv[1], &role) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_role_to_list(interp, role, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[3], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0' || *argv[2] != '\0') {
			if ((query = apol_role_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_role_query_set_role(policydb, query, argv[1]) ||
			    apol_role_query_set_type(policydb, query, argv[2]) ||
			    apol_role_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_role_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			role = (sepol_role_datum_t *) apol_vector_get_element(v, i);
			if (append_role_to_list(interp, role, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_role_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
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

/**
 * Converts an apol_mls_level_t to a Tcl representation:
 * <code>
 *   { level { cat0 cat1 ... } }
 * </code>
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


/**
 * Takes a sepol_user_datum_t and appends a tuple of it to
 * result_list.	 The tuple consists of:
 * <code>
 *    { user_name { role0 role1 ... } default_level { low_range high_range } }
 * </code>
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
				      user_datum, &user_name) < 0 ||
	    sepol_user_datum_get_role_iter(policydb->sh, policydb->p,
					   user_datum, &role_iter) < 0) {
		goto cleanup;
	}
	user_elem[0] = Tcl_NewStringObj(user_name, -1);
	user_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(role_iter); sepol_iterator_next(role_iter)) {
		sepol_role_datum_t *role_datum;
		char *role_name;
		Tcl_Obj *role_obj;
		if (sepol_iterator_get_item(role_iter, (void **) &role_datum) < 0 ||
		    sepol_role_datum_get_name(policydb->sh, policydb->p,
					      role_datum, &role_name) < 0) {
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
			goto cleanup;
		}
		if (sepol_user_datum_get_range(policydb->sh, policydb->p, user_datum, &range) < 0) {
			goto cleanup;
		}
		if ((apol_default =
		     apol_mls_level_create_from_sepol_mls_level(policydb,
								default_level)) == NULL ||
		    (apol_range =
		     apol_mls_range_create_from_sepol_mls_range(policydb,
								range)) == NULL) {
			goto cleanup;
		}
		    
		if (apol_level_to_tcl_obj(interp, apol_default, user_elem + 2) == TCL_ERROR ||
		    apol_level_to_tcl_obj(interp, apol_range->low, range_elem + 0) == TCL_ERROR ||
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

/**
 * Returns an unordered list of user tuples within the policy.  Each
 * tuple consists of:
 * <ul>
 *   <li>user name
 *   <li>list of role names authorized for user
 *   <li>default level if MLS, empty otherwise (level = sensitivity +
 *       list of categories)
 *   <li>authorized range for user if MLS, empty otherwise (range =
 *       2-uple of levels)
 * </ul>
 * @param argv This function takes six parameters:
 * <ol>
 *   <li>user name to look up, or a regular expression, or empty to
 *       get all users
 *   <li>(optional) role that user cantains
 *   <li>(optional) default MLS level
 *   <li>(optional) MLS range
 *   <li>(optional) range query type
 *   <li>(optional) treat argv[1] as a user name or regex
 * </ol>
 */
static int Apol_GetUsers(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj;
	sepol_user_datum_t *user;
	apol_user_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc != 2 && argc < 7) {
		ERR(policydb, "Need a user name, ?role?, ?default level?, ?range?, ?range type?, and ?regex flag?.");
		goto cleanup;
	}
	result_obj = Tcl_NewListObj(0, NULL);
	if (argc == 2) {
		if (sepol_policydb_get_user_by_name(policydb->sh, policydb->p,
						    argv[1], &user) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_user_to_list(interp, user, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[6], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0' || *argv[2] != '\0' ||
		    *argv[3] != '\0' || *argv[4] != '\0') {
			if ((query = apol_user_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_user_query_set_user(policydb, query, argv[1]) ||
			    apol_user_query_set_role(policydb, query, argv[2]) ||
			    apol_user_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (*argv[3] != '\0') {
			apol_mls_level_t *default_level;
			if ((default_level = apol_mls_level_create()) == NULL) {
				ERR(policydb, "Out of memory.");
				goto cleanup;
			}
			if (apol_tcl_string_to_level(interp, argv[3], default_level) != 0 ||
			    apol_user_query_set_default_level(policydb, query, default_level) < 0) {
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
				ERR(policydb, "Out of memory.");
				goto cleanup;
			}
			if (apol_tcl_string_to_range(interp, argv[4], range) != 0 ||
			    apol_user_query_set_range(policydb, query, range, range_match) < 0) {
				apol_mls_range_destroy(&range);
				goto cleanup;
			}
		}
		if (apol_get_user_by_query(policydb, query, &v) < 0) {
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
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a sepol_bool_datum_t and appends a tuple of it to
 * result_list.	 The tuple consists of:
 * <code>
 *    { bool_name current_value}
 * </code>
 */
static int append_bool_to_list(Tcl_Interp *interp,
			       sepol_bool_datum_t *bool_datum,
			       Tcl_Obj *result_list)
{
	char *bool_name;
	int bool_state;
	Tcl_Obj *bool_elem[3], *bool_list;
	if (sepol_bool_datum_get_name(policydb->sh, policydb->p,
				      bool_datum, &bool_name) < 0 ||
	    sepol_bool_datum_get_state(policydb->sh, policydb->p,
				       bool_datum, &bool_state) < 0) {
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

/**
 * Return an unordered list of all conditional boolean tuples within
 * the policy.  Each tuple consists of:
 * <ul>
 *   <li>boolean name
 *   <li>current state of the boolean (either 0 or 1)
 * </ul>
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>boolean name to look up, or a regular expression, or empty to
 *       get all booleans
 *   <li>(optional) treat argv[1] as a boolean name or regex
 * </ol>
 */
static int Apol_GetBools(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_bool_datum_t *bool;
	apol_bool_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc != 2 && argc < 3) {
		ERR(policydb, "Need a boolean name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_bool_by_name(policydb->sh, policydb->p,
						    argv[1], &bool) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_bool_to_list(interp, bool, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_bool_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_bool_query_set_bool(policydb, query, argv[1]) ||
			    apol_bool_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_bool_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			bool = (sepol_bool_datum_t *) apol_vector_get_element(v, i);
			if (append_bool_to_list(interp, bool, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_bool_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Sets a boolean value within the policy.
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>boolean name
 *   <li>new state for the boolean (either 0 or 1)
 * </ol>
 */
static int Apol_SetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	sepol_bool_datum_t *bool;
	Tcl_Obj *value_obj;
	int value;

	apol_tcl_clear_error();
	if (argc != 3) {
		ERR(policydb, "Need a bool name and a value.");
		return TCL_ERROR;
	}
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
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
		apol_tcl_write_error(interp);
		return TCL_ERROR;
	}
	return TCL_OK;
}

/**
 * Takes a sepol_level_datum_t and appends a tuple of it to
 * result_list.	 The tuple consists of:
 * <code>
 *    { sens_name {alias0 alias1 ...} {cats0 cats1 ...} dominance_value }
 * </code>
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
				       level_datum, &sens_name) < 0 ||
	    sepol_level_datum_get_alias_iter(policydb->sh, policydb->p,
					     level_datum, &alias_iter) < 0 ||
	    sepol_level_datum_get_cat_iter(policydb->sh, policydb->p,
					   level_datum, &cat_iter) < 0 ||
	    sepol_level_datum_get_value(policydb->sh, policydb->p,
					level_datum, &level_value) < 0) {
		ERR(policydb, "Could not get level value.");
		goto cleanup;
	}
	level_elem[0] = Tcl_NewStringObj(sens_name, -1);
	level_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(alias_iter); sepol_iterator_next(alias_iter)) {
		char *alias_name;
		Tcl_Obj *alias_obj;
		if (sepol_iterator_get_item(alias_iter, (void **) &alias_name) < 0) {
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

/**
 * Return an unordered list of MLS level tuples within the policy.
 * Each tuple consists of:
 * <ul>
 *   <li>sensitivity name
 *   <li>list of that sensitivity's aliases
 *   <li>list of categories
 *   <li>level dominance value
 * </ul>
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>sensitivity name to look up, or a regular expression, or
 *       empty to get all levels
 *   <li>(optional) treat argv[1] as a sensitivity name or regex
 * </ol>
 */
static int Apol_GetLevels(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_level_datum_t *level;
	apol_level_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "Need a sensitivity name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_level_by_name(policydb->sh, policydb->p,
						     argv[1], &level) < 0) {
			/* passed sensitivity is not within the policy */
			return TCL_OK;
		}
		if (append_level_to_list(interp, level, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_level_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_level_query_set_sens(policydb, query, argv[1]) ||
			    apol_level_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_level_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(v); i++) {
			level = (sepol_level_datum_t *) apol_vector_get_element(v, i);
			if (append_level_to_list(interp, level, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_level_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a sepol_cat_datum_t and appends a tuple of it to
 * result_list.	 The tuple consists of:
 * <code>
 *    { cat_name {alias0 alias1 ...} {level0 level1 ...} cat_value }
 * </code>
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
				     cat_datum, &cat_name) < 0 ||
	    sepol_cat_datum_get_alias_iter(policydb->sh, policydb->p,
					   cat_datum, &alias_iter) < 0 ||
	    sepol_cat_datum_get_value(policydb->sh, policydb->p,
				      cat_datum, &cat_value) < 0) {
		goto cleanup;
	}
	cat_elem[0] = Tcl_NewStringObj(cat_name, -1);
	cat_elem[1] = Tcl_NewListObj(0, NULL);
	for ( ; !sepol_iterator_end(alias_iter); sepol_iterator_next(alias_iter)) {
		char *alias_name;
		Tcl_Obj *alias_obj;
		if (sepol_iterator_get_item(alias_iter, (void **) &alias_name) < 0) {
			goto cleanup;
		}
		alias_obj = Tcl_NewStringObj(alias_name, -1);
		if (Tcl_ListObjAppendElement(interp, cat_elem[1], alias_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	cat_elem[2] = Tcl_NewListObj(0, NULL);
	if ((query = apol_level_query_create()) == NULL ||
	    apol_level_query_set_cat(policydb, query, cat_name) < 0 ||
	    apol_get_level_by_query(policydb, query, &levels) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(levels); i++) {
		sepol_level_datum_t *level = (sepol_level_datum_t *) apol_vector_get_element(levels, i);
		char *sens_name;
		Tcl_Obj *sens_obj;
		if (sepol_level_datum_get_name(policydb->sh, policydb->p,
					       level, &sens_name) < 0) {
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

/**
 * Returns an unordered list of MLS category tuples within the policy.
 * Each tuple consists of:
 * <ul>
 *   <li>category name
 *   <li>list of that category's aliases
 *   <li>unordered list of sensitivities that have this category
 *   <li>category value
 * </ul>
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>category name to look up, or a regular expression, or empty
 *       to get all categories
 *   <li>(optional) treat argv[1] as a category name or regex
 * </ol>
 */
static int Apol_GetCats(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_cat_datum_t *cat;
	apol_cat_query_t *query = NULL;
	apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc < 2) {
		ERR(policydb, "Need a category name and ?regex flag?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_cat_by_name(policydb->sh, policydb->p,
						   argv[1], &cat) < 0) {
			/* passed category is not within the policy */
			return TCL_OK;
		}
		if (append_cat_to_list(interp, cat, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
		int regex_flag;
		size_t i;
		if (Tcl_GetBoolean(interp, argv[2], &regex_flag) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[1] != '\0') {
			if ((query = apol_cat_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_cat_query_set_cat(policydb, query, argv[1]) ||
			    apol_cat_query_set_regex(policydb, query, regex_flag)) {
				goto cleanup;
			}
		}
		if (apol_get_cat_by_query(policydb, query, &v) < 0) {
			goto cleanup;
		}
		apol_cat_query_destroy(&query);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			cat = (sepol_cat_datum_t *) apol_vector_get_element(v, i);
			if (append_cat_to_list(interp, cat, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_cat_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
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

/**
 * Given a sepol_context_struct, allocate a new TclObj to the
 * referenced paramater dest_obj.  The returned Tcl list is:
 * <code>
 *   { user role type range }
 * </code>
 * If the current policy is non-MLS then range will be an empty list.
 * Otherwise it will be a 2-ple list of levels.
 */
static int sepol_context_to_tcl_obj(Tcl_Interp *interp, sepol_context_struct_t *context, Tcl_Obj **dest_obj) {
	apol_context_t *apol_context = NULL;
	Tcl_Obj *context_elem[4], *range_elem[2];
	int retval = TCL_ERROR;

	apol_context = apol_context_create_from_sepol_context(policydb, context);
	if (apol_context == NULL) {
		ERR(policydb, "Out of memory!");
		goto cleanup;
	}
	context_elem[0] = Tcl_NewStringObj(apol_context->user, -1);
	context_elem[1] = Tcl_NewStringObj(apol_context->role, -1);
	context_elem[2] = Tcl_NewStringObj(apol_context->type, -1);
	if (is_mls_policy(policy)) {
		if (apol_level_to_tcl_obj(interp, apol_context->range->low, range_elem + 0) == TCL_ERROR ||
		    apol_level_to_tcl_obj(interp, apol_context->range->high, range_elem + 1) == TCL_ERROR) {
			goto cleanup;
		}
		context_elem[3] = Tcl_NewListObj(2, range_elem);
	}
	else {
		context_elem[3] = Tcl_NewListObj(0, NULL);
	}
	*dest_obj = Tcl_NewListObj(4, context_elem);
	retval = TCL_OK;
 cleanup:
	apol_context_destroy(&apol_context);
	return retval;
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

/**
 * Takes a sepol_portcon_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *   { low_port high_port protocol context }
 * </code>
 * where a context is:
 * <code>
 *   { user role type {low_level high_level} }
 * </code>
 */
static int append_portcon_to_list(Tcl_Interp *interp,
				  sepol_portcon_t *portcon,
				  Tcl_Obj *result_list)
{
	Tcl_Obj *portcon_elem[4], *portcon_list;
	uint8_t protocol;
	const char *proto_str;
	uint16_t low_port, high_port;
	sepol_context_struct_t *context;
	int retval = TCL_ERROR;
	if (sepol_portcon_get_low_port(policydb->sh, policydb->p,
				       portcon, &low_port) < 0 ||
	    sepol_portcon_get_high_port(policydb->sh, policydb->p,
					portcon, &high_port) < 0 ||
	    sepol_portcon_get_protocol(policydb->sh, policydb->p,
				       portcon, &protocol) < 0 ||
	    sepol_portcon_get_context(policydb->sh, policydb->p,
				      portcon, &context) < 0) {
		goto cleanup;
	}
	portcon_elem[0] = Tcl_NewIntObj(low_port);
	portcon_elem[1] = Tcl_NewIntObj(high_port);
	if ((proto_str = apol_protocol_to_str(protocol)) == NULL) {
		ERR(policydb, "Unrecognized protocol in portcon");
		goto cleanup;
	}
	portcon_elem[2] = Tcl_NewStringObj(proto_str, -1);
	if (sepol_context_to_tcl_obj(interp, context, portcon_elem + 3) == TCL_ERROR) {
		goto cleanup;
	}
	portcon_list = Tcl_NewListObj(4, portcon_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, portcon_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Given a string giving a protocol name, set the referenced proto
 * variable to its numerical representation.  Current acceptable names
 * are "tcp" and "udp" (note the lowercase).
 *
 * @param interp Tcl interpreter object.
 * @param proto_name Protocol name.
 * @param proto Reference to where to store protocol number.
 *
 * @return 0 on success, <0 if the protocol was unknown.
 */
static int apol_tcl_string_to_proto(Tcl_Interp *interp, const char *proto_name, int *proto)
{
	if (strcmp(proto_name, "tcp") == 0) {
		*proto = IPPROTO_TCP;
	}
	else if (strcmp(proto_name, "udp") == 0) {
		*proto = IPPROTO_UDP;
	}
	else if (*proto_name != '\0') {
		ERR(policydb, "Unknown protocol.");
		return -1;
	}
	return 0;
}

/**
 * Return an unordered list of portcon tuples within the current
 * policy.  Each tuple consists of:
 * <ul>
 *   <li>low port
 *   <li>high port
 *   <li>protocol
 *   <li>portcon context
 * </ul>
 * where a context is:
 * <code>
 *   { user role type range }
 * </code>
 *
 * @param argv This function takes five parameters:
 * <ol>
 *   <li>low port to lookup, or -1 to ignore
 *   <li>high port, or -1 to ignore
 *   <li>(optional) protocol string
 *   <li>(optional) full or partial context to match
 *   <li>(optional) range query type
 * </ol>
 */
static int Apol_GetPortcons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_portcon_t *portcon;
	int low = -1, high = -1, proto = -1;
	apol_context_t *context = NULL;
	unsigned int range_match;
	apol_portcon_query_t *query = NULL;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc != 3 && argc != 6) {
		ERR(policydb, "Need a low port, high port, ?proto?, ?context?, ?range_match?.");
		goto cleanup;
	}
	
	if (Tcl_GetInt(interp, argv[1], &low) == TCL_ERROR ||
	    Tcl_GetInt(interp, argv[2], &high) == TCL_ERROR) {
		goto cleanup;
	}
	if (argc == 6) {
		if (apol_tcl_string_to_proto(interp, argv[3], &proto) == TCL_ERROR) {
			goto cleanup;
		}
		if (*argv[4] != '\0') {
			if ((context = apol_context_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_tcl_string_to_context(interp, argv[4], context) < 0 ||
			    apol_tcl_string_to_range_match(interp, argv[5], &range_match) < 0) {
				goto cleanup;
			}
		}
	}
	if (low >= 0 || high >= 0 || proto >= 0 || context != NULL) {
		if ((query = apol_portcon_query_create()) == NULL) {
			ERR(policydb, "Out of memory!");
			goto cleanup;
		}
		if (apol_portcon_query_set_low(policydb, query, low) < 0 ||
		    apol_portcon_query_set_high(policydb, query, high) < 0 ||
		    apol_portcon_query_set_proto(policydb, query, proto) < 0 ||
		    apol_portcon_query_set_context(policydb, query, context, range_match)) {
			goto cleanup;
		}
		context = NULL;
	}
	if (apol_get_portcon_by_query(policydb, query, &v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		portcon = (sepol_portcon_t *) apol_vector_get_element(v, i);
		if (append_portcon_to_list(interp, portcon, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_context_destroy(&context);
	apol_portcon_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a sepol_netifcon_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *   { device if_context msg_context }
 * </code>
 */
static int append_netifcon_to_list(Tcl_Interp *interp,
				  sepol_netifcon_t *netifcon,
				  Tcl_Obj *result_list)
{
	char *name;
	sepol_context_struct_t *if_context, *msg_context;
	Tcl_Obj *netifcon_elem[3], *netifcon_list;
	int retval = TCL_ERROR;
	if (sepol_netifcon_get_name(policydb->sh, policydb->p,
				    netifcon, &name) < 0 ||
	    sepol_netifcon_get_if_con(policydb->sh, policydb->p,
				      netifcon, &if_context) < 0 ||
	    sepol_netifcon_get_msg_con(policydb->sh, policydb->p,
				       netifcon, &msg_context) < 0) {
		goto cleanup;
	}
	netifcon_elem[0] = Tcl_NewStringObj(name, -1);
	if (sepol_context_to_tcl_obj(interp, if_context, netifcon_elem + 1) == TCL_ERROR ||
	    sepol_context_to_tcl_obj(interp, msg_context, netifcon_elem + 2) == TCL_ERROR) {
		goto cleanup;
	}
	netifcon_list = Tcl_NewListObj(3, netifcon_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, netifcon_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return an unsorted list of netifcon tuples within the policy.  Each
 * tuple consists of:
 * <ul>
 *   <li>network device
 *   <li>context for device
 *   <li>context for messages sent through that device
 * </ul>
 * where a context is:
 * <code>
 *   { user role type range }
 * </code>
 *
 * @param argv This function takes five parameters:
 * <ol>
 *   <li>network device name to look up, or empty to get all netifcons
 *   <li>(optional) device context, full or partial
 *   <li>(optional) range query type for device context
 *   <li>(optional) message context, full or partial
 *   <li>(optional) range query type for message context
 * </ol>
 */
static int Apol_GetNetifcons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_netifcon_t *netifcon;
        apol_context_t *if_context = NULL, *msg_context = NULL;
        unsigned int if_range_match = 0, msg_range_match = 0;
        apol_netifcon_query_t *query = NULL;
        apol_vector_t *v = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc != 2 && argc != 6) {
		ERR(policydb, "Need a device, ?if_context?, ?if_range_match?, ?msg_context?, and ?msg_range_match?.");
		goto cleanup;
	}
	if (argc == 2) {
		if (sepol_policydb_get_netifcon_by_name(policydb->sh, policydb->p,
							argv[1], &netifcon) < 0) {
			/* passed netifcon is not within the policy */
			return TCL_OK;
		}
		if (append_netifcon_to_list(interp, netifcon, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	else {
                const char *dev = NULL;
                size_t i;
                if (*argv[1] != '\0') {
                        dev = argv[1];
                }
                if (*argv[2] != '\0') {
                        if ((if_context = apol_context_create()) == NULL) {
                                ERR(policydb, "Out of memory!");
                                goto cleanup;
                        }
                        if (apol_tcl_string_to_context(interp, argv[2], if_context) < 0 ||
                            apol_tcl_string_to_range_match(interp, argv[3], &if_range_match) < 0) {
                                goto cleanup;
                        }
                }
                if (*argv[4] != '\0') {
                        if ((msg_context = apol_context_create()) == NULL) {
                                ERR(policydb, "Out of memory!");
                                goto cleanup;
                        }
                        if (apol_tcl_string_to_context(interp, argv[4], msg_context) < 0 ||
                            apol_tcl_string_to_range_match(interp, argv[5], &msg_range_match) < 0) {
                                goto cleanup;
                        }
                }
                if (dev != NULL || if_context != NULL || msg_context != NULL) {
                        if ((query = apol_netifcon_query_create()) == NULL) {
                                ERR(policydb, "Out of memory!");
                                goto cleanup;
                        }
                        if (apol_netifcon_query_set_device(policydb, query,
                                                           dev) < 0 ||
                            apol_netifcon_query_set_if_context(policydb, query,
                                                               if_context, if_range_match) < 0) {
                                goto cleanup;
                        }
                        if_context = NULL;
                        if (apol_netifcon_query_set_msg_context(policydb, query,
                                                                msg_context, msg_range_match) < 0) {
                                goto cleanup;
                        }
                        msg_context = NULL;
                }
                if (apol_get_netifcon_by_query(policydb, query, &v) < 0) {
                        goto cleanup;
                }
                for (i = 0; i < apol_vector_get_size(v); i++) {
                        netifcon = (sepol_netifcon_t *) apol_vector_get_element(v, i);
                        if (append_netifcon_to_list(interp, netifcon, result_obj) < 0) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
        apol_context_destroy(&if_context);
        apol_context_destroy(&msg_context);
	apol_netifcon_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a sepol_nodecon_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *   { IP_type address mask context }
 * </code>
 */
static int append_nodecon_to_list(Tcl_Interp *interp,
				  sepol_nodecon_t *nodecon,
				  Tcl_Obj *result_list)
{
	unsigned char proto, proto_a, proto_m;
	uint32_t *addr, *mask;
	char *addr_str = NULL, *mask_str = NULL;
	sepol_context_struct_t *context;
	Tcl_Obj *nodecon_elem[4], *nodecon_list;
	int retval = TCL_ERROR;
	if (sepol_nodecon_get_protocol(policydb->sh, policydb->p,
				   nodecon, &proto) < 0 ||
	    sepol_nodecon_get_addr(policydb->sh, policydb->p,
				   nodecon, &addr, &proto_a) < 0 ||
	    sepol_nodecon_get_mask(policydb->sh, policydb->p,
				   nodecon, &mask, &proto_m) < 0 ||
	    sepol_nodecon_get_context(policydb->sh, policydb->p,
				      nodecon, &context) < 0) {
		goto cleanup;
	}
	assert(proto == proto_a && proto == proto_m);
	if (proto == SEPOL_IPV4) {
		nodecon_elem[0] = Tcl_NewStringObj("ipv4", -1);
		if ((addr_str = re_render_ipv4_addr(policydb, addr[0])) == NULL ||
		    (mask_str = re_render_ipv4_addr(policydb, mask[0])) == NULL) {
			goto cleanup;
		}
	}
	else if (proto == SEPOL_IPV6) {
		nodecon_elem[0] = Tcl_NewStringObj("ipv6", -1);
		if ((addr_str = re_render_ipv6_addr(policydb, addr)) == NULL ||
		    (mask_str = re_render_ipv6_addr(policydb, mask)) == NULL) {
			goto cleanup;
		}
	}
	else {
		ERR(policydb, "Unknown protocol.");
		goto cleanup;
	}
	nodecon_elem[1] = Tcl_NewStringObj(addr_str, -1);
	nodecon_elem[2] = Tcl_NewStringObj(mask_str, -1);
	if (sepol_context_to_tcl_obj(interp, context, nodecon_elem + 3) == TCL_ERROR) {
		goto cleanup;
	}
	nodecon_list = Tcl_NewListObj(4, nodecon_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, nodecon_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	free(addr_str);
	free(mask_str);
	return retval;
}

/**
 * Return an unsorted list of nodecon declarations within the policy.
 * Each tuple consists of:
 * <ul>
 *   <li>IP type ("ipv4" or "ipv6")
 *   <li>address
 *   <li>netmask
 *   <li>nodecon context
 * </ul>
 * where addresses and netmasks are lists of 4 unsigned values and a
 * context is:
 * <code>
 *   { user role type range }
 * </code>
 *
 * @param argv This function takes five parameters:
 * <ol>
 *   <li>address, or empty to ignore
 *   <li>(optional) netmask, or empty to ignore
 *   <li>(optional) IP type ("ipv4" or "ipv6") to lookup, or empty to ignore
 *   <li>(optional) full or partial context to match
 *   <li>(optional) range query type
 * </ol>
 */
static int Apol_GetNodecons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_nodecon_t *nodecon;
	int proto = -1, proto_a = -1, proto_m = -1;
	uint32_t *addr = NULL, *mask = NULL;
	unsigned char has_addr = 0, has_mask = 0;
	apol_context_t *context = NULL;
	unsigned int range_match;
	apol_nodecon_query_t *query = NULL;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = TCL_ERROR;
	
	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc != 2 && argc != 6) {
		ERR(policydb, "Need an address, ?netmask?, ?IP_type?, ?context?, and ?range_match?.");
		goto cleanup;
	}
	if (*argv[1] != '\0') {
		if ((addr = calloc(4, sizeof(*addr))) == NULL) {
			ERR(policydb, "Out of memory!");
			goto cleanup;
		}
		if ((proto_a = apol_str_to_internal_ip(argv[1], addr)) < 0) {
			ERR(policydb, "Invalid address.");
			goto cleanup;
		}
		has_addr = 1;
	}
	if (argc == 6) {
		if (*argv[2] != '\0') {
			if ((mask = calloc(4, sizeof(*mask))) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if ((proto_m = apol_str_to_internal_ip(argv[2], mask)) < 0) {
				ERR(policydb, "Invalid mask.");
				goto cleanup;
			}
			has_mask = 1;
		}
		if (strcmp(argv[3], "ipv4") == 0) {
			proto = 0;
		}
		else if (strcmp(argv[3], "ipv6") == 0) {
			proto = 1;
		}
		else if (*argv[3] != '\0') {
			ERR(policydb, "Unknown protocol.");
			goto cleanup;
		}
		if (*argv[4] != '\0') {
			if ((context = apol_context_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_tcl_string_to_context(interp, argv[4], context) < 0 ||
			    apol_tcl_string_to_range_match(interp, argv[5], &range_match) < 0) {
				goto cleanup;
			}
		}
	}
	if (proto >= 0 || has_addr || has_mask || context != NULL) {
		if ((query = apol_nodecon_query_create()) == NULL) {
			ERR(policydb, "Out of memory!");
			goto cleanup;
		}
		if (apol_nodecon_query_set_proto(policydb, query, proto) < 0 ||
		    apol_nodecon_query_set_addr(policydb, query, addr, proto_a) < 0 ||
		    apol_nodecon_query_set_mask(policydb, query, mask, proto_m) < 0 ||
		    apol_nodecon_query_set_context(policydb, query, context, range_match) < 0) {
			goto cleanup;
		}
		context = NULL;
	}
	if (apol_get_nodecon_by_query(policydb, query, &v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		nodecon = (sepol_nodecon_t *) apol_vector_get_element(v, i);
		if (append_nodecon_to_list(interp, nodecon, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	free(addr);
	free(mask);
	apol_context_destroy(&context);
	apol_nodecon_query_destroy(&query);
	apol_vector_destroy(&v, free);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a sepol_genfscon_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *   { fs_type path object_class context }
 * </code>
 */
static int append_genfscon_to_list(Tcl_Interp *interp,
				   sepol_genfscon_t *genfscon,
				   Tcl_Obj *result_obj)
{
	char *name, *path;
	uint32_t objclass_val;
	const char *objclass;
	sepol_context_struct_t *context;
	Tcl_Obj *genfs_elem[4], *genfs_list;
	int retval = TCL_ERROR;
	if (sepol_genfscon_get_name(policydb->sh, policydb->p,
				    genfscon, &name) < 0 ||
	    sepol_genfscon_get_path(policydb->sh, policydb->p,
				    genfscon, &path) < 0 ||
	    sepol_genfscon_get_class(policydb->sh, policydb->p,
				     genfscon, &objclass_val) < 0 ||
	    sepol_genfscon_get_context(policydb->sh, policydb->p,
				       genfscon, &context) < 0) {
		goto cleanup;
	}
	genfs_elem[0] = Tcl_NewStringObj(name, -1);
	genfs_elem[1] = Tcl_NewStringObj(path, -1);
	if ((objclass = apol_objclass_to_str(objclass_val)) == NULL) {
		ERR(policydb, "Illegal object class given in genfscon node.");
		goto cleanup;
	}
	genfs_elem[2] = Tcl_NewStringObj(objclass, -1);
	if (sepol_context_to_tcl_obj(interp, context, genfs_elem + 3) == TCL_ERROR) {
		goto cleanup;
	}
	genfs_list = Tcl_NewListObj(4, genfs_elem);
	if (Tcl_ListObjAppendElement(interp, result_obj, genfs_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return an unsorted list of genfscon declarations within the policy.
 * Each tuple consists of:
 * <ul>
 *   <li>filesystem type
 *   <li>path
 *   <li>object class ("block", "char", "dir", etc)
 *   <li>context
 * </ul>
 * where context is:
 * <code>
 *   { user role type range }
 * </code>
 *
 * Entries with the same filesystem are reported as separate elements.
 *
 * @param argv This function takes four parameters:
 * <ol>
 *   <li>filesystem
 *   <li>(optional) path
 *   <li>(optional) full or partial context to match
 *   <li>(optional) range query type
 * </ol>
 */
static int Apol_GetGenFSCons(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
        sepol_genfscon_t *genfscon;
        CONST char *fstype = NULL, *path = NULL;
        int objclass = -1;
        apol_context_t *context = NULL;
        unsigned int range_match = 0;
        apol_genfscon_query_t *query = NULL;
        apol_vector_t *v = NULL;
        size_t i;
        int retval = TCL_ERROR;

        apol_tcl_clear_error();
        if (policy == NULL) {
                ERR(policydb, "No current policy file is opened!");
                goto cleanup;
        }
        if (argc != 2 && argc != 5) {
                ERR(policydb, "Need a fstype, ?path?, ?file_type?, ?context?, and ?range_match?.");
                goto cleanup;
        }
        if (*argv[1] != '\0') {
                fstype = argv[1];
        }
        if (argc == 5) {
                if (*argv[2] != '\0') {
                        path = argv[2];
                }
                if (*argv[3] != '\0') {
                        if ((context = apol_context_create()) == NULL) {
                                ERR(policydb, "Out of memory!");
                                goto cleanup;
                        }
                        if (apol_tcl_string_to_context(interp, argv[3], context) < 0 ||
                            apol_tcl_string_to_range_match(interp, argv[4], &range_match) < 0) {
                                goto cleanup;
                        }
                }
        }
        if (fstype != NULL || path != NULL || objclass >= 0 || context != NULL) {
                if ((query = apol_genfscon_query_create()) == NULL) {
                        ERR(policydb, "Out of memory!");
                        goto cleanup;
                }
                if (apol_genfscon_query_set_filesystem(policydb, query, fstype) < 0 ||
                    apol_genfscon_query_set_path(policydb, query, path) < 0 ||
                    apol_genfscon_query_set_objclass(policydb, query, objclass) < 0 ||
                    apol_genfscon_query_set_context(policydb, query, context, range_match) < 0) {
                        goto cleanup;
                }
                context = NULL;
        }
        if (apol_get_genfscon_by_query(policydb, query, &v) < 0) {
                goto cleanup;
        }
        for (i = 0; i < apol_vector_get_size(v); i++) {
                genfscon = (sepol_genfscon_t *) apol_vector_get_element(v, i);
                if (append_genfscon_to_list(interp, genfscon, result_obj) == TCL_ERROR) {
                        goto cleanup;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        retval = TCL_OK;
 cleanup:
        apol_context_destroy(&context);
        apol_genfscon_query_destroy(&query);
        apol_vector_destroy(&v, free);
        if (retval == TCL_ERROR) {
                apol_tcl_write_error(interp);
        }
        return retval;
}

/**
 * Takes a sepol_fs_use_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *   { fs_behavior fs_type context }
 * </code>
 *
 * Note that if fs_behavior is SEPOL_FS_USE_PSID, the context will be
 * an empty string.
 */
static int append_fs_use_to_list(Tcl_Interp *interp,
				 sepol_fs_use_t *fsuse,
				 Tcl_Obj *result_obj) {
	char *name;
	uint32_t behavior;
	const char *behav_str;
	sepol_context_struct_t *context;
	Tcl_Obj *fsuse_elem[3], *fsuse_list;
	int retval = TCL_ERROR;
	if (sepol_fs_use_get_behavior(policydb->sh, policydb->p,
				      fsuse, &behavior) < 0 ||
	    sepol_fs_use_get_name(policydb->sh, policydb->p,
				  fsuse, &name) < 0 ||
	    (behavior != SEPOL_FS_USE_PSID &&
	     sepol_fs_use_get_context(policydb->sh, policydb->p,
				      fsuse, &context) < 0)) {
		goto cleanup;
	}
	if ((behav_str = apol_fs_use_behavior_to_str(behavior)) == NULL) {
		ERR(policydb, "Illegal fs_use bahavior given in fs_use.");
		goto cleanup;
	}
	fsuse_elem[0] = Tcl_NewStringObj(behav_str, -1);
	fsuse_elem[1] = Tcl_NewStringObj(name, -1);
	if (behavior == SEPOL_FS_USE_PSID) {
		fsuse_elem[2] = Tcl_NewStringObj("", -1);
	}
	else {
		if (sepol_context_to_tcl_obj(interp, context, fsuse_elem + 2) == TCL_ERROR) {
			goto cleanup;
		}
	}
	fsuse_list = Tcl_NewListObj(3, fsuse_elem);
	if (Tcl_ListObjAppendElement(interp, result_obj, fsuse_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return an unsorted list of fs_use declarations within the policy.
 * Each tuple consists of:
 * <ul>
 *   <li>fs_use behavior ("fs_use_psid,", "fs_use_xattr", etc.)
 *   <li>filesystem type
 *   <li>context
 * </ul>
 * where context is:
 * <code>
 *   { user role type range }
 * </code>
 *
 * If the behavior is "fs_use_psid", the context will be an empty
 * string.
 *
 * @param argv This function takes four parameters:
 * <ol>
 *   <li>filesystem
 *   <li>(optional) behavior ("fs_use_psid", "fs_use_xattr", etc.)
 *   <li>(optional) full or partial context to match
 *   <li>(optional) range query type
 * </ol>
 */
static int Apol_GetFSUses(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	sepol_fs_use_t *fsuse;
	CONST char *fstype = NULL;
	int behavior = -1;
	apol_context_t *context = NULL;
	unsigned int range_match = 0;
	apol_fs_use_query_t *query = NULL;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		ERR(policydb, "No current policy file is opened!");
		goto cleanup;
	}
	if (argc != 2 && argc != 5) {
		ERR(policydb, "Need a fstype, ?fs_behavior?, ?context?, and ?range_match?.");
		goto cleanup;
	}
	if (*argv[1] != '\0') {
		fstype = argv[1];
	}
	if (argc == 5) {
		if (*argv[2] != '\0' &&
		    (behavior = apol_str_to_fs_use_behavior(argv[2])) < 0) {
			ERR(policydb, "Invalid fs_use behavior.");
			goto cleanup;
		}
		if (*argv[3] != '\0') {
			if ((context = apol_context_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
			if (apol_tcl_string_to_context(interp, argv[3], context) < 0 ||
			    apol_tcl_string_to_range_match(interp, argv[4], &range_match) < 0) {
				goto cleanup;
			}
		}
	}
	if (fstype != NULL || behavior >= 0 || context != NULL) {
		if ((query = apol_fs_use_query_create()) == NULL) {
			ERR(policydb, "Out of memory!");
			goto cleanup;
		}
		if (apol_fs_use_query_set_filesystem(policydb, query, fstype) < 0 ||
		    apol_fs_use_query_set_behavior(policydb, query, behavior) < 0 ||
		    apol_fs_use_query_set_context(policydb, query, context, range_match) < 0) {
			goto cleanup;
		}
		context = NULL;
	}
	if (apol_get_fs_use_by_query(policydb, query, &v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		fsuse = (sepol_fs_use_t *) apol_vector_get_element(v, i);
		if (append_fs_use_to_list(interp, fsuse, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_context_destroy(&context);
	apol_fs_use_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
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
	Tcl_CreateCommand(interp, "apol_GetPortcons", Apol_GetPortcons, NULL, NULL);
 	Tcl_CreateCommand(interp, "apol_GetNetifcons", Apol_GetNetifcons, NULL, NULL);
 	Tcl_CreateCommand(interp, "apol_GetNodecons", Apol_GetNodecons, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetGenFSCons", Apol_GetGenFSCons, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetFSUses", Apol_GetFSUses, NULL, NULL);
        return TCL_OK;
}
