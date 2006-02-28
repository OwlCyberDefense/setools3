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
	else if(strcmp("attribs", argv[1]) == 0) {
		for(i = 0; get_attrib_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
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
	else if(strcmp("common_perms", argv[1]) == 0) {
		for(i = 0; get_common_perm_name(i, &name, policy) == 0; i++) {
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
	else if(strcmp("cond_bools", argv[1]) == 0) {
		for(i = 0; get_cond_bool_name(i, &name, policy) == 0; i++) {
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

/* get types for a given attribute, returns a TCL list */
/* args ordering:
 * argv[1]	attrib name
 */
static int Apol_GetAttribTypesList(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int idx, j;
	char tmpbuf[APOL_STR_SZ];
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Type/attrib string is too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	idx = get_attrib_idx(argv[1], policy);
	if(idx < 0) {
		sprintf(tmpbuf, "Invalid  attribute (%s)", argv[1]);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;			
	}	
	
	for(j = 0; j < policy->attribs[idx].num; j++) {
		Tcl_AppendElement(interp, policy->types[policy->attribs[idx].a[j]].name);
	}	
	
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
	char *type_name;
	sepol_iterator_t *attr_iter = NULL, *alias_iter = NULL;
	Tcl_Obj *type_elem[3], *type_list;
	int retval = TCL_ERROR;
	if (sepol_type_datum_get_name(policy_handle, policydb,
				      type_datum, &type_name) < 0) {
		Tcl_SetResult(interp, "Could not get type name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_type_datum_get_attr_iter(policy_handle, policydb,
					   type_datum, &attr_iter) < 0) {
		Tcl_SetResult(interp, "Could not get attr iterator.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_type_datum_get_alias_iter(policy_handle, policydb,
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
		    sepol_type_datum_get_name(policy_handle, policydb,
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
		if (sepol_policydb_get_type_by_name(policy_handle, policydb,
						    argv[1], &type) < 0) {
			/* name is an attribute or not within policy */
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
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_type_by_query(policy_handle, policydb,
					   query, &v)) {
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


/* Returns an unordered list of attribute tuples within the policy.
 *   elem 0 - attribute name
 *   elem 1 - list of types with that attribute
 * argv[1] - attribute name to look up, or a regular expression, or
 *	     empty to get all attributes
 * argv[2] - treat argv[1] as an attribute name or regex
 */
static int Apol_GetAttribs(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	int i, target_attrib = -1;
	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 3) {
		Tcl_SetResult(interp, "Need an attribute name and a regex flag.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (strcmp(argv[1], "") != 0) {
		target_attrib = get_attrib_idx(argv[1], policy);
		if (target_attrib == -1) {
			/* name is a type or not within policy */
			return TCL_OK;
		}
	}
	for (i = 0; i < policy->num_attribs; i++) {
		Tcl_Obj *attrib_elem[2], *attrib_list;
		name_a_t *attrib = policy->attribs + i;
		int j;
		if (target_attrib != -1 && i != target_attrib) {
			continue;
		}
		attrib_elem[0] = Tcl_NewStringObj(attrib->name, -1);
		attrib_elem[1] = Tcl_NewListObj(0, NULL);
		for (j = 0; j < attrib->num; j++) {
			int type_idx = attrib->a[j];
			type_item_t *type = policy->types + type_idx;
			Tcl_Obj *type_name = Tcl_NewStringObj(type->name, -1);
			if (Tcl_ListObjAppendElement(interp, attrib_elem[1], type_name) == TCL_ERROR) {
				return TCL_ERROR;
			}
		}
		attrib_list = Tcl_NewListObj(2, attrib_elem);
		if (Tcl_ListObjAppendElement(interp, result_obj, attrib_list) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

static int append_common_perm_str(bool_t do_perms, bool_t do_classes, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy);
static int append_perm_str(bool_t do_common_perms, bool_t do_classes, bool_t newline, int idx, Tcl_DString *buf,
                           policy_t *policy);

static int append_class_str(bool_t do_perms, bool_t do_cps, bool_t expand_cps, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy)
{
	int i, cp_idx;
	
	if(idx >= policy->num_obj_classes|| buf == NULL) {
		return -1;
	}
	
	Tcl_DStringAppend(buf, policy->obj_classes[idx].name, -1);
	
	if(do_cps || do_perms) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	/* class-specific perms */
	if(do_perms) {
		for(i = 0; i < policy->obj_classes[idx].num_u_perms; i++) {
			assert(i < policy->num_perms);
			Tcl_DStringAppend(buf, "     ", -1);
			append_perm_str(0, 0, 1, policy->obj_classes[idx].u_perms[i], buf, policy);
		}
	}
	
	/* common perms */
	if(do_cps) {
		if(policy->obj_classes[idx].common_perms >= 0) {
			cp_idx = policy->obj_classes[idx].common_perms;
			Tcl_DStringAppend(buf, "     ", -1);
			append_common_perm_str(0, 0, 0, cp_idx, buf, policy);
			Tcl_DStringAppend(buf, "  (common perm)\n", -1);
			if(expand_cps) {
				for(i = 0; i < policy->common_perms[cp_idx].num_perms; i++) {
					assert(i < policy->num_perms);
					Tcl_DStringAppend(buf, "          ", -1);
					append_perm_str(0, 0, 1, policy->common_perms[cp_idx].perms[i], buf, policy);
				}
			}
		}
	}
	
	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);		
	return TCL_OK;
}

static int append_common_perm_str(bool_t do_perms, bool_t do_classes, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy)
{
	int i;
	char tbuf[APOL_STR_SZ + 64];
	
	if(idx >= policy->num_common_perms|| buf == NULL) {
		return -1;
	}	
	Tcl_DStringAppend(buf, policy->common_perms[idx].name, -1);
	if(do_perms) {
		sprintf(tbuf, "   (%d permissions)\n", policy->common_perms[idx].num_perms);
		Tcl_DStringAppend(buf, tbuf, -1);
		for(i = 0; i < policy->common_perms[idx].num_perms; i++) {
			Tcl_DStringAppend(buf, "     ", -1);
			append_perm_str(0, 0, 1, policy->common_perms[idx].perms[i], buf, policy);
		}
	}
	/* determine which classes use this common perm */
	if(do_classes) {
		Tcl_DStringAppend(buf, "\n   Object classes that use this common permission\n", -1);
		for(i = 0; i < policy->num_obj_classes; i++) {
			if(does_class_use_common_perm(i, idx, policy)) {
				Tcl_DStringAppend(buf, "     ", -1);
				append_class_str(0,0,0,1,i,buf,policy);
			}
		}
	}
	
	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);		
	return TCL_OK;
}


static int append_perm_str(bool_t do_common_perms, bool_t do_classes, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy)
{
	int i;
	bool_t used;
	
	if(idx >= policy->num_perms|| buf == NULL) {
		return -1;
	}
	
	Tcl_DStringAppend(buf, policy->perms[idx], -1);
	if(do_classes || do_common_perms) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	/* find the classes that use this perm */
	if(do_classes) {
		used = FALSE;
		Tcl_DStringAppend(buf, "   object classes:\n", -1);
		for(i = 0; i < policy->num_obj_classes; i++) {
			if(does_class_use_perm(i, idx, policy)) {
				used = TRUE;
				Tcl_DStringAppend(buf, "        ", -1);
				append_class_str(0,0,0,1,i,buf,policy);
			}
			else if(does_class_indirectly_use_perm(i, idx, policy)) {
				used = TRUE;
				Tcl_DStringAppend(buf, "        ", -1);
				append_class_str(0,0,0,0,i,buf,policy);
				/* we "star" those included via common perm */
				Tcl_DStringAppend(buf, "*\n", -1);
			}
		}
		if(!used) {
			Tcl_DStringAppend(buf, "        <none>\n", -1);
		}
	}	
	/* find the common perms that use this perm */
	if(do_common_perms) {
		used = FALSE;
		Tcl_DStringAppend(buf, "   common permissions:\n", -1);
		for(i = 0; i < policy->num_common_perms; i++) {
			if(does_common_perm_use_perm(i, idx, policy)) {
				used = TRUE;
				Tcl_DStringAppend(buf, "        ", -1);
				append_common_perm_str(0,0,1,i,buf,policy);
			}
		}
		if(!used) {
			Tcl_DStringAppend(buf, "        <none>\n", -1);
		}
	}

	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);		
	return TCL_OK;	
}

/* 
 * Get information about object classes, permissions, and common perms
 * args are:
 *
 * 1	do_classes	(bool)
 * 2	classes_perms 	(bool, ignored if !do_classes)
 * 3	classes_cps	(bool, ignored if !do_classes || !classes_cps)
 * 4	do_comm_perms	(bool)
 * 5	cp_perms	(bool, ignored if !do_comm_perms)
 * 6	cp_classes	(bool, ignored if !do_comm_perms)
 * 7	do_perms	(bool)
 * 8	perm_classes	(bool, ignored if !do_perms)
 * 9	perm_cps	(bool, ignored if !do_perms)
 * 10	use_srchstr	(bool, regex)
 * 11	srch_str	(string, ignored if !use_srch_str)
 *
 */
static int Apol_GetClassPermInfo(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int i, sz, rt;
	char *err;
	Tcl_DString buffer, *buf = &buffer;
	bool_t do_classes, classes_perms, classes_cps, do_common_perms, cp_perms, cp_classes, do_perms,
		perm_classes, perm_cps, use_srchstr;
	regex_t reg;
        int results_found;
	
	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	do_classes = getbool(argv[1]);
	if(do_classes) {
		classes_perms = getbool(argv[2]);
		if(classes_perms)
			classes_cps = getbool(argv[3]);
		else
			classes_cps = FALSE;
	}
	else {
		classes_perms = FALSE;
		classes_cps = FALSE;
	}
	do_common_perms = getbool(argv[4]);
	if(do_common_perms) {
		cp_perms = getbool(argv[5]);
		cp_classes = getbool(argv[6]);
	}
	else {
		cp_perms = FALSE;
		cp_classes = FALSE;
	}
	do_perms = getbool(argv[7]);
	if(do_perms) {
		perm_classes = getbool(argv[8]);
		perm_cps = getbool(argv[9]);
	}
	else {
		perm_classes = FALSE;
		perm_cps = FALSE;
	}
	if(!do_classes && !do_common_perms && !do_perms) {
		return TCL_OK; /* nothing to do! */
	}
	use_srchstr = getbool(argv[10]);
	if(use_srchstr) {
		if(!is_valid_str_sz(argv[11])) {
			Tcl_AppendResult(interp, "Regular expression string is too large", (char *) NULL);
			return TCL_ERROR;
		}
		rt = regcomp(&reg, argv[11], REG_EXTENDED|REG_NOSUB);
		if(rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				Tcl_AppendResult(interp, "out of memory", (char *) NULL);
				return TCL_ERROR;
			}
			regerror(rt, &reg, err, sz);
			Tcl_AppendResult(interp, "Invalid regular expression:\n\n     ", (char*) NULL);
			Tcl_AppendResult(interp, argv[11], (char*) NULL);
			Tcl_AppendResult(interp, "\n\n", (char*) NULL);
			Tcl_AppendResult(interp, err, (char *) NULL);
			Tcl_DStringFree(buf);
			regfree(&reg);
			free(err);
			return TCL_ERROR;
			
		}
	}

	
	Tcl_DStringInit(buf);

	/* FIX: Here and elsewhere, need to use sorted traversal using AVL trees */	
	if(do_classes) {
                results_found = 0;
		Tcl_DStringAppend(buf, "OBJECT CLASSES:\n", -1);
		for(i = 0; i < policy->num_obj_classes; i++) {
			if(use_srchstr && (regexec(&reg, policy->obj_classes[i].name, 0,NULL,0) != 0)) {
				continue;
			}
			append_class_str(classes_perms, classes_perms, classes_cps, 1, i, buf, policy);
                        results_found = 1;
		}
                if (results_found == 0) {
                        Tcl_DStringAppend(buf, "Search returned no results.", -1);
                }
		Tcl_DStringAppend(buf, "\n\n", -1);
	}
	if(do_common_perms) {
                results_found = 0;
		Tcl_DStringAppend(buf, "COMMON PERMISSIONS:\n", -1);
		for(i = 0; i < policy->num_common_perms; i++) {
			if(use_srchstr && (regexec(&reg, policy->common_perms[i].name, 0,NULL,0) != 0)) {
				continue;
			}
			append_common_perm_str(cp_perms, cp_classes, 1, i, buf, policy);
                        results_found = 1;
		}
                if (results_found == 0) {
                        Tcl_DStringAppend(buf, "Search returned no results.", -1);
                }
		Tcl_DStringAppend(buf, "\n\n", -1);
	}
	if(do_perms) {
                results_found = 0;
		Tcl_DStringAppend(buf, "PERMISSIONS", -1);
		if(perm_classes) {
			Tcl_DStringAppend(buf,  "  (* means class uses permission via a common permission):\n", -1);
		}
		else {
			Tcl_DStringAppend(buf, ":\n", -1);
		}
		for(i = 0; i < policy->num_perms; i++) {
			if(use_srchstr && (regexec(&reg, policy->perms[i], 0,NULL,0) != 0)) {
				continue;
			}
			append_perm_str(perm_cps, perm_classes, 1, i, buf, policy);
                        results_found = 1;
		}
                if (results_found == 0) {
                        Tcl_DStringAppend(buf, "Search returned no results.", -1);
                }
		Tcl_DStringAppend(buf, "\n", -1);
	}
	
	Tcl_DStringResult(interp, buf);
	return TCL_OK;
}

/* get information for a single class/perm/common perm 
 * argv[1]	name
 * argv[2]	which ("class", "perm", or "common_perm")
 */
static int Apol_GetSingleClassPermInfo(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int rt, idx;
	char tbuf[APOL_STR_SZ+64];
	Tcl_DString buffer, *buf = &buffer;
	
	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	

	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Class/Perm name is too large", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "Which option string is too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	Tcl_DStringInit(buf);
	if(strcmp(argv[2], "class") == 0) {
		idx = get_obj_class_idx(argv[1], policy);
		if(idx < 0) {
			Tcl_DStringFree(buf);
			sprintf(tbuf, "%s is an invalid class name", argv[1]);
			Tcl_AppendResult(interp, tbuf, (char *) NULL);
			return TCL_ERROR;
		}
		rt = append_class_str(1, 1, 0, 0, idx, buf, policy);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_AppendResult(interp, "error appending class info", (char *) NULL);
			return TCL_ERROR;
		}
	}
	else if(strcmp(argv[2], "common_perm") == 0) {
		idx = get_common_perm_idx(argv[1], policy);
		if(idx < 0) {
			Tcl_DStringFree(buf);
			sprintf(tbuf, "%s is an invalid common permission name", argv[1]);
			Tcl_AppendResult(interp, tbuf, (char *) NULL);
			return TCL_ERROR;
		}
		rt = append_common_perm_str(1, 0, 0, idx, buf, policy);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_AppendResult(interp, "error appending common perm info", (char *) NULL);
			return TCL_ERROR;
		}
	}
	else if(strcmp(argv[2], "perm") == 0) {
		idx = get_perm_idx(argv[1], policy);
		if(idx < 0) {
			Tcl_DStringFree(buf);
			sprintf(tbuf, "%s is an invalid permission name", argv[1]);
			Tcl_AppendResult(interp, tbuf, (char *) NULL);
			return TCL_ERROR;
		}
		rt = append_perm_str(1,1, 0, idx, buf, policy);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_AppendResult(interp, "error appending permmission info", (char *) NULL);
			return TCL_ERROR;
		}
	}
	else {
		Tcl_DStringFree(buf);
		sprintf(tbuf, "%s is an invalid which options", argv[2]);
		Tcl_AppendResult(interp, tbuf, (char *) NULL);
		return TCL_ERROR;
	}
	
	Tcl_DStringResult(interp, buf);
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
	if (sepol_role_datum_get_name(policy_handle, policydb,
				      role_datum, &role_name) < 0) {
		Tcl_SetResult(interp, "Could not get role name.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_role_datum_get_type_iter(policy_handle, policydb,
					   role_datum, &type_iter) < 0) {
		Tcl_SetResult(interp, "Could not get type iterator.", TCL_STATIC);
		goto cleanup;
	}
	if (sepol_role_datum_get_dominate_iter(policy_handle, policydb,
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
		    sepol_type_datum_get_name(policy_handle, policydb,
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
		    sepol_role_datum_get_name(policy_handle, policydb,
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
		if (sepol_policydb_get_role_by_name(policy_handle, policydb,
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
				Tcl_SetResult(interp, "Error setting query options.", TCL_STATIC);
				return TCL_ERROR;
			}
		}
		if (apol_get_role_by_query(policy_handle, policydb,
					   query, &v)) {
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
	for (i = 0; i < level->num_cats; i++) {
		cats_obj = Tcl_NewStringObj(level->cats[i], -1);
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
	if (sepol_user_datum_get_name(policy_handle, policydb,
				      user_datum, &user_name) < 0) {
		Tcl_SetResult(interp, "Could not get user name.", TCL_STATIC);
		goto cleanup;
	}
	user_elem[0] = Tcl_NewStringObj(user_name, -1);
	if (sepol_user_datum_get_role_iter(policy_handle, policydb,
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
		    sepol_role_datum_get_name(policy_handle, policydb,
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
		if (sepol_user_datum_get_dfltlevel(policy_handle, policydb, user_datum, &default_level) < 0) {
			Tcl_SetResult(interp, "Could not get default level.", TCL_STATIC);
			goto cleanup;
		}
		if (sepol_user_datum_get_range(policy_handle, policydb, user_datum, &range) < 0) {
			Tcl_SetResult(interp, "Could not get range.", TCL_STATIC);
			goto cleanup;
		}
		if ((apol_default =
		     apol_mls_level_create_from_sepol_mls_level(policy_handle, policydb,
								default_level)) == NULL ||
		    (apol_range =
		     apol_mls_range_create_from_sepol_mls_range(policy_handle, policydb,
								range)) == NULL) {
			Tcl_SetResult(interp, "Could not convert to MLS structs.", TCL_STATIC);
			goto cleanup;
		}
		    
		if (apol_level_to_tcl_obj(interp, apol_default, user_elem + 2) == TCL_ERROR) {
			goto cleanup;
		}
		if (apol_level_to_tcl_obj(interp, apol_range->low, range_elem + 0) == TCL_ERROR ||
		    apol_level_to_tcl_obj(interp, apol_range->high, range_elem + 1) == TCL_ERROR) {
			return TCL_ERROR;
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
	int i, j, num_roles, *roles;
	Tcl_Obj *result_obj, *user_list, *user_elem[4], *role_obj;
	Tcl_Obj *range_elem[2];
	sepol_user_datum_t *user;
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
		if (sepol_policydb_get_user_by_name(policy_handle, policydb,
						    argv[1], &user) < 0) {
			/* name is not within policy */
			return TCL_OK;
		}
		if (append_user_to_list(interp, user, result_obj) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	else {
	for(i = 0; i < policy->num_users; i++) {
		ap_user_t *user = policy->users + i;
		if (strcmp(argv[1], "") != 0 && strcmp(argv[1], user->name) != 0) {
			continue;
		}
		user_elem[0] = Tcl_NewStringObj(user->name, -1);
		if (get_user_roles(i, &num_roles, &roles, policy)) {
			Tcl_SetResult(interp, "Could not obtain user information.", TCL_STATIC);
			return TCL_ERROR;
		}
		user_elem[1] = Tcl_NewListObj(0, NULL);
		for (j = 0; j < num_roles; j++) {
			role_obj = Tcl_NewStringObj(policy->roles[roles[j]].name, -1);
			if (Tcl_ListObjAppendElement(interp, user_elem[1], role_obj) == TCL_ERROR) {
				free(roles);
				return TCL_ERROR;
			}
		}
		free(roles);

		if (is_mls_policy(policy)) {
			if (level_to_tcl_obj(interp, user->dflt_level, user_elem + 2) == TCL_ERROR) {
				return TCL_ERROR;
			}
			if (level_to_tcl_obj(interp, user->range->low, range_elem + 0) == TCL_ERROR ||
			    level_to_tcl_obj(interp, user->range->high, range_elem + 1) == TCL_ERROR) {
				return TCL_ERROR;
			}
			user_elem[3] = Tcl_NewListObj(2, range_elem);
		}
		else {
			user_elem[2] = Tcl_NewListObj(0, NULL);
			user_elem[3] = Tcl_NewListObj(0, NULL);
		}
		user_list = Tcl_NewListObj(4, user_elem);
		if (Tcl_ListObjAppendElement(interp, result_obj, user_list) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

/* args ordering:
 * argv[1]	bool name
 * argv[2]	new value
 */
static int Apol_Cond_Bool_SetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int rt, bool_idx;
	bool_t value;
		
	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Bool string is too large", (char *) NULL);
		return TCL_ERROR;
	}
	bool_idx = get_cond_bool_idx(argv[1], policy);
	if (bool_idx < 0) {
		Tcl_AppendResult(interp, "Error getting index value for ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}
	value = getbool(argv[2]);
	
	rt = set_cond_bool_val(bool_idx, value, policy);
	if (rt != 0) {
		Tcl_AppendResult(interp, "Error setting value for ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}
	
	rt = update_cond_expr_items(policy);
	if (rt != 0) {
		Tcl_AppendResult(interp, "Error updating conditional expressions.",  (char *)NULL);
		return TCL_ERROR;
	}	
	
	return TCL_OK;
}

/* args ordering:
 * argv[1]	bool name
 */
static int Apol_Cond_Bool_GetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	bool_t bool_val;
	int rt;
	char tbuf[64];	
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Bool string is too large", (char *) NULL);
		return TCL_ERROR;
	}
		
	rt = get_cond_bool_val(argv[1], &bool_val, policy);
	if (rt < 0) {
		Tcl_AppendResult(interp, "Error getting conditional boolean value for ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}
	
	sprintf(tbuf, "%d", bool_val);	
	Tcl_AppendElement(interp, tbuf);
	
	return TCL_OK;
}


/* Return a list of sensitivities tuples, ordered by dominance (low to
 * high) within the policy, or an empty list if no policy was loaded.
 *   elem 0 - sensitivity name
 *   elem 1 - list of associated aliases
 * If a parameter is given, return only that sensitivity tuple. If the
 * sensitivity does not exist then return an empty list.
 */
static int Apol_GetSens(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	int i, target_sens = -1;

	if (policy == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
        if (argc > 1) {
                target_sens = get_sensitivity_idx(argv[1], policy);
                if (target_sens == -1) {
                        /* passed sensitivity is not within the policy */
                        return TCL_OK;
                }
        }
	for (i = 0; i < policy->num_sensitivities; i++) {
                ap_mls_sens_t *sens = policy->sensitivities + policy->mls_dominance[i];
                name_item_t *name = sens->aliases;
                Tcl_Obj *sens_elem[2], *sens_list;
                if (argc > 1 && policy->mls_dominance[i] != target_sens) {
                        continue;
                }
                sens_elem[0] = Tcl_NewStringObj(sens->name, -1);
                sens_elem[1] = Tcl_NewListObj(0, NULL);
                while (name != NULL) {
                        Tcl_Obj *alias_obj = Tcl_NewStringObj(name->name, -1);
                        if (Tcl_ListObjAppendElement(interp, sens_elem[1], alias_obj) == TCL_ERROR) {
                                return TCL_ERROR;
                        }
                        name = name->next;
                }
                sens_list = Tcl_NewListObj(2, sens_elem);
                if (Tcl_ListObjAppendElement(interp, result_obj, sens_list) == TCL_ERROR) {
                        return TCL_ERROR;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}


/* Returns an ordered a 2-ple list of categories:
 *   elem 0 - category name
 *   elem 1 - list of associated aliases
 * If a parameter is given, return only that category tuple. If the
 * sensitivity does not exist or there is no policy loaded then throw
 * an error.
 */
static int Apol_GetCats(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	int i, target_cats = -1;

	if (policy == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
        if (argc > 1) {
                target_cats = get_category_idx(argv[1], policy);
                if (target_cats == -1) {
                        /* passed category is not within the policy */
                        return TCL_OK;
                }
        }
        for (i = 0; i < policy->num_categories; i++) {
                Tcl_Obj *cats_obj[2], *cats_list;
                ap_mls_cat_t *cats = policy->categories + i;
                name_item_t *name = cats->aliases;
                if (argc > 1 && i != target_cats) {
                        continue;
                }
                cats_obj[0] = Tcl_NewStringObj(cats->name, -1);
                cats_obj[1] = Tcl_NewListObj(0, NULL);
                while (name != NULL) {
                        Tcl_Obj *alias_obj = Tcl_NewStringObj(name->name, -1);
                        if (Tcl_ListObjAppendElement(interp, cats_obj[1], alias_obj) == TCL_ERROR) {
                                return TCL_ERROR;
                        }
                        name = name->next;
                }
                cats_list = Tcl_NewListObj(2, cats_obj);
                if (Tcl_ListObjAppendElement(interp, result_obj, cats_list) == TCL_ERROR) {
                        return TCL_ERROR;
                }
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}

/* Given a sensitivity, return a list of categories associated with
 * that level. */
static int Apol_SensCats(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int i, sens_index;

	if (argc != 2) {
		Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
		return TCL_ERROR;
	}
	if (policy == NULL) {
		return TCL_OK;
	}
        if ((sens_index = get_sensitivity_idx(argv[1], policy)) >= 0) {
                int *cats, num_cats;
                if (ap_mls_sens_get_level_cats(sens_index, &cats, &num_cats, policy) < 0) {
                        Tcl_SetResult(interp, "could not get categories list", TCL_STATIC);
                        return TCL_ERROR;
                }
                for (i = 0; i < num_cats; i++) {
                        Tcl_AppendElement(interp, policy->categories[cats[i]].name);
                }
                free(cats);
        }
        return TCL_OK;
}

/* Given a category name, return a list a sensitivities that contain
 * that category. */
static int Apol_CatsSens(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int i, cats_index;

	if (argc != 2) {
		Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
		return TCL_ERROR;
	}
	if (policy == NULL) {
		return TCL_OK;
	}
        if ((cats_index = get_category_idx(argv[1], policy)) >= 0) {
                for (i = 0; i < policy->num_levels; i++) {
                        ap_mls_level_t *level = policy->levels + i;
                        if (ap_mls_does_level_use_category(level, cats_index)) {
                                Tcl_AppendElement(interp, policy->sensitivities[level->sensitivity].name);
                        }
                }
        }
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
	Tcl_CreateCommand(interp, "apol_GetAttribTypesList", Apol_GetAttribTypesList, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetTypes", Apol_GetTypes, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetAttribs", Apol_GetAttribs, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetClassPermInfo", Apol_GetClassPermInfo, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetSingleClassPermInfo", Apol_GetSingleClassPermInfo, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetRoles", Apol_GetRoles, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetUsers", Apol_GetUsers, NULL, NULL);
        Tcl_CreateCommand(interp, "apol_Cond_Bool_SetBoolValue", Apol_Cond_Bool_SetBoolValue, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_Cond_Bool_GetBoolValue", Apol_Cond_Bool_GetBoolValue, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetSens", Apol_GetSens, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetCats", Apol_GetCats, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SensCats", Apol_SensCats, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_CatsSens", Apol_CatsSens, NULL, NULL);
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
