/**
 * @file apol_tcl_rules.c
 * Implementation for the apol interface to search rules within a policy.
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

#include <config.h>
#include <tcl.h>
#include <assert.h>

#include "old-policy-query.h"
#include "render.h"

#include "apol_tcl_other.h"
#include "apol_tcl_render.h"

#ifdef LIBSEFS
#include "../libsefs/fsdata.h"
#endif

extern char *rulenames[]; /* in render.c*/

/**
 * Takes a Tcl typeset list (e.g., "{foo 1}") and splits in into its
 * symbol name and indirect flag.
 *
 * @param interp Tcl interpreter object.
 * @param typeset Character string represting a Tcl typeset.
 * @param sym_name Reference to where to write the symbol name.  The
 * caller must free() this value afterwards.
 * @param indirect Reference to where to write indirect flag.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_tcl_string_to_typeset(Tcl_Interp *interp,
				      CONST char *typeset,
				      char **sym_name,
				      int *indirect)
{
	Tcl_Obj *typeset_obj = Tcl_NewStringObj(typeset, -1);
	Tcl_Obj *name_obj, *indirect_obj;
	char *s;
	*sym_name = NULL;
	*indirect = 0;
	if (Tcl_ListObjIndex(interp, typeset_obj, 0, &name_obj) == TCL_ERROR ||
	    Tcl_ListObjIndex(interp, typeset_obj, 1, &indirect_obj) == TCL_ERROR) {
		return -1;
	}
	if (Tcl_GetBooleanFromObj(interp, indirect_obj, indirect) == TCL_ERROR) {
		return -1;
	}
	s = Tcl_GetString(name_obj);
	if (s[0] == '\0') {
		*sym_name = NULL;
	}
	else {
		*sym_name = strdup(s);
		if (*sym_name == NULL) {
			Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
			return -1;
		}
	}
	return 0;
}

/**
 * Takes a qpol_avrule_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *    { rule_type source_type_set target_type_set object_class perm_set
 *      line_number }
 * </code>
 * The type sets and perm sets are Tcl lists.
 */
static int append_avrule_to_list(Tcl_Interp *interp,
				 qpol_avrule_t *avrule,
				 Tcl_Obj *result_list)
{
	uint32_t rule_type;
	const char *rule_string;
	qpol_type_t *source, *target;
	qpol_class_t *obj_class;
	qpol_iterator_t *perm_iter = NULL;
	char *source_name, *target_name, *obj_class_name;
	Tcl_Obj *avrule_elem[6], *avrule_list;
	int retval = TCL_ERROR;

	if (qpol_avrule_get_rule_type(policydb->qh, policydb->p, avrule, &rule_type) < 0 ||
	    qpol_avrule_get_source_type(policydb->qh, policydb->p, avrule, &source) < 0 ||
	    qpol_avrule_get_target_type(policydb->qh, policydb->p, avrule, &target) < 0 ||
	    qpol_avrule_get_object_class(policydb->qh, policydb->p, avrule, &obj_class) < 0 ||
	    qpol_avrule_get_perm_iter(policydb->qh, policydb->p, avrule, &perm_iter) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		goto cleanup;
	}
	if (qpol_type_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0 ||
	    qpol_class_get_name(policydb->qh, policydb->p, obj_class, &obj_class_name) < 0) {
		goto cleanup;
	}
	avrule_elem[0] = Tcl_NewStringObj(rule_string, -1);
	avrule_elem[1] = Tcl_NewStringObj(source_name, -1);
	avrule_elem[2] = Tcl_NewStringObj(target_name, -1);
	avrule_elem[3] = Tcl_NewStringObj(obj_class_name, -1);
	avrule_elem[4] = Tcl_NewListObj(0, NULL);
	for ( ; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		char *perm_name;
		Tcl_Obj *perm_obj;
		if (qpol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
			goto cleanup;
		}
		perm_obj = Tcl_NewStringObj(perm_name, -1);
		if (Tcl_ListObjAppendElement(interp, avrule_elem[4], perm_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	avrule_elem[5] = Tcl_NewStringObj("", -1);   /* FIX ME! */
	avrule_list = Tcl_NewListObj(6, avrule_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, avrule_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

/**
 * Takes a qpol_terule_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *    { rule_type source_type_set target_type_set object_class default_type
 *      line_number }
 * </code>
 * The type sets are Tcl lists.
 */
static int append_terule_to_list(Tcl_Interp *interp,
				 qpol_terule_t *terule,
				 Tcl_Obj *result_list)
{
	uint32_t rule_type;
	const char *rule_string;
	qpol_type_t *source, *target, *default_type;
	qpol_class_t *obj_class;
	char *source_name, *target_name, *obj_class_name, *default_name;
	Tcl_Obj *terule_elem[6], *terule_list;
	int retval = TCL_ERROR;

	if (qpol_terule_get_rule_type(policydb->qh, policydb->p, terule, &rule_type) < 0 ||
	    qpol_terule_get_source_type(policydb->qh, policydb->p, terule, &source) < 0 ||
	    qpol_terule_get_target_type(policydb->qh, policydb->p, terule, &target) < 0 ||
	    qpol_terule_get_object_class(policydb->qh, policydb->p, terule, &obj_class) < 0 ||
	    qpol_terule_get_default_type(policydb->qh, policydb->p, terule, &default_type) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		goto cleanup;
	}
	if (qpol_type_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0 ||
	    qpol_class_get_name(policydb->qh, policydb->p, obj_class, &obj_class_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, default_type, &default_name) < 0) {
		goto cleanup;
	}
	terule_elem[0] = Tcl_NewStringObj(rule_string, -1);
	terule_elem[1] = Tcl_NewStringObj(source_name, -1);
	terule_elem[2] = Tcl_NewStringObj(target_name, -1);
	terule_elem[3] = Tcl_NewStringObj(obj_class_name, -1);
	terule_elem[4] = Tcl_NewStringObj(default_name, -1);
	terule_elem[5] = Tcl_NewStringObj("", -1);   /* FIX ME! */
	terule_list = Tcl_NewListObj(6, terule_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, terule_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return an unsorted list of TE rules (av rules and type rules)
 * tuples within the policy.  Each tuple consists of:
 * <ul>
 *   <li>rule type ("allow", "type_transition", etc.)
 *   <li>source type set
 *   <li>target type set
 *   <li>object class
 *   <li>for av rules: permission set; for type rules: default type
 *   <li>line number, or -1 unknown
 * </ul>
 *
 * @param argv This function takes seven parameters:
 * <ol>
 *   <li>rule selections
 *   <li>other options
 *   <li>source type options
 *   <li>target type options
 *   <li>default type options (ignored when searching av rules)
 *   <li>classes options
 *   <li>permissions options  (ignored when searching type rules)
 * </ol>
 *
 * For rule selections list, this is a list of which rules to search.
 * Valid rule strings are:
 * <ul>
 *   <li>allow
 *   <li>neverallow
 *   <li>auditallow
 *   <li>dontaudit
 *   <li>type_transition
 *   <li>type_member
 *   <li>type_change
 * </ul>
 *
 * For other options, this is a list of strings that affect searching.
 * Valid strings are:
 * <ul>
 *   <li>only_enabled - search unconditional and those in enabled conditionals
 *   <li>source_any - treat source symbol as criteria for target and default
 *   <li>regex - treat all symbols as regular expression
 * </ul>
 *
 * For source/target/default types, these are each a list of two parameters:
 * <ol>
 *   <li>type/attribute symbol name (or empty string to ignore)
 *   <li>perform indirect matching with this symbol
 * </ol>
 *
 * For classes, the returned rule's class must be within this list.
 * For permissions, the rule must have at least one permission within
 * this list.  Pass an empty list to skip this filter.
 */
static int Apol_SearchTERules(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_avrule_t *avrule;
	qpol_terule_t *terule;
	unsigned int avrules = 0, terules = 0;
	CONST char **rule_strings = NULL, **other_opt_strings = NULL,
		**class_strings = NULL, **perm_strings = NULL;
	char *sym_name = NULL;
	int num_opts, indirect;
	apol_avrule_query_t *avquery = NULL;
	apol_terule_query_t *tequery = NULL;
	apol_vector_t *av = NULL, *te = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 8) {
		ERR(policydb, "Need a rule selection, other options, source type, target type, default type, classes, and permissions");
		goto cleanup;
	}

	if ((avquery = apol_avrule_query_create()) == NULL ||
	    (tequery = apol_terule_query_create()) == NULL) {
		ERR(policydb, "Out of memory!");
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[1], &num_opts, &rule_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = rule_strings[num_opts];
		if (strcmp(s, "allow") == 0) {
			avrules |= QPOL_RULE_ALLOW;
		}
		else if (strcmp(s, "neverallow") == 0) {
			avrules |= QPOL_RULE_NEVERALLOW;
		}
		else if (strcmp(s, "auditallow") == 0) {
			avrules |= QPOL_RULE_AUDITALLOW;
		}
		else if (strcmp(s, "dontaudit") == 0) {
			avrules |= QPOL_RULE_DONTAUDIT;
		}
		else if (strcmp(s, "type_transition") == 0) {
			terules |= QPOL_RULE_TYPE_TRANS;
		}
		else if (strcmp(s, "type_member") == 0) {
			terules |= QPOL_RULE_TYPE_MEMBER;
		}
		else if (strcmp(s, "type_change") == 0) {
			terules |= QPOL_RULE_TYPE_CHANGE;
		}
		else {
			ERR(policydb, "Invalid rule selection %s.", s);
			goto cleanup;
		}
	}
	if (apol_avrule_query_set_rules(policydb, avquery, avrules) < 0 ||
	    apol_terule_query_set_rules(policydb, tequery, terules) < 0) {
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[2], &num_opts, &other_opt_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = other_opt_strings[num_opts];
		if (strcmp(s, "only_enabled") == 0) {
			apol_avrule_query_set_enabled(policydb, avquery, 1);
			apol_terule_query_set_enabled(policydb, tequery, 1);
		}
		else if (strcmp(s, "source_any") == 0) {
			apol_avrule_query_set_source_any(policydb, avquery, 1);
			apol_terule_query_set_source_any(policydb, tequery, 1);
		}
		else if (strcmp(s, "regex") == 0) {
			apol_avrule_query_set_regex(policydb, avquery, 1);
			apol_terule_query_set_regex(policydb, tequery, 1);
		}
		else {
			ERR(policydb, "Invalid option %s.", s);
			goto cleanup;
		}
	}

	if (apol_tcl_string_to_typeset(interp, argv[3], &sym_name, &indirect) < 0 ||
	    apol_avrule_query_set_source(policydb, avquery, sym_name, indirect) < 0 ||
	    apol_terule_query_set_source(policydb, tequery, sym_name, indirect) < 0) {
		goto cleanup;
	}

	free(sym_name);
	sym_name = NULL;
	if (apol_tcl_string_to_typeset(interp, argv[4], &sym_name, &indirect) < 0 ||
	    apol_avrule_query_set_target(policydb, avquery, sym_name, indirect) < 0 ||
	    apol_terule_query_set_target(policydb, tequery, sym_name, indirect) < 0) {
		goto cleanup;
	}

	free(sym_name);
	sym_name = NULL;
	if (apol_tcl_string_to_typeset(interp, argv[5], &sym_name, &indirect) < 0 ||
	    apol_terule_query_set_default(policydb, tequery, sym_name) < 0) {
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[6], &num_opts, &class_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = class_strings[num_opts];
		if (apol_avrule_query_append_class(policydb, avquery, s) < 0 ||
		    apol_terule_query_append_class(policydb, tequery, s) < 0) {
			goto cleanup;
		}
	}

	if (Tcl_SplitList(interp, argv[7], &num_opts, &perm_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = perm_strings[num_opts];
		if (apol_avrule_query_append_perm(policydb, avquery, s) < 0) {
			goto cleanup;
		}
	}

	if (avrules != 0) {
		if (apol_get_avrule_by_query(policydb, avquery, &av) < 0) {
		    goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(av); i++) {
			avrule = (qpol_avrule_t *) apol_vector_get_element(av, i);
			if (append_avrule_to_list(interp, avrule, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}

	if (terules != 0) {
		if (apol_get_terule_by_query(policydb, tequery, &te) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(te); i++) {
			terule = (qpol_terule_t *) apol_vector_get_element(te, i);
			if (append_terule_to_list(interp, terule, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	if (rule_strings != NULL) {
		Tcl_Free((char *) rule_strings);
	}
	if (other_opt_strings != NULL) {
		Tcl_Free((char *) other_opt_strings);
	}
	if (class_strings != NULL) {
		Tcl_Free((char *) class_strings);
	}
	if (perm_strings != NULL) {
		Tcl_Free((char *) perm_strings);
	}
	free(sym_name);
	apol_avrule_query_destroy(&avquery);
	apol_terule_query_destroy(&tequery);
	apol_vector_destroy(&av, NULL);
	apol_vector_destroy(&te, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

static void apol_cond_rules_append_expr(cond_expr_t *exp, policy_t *policy, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ];
	cond_expr_t *cur;
	Tcl_DString buffer, *buf = &buffer;
	
	Tcl_DStringInit(buf);
			
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			snprintf(tbuf, sizeof(tbuf)-1, "%s ", policy->cond_bools[cur->bool].name); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_NOT:
			snprintf(tbuf, sizeof(tbuf)-1, "! "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_OR:
			snprintf(tbuf, sizeof(tbuf)-1, "|| "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_AND:
			snprintf(tbuf, sizeof(tbuf)-1, "&& "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_XOR:
			snprintf(tbuf, sizeof(tbuf)-1, "^ "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_EQ:
			snprintf(tbuf, sizeof(tbuf)-1, "== "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_NEQ:
			snprintf(tbuf, sizeof(tbuf)-1, "!= ");
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		default:
			break;
		}
	}
	/* Append the conditional expression to our tcl list */
	Tcl_AppendElement(interp, buf->string);
	Tcl_DStringFree(buf);
}

static void apol_cond_rules_append_cond_list(cond_rule_list_t *list, bool_t include_allow, bool_t include_audit, bool_t include_tt, 
				     	     policy_t *policy, Tcl_Interp *interp)
{
	int i;
	char tbuf[BUF_SZ], *rule = NULL;
	
	if (!list) {
		/* Indicate that there are no rules, since the list is empty. */
		Tcl_AppendElement(interp, "0");
		Tcl_AppendElement(interp, "0");
		Tcl_AppendElement(interp, "0");
		return;
	}
	assert(policy != NULL);
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_av_access);
	Tcl_AppendElement(interp, tbuf);
	if (include_allow) {
		for (i = 0; i < list->num_av_access; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->av_access[list->av_access[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_av_rule(FALSE, list->av_access[i], FALSE, policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->av_access[list->av_access[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_av_audit);
	Tcl_AppendElement(interp, tbuf);
	if (include_audit) {
		for (i = 0; i < list->num_av_audit; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->av_audit[list->av_audit[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_av_rule(FALSE, list->av_audit[i], TRUE, policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->av_audit[list->av_audit[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_te_trans);
	Tcl_AppendElement(interp, tbuf);
	if (include_tt) {
		for (i = 0; i < list->num_te_trans; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->te_trans[list->te_trans[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_tt_rule(FALSE, list->te_trans[i], policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->te_trans[list->te_trans[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
}

/* 
 * argv[1] boolean name
 * argv[2] use reg expression
 * argv[3] include allow rules
 * argv[4] include audit rules
 * argv[5] include type transition rules
 * argv[6] use boolean for search
 */
static int Apol_SearchConditionalRules(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	char *error_msg = NULL;
	bool_t regex, *exprs_b, use_bool;
	bool_t include_allow, include_audit, include_tt;
	int i;
	
	if (argc != 7) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	
	if (!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "The provided user string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	
	regex = getbool(argv[2]);
	include_allow = getbool(argv[3]);
	include_audit = getbool(argv[4]);
	include_tt = getbool(argv[5]);
	use_bool = getbool(argv[6]);
	if (use_bool && str_is_only_white_space(argv[1])) {
		Tcl_AppendResult(interp, "You umust provide a boolean!", (char *) NULL);
		return TCL_ERROR;
	}
	/* If regex is turned OFF, then validate that the boolean exists. */
	if (use_bool && !regex && get_cond_bool_idx(argv[1], policy) < 0) {
		Tcl_AppendResult(interp, "Invalid boolean name provided. You may need to turn on the regular expression option.", (char *) NULL);
		return TCL_ERROR;
	}
	exprs_b = (bool_t*)malloc(sizeof(bool_t) * policy->num_cond_exprs);
	if (!exprs_b) {
		Tcl_AppendResult(interp, "Memory error\n", (char *) NULL);
		return TCL_ERROR;
	}
	memset(exprs_b, FALSE, sizeof(bool_t) * policy->num_cond_exprs);
	
	if (search_conditional_expressions(use_bool, (char *) argv[1], regex, exprs_b, &error_msg, policy) != 0) {
		Tcl_AppendResult(interp, "Error searching conditional expressions: ", error_msg, (char *) NULL);
		free(error_msg);
		return TCL_ERROR;
	}
	for (i = 0; i < policy->num_cond_exprs; i++) {
		if (exprs_b[i]) {
			apol_cond_rules_append_expr(policy->cond_exprs[i].expr, policy, interp);
		
			apol_cond_rules_append_cond_list(policy->cond_exprs[i].true_list, 
							include_allow, include_audit, include_tt, 
							policy, interp);
			
			apol_cond_rules_append_cond_list(policy->cond_exprs[i].false_list, 
							include_allow, include_audit, include_tt, 
							policy, interp);
		}
	}
	free(exprs_b);
										
	return TCL_OK;
}

static int append_role_allow_rule(role_allow_t *rule, policy_t *policy, Tcl_DString *buf)
{
	ta_item_t *tptr;	
	int multiple = 0;
	if(buf == NULL) {
		return -1;
	}
		
	Tcl_DStringAppend(buf, rulenames[RULE_ROLE_ALLOW], -1);

	/* source roles */
	if(rule->flags & AVFLAG_SRC_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->src_roles != NULL && rule->src_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		Tcl_DStringAppend(buf, "*", -1);
			
	for(tptr = rule->src_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	/* target roles */
	if(rule->flags & AVFLAG_TGT_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->tgt_roles != NULL && rule->tgt_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		Tcl_DStringAppend(buf, "*", -1);

	
	for(tptr = rule->tgt_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	
	Tcl_DStringAppend(buf, ";\n", -1);
		
	return 0;
}

static int append_role_trans_rule(rt_item_t *rule, policy_t *policy, Tcl_DString *buf)
{
	ta_item_t *tptr;	
	int multiple = 0;
	if(buf == NULL) {
		return -1;
	}
		
	Tcl_DStringAppend(buf, rulenames[RULE_ROLE_TRANS], -1);
	
	/* source roles */
	if(rule->flags & AVFLAG_SRC_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->src_roles != NULL && rule->src_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		Tcl_DStringAppend(buf, "*", -1);
			
	for(tptr = rule->src_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	/* target types/attributes */
	if(rule->flags & AVFLAG_TGT_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->tgt_types != NULL && rule->tgt_types->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		Tcl_DStringAppend(buf, "*", -1);

	for(tptr = rule->tgt_types; tptr != NULL; tptr = tptr->next) {
		if ((tptr->type & IDX_SUBTRACT)) {
			Tcl_DStringAppend(buf, "-", -1);
		}
		if ((tptr->type & IDX_TYPE)) {
			Tcl_DStringAppend(buf, " ", -1);
			if(ap_tcl_append_type_str(0, 0, 0, tptr->idx, policy, buf) != 0)
				return -1;
		}
		else if ((tptr->type & IDX_ATTRIB)) {
			Tcl_DStringAppend(buf, " ", -1);
			if(ap_tcl_append_attrib_str(0, 0, 0, 0, 0, tptr->idx, policy, buf) != 0)
				return -1;
		}			
		else {
			fprintf(stderr, "Invalid index type: %d\n", tptr->type);
			return -1;
		}
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	
	/* default role */
	Tcl_DStringAppend(buf, " ", -1);
	assert(rule->trans_role.type == IDX_ROLE);
	Tcl_DStringAppend(buf, policy->roles[rule->trans_role.idx].name, -1);
	
	Tcl_DStringAppend(buf, ";\n", -1);
		
	return 0;
}

/* Search role rules */
/* arg ordering for argv[x]:
 * 1	allow (bool)		get allow rules
 * 2	trans (bool)		get role_transition rules
 * 3	use_src (bool)		whether to search by source role
 * 4	source			the source role
 * 5	which			whether source used for source or any (if any, others ignored)
 *					possible values: "source", "any"
 * 6	use_tgt (bool)		whether to search by target role (allow) or type (trans)
 * 7	target			the target role/type
 * 8	tgt_is_role (bool) 	whther target is role (allow only) or type (trans only)
 * 9	use_default (bool) 	search using default role (trans only)
 * 10	default			the default role
 */
static int Apol_GetRoleRules(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int i, rt, src_idx = -1, tgt_idx = -1, tgt_type = IDX_ROLE, dflt_idx = -1;
	Tcl_DString buffer, *buf = &buffer;
	char tmpbuf[APOL_STR_SZ+64];
	bool_t allow, trans, any = FALSE, use_src, use_tgt, tgt_is_role, use_dflt;
	rbac_bool_t src_b, tgt_b, dflt_b;
	
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(argc != 11) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}

	allow = getbool(argv[1]);
	trans = getbool(argv[2]);
	use_src = getbool(argv[3]);
	tgt_is_role = getbool(argv[8]);

	if(use_src) {
		if(strcmp(argv[5], "source") == 0)
			any = FALSE;
		else if(strcmp(argv[5], "any") == 0)
			any = TRUE;
		else {
			Tcl_AppendResult(interp, "Invalid which option for source ", (char *) NULL);
			return TCL_ERROR;			
		}
		if(!is_valid_str_sz(argv[4])) {
			Tcl_AppendResult(interp, "Source string is too large", (char *) NULL);
			return TCL_ERROR;
		}		
		src_idx = get_role_idx(argv[4], policy);
		if(src_idx < 0) {
			sprintf(tmpbuf, "Invalid source role name (%s)", argv[4]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			return TCL_ERROR;			
		}
		
	}
	use_tgt = getbool(argv[6]) && !any;
	if(use_tgt) {
		if(allow && trans) {
			Tcl_AppendResult(interp, "Invalid option, target option may only be used if EITHER allow or role_trans is selected, but not both", (char *) NULL);
			return TCL_ERROR;
		}
		if(tgt_is_role && (!allow || trans)) {
			Tcl_AppendResult(interp, "Invalid option, target option may be a ROLE when allow, and only allow, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(!tgt_is_role && (allow || !trans)) {
			Tcl_AppendResult(interp, "Invalid option, target option may be a TYPE when role_trans, and only role_trans, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(tgt_is_role) {
			if(!is_valid_str_sz(argv[7])) {
				Tcl_AppendResult(interp, "Target string is too large", (char *) NULL);
				return TCL_ERROR;
			}
			tgt_idx = get_role_idx(argv[7], policy);
			if(tgt_idx < 0) {
				sprintf(tmpbuf, "Invalid target role name (%s)", argv[7]);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;			
			}
			tgt_type = IDX_ROLE;
		}
		else {
			if(!is_valid_str_sz(argv[7])) {
				Tcl_AppendResult(interp, "Target string is too large", (char *) NULL);
				return TCL_ERROR;
			}
			tgt_idx = get_type_or_attrib_idx(argv[7], &tgt_type, policy);
			if(tgt_idx < 0) {
				sprintf(tmpbuf, "Invalid target type or attribute (%s)", argv[7]);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;			
			}
		}
		
	}
	use_dflt = getbool(argv[9]) && !any;
	if(use_dflt) {
		if(allow || !trans) {
			Tcl_AppendResult(interp, "Invalid option, default may use when role_trans, and only role_trans, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(!is_valid_str_sz(argv[10])) {
			Tcl_AppendResult(interp, "Default string is too large", (char *) NULL);
			return TCL_ERROR;
		}
		dflt_idx = get_role_idx(argv[10], policy);
		if(dflt_idx < 0) {
			sprintf(tmpbuf, "Invalid default role name (%s)", argv[10]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			return TCL_ERROR;			
		}
	}
	
	Tcl_DStringInit(buf);
	
	if(init_rbac_bool(&src_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing src rules bool", (char *) NULL);
		return TCL_ERROR;
	}
	if(init_rbac_bool(&tgt_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing tgt rules bool", (char *) NULL);
		free_rbac_bool(&src_b);	
		return TCL_ERROR;
	}
	if(init_rbac_bool(&dflt_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing default rules bool", (char *) NULL);
		free_rbac_bool(&src_b);	
		free_rbac_bool(&tgt_b);	
		return TCL_ERROR;
	}
	
	if(use_src) {
		if(match_rbac_rules(src_idx, IDX_ROLE, SRC_LIST, FALSE, tgt_is_role, &src_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching source", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
	}
	else {
		all_true_rbac_bool(&src_b, policy);
	}
	if(use_src && any) {
		if(match_rbac_rules(src_idx, IDX_ROLE, TGT_LIST, FALSE, TRUE, &tgt_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching target", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
		if(match_rbac_rules(src_idx, IDX_ROLE, DEFAULT_LIST, FALSE, TRUE, &dflt_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching default", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
	}
	else {
		
		if(use_tgt && tgt_is_role) {
			if(match_rbac_rules(tgt_idx, IDX_ROLE, TGT_LIST, FALSE, TRUE, &tgt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching target", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}
		}
		else if(use_tgt && !tgt_is_role) {
			if(match_rbac_rules(tgt_idx, tgt_type, TGT_LIST, FALSE, FALSE, &tgt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching target", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}			
		}
		else {
			all_true_rbac_bool(&tgt_b, policy);
		}
		if(use_dflt) {
			if(match_rbac_rules(dflt_idx, IDX_ROLE, DEFAULT_LIST, FALSE, FALSE, &dflt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching default", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}
		}
		else {
			all_true_rbac_bool(&dflt_b, policy);
		}
	}
	
	if(allow) {
		for(i = 0; i < policy->num_role_allow; i++) {
			if((!any && (src_b.allow[i] && tgt_b.allow[i])) ||
			   (any && (src_b.allow[i] || tgt_b.allow[i]))) {
				rt = append_role_allow_rule(&(policy->role_allow[i]), policy, buf);
				if(rt != 0) {
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending role allow rule", (char *) NULL);
					free_rbac_bool(&src_b);	
					free_rbac_bool(&tgt_b);	
					free_rbac_bool(&dflt_b);
					return TCL_ERROR;
				}
			}
		}
	}
	if(trans) {
		for(i =0; i < policy->num_role_trans; i++) {
			if((!any && (src_b.trans[i] && tgt_b.trans[i] && dflt_b.trans[i])) ||
			   (any && (src_b.trans[i] || tgt_b.trans[i] || dflt_b.trans[i]))) {
				rt = append_role_trans_rule(&(policy->role_trans[i]), policy, buf);
				if(rt != 0) {
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending role_transition rule", (char *) NULL);
					free_rbac_bool(&src_b);	
					free_rbac_bool(&tgt_b);	
					free_rbac_bool(&dflt_b);
					return TCL_ERROR;
				}
			}
		}
	}
	
	Tcl_DStringResult(interp, buf);
	free_rbac_bool(&src_b);	
	free_rbac_bool(&tgt_b);	
	free_rbac_bool(&dflt_b);				
	return TCL_OK;	
}


/* Perform a range transition search.  Expected arguments are:
 *
 *  argv[1] - list of source types  (string)
 *  argv[2] - list of target types  (string)
 *  argv[3] - low level             (2-ple of sensitivity + list of categories)
 *  argv[4] - high level            (2-ple of sensitivity + list of categories)
 *  argv[5] - search type           ("", "exact", "subset", or "superset")
 *
 * If search type is "" then ignore argv[3] and argv[4].
 * Returns a list of range_transition indices.
 */
static int Apol_SearchRangeTransRules(ClientData clientData, Tcl_Interp *interp, int argc, const char *argv[])
{
        int *types[2] = {NULL, NULL}, num_types[2] = {0, 0};
        ap_mls_range_t range;
        unsigned search_type = 0;
        int *found_rules = NULL;
        int num_rules;
        int retval = TCL_ERROR;

        ap_mls_level_t low = {0, NULL, 0}, high = {0, NULL, 0};
        int i, j;
        Tcl_Obj *result_list_obj;

        if (argc != 6) {
		Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
		return TCL_ERROR;
	}

        for (i = 0; i < 2; i++) {
                Tcl_Obj *types_list_obj = Tcl_NewStringObj(argv[i + 1], -1);
                Tcl_Obj *types_obj;
                char *type_string;
                int num_list_objs, type_value;
                if (Tcl_ListObjLength(interp, types_list_obj, &num_list_objs) == TCL_ERROR) {
                        goto cleanup;
                }
                for (j = 0; j < num_list_objs; j++) {
                        if (Tcl_ListObjIndex(interp, types_list_obj, j, &types_obj) == TCL_ERROR) {
                                goto cleanup;
                        }
                        assert(types_obj != NULL);
                        type_string = Tcl_GetString(types_obj);
                        if ((type_value = get_type_idx(type_string, policy)) < 0) {
                                Tcl_AppendResult(interp, "Unknown type ", type_string, NULL);
                                goto cleanup;
                        }
                        if (add_i_to_a(type_value, num_types + i, types + i)) {
                                Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
                                goto cleanup;
                        }
                }
        }
        if (num_types[0] > 0) {
                search_type |= AP_MLS_RTS_SRC_TYPE;
        }
        if (num_types[1] > 0) {
                search_type |= AP_MLS_RTS_TGT_TYPE;
        }
        
        if (argv[5][0] != '\0') {
                /* in a search type was given, then try to parse the range */
            /* FIX ME: not done yet
               
                if (strcmp(argv[5], "exact") == 0) {
                        search_type |= AP_MLS_RTS_RNG_EXACT;
                }
                else if (strcmp(argv[5], "subset") == 0) {
                        search_type |= AP_MLS_RTS_RNG_SUB;
                }
                else if (strcmp(argv[5], "superset") == 0) {
                        search_type |= AP_MLS_RTS_RNG_SUPER;
                }
                else {
                        Tcl_SetResult(interp, "Illegal search type given.", TCL_STATIC);
                        goto cleanup;
                }

                if (ap_tcl_level_string_to_level(interp, argv[3], &low) != 0) {
                        goto cleanup;
                }
                if (ap_tcl_level_string_to_level(interp, argv[4], &high) != 0) {
                        goto cleanup;
                }
            */
        }
        range.low = &low;
        range.high = &high;

        num_rules = ap_mls_range_transition_search(types[0], num_types[0], 
                                                   IDX_TYPE, types[1], 
                                                   num_types[1], IDX_TYPE, 
                                                   &range, search_type,
                                                   &found_rules, policy);
        if (num_rules < 0) {
                Tcl_SetResult(interp, "Error while executing range transition search.", TCL_STATIC);
		char buf[1024];
		sprintf(buf, "%d", num_rules);
		Tcl_AppendResult(interp, buf, NULL);
                goto cleanup;
        }
        
        result_list_obj = Tcl_NewListObj(0, NULL);
        for (i = 0; i < num_rules; i++) {
                Tcl_Obj *rule_obj = Tcl_NewIntObj(found_rules[i]);
                if (Tcl_ListObjAppendElement(interp, result_list_obj, rule_obj) == TCL_ERROR) {
                        goto cleanup;
                }
        }
        Tcl_SetObjResult(interp, result_list_obj);
        retval = TCL_OK;

 cleanup:
        free(types[0]);
        free(types[1]);
        ap_mls_level_free(&low);
        ap_mls_level_free(&high);
        free(found_rules);
        return retval;
}


int apol_tcl_rules_init(Tcl_Interp *interp) {
	Tcl_CreateCommand(interp, "apol_SearchTERules", Apol_SearchTERules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SearchConditionalRules", Apol_SearchConditionalRules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetRoleRules", Apol_GetRoleRules, NULL, NULL);
        Tcl_CreateCommand(interp, "apol_SearchRangeTransRules", Apol_SearchRangeTransRules, NULL, NULL);
        return TCL_OK;
}
