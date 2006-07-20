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

#include <tcl.h>

#include "apol_tcl_other.h"
#include "apol_tcl_render.h"

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
	if (*typeset == '\0') {
		return 0;
	}
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
 *      line_number cond_info }
 * </code>
 * The type sets and perm sets are Tcl lists.  If cond_info is an
 * empty list then this rule is unconditional.  Otherwise cond_info is
 * a 2-uple list, where the first element is either "enabled" or
 * "disabled", and the second element is the line number for its
 * conditional expression.
 */
static int append_avrule_to_list(Tcl_Interp *interp,
				 qpol_avrule_t *avrule,
				 Tcl_Obj *result_list)
{
	Tcl_Obj *avrule_list;
	if (apol_avrule_to_tcl_obj(interp, avrule, &avrule_list) == TCL_ERROR ||
	    Tcl_ListObjAppendElement(interp, result_list, avrule_list) == TCL_ERROR) {
		return TCL_ERROR;
	}
	return TCL_OK;
}

/**
 * Takes a qpol_terule_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *    { rule_type source_type_set target_type_set object_class default_type
 *      line_number cond_info }
 * </code>
 * The type sets and perm sets are Tcl lists.  If cond_info is an
 * empty list then this rule is unconditional.  Otherwise cond_info is
 * a 2-uple list, where the first element is either "enabled" or
 * "disabled", and the second element is the line number for its
 * conditional expression.
 */
static int append_terule_to_list(Tcl_Interp *interp,
				 qpol_terule_t *terule,
				 Tcl_Obj *result_list)
{
	uint32_t rule_type, is_enabled;
	const char *rule_string;
	qpol_type_t *source, *target, *default_type;
	qpol_class_t *obj_class;
	char *source_name, *target_name, *obj_class_name, *default_name;
	qpol_cond_t *cond;
	Tcl_Obj *terule_elem[7], *terule_list, *cond_elem[2];
	int retval = TCL_ERROR;

	if (qpol_terule_get_rule_type(policydb->qh, policydb->p, terule, &rule_type) < 0 ||
	    qpol_terule_get_source_type(policydb->qh, policydb->p, terule, &source) < 0 ||
	    qpol_terule_get_target_type(policydb->qh, policydb->p, terule, &target) < 0 ||
	    qpol_terule_get_object_class(policydb->qh, policydb->p, terule, &obj_class) < 0 ||
	    qpol_terule_get_default_type(policydb->qh, policydb->p, terule, &default_type) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		ERR(policydb, "Invalid terule type %d.", rule_type);
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
	if (qpol_terule_get_cond(policydb->qh, policydb->p, terule, &cond) < 0 ||
	    qpol_terule_get_is_enabled(policydb->qh, policydb->p, terule, &is_enabled) < 0) {
		goto cleanup;
	}
	if (cond == NULL) {
		terule_elem[6] = Tcl_NewListObj(0, NULL);
	}
	else {
		cond_elem[0] = Tcl_NewStringObj(is_enabled ? "enabled" : "disabled", -1);
		cond_elem[1] = Tcl_NewStringObj("", -1);  /* FIX ME! */
		terule_elem[6] = Tcl_NewListObj(2, cond_elem);
	}
	terule_list = Tcl_NewListObj(7, terule_elem);
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
 *   <li>conditional info (empty list, or 2-uple list of
 *   enabled/disabled + conditional's line number)
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
 * For other options, this is a list of strings that affect searching.
 * Valid strings are:
 * <ul>
 *   <li>only_enabled - search unconditional and those in enabled conditionals
 *   <li>source_any - treat source symbol as criteria for target and default
 *   <li>regex - treat all symbols as regular expression
 * </ul>
 * For source/target/default types, these are each a list of two parameters:
 * <ol>
 *   <li>type/attribute symbol name (or empty string to ignore)
 *   <li>perform indirect matching with this symbol
 * </ol>
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
	if (policydb == NULL) {
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

/**
 * Converts an iterator of qpol_cond_expr_node_t to a Tcl representation:
 * <code>
 *   { bool_or_operator0 bool_or_operator1 ... }
 * </code>
 *
 * Note that the iterator will have been incremented to its end.
 *
 * @param interp Tcl interpreter object.
 * @param level Level to convert.
 * @param obj Destination to create Tcl object representing expression.
 *
 * @return 0 if conditional expression was converted, <0 on error.
 */
static int cond_expr_iter_to_tcl_obj(Tcl_Interp *interp,
				     qpol_iterator_t *iter,
				     Tcl_Obj **obj)
{
	qpol_cond_expr_node_t *expr;
	qpol_bool_t *cond_bool;
	char *bool_name;
	uint32_t expr_type;
	const char *expr_str;
	Tcl_Obj *expr_elem;
	int retval = TCL_ERROR;

	*obj = Tcl_NewListObj(0, NULL);
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &expr) < 0 ||
		    qpol_cond_expr_node_get_expr_type(policydb->qh, policydb->p,
						      expr, &expr_type) < 0) {
			goto cleanup;
		}
		if (expr_type == QPOL_COND_EXPR_BOOL) {
			if (qpol_cond_expr_node_get_bool(policydb->qh, policydb->p,
							 expr, &cond_bool) < 0 ||
			    qpol_bool_get_name(policydb->qh, policydb->p,
					       cond_bool, &bool_name) < 0) {
				goto cleanup;
			}
			expr_elem = Tcl_NewStringObj(bool_name, -1);
		}
		else {
			if ((expr_str = apol_cond_expr_type_to_str(expr_type)) == NULL) {
				goto cleanup;
			}
			expr_elem = Tcl_NewStringObj(expr_str, -1);
		}
		if (Tcl_ListObjAppendElement(interp, *obj, expr_elem) == TCL_ERROR) {
			goto cleanup;
		}
	}

	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Takes a qpol_cond_t and appends a tuple of its expression and its
 * rules to result_list.  The tuple consists of:
 * <code>
 *   { expression_list true_list false_list }
 * </code>
 * Rules lists are formatted as per append_avrule_to_list() and
 * append_terule_to_list().
 *
 * @param avrules A bitmask of which av rules to add to rules lists.
 * @param terules A bitmask of which te rules to add to rules lists.
 */
static int append_cond_result_to_list(Tcl_Interp *interp,
				      qpol_cond_t *result,
				      unsigned int avrules,
				      unsigned int terules,
				      Tcl_Obj *result_list)
{
	Tcl_Obj *cond_elem[3], *cond_list;
	qpol_iterator_t *iter = NULL;
	qpol_avrule_t *avrule;
	qpol_terule_t *terule;
	int retval = TCL_ERROR;

	if (qpol_cond_get_expr_node_iter(policydb->qh, policydb->p, result, &iter) < 0 ||
	    cond_expr_iter_to_tcl_obj(interp, iter, cond_elem + 0) == TCL_ERROR) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	cond_elem[1] = Tcl_NewListObj(0, NULL);

	if (qpol_cond_get_av_true_iter(policydb->qh, policydb->p,
				       result, avrules, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &avrule) < 0 ||
		    append_avrule_to_list(interp, avrule, cond_elem[1]) == TCL_ERROR) {
			goto cleanup;
		}
	}
	qpol_iterator_destroy(&iter);

	if (qpol_cond_get_te_true_iter(policydb->qh, policydb->p,
				       result, terules, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &terule) < 0 ||
		    append_terule_to_list(interp, terule, cond_elem[1]) == TCL_ERROR) {
			goto cleanup;
		}
	}
	qpol_iterator_destroy(&iter);

        cond_elem[2] = Tcl_NewListObj(0, NULL);

	if (qpol_cond_get_av_false_iter(policydb->qh, policydb->p,
				       result, avrules, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &avrule) < 0 ||
		    append_avrule_to_list(interp, avrule, cond_elem[2]) == TCL_ERROR) {
			goto cleanup;
		}
	}
	qpol_iterator_destroy(&iter);

	if (qpol_cond_get_te_false_iter(policydb->qh, policydb->p,
				       result, terules, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &terule) < 0 ||
		    append_terule_to_list(interp, terule, cond_elem[2]) == TCL_ERROR) {
			goto cleanup;
		}
	}

	cond_list = Tcl_NewListObj(3, cond_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, cond_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}

/**
 * Return an unsorted list of TE rules (av rules and type rules) that
 * are only members of conditional expressions within the policy.
 * Each tuple within the results list consists of:
 * <ul>
 *   <li>list of expression nodes
 *   <li>list of true rules
 *   <li>list of false rules
 * </ul>
 *
 * Expression nodes list is a list of boolean strings and operands
 * (e.g., "==").  The expression will be written in reverse polish
 * notation, from left to right.
 *
 * The two rules lists are of the same format as returned by
 * Apol_SearchTERules().
 *
 * @param argv This function takes three parameters:
 * <ol>
 *   <li>rule selections
 *   <li>other options
 *   <li>boolean variable to search, or an empty string to search all
 *   conditionals
 * </ol>
 * For rule selections list, this is a list of which rules to search.
 * Valid rule strings are:
 * <ul>
 *   <li>allow
 *   <li>auditallow
 *   <li>dontaudit
 *   <li>type_transition
 *   <li>type_member
 *   <li>type_change
 * </ul>
 * For other options, this is a list of strings that affect searching.
 * The only valid string is:
 * <ul>
 *   <li>regex - treat boolean symbol as a regular expression
 * </ul>
 */
static int Apol_SearchConditionalRules(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_cond_t *cond;
	unsigned int avrules = 0, terules = 0;
	CONST char **rule_strings = NULL, **other_opt_strings = NULL;
	int num_opts;
	apol_cond_query_t *query = NULL;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 4) {
		ERR(policydb, "Need a rule selection, other options, and boolean name.");
		goto cleanup;
	}

	if ((query = apol_cond_query_create()) == NULL) {
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

	if (Tcl_SplitList(interp, argv[2], &num_opts, &other_opt_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = other_opt_strings[num_opts];
		if (strcmp(s, "regex") == 0) {
			apol_cond_query_set_regex(policydb, query, 1);
		}
		else {
			ERR(policydb, "Invalid option %s.", s);
			goto cleanup;
		}
	}

	if (*argv[3] != '\0' &&
	    apol_cond_query_set_bool(policydb, query, argv[3]) < 0) {
		goto cleanup;
	}

	if (apol_get_cond_by_query(policydb, query, &v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		cond = (qpol_cond_t *) apol_vector_get_element(v, i);
		if (append_cond_result_to_list(interp, cond, avrules, terules, result_obj) == TCL_ERROR) {
			goto cleanup;
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
	apol_cond_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a qpol_role_allow_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *    { "allow" source_role target_role "" line_number }
 * </code>
 */
static int append_role_allow_to_list(Tcl_Interp *interp,
				     qpol_role_allow_t *rule,
				     Tcl_Obj *result_list)
{
	qpol_role_t *source, *target;
	char *source_name, *target_name;
	Tcl_Obj *allow_elem[5], *allow_list;
	int retval = TCL_ERROR;

	if (qpol_role_allow_get_source_role(policydb->qh, policydb->p, rule, &source) < 0 ||
	    qpol_role_allow_get_target_role(policydb->qh, policydb->p, rule, &target) < 0) {
		goto cleanup;
	}

	if (qpol_role_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_role_get_name(policydb->qh, policydb->p, target, &target_name) < 0) {
		goto cleanup;
	}
	allow_elem[0] = Tcl_NewStringObj("allow", -1);
	allow_elem[1] = Tcl_NewStringObj(source_name, -1);
	allow_elem[2] = Tcl_NewStringObj(target_name, -1);
	allow_elem[3] = Tcl_NewStringObj("", -1);
	allow_elem[4] = Tcl_NewStringObj("", -1);  /* FIX ME! */
	allow_list = Tcl_NewListObj(5, allow_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, allow_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Takes a qpol_role_trans_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *    { "role_transition" source_role target_type default_role line_number }
 * </code>
 */
static int append_role_trans_to_list(Tcl_Interp *interp,
                                     qpol_role_trans_t *rule,
                                     Tcl_Obj *result_list)
{
	qpol_role_t *source, *default_role;
	qpol_type_t *target;
	char *source_name, *target_name, *default_name;
	Tcl_Obj *role_trans_elem[5], *role_trans_list;
	int retval = TCL_ERROR;

	if (qpol_role_trans_get_source_role(policydb->qh, policydb->p, rule, &source) < 0 ||
	    qpol_role_trans_get_target_type(policydb->qh, policydb->p, rule, &target) < 0 ||
	    qpol_role_trans_get_default_role(policydb->qh, policydb->p, rule, &default_role) < 0) {
		goto cleanup;
	}

	if (qpol_role_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0 ||
	    qpol_role_get_name(policydb->qh, policydb->p, default_role, &default_name) < 0) {
		goto cleanup;
	}
	role_trans_elem[0] = Tcl_NewStringObj("role_transition", -1);
	role_trans_elem[1] = Tcl_NewStringObj(source_name, -1);
	role_trans_elem[2] = Tcl_NewStringObj(target_name, -1);
	role_trans_elem[3] = Tcl_NewStringObj(default_name, -1);
	role_trans_elem[4] = Tcl_NewStringObj("", -1);  /* FIX ME! */
	role_trans_list = Tcl_NewListObj(5, role_trans_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, role_trans_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return an unsorted list of RBAC rules (role allow and
 * role_transition rules) tuples within the policy.  Each tuple
 * consists of:
 * <ul>
 *   <li>rule type ("allow" or "role_transition")
 *   <li>source role
 *   <li>for allow rules: target role; for role_transition:  target
 *   type
 *   <li>for allow rules: an empty list; for role_transition: default
 *   role
 *   <li>line number, or -1 if unknown
 * </ul>
 *
 * @param argv This function takes five parameters:
 * <ol>
 *   <li>rule selections
 *   <li>other options
 *   <li>source role
 *   <li>target role or type
 *   <li>default role (ignored when searching allow rules)
 * </ol>
 * For rule selections list, this is a list of which rules to search.
 * Valid rule strings are:
 * <ul>
 *   <li>allow
 *   <li>role_transition
 * </ul>
 * For other options, this is a list of strings that affect searching.
 * The only valid string is:
 * <ul>
 *   <li>source_any - treat source symbol as criteria for target role
 *   (for allow) and default role (for role_transition)
 * </ul>
 */
static int Apol_SearchRBACRules(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_role_allow_t *allow;
	qpol_role_trans_t *role_trans;
	CONST char **rule_strings = NULL, **other_opt_strings = NULL;
	int num_opts;
	apol_role_allow_query_t *raquery = NULL;
	apol_role_trans_query_t *rtquery = NULL;
	apol_vector_t *rav = NULL, *rtv = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 6) {
		ERR(policydb, "Need a rule selection, other options, source role, target role/type, and default role.");
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[1], &num_opts, &rule_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = rule_strings[num_opts];
		if (strcmp(s, "allow") == 0) {
			if ((raquery = apol_role_allow_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
		}
		else if (strcmp(s, "role_transition") == 0) {
			if ((rtquery = apol_role_trans_query_create()) == NULL) {
				ERR(policydb, "Out of memory!");
				goto cleanup;
			}
		}
		else {
			ERR(policydb, "Invalid rule selection %s.", s);
			goto cleanup;
		}
	}

	if (Tcl_SplitList(interp, argv[2], &num_opts, &other_opt_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = other_opt_strings[num_opts];
		if (strcmp(s, "source_any") == 0) {
			if (raquery != NULL) {
				apol_role_allow_query_set_source_any(policydb, raquery, 1);
			}
			if (rtquery != NULL) {
				apol_role_trans_query_set_source_any(policydb, rtquery, 1);
			}
		}
		else {
			ERR(policydb, "Invalid option %s.", s);
			goto cleanup;
		}
	}

	if (raquery != NULL) {
		if (apol_role_allow_query_set_source(policydb, raquery, argv[3]) < 0 ||
		    apol_role_allow_query_set_target(policydb, raquery, argv[4]) < 0) {
			goto cleanup;
		}
		if (apol_get_role_allow_by_query(policydb, raquery, &rav) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(rav); i++) {
			allow = (qpol_role_allow_t *) apol_vector_get_element(rav, i);
			if (append_role_allow_to_list(interp, allow, result_obj) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}

	if (rtquery != NULL) {
		if (apol_role_trans_query_set_source(policydb, rtquery, argv[3]) < 0 ||
		    apol_role_trans_query_set_target(policydb, rtquery, argv[4], 0) < 0 ||
		    apol_role_trans_query_set_default(policydb, rtquery, argv[5]) < 0) {
			goto cleanup;
		}
		if (apol_get_role_trans_by_query(policydb, rtquery, &rav) < 0) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(rav); i++) {
			role_trans = (qpol_role_trans_t *) apol_vector_get_element(rav, i);
			if (append_role_trans_to_list(interp, role_trans, result_obj) == TCL_ERROR) {
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
	apol_role_allow_query_destroy(&raquery);
	apol_role_trans_query_destroy(&rtquery);
	apol_vector_destroy(&rav, NULL);
	apol_vector_destroy(&rtv, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a qpol_range_trans_t and appends a tuple of it to
 * result_list.  The tuple consists of:
 * <code>
 *    { source_type_set target_type_set range line_number }
 * </code>
 * The type sets are Tcl lists.
 */
static int append_range_trans_to_list(Tcl_Interp *interp,
				      qpol_range_trans_t *rule,
				      Tcl_Obj *result_list)
{
	qpol_type_t *source, *target;
	qpol_mls_range_t *range;
	apol_mls_range_t *apol_range = NULL;
	char *source_name, *target_name;
	Tcl_Obj *range_elem[2], *rule_elem[4], *rule_list;
	int retval = TCL_ERROR;

	if (qpol_range_trans_get_source_type(policydb->qh, policydb->p, rule, &source) < 0 ||
	    qpol_range_trans_get_target_type(policydb->qh, policydb->p, rule, &target) < 0 ||
	    qpol_range_trans_get_range(policydb->qh, policydb->p, rule, &range) < 0) {
		goto cleanup;
	}

	if (qpol_type_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0 ||
	    (apol_range =
	     apol_mls_range_create_from_qpol_mls_range(policydb, range)) == NULL) {
		goto cleanup;
	}

	rule_elem[0] = Tcl_NewStringObj(source_name, -1);
	rule_elem[1] = Tcl_NewStringObj(target_name, -1);
	if (apol_level_to_tcl_obj(interp, apol_range->low, range_elem + 0) < 0 ||
	    apol_level_to_tcl_obj(interp, apol_range->high, range_elem + 1) < 0) {
		goto cleanup;
	}
	rule_elem[2] = Tcl_NewListObj(2, range_elem);
	rule_elem[3] = Tcl_NewStringObj("", -1);  /* FIX ME! */
	rule_list = Tcl_NewListObj(4, rule_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, rule_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	apol_mls_range_destroy(&apol_range);
	return retval;
}

/**
 * Returns an unsortecd list of range transition rules within the
 * policy.  Each tuple consists of:
 * <ul>
 *   <li>source type set
 *   <li>target type set
 *   <li>new range (range = 2-uple of levels)
 *   <li>line number, or -1 if unknown
 * </ul>
 *
 * @param argv This function takes four parameters:
 * <ol>
 *   <li>source type
 *   <li>target type
 *   <li>new range
 *   <li>range query type
 * </ol>
 */
static int Apol_SearchRangeTransRules(ClientData clientData, Tcl_Interp *interp, int argc, const char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_range_trans_t *rule;
	apol_range_trans_query_t *query = NULL;
	apol_vector_t *v = NULL;
	size_t i;
        int retval = TCL_ERROR;

        apol_tcl_clear_error ();
        if (policydb == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
                goto cleanup;
        }
        if (argc != 5) {
                ERR(policydb, "Need a source type, target type, range, and range type.");
                goto cleanup;
        }

	if ((query = apol_range_trans_query_create()) == NULL) {
		ERR(policydb, "Out of memory!");
		goto cleanup;
	}

	if (apol_range_trans_query_set_source(policydb, query, argv[1], 0) < 0 ||
	    apol_range_trans_query_set_target(policydb, query, argv[2], 0) < 0) {
		goto cleanup;
	}
	if (*argv[3] != '\0') {
		apol_mls_range_t *range;
		unsigned int range_match = 0;
		if (apol_tcl_string_to_range_match(interp, argv[4], &range_match) < 0) {
			goto cleanup;
		}
		if ((range = apol_mls_range_create()) == NULL) {
			ERR(policydb, "Out of memory!");
			goto cleanup;
		}
		if (apol_tcl_string_to_range(interp, argv[3], range) != 0 ||
		    apol_range_trans_query_set_range(policydb, query, range, range_match) < 0) {
			apol_mls_range_destroy(&range);
			goto cleanup;
		}
	}

	if (apol_get_range_trans_by_query(policydb, query, &v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		rule = (qpol_range_trans_t *) apol_vector_get_element(v, i);
		if (append_range_trans_to_list(interp, rule, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_range_trans_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
        return retval;
}


int apol_tcl_rules_init(Tcl_Interp *interp) {
	Tcl_CreateCommand(interp, "apol_SearchTERules", Apol_SearchTERules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SearchConditionalRules", Apol_SearchConditionalRules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SearchRBACRules", Apol_SearchRBACRules, NULL, NULL);
        Tcl_CreateCommand(interp, "apol_SearchRangeTransRules", Apol_SearchRangeTransRules, NULL, NULL);
        return TCL_OK;
}
