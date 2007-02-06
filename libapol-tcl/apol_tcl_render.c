/**
 * @file
 * Implementation for the apol interface to render parts of a policy.
 * This file takes various policy stuff and returns formatted Tcl
 * lists, suitable for displaying results in Apol.
 *
 *  @author Kevin Carr kcarr@tresys.com
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
#include "apol_tcl_rules.h"

#include <apol/policy.h>
#include <apol/util.h>

#include <errno.h>
#include <tcl.h>

int apol_level_to_tcl_obj(Tcl_Interp * interp, apol_mls_level_t * level, Tcl_Obj ** obj)
{
	Tcl_Obj *level_elem[2], *cats_obj;
	size_t i;
	level_elem[0] = Tcl_NewStringObj(level->sens, -1);
	level_elem[1] = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(level->cats); i++) {
		cats_obj = Tcl_NewStringObj((char *)apol_vector_get_element(level->cats, i), -1);
		if (Tcl_ListObjAppendElement(interp, level_elem[1], cats_obj) == TCL_ERROR) {
			return -1;
		}
	}
	*obj = Tcl_NewListObj(2, level_elem);
	return 0;
}

/**
 * Converts a qpol_avrule_t to a Tcl representation:
 * The tuple consists of:
 * <code>
 *    { rule_type source_type target_type object_class perm_set
 *      cond_info }
 * </code>
 * The perm sets is a Tcl lists.  If cond_info is an empty list then
 * this rule is unconditional.  Otherwise cond_info is a 2-uple list,
 * where the first element is either "enabled" or "disabled", and the
 * second element is a unique identifier to the conditional
 * expression.
 */
static int qpol_avrule_to_tcl_list(Tcl_Interp * interp, qpol_avrule_t * avrule, Tcl_Obj ** obj)
{
	uint32_t rule_type, is_enabled;
	const char *rule_string;
	qpol_type_t *source, *target;
	qpol_class_t *obj_class;
	qpol_iterator_t *perm_iter = NULL;
	char *source_name, *target_name, *obj_class_name;
	qpol_cond_t *cond;
	Tcl_Obj *avrule_elem[6], *cond_elem[2];
	int retval = TCL_ERROR;

	if (qpol_avrule_get_rule_type(qpolicydb, avrule, &rule_type) < 0 ||
	    qpol_avrule_get_source_type(qpolicydb, avrule, &source) < 0 ||
	    qpol_avrule_get_target_type(qpolicydb, avrule, &target) < 0 ||
	    qpol_avrule_get_object_class(qpolicydb, avrule, &obj_class) < 0 ||
	    qpol_avrule_get_perm_iter(qpolicydb, avrule, &perm_iter) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		ERR(policydb, "Invalid avrule type %d.", rule_type);
		goto cleanup;
	}
	if (qpol_type_get_name(qpolicydb, source, &source_name) < 0 ||
	    qpol_type_get_name(qpolicydb, target, &target_name) < 0 ||
	    qpol_class_get_name(qpolicydb, obj_class, &obj_class_name) < 0) {
		goto cleanup;
	}
	avrule_elem[0] = Tcl_NewStringObj(rule_string, -1);
	avrule_elem[1] = Tcl_NewStringObj(source_name, -1);
	avrule_elem[2] = Tcl_NewStringObj(target_name, -1);
	avrule_elem[3] = Tcl_NewStringObj(obj_class_name, -1);
	avrule_elem[4] = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		char *perm_name;
		Tcl_Obj *perm_obj;
		if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0) {
			goto cleanup;
		}
		perm_obj = Tcl_NewStringObj(perm_name, -1);
		free(perm_name);
		if (Tcl_ListObjAppendElement(interp, avrule_elem[4], perm_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	if (qpol_avrule_get_cond(qpolicydb, avrule, &cond) < 0 || qpol_avrule_get_is_enabled(qpolicydb, avrule, &is_enabled) < 0) {
		goto cleanup;
	}
	if (cond == NULL) {
		avrule_elem[5] = Tcl_NewListObj(0, NULL);
	} else {
		cond_elem[0] = Tcl_NewStringObj(is_enabled ? "enabled" : "disabled", -1);
		cond_elem[1] = Tcl_NewStringObj("", -1);	/* FIX ME! */
		avrule_elem[5] = Tcl_NewListObj(2, cond_elem);
	}
	*obj = Tcl_NewListObj(6, avrule_elem);
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

/**
 * Converts a qpol_terule_t to a Tcl representation:
 * The tuple consists of:
 * <code>
 *    { rule_type source_type target_type object_class default_type
 *      cond_info }
 * </code>
 * The perm sets is a Tcl lists.  If cond_info is an empty list then
 * this rule is unconditional.  Otherwise cond_info is a 2-uple list,
 * where the first element is either "enabled" or "disabled", and the
 * second element is a unique identifier to the conditional
 * expression.
 */
static int qpol_terule_to_tcl_list(Tcl_Interp * interp, qpol_terule_t * terule, Tcl_Obj ** obj)
{
	uint32_t rule_type, is_enabled;
	const char *rule_string;
	qpol_type_t *source, *target, *default_type;
	qpol_class_t *obj_class;
	char *source_name, *target_name, *obj_class_name, *default_name;
	qpol_cond_t *cond;
	Tcl_Obj *terule_elem[6], *cond_elem[2];
	int retval = TCL_ERROR;

	if (qpol_terule_get_rule_type(qpolicydb, terule, &rule_type) < 0 ||
	    qpol_terule_get_source_type(qpolicydb, terule, &source) < 0 ||
	    qpol_terule_get_target_type(qpolicydb, terule, &target) < 0 ||
	    qpol_terule_get_object_class(qpolicydb, terule, &obj_class) < 0 ||
	    qpol_terule_get_default_type(qpolicydb, terule, &default_type) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		ERR(policydb, "Invalid terule type %d.", rule_type);
		goto cleanup;
	}
	if (qpol_type_get_name(qpolicydb, source, &source_name) < 0 ||
	    qpol_type_get_name(qpolicydb, target, &target_name) < 0 ||
	    qpol_class_get_name(qpolicydb, obj_class, &obj_class_name) < 0 ||
	    qpol_type_get_name(qpolicydb, default_type, &default_name) < 0) {
		goto cleanup;
	}
	terule_elem[0] = Tcl_NewStringObj(rule_string, -1);
	terule_elem[1] = Tcl_NewStringObj(source_name, -1);
	terule_elem[2] = Tcl_NewStringObj(target_name, -1);
	terule_elem[3] = Tcl_NewStringObj(obj_class_name, -1);
	terule_elem[4] = Tcl_NewStringObj(default_name, -1);
	if (qpol_terule_get_cond(qpolicydb, terule, &cond) < 0 || qpol_terule_get_is_enabled(qpolicydb, terule, &is_enabled) < 0) {
		goto cleanup;
	}
	if (cond == NULL) {
		terule_elem[5] = Tcl_NewListObj(0, NULL);
	} else {
		cond_elem[0] = Tcl_NewStringObj(is_enabled ? "enabled" : "disabled", -1);
		cond_elem[1] = Tcl_NewStringObj("", -1);	/* FIX ME! */
		terule_elem[5] = Tcl_NewListObj(2, cond_elem);
	}
	*obj = Tcl_NewListObj(6, terule_elem);
	retval = TCL_OK;
      cleanup:
	return retval;
}

/**
 * Given a type set and a 'self' flag, create and return a Tcl list
 * containing the type set's elements.  If the set is complemented
 * then the list will begin with a "~".  Next, if the set is starred
 * then the list will have a "*".  Following that are all included
 * types.  Excluded types follow; those types will be prepended by a
 * "-".  Finally, if the self flag is set then append the word "self"
 * to the list.
 *
 * @param interp Tcl interpreter object.
 * @param ts Type set to convert.
 * @param is_self 1 if the word "self" should be appended to the list.
 * @param obj Reference to where to build Tcl list.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 */
static int qpol_type_set_to_tcl_list(Tcl_Interp * interp, qpol_type_set_t * ts, uint32_t is_self, Tcl_Obj ** obj)
{
	uint32_t is_star, is_comp;
	qpol_iterator_t *inc_iter = NULL, *sub_iter = NULL;
	qpol_type_t *type;
	char *type_name;
	Tcl_Obj *o;
	int retval = TCL_ERROR;
	if (qpol_type_set_get_is_comp(qpolicydb, ts, &is_comp) < 0 ||
	    qpol_type_set_get_is_star(qpolicydb, ts, &is_star) < 0 ||
	    qpol_type_set_get_included_types_iter(qpolicydb, ts, &inc_iter) < 0 ||
	    qpol_type_set_get_subtracted_types_iter(qpolicydb, ts, &sub_iter) < 0) {
		goto cleanup;
	}
	*obj = Tcl_NewListObj(0, NULL);
	if (is_comp) {
		o = Tcl_NewStringObj("~", -1);
		if (Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	if (is_star) {
		o = Tcl_NewStringObj("*", -1);
		if (Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	for (; !qpol_iterator_end(inc_iter); qpol_iterator_next(inc_iter)) {
		if (qpol_iterator_get_item(inc_iter, (void **)&type) < 0 || qpol_type_get_name(qpolicydb, type, &type_name) < 0) {
			goto cleanup;
		}
		o = Tcl_NewStringObj(type_name, -1);
		if (Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	for (; !qpol_iterator_end(sub_iter); qpol_iterator_next(sub_iter)) {
		if (qpol_iterator_get_item(sub_iter, (void **)&type) < 0 || qpol_type_get_name(qpolicydb, type, &type_name) < 0) {
			goto cleanup;
		}
		o = Tcl_NewStringObj("-", -1);
		Tcl_AppendStringsToObj(o, type_name, (char *)NULL);
		if (Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	if (is_self) {
		o = Tcl_NewStringObj("self", -1);
		if (Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&inc_iter);
	qpol_iterator_destroy(&sub_iter);
	return retval;
}

/**
 * Converts a qpol_syn_avrule_t to a Tcl representation:
 * The tuple consists of:
 * <code>
 *    { rule_type source_type_set target_type_set object_class perm_set
 *      line_number cond_info }
 * </code>
 * The type sets and perm sets are Tcl lists.  If cond_info is an
 * empty list then this rule is unconditional.  Otherwise cond_info is
 * a 2-uple list, where the first element is either "enabled" or
 * "disabled", and the second element is a unique identifier to the
 * conditional expression.
 */
static int qpol_syn_avrule_to_tcl_obj(Tcl_Interp * interp, qpol_syn_avrule_t * avrule, Tcl_Obj ** obj)
{
	uint32_t rule_type, is_self;
	qpol_type_set_t *source_set, *target_set;
	qpol_iterator_t *class_iter = NULL, *perm_iter = NULL;
	const char *rule_string;
	unsigned long lineno;
	qpol_cond_t *cond;
	uint32_t is_enabled;
	qpol_class_t *obj_class;
	char *obj_class_name, *perm_name;
	Tcl_Obj *avrule_elem[7], *o;
	int retval = TCL_ERROR;

	if (qpol_syn_avrule_get_rule_type(qpolicydb, avrule, &rule_type) < 0 ||
	    qpol_syn_avrule_get_source_type_set(qpolicydb, avrule, &source_set) < 0 ||
	    qpol_syn_avrule_get_is_target_self(qpolicydb, avrule, &is_self) < 0 ||
	    qpol_syn_avrule_get_class_iter(qpolicydb, avrule, &class_iter) < 0 ||
	    qpol_syn_avrule_get_perm_iter(qpolicydb, avrule, &perm_iter) < 0 ||
	    qpol_syn_avrule_get_lineno(qpolicydb, avrule, &lineno) < 0 ||
	    qpol_syn_avrule_get_cond(qpolicydb, avrule, &cond) < 0 ||
	    qpol_syn_avrule_get_is_enabled(qpolicydb, avrule, &is_enabled) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		ERR(policydb, "Invalid avrule type %d.", rule_type);
		goto cleanup;
	}
	avrule_elem[0] = Tcl_NewStringObj(rule_string, -1);
	if (qpol_type_set_to_tcl_list(interp, source_set, 0, avrule_elem + 1) == TCL_ERROR) {
		goto cleanup;
	}
	if (qpol_syn_avrule_get_target_type_set(qpolicydb, avrule, &target_set) < 0 ||
	    qpol_type_set_to_tcl_list(interp, target_set, is_self, avrule_elem + 2) == TCL_ERROR) {
		goto cleanup;
	}
	avrule_elem[3] = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(class_iter); qpol_iterator_next(class_iter)) {
		if (qpol_iterator_get_item(class_iter, (void **)&obj_class) < 0 ||
		    qpol_class_get_name(qpolicydb, obj_class, &obj_class_name) < 0) {
			goto cleanup;
		}
		o = Tcl_NewStringObj(obj_class_name, -1);
		if (Tcl_ListObjAppendElement(interp, avrule_elem[3], o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	avrule_elem[4] = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0) {
			goto cleanup;
		}
		o = Tcl_NewStringObj(perm_name, -1);
		if (Tcl_ListObjAppendElement(interp, avrule_elem[4], o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	avrule_elem[5] = Tcl_NewLongObj((long)lineno);
	if (cond == NULL) {
		avrule_elem[6] = Tcl_NewListObj(0, NULL);
	} else {
		Tcl_Obj *cond_elem[2];
		cond_elem[0] = Tcl_NewStringObj(is_enabled ? "enabled" : "disabled", -1);
		cond_elem[1] = Tcl_NewStringObj("", -1);	/* FIX ME! */
		avrule_elem[6] = Tcl_NewListObj(2, cond_elem);
	}
	*obj = Tcl_NewListObj(7, avrule_elem);
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&class_iter);
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

/**
 * Converts a qpol_syn_terule_t to a Tcl representation:
 * The tuple consists of:
 * <code>
 *    { rule_type source_type_set target_type_set object_class default_type
 *      line_number cond_info }
 * </code>
 * The type sets and perm sets are Tcl lists.  If cond_info is an
 * empty list then this rule is unconditional.  Otherwise cond_info is
 * a 2-uple list, where the first element is either "enabled" or
 * "disabled", and the second element is a unique identifier to the
 * conditional expression.
 */
static int qpol_syn_terule_to_tcl_obj(Tcl_Interp * interp, qpol_syn_terule_t * terule, Tcl_Obj ** obj)
{
	uint32_t rule_type;
	qpol_type_set_t *source_set, *target_set;
	qpol_type_t *default_type;
	qpol_iterator_t *class_iter = NULL;
	const char *rule_string;
	unsigned long lineno;
	qpol_cond_t *cond;
	uint32_t is_enabled;
	qpol_class_t *obj_class;
	char *obj_class_name, *default_type_name;
	Tcl_Obj *terule_elem[7], *o;
	int retval = TCL_ERROR;

	if (qpol_syn_terule_get_rule_type(qpolicydb, terule, &rule_type) < 0 ||
	    qpol_syn_terule_get_source_type_set(qpolicydb, terule, &source_set) < 0 ||
	    qpol_syn_terule_get_target_type_set(qpolicydb, terule, &target_set) < 0 ||
	    qpol_syn_terule_get_class_iter(qpolicydb, terule, &class_iter) < 0 ||
	    qpol_syn_terule_get_default_type(qpolicydb, terule, &default_type) < 0 ||
	    qpol_syn_terule_get_lineno(qpolicydb, terule, &lineno) < 0 ||
	    qpol_syn_terule_get_cond(qpolicydb, terule, &cond) < 0 ||
	    qpol_syn_terule_get_is_enabled(qpolicydb, terule, &is_enabled) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		ERR(policydb, "Invalid terule type %d.", rule_type);
		goto cleanup;
	}
	terule_elem[0] = Tcl_NewStringObj(rule_string, -1);
	if (qpol_type_set_to_tcl_list(interp, source_set, 0, terule_elem + 1) == TCL_ERROR ||
	    qpol_type_set_to_tcl_list(interp, target_set, 0, terule_elem + 2) == TCL_ERROR) {
		goto cleanup;
	}
	terule_elem[3] = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(class_iter); qpol_iterator_next(class_iter)) {
		if (qpol_iterator_get_item(class_iter, (void **)&obj_class) < 0 ||
		    qpol_class_get_name(qpolicydb, obj_class, &obj_class_name) < 0) {
			goto cleanup;
		}
		o = Tcl_NewStringObj(obj_class_name, -1);
		if (Tcl_ListObjAppendElement(interp, terule_elem[3], o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	if (qpol_type_get_name(qpolicydb, default_type, &default_type_name) < 0) {
		goto cleanup;
	}
	terule_elem[4] = Tcl_NewStringObj(default_type_name, -1);
	terule_elem[5] = Tcl_NewLongObj((long)lineno);
	if (cond == NULL) {
		terule_elem[6] = Tcl_NewListObj(0, NULL);
	} else {
		Tcl_Obj *cond_elem[2];
		cond_elem[0] = Tcl_NewStringObj(is_enabled ? "enabled" : "disabled", -1);
		cond_elem[1] = Tcl_NewStringObj("", -1);	/* FIX ME! */
		terule_elem[6] = Tcl_NewListObj(2, cond_elem);
	}
	*obj = Tcl_NewListObj(7, terule_elem);
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&class_iter);
	return retval;
}

/******************** functions callable by apol below ********************/

/**
 * Take a Tcl string representing a level (level = sensitivity + list
 * of categories) and return a string representation of it.  If the
 * level is nat valid according to the policy then return an empty
 * string.
 *
 * @param argv A MLS level.
 */
static int Apol_RenderLevel(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
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
		ERR(policydb, "%s", "Need a level to render.");
		goto cleanup;
	}
	if ((level = apol_mls_level_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	retval2 = apol_tcl_string_to_level(interp, argv[1], level);
	if (retval2 < 0) {
		goto cleanup;
	} else if (retval2 == 1) {
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
static int Apol_RenderContext(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = NULL;
	apol_context_t *context = NULL;
	char *rendered_context = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a context.");
		goto cleanup;
	}
	if ((context = apol_context_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
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

/**
 * Take a Tcl object representing an AV rule identifier (relative to
 * the currently loaded policy) and return a Tcl list representation
 * of it:
 * <code>
 *    { rule_type source_type target_type object_class perm_set cond_info }
 * </code>
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 * </ol>
 */
static int Apol_RenderAVRule(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	Tcl_Obj *result_obj = NULL;
	qpol_avrule_t *avrule;
	int retval = TCL_ERROR;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_avrule(interp, objv[1], &avrule) == TCL_ERROR ||
	    qpol_avrule_to_tcl_list(interp, avrule, &result_obj) == TCL_ERROR) {
		goto cleanup;
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing an AV rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's rule type ("allow", "neverallow", etc.)
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 * </ol>
 */
static int Apol_RenderAVRuleType(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_avrule_t *avrule;
	uint32_t rule_type;
	const char *rule_string;
	Tcl_Obj *o;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_avrule(interp, objv[1], &avrule) == TCL_ERROR ||
	    qpol_avrule_get_rule_type(qpolicydb, avrule, &rule_type) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		ERR(policydb, "Invalid avrule type %d.", rule_type);
		goto cleanup;
	}
	o = Tcl_NewStringObj(rule_string, -1);
	Tcl_SetObjResult(interp, o);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing an AV rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's source type.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 * </ol>
 */
static int Apol_RenderAVRuleSource(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_avrule_t *avrule;
	qpol_type_t *source;
	char *source_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_avrule(interp, objv[1], &avrule) == TCL_ERROR ||
	    qpol_avrule_get_source_type(qpolicydb, avrule, &source) < 0 ||
	    qpol_type_get_name(qpolicydb, source, &source_string) < 0) {
		goto cleanup;
	}
	Tcl_SetResult(interp, source_string, TCL_VOLATILE);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing an AV rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's target type.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 * </ol>
 */
static int Apol_RenderAVRuleTarget(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_avrule_t *avrule;
	qpol_type_t *target;
	char *target_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_avrule(interp, objv[1], &avrule) == TCL_ERROR ||
	    qpol_avrule_get_target_type(qpolicydb, avrule, &target) < 0 ||
	    qpol_type_get_name(qpolicydb, target, &target_string) < 0) {
		goto cleanup;
	}
	Tcl_SetResult(interp, target_string, TCL_VOLATILE);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing an AV rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's object class.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 * </ol>
 */
static int Apol_RenderAVRuleClass(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_avrule_t *avrule;
	qpol_class_t *obj_class;
	char *obj_class_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_avrule(interp, objv[1], &avrule) == TCL_ERROR ||
	    qpol_avrule_get_object_class(qpolicydb, avrule, &obj_class) < 0 ||
	    qpol_class_get_name(qpolicydb, obj_class, &obj_class_string) < 0) {
		goto cleanup;
	}
	Tcl_SetResult(interp, obj_class_string, TCL_VOLATILE);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing an AV rule identifier (relative to
 * the currently loaded policy) and return a list of that rule's
 * permissions.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 * </ol>
 */
static int Apol_RenderAVRulePerms(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	Tcl_Obj *result_obj = NULL, *perm_obj;
	qpol_avrule_t *avrule;
	qpol_iterator_t *perm_iter = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_avrule(interp, objv[1], &avrule) == TCL_ERROR ||
	    qpol_avrule_get_perm_iter(qpolicydb, avrule, &perm_iter) < 0) {
		goto cleanup;
	}
	result_obj = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		char *perm_name;
		if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0) {
			goto cleanup;
		}
		perm_obj = Tcl_NewStringObj(perm_name, -1);
		free(perm_name);
		if (Tcl_ListObjAppendElement(interp, result_obj, perm_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&perm_iter);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing a TE rule identifier (relative to
 * the currently loaded policy) and return a Tcl list representation
 * of it:
 * <code>
 *    { rule_type source_type target_type object_class default_type
 *      cond_info }
 * </code>
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an te rule identifier.
 * </ol>
 */
static int Apol_RenderTERule(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	Tcl_Obj *result_obj;
	qpol_terule_t *terule;
	int retval = TCL_ERROR;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a terule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_terule(interp, objv[1], &terule) == TCL_ERROR ||
	    qpol_terule_to_tcl_list(interp, terule, &result_obj) == TCL_ERROR) {
		goto cleanup;
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing a TE rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's rule type ("type_transition", "type_change", etc.)
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing a te rule identifier.
 * </ol>
 */
static int Apol_RenderTERuleType(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_terule_t *terule;
	uint32_t rule_type;
	const char *rule_string;
	Tcl_Obj *o;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a terule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_terule(interp, objv[1], &terule) == TCL_ERROR ||
	    qpol_terule_get_rule_type(qpolicydb, terule, &rule_type) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		ERR(policydb, "Invalid terule type %d.", rule_type);
		goto cleanup;
	}
	o = Tcl_NewStringObj(rule_string, -1);
	Tcl_SetObjResult(interp, o);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing a TE rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's source type.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing a te rule identifier.
 * </ol>
 */
static int Apol_RenderTERuleSource(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_terule_t *terule;
	qpol_type_t *source;
	char *source_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a terule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_terule(interp, objv[1], &terule) == TCL_ERROR ||
	    qpol_terule_get_source_type(qpolicydb, terule, &source) < 0 ||
	    qpol_type_get_name(qpolicydb, source, &source_string) < 0) {
		goto cleanup;
	}
	Tcl_SetResult(interp, source_string, TCL_VOLATILE);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing a te rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's target type.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing a te rule identifier.
 * </ol>
 */
static int Apol_RenderTERuleTarget(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_terule_t *terule;
	qpol_type_t *target;
	char *target_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a terule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_terule(interp, objv[1], &terule) == TCL_ERROR ||
	    qpol_terule_get_target_type(qpolicydb, terule, &target) < 0 ||
	    qpol_type_get_name(qpolicydb, target, &target_string) < 0) {
		goto cleanup;
	}
	Tcl_SetResult(interp, target_string, TCL_VOLATILE);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing a te rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's object class.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing a te rule identifier.
 * </ol>
 */
static int Apol_RenderTERuleClass(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_terule_t *terule;
	qpol_class_t *obj_class;
	char *obj_class_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a terule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_terule(interp, objv[1], &terule) == TCL_ERROR ||
	    qpol_terule_get_object_class(qpolicydb, terule, &obj_class) < 0 ||
	    qpol_class_get_name(qpolicydb, obj_class, &obj_class_string) < 0) {
		goto cleanup;
	}
	Tcl_SetResult(interp, obj_class_string, TCL_VOLATILE);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing a te rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's default type.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing a te rule identifier.
 * </ol>
 */
static int Apol_RenderTERuleDefault(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_terule_t *terule;
	qpol_type_t *default_type;
	char *default_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a terule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_terule(interp, objv[1], &terule) == TCL_ERROR ||
	    qpol_terule_get_default_type(qpolicydb, terule, &default_type) < 0 ||
	    qpol_type_get_name(qpolicydb, default_type, &default_string) < 0) {
		goto cleanup;
	}
	Tcl_SetResult(interp, default_string, TCL_VOLATILE);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take two Tcl objects representing AV rule identifiers (relative to
 * the currently loaded policy) and return -1, 0, or 1 if the first
 * come before, the same, or after the other one, respectively,
 * according to printing order.
 *
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 *   <li>Tcl object representing another av rule identifier.
 * </ol>
 */
static int Apol_RenderAVRuleComp(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_avrule_t *r1, *r2;
	uint32_t rt1, rt2;
	const char *rule_type1, *rule_type2;
	qpol_type_t *t1, *t2;
	qpol_class_t *c1, *c2;
	char *s1, *s2;
	int retval = TCL_ERROR, compval;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 3) {
		ERR(policydb, "%s", "Need two avrule identifiers.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_avrule(interp, objv[1], &r1) == TCL_ERROR || tcl_obj_to_qpol_avrule(interp, objv[2], &r2) == TCL_ERROR) {
		goto cleanup;
	}
	if (qpol_avrule_get_rule_type(qpolicydb, r1, &rt1) < 0 ||
	    qpol_avrule_get_rule_type(qpolicydb, r2, &rt2) < 0 ||
	    (rule_type1 = apol_rule_type_to_str(rt1)) == NULL || (rule_type2 = apol_rule_type_to_str(rt2)) == NULL) {
		ERR(policydb, "%s", "Invalid avrule type.");
		goto cleanup;
	}
	if ((compval = strcmp(rule_type1, rule_type2)) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewIntObj(compval));
		return TCL_OK;
	}
	if (qpol_avrule_get_source_type(qpolicydb, r1, &t1) < 0 ||
	    qpol_avrule_get_source_type(qpolicydb, r2, &t2) < 0 ||
	    qpol_type_get_name(qpolicydb, t1, &s1) < 0 || qpol_type_get_name(qpolicydb, t2, &s2) < 0) {
		goto cleanup;
	}
	if ((compval = strcmp(s1, s2)) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewIntObj(compval));
		return TCL_OK;
	}
	if (qpol_avrule_get_target_type(qpolicydb, r1, &t1) < 0 ||
	    qpol_avrule_get_target_type(qpolicydb, r2, &t2) < 0 ||
	    qpol_type_get_name(qpolicydb, t1, &s1) < 0 || qpol_type_get_name(qpolicydb, t2, &s2) < 0) {
		goto cleanup;
	}
	if ((compval = strcmp(s1, s2)) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewIntObj(compval));
		return TCL_OK;
	}
	if (qpol_avrule_get_object_class(qpolicydb, r1, &c1) < 0 ||
	    qpol_avrule_get_object_class(qpolicydb, r2, &c2) < 0 ||
	    qpol_class_get_name(qpolicydb, c1, &s1) < 0 || qpol_class_get_name(qpolicydb, c2, &s2) < 0) {
		goto cleanup;
	}
	compval = strcmp(s1, s2);
	Tcl_SetObjResult(interp, Tcl_NewIntObj(compval));
	return TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take two Tcl objects representing TE rule identifiers (relative to
 * the currently loaded policy) and return -1, 0, or 1 if the first
 * come before, the same, or after the other one, respectively,
 * according to printing order.
 *
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>Tcl object representing an te rule identifier.
 *   <li>Tcl object representing another te rule identifier.
 * </ol>
 */
static int Apol_RenderTERuleComp(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	qpol_terule_t *r1, *r2;
	uint32_t rt1, rt2;
	const char *rule_type1, *rule_type2;
	qpol_type_t *t1, *t2;
	qpol_class_t *c1, *c2;
	char *s1, *s2;
	int retval = TCL_ERROR, compval;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 3) {
		ERR(policydb, "%s", "Need two terule identifiers.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_terule(interp, objv[1], &r1) == TCL_ERROR || tcl_obj_to_qpol_terule(interp, objv[2], &r2) == TCL_ERROR) {
		goto cleanup;
	}
	if (qpol_terule_get_rule_type(qpolicydb, r1, &rt1) < 0 ||
	    qpol_terule_get_rule_type(qpolicydb, r2, &rt2) < 0 ||
	    (rule_type1 = apol_rule_type_to_str(rt1)) == NULL || (rule_type2 = apol_rule_type_to_str(rt2)) == NULL) {
		ERR(policydb, "%s", "Invalid terule type.");
		goto cleanup;
	}
	if ((compval = strcmp(rule_type1, rule_type2)) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewIntObj(compval));
		return TCL_OK;
	}
	if (qpol_terule_get_source_type(qpolicydb, r1, &t1) < 0 ||
	    qpol_terule_get_source_type(qpolicydb, r2, &t2) < 0 ||
	    qpol_type_get_name(qpolicydb, t1, &s1) < 0 || qpol_type_get_name(qpolicydb, t2, &s2) < 0) {
		goto cleanup;
	}
	if ((compval = strcmp(s1, s2)) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewIntObj(compval));
		return TCL_OK;
	}
	if (qpol_terule_get_target_type(qpolicydb, r1, &t1) < 0 ||
	    qpol_terule_get_target_type(qpolicydb, r2, &t2) < 0 ||
	    qpol_type_get_name(qpolicydb, t1, &s1) < 0 || qpol_type_get_name(qpolicydb, t2, &s2) < 0) {
		goto cleanup;
	}
	if ((compval = strcmp(s1, s2)) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewIntObj(compval));
		return TCL_OK;
	}
	if (qpol_terule_get_object_class(qpolicydb, r1, &c1) < 0 ||
	    qpol_terule_get_object_class(qpolicydb, r2, &c2) < 0 ||
	    qpol_class_get_name(qpolicydb, c1, &s1) < 0 || qpol_class_get_name(qpolicydb, c2, &s2) < 0) {
		goto cleanup;
	}
	compval = strcmp(s1, s2);
	Tcl_SetObjResult(interp, Tcl_NewIntObj(compval));
	return TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing a syntactic AV rule identifier
 * (relative to the currently loaded policy) and return a Tcl list
 * representation of it:
 * <code>
 *    { rule_type source_type_set target_type_set object_class perm_set
 *      line_number cond_info }
 * </code>
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 * </ol>
 */
static int Apol_RenderSynAVRule(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	Tcl_Obj *result_obj = NULL;
	qpol_syn_avrule_t *avrule;
	int retval = TCL_ERROR;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a syn avrule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_syn_avrule(interp, objv[1], &avrule) == TCL_ERROR ||
	    qpol_syn_avrule_to_tcl_obj(interp, avrule, &result_obj) == TCL_ERROR) {
		goto cleanup;
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl object representing a syntactic TE rule identifier
 * (relative to the currently loaded policy) and return a Tcl list
 * representation of it:
 * <code>
 *    { rule_type source_type_set target_type_set object_class default_type
 *      line_number cond_info }
 * </code>
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing an av rule identifier.
 * </ol>
 */
static int Apol_RenderSynTERule(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	Tcl_Obj *result_obj = NULL;
	qpol_syn_terule_t *terule;
	int retval = TCL_ERROR;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a syn terule identifier.");
		goto cleanup;
	}
	if (tcl_obj_to_qpol_syn_terule(interp, objv[1], &terule) == TCL_ERROR ||
	    qpol_syn_terule_to_tcl_obj(interp, terule, &result_obj) == TCL_ERROR) {
		goto cleanup;
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

int apol_tcl_render_init(Tcl_Interp * interp)
{
	Tcl_CreateCommand(interp, "apol_RenderLevel", Apol_RenderLevel, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderContext", Apol_RenderContext, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderAVRule", Apol_RenderAVRule, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderAVRuleType", Apol_RenderAVRuleType, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderAVRuleSource", Apol_RenderAVRuleSource, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderAVRuleTarget", Apol_RenderAVRuleTarget, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderAVRuleClass", Apol_RenderAVRuleClass, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderAVRulePerms", Apol_RenderAVRulePerms, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderTERule", Apol_RenderTERule, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderTERuleType", Apol_RenderTERuleType, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderTERuleSource", Apol_RenderTERuleSource, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderTERuleTarget", Apol_RenderTERuleTarget, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderTERuleClass", Apol_RenderTERuleClass, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderTERuleDefault", Apol_RenderTERuleDefault, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderAVRuleComp", Apol_RenderAVRuleComp, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderTERuleComp", Apol_RenderTERuleComp, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderSynAVRule", Apol_RenderSynAVRule, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_RenderSynTERule", Apol_RenderSynTERule, NULL, NULL);
	return TCL_OK;
}
