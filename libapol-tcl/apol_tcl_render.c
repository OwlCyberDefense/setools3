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

#include "apol_tcl_other.h"

#include <apol/policy.h>
#include <apol/util.h>

#include <errno.h>
#include <tcl.h>

int apol_level_to_tcl_obj(Tcl_Interp *interp, apol_mls_level_t *level, Tcl_Obj **obj) {
	Tcl_Obj *level_elem[2], *cats_obj;
	size_t i;
	level_elem[0] = Tcl_NewStringObj(level->sens, -1);
	level_elem[1] = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(level->cats); i++) {
		cats_obj = Tcl_NewStringObj((char *) apol_vector_get_element(level->cats, i), -1);
		if (Tcl_ListObjAppendElement(interp, level_elem[1], cats_obj) == TCL_ERROR) {
			return -1;
		}
	}
	*obj = Tcl_NewListObj(2, level_elem);
	return 0;
}

int apol_avrule_to_tcl_obj(Tcl_Interp *interp,
			   qpol_avrule_t *avrule,
			   Tcl_Obj **obj)
{
        uint32_t rule_type, is_enabled;
	const char *rule_string;
	qpol_type_t *source, *target;
	qpol_class_t *obj_class;
	qpol_iterator_t *perm_iter = NULL;
	char *source_name, *target_name, *obj_class_name;
	qpol_cond_t *cond;
	Tcl_Obj *avrule_elem[7], *cond_elem[2];
	int retval = TCL_ERROR;

	if (qpol_avrule_get_rule_type(policydb->qh, policydb->p, avrule, &rule_type) < 0 ||
	    qpol_avrule_get_source_type(policydb->qh, policydb->p, avrule, &source) < 0 ||
	    qpol_avrule_get_target_type(policydb->qh, policydb->p, avrule, &target) < 0 ||
	    qpol_avrule_get_object_class(policydb->qh, policydb->p, avrule, &obj_class) < 0 ||
	    qpol_avrule_get_perm_iter(policydb->qh, policydb->p, avrule, &perm_iter) < 0) {
		goto cleanup;
	}
	if ((rule_string = apol_rule_type_to_str(rule_type)) == NULL) {
		ERR(policydb, "Invalid avrule type %d.", rule_type);
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
		free(perm_name);
		if (Tcl_ListObjAppendElement(interp, avrule_elem[4], perm_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	avrule_elem[5] = Tcl_NewStringObj("", -1);   /* FIX ME! */
	if (qpol_avrule_get_cond(policydb->qh, policydb->p, avrule, &cond) < 0 ||
	    qpol_avrule_get_is_enabled(policydb->qh, policydb->p, avrule, &is_enabled) < 0) {
		goto cleanup;
	}
	if (cond == NULL) {
		avrule_elem[6] = Tcl_NewListObj(0, NULL);
	}
	else {
		cond_elem[0] = Tcl_NewStringObj(is_enabled ? "enabled" : "disabled", -1);
		cond_elem[1] = Tcl_NewStringObj("", -1);  /* FIX ME! */
		avrule_elem[6] = Tcl_NewListObj(2, cond_elem);
	}
	*obj = Tcl_NewListObj(7, avrule_elem);
        retval = TCL_OK;
 cleanup:
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

int apol_terule_to_tcl_obj(Tcl_Interp *interp,
			   qpol_terule_t *terule,
			   Tcl_Obj **obj)
{
	uint32_t rule_type, is_enabled;
	const char *rule_string;
	qpol_type_t *source, *target, *default_type;
	qpol_class_t *obj_class;
	char *source_name, *target_name, *obj_class_name, *default_name;
	qpol_cond_t *cond;
	Tcl_Obj *terule_elem[7], *cond_elem[2];
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
	*obj = Tcl_NewListObj(7, terule_elem);
	retval = TCL_OK;
 cleanup:
	return retval;
}

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
 * Take a Tcl string representing an AV rule identifier (relative to
 * the currently loaded policy) and return a Tcl list representation
 * of it:
 * <code>
 *    { rule_type source_type_set target_type_set object_class perm_set
 *      line_number cond_info }
 * </code>
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl string representing an av rule identifier
 * </ol>
 */
static int Apol_RenderAVRule(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *o, *result_obj;
	long rule_num;
	qpol_avrule_t *avrule;
	int retval = TCL_ERROR;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	o = Tcl_NewStringObj(argv[1], -1);
	if (Tcl_GetLongFromObj(interp, o, &rule_num) == TCL_ERROR) {
		goto cleanup;
	}
	avrule = (qpol_avrule_t *) rule_num;
	if (apol_avrule_to_tcl_obj(interp, avrule, &result_obj) == TCL_ERROR) {
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
 * Take a Tcl string representing an AV rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's source type.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl string representing an av rule identifier
 * </ol>
 */
static int Apol_RenderAVRuleSource(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *o;
	long rule_num;
	qpol_avrule_t *avrule;
	qpol_type_t *source;
	char *source_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	o = Tcl_NewStringObj(argv[1], -1);
	if (Tcl_GetLongFromObj(interp, o, &rule_num) == TCL_ERROR) {
		goto cleanup;
	}
	avrule = (qpol_avrule_t *) rule_num;
	if (qpol_avrule_get_source_type(policydb->qh, policydb->p, avrule, &source) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, source, &source_string) < 0) {
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
 * Take a Tcl string representing an AV rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's target type.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl string representing an av rule identifier
 * </ol>
 */
static int Apol_RenderAVRuleTarget(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *o;
	long rule_num;
	qpol_avrule_t *avrule;
	qpol_type_t *target;
	char *target_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	o = Tcl_NewStringObj(argv[1], -1);
	if (Tcl_GetLongFromObj(interp, o, &rule_num) == TCL_ERROR) {
		goto cleanup;
	}
	avrule = (qpol_avrule_t *) rule_num;
	if (qpol_avrule_get_target_type(policydb->qh, policydb->p, avrule, &target) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_string) < 0) {
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
 * Take a Tcl string representing an AV rule identifier (relative to
 * the currently loaded policy) and return the string representation
 * of that rule's object class.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl string representing an av rule identifier
 * </ol>
 */
static int Apol_RenderAVRuleClass(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *o;
	long rule_num;
	qpol_avrule_t *avrule;
	qpol_class_t *obj_class;
	char *obj_class_string;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	o = Tcl_NewStringObj(argv[1], -1);
	if (Tcl_GetLongFromObj(interp, o, &rule_num) == TCL_ERROR) {
		goto cleanup;
	}
	avrule = (qpol_avrule_t *) rule_num;
	if (qpol_avrule_get_object_class(policydb->qh, policydb->p, avrule, &obj_class) < 0 ||
	    qpol_class_get_name(policydb->qh, policydb->p, obj_class, &obj_class_string) < 0) {
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
 * Take a Tcl string representing an AV rule identifier (relative to
 * the currently loaded policy) and return a list of that rule's
 * permissions.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl string representing an av rule identifier
 * </ol>
 */
static int Apol_RenderAVRulePerms(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *o, *result_obj, *perm_obj;
	long rule_num;
	qpol_avrule_t *avrule;
	qpol_iterator_t *perm_iter = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	o = Tcl_NewStringObj(argv[1], -1);
	if (Tcl_GetLongFromObj(interp, o, &rule_num) == TCL_ERROR) {
		goto cleanup;
	}
	avrule = (qpol_avrule_t *) rule_num;
	if (qpol_avrule_get_perm_iter(policydb->qh, policydb->p, avrule, &perm_iter) < 0) {
		goto cleanup;
	}
	result_obj = Tcl_NewListObj(0, NULL);
	for ( ; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		char *perm_name;
		if (qpol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
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
 * Take a Tcl string representing a TE rule identifier (relative to
 * the currently loaded policy) and return a Tcl list representation
 * of it:
 * <code>
 *    { rule_type source_type_set target_type_set object_class default_type
 *      line_number cond_info }
 * </code>
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl string representing an te rule identifier
 * </ol>
 */
static int Apol_RenderTERule(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *o, *result_obj;
	long rule_num;
	qpol_terule_t *terule;
	int retval = TCL_ERROR;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need an avrule identifier.");
		goto cleanup;
	}
	o = Tcl_NewStringObj(argv[1], -1);
	if (Tcl_GetLongFromObj(interp, o, &rule_num) == TCL_ERROR) {
		goto cleanup;
	}
	terule = (qpol_terule_t *) rule_num;
	if (apol_terule_to_tcl_obj(interp, terule, &result_obj) == TCL_ERROR) {
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

int apol_tcl_render_init(Tcl_Interp *interp) {
        Tcl_CreateCommand(interp, "apol_RenderLevel", Apol_RenderLevel, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderContext", Apol_RenderContext, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderAVRule", Apol_RenderAVRule, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderAVRuleSource", Apol_RenderAVRuleSource, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderAVRuleTarget", Apol_RenderAVRuleTarget, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderAVRuleClass", Apol_RenderAVRuleClass, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderAVRulePerms", Apol_RenderAVRulePerms, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderTERule", Apol_RenderTERule, NULL, NULL);
	return TCL_OK;
}
