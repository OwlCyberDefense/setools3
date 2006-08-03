/**
 * @file apol_tcl_analysis.c
 * Implementation for the apol interface to analyze policy.
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

#include <tcl.h>
#include <errno.h>

/********* routines to manipulate an infoflow graph as a Tcl object *********/

/* Build a hashtable of infoflow graph handlers.  Code based upon
 * http://mini.net/tcl/13881, 'Creating and Using Tcl Handles in C
 * Extensions'.
 */
static Tcl_HashTable infoflow_htable;

static struct Tcl_ObjType infoflow_tcl_obj_type = {
	"infoflow",
	NULL,
	NULL,
	NULL,
	NULL
};
typedef struct infoflow_tcl {
	Tcl_Obj *obj;
	Tcl_HashEntry *hash;
	apol_infoflow_graph_t *g;
} infoflow_tcl_t;

static int infoflow_graph_count = 0;
static int infoflow_graph_epoch = 0;

/**
 * Given an apol_infoflow_graph_t object, add it to the global
 * hashtable and create a new Tcl_Obj with a handle to that graph.
 * The Tcl_Obj will have a unique string identifier for the graph.
 *
 * @param interp Tcl interpreter object.
 * @param g Infoflow graph to store.
 * @param o Reference to where to create the new Tcl_Obj.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 *
 * @see Treating the graph as a Tcl object handler is based upon the
 * code at http://mini.net/tcl/13881.
 */
static int apol_infoflow_graph_to_tcl_obj(Tcl_Interp *interp, apol_infoflow_graph_t *g, Tcl_Obj **o)
{
	char s[1], *handle_name;
	int num_bytes, new_entry;
	infoflow_tcl_t *infoflow_tcl;
	Tcl_HashEntry *entry;

	infoflow_tcl = (infoflow_tcl_t *) ckalloc(sizeof(*infoflow_tcl));

	num_bytes = snprintf(s, 1, "infoflow%d", infoflow_graph_count) + 1;
	handle_name = ckalloc(num_bytes);
	snprintf(handle_name, num_bytes, "infoflow%d", infoflow_graph_count++);
	*o = Tcl_NewStringObj(handle_name, -1);
	(*o)->typePtr = &infoflow_tcl_obj_type;
	(*o)->internalRep.twoPtrValue.ptr1 = infoflow_tcl;
	(*o)->internalRep.twoPtrValue.ptr2 = (void *) infoflow_graph_epoch;

	infoflow_tcl->obj = *o;
	infoflow_tcl->g = g;
	entry = Tcl_CreateHashEntry(&infoflow_htable, handle_name, &new_entry);
	infoflow_tcl->hash = entry;
	Tcl_SetHashValue(entry, infoflow_tcl);
	ckfree(handle_name);
	return TCL_OK;
}

/**
 * Given a Tcl object, retrieve the infoflow_tcl_t stored within.  If
 * the object is not already an infoflow_tcl_obj_type or if its cache
 * has been marked as invalid, shimmer it to an infoflow_tcl_obj_type,
 * fetch the graph from the hash table, and then update the object's
 * cache.
 *
 * @param interp Tcl interpreter object.
 * @param o Tcl object from which to get infoflow_tcl_t.
 * @param i Reference to where to write result.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 */
static int tcl_obj_to_infoflow_tcl(Tcl_Interp *interp, Tcl_Obj *o, infoflow_tcl_t **i)
{
	if (o->typePtr != &infoflow_tcl_obj_type ||
	    (int) o->internalRep.twoPtrValue.ptr2 != infoflow_graph_epoch) {
		char *name;
		Tcl_HashEntry *entry;
		name = Tcl_GetString(o);
		entry = Tcl_FindHashEntry(&infoflow_htable, name);
		if (entry == NULL) {
			Tcl_SetResult(interp, "Invalid infoflow_tcl object.", TCL_STATIC);
			return TCL_ERROR;
		}
		*i = Tcl_GetHashValue(entry);
		/* shimmer the object back to an infoflow_tcl */
		o->typePtr = &infoflow_tcl_obj_type;
		o->internalRep.twoPtrValue.ptr1 = *i;
		o->internalRep.twoPtrValue.ptr2 = (void *) infoflow_graph_epoch;
	}
	else {
		*i = (infoflow_tcl_t *) o->internalRep.twoPtrValue.ptr1;
	}
	return TCL_OK;
}

/**
 * Destroy the infoflow_graph stored within an infoflow_tcl_t object
 * and remove its entry from the global hash table.  Then invalidate
 * all other Tcl_Objs caches.
 *
 * @param i Infoflow_tcl_t object to free.
 */
static void infoflow_tcl_free(infoflow_tcl_t *i)
{
	apol_infoflow_graph_t *g = i->g;
	apol_infoflow_graph_destroy(&g);
	Tcl_DeleteHashEntry(i->hash);
	ckfree((char *) i);
	/* now invalidate all cached infoflow_tcl_t pointers stored
	 * within Tcl_Objs */
	infoflow_graph_epoch++;
}

/**
 * For the given symbol, expand it if an attribute, or return the
 * symbol otherwise.
 *
 * @param argv This fuction takes one parameter:
 * <ol>
 *   <li>symbol to expand
 * </ol>
 *
 */
static int Apol_ExpandType(ClientData clientData, Tcl_Interp *interp,
			   int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL), *o;
	qpol_type_t *type;
	unsigned char isattr;
	char *type_name;
	qpol_iterator_t *iter = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a type symbol.");
		goto cleanup;
	}
	if (qpol_policy_get_type_by_name(policydb->qh, policydb->p, argv[1], &type) < 0 ||
	    qpol_type_get_isattr(policydb->qh, policydb->p, type, &isattr) < 0) {
		goto cleanup;
	}
	if (!isattr) {
		if (qpol_type_get_name(policydb->qh, policydb->p, type, &type_name) < 0) {
			goto cleanup;
		}
		result_obj = Tcl_NewStringObj(type_name, -1);
	}
	else {
		if (qpol_type_get_type_iter(policydb->qh, policydb->p, type, &iter) < 0) {
			goto cleanup;
		}
		for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **) &type) < 0 ||
			    qpol_type_get_name(policydb->qh, policydb->p, type, &type_name) < 0) {
				goto cleanup;
			}
			o = Tcl_NewStringObj(type_name, -1);
			if (Tcl_ListObjAppendElement(interp, result_obj, o) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	qpol_iterator_destroy(&iter);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * For the given object class, return an unsorted list of its
 * permissions, including those that the class inherits from its
 * common.
 *
 * @param argv This fuction takes one parameter:
 * <ol>
 *   <li>class from which to get permissions
 * </ol>
 *
 */
static int Apol_GetAllPermsForClass(ClientData clientData, Tcl_Interp *interp,
				    int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_class_t *obj_class;
	qpol_common_t *common;
	qpol_iterator_t *perm_iter = NULL, *common_iter = NULL;
	char *perm;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a class name.");
		goto cleanup;
	}
	if (qpol_policy_get_class_by_name(policydb->qh, policydb->p, argv[1], &obj_class) < 0 ||
	    qpol_class_get_common(policydb->qh, policydb->p, obj_class, &common) < 0 ||
	    qpol_class_get_perm_iter(policydb->qh, policydb->p, obj_class, &perm_iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		if (qpol_iterator_get_item(perm_iter, (void **) &perm) < 0) {
				goto cleanup;
		}
		Tcl_Obj *o = Tcl_NewStringObj(perm, -1);
		if (Tcl_ListObjAppendElement(interp, result_obj, o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	if (common != NULL) {
		if (qpol_common_get_perm_iter(policydb->qh, policydb->p, common, &common_iter) < 0) {
			goto cleanup;
		}
		for ( ; !qpol_iterator_end(common_iter); qpol_iterator_next(common_iter)) {
			if (qpol_iterator_get_item(common_iter, (void **) &perm) < 0) {
				goto cleanup;
			}
			Tcl_Obj *o = Tcl_NewStringObj(perm, -1);
			if (Tcl_ListObjAppendElement(interp, result_obj, o) == TCL_ERROR) {
				goto cleanup;
			}
		}
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	qpol_iterator_destroy(&perm_iter);
	qpol_iterator_destroy(&common_iter);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Convert an apol vector of pointers to a Tcl representation.
 *
 * @param interp Tcl interpreter object.
 * @param v Apol vector to convert.
 * @param obj Destination to create Tcl list.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_vector_to_tcl_list(Tcl_Interp *interp,
				   apol_vector_t *v,
				   Tcl_Obj **obj)
{
	size_t i;
	*obj = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		void *p = apol_vector_get_element(v, i);
		Tcl_Obj *o = Tcl_NewLongObj((long) p);
		if (Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			return -1;
		}
	}
	return 0;
}

/**
 * Take a result node from a domain transition analysis and append a
 * tuple of it to result_list.  The tuple consists of:
 * <code>
 *   { source_type target_type entrypoint_type
 *     proctrans_rules entrypoint_rules execute_rules
 *     setexec_rules type_trans_rules access_ruless }
 * </code>
 */
static int append_domain_trans_result_to_list(Tcl_Interp *interp,
					       apol_domain_trans_result_t *result,
					       Tcl_Obj *result_list)
{
	Tcl_Obj *dta_elem[9], *dta_list;
	qpol_type_t *source, *target, *entry;
	char *source_name, *target_name, *entry_name;
	apol_vector_t *proctrans, *entrypoint, *execute,
		*setexec, *type_trans, *access_rules;
	int retval = TCL_ERROR;

	source = apol_domain_trans_result_get_start_type(result);
	target = apol_domain_trans_result_get_end_type(result);
	entry =	 apol_domain_trans_result_get_entrypoint_type(result);
	proctrans = apol_domain_trans_result_get_proc_trans_rules(result);
	entrypoint = apol_domain_trans_result_get_entrypoint_rules(result);
	execute = apol_domain_trans_result_get_exec_rules(result);
	if (qpol_type_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, entry, &entry_name) < 0) {
		goto cleanup;
	}
	dta_elem[0] = Tcl_NewStringObj(source_name, -1);
	dta_elem[1] = Tcl_NewStringObj(target_name, -1);
	dta_elem[2] = Tcl_NewStringObj(entry_name, -1);
	if (apol_vector_to_tcl_list(interp, proctrans, dta_elem + 3) == TCL_ERROR ||
	    apol_vector_to_tcl_list(interp, entrypoint, dta_elem + 4) == TCL_ERROR ||
	    apol_vector_to_tcl_list(interp, execute, dta_elem + 5) == TCL_ERROR) {
		goto cleanup;
	}
	if ((setexec = apol_domain_trans_result_get_setexec_rules(result)) == NULL) {
		dta_elem[6] = Tcl_NewListObj(0, NULL);
	}
	else if (apol_vector_to_tcl_list(interp, setexec, dta_elem + 6) == TCL_ERROR) {
		goto cleanup;
	}
	if ((type_trans = apol_domain_trans_result_get_type_trans_rules(result)) == NULL) {
		dta_elem[7] = Tcl_NewListObj(0, NULL);
	}
	else if (apol_vector_to_tcl_list(interp, type_trans, dta_elem + 7) == TCL_ERROR) {
		goto cleanup;
	}
	if ((access_rules = apol_domain_trans_result_get_access_rules(result)) == NULL) {
		dta_elem[8] = Tcl_NewListObj(0, NULL);
	}
	else if (apol_vector_to_tcl_list(interp, access_rules, dta_elem + 8) == TCL_ERROR) {
		goto cleanup;
	}
	dta_list = Tcl_NewListObj(9, dta_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, dta_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return an unsorted list of result tuples for a domain transition
 * analysis.  Each tuple consists of:
 * <ul>
 *   <li>source type for the transition
 *   <li>resulting target type of the transition
 *   <li>entrypoint type of the transition
 *   <li>list of AV rule that allows the source type to transition to
 *       target type
 *   <li>list AV rule that allows a file entrypoint from the
 *       entrypoint type
 *   <li>list of AV rule that allows the source to execute the
 *       entrypoint type
 *   <li>list of setexec that permit the domain to transition (could
 *       be empty list)
 *   <li>list of type transition rules that perform the transition
 *       (could be empty list)
 *   <li>list of AV rules that satisfy the access filters (could be
 *       empty list)
 * </ul>
 *
 * Rules are unique identifiers (relative to currently loaded policy).
 * Call [apol_RenderAVRule] to display them.
 *
 * @param argv This fuction takes five parameters:
 * <ol>
 *   <li>analysis mode, one of "forward" or "reverse"
 *   <li>starting type (string)
 *   <li>list of object types, or an empty list to consider all types
 *   <li>list of class/perm pairs, or an empty list to consider all
 *       classes/perms
 *   <li>regular expression for resulting types, or empty string to accept all
 * </ol>
 *
 * Note that the list of object types and list of class/perm pairs are
 * ignored if the analysis mode is "reverse".
 */
static int Apol_DomainTransitionAnalysis(ClientData clientData, Tcl_Interp *interp,
					 int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	apol_domain_trans_result_t *result = NULL;
	apol_vector_t *v = NULL;
	apol_domain_trans_analysis_t *analysis = NULL;
	int direction, num_opts;
	CONST char **targets_strings = NULL, **classperm_strings = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 6) {
		ERR(policydb, "%s", "Need an analysis mode, starting type, object types, class/perm pairs, and result regex.");
		goto cleanup;
	}

	if ((analysis = apol_domain_trans_analysis_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (strcmp(argv[1], "forward") == 0) {
		direction = APOL_DOMAIN_TRANS_DIRECTION_FORWARD;
	}
	else if (strcmp(argv[1], "reverse") == 0) {
		direction = APOL_DOMAIN_TRANS_DIRECTION_REVERSE;
	}
	else {
		ERR(policydb, "Invalid domain transition mode %s.", argv[1]);
		goto cleanup;
	}
	if (apol_domain_trans_analysis_set_direction(policydb, analysis, direction) < 0 ||
	    apol_domain_trans_analysis_set_start_type(policydb, analysis, argv[2]) < 0 ||
	    apol_domain_trans_analysis_set_result_regex(policydb, analysis, argv[5])) {
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[3], &num_opts, &targets_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = targets_strings[num_opts];
		if (apol_domain_trans_analysis_append_access_type(policydb, analysis, s) < 0) {
			goto cleanup;
		}
	}

	if (Tcl_SplitList(interp, argv[4], &num_opts, &classperm_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = classperm_strings[num_opts];
		Tcl_Obj *cp_obj = Tcl_NewStringObj(s, -1), **cp;
		int obj_count;
		if (Tcl_ListObjGetElements(interp, cp_obj, &obj_count, &cp) == TCL_ERROR) {
			goto cleanup;
		}
		if (obj_count != 2) {
			ERR(policydb, "Not a class/perm pair: %s", s);
			goto cleanup;
		}
		if (apol_domain_trans_analysis_append_class_perm
		    (policydb, analysis, Tcl_GetString(cp[0]), Tcl_GetString(cp[1])) < 0) {
			goto cleanup;
		}
	}

	apol_domain_trans_table_reset(policydb);
	if (apol_domain_trans_analysis_do(policydb, analysis, &v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		result = (apol_domain_trans_result_t *) apol_vector_get_element(v, i);
		if (append_domain_trans_result_to_list(interp, result, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	if (targets_strings != NULL) {
		Tcl_Free((char *) targets_strings);
	}
	if (classperm_strings != NULL) {
		Tcl_Free((char *) classperm_strings);
	}
	apol_domain_trans_analysis_destroy(&analysis);
	apol_vector_destroy(&v, apol_domain_trans_result_free);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a result node from a direct information flow analysis and
 * append a tuple of it to result_list.  The tuple consists of:
 * <code>
 *   { flow_direction  source_type  target_type  list_of_rules }
 * </code>
 */
static int append_direct_infoflow_result_to_list(Tcl_Interp *interp,
						 apol_infoflow_result_t *result,
						 Tcl_Obj *result_list)
{
	Tcl_Obj *direct_elem[4], *direct_list;
	unsigned int dir;
	qpol_type_t *source, *target;
	char *dir_str, *source_name, *target_name;
	apol_vector_t *steps, *rules;
	apol_infoflow_step_t *step;
	int retval = TCL_ERROR;

	dir = apol_infoflow_result_get_dir(result);
	source = apol_infoflow_result_get_start_type(result);
	target = apol_infoflow_result_get_end_type(result);
	steps = apol_infoflow_result_get_steps(result);
	step = (apol_infoflow_step_t *) apol_vector_get_element(steps, 0);
	rules = apol_infoflow_step_get_rules(step);
	switch (dir) {
	case APOL_INFOFLOW_IN: dir_str = "in"; break;
	case APOL_INFOFLOW_OUT: dir_str = "out"; break;
	case APOL_INFOFLOW_BOTH: dir_str = "both"; break;
	default:
		Tcl_SetResult(interp, "Illegal flow direction.", TCL_STATIC);
		goto cleanup;
	}
	if (qpol_type_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0) {
		goto cleanup;
	}
	direct_elem[0] = Tcl_NewStringObj(dir_str, -1);
	direct_elem[1] = Tcl_NewStringObj(source_name, -1);
	direct_elem[2] = Tcl_NewStringObj(target_name, -1);
	if (apol_vector_to_tcl_list(interp, rules, direct_elem + 3) == TCL_ERROR) {
		goto cleanup;
	}
	direct_list = Tcl_NewListObj(4, direct_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, direct_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return a infoflow_tcl object and a list containing an infoflow_tcl
 * object followed by results for a direct information flow analysis.
 * The infoflow_tcl object is a pointer to the infoflow graph that was
 * constructed for this query; it may be used as a parameter to
 * Apol_DirectInformationFlowMore().  Each result tuple consists of:
 *
 * <ul>
 *   <li>direction of flow, one of "in", "out", or "both"
 *   <li>source type for flow
 *   <li>target type for flow
 *   <li>list of AV rules that permit information flow
 * </ul>
 * Rules are unique identifiers (relative to currently loaded policy).
 * Call [apol_RenderAVRule] to display them.
 *
 * @param argv This fuction takes four parameters:
 * <ol>
 *   <li>flow direction, one of "in", "out", "either", or "both"
 *   <li>starting type (string)
 *   <li>list of class/perm pairs, or an empty list to consider all
 *       classes/perms
 *   <li>regular expression for resulting types, or empty string to accept all
 * </ol>
 */
static int Apol_DirectInformationFlowAnalysis(ClientData clientData, Tcl_Interp *interp,
					      int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL), *graph_obj;
	apol_infoflow_result_t *result = NULL;
	apol_vector_t *v = NULL;
	apol_infoflow_graph_t *g = NULL;
	apol_infoflow_analysis_t *analysis = NULL;
	int direction, num_opts;
	CONST char **class_strings = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 5) {
		ERR(policydb, "%s", "Need a flow direction, starting type, object classes, and resulting type regex.");
		goto cleanup;
	}

	if (strcmp(argv[1], "in") == 0) {
		direction = APOL_INFOFLOW_IN;
	}
	else if (strcmp(argv[1], "out") == 0) {
		direction = APOL_INFOFLOW_OUT;
	}
	else if (strcmp(argv[1], "either") == 0) {
		direction = APOL_INFOFLOW_EITHER;
	}
	else if (strcmp(argv[1], "both") == 0) {
		direction = APOL_INFOFLOW_BOTH;
	}
	else {
		ERR(policydb, "Invalid direct infoflow direction %s.", argv[1]);
		goto cleanup;
	}

	if ((analysis = apol_infoflow_analysis_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (apol_infoflow_analysis_set_mode(policydb, analysis, APOL_INFOFLOW_MODE_DIRECT) < 0 ||
	    apol_infoflow_analysis_set_dir(policydb, analysis, direction) < 0 ||
	    apol_infoflow_analysis_set_type(policydb, analysis, argv[2]) < 0 ||
	    apol_infoflow_analysis_set_result_regex(policydb, analysis, argv[4])) {
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[3], &num_opts, &class_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = class_strings[num_opts];
		Tcl_Obj *cp_obj = Tcl_NewStringObj(s, -1), **cp;
		int obj_count;
		if (Tcl_ListObjGetElements(interp, cp_obj, &obj_count, &cp) == TCL_ERROR) {
			goto cleanup;
		}
		if (obj_count != 2) {
			ERR(policydb, "Not a class/perm pair: %s", s);
			goto cleanup;
		}
		if (apol_infoflow_analysis_append_class_perm
		    (policydb, analysis, Tcl_GetString(cp[0]), Tcl_GetString(cp[1])) < 0) {
			goto cleanup;
		}
	}

	if (apol_infoflow_analysis_do(policydb, analysis, &v, &g) < 0) {
		goto cleanup;
	}
	if (apol_infoflow_graph_to_tcl_obj(interp, g, &graph_obj) ||
	    Tcl_ListObjAppendElement(interp, result_obj, graph_obj) == TCL_ERROR) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		result = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		if (append_direct_infoflow_result_to_list(interp, result, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	if (class_strings != NULL) {
		Tcl_Free((char *) class_strings);
	}
	apol_infoflow_analysis_destroy(&analysis);
	apol_vector_destroy(&v, apol_infoflow_result_free);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Perform additional analysis upon a pre-existing direct information
 * flow graph, returning an unsorted list of result tuples.  The
 * analysis will use the same parameters as those that were used to
 * construct the graph.
 *
 * @param argv This fuction takes two parameters:
 * <ol>
 *   <li>handler to an existing direct information flow graph
 *   <li>starting type (string)
 * </ol>
 */
static int Apol_DirectInformationFlowMore(ClientData clientData, Tcl_Interp *interp,
					  int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL), *graph_obj;
	infoflow_tcl_t *i_t;
	apol_infoflow_graph_t *g = NULL;
	apol_infoflow_result_t *result = NULL;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 3) {
		ERR(policydb, "%s", "Need an infoflow graph handler and a starting type.");
		goto cleanup;
	}
	graph_obj = Tcl_NewStringObj(argv[1], -1);
	if (tcl_obj_to_infoflow_tcl(interp, graph_obj, &i_t) == TCL_ERROR) {
		goto cleanup;
	}
	g = i_t->g;
	if (apol_infoflow_analysis_do_more(policydb, g, argv[2], &v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		result = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		if (append_direct_infoflow_result_to_list(interp, result, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_vector_destroy(&v, apol_infoflow_result_free);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a result node from a transitive information flow analysis and
 * append a tuple of it to result_list.  The tuple consists of:
 * <code>
 *   { flow_dir  source_type  target_type  length  list_of_steps }
 * </code>
 *
 * A path consists of a list of steps; each steps has a list of rules.
 */
static int append_trans_infoflow_result_to_list(Tcl_Interp *interp,
						apol_infoflow_result_t *result,
						Tcl_Obj *result_list)
{
	Tcl_Obj *trans_elem[5], *trans_list, *step_elem[4], *step_list;
	unsigned int dir, length;
	qpol_type_t *source, *target;
	char *dir_str, *source_name, *target_name;
	apol_vector_t *steps, *rules;
	size_t i;
	apol_infoflow_step_t *step;
	int weight, retval = TCL_ERROR;

	dir = apol_infoflow_result_get_dir(result);
	source = apol_infoflow_result_get_start_type(result);
	target = apol_infoflow_result_get_end_type(result);
	length = apol_infoflow_result_get_length(result);
	steps = apol_infoflow_result_get_steps(result);
	switch (dir) {
	case APOL_INFOFLOW_IN: dir_str = "to"; break;
	case APOL_INFOFLOW_OUT: dir_str = "from"; break;
	default:
		Tcl_SetResult(interp, "Illegal flow direction.", TCL_STATIC);
		goto cleanup;
	}
	if (qpol_type_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0) {
		goto cleanup;
	}
	trans_elem[0] = Tcl_NewStringObj(dir_str, -1);
	trans_elem[1] = Tcl_NewStringObj(source_name, -1);
	trans_elem[2] = Tcl_NewStringObj(target_name, -1);
	trans_elem[3] = Tcl_NewIntObj(length);
	trans_elem[4] = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(steps); i++) {
		step = (apol_infoflow_step_t *) apol_vector_get_element(steps, i);
		source = apol_infoflow_step_get_start_type(step);
		target = apol_infoflow_step_get_end_type(step);
		weight = apol_infoflow_step_get_weight(step);
		rules = apol_infoflow_step_get_rules(step);
		if (qpol_type_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
		    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0) {
			goto cleanup;
		}
		step_elem[0] = Tcl_NewStringObj(source_name, -1);
		step_elem[1] = Tcl_NewStringObj(target_name, -1);
		step_elem[2] = Tcl_NewIntObj(weight);
		if (apol_vector_to_tcl_list(interp, rules, step_elem + 3) == TCL_ERROR) {
			goto cleanup;
		}
		step_list = Tcl_NewListObj(4, step_elem);
		if (Tcl_ListObjAppendElement(interp, trans_elem[4], step_list) == TCL_ERROR) {
			goto cleanup;
		}
	}
	trans_list = Tcl_NewListObj(5, trans_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, trans_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return a infoflow_tcl object and a list containing an infoflow_tcl
 * object followed by results for a transitive information flow
 * analysis.  The infoflow_tcl object is a pointer to the infoflow
 * graph that was constructed for this query; it may be used as a
 * parameter to Apol_TransInformationFlowMore().  Each result tuple
 * consists of:
 *
 * <ul>
 *   <li>direction of flow, one of "to" or "from"
 *   <li>source type for flow
 *   <li>target type for flow
 *   <li>length of flow
 *   <li>list of steps
 * </ul>
 *
 * Each step consists of:
 *
 * <ul>
 *   <li>start type for this step
 *   <li>end type for this step
 *   <li>weight of this step
 *   <li>list of rules that permit access from start type to end type
 * </ul>
 * Rules are unique identifiers (relative to currently loaded policy).
 * Call [apol_RenderAVRule] to display them.
 *
 * @param argv This fuction takes four parameters:
 * <ol>
 *   <li>flow direction, one of "to" or "from"
 *   <li>starting type (string)
 *   <li>list of allowable intermediate types, or empty list to accept all
 *   <li>list of allowable class/perm pairs, or an empty list to accept all
 *   <li>regular expression for resulting types, or empty string to accept all
 * </ol>
 */
static int Apol_TransInformationFlowAnalysis(ClientData clientData, Tcl_Interp *interp,
					      int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL), *graph_obj;
	apol_infoflow_result_t *result = NULL;
	apol_vector_t *v = NULL;
	apol_infoflow_graph_t *g = NULL;
	apol_infoflow_analysis_t *analysis = NULL;
	int direction, num_opts;
	CONST char **intermed_strings = NULL, **classperm_strings = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 6) {
		ERR(policydb, "%s", "Need a flow direction, starting type, intermediate types, class/perm pairs, and resulting type regex.");
		goto cleanup;
	}

	if (strcmp(argv[1], "to") == 0) {
		direction = APOL_INFOFLOW_IN;
	}
	else if (strcmp(argv[1], "from") == 0) {
		direction = APOL_INFOFLOW_OUT;
	}
	else {
		ERR(policydb, "Invalid trans infoflow direction %s.", argv[1]);
		goto cleanup;
	}

	if ((analysis = apol_infoflow_analysis_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (apol_infoflow_analysis_set_mode(policydb, analysis, APOL_INFOFLOW_MODE_TRANS) < 0 ||
	    apol_infoflow_analysis_set_dir(policydb, analysis, direction) < 0 ||
	    apol_infoflow_analysis_set_type(policydb, analysis, argv[2]) < 0 ||
	    apol_infoflow_analysis_set_result_regex(policydb, analysis, argv[5])) {
		goto cleanup;
	}
	if (Tcl_SplitList(interp, argv[3], &num_opts, &intermed_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = intermed_strings[num_opts];
		if (apol_infoflow_analysis_append_intermediate(policydb, analysis, s) < 0) {
			goto cleanup;
		}
	}

	if (Tcl_SplitList(interp, argv[4], &num_opts, &classperm_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = classperm_strings[num_opts];
		Tcl_Obj *cp_obj = Tcl_NewStringObj(s, -1), **cp;
		int obj_count;
		if (Tcl_ListObjGetElements(interp, cp_obj, &obj_count, &cp) == TCL_ERROR) {
			goto cleanup;
		}
		if (obj_count != 2) {
			ERR(policydb, "Not a class/perm pair: %s", s);
			goto cleanup;
		}
		if (apol_infoflow_analysis_append_class_perm
		    (policydb, analysis, Tcl_GetString(cp[0]), Tcl_GetString(cp[1])) < 0) {
			goto cleanup;
		}
	}

	if (apol_infoflow_analysis_do(policydb, analysis, &v, &g) < 0) {
		goto cleanup;
	}
	if (apol_infoflow_graph_to_tcl_obj(interp, g, &graph_obj) ||
	    Tcl_ListObjAppendElement(interp, result_obj, graph_obj) == TCL_ERROR) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		result = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		if (append_trans_infoflow_result_to_list(interp, result, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	if (intermed_strings != NULL) {
		Tcl_Free((char *) intermed_strings);
	}
	if (classperm_strings != NULL) {
		Tcl_Free((char *) classperm_strings);
	}
	apol_infoflow_analysis_destroy(&analysis);
	apol_vector_destroy(&v, apol_infoflow_result_free);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Perform additional analysis upon a pre-existing transitive
 * information flow graph, returning an unsorted list of result
 * tuples.  The analysis will use the same parameters as those that
 * were used to construct the graph.
 *
 * @param argv This fuction takes two parameters:
 * <ol>
 *   <li>handler to an existing transitive information flow graph
 *   <li>starting type (string)
 * </ol>
 */
static int Apol_TransInformationFlowMore(ClientData clientData, Tcl_Interp *interp,
					 int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL), *graph_obj;
	infoflow_tcl_t *i_t;
	apol_infoflow_graph_t *g = NULL;
	apol_infoflow_result_t *result = NULL;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 3) {
		ERR(policydb, "%s", "Need an infoflow graph handler and a starting type.");
		goto cleanup;
	}
	graph_obj = Tcl_NewStringObj(argv[1], -1);
	if (tcl_obj_to_infoflow_tcl(interp, graph_obj, &i_t) == TCL_ERROR) {
		goto cleanup;
	}
	g = i_t->g;
	if (apol_infoflow_analysis_do_more(policydb, g, argv[2], &v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		result = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		if (append_trans_infoflow_result_to_list(interp, result, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_vector_destroy(&v, apol_infoflow_result_free);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Prepare a pre-existing transitive information flow analysis to
 * perform further analysis of a particular start and end nodes.  The
 * analysis will use the same parameters as those that were used to
 * construct the graph.
 *
 * @param argv This fuction takes three parameters:
 * <ol>
 *   <li>handler to an existing transitive information flow graph
 *   <li>starting type (string)
 *   <li>ending type (string)
 * </ol>
 */
static int Apol_TransInformationFurtherPrepare(ClientData clientData, Tcl_Interp *interp,
					       int argc, CONST char *argv[])
{
	Tcl_Obj *graph_obj;
	infoflow_tcl_t *i_t;
	apol_infoflow_graph_t *g = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 4) {
		ERR(policydb, "%s", "Need a transitive infoflow graph handler, starting type, and ending type.");
		goto cleanup;
	}
	graph_obj = Tcl_NewStringObj(argv[1], -1);
	if (tcl_obj_to_infoflow_tcl(interp, graph_obj, &i_t) == TCL_ERROR) {
		goto cleanup;
	}
	g = i_t->g;
	if (apol_infoflow_analysis_trans_further_prepare(policydb, g, argv[2], argv[3]) < 0) {
		goto cleanup;
	}
	Tcl_SetResult(interp, "", TCL_STATIC);
	retval = TCL_OK;
 cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Obtain some more results from a prepare transitive information flow
 * graph.  The analysis will use the same parameters as those that
 * were used to construct the graph.
 *
 * @param argv This fuction takes one parameters:
 * <ol>
 *   <li>handler to an existing transitive information flow graph
 * </ol>
 */
static int Apol_TransInformationFurtherNext(ClientData clientData, Tcl_Interp *interp,
					    int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL), *graph_obj;
	infoflow_tcl_t *i_t;
	apol_infoflow_graph_t *g = NULL;
	apol_infoflow_result_t *result = NULL;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a prepared infoflow graph handler.");
		goto cleanup;
	}
	graph_obj = Tcl_NewStringObj(argv[1], -1);
	if (tcl_obj_to_infoflow_tcl(interp, graph_obj, &i_t) == TCL_ERROR) {
		goto cleanup;
	}
	g = i_t->g;
	if ((v = apol_vector_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_infoflow_analysis_trans_further_next(policydb, g, v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		result = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		if (append_trans_infoflow_result_to_list(interp, result, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_vector_destroy(&v, apol_infoflow_result_free);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Destroy the information flow graph stored within a Tcl object
 * handler.  It is an error to repeatedly destroy the same graph.
 *
 * @param argv This fuction takes one parameters:
 * <ol>
 *   <li>handle to the infoflow graph
 * </ol>
 */
static int Apol_InformationFlowDestroy(ClientData clientData, Tcl_Interp *interp,
				       int argc, CONST char *argv[])
{
	Tcl_Obj *o;
	infoflow_tcl_t *i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (argc != 2) {
		ERR(policydb, "%s", "Need an infoflow graph handler.");
		goto cleanup;
	}
	o = Tcl_NewStringObj(argv[1], -1);
	if (tcl_obj_to_infoflow_tcl(interp, o, &i) == TCL_ERROR) {
		goto cleanup;
	}
	infoflow_tcl_free(i);
	retval = TCL_OK;
 cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a result node from a relabel analysis and append a tuple of it
 * to result_list.  The tuple consists of:
 * <code>
 *   { to_rules  from_rules  both_rules }
 * </code>
 */
static int append_relabel_result_to_list(Tcl_Interp *interp,
                                         apol_relabel_result_t *result,
                                         Tcl_Obj *result_list)
{
	Tcl_Obj *relabel_elem[3], *relabel_list;
	int retval = TCL_ERROR;

	if (apol_vector_to_tcl_list(interp, apol_relabel_result_get_to(result), relabel_elem + 0) < 0 ||
	    apol_vector_to_tcl_list(interp, apol_relabel_result_get_from(result), relabel_elem + 1) < 0 ||
	    apol_vector_to_tcl_list(interp, apol_relabel_result_get_both(result), relabel_elem + 2) < 0) {
		goto cleanup;
	}
	relabel_list = Tcl_NewListObj(3, relabel_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, relabel_list) == TCL_ERROR) {
	    goto cleanup;
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Return an unsorted list of result tuples for a relabel analysis.
 * Each tuple consists of:
 * <ul>
 *   <li>list of rules to which can be relabeled
 *   <li>list of rules from which can be relabeled
 *   <li>list of rules that can be relabeled to and from
 * </ul>
 * Note that for subject mode searches, this list will have exactly
 * one result tuple.
 *
 * Rules are unique identifiers (relative to currently loaded policy).
 * Call [apol_RenderAVRule] to display them.
 *
 * @param argv This fuction takes five parameters:
 * <ol>
 *   <li>analysis mode, one of "to", "from", "both", or "subject"
 *   <li>starting type (string)
 *   <li>list of object classes to include
 *   <li>list of subject types to include
 *   <li>regular expression for resulting types, or empty string to accept all
 * </ol>
 */
static int Apol_RelabelAnalysis(ClientData clientData, Tcl_Interp *interp,
                                int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	apol_relabel_result_t *result = NULL;
	apol_vector_t *v = NULL;
	apol_relabel_analysis_t *analysis = NULL;
	int direction, num_opts;
	CONST char **class_strings = NULL, **subject_strings = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 6) {
		ERR(policydb, "%s", "Need an analysis mode, starting type, object classes, subject types, and resulting type regex.");
		goto cleanup;
	}

	if (strcmp(argv[1], "to") == 0) {
		direction = APOL_RELABEL_DIR_TO;
	}
	else if (strcmp(argv[1], "from") == 0) {
		direction = APOL_RELABEL_DIR_FROM;
	}
	else if (strcmp(argv[1], "both") == 0) {
		direction = APOL_RELABEL_DIR_BOTH;
	}
	else if (strcmp(argv[1], "subject") == 0) {
		direction = APOL_RELABEL_DIR_SUBJECT;
	}
	else {
		ERR(policydb, "Invalid relabel mode %s.", argv[1]);
		goto cleanup;
	}

        if ((analysis = apol_relabel_analysis_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (apol_relabel_analysis_set_dir(policydb, analysis, direction) < 0 ||
	    apol_relabel_analysis_set_type(policydb, analysis, argv[2]) < 0 ||
	    apol_relabel_analysis_set_result_regex(policydb, analysis, argv[5])) {
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[3], &num_opts, &class_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = class_strings[num_opts];
		if (apol_relabel_analysis_append_class(policydb, analysis, s) < 0) {
			goto cleanup;
		}
	}

	if (Tcl_SplitList(interp, argv[4], &num_opts, &subject_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = subject_strings[num_opts];
		if (apol_relabel_analysis_append_subject(policydb, analysis, s) < 0) {
			goto cleanup;
		}
	}

	if (apol_relabel_analysis_do(policydb, analysis, &v) < 0) {
                goto cleanup;
        }
	for (i = 0; i < apol_vector_get_size(v); i++) {
		result = (apol_relabel_result_t *) apol_vector_get_element(v, i);
		if (append_relabel_result_to_list(interp, result, result_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	if (class_strings != NULL) {
		Tcl_Free((char *) class_strings);
	}
	if (subject_strings != NULL) {
		Tcl_Free((char *) subject_strings);
	}
	apol_relabel_analysis_destroy(&analysis);
	apol_vector_destroy(&v, apol_relabel_result_free);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Given a result object from a two types relationship analysis,
 * create a new Tcl list containing the names of common attributes.
 */
static int apol_types_relation_attribs_to_tcl_list(Tcl_Interp *interp,
						   apol_types_relation_result_t *r,
						   Tcl_Obj **o)
{
	apol_vector_t *v = apol_types_relation_result_get_attributes(r);
	*o = Tcl_NewListObj(0, NULL);
	size_t i;
	int retval = TCL_ERROR;
	for (i = 0; v != NULL && i < apol_vector_get_size(v); i++) {
		qpol_type_t *t = (qpol_type_t *) apol_vector_get_element(v, i);
		char *name;
		Tcl_Obj *type_obj;
		if (qpol_type_get_name(policydb->qh, policydb->p, t, &name) < 0) {
			goto cleanup;
		}
		type_obj = Tcl_NewStringObj(name, -1);
		if (Tcl_ListObjAppendElement(interp, *o, type_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Given a result object from a two types relationship analysis,
 * create a new Tcl list containing the names of common roles.
 */
static int apol_types_relation_roles_to_tcl_list(Tcl_Interp *interp,
						 apol_types_relation_result_t *r,
						 Tcl_Obj **o)
{
	apol_vector_t *v = apol_types_relation_result_get_roles(r);
	*o = Tcl_NewListObj(0, NULL);
	size_t i;
	int retval = TCL_ERROR;
	for (i = 0; v != NULL && i < apol_vector_get_size(v); i++) {
		qpol_role_t *role = (qpol_role_t *) apol_vector_get_element(v, i);
		char *name;
		Tcl_Obj *role_obj;
		if (qpol_role_get_name(policydb->qh, policydb->p, role, &name) < 0) {
			goto cleanup;
		}
		role_obj = Tcl_NewStringObj(name, -1);
		if (Tcl_ListObjAppendElement(interp, *o, role_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Given a result object from a two types relationship analysis,
 * create a new Tcl list containing the names of common users.
 */
static int apol_types_relation_users_to_tcl_list(Tcl_Interp *interp,
						 apol_types_relation_result_t *r,
						 Tcl_Obj **o)
{
	apol_vector_t *v = apol_types_relation_result_get_users(r);
	*o = Tcl_NewListObj(0, NULL);
	size_t i;
	int retval = TCL_ERROR;
	for (i = 0; v != NULL && i < apol_vector_get_size(v); i++) {
		qpol_user_t *u = (qpol_user_t *) apol_vector_get_element(v, i);
		char *name;
		Tcl_Obj *user_obj;
		if (qpol_user_get_name(policydb->qh, policydb->p, u, &name) < 0) {
			goto cleanup;
		}
		user_obj = Tcl_NewStringObj(name, -1);
		if (Tcl_ListObjAppendElement(interp, *o, user_obj) == TCL_ERROR) {
			goto cleanup;
		}
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Given a vector of apol_types_relation_access_t pointers, create a
 * new Tcl list containing those accesses.
 */
static int apol_types_relation_access_to_tcl_list(Tcl_Interp *interp,
						  apol_vector_t *v,
						  Tcl_Obj **o)
{
	*o = Tcl_NewListObj(0, NULL);
	size_t i;
	int retval = TCL_ERROR;
	for (i = 0; v != NULL && i < apol_vector_get_size(v); i++) {
		apol_types_relation_access_t *a;
		Tcl_Obj *access_elem[2], *access_list;
		qpol_type_t *type;
		apol_vector_t *rules;
		char *name;
		a = (apol_types_relation_access_t *) apol_vector_get_element(v, i);
		type = apol_types_relation_access_get_type(a);
		rules = apol_types_relation_access_get_rules(a);
		if (qpol_type_get_name(policydb->qh, policydb->p, type, &name) < 0) {
			goto cleanup;
		}
		access_elem[0] = Tcl_NewStringObj(name, -1);
		if (apol_vector_to_tcl_list(interp, rules, access_elem + 1) < 0) {
			goto cleanup;
		}
		access_list = Tcl_NewListObj(2, access_elem);
		if (Tcl_ListObjAppendElement(interp, *o, access_list) == TCL_ERROR) {
			goto cleanup;
		}
	}
	retval = TCL_OK;
 cleanup:
	return retval;
}

/**
 * Given a result object from a two types relationship analysis,
 * create a new Tcl list containing lists of similar accesses.
 */
static int apol_types_relation_similar_to_tcl_list(Tcl_Interp *interp,
						   apol_types_relation_result_t *r,
						   Tcl_Obj **o)
{
	Tcl_Obj *sim[2];
	apol_vector_t *v;
	v = apol_types_relation_result_get_similar_first(r);
	if (apol_types_relation_access_to_tcl_list(interp, v, sim + 0) == TCL_ERROR) {
		return TCL_ERROR;
	}
	v = apol_types_relation_result_get_similar_other(r);
	if (apol_types_relation_access_to_tcl_list(interp, v, sim + 1) == TCL_ERROR) {
		return TCL_ERROR;
	}
	*o = Tcl_NewListObj(2, sim);
	return TCL_OK;
}

/**
 * Given a result object from a two types relationship analysis,
 * create a new Tcl list containing lists of dissimilar accesses.
 */
static int apol_types_relation_dissimilar_to_tcl_list(Tcl_Interp *interp,
						      apol_types_relation_result_t *r,
						      Tcl_Obj **o)
{
	Tcl_Obj *dis[2];
	apol_vector_t *v;
	v = apol_types_relation_result_get_dissimilar_first(r);
	if (apol_types_relation_access_to_tcl_list(interp, v, dis + 0) == TCL_ERROR) {
		return TCL_ERROR;
	}
	v = apol_types_relation_result_get_dissimilar_other(r);
	if (apol_types_relation_access_to_tcl_list(interp, v, dis + 1) == TCL_ERROR) {
		return TCL_ERROR;
	}
	*o = Tcl_NewListObj(2, dis);
	return TCL_OK;
}

/**
 * Given a result object from a two types relationship analysis,
 * create a new Tcl list containing the pointers to allow rules.
 */
static int apol_types_relation_allows_to_tcl_list(Tcl_Interp *interp,
						 apol_types_relation_result_t *r,
						 Tcl_Obj **o)
{
	apol_vector_t *v = apol_types_relation_result_get_allowrules(r);
	if (v == NULL) {
		*o = Tcl_NewListObj(0, NULL);
	}
	else if (apol_vector_to_tcl_list(interp, v, o) < 0) {
		return TCL_ERROR;
	}
	return TCL_OK;
}

/**
 * Given a result object from a two types relationship analysis,
 * create a new Tcl list containing the pointers to type rules.
 */
static int apol_types_relation_terules_to_tcl_list(Tcl_Interp *interp,
						   apol_types_relation_result_t *r,
						   Tcl_Obj **o)
{
	apol_vector_t *v = apol_types_relation_result_get_typerules(r);
	if (v == NULL) {
		*o = Tcl_NewListObj(0, NULL);
	}
	else if (apol_vector_to_tcl_list(interp, v, o) < 0) {
		return TCL_ERROR;
	}
	return TCL_OK;
}

/**
 * Given a result object from a two types relationship analysis,
 * create a new Tcl list containing direct flows between the types.
 * See Apol_DirectInformationFlowAnalysis() for format.
 */
static int apol_types_relation_directflows_to_tcl_list(Tcl_Interp *interp,
						       apol_types_relation_result_t *r,
						       Tcl_Obj **o)
{
	apol_vector_t *v = apol_types_relation_result_get_directflows(r);
	size_t i;
	*o = Tcl_NewListObj(0, NULL);
	for (i = 0; v != NULL && i < apol_vector_get_size(v); i++) {
		apol_infoflow_result_t *r;
		r = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		if (append_direct_infoflow_result_to_list(interp, r, *o) == TCL_ERROR) {
			return TCL_ERROR;
		}
	}
	return TCL_OK;
}

/**
 * Return a sorted results list for a two types relationship analysis.
 * Each element corresponds to a sublist of results after running each
 * individual sub-analysis.  If the sub-analysis was not selected
 * within the list at argv[3] then its entry in the results list will
 * be an empty list.  The results list consists of sublists:
 * <ol>
 *   <li>list of attribute strings
 *   <li>list of role strings
 *   <li>list of user strings
 *   <li>two lists of similar accesses
 *   <li>two lists of dissimilar accesses
 *   <li>list of allow rules
 *   <li>list of type transition/change rules
 * </ol>
 *
 * A similar/dissimilar access result is a tuple of:
 * <ul>
 *   <li>type name
 *   <li>list of allow rules
 * </ul>
 * For the similar sub-list there will be an equal number of access
 * results for the two types.
 *
 * Rules are unique identifiers (relative to currently loaded policy).
 * Call [apol_RenderAVRule] or [apol_RenderTERule] to display them.
 *
 * @param argv This fuction takes three parameters:
 * <ol>
 *   <li>first type to compare
 *   <li>other type to compare
 *   <li>list of analyzes to run, from the list "attribs", "roles",
 *       "users", "similars", "dissimilars", "allows", "trans",
 *       "direct", "transAB", "transBA", "domainAB", and "domainBA"
 * </ol>
 */
static int Apol_TypesRelationshipAnalysis(ClientData clientData, Tcl_Interp *interp,
					  int argc, CONST char *argv[])
{
	Tcl_Obj *result_elem[8], *result_obj;
	apol_types_relation_analysis_t *analysis = NULL;
	apol_types_relation_result_t *result = NULL;
	CONST char **analyses_strings = NULL;
	int num_opts;
	unsigned int analyses = 0;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 4) {
		ERR(policydb, "%s", "Need a type, another type, and list of analyzes.");
		goto cleanup;
	}
	if (Tcl_SplitList(interp, argv[3], &num_opts, &analyses_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = analyses_strings[num_opts];
		if (strcmp(s, "attribs") == 0) {
			analyses |= APOL_TYPES_RELATION_COMMON_ATTRIBS;
		}
		else if (strcmp(s, "roles") == 0) {
			analyses |= APOL_TYPES_RELATION_COMMON_ROLES;
		}
		else if (strcmp(s, "users") == 0) {
			analyses |= APOL_TYPES_RELATION_COMMON_USERS;
		}
		else if (strcmp(s, "similars") == 0) {
			analyses |= APOL_TYPES_RELATION_SIMILAR_ACCESS;
		}
		else if (strcmp(s, "dissimilars") == 0) {
			analyses |= APOL_TYPES_RELATION_DISSIMILAR_ACCESS;
		}
		else if (strcmp(s, "allows") == 0) {
			analyses |= APOL_TYPES_RELATION_ALLOW_RULES;
		}
		else if (strcmp(s, "trans") == 0) {
			analyses |= APOL_TYPES_RELATION_TYPE_RULES;
		}
		else if (strcmp(s, "direct") == 0) {
			analyses |= APOL_TYPES_RELATION_DIRECT_FLOW;
		}
		else if (strcmp(s, "transAB") == 0) {
			analyses |= APOL_TYPES_RELATION_TRANS_FLOW_AB;
		}
		else if (strcmp(s, "transBA") == 0) {
			analyses |= APOL_TYPES_RELATION_TRANS_FLOW_BA;
		}
		else {
			ERR(policydb, "Invalid analysis type %s.", s);
			goto cleanup;
		}
	}
	if ((analysis = apol_types_relation_analysis_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_types_relation_analysis_set_first_type(policydb, analysis, argv[1]) < 0 ||
	    apol_types_relation_analysis_set_other_type(policydb, analysis, argv[2]) < 0 ||
	    apol_types_relation_analysis_set_analyses(policydb, analysis, analyses) < 0) {
		goto cleanup;
	}
	if (apol_types_relation_analysis_do(policydb, analysis, &result) < 0) {
		goto cleanup;
	}
	if (apol_types_relation_attribs_to_tcl_list(interp, result, result_elem + 0) == TCL_ERROR ||
	    apol_types_relation_roles_to_tcl_list(interp, result, result_elem + 1) == TCL_ERROR ||
	    apol_types_relation_users_to_tcl_list(interp, result, result_elem + 2) == TCL_ERROR ||
	    apol_types_relation_similar_to_tcl_list(interp, result, result_elem + 3) == TCL_ERROR ||
	    apol_types_relation_dissimilar_to_tcl_list(interp, result, result_elem + 4) == TCL_ERROR ||
	    apol_types_relation_allows_to_tcl_list(interp, result, result_elem + 5) == TCL_ERROR ||
	    apol_types_relation_terules_to_tcl_list(interp, result, result_elem + 6) == TCL_ERROR ||
	    apol_types_relation_directflows_to_tcl_list(interp, result, result_elem + 7) == TCL_ERROR) {
		goto cleanup;
	}
	result_obj = Tcl_NewListObj(8, result_elem);
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	if (analyses_strings != NULL) {
		Tcl_Free((char *) analyses_strings);
	}
	apol_types_relation_analysis_destroy(&analysis);
	apol_types_relation_result_destroy(&result);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

int apol_tcl_analysis_init(Tcl_Interp *interp)
{
	Tcl_InitHashTable(&infoflow_htable, TCL_STRING_KEYS);
	Tcl_CreateCommand(interp, "apol_ExpandType", Apol_ExpandType, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetAllPermsForClass", Apol_GetAllPermsForClass, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_DomainTransitionAnalysis", Apol_DomainTransitionAnalysis, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_DirectInformationFlowAnalysis", Apol_DirectInformationFlowAnalysis, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_DirectInformationFlowMore", Apol_DirectInformationFlowMore, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TransInformationFlowAnalysis", Apol_TransInformationFlowAnalysis, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TransInformationFlowMore", Apol_TransInformationFlowMore, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TransInformationFurtherPrepare", Apol_TransInformationFurtherPrepare, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TransInformationFurtherNext", Apol_TransInformationFurtherNext, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_InformationFlowDestroy", Apol_InformationFlowDestroy, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RelabelAnalysis", Apol_RelabelAnalysis, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TypesRelationshipAnalysis", Apol_TypesRelationshipAnalysis, NULL, NULL);
        return TCL_OK;
}
