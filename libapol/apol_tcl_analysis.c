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

#include "policy.h"
#include "apol_tcl_other.h"

#include <tcl.h>

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
 * has been marked as invalid, shimmer it an infoflow_tcl_obj_type,
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
		ERR(policydb, "Need a class name.");
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
 *     execute_rule proctrans_rule entrypoint_rule access_rules }
 * </code>
 */
static int append_domain_trans_result_to_list(Tcl_Interp *interp,
					       apol_domain_trans_result_t *result,
					       Tcl_Obj *result_list)
{
	Tcl_Obj *dta_elem[7], *dta_list;
	qpol_type_t *source, *target, *entry;
	char *source_name, *target_name, *entry_name;
	qpol_avrule_t *entrypoint, *proctrans, *execute;
	apol_vector_t *access_rules;
	int retval = TCL_ERROR;

	source = apol_domain_trans_result_get_start_type(result);
	target = apol_domain_trans_result_get_end_type(result);
	entry =	 apol_domain_trans_result_get_entrypoint_type(result);
	execute = apol_domain_trans_result_get_exec_rule(result);
	proctrans = apol_domain_trans_result_get_proc_trans_rule(result);
	entrypoint = apol_domain_trans_result_get_entrypoint_rule(result);
	if (qpol_type_get_name(policydb->qh, policydb->p, source, &source_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, target, &target_name) < 0 ||
	    qpol_type_get_name(policydb->qh, policydb->p, entry, &entry_name) < 0) {
		goto cleanup;
	}
	dta_elem[0] = Tcl_NewStringObj(source_name, -1);
	dta_elem[1] = Tcl_NewStringObj(target_name, -1);
	dta_elem[2] = Tcl_NewStringObj(entry_name, -1);
	dta_elem[3] = Tcl_NewLongObj((long) execute);
	dta_elem[4] = Tcl_NewLongObj((long) proctrans);
	dta_elem[5] = Tcl_NewLongObj((long) entrypoint);
	if ((access_rules = apol_domain_trans_result_get_access_rules(result)) == NULL) {
		dta_elem[6] = Tcl_NewListObj(0, NULL);
	}
	else if (apol_vector_to_tcl_list(interp, access_rules, dta_elem + 6) == TCL_ERROR) {
		goto cleanup;
	}
	dta_list = Tcl_NewListObj(7, dta_elem);
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
 *   <li>AV rule that allows the source to execute the entrypoint type
 *   <li>AV rule that allows the source type to transition to target type
 *   <li>AV rule that allows a file entrypoint from the entrypoint type
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
		ERR(policydb, "Need an analysis mode, starting type, object types, class/perm pairs, and result regex.");
		goto cleanup;
	}

	if ((analysis = apol_domain_trans_analysis_create()) == NULL) {
		ERR(policydb, "Out of memory!");
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
	apol_vector_t *rules;
	int retval = TCL_ERROR;

	dir = apol_infoflow_result_get_dir(result);
	source = apol_infoflow_result_get_start_type(result);
	target = apol_infoflow_result_get_end_type(result);
	rules = apol_infoflow_result_get_rules(result);
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
		ERR(policydb, "Need a flow direction, starting type, object classes, and resulting type regex.");
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
		ERR(policydb, "Out of memory!");
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
 * Perform additional an analysis upon a pre-existing direct
 * information flow graph, returning an unsorted list of result
 * tuples.  The analysis will use the same parameters as those that
 * were used to construct the graph.  Each result tuple consists of:
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
		ERR(policydb, "Need an infoflow graph handler and a starting type.");
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
		ERR(policydb, "Need an infoflow graph handler.");
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
 *
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
		ERR(policydb, "Need an analysis mode, starting type, object classes, subject types, and resulting type regex.");
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
		ERR(policydb, "Out of memory!");
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

int apol_tcl_analysis_init(Tcl_Interp *interp)
{
	Tcl_InitHashTable(&infoflow_htable, TCL_STRING_KEYS);
	Tcl_CreateCommand(interp, "apol_GetAllPermsForClass", Apol_GetAllPermsForClass, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_DomainTransitionAnalysis", Apol_DomainTransitionAnalysis, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_DirectInformationFlowAnalysis", Apol_DirectInformationFlowAnalysis, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_DirectInformationFlowMore", Apol_DirectInformationFlowMore, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_InformationFlowDestroy", Apol_InformationFlowDestroy, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RelabelAnalysis", Apol_RelabelAnalysis, NULL, NULL);
        /*
	Tcl_CreateCommand(interp, "apol_TransitiveFlowAnalysis", Apol_TransitiveFlowAnalysis, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFindPathsStart", Apol_TransitiveFindPathsStart, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFindPathsNext", Apol_TransitiveFindPathsNext, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFindPathsGetResults", Apol_TransitiveFindPathsGetResults, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFindPathsAbort", Apol_TransitiveFindPathsAbort, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_TypesRelationshipAnalysis", Apol_TypesRelationshipAnalysis, NULL, NULL);
        */
        return TCL_OK;
}

/******************** attic ********************/

#if 0



static int append_direct_edge_to_results(policy_t *policy, iflow_query_t* q,
					 iflow_t *answer, Tcl_Interp *interp)
{
	int j, k, num_obj_classes = 0;
	char *rule, tbuf[BUF_SZ];

	/* Append number of object classes */
	for (j = 0; j < answer->num_obj_classes; j++)
		if (answer->obj_classes[j].num_rules)
			num_obj_classes++;
	sprintf(tbuf, "%d", num_obj_classes);
	Tcl_AppendElement(interp, tbuf);

	for (j = 0; j < answer->num_obj_classes; j++) {
		/* if this is 0 then the obj_class is not defined for a given edge */
		if (answer->obj_classes[j].num_rules) {
			/* Indicate this is an object class we care about */
			Tcl_AppendElement(interp, "1");
			/* Append the object class name to the TCL list */
			sprintf(tbuf, "%s", policy->obj_classes[j].name);
			Tcl_AppendElement(interp, tbuf);

			/* Append the number of rules */
			sprintf(tbuf, "%d", answer->obj_classes[j].num_rules);
			Tcl_AppendElement(interp, tbuf);

			/* Append the allow rule(s) to the TCL list */
			for (k = 0; k < answer->obj_classes[j].num_rules; k++) {
				rule = re_render_av_rule(TRUE, answer->obj_classes[j].rules[k], FALSE, policy);
				if(rule == NULL) {
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "analysis error (rendering allow rule)",  (char *) NULL);
					return -1;
				}
				Tcl_AppendElement(interp, rule);
				free(rule);
				/* Append a boolean value indicating whether this rule is enabled
				 * for conditional policy support */
				sprintf(tbuf, "%d", policy->av_access[answer->obj_classes[j].rules[k]].enabled);
				Tcl_AppendElement(interp, tbuf);
			}
		}
	}
	return 0;
}

static int append_transitive_iflow_rules_to_results(policy_t *policy, iflow_transitive_t* answers, iflow_path_t *cur, int path_idx, int obj_idx, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ], *rule;
	int l;

	/* Append the number of rules */
	sprintf(tbuf, "%d", cur->iflows[path_idx].obj_classes[obj_idx].num_rules);
	Tcl_AppendElement(interp, tbuf);

	/* Append the allow rule(s) to the TCL list */
	for (l = 0; l < cur->iflows[path_idx].obj_classes[obj_idx].num_rules; l++) {
		rule = re_render_av_rule(TRUE, cur->iflows[path_idx].obj_classes[obj_idx].rules[l], FALSE, policy);
		if(rule == NULL) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "analysis error (rendering allow rule)",  (char *) NULL);
			return -1;
		}
		Tcl_AppendElement(interp, rule);
		free(rule);
		/* Append a boolean value indicating whether this rule is enabled
		 * for conditional policy support */
		sprintf(tbuf, "%d", policy->av_access[cur->iflows[path_idx].obj_classes[obj_idx].rules[l]].enabled);
		Tcl_AppendElement(interp, tbuf);
	}
	return 0;
}

static int append_transitive_iflow_objects_to_results(policy_t *policy, iflow_transitive_t *answers, iflow_path_t *cur, Tcl_Interp *interp, int j)
{
	char tbuf[BUF_SZ];
	int num_obj_classes, k, rt;

	/* Append the number of object classes */
	num_obj_classes = 0;
	for (k = 0; k < cur->iflows[j].num_obj_classes; k++)
		if (cur->iflows[j].obj_classes[k].num_rules)
			num_obj_classes++;
	sprintf(tbuf, "%d", num_obj_classes);
	Tcl_AppendElement(interp, tbuf);

	for (k = 0; k < cur->iflows[j].num_obj_classes; k++) {
		/* if 0, the obj_class is not defined for a given edge */
		if (cur->iflows[j].obj_classes[k].num_rules) {
			/* Append the object class name */
			sprintf(tbuf, "%s", policy->obj_classes[k].name);
			Tcl_AppendElement(interp, tbuf);

			/* Append the rules for each object */
			rt = append_transitive_iflow_rules_to_results(policy, answers, cur, j, k, interp);
			if (rt != 0) {
				return -1;
			}
		}
	}
	return 0;
}

static int append_transitive_iflows_to_results(policy_t *policy, iflow_transitive_t* answers, iflow_path_t *cur, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ];
	int j, rt;

	/* Append the number of flows in path */
	sprintf(tbuf, "%d", cur->num_iflows);
	Tcl_AppendElement(interp, tbuf);
	for (j = 0; j < cur->num_iflows; j++) {
		/* Append the start type */
		sprintf(tbuf, "%s", policy->types[cur->iflows[j].start_type].name);
		Tcl_AppendElement(interp, tbuf);
		/* Append the end type */
		sprintf(tbuf, "%s", policy->types[cur->iflows[j].end_type].name);
		Tcl_AppendElement(interp, tbuf);
		/* Append the objects */
		rt = append_transitive_iflow_objects_to_results(policy, answers, cur, interp, j);
		if(rt != 0)
			return -1;
	}
	return 0;
}


static int append_transitive_iflow_paths_to_results(policy_t *policy, iflow_transitive_t* answers, Tcl_Interp *interp, int end_type)
{
	char tbuf[BUF_SZ];
	int rt;
	iflow_path_t *cur;

	/* Append the number of paths for this type */
	sprintf(tbuf, "%d", answers->num_paths[end_type]);
	Tcl_AppendElement(interp, tbuf);
	for (cur = answers->paths[end_type]; cur != NULL; cur = cur->next) {
		/* Append the iflows for each path */
		rt = append_transitive_iflows_to_results(policy, answers, cur, interp);
		if (rt != 0) {
			return -1;
		}
	}
	return 0;
}

static int append_transitive_iflow_results(policy_t *policy, iflow_transitive_t *answers, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ];
	int i, rt;

	/* Append the number of types */
	sprintf(tbuf, "%d", answers->num_end_types);
	Tcl_AppendElement(interp, tbuf);

	for (i = 0; i < answers->num_end_types; i++) {
		/* Append the type */
		sprintf(tbuf, "%s", policy->types[answers->end_types[i]].name);
		Tcl_AppendElement(interp, tbuf);
		/* Append the paths for the type */
		rt = append_transitive_iflow_paths_to_results(policy, answers, interp, i);
		if (rt != 0)
			return -1;
	}
	return 0;
}

/******************** transitive information flow ********************/

/*
 * argv[1] - domain type used to start the analysis
 * argv[2] - flow direction - IN or OUT
 * argv[3] - flag (boolean value) for indicating that a list of object classes are being provided.
 * argv[4] - number of object classes that are to be included in the query.
 * argv[5] - flag (boolean value) for indicating that filter on end type(s) is being provided
 * argv[6] - ending type regular expression
 * argv[7] - encoded list of object class/permissions to exclude in the query
 * argv[8] - flag (boolean value) for indicating whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
 * argv[10] - flag (boolean value) whether or not to use minimum weight.
 * argv[11] - minimum weight value
 *
 * NOTE: THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! If, not it will throw an error.
 *
 */
static iflow_query_t* set_transitive_query_args(Tcl_Interp *interp, CONST char *argv[])
{
        /* FIX ME! */
	int num_objs, num_obj_perms, num_objs_options, obj, perm;
	int num_inter_types, type, *types = NULL;
	int i, j, rt, num, cur, sz = 0;
	char *start_type = NULL, *end_type = NULL;
	char *err, *name;
	char tbuf[64];
	CONST char **obj_class_perms = NULL, **inter_types = NULL;
	bool_t filter_obj_classes, filter_end_types, filter_inter_types, use_min_weight;
	regex_t reg;
	iflow_query_t *iflow_query = NULL;

	if (policydb == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return NULL;
	}
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded!", (char *) NULL);
		return NULL;
	}

	/* Set start_type variable and guard against buffer overflows by checking string length */
	start_type = (char *) argv[1];
	if(start_type == NULL || str_is_only_white_space(start_type)) {
		Tcl_AppendResult(interp, "empty starting type!", (char *) NULL);
		return NULL;
	}
	if(!is_valid_str_sz(start_type)) {
		Tcl_AppendResult(interp, "The provided start type string is too large.", (char *) NULL);
		return NULL;
	}

	filter_obj_classes = getbool(argv[3]);
	filter_end_types = getbool(argv[5]);
	filter_inter_types = getbool(argv[8]);
	use_min_weight = getbool(argv[10]);
	rt = Tcl_GetInt(interp, argv[4], &num_objs);
	if(rt == TCL_ERROR) {
		Tcl_AppendResult(interp,"argv[4] apparently not an integer", (char *) NULL);
		return NULL;
	}

	if(filter_obj_classes) {
		/* Second, disassemble list of object class permissions, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[7], &num_objs_options, &obj_class_perms);
		if(rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return NULL;
		}

		if(num_objs_options < 1) {
			Tcl_AppendResult(interp, "Must provide object class permissions.", (char *) NULL);
			Tcl_Free((char *) obj_class_perms);
			return NULL;
		}
	}

	if(filter_end_types) {
		if(!is_valid_str_sz(argv[6])) {
			Tcl_AppendResult(interp, "The provided end type filter string is too large.", (char *) NULL);
			return NULL;
		}
		sz = strlen(argv[6]) + 1;
	        end_type = (char *)malloc(sz);
	        if(end_type == NULL) {
		      fprintf(stderr, "out of memory");
		      return NULL;
		}
		end_type = strcpy(end_type, argv[6]);
		if(end_type == NULL || str_is_only_white_space(end_type)) {
			free(end_type);
			Tcl_AppendResult(interp, "Please provide a regular expression for filtering the end types.", (char *) NULL);
			return NULL;
		}
	}
	if (filter_inter_types) {
		/* First, disassemble TCL intermediate types list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[9], &num_inter_types, &inter_types);
		if(rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return NULL;
		}

		if(num_inter_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least one intermediate type.", (char *) NULL);
			Tcl_Free((char *) inter_types);
			return NULL;
		}
	}
	/* Initialize query structure */
	iflow_query = iflow_query_create();
	if (iflow_query == NULL) {
		Tcl_AppendResult(interp,"Memory error allocating query\n", (char *) NULL);
		return NULL;
	}

	if(strcmp(argv[2], "in") == 0) {
		iflow_query->direction = IFLOW_IN;
	}
	else if(strcmp(argv[2], "out") == 0) {
		iflow_query->direction = IFLOW_OUT;
	}
	else {
		Tcl_AppendResult(interp, "Unknown flow direction provided:", argv[2], " Must be either 'in' or 'out'.", (char *) NULL);
		iflow_query_destroy(iflow_query);
		return NULL;
	}

	if (use_min_weight) {
		rt = Tcl_GetInt(interp, argv[11], &iflow_query->min_weight);
		if (rt == TCL_ERROR) {
			Tcl_AppendResult(interp,"argv[11] apparently is not an integer", (char *) NULL);
			return NULL;
		}
	}

	/* Set the start type for our query */
	iflow_query->start_type = get_type_idx(start_type, policy);
	if (iflow_query->start_type < 0) {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "Invalid starting type ", start_type, (char *) NULL);
		return NULL;
	}

	if(filter_obj_classes && obj_class_perms != NULL) {
		assert(num_objs > 0);
		cur = 0;
		/* Set the object classes permission info */
		/* Keep in mind that this is an encoded TCL list in the form
		   "class1 num_perms perm1 ... permN ... classN num_perms perm1 ... permN" */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_class_perms[cur], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class:\n", obj_class_perms[cur], (char *) NULL);
				Tcl_Free((char *) obj_class_perms);
				iflow_query_destroy(iflow_query);
				return NULL;
			}
			/* Increment to next element, which should be the number of permissions to exclude for the class
			 * num_obj_perms = 0 means to exclude the entire class */
			cur++;
			rt = Tcl_GetInt(interp, obj_class_perms[cur], &num_obj_perms);
			if(rt == TCL_ERROR) {
				Tcl_AppendResult(interp, "Item in obj_class_perms list apparently is not an integer\n", (char *) NULL);
				return NULL;
			}

			/* If this there are no permissions given then exclude the entire object class. */
			if (num_obj_perms == 0) {
				if (iflow_query_add_obj_class(iflow_query, obj) == -1) {
					Tcl_AppendResult(interp, "error adding obj\n", (char *) NULL);
					return NULL;
				}
			} else {
				for (j = 0; j < num_obj_perms; j++) {
					cur++;
					perm = get_perm_idx(obj_class_perms[cur], policy);
					if (perm < 0 || !is_valid_perm_for_obj_class(policy, obj, perm)) {
						fprintf(stderr, "Invalid object class permission\n");
						continue;
					}
					if (iflow_query_add_obj_class_perm(iflow_query, obj, perm) == -1) {
						Tcl_AppendResult(interp, "error adding perm\n", (char *) NULL);
						return NULL;
					}
				}
			}
			cur++;
		}
		Tcl_Free((char *) obj_class_perms);
	}

	/* filter ending type(s) */
	if(filter_end_types) {
		trim_trailing_whitespace(&end_type);
		rt = regcomp(&reg, end_type, REG_EXTENDED|REG_NOSUB);
		if(rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				Tcl_AppendResult(interp, "out of memory", (char *) NULL);
				iflow_query_destroy(iflow_query);
				return NULL;
			}
			regerror(rt, &reg, err, sz);
			regfree(&reg);
			Tcl_AppendResult(interp, err, (char *) NULL);
			free(err);
			free(end_type);
			iflow_query_destroy(iflow_query);
			return NULL;
		}
		free(end_type);
		rt = get_type_idxs_by_regex(&types, &num, &reg, FALSE, policy);
		if(rt < 0) {
			Tcl_AppendResult(interp, "Error searching types\n", (char *) NULL);
			iflow_query_destroy(iflow_query);
			return NULL;
		}
		for(i = 0; i < num; i++) {
			rt = get_type_name(types[i], &name, policy);
			if(rt < 0) {
				sprintf(tbuf, "Problem getting %dth matching type name for idx: %d", i, types[i]);
				Tcl_AppendResult(interp, tbuf, (char *) NULL);
				iflow_query_destroy(iflow_query);
				return NULL;
			}
			type = get_type_idx(name, policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				free(name);
				continue;
			}
			if (iflow_query_add_end_type(iflow_query, type) != 0) {
				free(name);
				iflow_query_destroy(iflow_query);
				Tcl_AppendResult(interp, "Error adding end type to query!\n", (char *) NULL);
				return NULL;
			}
			free(name);
		}
	}
	if (filter_inter_types && inter_types != NULL) {
		/* Set intermediate type info */
		for (i = 0; i < num_inter_types; i++) {
			type = get_type_idx(inter_types[i], policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				continue;
			}
			if (iflow_query_add_type(iflow_query, type) != 0) {
				iflow_query_destroy(iflow_query);
				Tcl_AppendResult(interp, "Memory error!\n", (char *) NULL);
				return NULL;
			}
		}
		Tcl_Free((char *) inter_types);
	}
	return iflow_query;
        return NULL;
}


/*
 * TRANSITIVE INFORMATION FLOW RESULTS:
 *
 * argv[1] - domain type used to start the analysis
 * argv[2] - flow direction - IN or OUT
 * argv[3] - flag (boolean value) for indicating that a list of object classes are being provided.
 * argv[4] - number of object classes that are to be included in the query.
 * argv[5] - flag (boolean value) for indicating that filter on end type(s) is being provided
 * argv[6] - ending type regular expression
 * argv[7] - encoded list of object class/permissions to exclude in the query
 * argv[8] - flag (boolean value) for indicatinf whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
 * argv[10] - flag (boolean value) whether or not to use minimum weight.
 * argv[11] - minimum weight value
 *
 * NOTE: THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! If, not it will throw an error.
 *
 *	Returns a list organized to represent the tree structure that results from a transitive information flow
 *	analysis.  The TCL list looks like this:
 *
 *	INDEX		CONTENTS
 *	0		starting type provided by the user.
 *	1		number of answers found from query (Ne)
 *	2		type 1
 *	3			total path length for this particular type (Np)
 *		4		flow 1
 *		5			flow1 start type name
 *		6			flow1 target type name
 *		7			number of object classes for each edge (No)
 *		8			object class(1)
 *		9				number of rules (Nr)
 *		10					allow rule 1, lineno1,....
 *							....
 *							....
 *		next					allow rule Nr, linenoNr
 *					...
 *					...
 *		next			object class(No)
 *				....
 *				....
 *		next		flow N
 *			....
 *			....
 *	next		type Ne
 *
 */
static int Apol_TransitiveFlowAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        /* FIX ME */
	iflow_transitive_t *answers = NULL;
	iflow_query_t* iflow_query = NULL;
	char *start_type = NULL;
	int rt;
	char tbuf[64];
	bool_t filter_end_types, filter_inter_types;

	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	iflow_query = set_transitive_query_args(interp, argv);
	if (iflow_query == NULL) {
		return TCL_ERROR;
	}

	filter_inter_types = getbool(argv[8]);
	/* Don't run the analysis call if the start type is excluded */
	if (filter_inter_types && find_int_in_array(iflow_query->start_type, iflow_query->types, iflow_query->num_types) != -1) {
			assert(FALSE); /* this should get caught by the tcl code */
			Tcl_AppendResult(interp, "Advanced filter cannot exclude start type from analysis\n", (char *) NULL);
			return TCL_ERROR;
	}
	filter_end_types = getbool(argv[5]);
	/* Don't run the analysis call if the user has specified to filter end types by reg exp
	 * and we've determined in the call to set_transitive_query_args() that there are no
	 * matching end types. */
	if (!(filter_end_types && iflow_query->num_end_types == 0)) {
		if ((answers = iflow_transitive_flows(policy, iflow_query)) == NULL) {
			iflow_query_destroy(iflow_query);
			Tcl_AppendResult(interp, "There were errors in the information flow analysis\n", (char *) NULL);
			return TCL_ERROR;
		}
	}
	/* Append the start type to our encoded TCL list */
	rt = get_type_name(iflow_query->start_type, &start_type, policy);
	if (rt != 0) {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "Could not get start type name. ", (char *) NULL);
		return TCL_ERROR;
	}
	sprintf(tbuf, "%s", start_type);
	Tcl_AppendElement(interp, tbuf);
	if (!(filter_end_types && iflow_query->num_end_types == 0)) {
		rt = append_transitive_iflow_results(policy, answers, interp);
		if(rt != 0) {
			iflow_transitive_destroy(answers);
			iflow_query_destroy(iflow_query);
			Tcl_AppendResult(interp, "Error appending edge information!\n", (char *) NULL);
			return TCL_ERROR;
		}
		iflow_transitive_destroy(answers);
	} else {
		Tcl_AppendElement(interp, "0");
	}
	iflow_query_destroy(iflow_query);
	return TCL_OK;
}

/* argv[1] - domain type used to start the analysis
 * argv[2] - flow direction - IN or OUT
 * argv[3] - flag (boolean value) for indicating that a list of object classes are being provided.
 * argv[4] - number of object classes that are to be included in the query.
 * argv[5] - flag (boolean value) for indicating that filter on end type(s) is being provided
 * argv[6] - ending type regular expression
 * argv[7] - encoded list of object class/permissions to exclude in the query
 * argv[8] - flag (boolean value) for indicating whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
 * argv[10] - flag (boolean value) whether or not to use minimum weight.
 * argv[11] - minimum weight value
 */
static int Apol_TransitiveFindPathsStart(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        /* FIX ME! */
	iflow_query_t* iflow_query = NULL;

	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	iflow_query = set_transitive_query_args(interp, argv);
	if (iflow_query == NULL) {
		return TCL_ERROR;
	}
	if(iflow_query == NULL) {
		Tcl_AppendResult(interp, "Query is empty!", (char *) NULL);
		return TCL_ERROR;
	}
	/* Start finding additional iflow paths */
	state = iflow_find_paths_start(policy, iflow_query);
	if (state == NULL) {
		Tcl_AppendResult(interp, "Could not start iflow paths search.", (char *) NULL);
		return TCL_ERROR;
	}
	iflow_query_destroy(iflow_query);
	return TCL_OK;
}

static int Apol_TransitiveFindPathsNext(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        /* FIX ME */
	int num_paths;
	char tbuf[64];

	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded!", (char *) NULL);
		return TCL_ERROR;
	}
	if(state == NULL) {
		Tcl_AppendResult(interp,"Analysis not started!", (char *) NULL);
		return TCL_ERROR;
	}
	num_paths = iflow_find_paths_next(state);
	if (num_paths == -1) {
		iflow_find_paths_abort(state);
		Tcl_AppendResult(interp, "Error while finding additional paths.", (char *) NULL);
		return TCL_ERROR;
	}
	sprintf(tbuf, "%d", num_paths);
	Tcl_AppendResult(interp, tbuf, (char *) NULL);
	return TCL_OK;
}

static int Apol_TransitiveFindPathsGetResults(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        /* FIX ME */
	int rt;
	iflow_transitive_t *answers = NULL;

	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded!", (char *) NULL);
		return TCL_ERROR;
	}
	if(state == NULL) {
		Tcl_AppendResult(interp,"Analysis not started!", (char *) NULL);
		return TCL_ERROR;
	}
	answers = iflow_find_paths_end(state);
	if (answers == NULL) {
		iflow_find_paths_abort(state);
		Tcl_AppendResult(interp, "Error while retrieving additional paths. Results were empty.", (char *) NULL);
		return TCL_ERROR;
	}
	rt = append_transitive_iflow_results(policy, answers, interp);
	if(rt != 0) {
		iflow_transitive_destroy(answers);
		Tcl_AppendResult(interp, "Error while retrieving additional paths results.\n", (char *) NULL);
		return TCL_ERROR;
	}
	iflow_transitive_destroy(answers);
	return TCL_OK;
}

static int Apol_TransitiveFindPathsAbort(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        /* FIX ME */
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(state != NULL) {
		iflow_find_paths_abort(state);
	}
	return TCL_OK;
}


/******************** types relationship analysis ********************/

/* argv[18] - flag (boolean value) for indicating that a list of object classes are being provided to the DTA query.
 * argv[19] - number of object classes that are to be included in the DTA query.
 * argv[20] - list of object classes/permissions for the DTA query.
 * argv[21] - flag (boolean value) for selecting object type(s) in the DTA query.
 * argv[22] - list of object types for the DTA query.
 */
static int types_relation_get_dta_options(dta_query_t *dta_query, Tcl_Interp *interp, CONST char *argv[], policy_t *policy)
{
	int rt, num_objs, num_objs_options, num_end_types, i, j;
	int cur, type;
	int num_obj_perms, obj, perm;
	CONST char **obj_class_perms, **end_types;
	bool_t filter_obj_classes, filter_end_types;

	assert(dta_query != NULL);
	filter_obj_classes = getbool(argv[18]);
	filter_end_types = getbool(argv[21]);
	rt = Tcl_GetInt(interp, argv[19], &num_objs);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp, "argv[19] apparently not an integer", (char *) NULL);
		return TCL_ERROR;
	}

	if(filter_obj_classes) {
		/* Second, disassemble list of object class permissions, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[20], &num_objs_options, &obj_class_perms);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}

		if (num_objs_options < 1) {
			Tcl_AppendResult(interp, "Must provide object class permissions.", (char *) NULL);
			Tcl_Free((char *) obj_class_perms);
			return TCL_ERROR;
		}
	}

	if (filter_end_types) {
		/* First, disassemble TCL intermediate types list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[22], &num_end_types, &end_types);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}

		if (num_end_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least one end type.", (char *) NULL);
			Tcl_Free((char *) end_types);
			return TCL_ERROR;
		}
	}

	if(filter_obj_classes && obj_class_perms != NULL) {
		assert(num_objs > 0);
		cur = 0;
		/* Set the object classes permission info */
		/* Keep in mind that this is an encoded TCL list in the form
		 * "class1 num_perms perm1 ... permN ... classN num_perms perm1 ... permN" */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_class_perms[cur], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class:\n", obj_class_perms[cur], (char *) NULL);
				Tcl_Free((char *) obj_class_perms);
				return TCL_ERROR;
			}
			/* Increment to next element, which should be the number of specified permissions for the class */
			cur++;
			rt = Tcl_GetInt(interp, obj_class_perms[cur], &num_obj_perms);
			if (rt == TCL_ERROR) {
				Tcl_AppendResult(interp, "Item in obj_class_perms list apparently is not an integer\n", (char *) NULL);
				return TCL_ERROR;
			}
			if (num_obj_perms == 0) {
				fprintf(stderr, "No permissions for object: %s. Skipping...\n", obj_class_perms[cur - 1]);
				continue;
			}

			for (j = 0; j < num_obj_perms; j++) {
				cur++;
				perm = get_perm_idx(obj_class_perms[cur], policy);
				if (perm < 0 || !is_valid_perm_for_obj_class(policy, obj, perm)) {
					fprintf(stderr, "Invalid object class permission\n");
					continue;
				}
				if (dta_query_add_obj_class_perm(dta_query, obj, perm) == -1) {
					Tcl_AppendResult(interp, "error adding perm\n", (char *) NULL);
					return TCL_ERROR;
				}
			}
			cur++;
		}
		Tcl_Free((char *) obj_class_perms);
	}

	if (filter_end_types) {
		/* Set intermediate type info */
		for (i = 0; i < num_end_types; i++) {
			type = get_type_idx(end_types[i], policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				continue;
			}
			if (dta_query_add_end_type(dta_query, type) != 0) {
				Tcl_AppendResult(interp, "Memory error!\n", (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) end_types);
	}

	return TCL_OK;
}

/* argv[13] - (boolean value) for indicating that a list of transitive flow object classes are being provided to the TIF query.
 * argv[14] - number of object classes that are to be included in the transitive flow query.
 * argv[15] - encoded list of object class/permissions to include in the the transitive flow query.
 * argv[16] - flag (boolean value) for indicating whether or not to include intermediate types in the
 *	      the transitive flow query.
 * argv[17] - TCL list of intermediate types for the transitive flow analysis
 * NOTE: IF SEARCHING TRANSITIVE FLOWS, THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!!
 *	 If, not it will throw an error.
 */
static int types_relation_get_transflow_options(iflow_query_t *trans_flow_query, Tcl_Interp *interp, CONST char *argv[], policy_t *policy)
{
	int num_objs, num_obj_perms, num_objs_options, obj, perm;
	int num_inter_types, type;
	int i, j, rt, cur;
	CONST char **obj_class_perms = NULL, **inter_types = NULL;
	bool_t filter_obj_classes, filter_inter_types;

	assert(trans_flow_query != NULL);
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded for Transitive Flow Analysis!", (char *) NULL);
		return TCL_ERROR;
	}

	filter_obj_classes = getbool(argv[13]);
	filter_inter_types = getbool(argv[16]);
	rt = Tcl_GetInt(interp, argv[14], &num_objs);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp,"argv[14] apparently not an integer", (char *) NULL);
		return TCL_ERROR;
	}

	if (filter_obj_classes) {
		/* Second, disassemble list of object class permissions, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[15], &num_objs_options, &obj_class_perms);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}

		if (num_objs_options < 1) {
			Tcl_AppendResult(interp, "Must provide object class permissions.", (char *) NULL);
			Tcl_Free((char *) obj_class_perms);
			return TCL_ERROR;
		}
	}

	if (filter_inter_types) {
		/* First, disassemble TCL intermediate types list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[17], &num_inter_types, &inter_types);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}

		if (num_inter_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least one intermediate type.", (char *) NULL);
			Tcl_Free((char *) inter_types);
			return TCL_ERROR;
		}
	}

	if (filter_obj_classes && obj_class_perms != NULL) {
		assert(num_objs > 0);
		cur = 0;
		/* Set the object classes permission info */
		/* Keep in mind that this is an encoded TCL list in the form "class1 num_perms perm1 ... permN ... classN num_perms perm1 ... permN" */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_class_perms[cur], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class:\n", obj_class_perms[cur], (char *) NULL);
				Tcl_Free((char *) obj_class_perms);
				return TCL_ERROR;
			}
			/* Increment to next element, which should be the number of permissions for the class */
			cur++;
			rt = Tcl_GetInt(interp, obj_class_perms[cur], &num_obj_perms);
			if (rt == TCL_ERROR) {
				Tcl_AppendResult(interp, "Item in obj_class_perms list apparently is not an integer\n", (char *) NULL);
				return TCL_ERROR;
			}

			/* If this there are no permissions given then exclude the entire object class. */
			if (num_obj_perms == 0) {
				if (iflow_query_add_obj_class(trans_flow_query, obj) == -1) {
					Tcl_AppendResult(interp, "error adding obj\n", (char *) NULL);
					return TCL_ERROR;
				}
			} else {
				for (j = 0; j < num_obj_perms; j++) {
					cur++;
					perm = get_perm_idx(obj_class_perms[cur], policy);
					if (perm < 0 || !is_valid_perm_for_obj_class(policy, obj, perm)) {
						fprintf(stderr, "Invalid object class permission\n");
						continue;
					}
					if (iflow_query_add_obj_class_perm(trans_flow_query, obj, perm) == -1) {
						Tcl_AppendResult(interp, "error adding perm\n", (char *) NULL);
						return TCL_ERROR;
					}
				}
			}
			cur++;
		}
		Tcl_Free((char *) obj_class_perms);
	}
	if (filter_inter_types && inter_types != NULL) {
		/* Set intermediate type info */
		for (i = 0; i < num_inter_types; i++) {
			type = get_type_idx(inter_types[i], policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				continue;
			}
			if (iflow_query_add_type(trans_flow_query, type) != 0) {
				Tcl_AppendResult(interp, "Memory error!\n", (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) inter_types);
	}

	return TCL_OK;
}


/* argv[23] - flag (boolean value) for indicating that a list of object classes are being provided to the DIF query.
 * argv[24] - object classes for DIF query (a TCL list string). At least one object class must be given or
 *	     an error is thrown.
 * NOTE: IF SEARCHING DIRECT FLOWS, THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!!
 *	 If, not it will throw an error.
 */
static int types_relation_get_dirflow_options(iflow_query_t *direct_flow_query, Tcl_Interp *interp, CONST char *argv[], policy_t *policy)
{
	int num_objs, obj;
	int i, rt;
	CONST char **obj_classes;
	bool_t filter_obj_classes;

	assert(direct_flow_query != NULL);
	if (policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded for Direct Flow Analysis!", (char *) NULL);
		return TCL_ERROR;
	}

	filter_obj_classes = getbool(argv[23]);
	if (filter_obj_classes) {
		/* First, disassemble TCL object classes list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[24], &num_objs, &obj_classes);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}

		if (num_objs < 1) {
			Tcl_AppendResult(interp, "Must provide at least one object class to Direct Flow query.", (char *) NULL);
			Tcl_Free((char *) obj_classes);
			return TCL_ERROR;
		}
	}

	if (filter_obj_classes && obj_classes != NULL) {
		/* Set the object classes info */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_classes[i], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class provided to Direct Flow query:\n", obj_classes[i], (char *) NULL);
				Tcl_Free((char *) obj_classes);
				return TCL_ERROR;
			}
			if (iflow_query_add_obj_class(direct_flow_query, obj) == -1) {
				Tcl_AppendResult(interp, "Error adding object class to direct flow query!\n", (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) obj_classes);
	}

	return TCL_OK;
}

static int types_relation_append_results(types_relation_query_t *tr_query,
							types_relation_results_t *tr_results,
							Tcl_Interp *interp,
							policy_t *policy)
{
	char tbuf[BUF_SZ], *name = NULL, *rule = NULL;
	int i, j, rt;
	int rule_idx, type_idx;

	assert(tr_query != NULL && tr_results != NULL);
	/* Append typeA string */
	snprintf(tbuf, sizeof(tbuf)-1, "%s", tr_query->type_name_A);
	Tcl_AppendElement(interp, tbuf);
	/* Append the number of common attributes */
	snprintf(tbuf, sizeof(tbuf)-1, "%s", tr_query->type_name_B);
	Tcl_AppendElement(interp, tbuf);

	/* Append the number of common attributes */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_common_attribs);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_common_attribs; i++) {
		if (get_attrib_name(tr_results->common_attribs[i], &name, policy) != 0) {
			Tcl_AppendResult(interp, "Error getting attribute name.", (char *) NULL);
			free(name);
			return TCL_ERROR;
		}
		/* Append the attribute string */
		snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
		Tcl_AppendElement(interp, tbuf);
		free(name);
	}
	/* Append the number of common roles */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_common_roles);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_common_roles; i++) {
		if (get_role_name(tr_results->common_roles[i], &name, policy) != 0) {
			Tcl_AppendResult(interp, "Error getting role name.", (char *) NULL);
			free(name);
			return TCL_ERROR;
		}
		/* Append the role string */
		snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
		Tcl_AppendElement(interp, tbuf);
		free(name);
	}
	/* Append the number of common users */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_common_users);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_common_users; i++) {
		if (get_user_name2(tr_results->common_users[i], &name, policy) != 0) {
			Tcl_AppendResult(interp, "Error getting user name.", (char *) NULL);
			free(name);
			return TCL_ERROR;
		}
		/* Append the user string */
		snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
		Tcl_AppendElement(interp, tbuf);
		free(name);
	}
	/* Append the number of type transition/change rules */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_tt_rules);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_tt_rules; i++) {
		rule = re_render_tt_rule(1, tr_results->tt_rules_results[i], policy);
		if (rule == NULL)
			return TCL_ERROR;
		Tcl_AppendElement(interp, rule);
		free(rule);
	}
	/* Append the number of allow rules */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_allow_rules);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_allow_rules; i++) {
		rule = re_render_av_rule(1, tr_results->allow_rules_results[i], 0, policy);
		if (rule == NULL)
			return TCL_ERROR;
		Tcl_AppendElement(interp, rule);
		free(rule);
	}

	/* Append common object type access information for type A and B */
	if (tr_results->common_obj_types_results != NULL) {
		snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->common_obj_types_results->num_objs_A);
		Tcl_AppendElement(interp, tbuf);
		for (i = 0; i < tr_results->common_obj_types_results->num_objs_A; i++) {
			type_idx = tr_results->common_obj_types_results->objs_A[i];
			if (get_type_name(type_idx, &name, policy) != 0) {
				Tcl_AppendResult(interp, "Error getting attribute name!", (char *) NULL);
				return TCL_ERROR;
			}
			snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
			Tcl_AppendElement(interp, tbuf);
			free(name);

			snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->typeA_access_pool->type_rules[type_idx]->num_rules);
			Tcl_AppendElement(interp, tbuf);
			for (j = 0; j < tr_results->typeA_access_pool->type_rules[type_idx]->num_rules; j++) {
				rule_idx = tr_results->typeA_access_pool->type_rules[type_idx]->rules[j];
				rule = re_render_av_rule(1, rule_idx, 0, policy);
				if (rule == NULL)
					return TCL_ERROR;
				Tcl_AppendElement(interp, rule);
				free(rule);
			}
			snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->typeB_access_pool->type_rules[type_idx]->num_rules);
			Tcl_AppendElement(interp, tbuf);
			for (j = 0; j < tr_results->typeB_access_pool->type_rules[type_idx]->num_rules; j++) {
				rule_idx = tr_results->typeB_access_pool->type_rules[type_idx]->rules[j];
				rule = re_render_av_rule(1, rule_idx, 0, policy);
				if (rule == NULL)
					return TCL_ERROR;
				Tcl_AppendElement(interp, rule);
				free(rule);
			}
		}
	} else {
		Tcl_AppendElement(interp, "0");
	}

	/* Append unique object type access information for type A */
	if (tr_results->unique_obj_types_results != NULL) {
		snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->unique_obj_types_results->num_objs_A);
		Tcl_AppendElement(interp, tbuf);
		for (i = 0; i < tr_results->unique_obj_types_results->num_objs_A; i++) {
			type_idx = tr_results->unique_obj_types_results->objs_A[i];
			if (get_type_name(type_idx, &name, policy) != 0) {
				Tcl_AppendResult(interp, "Error getting attribute name!", (char *) NULL);
				return TCL_ERROR;
			}
			snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
			Tcl_AppendElement(interp, tbuf);
			free(name);

			snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->typeA_access_pool->type_rules[type_idx]->num_rules);
			Tcl_AppendElement(interp, tbuf);
			for (j = 0; j < tr_results->typeA_access_pool->type_rules[type_idx]->num_rules; j++) {
				rule_idx = tr_results->typeA_access_pool->type_rules[type_idx]->rules[j];
				rule = re_render_av_rule(1, rule_idx, 0, policy);
				if (rule == NULL)
					return TCL_ERROR;
				Tcl_AppendElement(interp, rule);
				free(rule);
			}
		}
		/* Append unique object type access information for type B */
		snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->unique_obj_types_results->num_objs_B);
		Tcl_AppendElement(interp, tbuf);
		for(i = 0; i < tr_results->unique_obj_types_results->num_objs_B; i++) {
			type_idx = tr_results->unique_obj_types_results->objs_B[i];
			if (get_type_name(type_idx, &name, policy) != 0) {
				Tcl_AppendResult(interp, "Error getting attribute name!", (char *) NULL);
				return TCL_ERROR;
			}
			snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
			Tcl_AppendElement(interp, tbuf);
			free(name);

			snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->typeB_access_pool->type_rules[type_idx]->num_rules);
			Tcl_AppendElement(interp, tbuf);
			for (j = 0; j < tr_results->typeB_access_pool->type_rules[type_idx]->num_rules; j++) {
				rule_idx = tr_results->typeB_access_pool->type_rules[type_idx]->rules[j];
				rule = re_render_av_rule(1, rule_idx, 0, policy);
				if (rule == NULL)
					return TCL_ERROR;
				Tcl_AppendElement(interp, rule);
				free(rule);
			}
		}
	} else {
		Tcl_AppendElement(interp, "0");
		Tcl_AppendElement(interp, "0");
	}

	/* Append direct information flow information */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_dirflows);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_dirflows; i++) {
		/* Append the ending type name to the TCL list */
		snprintf(tbuf, sizeof(tbuf)-1, "%s", policy->types[tr_results->direct_flow_results[i].end_type].name);
		Tcl_AppendElement(interp, tbuf);
		/* Append the direction of the information flow for each ending type to the TCL list */
		if (tr_results->direct_flow_results[i].direction == IFLOW_BOTH)
			Tcl_AppendElement(interp, "both");
		else if (tr_results->direct_flow_results[i].direction == IFLOW_OUT)
			Tcl_AppendElement(interp, "out");
		else
			Tcl_AppendElement(interp, "in");

		rt = append_direct_edge_to_results(policy, tr_query->direct_flow_query, &tr_results->direct_flow_results[i], interp);
		if (rt != 0) {
			Tcl_AppendResult(interp, "Error appending direct flow edge information!\n", (char *) NULL);
			return TCL_ERROR;
		}
	}

	/* Append transitive information flow information for typeA->typeB */
	if (tr_results->trans_flow_results_A_to_B != NULL) {
		rt = append_transitive_iflow_results(policy, tr_results->trans_flow_results_A_to_B, interp);
		if (rt != 0) {
			Tcl_AppendResult(interp, "Error appending transitive flow results!\n", (char *) NULL);
			return TCL_ERROR;
		}
	} else {
		Tcl_AppendElement(interp, "0");
	}
	/* Append transitive information flow information for typeB->typeA */
	if (tr_results->trans_flow_results_B_to_A != NULL) {
		rt = append_transitive_iflow_results(policy, tr_results->trans_flow_results_B_to_A, interp);
		if (rt != 0) {
			Tcl_AppendResult(interp, "Error appending transitive flow results!\n", (char *) NULL);
			return TCL_ERROR;
		}
	} else {
		Tcl_AppendElement(interp, "0");
	}

	/* Append DTA information for typeA->typeB */
	if (tr_results->dta_results_A_to_B != NULL) {
		if (append_dta_results(policy, tr_results->dta_results_A_to_B, interp) != TCL_OK) {
			Tcl_AppendResult(interp, "Error appending domain transition analysis results!", (char *) NULL);
			return TCL_ERROR;
		}
	} else {
		Tcl_AppendElement(interp, "0");
	}
	/* Append DTA information for typeB->typeA */
	if (tr_results->dta_results_B_to_A != NULL) {
		if (append_dta_results(policy, tr_results->dta_results_B_to_A, interp) != TCL_OK) {
			Tcl_AppendResult(interp, "Error appending domain transition analysis results!", (char *) NULL);
			return TCL_ERROR;
		}
	} else {
		Tcl_AppendElement(interp, "0");
	}

	return 0;
}

/*
 * Types Relationship Analysis (QUERY ARGUMENTS):
 * argv[1]  - typeA (string)
 * argv[2]  - typeB (string)
 * argv[3]  - comm_attribs_sel (boolean value)
 * argv[4]  - comm_roles_sel (boolean value)
 * argv[5]  - comm_users_sel (boolean value)
 * argv[6]  - comm_access_sel (boolean value)
 * argv[7]  - unique_access_sel (boolean value)
 * argv[8]  - dta_sel (boolean value)
 * argv[9]  - trans_flow_sel (boolean value)
 * argv[10] - dir_flow_sel (boolean value)
 * argv[11] - tt_rule_sel  (boolean value)
 * argv[12] - te_rules_sel (boolean value)
 *
 * argv[13] - (boolean value) for indicating that a list of transitive flow object classes are being provided to the TIF query.
 * argv[14] - number of object classes that are to be included in the transitive flow query.
 * argv[15] - encoded list of object class/permissions to include in the the transitive flow query.
 * argv[16] - flag (boolean value) for indicating whether or not to include intermediate types in the
 *	      the transitive flow query.
 * argv[17] - TCL list of intermediate types for the transitive flow analysis
 * NOTE: IF SEARCHING TRANSITIVE FLOWS, THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!!
 *	 If, not it will throw an error.
 *
 * argv[18] - flag (boolean value) for indicating that a list of object classes are being provided to the DTA query.
 * argv[19] - number of object classes that are to be included in the DTA query.
 * argv[20] - list of object classes/permissions for the DTA query.
 * argv[21] - flag (boolean value) for selecting object type(s) in the DTA query.
 * argv[22] - list of object types for the DTA query.
 *
 * argv[23] - flag (boolean value) for indicating that a list of object classes are being provided to the DIF query.
 * argv[24] - object classes for DIF query (a TCL list string). At least one object class must be given or
 *	     an error is thrown.
 * NOTE: IF SEARCHING DIRECT FLOWS, THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!!
 *	 If, not it will throw an error.
 *
 *
 * Types Relationship Analysis (RESULTS FORMAT):
 *	Returns a list organized to represent the tree structure that results from a types relationship
 *	analysis.  The TCL list looks like the following:
 *
 *	INDEX			CONTENTS
 *	0			typeA string
 *	1			typeB string
 *	2			Number of common attributes (Na)
 *		3		attribute 1
 *		....
 *		Na		attribute Na
 *	next			Number of common roles (Nr)
 *		next		role 1
 *		...
 *		Nr		role Nr
 *	next			Number of common users (Nu)
 *		next		user 1
 *		...
 *		Nu		user Nu
 *	next			Number of type transition rules
 *		next
 *		...
 *		N		tt rule N
 *	next			Number of other allow rules
 *		next
 *		...
 *		Np		allow rule Np
 *	next			Number of common objects for typeA
 *		next		object 1
 *		...
 *		N		typeA common object N
 *				Number of common object rules for typeA
 *				Number of common objects for typeB
 *				Number of common object rules for typeB
 *	next			Number of unique objects for typeA
 *				Number of unique object rules for typeA
 *				Number of unique objects for typeB
 *				Number of unique object rules for typeB
 *	next			Number of Direct Information flows
 *			Follows the format for the Apol_DirectInformationFlowAnalysis()
 *	next			Number of Transitive Information flows from typeA->typeB
 *			Follows the format for the Apol_TransitiveFlowAnalysis()
 *	next			Number of Transitive Information flows from typeB->typeA
 *			Follows the format for the Apol_TransitiveFlowAnalysis()
 *	next			Number of Forward Domain Transitions from typeA->typeB
 *	next		N, # of target domain types (if none, then no other results returned)
 *	  next		name first target type (if any)
 *	  next		X, # of allow transition rules
 *	  next X*2	pt rule1, lineno1, ....
 *	  next		Y, # of entry point file types for first target type
 *	    next	first file type
 *	    next	A, # of file entrypoint rules
 *	    next A*2	ep rule 1, lineno1,....
 *	    next	B, # of file execute rules
 *	    next B*2	ex rule1, lineno1, ...
 *
 *	    next	(repeat next file type record as above Y times)
 *
 *	next		(repeat target type record N times)
 *				Number of Forward Domain Transitions from typeB->typeA
 *		Follows the preceding format.
 *
 */
static int Apol_TypesRelationshipAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        /* FIX ME */
	types_relation_query_t *tr_query = NULL;
	types_relation_results_t *tr_results = NULL;
	int rt, i;
	bool_t option_selected;

	if(argc != 25) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (policydb == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}

	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "TypeA string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "TypeB string is too large.", (char *) NULL);
		return TCL_ERROR;
	}

	tr_query = types_relation_query_create();
	if (tr_query == NULL) {
		Tcl_AppendResult(interp, "Error creating query.", (char *) NULL);
		return TCL_ERROR;
	}

	tr_query->type_name_A = (char *)malloc((strlen(argv[1]) + 1) * sizeof(char));
	if (tr_query->type_name_A == NULL) {
		types_relation_query_destroy(tr_query);
		Tcl_AppendResult(interp, "out of memory", (char *) NULL);
		return TCL_ERROR;
	}
	strcpy(tr_query->type_name_A, argv[1]);

	tr_query->type_name_B = (char *)malloc((strlen(argv[2]) + 1) * sizeof(char));
	if (tr_query->type_name_B == NULL) {
		types_relation_query_destroy(tr_query);
		Tcl_AppendResult(interp, "out of memory", (char *) NULL);
		return TCL_ERROR;
	}
	strcpy(tr_query->type_name_B, argv[2]);

	for (i = 3; i < 13; i++) {
		option_selected = getbool(argv[i]);
		if (option_selected) {
			switch(i) {
			case 3:
				tr_query->options |= TYPES_REL_COMMON_ATTRIBS;
				break;
			case 4:
				tr_query->options |= TYPES_REL_COMMON_ROLES;
				break;
			case 5:
				tr_query->options |= TYPES_REL_COMMON_USERS;
				break;
			case 6:
				tr_query->options |= TYPES_REL_COMMON_ACCESS;
				break;
			case 7:
				tr_query->options |= TYPES_REL_UNIQUE_ACCESS;
				break;
			case 8:
				tr_query->options |= TYPES_REL_DOMAINTRANS;
				/* Create the query structure */
				if (!tr_query->dta_query) {
					tr_query->dta_query = dta_query_create();
					if (tr_query->dta_query == NULL) {
						Tcl_AppendResult(interp, "Memory error allocating dta query.\n",
							(char *) NULL);
						types_relation_query_destroy(tr_query);
						return TCL_ERROR;
					}
				}
				/* Gather DTA options */
				if (types_relation_get_dta_options(tr_query->dta_query, interp, argv, policy) != 0) {
					types_relation_query_destroy(tr_query);
					return TCL_ERROR;
				}
				break;
			case 9:
				tr_query->options |= TYPES_REL_TRANSFLOWS;
				/* Create the query structure */
				if (!tr_query->trans_flow_query) {
					tr_query->trans_flow_query = iflow_query_create();
					if (tr_query->trans_flow_query == NULL) {
						Tcl_AppendResult(interp, "Memory error allocating transitive iflow query.\n",
							(char *) NULL);
						types_relation_query_destroy(tr_query);
						return TCL_ERROR;
					}
				}
				/* Gather TRANSFLOW options*/
				if (types_relation_get_transflow_options(tr_query->trans_flow_query, interp, argv, policy) != 0) {
					types_relation_query_destroy(tr_query);
					return TCL_ERROR;
				}
				break;
			case 10:
				tr_query->options |= TYPES_REL_DIRFLOWS;
				/* Create the query structure */
				if (!tr_query->direct_flow_query) {
					tr_query->direct_flow_query = iflow_query_create();
					if (tr_query->direct_flow_query == NULL) {
						Tcl_AppendResult(interp, "Memory error allocating direct iflow query.\n",
							(char *) NULL);
						types_relation_query_destroy(tr_query);
						return TCL_ERROR;
					}
				}
				/* Gather DIRFLOW options*/
				if (types_relation_get_dirflow_options(tr_query->direct_flow_query, interp, argv, policy) != 0) {
					types_relation_query_destroy(tr_query);
					return TCL_ERROR;
				}
				break;
			case 11:
				tr_query->options |= TYPES_REL_TTRULES;
				break;
			case 12:
				tr_query->options |= TYPES_REL_ALLOW_RULES;
				break;
			default:
				fprintf(stderr, "Invalid option index: %d\n", i);
			}
		}
	}
	/* Perform the analysis */
	rt = types_relation_determine_relationship(tr_query, &tr_results, policy);
	if (rt != 0) {
		types_relation_query_destroy(tr_query);
		Tcl_AppendResult(interp, "Analysis error!", (char *) NULL);
		return TCL_ERROR;
	}
	if (types_relation_append_results(tr_query, tr_results, interp, policy) != TCL_OK) {
		types_relation_query_destroy(tr_query);
		if (tr_results) types_relation_destroy_results(tr_results);
		return TCL_ERROR;
	}

	types_relation_query_destroy(tr_query);
	if (tr_results) types_relation_destroy_results(tr_results);
	return TCL_OK;
}

#endif
