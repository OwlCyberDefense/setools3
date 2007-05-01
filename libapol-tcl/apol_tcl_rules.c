/**
 * @file
 * Implementation for the apol interface to search rules within a policy.
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

#include <config.h>

#include "apol_tcl_other.h"
#include "apol_tcl_render.h"

#include <apol/util.h>
#include <qpol/policy_extend.h>
#include <tcl.h>
#include <errno.h>

/********* routines to manipulate a qpol rule as a Tcl object *********/

/**
 * Create and return a new Tcl_Obj whose value is set to prefix-rule.
 */
static Tcl_Obj *rule_to_tcl_obj(const char *prefix, void *rule)
{
	Tcl_Obj *o;
	char s[1], *name;
	int num_bytes;

	num_bytes = snprintf(s, 1, "%s-%p", prefix, rule) + 1;
	name = ckalloc(num_bytes);
	snprintf(name, num_bytes, "%s-%p", prefix, rule);
	o = Tcl_NewStringObj(name, -1);
	o->internalRep.otherValuePtr = rule;
	ckfree(name);
	return o;
}

static struct Tcl_ObjType qpol_avrule_tcl_obj_type = {
	"avrule",
	NULL,
	NULL,
	NULL,
	NULL
};

int qpol_avrule_to_tcl_obj(Tcl_Interp * interp, qpol_avrule_t * rule, Tcl_Obj ** o)
{
	*o = rule_to_tcl_obj("avrule", rule);
	(*o)->typePtr = &qpol_avrule_tcl_obj_type;
	return TCL_OK;
}

static struct Tcl_ObjType qpol_terule_tcl_obj_type = {
	"terule",
	NULL,
	NULL,
	NULL,
	NULL
};

int qpol_terule_to_tcl_obj(Tcl_Interp * interp, qpol_terule_t * rule, Tcl_Obj ** o)
{
	*o = rule_to_tcl_obj("terule", rule);
	(*o)->typePtr = &qpol_terule_tcl_obj_type;
	return TCL_OK;
}

/**
 * Convert an iterator of qpol_avrule_t pointers to a Tcl
 * representation.  Note that the iterator will be incremented to its
 * end when this function returns.
 *
 * @param interp Tcl interpreter object.
 * @param iter Iterator to convert.
 * @param obj Destination to create Tcl list.
 *
 * @return 0 on success, < 0 on error.
 */
static int qpol_iter_avrule_to_tcl_list(Tcl_Interp * interp, qpol_iterator_t * iter, Tcl_Obj ** obj)
{
	qpol_avrule_t *avrule;
	Tcl_Obj *o;
	*obj = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&avrule) < 0 ||
		    qpol_avrule_to_tcl_obj(interp, avrule, &o) < 0 || Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			return -1;
		}
	}
	return 0;
}

/**
 * Convert an iterator of qpol_terule_t pointers to a Tcl
 * representation.  Note that the iterator will be incremented to its
 * end when this function returns.
 *
 * @param interp Tcl interpreter object.
 * @param iter Iterator to convert.
 * @param obj Destination to create Tcl list.
 *
 * @return 0 on success, < 0 on error.
 */
static int qpol_iter_terule_to_tcl_list(Tcl_Interp * interp, qpol_iterator_t * iter, Tcl_Obj ** obj)
{
	qpol_terule_t *terule;
	Tcl_Obj *o;
	*obj = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&terule) < 0 ||
		    qpol_terule_to_tcl_obj(interp, terule, &o) < 0 || Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			return -1;
		}
	}
	return 0;
}

int apol_vector_avrule_to_tcl_list(Tcl_Interp * interp, apol_vector_t * v, Tcl_Obj ** obj)
{
	size_t i;
	*obj = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		qpol_avrule_t *rule = (qpol_avrule_t *) apol_vector_get_element(v, i);
		Tcl_Obj *o;
		if (qpol_avrule_to_tcl_obj(interp, rule, &o) == TCL_ERROR || Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			return -1;
		}
	}
	return 0;
}

int apol_vector_terule_to_tcl_list(Tcl_Interp * interp, apol_vector_t * v, Tcl_Obj ** obj)
{
	size_t i;
	*obj = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		qpol_terule_t *rule = (qpol_terule_t *) apol_vector_get_element(v, i);
		Tcl_Obj *o;
		if (qpol_terule_to_tcl_obj(interp, rule, &o) == TCL_ERROR || Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			return -1;
		}
	}
	return 0;
}

int tcl_obj_to_qpol_avrule(Tcl_Interp * interp, Tcl_Obj * o, qpol_avrule_t ** rule)
{
	if (o->typePtr != &qpol_avrule_tcl_obj_type) {
		CONST char *name;
		name = Tcl_GetString(o);
		if (sscanf(name, "avrule-%p", (void **)rule) != 1) {
			Tcl_SetResult(interp, "Invalid qpol_avrule_tcl object.", TCL_STATIC);
			return TCL_ERROR;
		}
		/* shimmer the object back to a qpol_avrule_tcl */
		o->typePtr = &qpol_avrule_tcl_obj_type;
		o->internalRep.otherValuePtr = *rule;
	} else {
		*rule = (qpol_avrule_t *) o->internalRep.otherValuePtr;
	}
	return TCL_OK;
}

int tcl_obj_to_qpol_terule(Tcl_Interp * interp, Tcl_Obj * o, qpol_terule_t ** rule)
{
	if (o->typePtr != &qpol_terule_tcl_obj_type) {
		CONST char *name;
		name = Tcl_GetString(o);
		if (sscanf(name, "terule-%p", (void **)rule) != 1) {
			Tcl_SetResult(interp, "Invalid qpol_terule_tcl object.", TCL_STATIC);
			return TCL_ERROR;
		}
		/* shimmer the object back to a qpol_terule_tcl */
		o->typePtr = &qpol_terule_tcl_obj_type;
		o->internalRep.otherValuePtr = *rule;
	} else {
		*rule = (qpol_terule_t *) o->internalRep.otherValuePtr;
	}
	return TCL_OK;
}

static struct Tcl_ObjType qpol_syn_avrule_tcl_obj_type = {
	"syn_avrule",
	NULL,
	NULL,
	NULL,
	NULL
};

/**
 * Given a qpol_syn_avrule_t object, create a new Tcl_Obj which
 * represents it.  The Tcl_Obj will have a unique string identifier
 * for the rule.
 *
 * @param interp Tcl interpreter object.
 * @param rule Rule to store.
 * @param o Reference to where to create the new Tcl_Obj.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 */
static int qpol_syn_avrule_to_tcl_obj(Tcl_Interp * interp, qpol_syn_avrule_t * rule, Tcl_Obj ** o)
{
	*o = rule_to_tcl_obj("syn_avrule", rule);
	(*o)->typePtr = &qpol_syn_avrule_tcl_obj_type;
	return TCL_OK;
}

int tcl_obj_to_qpol_syn_avrule(Tcl_Interp * interp, Tcl_Obj * o, qpol_syn_avrule_t ** rule)
{
	if (o->typePtr != &qpol_syn_avrule_tcl_obj_type) {
		CONST char *name;
		name = Tcl_GetString(o);
		if (sscanf(name, "syn_avrule-%p", (void **)rule) != 1) {
			Tcl_SetResult(interp, "Invalid qpol_syn_avrule_tcl object.", TCL_STATIC);
			return TCL_ERROR;
		}
		/* shimmer the object back to a qpol_syn_avrule_tcl */
		o->typePtr = &qpol_syn_avrule_tcl_obj_type;
		o->internalRep.otherValuePtr = *rule;
	} else {
		*rule = (qpol_syn_avrule_t *) o->internalRep.otherValuePtr;
	}
	return TCL_OK;
}

static struct Tcl_ObjType qpol_syn_terule_tcl_obj_type = {
	"syn_terule",
	NULL,
	NULL,
	NULL,
	NULL
};

/**
 * Given a qpol_syn_terule_t object, create a new Tcl_Obj which
 * represents it.  The Tcl_Obj will have a unique string identifier
 * for the rule.
 *
 * @param interp Tcl interpreter object.
 * @param rule Rule to store.
 * @param o Reference to where to create the new Tcl_Obj.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 */
static int qpol_syn_terule_to_tcl_obj(Tcl_Interp * interp, qpol_syn_terule_t * rule, Tcl_Obj ** o)
{
	*o = rule_to_tcl_obj("syn_terule", rule);
	(*o)->typePtr = &qpol_syn_terule_tcl_obj_type;
	return TCL_OK;
}

int tcl_obj_to_qpol_syn_terule(Tcl_Interp * interp, Tcl_Obj * o, qpol_syn_terule_t ** rule)
{
	if (o->typePtr != &qpol_syn_terule_tcl_obj_type) {
		CONST char *name;
		name = Tcl_GetString(o);
		if (sscanf(name, "syn_terule-%p", (void **)rule) != 1) {
			Tcl_SetResult(interp, "Invalid qpol_syn_terule_tcl object.", TCL_STATIC);
			return TCL_ERROR;
		}
		/* shimmer the object back to a qpol_syn_terule_tcl */
		o->typePtr = &qpol_syn_terule_tcl_obj_type;
		o->internalRep.otherValuePtr = *rule;
	} else {
		*rule = (qpol_syn_terule_t *) o->internalRep.otherValuePtr;
	}
	return TCL_OK;
}

int apol_vector_syn_avrule_to_tcl_list(Tcl_Interp * interp, apol_vector_t * v, Tcl_Obj ** obj)
{
	size_t i;
	*obj = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		qpol_syn_avrule_t *rule = apol_vector_get_element(v, i);
		Tcl_Obj *o;
		if (qpol_syn_avrule_to_tcl_obj(interp, rule, &o) == TCL_ERROR
		    || Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			return -1;
		}
	}
	return 0;
}

int apol_vector_syn_terule_to_tcl_list(Tcl_Interp * interp, apol_vector_t * v, Tcl_Obj ** obj)
{
	size_t i;
	*obj = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		qpol_syn_terule_t *rule = apol_vector_get_element(v, i);
		Tcl_Obj *o;
		if (qpol_syn_terule_to_tcl_obj(interp, rule, &o) == TCL_ERROR
		    || Tcl_ListObjAppendElement(interp, *obj, o) == TCL_ERROR) {
			return -1;
		}
	}
	return 0;
}

/******************** analysis code below ********************/

/**
 * Takes a Tcl typeset list (e.g., "{foo 1 0 1}") and splits in into
 * its symbol name, indirect flag, and if the symbol is a type and/or
 * attribute.
 *
 * @param interp Tcl interpreter object.
 * @param typeset Character string represting a Tcl typeset.
 * @param sym_name Reference to where to write the symbol name.  The
 * caller must free() this value afterwards.
 * @param indirect Reference to where to write indirect flag.
 * @param type_attr Reference to where to write the type/attribute
 * selection flag.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_tcl_string_to_typeset(Tcl_Interp * interp, CONST char *typeset, char **sym_name, int *indirect, int *type_attr)
{
	Tcl_Obj *typeset_obj = Tcl_NewStringObj(typeset, -1);
	Tcl_Obj *name_obj, *indirect_obj, *type_obj, *attr_obj;
	char *s;
	int i;
	*sym_name = NULL;
	*indirect = 0;
	if (*typeset == '\0') {
		*type_attr = APOL_QUERY_SYMBOL_IS_TYPE | APOL_QUERY_SYMBOL_IS_ATTRIBUTE;
		return 0;
	}
	*type_attr = 0;
	if (Tcl_ListObjIndex(interp, typeset_obj, 0, &name_obj) == TCL_ERROR ||
	    Tcl_ListObjIndex(interp, typeset_obj, 1, &indirect_obj) == TCL_ERROR ||
	    Tcl_ListObjIndex(interp, typeset_obj, 2, &type_obj) == TCL_ERROR ||
	    Tcl_ListObjIndex(interp, typeset_obj, 3, &attr_obj) == TCL_ERROR) {
		return -1;
	}
	if (indirect_obj == NULL || Tcl_GetBooleanFromObj(interp, indirect_obj, indirect) == TCL_ERROR) {
		ERR(policydb, "Invalid indirect flag for typeset '%s'.", typeset);
		return -1;
	}
	if (type_obj == NULL || Tcl_GetBooleanFromObj(interp, type_obj, &i) == TCL_ERROR) {
		ERR(policydb, "Invalid type flag for typeset '%s'.", typeset);
		return -1;
	}
	if (i) {
		*type_attr |= APOL_QUERY_SYMBOL_IS_TYPE;
	}
	if (attr_obj == NULL || Tcl_GetBooleanFromObj(interp, attr_obj, &i) == TCL_ERROR) {
		ERR(policydb, "Invalid attribute flag for typeset '%s'.", typeset);
		return -1;
	}
	if (i) {
		*type_attr |= APOL_QUERY_SYMBOL_IS_ATTRIBUTE;
	}
	s = Tcl_GetString(name_obj);
	if (s[0] == '\0') {
		*sym_name = NULL;
	} else {
		*sym_name = strdup(s);
		if (*sym_name == NULL) {
			Tcl_SetResult(interp, strerror(ENOMEM), TCL_STATIC);
			return -1;
		}
	}
	return 0;
}

/**
 * Perform a rule search upon the currently loaded policy, returning
 * two unsorted lists of rules.  The first list is a list of av rules,
 * the second for te rules.  If <tt>syn_search</tt> is given as an
 * option, then this will be a vector of syntactic rules rather than
 * semantic rules.
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
 *   <li>regex - treat all symbols as regular expression
 *   <li>source_any - treat source symbol as criteria for target and default
 *   <li>syn_search - perform syntactic search instead of semantic (default)
 *   <li>match_all_perms - find rules that match all selected
 *                         permissions instead of any permission
 * </ul>
 * For source/target/default types, these are each a list of four parameters:
 * <ol>
 *   <li>type/attribute symbol name (or empty string to ignore)
 *   <li>if non-zero, then perform indirect matching with this symbol
 *   <li>if non-zero, then the symbol as a type
 *   <li>if non-zero, then treat the symbol as an attribute
 * </ol>
 * For classes, the returned rule's class must be within this list.
 * For permissions, the rule must have at least one permission within
 * this list.  Pass an empty list to skip this filter.
 */
static int Apol_SearchTERules(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	Tcl_Obj *rules_elem[2], *result_obj;
	unsigned int avrules = 0, terules = 0;
	CONST char **rule_strings = NULL, **other_opt_strings = NULL, **class_strings = NULL, **perm_strings = NULL;
	char *sym_name = NULL;
	int num_opts, do_syn_search = 0, indirect, type_attr;
	apol_avrule_query_t *avquery = NULL;
	apol_terule_query_t *tequery = NULL;
	apol_vector_t *av = NULL, *te = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 8) {
		ERR(policydb, "%s",
		    "Need a rule selection, other options, source type, target type, default type, classes, and permissions");
		goto cleanup;
	}

	if ((avquery = apol_avrule_query_create()) == NULL || (tequery = apol_terule_query_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[1], &num_opts, &rule_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = rule_strings[num_opts];
		if (strcmp(s, "allow") == 0) {
			avrules |= QPOL_RULE_ALLOW;
		} else if (strcmp(s, "neverallow") == 0) {
			avrules |= QPOL_RULE_NEVERALLOW;
		} else if (strcmp(s, "auditallow") == 0) {
			avrules |= QPOL_RULE_AUDITALLOW;
		} else if (strcmp(s, "dontaudit") == 0) {
			avrules |= QPOL_RULE_DONTAUDIT;
		} else if (strcmp(s, "type_transition") == 0) {
			terules |= QPOL_RULE_TYPE_TRANS;
		} else if (strcmp(s, "type_member") == 0) {
			terules |= QPOL_RULE_TYPE_MEMBER;
		} else if (strcmp(s, "type_change") == 0) {
			terules |= QPOL_RULE_TYPE_CHANGE;
		} else {
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
		} else if (strcmp(s, "regex") == 0) {
			apol_avrule_query_set_regex(policydb, avquery, 1);
			apol_terule_query_set_regex(policydb, tequery, 1);
		} else if (strcmp(s, "source_any") == 0) {
			apol_avrule_query_set_source_any(policydb, avquery, 1);
			apol_terule_query_set_source_any(policydb, tequery, 1);
		} else if (strcmp(s, "syn_search") == 0) {
			do_syn_search = 1;
		} else if (strcmp(s, "match_all_perms") == 0) {
			apol_avrule_query_set_all_perms(policydb, avquery, 1);
		} else {
			ERR(policydb, "Invalid option %s.", s);
			goto cleanup;
		}
	}

	if (apol_tcl_string_to_typeset(interp, argv[3], &sym_name, &indirect, &type_attr) < 0 ||
	    apol_avrule_query_set_source(policydb, avquery, sym_name, indirect) < 0 ||
	    apol_avrule_query_set_source_component(policydb, avquery, type_attr) < 0 ||
	    apol_terule_query_set_source(policydb, tequery, sym_name, indirect) < 0 ||
	    apol_terule_query_set_source_component(policydb, tequery, type_attr) < 0) {
		goto cleanup;
	}

	free(sym_name);
	sym_name = NULL;
	if (apol_tcl_string_to_typeset(interp, argv[4], &sym_name, &indirect, &type_attr) < 0 ||
	    apol_avrule_query_set_target(policydb, avquery, sym_name, indirect) < 0 ||
	    apol_avrule_query_set_target_component(policydb, avquery, type_attr) < 0 ||
	    apol_terule_query_set_target(policydb, tequery, sym_name, indirect) < 0 ||
	    apol_terule_query_set_target_component(policydb, tequery, type_attr) < 0) {
		goto cleanup;
	}

	free(sym_name);
	sym_name = NULL;
	if (apol_tcl_string_to_typeset(interp, argv[5], &sym_name, &indirect, &type_attr) < 0 ||
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
		if (!do_syn_search) {
			if (apol_avrule_get_by_query(policydb, avquery, &av) < 0 ||
			    apol_vector_avrule_to_tcl_list(interp, av, rules_elem + 0) < 0) {
				goto cleanup;
			}
		} else {
			if (apol_syn_avrule_get_by_query(policydb, avquery, &av) < 0 ||
			    apol_vector_syn_avrule_to_tcl_list(interp, av, rules_elem + 0) < 0) {
				goto cleanup;
			}
		}
	} else {
		rules_elem[0] = Tcl_NewListObj(0, NULL);
	}

	if (terules != 0) {
		if (!do_syn_search) {
			if (apol_terule_get_by_query(policydb, tequery, &te) < 0 ||
			    apol_vector_terule_to_tcl_list(interp, te, rules_elem + 1) < 0) {
				goto cleanup;
			}
		} else {
			if (apol_syn_terule_get_by_query(policydb, tequery, &te) < 0 ||
			    apol_vector_syn_terule_to_tcl_list(interp, te, rules_elem + 1) < 0) {
				goto cleanup;
			}
		}
	} else {
		rules_elem[1] = Tcl_NewListObj(0, NULL);
	}

	result_obj = Tcl_NewListObj(2, rules_elem);
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	if (rule_strings != NULL) {
		Tcl_Free((char *)rule_strings);
	}
	if (other_opt_strings != NULL) {
		Tcl_Free((char *)other_opt_strings);
	}
	if (class_strings != NULL) {
		Tcl_Free((char *)class_strings);
	}
	if (perm_strings != NULL) {
		Tcl_Free((char *)perm_strings);
	}
	free(sym_name);
	apol_avrule_query_destroy(&avquery);
	apol_terule_query_destroy(&tequery);
	apol_vector_destroy(&av);
	apol_vector_destroy(&te);
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
static int cond_expr_iter_to_tcl_obj(Tcl_Interp * interp, qpol_iterator_t * iter, Tcl_Obj ** obj)
{
	qpol_cond_expr_node_t *expr;
	qpol_bool_t *cond_bool;
	char *bool_name;
	uint32_t expr_type;
	const char *expr_str;
	Tcl_Obj *expr_elem;
	int retval = TCL_ERROR;

	*obj = Tcl_NewListObj(0, NULL);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&expr) < 0 ||
		    qpol_cond_expr_node_get_expr_type(qpolicydb, expr, &expr_type) < 0) {
			goto cleanup;
		}
		if (expr_type == QPOL_COND_EXPR_BOOL) {
			if (qpol_cond_expr_node_get_bool(qpolicydb,
							 expr, &cond_bool) < 0 ||
			    qpol_bool_get_name(qpolicydb, cond_bool, &bool_name) < 0) {
				goto cleanup;
			}
			expr_elem = Tcl_NewStringObj(bool_name, -1);
		} else {
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
 * Rules lists are each two sub-lists, one for av rules the other for
 * te rules.
 *
 * @param avrules A bitmask of which av rules to add to rules lists.
 * @param terules A bitmask of which te rules to add to rules lists.
 */
static int append_cond_result_to_list(Tcl_Interp * interp,
				      qpol_cond_t * result, unsigned int avrules, unsigned int terules, Tcl_Obj * result_list)
{
	Tcl_Obj *cond_elem[3], *cond_list, *rules_elem[2];
	qpol_iterator_t *conditer, *aviter = NULL, *teiter = NULL;
	int retval = TCL_ERROR;

	if (qpol_cond_get_expr_node_iter(qpolicydb, result, &conditer) < 0 ||
	    cond_expr_iter_to_tcl_obj(interp, conditer, cond_elem + 0) == TCL_ERROR) {
		goto cleanup;
	}

	if (qpol_cond_get_av_true_iter(qpolicydb,
				       result, avrules, &aviter) < 0 ||
	    qpol_cond_get_te_true_iter(qpolicydb, result, terules, &teiter)) {
		goto cleanup;
	}
	if (qpol_iter_avrule_to_tcl_list(interp, aviter, rules_elem + 0) < 0 ||
	    qpol_iter_terule_to_tcl_list(interp, teiter, rules_elem + 1) < 0) {
		goto cleanup;
	}
	cond_elem[1] = Tcl_NewListObj(2, rules_elem);
	qpol_iterator_destroy(&aviter);
	qpol_iterator_destroy(&teiter);

	if (qpol_cond_get_av_false_iter(qpolicydb,
					result, avrules, &aviter) < 0 ||
	    qpol_cond_get_te_false_iter(qpolicydb, result, terules, &teiter)) {
		goto cleanup;
	}
	if (qpol_iter_avrule_to_tcl_list(interp, aviter, rules_elem + 0) < 0 ||
	    qpol_iter_terule_to_tcl_list(interp, teiter, rules_elem + 1) < 0) {
		goto cleanup;
	}
	cond_elem[2] = Tcl_NewListObj(2, rules_elem);

	cond_list = Tcl_NewListObj(3, cond_elem);
	if (Tcl_ListObjAppendElement(interp, result_list, cond_list) == TCL_ERROR) {
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&conditer);
	qpol_iterator_destroy(&aviter);
	qpol_iterator_destroy(&teiter);
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
static int Apol_SearchConditionalRules(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
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
		ERR(policydb, "%s", "Need a rule selection, other options, and boolean name.");
		goto cleanup;
	}

	if ((query = apol_cond_query_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[1], &num_opts, &rule_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = rule_strings[num_opts];
		if (strcmp(s, "allow") == 0) {
			avrules |= QPOL_RULE_ALLOW;
		} else if (strcmp(s, "auditallow") == 0) {
			avrules |= QPOL_RULE_AUDITALLOW;
		} else if (strcmp(s, "dontaudit") == 0) {
			avrules |= QPOL_RULE_DONTAUDIT;
		} else if (strcmp(s, "type_transition") == 0) {
			terules |= QPOL_RULE_TYPE_TRANS;
		} else if (strcmp(s, "type_member") == 0) {
			terules |= QPOL_RULE_TYPE_MEMBER;
		} else if (strcmp(s, "type_change") == 0) {
			terules |= QPOL_RULE_TYPE_CHANGE;
		} else {
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
		} else {
			ERR(policydb, "Invalid option %s.", s);
			goto cleanup;
		}
	}

	if (*argv[3] != '\0' && apol_cond_query_set_bool(policydb, query, argv[3]) < 0) {
		goto cleanup;
	}

	if (apol_cond_get_by_query(policydb, query, &v) < 0) {
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
		Tcl_Free((char *)rule_strings);
	}
	if (other_opt_strings != NULL) {
		Tcl_Free((char *)other_opt_strings);
	}
	apol_cond_query_destroy(&query);
	apol_vector_destroy(&v);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a qpol_role_allow_t and appends a tuple of it to result_list.
 * The tuple consists of:
 * <code>
 *    { "allow" source_role target_role "" }
 * </code>
 */
static int append_role_allow_to_list(Tcl_Interp * interp, qpol_role_allow_t * rule, Tcl_Obj * result_list)
{
	qpol_role_t *source, *target;
	char *source_name, *target_name;
	Tcl_Obj *allow_elem[4], *allow_list;
	int retval = TCL_ERROR;

	if (qpol_role_allow_get_source_role(qpolicydb, rule, &source) < 0 ||
	    qpol_role_allow_get_target_role(qpolicydb, rule, &target) < 0) {
		goto cleanup;
	}

	if (qpol_role_get_name(qpolicydb, source, &source_name) < 0 || qpol_role_get_name(qpolicydb, target, &target_name) < 0) {
		goto cleanup;
	}
	allow_elem[0] = Tcl_NewStringObj("allow", -1);
	allow_elem[1] = Tcl_NewStringObj(source_name, -1);
	allow_elem[2] = Tcl_NewStringObj(target_name, -1);
	allow_elem[3] = Tcl_NewStringObj("", -1);
	allow_list = Tcl_NewListObj(4, allow_elem);
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
 *    { "role_transition" source_role target_type default_role }
 * </code>
 */
static int append_role_trans_to_list(Tcl_Interp * interp, qpol_role_trans_t * rule, Tcl_Obj * result_list)
{
	qpol_role_t *source, *default_role;
	qpol_type_t *target;
	char *source_name, *target_name, *default_name;
	Tcl_Obj *role_trans_elem[4], *role_trans_list;
	int retval = TCL_ERROR;

	if (qpol_role_trans_get_source_role(qpolicydb, rule, &source) < 0 ||
	    qpol_role_trans_get_target_type(qpolicydb, rule, &target) < 0 ||
	    qpol_role_trans_get_default_role(qpolicydb, rule, &default_role) < 0) {
		goto cleanup;
	}

	if (qpol_role_get_name(qpolicydb, source, &source_name) < 0 ||
	    qpol_type_get_name(qpolicydb, target, &target_name) < 0 ||
	    qpol_role_get_name(qpolicydb, default_role, &default_name) < 0) {
		goto cleanup;
	}
	role_trans_elem[0] = Tcl_NewStringObj("role_transition", -1);
	role_trans_elem[1] = Tcl_NewStringObj(source_name, -1);
	role_trans_elem[2] = Tcl_NewStringObj(target_name, -1);
	role_trans_elem[3] = Tcl_NewStringObj(default_name, -1);
	role_trans_list = Tcl_NewListObj(4, role_trans_elem);
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
 *   <li>for allow rules: target role;
 *       for role_transition:  target type
 *   <li>for allow rules: an empty list;
 *       for role_transition: default role
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
static int Apol_SearchRBACRules(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
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
		ERR(policydb, "%s", "Need a rule selection, other options, source role, target role/type, and default role.");
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[1], &num_opts, &rule_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = rule_strings[num_opts];
		if (strcmp(s, "allow") == 0) {
			if ((raquery = apol_role_allow_query_create()) == NULL) {
				ERR(policydb, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		} else if (strcmp(s, "role_transition") == 0) {
			if ((rtquery = apol_role_trans_query_create()) == NULL) {
				ERR(policydb, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		} else {
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
		} else {
			ERR(policydb, "Invalid option %s.", s);
			goto cleanup;
		}
	}

	if (raquery != NULL) {
		if (apol_role_allow_query_set_source(policydb, raquery, argv[3]) < 0 ||
		    apol_role_allow_query_set_target(policydb, raquery, argv[4]) < 0) {
			goto cleanup;
		}
		if (apol_role_allow_get_by_query(policydb, raquery, &rav) < 0) {
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
		if (apol_role_trans_get_by_query(policydb, rtquery, &rav) < 0) {
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
		Tcl_Free((char *)rule_strings);
	}
	if (other_opt_strings != NULL) {
		Tcl_Free((char *)other_opt_strings);
	}
	apol_role_allow_query_destroy(&raquery);
	apol_role_trans_query_destroy(&rtquery);
	apol_vector_destroy(&rav);
	apol_vector_destroy(&rtv);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Takes a qpol_range_trans_t and appends a tuple of it to
 * result_list.  The tuple consists of:
 * <code>
 *    { source_type_set target_type_set target_class range }
 * </code>
 * The type sets are Tcl lists.
 */
static int append_range_trans_to_list(Tcl_Interp * interp, qpol_range_trans_t * rule, Tcl_Obj * result_list)
{
	qpol_type_t *source, *target;
	qpol_class_t *target_class;
	qpol_mls_range_t *range;
	apol_mls_range_t *apol_range = NULL;
	char *source_name, *target_name, *target_class_name;
	Tcl_Obj *range_elem[2], *rule_elem[4], *rule_list;
	int retval = TCL_ERROR;

	if (qpol_range_trans_get_source_type(qpolicydb, rule, &source) < 0 ||
	    qpol_range_trans_get_target_type(qpolicydb, rule, &target) < 0 ||
	    qpol_range_trans_get_target_class(qpolicydb, rule, &target_class) < 0 ||
	    qpol_range_trans_get_range(qpolicydb, rule, &range) < 0) {
		goto cleanup;
	}

	if (qpol_type_get_name(qpolicydb, source, &source_name) < 0 ||
	    qpol_type_get_name(qpolicydb, target, &target_name) < 0 ||
	    qpol_class_get_name(qpolicydb, target_class, &target_class_name) < 0 ||
	    (apol_range = apol_mls_range_create_from_qpol_mls_range(policydb, range)) == NULL) {
		goto cleanup;
	}

	rule_elem[0] = Tcl_NewStringObj(source_name, -1);
	rule_elem[1] = Tcl_NewStringObj(target_name, -1);
	rule_elem[2] = Tcl_NewStringObj(target_class_name, -1);
	if (apol_level_to_tcl_obj(interp, apol_mls_range_get_low(apol_range), range_elem + 0) < 0 ||
	    apol_level_to_tcl_obj(interp, apol_mls_range_get_high(apol_range), range_elem + 1) < 0) {
		goto cleanup;
	}
	rule_elem[3] = Tcl_NewListObj(2, range_elem);
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
 *   <li>target class
 *   <li>new range (range = 2-uple of levels)
 * </ul>
 *
 * @param argv This function takes four parameters:
 * <ol>
 *   <li>source type
 *   <li>target type
 *   <li>list of target classes
 *   <li>new range
 *   <li>range query type
 * </ol>
 * For classes, the returned rule's class must be within this list.
 */
static int Apol_SearchRangeTransRules(ClientData clientData, Tcl_Interp * interp, int argc, const char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	CONST char **class_strings = NULL;
	int num_opts;
	qpol_range_trans_t *rule;
	apol_range_trans_query_t *query = NULL;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 6) {
		ERR(policydb, "%s", "Need a source type, target type, target class, range, and range type.");
		goto cleanup;
	}

	if ((query = apol_range_trans_query_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (apol_range_trans_query_set_source(policydb, query, argv[1], 0) < 0 ||
	    apol_range_trans_query_set_target(policydb, query, argv[2], 0) < 0) {
		goto cleanup;
	}
	if (Tcl_SplitList(interp, argv[3], &num_opts, &class_strings) == TCL_ERROR) {
		goto cleanup;
	}
	while (--num_opts >= 0) {
		CONST char *s = class_strings[num_opts];
		if (apol_range_trans_query_append_class(policydb, query, s) < 0) {
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
			ERR(policydb, "%s", strerror(ENOMEM));
			goto cleanup;
		}
		if (apol_tcl_string_to_range(interp, argv[4], range) != 0 ||
		    apol_range_trans_query_set_range(policydb, query, range, range_match) < 0) {
			apol_mls_range_destroy(&range);
			goto cleanup;
		}
	}

	if (apol_range_trans_get_by_query(policydb, query, &v) < 0) {
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
	if (class_strings != NULL) {
		Tcl_Free((char *)class_strings);
	}
	apol_range_trans_query_destroy(&query);
	apol_vector_destroy(&v);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Given a list of Tcl objects representing av rule identifiers
 * (relative to the currently loaded policy) return a list of syn_av
 * tcl objects from which these rules were derived.
 *
 * @param argv This function takes one or two parameters:
 * <ol>
 *   <li>Tcl object representing a list of av rule identifiers.
 *   <li>(optional) List of permissions that syn av rules must have at
 *   least one of.
 * </ol>
 */
static int Apol_GetSynAVRules(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	apol_vector_t *rules = NULL, *perms = NULL, *syn_rules = NULL;
	qpol_avrule_t *rule;
	qpol_syn_avrule_t *syn_rule;
	Tcl_Obj *o, *result_list;
	size_t j;
	int len, i, retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc < 2 || objc > 3) {
		ERR(policydb, "%s", "Need a list of avrule identifiers ?and permissions list?.");
		goto cleanup;
	}

	if ((rules = apol_vector_create(NULL)) == NULL) {
		ERR(policydb, "%s", strerror(errno));
		goto cleanup;
	}
	if (Tcl_ListObjLength(interp, objv[1], &len) == TCL_ERROR) {
		goto cleanup;
	}
	for (i = 0; i < len; i++) {
		if (Tcl_ListObjIndex(interp, objv[1], i, &o) == TCL_ERROR || tcl_obj_to_qpol_avrule(interp, o, &rule) == TCL_ERROR) {
			goto cleanup;
		}
		if (apol_vector_append(rules, rule) < 0) {
			ERR(policydb, "%s", strerror(errno));
			goto cleanup;
		}
	}

	if (objc >= 3) {
		if ((perms = apol_vector_create(NULL)) == NULL) {
			ERR(policydb, "%s", strerror(errno));
			goto cleanup;
		}
		if (Tcl_ListObjLength(interp, objv[2], &len) == TCL_ERROR) {
			goto cleanup;
		}
		for (i = 0; i < len; i++) {
			if (Tcl_ListObjIndex(interp, objv[2], i, &o) == TCL_ERROR) {
				goto cleanup;
			}
			if (apol_vector_append(perms, Tcl_GetString(o)) < 0) {
				ERR(policydb, "%s", strerror(errno));
				goto cleanup;
			}
		}
	}

	if (apol_vector_get_size(rules) == 1) {
		syn_rules = apol_avrule_to_syn_avrules(policydb, apol_vector_get_element(rules, 0), perms);
	} else {
		syn_rules = apol_avrule_list_to_syn_avrules(policydb, rules, perms);
	}
	if (syn_rules == NULL) {
		goto cleanup;
	}
	result_list = Tcl_NewListObj(0, NULL);
	for (j = 0; j < apol_vector_get_size(syn_rules); j++) {
		syn_rule = apol_vector_get_element(syn_rules, j);
		if (qpol_syn_avrule_to_tcl_obj(interp, syn_rule, &o) == TCL_ERROR ||
		    Tcl_ListObjAppendElement(interp, result_list, o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	Tcl_SetObjResult(interp, result_list);
	retval = TCL_OK;
      cleanup:
	apol_vector_destroy(&rules);
	apol_vector_destroy(&perms);
	apol_vector_destroy(&syn_rules);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Given a list of Tcl objects representing te rule identifiers
 * (relative to the currently loaded policy) return a list of syn_te
 * tcl objects from which this rule derived.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>Tcl object representing a te rule identifier.
 * </ol>
 */
static int Apol_GetSynTERules(ClientData clientData, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
	apol_vector_t *rules = NULL, *syn_rules = NULL;
	qpol_terule_t *rule;
	qpol_syn_terule_t *syn_rule;
	Tcl_Obj *o, *result_list;
	size_t j;
	int len, i, retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (objc != 2) {
		ERR(policydb, "%s", "Need a list of terule identifiers.");
		goto cleanup;
	}

	if ((rules = apol_vector_create(NULL)) == NULL) {
		ERR(policydb, "%s", strerror(errno));
		goto cleanup;
	}
	if (Tcl_ListObjLength(interp, objv[1], &len) == TCL_ERROR) {
		goto cleanup;
	}
	for (i = 0; i < len; i++) {
		if (Tcl_ListObjIndex(interp, objv[1], i, &o) == TCL_ERROR || tcl_obj_to_qpol_terule(interp, o, &rule) == TCL_ERROR) {
			goto cleanup;
		}
		if (apol_vector_append(rules, rule) < 0) {
			ERR(policydb, "%s", strerror(errno));
			goto cleanup;
		}
	}

	if (apol_vector_get_size(rules) == 1) {
		syn_rules = apol_terule_to_syn_terules(policydb, apol_vector_get_element(rules, 0));
	} else {
		syn_rules = apol_terule_list_to_syn_terules(policydb, rules);
	}
	if (syn_rules == NULL) {
		goto cleanup;
	}
	result_list = Tcl_NewListObj(0, NULL);
	for (j = 0; j < apol_vector_get_size(syn_rules); j++) {
		syn_rule = apol_vector_get_element(syn_rules, j);
		if (qpol_syn_terule_to_tcl_obj(interp, syn_rule, &o) == TCL_ERROR ||
		    Tcl_ListObjAppendElement(interp, result_list, o) == TCL_ERROR) {
			goto cleanup;
		}
	}
	Tcl_SetObjResult(interp, result_list);
	retval = TCL_OK;
      cleanup:
	apol_vector_destroy(&rules);
	apol_vector_destroy(&syn_rules);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

int apol_tcl_rules_init(Tcl_Interp * interp)
{
	Tcl_CreateCommand(interp, "apol_SearchTERules", Apol_SearchTERules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SearchConditionalRules", Apol_SearchConditionalRules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SearchRBACRules", Apol_SearchRBACRules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SearchRangeTransRules", Apol_SearchRangeTransRules, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_GetSynAVRules", Apol_GetSynAVRules, NULL, NULL);
	Tcl_CreateObjCommand(interp, "apol_GetSynTERules", Apol_GetSynTERules, NULL, NULL);
	return TCL_OK;
}
