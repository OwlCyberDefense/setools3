/**
 *  @file
 *  Implementation for computing semantic differences in AV and Type
 *  rules.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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

#include "poldiff_internal.h"

#include <apol/policy-query.h>
#include <apol/util.h>
#include <qpol/policy_extend.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_terule_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	size_t num_added_type;
	size_t num_removed_type;
	int diffs_sorted;
	/** vector of poldiff_terule_t */
	apol_vector_t *diffs;
};

struct poldiff_terule
{
	uint32_t spec;
	/* pointer into policy's symbol table */
	const char *source, *target;
	/** the class string is pointer into the class_bst BST */
	char *cls;
	poldiff_form_e form;
	/* pointer into policy's symbol table */
	const char *orig_default, *mod_default;
	/** pointer into policy's conditional list, needed to render
	 * conditional expressions */
	qpol_cond_t *cond;
	uint32_t branch;
	/** vector of unsigned longs of line numbers from original policy */
	apol_vector_t *orig_linenos;
	/** vector of unsigned longs of line numbers from modified policy */
	apol_vector_t *mod_linenos;
	/** array of pointers for original rules */
	qpol_terule_t **orig_rules;
	size_t num_orig_rules;
	/** array of pointers for modified rules */
	qpol_terule_t **mod_rules;
	size_t num_mod_rules;
};

typedef struct pseudo_terule
{
	uint32_t spec;
	/** pseudo-type values */
	uint32_t source, target, default_type;
	/** pointer into the class_bst BST */
	char *cls;
	/** array of pointers into the bool_bst BST */
	char *bools[5];
	uint32_t bool_val;
	uint32_t branch;
	/** pointer into policy's conditional list, needed to render
	 * conditional expressions */
	qpol_cond_t *cond;
	/** array of qpol_terule_t pointers, for showing line numbers */
	qpol_terule_t **rules;
	size_t num_rules;
} pseudo_terule_t;

void poldiff_terule_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->terule_diffs->num_added;
	stats[1] = diff->terule_diffs->num_removed;
	stats[2] = diff->terule_diffs->num_modified;
	stats[3] = diff->terule_diffs->num_added_type;
	stats[4] = diff->terule_diffs->num_removed_type;
}

char *poldiff_terule_to_string(poldiff_t * diff, const void *terule)
{
	const poldiff_terule_t *pt = (const poldiff_terule_t *)terule;
	apol_policy_t *p;
	const char *rule_type;
	char *diff_char = "", *s = NULL, *cond_expr = NULL;
	size_t len = 0;
	int error;
	if (diff == NULL || terule == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (pt->form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:{
			diff_char = "+";
			p = diff->mod_pol;
			break;
		}
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE:{
			diff_char = "-";
			p = diff->orig_pol;
			break;
		}
	case POLDIFF_FORM_MODIFIED:{
			diff_char = "*";
			p = diff->orig_pol;
			break;
		}
	default:{
			ERR(diff, "%s", strerror(ENOTSUP));
			errno = ENOTSUP;
			return NULL;
		}
	}
	rule_type = apol_rule_type_to_str(pt->spec);
	if (apol_str_appendf(&s, &len, "%s %s %s %s : %s ", diff_char, rule_type, pt->source, pt->target, pt->cls) < 0) {
		error = errno;
		s = NULL;
		goto err;
	}
	switch (pt->form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:{
			if (apol_str_append(&s, &len, pt->mod_default) < 0) {
				error = errno;
				goto err;
			}
			break;
		}
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE:{
			if (apol_str_append(&s, &len, pt->orig_default) < 0) {
				error = errno;
				goto err;
			}
			break;
		}
	case POLDIFF_FORM_MODIFIED:{
			if (apol_str_appendf(&s, &len, "{ -%s +%s }", pt->orig_default, pt->mod_default) < 0) {
				error = errno;
				goto err;
			}
			break;
		}
	default:{
			ERR(diff, "%s", strerror(ENOTSUP));
			errno = ENOTSUP;
			return NULL;
		}
	}
	if (apol_str_append(&s, &len, ";") < 0) {
		error = errno;
		goto err;
	}
	if (pt->cond != NULL) {
		if ((cond_expr = apol_cond_expr_render(p, pt->cond)) == NULL) {
			error = errno;
			goto err;
		}
		if (apol_str_appendf(&s, &len, "  [%s]:%s", cond_expr, (pt->branch ? "TRUE" : "FALSE")) < 0) {
			error = errno;
			goto err;
		}
		free(cond_expr);
	}
	return s;
      err:
	free(s);
	free(cond_expr);
	ERR(diff, "%s", strerror(error));
	errno = error;
	return NULL;
}

/**
 * Sort poldiff_terule diff results in a mostly alphabetical order.
 */
static int poldiff_terule_cmp(const void *x, const void *y, void *data __attribute__ ((unused)))
{
	const poldiff_terule_t *a = (const poldiff_terule_t *)x;
	const poldiff_terule_t *b = (const poldiff_terule_t *)y;
	int compval;
	if (a->spec != b->spec) {
		const char *rule_type1 = apol_rule_type_to_str(a->spec);
		const char *rule_type2 = apol_rule_type_to_str(b->spec);
		compval = strcmp(rule_type1, rule_type2);
		if (compval != 0) {
			return compval;
		}
	}
	if ((compval = strcmp(a->source, b->source)) != 0) {
		return compval;
	}
	if ((compval = strcmp(a->target, b->target)) != 0) {
		return compval;
	}
	if ((compval = strcmp(a->cls, b->cls)) != 0) {
		return compval;
	}
	if (a->cond != b->cond) {
		return (char *)a->cond - (char *)b->cond;
	}
	/* sort true branch before false branch */
	return b->branch - a->branch;
}

apol_vector_t *poldiff_get_terule_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (diff->terule_diffs->diffs_sorted == 0) {
		apol_vector_sort(diff->terule_diffs->diffs, poldiff_terule_cmp, NULL);
		diff->terule_diffs->diffs_sorted = 1;
	}
	return diff->terule_diffs->diffs;
}

poldiff_form_e poldiff_terule_get_form(const void *terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return ((const poldiff_terule_t *)terule)->form;
}

uint32_t poldiff_terule_get_rule_type(const poldiff_terule_t * terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return terule->spec;
}

const char *poldiff_terule_get_source_type(const poldiff_terule_t * terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return terule->source;
}

const char *poldiff_terule_get_target_type(const poldiff_terule_t * terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return terule->target;
}

const char *poldiff_terule_get_object_class(const poldiff_terule_t * terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return terule->cls;
}

void poldiff_terule_get_cond(const poldiff_t * diff, const poldiff_terule_t * terule,
			     qpol_cond_t ** cond, uint32_t * which_list, apol_policy_t ** p)
{
	if (diff == NULL || terule == NULL || cond == NULL || p == NULL) {
		errno = EINVAL;
		return;
	}
	*cond = terule->cond;
	if (*cond == NULL) {
		*which_list = 1;
		*p = NULL;
	} else if (terule->form == POLDIFF_FORM_ADDED || terule->form == POLDIFF_FORM_ADD_TYPE) {
		*which_list = terule->branch;
		*p = diff->mod_pol;
	} else {
		*which_list = terule->branch;
		*p = diff->orig_pol;
	}
}

const char *poldiff_terule_get_original_target(const poldiff_terule_t * terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return terule->orig_default;
}

const char *poldiff_terule_get_modified_target(const poldiff_terule_t * terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return terule->orig_default;
}

apol_vector_t *poldiff_terule_get_orig_line_numbers(const poldiff_terule_t * terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return terule->orig_linenos;
}

apol_vector_t *poldiff_terule_get_mod_line_numbers(const poldiff_terule_t * terule)
{
	if (terule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return terule->mod_linenos;
}

/*************** protected functions ***************/

poldiff_terule_summary_t *terule_create(void)
{
	poldiff_terule_summary_t *rs = calloc(1, sizeof(*rs));
	if (rs == NULL) {
		return NULL;
	}
	if ((rs->diffs = apol_vector_create()) == NULL) {
		terule_destroy(&rs);
		return NULL;
	}
	return rs;
}

/**
 * Free all space used by a poldiff_terule_t, including the pointer
 * itself.  Does nothing if the pointer is already NULL.
 *
 * @param elem Pointer to a poldiff_terule_t.
 */
static void poldiff_terule_free(void *elem)
{
	if (elem != NULL) {
		poldiff_terule_t *t = elem;
		apol_vector_destroy(&t->orig_linenos, NULL);
		apol_vector_destroy(&t->mod_linenos, NULL);
		free(t->orig_rules);
		free(t->mod_rules);
		free(elem);
	}
}

void terule_destroy(poldiff_terule_summary_t ** rs)
{
	if (rs != NULL && *rs != NULL) {
		apol_vector_destroy(&(*rs)->diffs, poldiff_terule_free);
		free(*rs);
		*rs = NULL;
	}
}

int terule_reset(poldiff_t * diff)
{
	int error = 0;
	terule_destroy(&diff->terule_diffs);
	diff->terule_diffs = terule_create();
	if (diff->terule_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}
	return 0;
}

/**
 * Apply an ordering scheme to two pseudo-te rules.
 *
 * <ul>
 * <li>Sort by target pseudo-type value,
 * <li>Then by source pseudo-type value,
 * <li>Then by object class's BST's pointer value,
 * <li>Then by rule specified (allow, neverallow, etc.),
 * <li>Then choose unconditional rules over conditional rules,
 * <li>Then by conditional expression's BST's boolean pointer value.
 * </ul>
 *
 * If this function is being used for sorting (via terule_get_items())
 * then sort by truth value, and then by branch (true branch, then
 * false branch).  Otherwise, when comparing rules (via terule_comp())
 * then by truth value, inverting rule2's value if in the other
 * branch.
 */
static int pseudo_terule_comp(const pseudo_terule_t * rule1, const pseudo_terule_t * rule2, int is_sorting)
{
	size_t i;
	uint32_t bool_val;
	if (rule1->target != rule2->target) {
		return rule1->target - rule2->target;
	}
	if (rule1->source != rule2->source) {
		return rule1->source - rule2->source;
	}
	if (rule1->cls != rule2->cls) {
		return (int)(rule1->cls - rule2->cls);
	}
	if (rule1->spec != rule2->spec) {
		return rule1->spec - rule2->spec;
	}
	if (rule1->bools[0] == NULL && rule2->bools[0] == NULL) {
		/* both rules are unconditional */
		return 0;
	} else if (rule1->bools[0] == NULL && rule2->bools[0] != NULL) {
		/* unconditional rules come before conditional */
		return -1;
	} else if (rule1->bools[0] != NULL && rule2->bools[0] == NULL) {
		/* unconditional rules come before conditional */
		return 1;
	}
	for (i = 0; i < (sizeof(rule1->bools) / sizeof(rule1->bools[0])); i++) {
		if (rule1->bools[i] != rule2->bools[i]) {
			return (int)(rule1->bools[i] - rule2->bools[i]);
		}
	}
	if (is_sorting) {
		if (rule1->branch != rule2->branch) {
			return rule1->branch - rule2->branch;
		}
		return (int)rule1->bool_val - (int)rule2->bool_val;
	} else {
		if (rule1->branch == rule2->branch) {
			bool_val = rule2->bool_val;
		} else {
			bool_val = ~rule2->bool_val;
		}
		return rule1->bool_val - bool_val;
	}
}

static int terule_bst_comp(const void *x, const void *y, void *data)
{
	const pseudo_terule_t *r1 = (const pseudo_terule_t *)x;
	const pseudo_terule_t *r2 = (const pseudo_terule_t *)y;
	poldiff_t *diff = data;
	int retv;
	retv = pseudo_terule_comp(r1, r2, 1);
	if (!retv && r1->default_type != r2->default_type)
		WARN(diff, "Multiple %s rules for %s %s %s with different default types", apol_rule_type_to_str(r1->spec),
		     type_map_get_name(diff, r1->source, POLDIFF_POLICY_ORIG), type_map_get_name(diff, r1->target,
												 POLDIFF_POLICY_ORIG), r1->cls);
	return retv;
}

/**
 * Given a conditional expression, convert its booleans to a sorted
 * array of pseudo-boolean values, assign that array to the
 * pseudo-terule key, and then derive the truth table.
 *
 * @param diff Policy difference structure.
 * @param p Policy containing conditional.
 * @param cond Conditional expression to convert.
 * @param key Location to write converted expression.
 */
static int terule_build_cond(poldiff_t * diff, apol_policy_t * p, qpol_cond_t * cond, pseudo_terule_t * key)
{
	qpol_iterator_t *iter = NULL;
	qpol_cond_expr_node_t *node;
	uint32_t expr_type, truthiness;
	qpol_bool_t *bools[5], *bool;
	size_t i, j;
	size_t num_bools = 0;
	char *bool_name, *pseudo_bool, *t;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int retval = -1, error = 0, compval;
	if (qpol_cond_get_expr_node_iter(q, cond, &iter) < 0) {
		error = errno;
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&node) < 0 || qpol_cond_expr_node_get_expr_type(q, node, &expr_type) < 0) {
			error = errno;
			goto cleanup;
		}
		if (expr_type != QPOL_COND_EXPR_BOOL) {
			continue;
		}
		if (qpol_cond_expr_node_get_bool(q, node, &bool) < 0) {
			error = errno;
			goto cleanup;
		}
		for (i = 0; i < num_bools; i++) {
			if (bools[i] == bool) {
				break;
			}
		}
		if (i >= num_bools) {
			assert(num_bools < 4);
			bools[i] = bool;
			num_bools++;
		}
	}
	for (i = 0; i < num_bools; i++) {
		if (qpol_bool_get_name(q, bools[i], &bool_name) < 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_bst_get_element(diff->bool_bst, bool_name, NULL, (void **)&pseudo_bool) < 0) {
			error = EBADRQC;	/* should never get here */
			ERR(diff, "%s", strerror(error));
			assert(0);
			goto cleanup;
		}
		key->bools[i] = pseudo_bool;
	}

	/* bubble sorth the pseudo bools (not bad because there are at
	 * most five elements */
	for (i = num_bools; i > 1; i--) {
		for (j = 1; j < i; j++) {
			compval = strcmp(key->bools[j - 1], key->bools[j]);
			if (compval > 0) {
				t = key->bools[j];
				key->bools[j] = key->bools[j - 1];
				key->bools[j - 1] = t;
				bool = bools[j];
				bools[j] = bools[j - 1];
				bools[j - 1] = bools[j];
			}
		}
	}

	/* now compute the truth table for the booleans */
	key->bool_val = 0;
	for (i = 0; i < 32; i++) {
		for (j = 0; j < num_bools; j++) {
			if (qpol_bool_set_state_no_eval(q, bools[j], ((i & (1 << j)) ? 1 : 0)) < 0) {
				error = errno;
				goto cleanup;
			}
		}
		if (qpol_cond_eval(q, cond, &truthiness) < 0) {
			error = errno;
			goto cleanup;
		}
		key->bool_val = (key->bool_val << 1) | truthiness;
	}

	key->cond = cond;
	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}

/**
 * Given a rule, construct a new pseudo-terule and insert it into the
 * BST if not already there.
 *
 * @param diff Policy difference structure.
 * @param p Policy from which the rule came.
 * @param rule TE rule to insert.
 * @param source Source pseudo-type value.
 * @param target Target pseudo-type value.
 * @param b BST containing pseudo-terules.
 *
 * @return 0 on success, < 0 on error.
 */
static int terule_add_to_bst(poldiff_t * diff, apol_policy_t * p,
			     qpol_terule_t * rule, uint32_t source, uint32_t target, apol_bst_t * b)
{
	pseudo_terule_t *key, *inserted_key;
	qpol_class_t *obj_class;
	qpol_type_t *default_type;
	char *class_name;
	qpol_cond_t *cond;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int retval = -1, error = 0, compval;
	int which = (p == diff->orig_pol ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
	if ((key = calloc(1, sizeof(*key))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (qpol_terule_get_rule_type(q, rule, &(key->spec)) < 0 ||
	    qpol_terule_get_object_class(q, rule, &obj_class) < 0 ||
	    qpol_terule_get_default_type(q, rule, &default_type) < 0 || qpol_terule_get_cond(q, rule, &cond) < 0) {
		error = errno;
		goto cleanup;
	}
	if (qpol_class_get_name(q, obj_class, &class_name) < 0) {
		error = errno;
		goto cleanup;
	}
	if (apol_bst_get_element(diff->class_bst, class_name, NULL, (void **)&key->cls) < 0) {
		error = EBADRQC;       /* should never get here */
		ERR(diff, "%s", strerror(error));
		assert(0);
		goto cleanup;
	}
	if ((key->default_type = type_map_lookup(diff, default_type, which)) == 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	key->source = source;
	key->target = target;
	if (cond != NULL && (qpol_terule_get_which_list(q, rule, &(key->branch)) < 0 || terule_build_cond(diff, p, cond, key) < 0)) {
		error = errno;
		goto cleanup;
	}

	/* insert this pseudo into the tree if not already there */
	if ((compval = apol_bst_insert_and_get(b, (void **)&key, diff, terule_free_item)) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	inserted_key = key;
	key = NULL;

	/* store the rule pointer, to be used for showing line numbers */
	if (qpol_policy_has_capability(q, QPOL_CAP_LINE_NUMBERS)) {
		qpol_terule_t **t = realloc(inserted_key->rules,
					    (inserted_key->num_rules + 1) * sizeof(*t));
		if (t == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		inserted_key->rules = t;
		inserted_key->rules[inserted_key->num_rules++] = rule;
	}

	retval = 0;
      cleanup:
	if (retval < 0) {
		terule_free_item(key);
	}
	errno = error;
	return retval;
}

/**
 * Given a rule, expand its source and target types into individual
 * pseudo-type values.  Then add the expanded rule to the BST.  This
 * is needed for when the source and/or target is an attribute.
 *
 * @param diff Policy difference structure.
 * @param p Policy from which the rule came.
 * @param rule TE rule to insert.
 * @param b BST containing pseudo-terules.
 *
 * @return 0 on success, < 0 on error.
 */
static int terule_expand(poldiff_t * diff, apol_policy_t * p, qpol_terule_t * rule, apol_bst_t * b)
{
	qpol_type_t *source, *orig_target, *target;
	unsigned char source_attr, target_attr;
	qpol_iterator_t *source_iter = NULL, *target_iter = NULL;
	uint32_t source_val, target_val;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int which = (p == diff->orig_pol ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
	int retval = -1, error = 0;
	if (qpol_terule_get_source_type(q, rule, &source) < 0 ||
	    qpol_terule_get_target_type(q, rule, &orig_target) < 0 ||
	    qpol_type_get_isattr(q, source, &source_attr) < 0 || qpol_type_get_isattr(q, orig_target, &target_attr)) {
		error = errno;
		goto cleanup;
	}
	if (source_attr && qpol_type_get_type_iter(q, source, &source_iter) < 0) {
		error = errno;
		goto cleanup;
	}
	do {
		if (source_attr) {
			if (qpol_iterator_get_item(source_iter, (void **)&source) < 0) {
				error = errno;
				goto cleanup;
			}
			qpol_iterator_next(source_iter);
		}
		if (target_attr) {
			if (qpol_type_get_type_iter(q, orig_target, &target_iter) < 0) {
				error = errno;
				goto cleanup;
			}
		} else {
			target = orig_target;
		}
		do {
			if (target_attr) {
				if (qpol_iterator_get_item(target_iter, (void **)&target) < 0) {
					error = errno;
					goto cleanup;
				}
				qpol_iterator_next(target_iter);
			}
			char *n1, *n2;
			qpol_type_get_name(q, source, &n1);
			qpol_type_get_name(q, target, &n2);
			if ((source_val = type_map_lookup(diff, source, which)) == 0 ||
			    (target_val = type_map_lookup(diff, target, which)) == 0 ||
			    terule_add_to_bst(diff, p, rule, source_val, target_val, b) < 0) {
				error = errno;
				goto cleanup;
			}
		}
		while (target_attr && !qpol_iterator_end(target_iter));
		qpol_iterator_destroy(&target_iter);
	}
	while (source_attr && !qpol_iterator_end(source_iter));
	retval = 0;
      cleanup:
	qpol_iterator_destroy(&source_iter);
	qpol_iterator_destroy(&target_iter);
	errno = error;
	return retval;
}

apol_vector_t *terule_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	apol_vector_t *bools = NULL, *bool_states = NULL;
	size_t i, num_rules, j;
	apol_bst_t *b = NULL;
	apol_vector_t *v = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_terule_t *rule;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int retval = -1, error = 0;
	if (poldiff_build_bsts(diff) < 0) {
		error = errno;
		goto cleanup;
	}

	/* store original boolean values */
	if (apol_bool_get_by_query(policy, NULL, &bools) < 0) {
		error = errno;
		goto cleanup;
	}
	if ((bool_states = apol_vector_create_with_capacity(apol_vector_get_size(bools))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(bools); i++) {
		qpol_bool_t *bool = apol_vector_get_element(bools, i);
		int state;
		if (qpol_bool_get_state(q, bool, &state) < 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_append(bool_states, (void *)state) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if ((b = apol_bst_create(terule_bst_comp)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (qpol_policy_get_terule_iter(q, QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER, &iter) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	qpol_iterator_get_size(iter, &num_rules);
	for (j = 0; !qpol_iterator_end(iter); qpol_iterator_next(iter), j++) {
		if (qpol_iterator_get_item(iter, (void **)&rule) < 0 || terule_expand(diff, policy, rule, b) < 0) {
			error = errno;
			goto cleanup;
		}
		if (!(j % 1024)) {
			int percent = 50 * j / num_rules + (policy == diff->mod_pol ? 50 : 0);
			INFO(diff, "Computing TE rule difference: %02d%% complete", percent);
		}
	}
	if ((v = apol_bst_get_vector(b)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	retval = 0;
      cleanup:
	/* restore boolean states */
	for (i = 0; bools != NULL && i < apol_vector_get_size(bools); i++) {
		qpol_bool_t *bool = apol_vector_get_element(bools, i);
		int state = (int)apol_vector_get_element(bool_states, i);
		qpol_bool_set_state_no_eval(q, bool, state);
	}
	apol_vector_destroy(&bools, NULL);
	apol_vector_destroy(&bool_states, NULL);
	qpol_policy_reevaluate_conds(q);
	apol_bst_destroy(&b, NULL);
	qpol_iterator_destroy(&iter);
	if (retval < 0) {
		apol_vector_destroy(&v, terule_free_item);
		errno = error;
		return NULL;
	}
	return v;
}

void terule_free_item(void *item)
{
	pseudo_terule_t *t = (pseudo_terule_t *) item;
	if (item != NULL) {
		free(t->rules);
		free(t);
	}
}

int terule_comp(const void *x, const void *y, poldiff_t * diff __attribute__ ((unused)))
{
	const pseudo_terule_t *r1 = (const pseudo_terule_t *)x;
	const pseudo_terule_t *r2 = (const pseudo_terule_t *)y;
	return pseudo_terule_comp(r1, r2, 0);
}

/**
 * Allocate and return a new terule difference object.  If the
 * pseudo-terule's source and/or target expands to multiple read
 * types, then just choose the first one for display.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param rule Pseudo terule that changed.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling poldiff_terule_free() upon
 * the returned value.
 */
static poldiff_terule_t *make_tediff(poldiff_t * diff, poldiff_form_e form, pseudo_terule_t * rule)
{
	poldiff_terule_t *pt;
	const char *n1, *n2;
	int error;
	if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
		n1 = type_map_get_name(diff, rule->source, POLDIFF_POLICY_MOD);
		n2 = type_map_get_name(diff, rule->target, POLDIFF_POLICY_MOD);
	} else {
		n1 = type_map_get_name(diff, rule->source, POLDIFF_POLICY_ORIG);
		n2 = type_map_get_name(diff, rule->target, POLDIFF_POLICY_ORIG);
	}
	assert(n1 != NULL && n2 != NULL);
	if ((pt = calloc(1, sizeof(*pt))) == NULL) {
		error = errno;
		poldiff_terule_free(pt);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pt->spec = rule->spec;
	pt->source = n1;
	pt->target = n2;
	pt->cls = rule->cls;
	pt->form = form;
	pt->cond = rule->cond;
	pt->branch = rule->branch;
	return pt;
}

int terule_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	pseudo_terule_t *rule = (pseudo_terule_t *) item;
	poldiff_terule_t *pt = NULL;
	apol_vector_t *v1, *v2;
	apol_policy_t *p;
	const char *orig_default = NULL, *mod_default = NULL;
	int retval = -1, error = errno;

	/* check if form should really become ADD_TYPE / REMOVE_TYPE,
	 * by seeing if the /other/ policy's reverse lookup is
	 * empty */
	if (form == POLDIFF_FORM_ADDED) {
		if ((v1 = type_map_lookup_reverse(diff, rule->source, POLDIFF_POLICY_ORIG)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, rule->target, POLDIFF_POLICY_ORIG)) == NULL ||
		    (orig_default = type_map_get_name(diff, rule->default_type, POLDIFF_POLICY_MOD)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_ADD_TYPE;
		}
		p = diff->mod_pol;
	} else {
		if ((v1 = type_map_lookup_reverse(diff, rule->source, POLDIFF_POLICY_MOD)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, rule->target, POLDIFF_POLICY_MOD)) == NULL ||
		    (mod_default = type_map_get_name(diff, rule->default_type, POLDIFF_POLICY_ORIG)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_REMOVE_TYPE;
		}
		p = diff->orig_pol;
	}

	pt = make_tediff(diff, form, rule);
	if (pt == NULL) {
		return -1;
	}
	pt->orig_default = orig_default;
	pt->mod_default = mod_default;

	/* calculate line numbers */
	if (qpol_policy_has_capability(apol_policy_get_qpol(p), QPOL_CAP_LINE_NUMBERS)) {
		if ((v1 = apol_vector_create()) == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
			pt->mod_linenos = v1;
		} else {
			pt->orig_linenos = v1;
		}

		/* copy rule pointers for delayed line number claculation */
		if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
			pt->num_mod_rules = rule->num_rules;
			pt->mod_rules = calloc(rule->num_rules, sizeof(qpol_terule_t *));
			if (!pt->mod_rules) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			memcpy(pt->mod_rules, rule->rules, rule->num_rules * sizeof(qpol_terule_t *));
		} else {
			pt->num_orig_rules = rule->num_rules;
			pt->orig_rules = calloc(rule->num_rules, sizeof(qpol_terule_t *));
			if (!pt->orig_rules) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			memcpy(pt->orig_rules, rule->rules, rule->num_rules * sizeof(qpol_terule_t *));
		}
	}

	if (apol_vector_append(diff->terule_diffs->diffs, pt) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	switch (form) {
	case POLDIFF_FORM_ADDED:
		diff->terule_diffs->num_added++;
		break;
	case POLDIFF_FORM_ADD_TYPE:
		diff->terule_diffs->num_added_type++;
		break;
	case POLDIFF_FORM_REMOVED:
		diff->terule_diffs->num_removed++;
		break;
	case POLDIFF_FORM_REMOVE_TYPE:
		diff->terule_diffs->num_removed_type++;
		break;
	default:
		error = EBADRQC;       /* should never get here */
		ERR(diff, "%s", strerror(error));
		assert(0);
		goto cleanup;
	}
	diff->terule_diffs->diffs_sorted = 0;
	retval = 0;
      cleanup:
	if (retval < 0) {
		poldiff_terule_free(pt);
	}
	errno = error;
	return retval;
}

int terule_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	pseudo_terule_t *r1 = (pseudo_terule_t *) x;
	pseudo_terule_t *r2 = (pseudo_terule_t *) y;
	poldiff_terule_t *pt = NULL;
	int retval = -1, error = 0;

	if (r1->default_type != r2->default_type) {
		if ((pt = make_tediff(diff, POLDIFF_FORM_MODIFIED, r1)) == NULL) {
			error = errno;
			goto cleanup;
		}
		pt->orig_default = type_map_get_name(diff, r1->default_type, POLDIFF_POLICY_ORIG);
		pt->mod_default = type_map_get_name(diff, r2->default_type, POLDIFF_POLICY_MOD);

		/* calculate line numbers */
		if (qpol_policy_has_capability(apol_policy_get_qpol(diff->orig_pol), QPOL_CAP_LINE_NUMBERS)) {
			if ((pt->orig_linenos = apol_vector_create()) == NULL) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}

			/* copy rule pointers for delayed line number claculation */
			pt->num_orig_rules = r1->num_rules;
			pt->orig_rules = calloc(r1->num_rules, sizeof(qpol_terule_t *));
			if (!pt->orig_rules) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			memcpy(pt->orig_rules, r1->rules, r1->num_rules * sizeof(qpol_terule_t *));
		}
		if (qpol_policy_has_capability(apol_policy_get_qpol(diff->mod_pol), QPOL_CAP_LINE_NUMBERS)) {
			if ((pt->mod_linenos = apol_vector_create()) == NULL) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}

			/* copy rule pointers for delayed line number claculation */
			pt->num_mod_rules = r2->num_rules;
			pt->mod_rules = calloc(r2->num_rules, sizeof(qpol_terule_t *));
			if (!pt->mod_rules) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			memcpy(pt->mod_rules, r2->rules, r2->num_rules * sizeof(qpol_terule_t *));
		}

		if (apol_vector_append(diff->terule_diffs->diffs, pt) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->terule_diffs->num_modified++;
		diff->terule_diffs->diffs_sorted = 0;
	}
	retval = 0;
      cleanup:
	if (retval != 0) {
		poldiff_terule_free(pt);
	}
	errno = error;
	return retval;
}

int terule_enable_line_numbers(poldiff_t * diff)
{
	apol_vector_t *te = NULL;
	poldiff_terule_t *terule = NULL;
	size_t i, j;
	qpol_iterator_t *iter = NULL;
	qpol_syn_terule_t *ste = NULL;
	int error = 0;
	unsigned long lineno = 0;

	te = poldiff_get_terule_vector(diff);

	for (i = 0; i < apol_vector_get_size(te); i++) {
		terule = apol_vector_get_element(te, i);
		if (apol_vector_get_size(terule->mod_linenos) || apol_vector_get_size(terule->orig_linenos))
			continue;
		for (j = 0; j < terule->num_orig_rules; j++) {
			if (qpol_terule_get_syn_terule_iter(diff->orig_qpol, terule->orig_rules[j], &iter)) {
				error = errno;
				goto err;
			}
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&ste) < 0) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
				if (qpol_syn_terule_get_lineno(diff->orig_qpol, ste, &lineno) < 0) {
					error = errno;
					goto err;
				}
				if (apol_vector_append(terule->orig_linenos, (void *)lineno) < 0) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_sort_uniquify(terule->orig_linenos, NULL, NULL, NULL);
		for (j = 0; j < terule->num_mod_rules; j++) {
			if (qpol_terule_get_syn_terule_iter(diff->mod_qpol, terule->mod_rules[j], &iter)) {
				error = errno;
				goto err;
			}
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&ste) < 0) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
				if (qpol_syn_terule_get_lineno(diff->mod_qpol, ste, &lineno) < 0) {
					error = errno;
					goto err;
				}
				if (apol_vector_append(terule->mod_linenos, (void *)lineno) < 0) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_sort_uniquify(terule->mod_linenos, NULL, NULL, NULL);
	}

	return 0;
      err:
	qpol_iterator_destroy(&iter);
	return -1;
}
