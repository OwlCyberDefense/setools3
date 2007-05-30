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

struct poldiff_avrule_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	size_t num_added_type;
	size_t num_removed_type;
	int diffs_sorted;
	/** vector of poldiff_avrule_t */
	apol_vector_t *diffs;
};

struct poldiff_avrule
{
	uint32_t spec;
	/* pointer into policy's symbol table */
	const char *source, *target;
	/** the class string is pointer into the class_bst BST */
	char *cls;
	poldiff_form_e form;
	/** vector of pointers into the perm_bst BST (char *) */
	apol_vector_t *unmodified_perms;
	/** vector of pointers into the perm_bst BST (char *) */
	apol_vector_t *added_perms;
	/** vector of pointers into the perm_bst BST (char *) */
	apol_vector_t *removed_perms;
	/** pointer into policy's conditional list, needed to render
	 * conditional expressions */
	qpol_cond_t *cond;
	uint32_t branch;
	/** vector of unsigned longs of line numbers from original policy */
	apol_vector_t *orig_linenos;
	/** vector of unsigned longs of line numbers from modified policy */
	apol_vector_t *mod_linenos;
	/** array of pointers for original rules */
	qpol_avrule_t **orig_rules;
	size_t num_orig_rules;
	/** array of pointers for modified rules */
	qpol_avrule_t **mod_rules;
	size_t num_mod_rules;
};

typedef struct pseudo_avrule
{
	uint32_t spec;
	/** pseudo-type values */
	uint32_t source, target;
	/** pointer into the class_bst BST */
	char *cls;
	/** array of pointers into the perm_bst BST */
	/* (use an array here to save space) */
	char **perms;
	size_t num_perms;
	/** array of pointers into the bool_bst BST */
	char *bools[5];
	uint32_t bool_val;
	uint32_t branch;
	/** pointer into policy's conditional list, needed to render
	 * conditional expressions */
	qpol_cond_t *cond;
	/** array of qpol_avrule_t pointers, for showing line numbers */
	qpol_avrule_t **rules;
	size_t num_rules;
} pseudo_avrule_t;

/******************** public avrule functions ********************/

void poldiff_avrule_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->avrule_diffs->num_added;
	stats[1] = diff->avrule_diffs->num_removed;
	stats[2] = diff->avrule_diffs->num_modified;
	stats[3] = diff->avrule_diffs->num_added_type;
	stats[4] = diff->avrule_diffs->num_removed_type;
}

char *poldiff_avrule_to_string(poldiff_t * diff, const void *avrule)
{
	const poldiff_avrule_t *pa = (const poldiff_avrule_t *)avrule;
	apol_policy_t *p;
	const char *rule_type;
	char *diff_char = "", *s = NULL, *perm_name, *cond_expr = NULL;
	size_t i, len = 0;
	int show_perm_sym = 0, error;
	if (diff == NULL || avrule == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (pa->form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:
	{
		diff_char = "+";
		p = diff->mod_pol;
		break;
	}
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE:
	{
		diff_char = "-";
		p = diff->orig_pol;
		break;
	}
	case POLDIFF_FORM_MODIFIED:
	{
		diff_char = "*";
		p = diff->orig_pol;
		show_perm_sym = 1;
		break;
	}
	default:
	{
		ERR(diff, "%s", strerror(ENOTSUP));
		errno = ENOTSUP;
		return NULL;
	}
	}
	rule_type = apol_rule_type_to_str(pa->spec);
	if (apol_str_appendf(&s, &len, "%s %s %s %s : %s {", diff_char, rule_type, pa->source, pa->target, pa->cls) < 0) {
		error = errno;
		goto err;
	}
	for (i = 0; pa->unmodified_perms != NULL && i < apol_vector_get_size(pa->unmodified_perms); i++) {
		perm_name = (char *)apol_vector_get_element(pa->unmodified_perms, i);
		if (apol_str_appendf(&s, &len, " %s", perm_name) < 0) {
			error = errno;
			goto err;
		}
	}
	for (i = 0; pa->added_perms != NULL && i < apol_vector_get_size(pa->added_perms); i++) {
		perm_name = (char *)apol_vector_get_element(pa->added_perms, i);
		if (apol_str_appendf(&s, &len, " %s%s", (show_perm_sym ? "+" : ""), perm_name) < 0) {
			error = errno;
			goto err;
		}
	}
	for (i = 0; pa->removed_perms != NULL && i < apol_vector_get_size(pa->removed_perms); i++) {
		perm_name = (char *)apol_vector_get_element(pa->removed_perms, i);
		if (apol_str_appendf(&s, &len, " %s%s", (show_perm_sym ? "-" : ""), perm_name) < 0) {
			error = errno;
			goto err;
		}
	}
	if (apol_str_append(&s, &len, " };") < 0) {
		error = errno;
		goto err;
	}
	if (pa->cond != NULL) {
		if ((cond_expr = apol_cond_expr_render(p, pa->cond)) == NULL) {
			error = errno;
			goto err;
		}
		if (apol_str_appendf(&s, &len, "  [%s]:%s", cond_expr, (pa->branch ? "TRUE" : "FALSE")) < 0) {
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
 * Sort poldiff_avrule diff results in a mostly alphabetical order.
 */
static int poldiff_avrule_cmp(const void *x, const void *y, void *data __attribute__ ((unused)))
{
	const poldiff_avrule_t *a = (const poldiff_avrule_t *)x;
	const poldiff_avrule_t *b = (const poldiff_avrule_t *)y;
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

apol_vector_t *poldiff_get_avrule_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (diff->avrule_diffs->diffs_sorted == 0) {
		apol_vector_sort(diff->avrule_diffs->diffs, poldiff_avrule_cmp, NULL);
		diff->avrule_diffs->diffs_sorted = 1;
	}
	return diff->avrule_diffs->diffs;
}

poldiff_form_e poldiff_avrule_get_form(const void *avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return ((const poldiff_avrule_t *)avrule)->form;
}

uint32_t poldiff_avrule_get_rule_type(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->spec;
}

const char *poldiff_avrule_get_source_type(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->source;
}

const char *poldiff_avrule_get_target_type(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->target;
}

const char *poldiff_avrule_get_object_class(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->cls;
}

void poldiff_avrule_get_cond(const poldiff_t * diff, const poldiff_avrule_t * avrule,
			     qpol_cond_t ** cond, uint32_t * which_list, apol_policy_t ** p)
{
	if (diff == NULL || avrule == NULL || cond == NULL || p == NULL) {
		errno = EINVAL;
		return;
	}
	*cond = avrule->cond;
	if (*cond == NULL) {
		*which_list = 1;
		*p = NULL;
	} else if (avrule->form == POLDIFF_FORM_ADDED || avrule->form == POLDIFF_FORM_ADD_TYPE) {
		*which_list = avrule->branch;
		*p = diff->mod_pol;
	} else {
		*which_list = avrule->branch;
		*p = diff->orig_pol;
	}
}

apol_vector_t *poldiff_avrule_get_unmodified_perms(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avrule->unmodified_perms;
}

apol_vector_t *poldiff_avrule_get_added_perms(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avrule->added_perms;
}

apol_vector_t *poldiff_avrule_get_removed_perms(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avrule->removed_perms;
}

const apol_vector_t *poldiff_avrule_get_orig_line_numbers(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avrule->orig_linenos;
}

const apol_vector_t *poldiff_avrule_get_mod_line_numbers(const poldiff_avrule_t * avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avrule->mod_linenos;
}

/**
 * Get the line numbers from an array of qpol_avrule_t that contain
 * the given permission.
 */
static apol_vector_t *avrule_get_line_numbers_for_perm(poldiff_t * diff, const char *perm, qpol_policy_t * q,
						       qpol_avrule_t ** rules, const size_t num_rules)
{
	apol_vector_t *v = NULL;
	qpol_iterator_t *syn_iter = NULL, *perm_iter = NULL;
	size_t i;
	int error = 0;

	if ((v = apol_vector_create(NULL)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	for (i = 0; i < num_rules; i++) {
		if (qpol_avrule_get_syn_avrule_iter(q, rules[i], &syn_iter) < 0) {
			error = errno;
			goto cleanup;
		}
		for (; !qpol_iterator_end(syn_iter); qpol_iterator_next(syn_iter)) {
			qpol_syn_avrule_t *syn_rule;
			qpol_iterator_get_item(syn_iter, (void **)&syn_rule);
			if (qpol_syn_avrule_get_perm_iter(q, syn_rule, &perm_iter) < 0) {
				error = errno;
				goto cleanup;
			}
			for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
				char *syn_perm;
				qpol_iterator_get_item(perm_iter, (void **)&syn_perm);
				if (strcmp(perm, syn_perm) == 0) {
					unsigned long lineno;
					qpol_syn_avrule_get_lineno(q, syn_rule, &lineno);
					if (apol_vector_append(v, (void *)lineno) < 0) {
						ERR(diff, "%s", strerror(errno));
					}
					break;
				}
			}
			qpol_iterator_destroy(&perm_iter);
		}
		qpol_iterator_destroy(&syn_iter);
	}
	apol_vector_sort_uniquify(v, NULL, NULL);
      cleanup:
	qpol_iterator_destroy(&syn_iter);
	qpol_iterator_destroy(&perm_iter);
	if (error != 0) {
		apol_vector_destroy(&v);
		errno = error;
		return NULL;
	}
	return v;
}

apol_vector_t *poldiff_avrule_get_orig_line_numbers_for_perm(poldiff_t * diff, const poldiff_avrule_t * avrule, const char *perm)
{
	if (diff == NULL || avrule == NULL || perm == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (!diff->line_numbers_enabled || avrule->form == POLDIFF_FORM_ADDED || avrule->form == POLDIFF_FORM_ADD_TYPE) {
		return NULL;
	}
	if (avrule->num_orig_rules == 0) {
		return NULL;
	}
	return avrule_get_line_numbers_for_perm(diff, perm, diff->orig_qpol, avrule->orig_rules, avrule->num_orig_rules);
}

apol_vector_t *poldiff_avrule_get_mod_line_numbers_for_perm(poldiff_t * diff, const poldiff_avrule_t * avrule, const char *perm)
{
	if (diff == NULL || avrule == NULL || perm == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (!diff->line_numbers_enabled || avrule->form == POLDIFF_FORM_REMOVED || avrule->form == POLDIFF_FORM_REMOVE_TYPE) {
		return NULL;
	}
	if (avrule->num_mod_rules == 0) {
		return NULL;
	}
	return avrule_get_line_numbers_for_perm(diff, perm, diff->mod_qpol, avrule->mod_rules, avrule->num_mod_rules);
}

/******************** protected functions below ********************/

/**
 * Free all space used by a poldiff_avrule_t, including the pointer
 * itself.  Does nothing if the pointer is already NULL.
 *
 * @param elem Pointer to a poldiff_avrule_t.
 */
static void poldiff_avrule_free(void *elem)
{
	if (elem != NULL) {
		poldiff_avrule_t *a = (poldiff_avrule_t *) elem;
		apol_vector_destroy(&a->unmodified_perms);
		apol_vector_destroy(&a->added_perms);
		apol_vector_destroy(&a->removed_perms);
		apol_vector_destroy(&a->orig_linenos);
		apol_vector_destroy(&a->mod_linenos);
		free(a->orig_rules);
		free(a->mod_rules);
		free(a);
	}
}

poldiff_avrule_summary_t *avrule_create(void)
{
	poldiff_avrule_summary_t *rs = calloc(1, sizeof(*rs));
	if (rs == NULL) {
		return NULL;
	}
	if ((rs->diffs = apol_vector_create(poldiff_avrule_free)) == NULL) {
		avrule_destroy(&rs);
		return NULL;
	}
	return rs;
}

void avrule_destroy(poldiff_avrule_summary_t ** rs)
{
	if (rs != NULL && *rs != NULL) {
		apol_vector_destroy(&(*rs)->diffs);
		free(*rs);
		*rs = NULL;
	}
}

int avrule_reset(poldiff_t * diff)
{
	int error = 0;

	avrule_destroy(&diff->avrule_diffs);
	diff->avrule_diffs = avrule_create();
	if (diff->avrule_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

static void avrule_free_item(void *item)
{
	pseudo_avrule_t *a = (pseudo_avrule_t *) item;
	if (item != NULL) {
		free(a->perms);
		free(a->rules);
		free(a);
	}
}

/**
 * Apply an ordering scheme to two pseudo-av rules.
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
 * If this function is being used for sorting (via avrule_get_items())
 * then sort by truth value, and then by branch (true branch, then
 * false branch).  Otherwise, when comparing rules (via avrule_comp())
 * then by truth value, inverting rule2's value if in the other
 * branch.
 */
static int pseudo_avrule_comp(const pseudo_avrule_t * rule1, const pseudo_avrule_t * rule2, int is_sorting)
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

static int avrule_bst_comp(const void *x, const void *y, void *data __attribute__ ((unused)))
{
	const pseudo_avrule_t *r1 = (const pseudo_avrule_t *)x;
	const pseudo_avrule_t *r2 = (const pseudo_avrule_t *)y;
	return pseudo_avrule_comp(r1, r2, 1);
}

/**
 * Given a conditional expression, convert its booleans to a sorted
 * array of pseudo-boolean values, assign that array to the
 * pseudo-avrule key, and then derive the truth table.
 *
 * @param diff Policy difference structure.
 * @param p Policy containing conditional.
 * @param cond Conditional expression to convert.
 * @param key Location to write converted expression.
 */
static int avrule_build_cond(poldiff_t * diff, apol_policy_t * p, qpol_cond_t * cond, pseudo_avrule_t * key)
{
	qpol_iterator_t *iter = NULL;
	qpol_cond_expr_node_t *node;
	uint32_t expr_type, truthiness;
	qpol_bool_t *bools[5], *qbool;
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
		if (qpol_cond_expr_node_get_bool(q, node, &qbool) < 0) {
			error = errno;
			goto cleanup;
		}
		for (i = 0; i < num_bools; i++) {
			if (bools[i] == qbool) {
				break;
			}
		}
		if (i >= num_bools) {
			assert(num_bools < 4);
			bools[i] = qbool;
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
				qbool = bools[j];
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
 * Bubble sort the permissions within a pseudo-avrule, sorted by
 * pointer value.  (Bubble-sort is fine because the number of
 * permissions will usually be less than 10.)  Then uniquify the list.
 *
 * @param key Rule whose permissions to sort.
 */
static void sort_and_uniquify_perms(pseudo_avrule_t * key)
{
	size_t i, j;
	char *t;
	for (i = key->num_perms; i > 1; i--) {
		for (j = 1; j < i; j++) {
			if (key->perms[j - 1] > key->perms[j]) {
				t = key->perms[j];
				key->perms[j] = key->perms[j - 1];
				key->perms[j - 1] = t;
			}
		}
	}
	for (i = 1; i < key->num_perms; i++) {
		if (key->perms[i] == key->perms[i - 1]) {
			memmove(key->perms + i, key->perms + i + 1, (key->num_perms - i - 1) * sizeof(key->perms[0]));
			key->num_perms--;
		}
	}
}

/**
 * Given a rule, construct a new pseudo-avrule and insert it into the
 * BST if not already there.
 *
 * @param diff Policy difference structure.
 * @param p Policy from which the rule came.
 * @param rule AV rule to insert.
 * @param source Source pseudo-type value.
 * @param target Target pseudo-type value.
 * @param b BST containing pseudo-avrules.
 *
 * @return 0 on success, < 0 on error.
 */
static int avrule_add_to_bst(poldiff_t * diff, apol_policy_t * p,
			     qpol_avrule_t * rule, uint32_t source, uint32_t target, apol_bst_t * b)
{
	pseudo_avrule_t *key, *inserted_key;
	qpol_class_t *obj_class;
	qpol_iterator_t *perm_iter = NULL;
	char *class_name, *perm_name, *pseudo_perm, **t;
	size_t num_perms;
	qpol_cond_t *cond;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int retval = -1, error = 0, compval;
	if ((key = calloc(1, sizeof(*key))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (qpol_avrule_get_rule_type(q, rule, &(key->spec)) < 0 ||
	    qpol_avrule_get_object_class(q, rule, &obj_class) < 0 ||
	    qpol_avrule_get_perm_iter(q, rule, &perm_iter) < 0 || qpol_avrule_get_cond(q, rule, &cond) < 0) {
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
	key->source = source;
	key->target = target;
	if (cond != NULL && (qpol_avrule_get_which_list(q, rule, &(key->branch)) < 0 || avrule_build_cond(diff, p, cond, key) < 0)) {
		error = errno;
		goto cleanup;
	}

	/* insert this pseudo into the tree if not already there */
	if ((compval = apol_bst_insert_and_get(b, (void **)&key, NULL)) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	inserted_key = key;
	key = NULL;

	/* append and uniquify this rule's permissions */
	if (qpol_iterator_get_size(perm_iter, &num_perms) < 0) {
		error = errno;
		goto cleanup;
	}
	if ((t = realloc(inserted_key->perms, (inserted_key->num_perms + num_perms) * sizeof(*t))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	inserted_key->perms = t;
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		if (qpol_iterator_get_item(perm_iter, (void *)&perm_name) < 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_bst_get_element(diff->perm_bst, perm_name, NULL, (void **)&pseudo_perm) < 0) {
			error = EBADRQC;	/* should never get here */
			ERR(diff, "%s", strerror(error));
			assert(0);
			free(perm_name);
			goto cleanup;
		}
		free(perm_name);
		inserted_key->perms[(inserted_key->num_perms)++] = pseudo_perm;
	}
	sort_and_uniquify_perms(inserted_key);

	/* store the rule pointer, to be used for showing line numbers */
	if (qpol_policy_has_capability(q, QPOL_CAP_LINE_NUMBERS)) {
		qpol_avrule_t **a = realloc(inserted_key->rules,
					    (inserted_key->num_rules + 1) * sizeof(*a));
		if (a == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		inserted_key->rules = a;
		inserted_key->rules[inserted_key->num_rules++] = rule;
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&perm_iter);
	if (retval < 0) {
		avrule_free_item(key);
	}
	errno = error;
	return retval;
}

/**
 * Given a rule, expand its source and target types into individual
 * pseudo-type values.  Then add the expanded rules to the BST.  This
 * is needed for when the source and/or target is an attribute.
 *
 * @param diff Policy difference structure.
 * @param p Policy from which the rule came.
 * @param rule AV rule to insert.
 * @param b BST containing pseudo-avrules.
 *
 * @return 0 on success, < 0 on error.
 */
static int avrule_expand(poldiff_t * diff, apol_policy_t * p, qpol_avrule_t * rule, apol_bst_t * b)
{
	qpol_type_t *source, *orig_target, *target;
	unsigned char source_attr, target_attr;
	qpol_iterator_t *source_iter = NULL, *target_iter = NULL;
	uint32_t source_val, target_val;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int which = (p == diff->orig_pol ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
	int retval = -1, error = 0;
	if (qpol_avrule_get_source_type(q, rule, &source) < 0 ||
	    qpol_avrule_get_target_type(q, rule, &orig_target) < 0 ||
	    qpol_type_get_isattr(q, source, &source_attr) < 0 || qpol_type_get_isattr(q, orig_target, &target_attr)) {
		error = errno;
		goto cleanup;
	}
#ifdef SETOOLS_DEBUG
	char *orig_source_name, *orig_target_name;
	qpol_type_get_name(q, source, &orig_source_name);
	qpol_type_get_name(q, orig_target, &orig_target_name);
#endif

	if (source_attr) {
		if (qpol_type_get_type_iter(q, source, &source_iter) < 0) {
			error = errno;
			goto cleanup;
		}
		/* handle situation where a rule has as its source an
		 * attribute without any types */
		if (qpol_iterator_end(source_iter)) {
			retval = 0;
			goto cleanup;
		}
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
			/* handle situation where a rule has as its
			 * target an attribute without any types */
			if (qpol_iterator_end(target_iter)) {
				retval = 0;
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
#ifdef SETOOLS_DEBUG
			char *n1, *n2;
			qpol_type_get_name(q, source, &n1);
			qpol_type_get_name(q, target, &n2);
#endif
			if ((source_val = type_map_lookup(diff, source, which)) == 0 ||
			    (target_val = type_map_lookup(diff, target, which)) == 0 ||
			    avrule_add_to_bst(diff, p, rule, source_val, target_val, b) < 0) {
				error = errno;
				goto cleanup;
			}
		} while (target_attr && !qpol_iterator_end(target_iter));
		qpol_iterator_destroy(&target_iter);
	} while (source_attr && !qpol_iterator_end(source_iter));
	retval = 0;
      cleanup:
	qpol_iterator_destroy(&source_iter);
	qpol_iterator_destroy(&target_iter);
	errno = error;
	return retval;
}

apol_vector_t *avrule_get_allow(poldiff_t * diff, apol_policy_t * policy)
{
	return avrule_get_items(diff, policy, QPOL_RULE_ALLOW);
}

apol_vector_t *avrule_get_neverallow(poldiff_t * diff, apol_policy_t * policy)
{
	return avrule_get_items(diff, policy, QPOL_RULE_NEVERALLOW);
}

apol_vector_t *avrule_get_auditallow(poldiff_t * diff, apol_policy_t * policy)
{
	return avrule_get_items(diff, policy, QPOL_RULE_AUDITALLOW);
}

apol_vector_t *avrule_get_dontaudit(poldiff_t * diff, apol_policy_t * policy)
{
	return avrule_get_items(diff, policy, QPOL_RULE_DONTAUDIT);
}

apol_vector_t *avrule_get_items(poldiff_t * diff, apol_policy_t * policy, const unsigned int flag)
{
	apol_vector_t *bools = NULL, *bool_states = NULL;
	size_t i, num_rules, j;
	apol_bst_t *b = NULL;
	apol_vector_t *v = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_avrule_t *rule;
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
	if ((bool_states = apol_vector_create_with_capacity(apol_vector_get_size(bools), NULL)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(bools); i++) {
		qpol_bool_t *qbool = apol_vector_get_element(bools, i);
		int state;
		if (qpol_bool_get_state(q, qbool, &state) < 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_append(bool_states, (void *)((size_t) state)) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if ((b = apol_bst_create(avrule_bst_comp, avrule_free_item)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (qpol_policy_get_avrule_iter(q, flag, &iter) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	qpol_iterator_get_size(iter, &num_rules);
	for (j = 0; !qpol_iterator_end(iter); qpol_iterator_next(iter), j++) {
		if (qpol_iterator_get_item(iter, (void **)&rule) < 0 || avrule_expand(diff, policy, rule, b) < 0) {
			error = errno;
			goto cleanup;
		}
		if (!(j % 1024)) {
			int percent = 50 * j / num_rules + (policy == diff->mod_pol ? 50 : 0);
			INFO(diff, "Computing AV rule difference: %02d%% complete", percent);
		}
	}
	if ((v = apol_bst_get_vector(b, 1)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	retval = 0;
      cleanup:
	/* restore boolean states */
	for (i = 0; i < apol_vector_get_size(bools); i++) {
		qpol_bool_t *qbool = apol_vector_get_element(bools, i);
		int state = (int)((size_t) apol_vector_get_element(bool_states, i));
		qpol_bool_set_state_no_eval(q, qbool, state);
	}
	qpol_policy_reevaluate_conds(q);
	apol_vector_destroy(&bools);
	apol_vector_destroy(&bool_states);
	apol_bst_destroy(&b);
	qpol_iterator_destroy(&iter);
	if (retval < 0) {
		apol_vector_destroy(&v);
		errno = error;
		return NULL;
	}
	return v;
}

int avrule_comp(const void *x, const void *y, poldiff_t * diff __attribute__ ((unused)))
{
	const pseudo_avrule_t *r1 = (const pseudo_avrule_t *)x;
	const pseudo_avrule_t *r2 = (const pseudo_avrule_t *)y;
	return pseudo_avrule_comp(r1, r2, 0);
}

/**
 * Allocate and return a new avrule difference object.  If the
 * pseudo-avrule's source and/or target expands to multiple read
 * types, then just choose the first one for display.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param rule Pseudo avrule that changed.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling poldiff_avrule_free() upon
 * the returned value.
 */
static poldiff_avrule_t *make_avdiff(poldiff_t * diff, poldiff_form_e form, pseudo_avrule_t * rule)
{
	poldiff_avrule_t *pa = NULL;
	const char *n1, *n2;
	int error = 0;
	if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
		n1 = type_map_get_name(diff, rule->source, POLDIFF_POLICY_MOD);
		n2 = type_map_get_name(diff, rule->target, POLDIFF_POLICY_MOD);
	} else {
		n1 = type_map_get_name(diff, rule->source, POLDIFF_POLICY_ORIG);
		n2 = type_map_get_name(diff, rule->target, POLDIFF_POLICY_ORIG);
	}
	assert(n1 != NULL && n2 != NULL);
	if ((pa = calloc(1, sizeof(*pa))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	pa->spec = rule->spec;
	pa->source = n1;
	pa->target = n2;
	pa->cls = rule->cls;
	pa->form = form;
	pa->cond = rule->cond;
	pa->branch = rule->branch;
      cleanup:
	if (error != 0) {
		poldiff_avrule_free(pa);
		errno = error;
		return NULL;
	}
	return pa;
}

int avrule_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	pseudo_avrule_t *rule = (pseudo_avrule_t *) item;
	poldiff_avrule_t *pa = NULL;
	apol_vector_t *v1, *v2, **target;
	apol_policy_t *p;
	size_t i;
	int retval = -1, error = errno;

	/* check if form should really become ADD_TYPE / REMOVE_TYPE,
	 * by seeing if the /other/ policy's reverse lookup is
	 * empty */
	if (form == POLDIFF_FORM_ADDED) {
		if ((v1 = type_map_lookup_reverse(diff, rule->source, POLDIFF_POLICY_ORIG)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, rule->target, POLDIFF_POLICY_ORIG)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_ADD_TYPE;
		}
		p = diff->mod_pol;
	} else {
		if ((v1 = type_map_lookup_reverse(diff, rule->source, POLDIFF_POLICY_MOD)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, rule->target, POLDIFF_POLICY_MOD)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_REMOVE_TYPE;
		}
		p = diff->orig_pol;
	}

	pa = make_avdiff(diff, form, rule);
	if (pa == NULL) {
		return -1;
	}

	if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
		if ((pa->removed_perms = apol_vector_create_with_capacity(1, NULL)) == NULL ||
		    (pa->unmodified_perms = apol_vector_create_with_capacity(1, NULL)) == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		target = &pa->added_perms;
	} else {
		if ((pa->added_perms = apol_vector_create_with_capacity(1, NULL)) == NULL ||
		    (pa->unmodified_perms = apol_vector_create_with_capacity(1, NULL)) == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		target = &pa->removed_perms;
	}
	if ((*target = apol_vector_create_with_capacity(rule->num_perms, NULL)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < rule->num_perms; i++) {
		if (apol_vector_append(*target, rule->perms[i]) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	apol_vector_sort(*target, apol_str_strcmp, NULL);

	if (qpol_policy_has_capability(apol_policy_get_qpol(p), QPOL_CAP_LINE_NUMBERS)) {
		/* calculate line numbers */
		if ((v1 = apol_vector_create(NULL)) == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
			pa->mod_linenos = v1;
		} else {
			pa->orig_linenos = v1;
		}

		/* copy rule pointers for delayed line number claculation */
		if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
			pa->num_mod_rules = rule->num_rules;
			pa->mod_rules = calloc(rule->num_rules, sizeof(qpol_avrule_t *));
			if (!pa->mod_rules) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			memcpy(pa->mod_rules, rule->rules, rule->num_rules * sizeof(qpol_avrule_t *));
		} else {
			pa->num_orig_rules = rule->num_rules;
			pa->orig_rules = calloc(rule->num_rules, sizeof(qpol_avrule_t *));
			if (!pa->orig_rules) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			memcpy(pa->orig_rules, rule->rules, rule->num_rules * sizeof(qpol_avrule_t *));
		}
	}

	if (apol_vector_append(diff->avrule_diffs->diffs, pa) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	switch (form) {
	case POLDIFF_FORM_ADDED:
		diff->avrule_diffs->num_added++;
		break;
	case POLDIFF_FORM_ADD_TYPE:
		diff->avrule_diffs->num_added_type++;
		break;
	case POLDIFF_FORM_REMOVED:
		diff->avrule_diffs->num_removed++;
		break;
	case POLDIFF_FORM_REMOVE_TYPE:
		diff->avrule_diffs->num_removed_type++;
		break;
	default:
		error = EBADRQC;       /* should never get here */
		ERR(diff, "%s", strerror(error));
		assert(0);
		goto cleanup;
	}
	diff->avrule_diffs->diffs_sorted = 0;
	retval = 0;
      cleanup:
	if (retval < 0) {
		poldiff_avrule_free(pa);
	}
	errno = error;
	return retval;
}

int avrule_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	pseudo_avrule_t *r1 = (pseudo_avrule_t *) x;
	pseudo_avrule_t *r2 = (pseudo_avrule_t *) y;
	apol_vector_t *unmodified_perms = NULL, *added_perms = NULL, *removed_perms = NULL;
	size_t i, j;
	char *perm1, *perm2;
	poldiff_avrule_t *pa = NULL;
	int retval = -1, error = 0;

	if ((unmodified_perms = apol_vector_create(NULL)) == NULL ||
	    (added_perms = apol_vector_create(NULL)) == NULL || (removed_perms = apol_vector_create(NULL)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = j = 0; i < r1->num_perms;) {
		if (j >= r2->num_perms)
			break;
		perm1 = r1->perms[i];
		perm2 = r2->perms[j];
		if (perm2 > perm1) {
			if (apol_vector_append(removed_perms, perm1) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		} else if (perm1 > perm2) {
			if (apol_vector_append(added_perms, perm2) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			j++;
		} else {
			if (apol_vector_append(unmodified_perms, perm1) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
			j++;
		}
	}

	for (; i < r1->num_perms; i++) {
		perm1 = r1->perms[i];
		if (apol_vector_append(removed_perms, perm1) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < r2->num_perms; j++) {
		perm2 = r2->perms[j];
		if (apol_vector_append(added_perms, perm2) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (apol_vector_get_size(added_perms) > 0 || apol_vector_get_size(removed_perms) > 0) {
		if ((pa = make_avdiff(diff, POLDIFF_FORM_MODIFIED, r1)) == NULL) {
			error = errno;
			goto cleanup;
		}
		pa->unmodified_perms = unmodified_perms;
		pa->added_perms = added_perms;
		pa->removed_perms = removed_perms;
		unmodified_perms = NULL;
		added_perms = NULL;
		removed_perms = NULL;
		apol_vector_sort(pa->unmodified_perms, apol_str_strcmp, NULL);
		apol_vector_sort(pa->added_perms, apol_str_strcmp, NULL);
		apol_vector_sort(pa->removed_perms, apol_str_strcmp, NULL);

		/* calculate line numbers */
		if (qpol_policy_has_capability(apol_policy_get_qpol(diff->orig_pol), QPOL_CAP_LINE_NUMBERS)) {
			if ((pa->orig_linenos = apol_vector_create(NULL)) == NULL) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}

			/* copy rule pointers for delayed line number claculation */
			pa->num_orig_rules = r1->num_rules;
			pa->orig_rules = calloc(r1->num_rules, sizeof(qpol_avrule_t *));
			if (!pa->orig_rules) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			memcpy(pa->orig_rules, r1->rules, r1->num_rules * sizeof(qpol_avrule_t *));
		}
		if (qpol_policy_has_capability(apol_policy_get_qpol(diff->mod_pol), QPOL_CAP_LINE_NUMBERS)) {
			if ((pa->mod_linenos = apol_vector_create(NULL)) == NULL) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}

			/* copy rule pointers for delayed line number claculation */
			pa->num_mod_rules = r2->num_rules;
			pa->mod_rules = calloc(r2->num_rules, sizeof(qpol_avrule_t *));
			if (!pa->mod_rules) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			memcpy(pa->mod_rules, r2->rules, r2->num_rules * sizeof(qpol_avrule_t *));
		}
		if (apol_vector_append(diff->avrule_diffs->diffs, pa) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->avrule_diffs->num_modified++;
		diff->avrule_diffs->diffs_sorted = 0;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&unmodified_perms);
	apol_vector_destroy(&added_perms);
	apol_vector_destroy(&removed_perms);
	if (retval != 0) {
		poldiff_avrule_free(pa);
	}
	errno = error;
	return retval;
}

int avrule_enable_line_numbers(poldiff_t * diff)
{
	apol_vector_t *av = NULL;
	poldiff_avrule_t *avrule = NULL;
	size_t i, j;
	qpol_iterator_t *iter = NULL;
	qpol_syn_avrule_t *sav = NULL;
	int error = 0;
	unsigned long lineno = 0;

	av = poldiff_get_avrule_vector(diff);

	for (i = 0; i < apol_vector_get_size(av); i++) {
		avrule = apol_vector_get_element(av, i);
		if (apol_vector_get_size(avrule->mod_linenos) || apol_vector_get_size(avrule->orig_linenos))
			continue;
		for (j = 0; j < avrule->num_orig_rules; j++) {
			if (qpol_avrule_get_syn_avrule_iter(diff->orig_qpol, avrule->orig_rules[j], &iter)) {
				error = errno;
				goto err;
			}
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&sav) < 0) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
				if (qpol_syn_avrule_get_lineno(diff->orig_qpol, sav, &lineno) < 0) {
					error = errno;
					goto err;
				}
				if (apol_vector_append(avrule->orig_linenos, (void *)lineno) < 0) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_sort_uniquify(avrule->orig_linenos, NULL, NULL);
		for (j = 0; j < avrule->num_mod_rules; j++) {
			if (qpol_avrule_get_syn_avrule_iter(diff->mod_qpol, avrule->mod_rules[j], &iter)) {
				error = errno;
				goto err;
			}
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&sav) < 0) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
				if (qpol_syn_avrule_get_lineno(diff->mod_qpol, sav, &lineno) < 0) {
					error = errno;
					goto err;
				}
				if (apol_vector_append(avrule->mod_linenos, (void *)lineno) < 0) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_sort_uniquify(avrule->mod_linenos, NULL, NULL);
	}
	return 0;
      err:
	qpol_iterator_destroy(&iter);
	return -1;
}
