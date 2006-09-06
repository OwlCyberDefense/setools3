/**
 *  @file rule_diff.c
 *  Implementation for computing a semantic differences in av and te
 *  rules.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#include <apol/bst.h>
#include <apol/policy-query.h>
#include <apol/util.h>
#include <qpol/policy_query.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_rule_summary {
	size_t num_added_av, num_added_te;
	size_t num_removed_av, num_removed_te;
	size_t num_modified_av, num_modified_te;
	size_t num_added_type_av, num_added_type_te;
	size_t num_removed_type_av, num_removed_type_te;
	int diffs_sorted_av, diffs_sorted_te;
	/** vector of poldiff_avrule_t */
	apol_vector_t *diffs_av;
	/** vector of poldiff_terule_t */
	apol_vector_t *diffs_te;
	/** BST of duplicated strings */
	apol_bst_t *class_bst;
	/** BST of duplicated strings */
	apol_bst_t *perm_bst;
	/** BST of duplicated strings */
	apol_bst_t *bool_bst;
};

struct poldiff_avrule {
	uint32_t spec;
	/* pointer into policy's symbol table */
	char *source, *target;
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
};

typedef struct pseudo_avrule {
	uint32_t spec;
	/** pseudo-type values */
	uint32_t source, target;
	/** pointer into the class_bst BST */
	char *cls;
	/** vector of pointers into the perm_bst BST (char *) */
	apol_vector_t *perms;
	/** array of pointers into the bool_bst BST */
	char *bools[5];
	uint32_t bool_val;
	uint32_t branch;
	/** pointer into policy's conditional list, needed to render
	 * conditional expressions */
	qpol_cond_t *cond;
} pseudo_avrule_t;

void poldiff_avrule_get_stats(poldiff_t *diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->rule_diffs->num_added_av;
	stats[1] = diff->rule_diffs->num_removed_av;
	stats[2] = diff->rule_diffs->num_modified_av;
	stats[3] = diff->rule_diffs->num_added_type_av;
	stats[4] = diff->rule_diffs->num_removed_type_av;
}

char *poldiff_avrule_to_string(poldiff_t *diff, const void *avrule)
{
	const poldiff_avrule_t *pa = (const poldiff_avrule_t *) avrule;
	apol_policy_t *p;
	const char *rule_type;
	char *diff_char = "", *s = NULL, *t = NULL, *perm_name, *cond_expr = NULL;
	qpol_iterator_t *cond_iter = NULL;
	size_t i, len;
	int error;
	if (diff == NULL || avrule == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (pa->form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE: {
		diff_char = "+";
		p = diff->mod_pol;
		break;
	}
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE: {
		diff_char = "-";
		p = diff->orig_pol;
		break;
	}
	case POLDIFF_FORM_MODIFIED: {
		diff_char = "*";
		p = diff->orig_pol;
		break;
	}
	default: {
		ERR(diff, "%s", strerror(ENOTSUP));
		errno = ENOTSUP;
		return NULL;
	}
	}
	rule_type = apol_rule_type_to_str(pa->spec);
	if (asprintf(&s, "%s %s %s %s : %s {",
		     diff_char, rule_type, pa->source, pa->target, pa->cls) < 0) {
		error = errno;
		s = NULL;
		goto err;
	}
	len = strlen(s);
	for (i = 0; pa->unmodified_perms != NULL && i < apol_vector_get_size(pa->unmodified_perms); i++) {
		perm_name = (char *) apol_vector_get_element(pa->unmodified_perms, i);
		if (asprintf(&t, " %s", perm_name) < 0) {
			error = errno;
			t = NULL;
			goto err;
		}
		if (apol_str_append(&s, &len, t) < 0) {
			error = errno;
			goto err;
		}
		free(t);
		t = NULL;
	}
	for (i = 0; pa->added_perms != NULL && i < apol_vector_get_size(pa->added_perms); i++) {
		perm_name = (char *) apol_vector_get_element(pa->added_perms, i);
		if (asprintf(&t, " +%s", perm_name) < 0) {
			error = errno;
			t = NULL;
			goto err;
		}
		if (apol_str_append(&s, &len, t) < 0) {
			error = errno;
			goto err;
		}
		free(t);
		t = NULL;
	}
	for (i = 0; pa->removed_perms != NULL && i < apol_vector_get_size(pa->removed_perms); i++) {
		perm_name = (char *) apol_vector_get_element(pa->removed_perms, i);
		if (asprintf(&t, " -%s", perm_name) < 0) {
			error = errno;
			t = NULL;
			goto err;
		}
		if (apol_str_append(&s, &len, t) < 0) {
			error = errno;
			goto err;
		}
		free(t);
		t = NULL;
	}
	if (apol_str_append(&s, &len, " };") < 0) {
		error = errno;
		goto err;
	}
	if (pa->cond != NULL) {
		if (qpol_cond_get_expr_node_iter(p->qh, p->p, pa->cond, &cond_iter) < 0 ||
		    (cond_expr = apol_cond_expr_render(p, cond_iter)) == NULL) {
			error = errno;
			goto err;
		}
		if (asprintf(&t, "  [%s]:%s", cond_expr,
			     (pa->branch ? "TRUE" : "FALSE")) < 0) {
			error = errno;
			t = NULL;
			goto err;
		}
		if (apol_str_append(&s, &len, t) < 0) {
			error = errno;
			goto err;
		}
		free(t);
		t = NULL;
		free(cond_expr);
		qpol_iterator_destroy(&cond_iter);
	}
	return s;
 err:
	free(s);
	free(t);
	free(cond_expr);
	qpol_iterator_destroy(&cond_iter);
	ERR(diff, "%s", strerror(error));
	errno = error;
	return NULL;
}

/**
 * Sort poldiff_avrule diff results in a mostly alphabetical order.
 */
static int poldiff_avrule_cmp(const void *x, const void *y, void *data __attribute__((unused)))
{
	const poldiff_avrule_t *a = (const poldiff_avrule_t *) x;
	const poldiff_avrule_t *b = (const poldiff_avrule_t *) y;
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
		return (char *) a->cond - (char *) b->cond;
	}
	/* sort true branch before false branch */
	return b->branch - a->branch;
}

apol_vector_t *poldiff_get_avrule_vector(poldiff_t *diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (diff->rule_diffs->diffs_sorted_av == 0) {
		apol_vector_sort(diff->rule_diffs->diffs_av, poldiff_avrule_cmp, NULL);
		diff->rule_diffs->diffs_sorted_av = 1;
	}
	return diff->rule_diffs->diffs_av;
}

poldiff_form_e poldiff_avrule_get_form(const poldiff_avrule_t *avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->form;
}

uint32_t poldiff_avrule_get_rule_type(const poldiff_avrule_t *avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->spec;
}

const char *poldiff_avrule_get_source_type(const poldiff_avrule_t *avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->source;
}

const char *poldiff_avrule_get_target_type(const poldiff_avrule_t *avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->target;
}

const char *poldiff_avrule_get_object_class(const poldiff_avrule_t *avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return 0;
	}
	return avrule->cls;
}

apol_vector_t *poldiff_avrule_get_added_perms(const poldiff_avrule_t *avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avrule->added_perms;
}

apol_vector_t *poldiff_avrule_get_removed_types(const poldiff_avrule_t *avrule)
{
	if (avrule == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avrule->removed_perms;
}

/*************** protected functions for roles ***************/

poldiff_rule_summary_t *rule_create(void)
{
	poldiff_rule_summary_t *rs = calloc(1, sizeof(*rs));
	if (rs == NULL) {
		return NULL;
	}
	if ((rs->diffs_av = apol_vector_create()) == NULL ||
	    (rs->diffs_te = apol_vector_create()) == NULL) {
		rule_destroy(&rs);
		return NULL;
	}
	return rs;
}

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
		apol_vector_destroy(&a->unmodified_perms, NULL);
		apol_vector_destroy(&a->added_perms, NULL);
		apol_vector_destroy(&a->removed_perms, NULL);
		free(a);
	}
}

void rule_destroy(poldiff_rule_summary_t **rs)
{
	if (rs != NULL && *rs != NULL) {
		apol_vector_destroy(&(*rs)->diffs_av, poldiff_avrule_free);
		apol_vector_destroy(&(*rs)->diffs_te, NULL); /* FIX ME */
		apol_bst_destroy(&(*rs)->class_bst, free);
		apol_bst_destroy(&(*rs)->perm_bst, free);
		apol_bst_destroy(&(*rs)->bool_bst, free);
		free(*rs);
		*rs = NULL;
	}
}

/**
 * Build the BST for classes, permissions, and booleans.  This
 * effectively provides a partial mapping of rules from one policy to
 * the other.
 *
 * @param diff Policy difference structure containing policies to diff.
 *
 * @return 0 on success, < 0 on error.
 */
static int rule_build_bsts(poldiff_t *diff) {
	apol_vector_t *classes[2] = {NULL, NULL};
	apol_vector_t *perms[2] = {NULL, NULL};
	apol_vector_t *bools[2] = {NULL, NULL};
	size_t i, j;
	qpol_class_t *cls;
	qpol_bool_t *bool;
	char *name, *new_name;
	int retval = -1, error = 0;
	if ((diff->rule_diffs->class_bst = apol_bst_create(apol_str_strcmp)) == NULL ||
	    (diff->rule_diffs->perm_bst = apol_bst_create(apol_str_strcmp)) == NULL ||
	    (diff->rule_diffs->bool_bst = apol_bst_create(apol_str_strcmp)) == NULL) {
		error = errno;
		goto cleanup;
	}
	for (i = 0; i < 2; i++) {
		apol_policy_t *p = (i == 0 ? diff->orig_pol : diff->mod_pol);
		if (apol_get_class_by_query(p, NULL, &classes[i]) < 0 ||
		    apol_get_perm_by_query(p, NULL, &perms[i]) < 0 ||
		    apol_get_bool_by_query(p, NULL, &bools[i]) < 0) {
			error = errno;
			goto cleanup;
		}
		for (j = 0; j < apol_vector_get_size(classes[i]); j++) {
			cls = (qpol_class_t *) apol_vector_get_element(classes[i], j);
			if (qpol_class_get_name(p->qh, p->p, cls, &name) < 0) {
				error = errno;
				goto cleanup;
			}
			if ((new_name = strdup(name)) == NULL ||
			    apol_bst_insert_and_get(diff->rule_diffs->class_bst, (void **) &new_name, NULL, free) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
		}
		for (j = 0; j < apol_vector_get_size(perms[i]); j++) {
			name = (char *) apol_vector_get_element(perms[i], j);
			if ((new_name = strdup(name)) == NULL ||
			    apol_bst_insert_and_get(diff->rule_diffs->perm_bst, (void **) &new_name, NULL, free) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
		}
		for (j = 0; j < apol_vector_get_size(bools[i]); j++) {
			bool = (qpol_bool_t *) apol_vector_get_element(bools[i], j);
			if (qpol_bool_get_name(p->qh, p->p, bool, &name) < 0) {
				error = errno;
				goto cleanup;
			}
			if ((new_name = strdup(name)) == NULL ||
			    apol_bst_insert_and_get(diff->rule_diffs->bool_bst, (void **) &new_name, NULL, free) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
		}
	}
	retval = 0;
 cleanup:
	apol_vector_destroy(&classes[0], NULL);
	apol_vector_destroy(&classes[1], NULL);
	apol_vector_destroy(&perms[0], NULL);
	apol_vector_destroy(&perms[1], NULL);
	apol_vector_destroy(&bools[0], NULL);
	apol_vector_destroy(&bools[1], NULL);
	errno = error;
	return retval;
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
static int pseudo_avrule_comp(pseudo_avrule_t *rule1, pseudo_avrule_t *rule2, int is_sorting)
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
		return (int) (rule1->cls - rule2->cls);
	}
	if (rule1->spec != rule2->spec) {
		return rule1->spec - rule2->spec;
	}
	if (rule1->bools[0] == NULL && rule2->bools[0] == NULL) {
		/* both rules are unconditional */
		return 0;
	}
	else if (rule1->bools[0] == NULL && rule2->bools[0] != NULL) {
		/* unconditional rules come before conditional */
		return -1;
	}
	else if (rule1->bools[0] != NULL && rule2->bools[0] == NULL) {
		/* unconditional rules come before conditional */
		return 1;
	}
	for (i = 0; i < (sizeof(rule1->bools) / sizeof(rule1->bools[0])); i++) {
		if (rule1->bools[i] != rule2->bools[i]) {
			return (int) (rule1->bools[i] - rule2->bools[i]);
		}
	}
	if (is_sorting) {
		if (rule1->branch != rule2->branch) {
			return rule1->branch - rule2->branch;
		}
		return (int) rule1->bool_val - (int) rule2->bool_val;
	}
	else {
		if (rule1->branch == rule2->branch) {
			bool_val = rule2->bool_val;
		}
		else {
			bool_val = ~rule2->bool_val;
		}
		return rule1->bool_val - bool_val;
	}
}

static int avrule_bst_comp(const void *x, const void *y, void *data __attribute__((unused)))
{
	pseudo_avrule_t *r1 = (pseudo_avrule_t *) x;
	pseudo_avrule_t *r2 = (pseudo_avrule_t *) y;
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
static int avrule_build_cond(poldiff_t *diff, apol_policy_t *p, qpol_cond_t *cond, pseudo_avrule_t *key)
{
	qpol_iterator_t *iter = NULL;
	qpol_cond_expr_node_t *node;
	uint32_t expr_type, truthiness;
	qpol_bool_t *bools[5], *bool;
	size_t i, j;
	size_t num_bools = 0;
	char *bool_name, *pseudo_bool, *t;
	int orig_states[5];
	int retval = -1, error = 0, compval;
	if (qpol_cond_get_expr_node_iter(p->qh, p->p, cond, &iter) < 0) {
		error = errno;
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &node) < 0 ||
		    qpol_cond_expr_node_get_expr_type(p->qh, p->p, node, &expr_type) < 0) {
			error = errno;
			goto cleanup;
		}
		if (expr_type != QPOL_COND_EXPR_BOOL) {
			continue;
		}
		if (qpol_cond_expr_node_get_bool(p->qh, p->p, node, &bool) < 0) {
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
		if (qpol_bool_get_name(p->qh, p->p, bools[i], &bool_name) < 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_bst_get_element(diff->rule_diffs->bool_bst, bool_name, NULL, (void **) &pseudo_bool) < 0) {
			error = EBADRQC;  /* should never get here */
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

	/* store old boolean states prior to change */
	for (i = 0; i < num_bools; i++) {
		if (qpol_bool_get_state(p->qh, p->p, bools[i], orig_states + i) < 0) {
			error = errno;
			goto cleanup;
		}
	}

	/* now compute the truth table for the booleans */
	key->bool_val = 0;
	for (i = 0; i < 32; i++) {
		for (j = 0; j < num_bools; j++) {
			if (qpol_bool_set_state_no_eval(p->qh, p->p, bools[j], ((i & (1 << j)) ? 1 : 0)) < 0) {
				error = errno;
				goto cleanup;
			}
		}
		if (qpol_cond_eval(p->qh, p->p, cond, &truthiness) < 0) {
			error = errno;
			goto cleanup;
		}
		key->bool_val = (key->bool_val << 1) | truthiness;
	}

	/* restore old boolean states */
	for (i = 0; i < num_bools; i++) {
		if (qpol_bool_set_state_no_eval(p->qh, p->p, bools[i], orig_states[i]) < 0) {
			error = errno;
			goto cleanup;
		}
	}
	key->cond = cond;
	retval = 0;
 cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
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
static int avrule_add_to_bst(poldiff_t *diff, apol_policy_t *p,
			     qpol_avrule_t *rule, uint32_t source, uint32_t target,
			     apol_bst_t *b)
{
	pseudo_avrule_t *key, *inserted_key;
	qpol_class_t *obj_class;
	qpol_iterator_t *perm_iter = NULL;
        char *class_name, *perm_name, *pseudo_perm;
	size_t num_perms;
	qpol_cond_t *cond;
	int retval = -1, error = 0, compval;
	if ((key = calloc(1, sizeof(*key))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (qpol_avrule_get_rule_type(p->qh, p->p, rule, &(key->spec)) < 0 ||
	    qpol_avrule_get_object_class(p->qh, p->p, rule, &obj_class) < 0 ||
	    qpol_avrule_get_perm_iter(p->qh, p->p, rule, &perm_iter) < 0 ||
	    qpol_avrule_get_cond(p->qh, p->p, rule, &cond) < 0) {
		error = errno;
		goto cleanup;
	}
	if (qpol_class_get_name(p->qh, p->p, obj_class, &class_name) < 0) {
		error = errno;
		goto cleanup;
	}
	if (apol_bst_get_element(diff->rule_diffs->class_bst, class_name, NULL, (void **) &key->cls) < 0) {
		error = EBADRQC;  /* should never get here */
		ERR(diff, "%s", strerror(error));
		assert(0);
		goto cleanup;
	}
	key->source = source;
	key->target = target;
	if (cond != NULL &&
	    (qpol_avrule_get_which_list(p->qh, p->p, rule, &(key->branch)) < 0 ||
	     avrule_build_cond(diff, p, cond, key) < 0)) {
		error = errno;
		goto cleanup;
	}

	/* insert this pseudo into the tree if not already there */
        if ((compval = apol_bst_insert_and_get(b, (void **) &key, NULL, avrule_free_item)) < 0) {
                error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	inserted_key = key;
	key = NULL;
	/* append and uniquify this rule's permissions */
	if (inserted_key->perms == NULL) {
		if (qpol_iterator_get_size(perm_iter, &num_perms) < 0) {
			error = errno;
			goto cleanup;
		}
		if ((inserted_key->perms = apol_vector_create_with_capacity(num_perms)) == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for ( ; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		if (qpol_iterator_get_item(perm_iter, (void *) &perm_name) < 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_bst_get_element(diff->rule_diffs->perm_bst, perm_name, NULL, (void **) &pseudo_perm) < 0) {
			error = EBADRQC;  /* should never get here */
			ERR(diff, "%s", strerror(error));
			assert(0);
			free(perm_name);
			goto cleanup;
		}
		free(perm_name);
		if (apol_vector_append(inserted_key->perms, pseudo_perm) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	apol_vector_sort_uniquify(inserted_key->perms, NULL, NULL, NULL);
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
 * pseudo-type values.  Then add the expanded rule to the BST.  This
 * is needed for when the source and/or target is an attribute.
 *
 * @param diff Policy difference structure.
 * @param p Policy from which the rule came.
 * @param rule AV rule to insert.
 * @param b BST containing pseudo-avrules.
 *
 * @return 0 on success, < 0 on error.
 */
static int avrule_expand(poldiff_t *diff, apol_policy_t *p, qpol_avrule_t *rule, apol_bst_t *b)
{
	qpol_type_t *source, *orig_target, *target;
	unsigned char source_attr, target_attr;
	qpol_iterator_t *source_iter = NULL, *target_iter = NULL;
	uint32_t source_val, target_val;
	int which = (p == diff->orig_pol ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
	int retval = -1, error = 0;
	if (qpol_avrule_get_source_type(p->qh, p->p, rule, &source) < 0 ||
	    qpol_avrule_get_target_type(p->qh, p->p, rule, &orig_target) < 0 ||
	    qpol_type_get_isattr(p->qh, p->p, source, &source_attr) < 0 ||
	    qpol_type_get_isattr(p->qh, p->p, orig_target, &target_attr)) {
		error = errno;
		goto cleanup;
	}
	if (source_attr &&
	    qpol_type_get_type_iter(p->qh, p->p, source, &source_iter) < 0) {
		error = errno;
		goto cleanup;
	}
	do {
		if (source_attr) {
			if (qpol_iterator_get_item(source_iter, (void **) &source) < 0) {
				error = errno;
				goto cleanup;
			}
			qpol_iterator_next(source_iter);
		}
		if (target_attr) {
			if (qpol_type_get_type_iter(p->qh, p->p, orig_target, &target_iter) < 0) {
				error = errno;
				goto cleanup;
			}
		}
		else {
			target = orig_target;
		}
		do {
			if (target_attr) {
				if (qpol_iterator_get_item(target_iter, (void **) &target) < 0) {
					error = errno;
					goto cleanup;
				}
				qpol_iterator_next(target_iter);
			}
                        char *n1, *n2;
                        qpol_type_get_name(p->qh, p->p, source, &n1);
                        qpol_type_get_name(p->qh, p->p, target, &n2);
			if ((source_val = type_map_lookup(diff, source, which)) == 0 ||
			    (target_val = type_map_lookup(diff, target, which)) == 0 ||
			    avrule_add_to_bst(diff, p, rule, source_val, target_val, b) < 0) {
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

apol_vector_t *avrule_get_items(poldiff_t *diff, apol_policy_t *policy)
{
	apol_bst_t *b = NULL;
	apol_vector_t *v = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_avrule_t *rule;
	int retval = -1, error = 0;
	if (diff->rule_diffs->class_bst == NULL &&
	    rule_build_bsts(diff) < 0) {
		error = errno;
		goto cleanup;
	}
	if ((b = apol_bst_create(avrule_bst_comp)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (qpol_policy_get_avrule_iter(policy->qh, policy->p,
					QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT, &iter) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0 ||
		    avrule_expand(diff, policy, rule, b) < 0) {
			error = errno;
			goto cleanup;
		}
	}
	if ((v = apol_bst_get_vector(b)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	retval = 0;
 cleanup:
	apol_bst_destroy(&b, NULL);
	qpol_iterator_destroy(&iter);
	if (retval < 0) {
		apol_vector_destroy(&v, avrule_free_item);
		errno = error;
		return NULL;
	}
	return v;
}

void avrule_free_item(void *item)
{
	pseudo_avrule_t *a = (pseudo_avrule_t *) item;
	if (item != NULL) {
		apol_vector_destroy(&a->perms, NULL);
		free(a);
	}
}

int avrule_comp(const void *x, const void *y, poldiff_t *diff __attribute__((unused)))
{
	pseudo_avrule_t *r1 = (pseudo_avrule_t *) x;
	pseudo_avrule_t *r2 = (pseudo_avrule_t *) y;
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
static poldiff_avrule_t *make_diff(poldiff_t *diff, poldiff_form_e form, pseudo_avrule_t *rule)
{
	poldiff_avrule_t *pa;
	apol_vector_t *v1, *v2;
	qpol_type_t *t1, *t2;
	char *n1, *n2;
	int error;
	if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
		v1 = type_map_lookup_reverse(diff, rule->source, POLDIFF_POLICY_MOD);
		v2 = type_map_lookup_reverse(diff, rule->target, POLDIFF_POLICY_MOD);
	}
	else {
		v1 = type_map_lookup_reverse(diff, rule->source, POLDIFF_POLICY_ORIG);
		v2 = type_map_lookup_reverse(diff, rule->target, POLDIFF_POLICY_ORIG);
	}
	if (v1 == NULL || apol_vector_get_size(v1) == 0 ||
	    v2 == NULL || apol_vector_get_size(v2) == 0) {
		error = EBADRQC;  /* should never get here */
		ERR(diff, "%s", strerror(error));
		assert(0);
		return NULL;
	}
	/* only generate one missing rule, for the case where the type
	 * map reverse lookup yielded multiple types */
	t1 = apol_vector_get_element(v1, 0);
	t2 = apol_vector_get_element(v2, 0);
	if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
		if (qpol_type_get_name(diff->mod_pol->qh, diff->mod_pol->p, t1, &n1) < 0 ||
		    qpol_type_get_name(diff->mod_pol->qh, diff->mod_pol->p, t2, &n2) < 0) {
			return NULL;
		}
	}
	else {
		if (qpol_type_get_name(diff->orig_pol->qh, diff->orig_pol->p, t1, &n1) < 0 ||
		    qpol_type_get_name(diff->orig_pol->qh, diff->orig_pol->p, t2, &n2) < 0) {
			return NULL;
		}
	}
	if ((pa = calloc(1, sizeof(*pa))) == NULL) {
		error = errno;
		poldiff_avrule_free(pa);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pa->spec = rule->spec;
	pa->source = n1;
	pa->target = n2;
	pa->cls = rule->cls;
	pa->form = form;
	pa->cond = rule->cond;
	pa->branch = rule->branch;
	return pa;
}

int avrule_new_diff(poldiff_t *diff, poldiff_form_e form, const void *item)
{
	pseudo_avrule_t *rule = (pseudo_avrule_t *) item;
	poldiff_avrule_t *pa = NULL;
	apol_vector_t *v1, *v2;
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
	}
	else {
		if ((v1 = type_map_lookup_reverse(diff, rule->source, POLDIFF_POLICY_MOD)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, rule->target, POLDIFF_POLICY_MOD)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_REMOVE_TYPE;
		}
	}

	pa = make_diff(diff, form, rule);
	if (pa == NULL) {
		return -1;
	}
        if ((pa->unmodified_perms = apol_vector_create_from_vector(rule->perms)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}

	if (apol_vector_append(diff->rule_diffs->diffs_av, pa) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	switch (form) {
	case POLDIFF_FORM_ADDED:
		diff->rule_diffs->num_added_av++;
		break;
	case POLDIFF_FORM_ADD_TYPE:
		diff->rule_diffs->num_added_type_av++;
		break;
	case POLDIFF_FORM_REMOVED:
		diff->rule_diffs->num_removed_av++;
		break;
	case POLDIFF_FORM_REMOVE_TYPE:
		diff->rule_diffs->num_removed_type_av++;
		break;
        default:
		error = EBADRQC;  /* should never get here */
		ERR(diff, "%s", strerror(error));
		assert(0);
		goto cleanup;
        }
	diff->rule_diffs->diffs_sorted_av = 0;
	retval = 0;
 cleanup:
	if (retval < 0) {
		poldiff_avrule_free(pa);
	}
	errno = error;
	return retval;
}

int avrule_deep_diff(poldiff_t *diff, const void *x, const void *y)
{
	pseudo_avrule_t *r1 = (pseudo_avrule_t *) x;
	pseudo_avrule_t *r2 = (pseudo_avrule_t *) y;
	apol_vector_t *unmodified_perms = NULL, *added_perms = NULL, *removed_perms = NULL;
	size_t i, j;
	char *perm1, *perm2;
	poldiff_avrule_t *pa = NULL;
	int retval = -1, error = 0;

	if ((unmodified_perms = apol_vector_create()) == NULL ||
	    (added_perms = apol_vector_create()) == NULL ||
	    (removed_perms = apol_vector_create()) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = j = 0; i < apol_vector_get_size(r1->perms); ) {
		if (j >= apol_vector_get_size(r2->perms))
			break;
		perm1 = (char *) apol_vector_get_element(r1->perms, i);
		perm2 = (char *) apol_vector_get_element(r2->perms, j);
		if (perm2 > perm1) {
			if (apol_vector_append(removed_perms, perm1) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		}
		else if (perm1 > perm2) {
			if (apol_vector_append(added_perms, perm2) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			j++;
		}
		else {
			if (apol_vector_append(unmodified_perms, perm1) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
			j++;
		}
	}

	for ( ; i < apol_vector_get_size(r1->perms); i++) {
		perm1 = (char *) apol_vector_get_element(r1->perms, i);
		if (apol_vector_append(removed_perms, perm1) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for ( ; j < apol_vector_get_size(r2->perms); j++) {
		perm2 = (char *) apol_vector_get_element(r2->perms, j);
		if (apol_vector_append(added_perms, perm2) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (apol_vector_get_size(added_perms) > 0 ||
	    apol_vector_get_size(removed_perms) > 0) {
		if ((pa = make_diff(diff, POLDIFF_FORM_MODIFIED, r1)) == NULL) {
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
		if (apol_vector_append(diff->rule_diffs->diffs_av, pa) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->rule_diffs->num_modified_av++;
		diff->rule_diffs->diffs_sorted_av = 0;
	}
	retval = 0;
 cleanup:
	apol_vector_destroy(&unmodified_perms, NULL);
	apol_vector_destroy(&added_perms, NULL);
	apol_vector_destroy(&removed_perms, NULL);
	if (retval != 0) {
		poldiff_avrule_free(pa);
	}
	errno = error;
	return retval;
}
