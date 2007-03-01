/**
 *  @file
 *  Implementation for computing a semantic differences in range
 *  transition rules.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#include <apol/mls-query.h>
#include <apol/util.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_range_trans_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	size_t num_added_type;
	size_t num_removed_type;
	apol_vector_t *diffs;
};

struct poldiff_range_trans
{
	/* keep track of both the original policy's and modified
	 * policy's range transition.  note that this cannot have just
	 * qpol_range_trans_t, for multiple transitions could be
	 * merged into one due to the type map */
	char *source_type[2];
	char *target_type[2];
	char *target_class[2];
	poldiff_form_e form;
	apol_mls_range_t *range[2];
};

void poldiff_range_trans_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->range_trans_diffs->num_added;
	stats[1] = diff->range_trans_diffs->num_removed;
	stats[2] = diff->range_trans_diffs->num_modified;
	stats[3] = diff->range_trans_diffs->num_added_type;
	stats[4] = diff->range_trans_diffs->num_removed_type;
}

char *poldiff_range_trans_to_string(poldiff_t * diff, const void *range_trans)
{
	const poldiff_range_trans_t *rt = range_trans;
	size_t len = 0;
	char *range[2] = { NULL, NULL }, *s = NULL;
	if (diff == NULL || range_trans == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (rt->form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:
		{
			if ((range[1] = apol_mls_range_render(diff->mod_pol, rt->range[1])) == NULL ||
			    apol_str_appendf(&s, &len, "+ range_transition %s %s : %s %s;", rt->source_type[1], rt->target_type[1],
					     rt->target_class[1], range[1]) < 0) {
				break;
			}
			goto cleanup;
		}
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE:
		{
			if ((range[0] = apol_mls_range_render(diff->orig_pol, rt->range[0])) == NULL ||
			    apol_str_appendf(&s, &len, "- range_transition %s %s : %s %s;", rt->source_type[0], rt->target_type[0],
					     rt->target_class[0], range[0]) < 0) {
				break;
			}
			goto cleanup;
		}
	case POLDIFF_FORM_MODIFIED:
		{
			if ((range[0] = apol_mls_range_render(diff->orig_pol, rt->range[0])) == NULL ||
			    (range[1] = apol_mls_range_render(diff->mod_pol, rt->range[1])) == NULL) {
				break;
			}
			if (apol_str_appendf
			    (&s, &len, "* range_transition %s %s : %s %s\n", rt->source_type[0], rt->target_type[0],
			     rt->target_class[0], range[0]) < 0
			    || apol_str_appendf(&s, &len, "  range_transition %s %s : %s %s\n<FIXME>", rt->source_type[0],
						rt->target_type[0], rt->target_class[0], range[1]) < 0) {
				break;
			}
			goto cleanup;
		}
	default:
		{
			ERR(diff, "%s", strerror(ENOTSUP));
			errno = ENOTSUP;
			return NULL;
		}
	}
	/* if this is reached then an error occurred */
	free(s);
	s = NULL;
	ERR(diff, "%s", strerror(ENOMEM));
	errno = ENOMEM;
      cleanup:
	free(range[0]);
	free(range[1]);
	return s;
}

apol_vector_t *poldiff_get_range_trans_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	return diff->range_trans_diffs->diffs;
}

const char *poldiff_range_trans_get_source_type(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (range_trans->source_type[0] != NULL) {
		return range_trans->source_type[0];
	}
	return range_trans->source_type[1];
}

const char *poldiff_range_trans_get_target_type(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (range_trans->target_type[0] != NULL) {
		return range_trans->target_type[0];
	}
	return range_trans->target_type[1];
}

const char *poldiff_range_trans_get_target_class(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (range_trans->target_class[0] != NULL) {
		return range_trans->target_class[0];
	}
	return range_trans->target_class[1];
}

const apol_mls_range_t *poldiff_range_trans_get_original_range(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->range[0];
}

const apol_mls_range_t *poldiff_range_trans_get_modified_range(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->range[1];
}

poldiff_form_e poldiff_range_trans_get_form(const void *range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}
	return ((const poldiff_range_trans_t *)range_trans)->form;
}

poldiff_range_trans_summary_t *range_trans_create(void)
{
	poldiff_range_trans_summary_t *rts = calloc(1, sizeof(*rts));
	if (rts == NULL) {
		return NULL;
	}
	if ((rts->diffs = apol_vector_create()) == NULL) {
		range_trans_destroy(&rts);
		return NULL;
	}
	return rts;
}

static void range_trans_free(void *elem)
{
	if (elem != NULL) {
		poldiff_range_trans_t *rt = (poldiff_range_trans_t *) elem;
		size_t i;
		for (i = 0; i < 2; i++) {
			free(rt->source_type[i]);
			free(rt->target_type[i]);
			free(rt->target_class[i]);
			apol_mls_range_destroy(&rt->range[i]);
		}
		free(rt);
	}
}

void range_trans_destroy(poldiff_range_trans_summary_t ** rts)
{
	if (rts != NULL && *rts != NULL) {
		apol_vector_destroy(&(*rts)->diffs, range_trans_free);
		free(*rts);
		*rts = NULL;
	}
}

typedef struct pseudo_range_trans
{
	uint32_t source_type, target_type;
	/* pointer into a policy's class's symbol table */
	char *target_class;
	apol_mls_range_t *range;
} pseudo_range_trans_t;

void range_trans_free_item(void *item)
{
	if (item != NULL) {
		pseudo_range_trans_t *prt = item;
		apol_mls_range_destroy(&prt->range);
		free(item);
	}
}

int range_trans_comp(const void *x, const void *y, poldiff_t * diff __attribute__ ((unused)))
{
	const pseudo_range_trans_t *p1 = x;
	const pseudo_range_trans_t *p2 = y;

	if (p1->source_type != p2->source_type) {
		return p1->source_type - p2->source_type;
	}
	if (p1->target_type != p2->target_type) {
		return p1->target_type - p2->target_type;
	}
	return strcmp(p1->target_class, p2->target_class);
}

int range_trans_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	range_trans_destroy(&diff->range_trans_diffs);
	diff->range_trans_diffs = range_trans_create();
	if (diff->range_trans_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Get the first valid name that can be found for a pseudo type value.
 *
 * @param diff Policy difference structure associated with the value.
 * @param pseudo_val Value for which to get a name.
 * @param pol The policy to use, either POLDIFF_POLICY_ORIG or
 * POLDIFF_POLICY_MOD.
 *
 * @return A valid name of a type from either policy that maps to the
 * specified value.  The caller must free() this string afterwards.
 */
static char *get_valid_name(poldiff_t * diff, const uint32_t pseudo_val, int pol)
{
	apol_vector_t *v = NULL;
	char *name = NULL;
	qpol_type_t *t;

	v = type_map_lookup_reverse(diff, pseudo_val, pol);
	if (apol_vector_get_size(v) == 0) {
		/* should never get here */
		assert(0);
		return NULL;
	}
	t = apol_vector_get_element(v, 0);
	if (pol == POLDIFF_POLICY_ORIG)
		qpol_type_get_name(diff->orig_qpol, t, &name);
	else
		qpol_type_get_name(diff->mod_qpol, t, &name);
	if ((name = strdup(name)) == NULL) {
		ERR(diff, "%s", strerror(errno));
		return NULL;
	}
	return name;
}

int range_trans_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	const pseudo_range_trans_t *prt = (const pseudo_range_trans_t *)item;
	poldiff_range_trans_t *rt;

	if ((rt = calloc(1, sizeof(*rt))) == NULL) {
		int error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}
	/* convert the prt's source and target pseudo-types to actual
	 * names */
	if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE || form == POLDIFF_FORM_MODIFIED) {
		rt->source_type[1] = get_valid_name(diff, prt->source_type, POLDIFF_POLICY_MOD);
		rt->target_type[1] = get_valid_name(diff, prt->target_type, POLDIFF_POLICY_MOD);
		rt->target_class[1] = prt->target_class;
		/* FIX ME: for a modified range trans, range[0] is not
		 * necessarily range[1].  also, need to keep track of
		 * which sensitivities are actually different */
		if ((rt->range[1] = apol_mls_range_create_from_mls_range(prt->range)) == NULL) {
			int error = errno;
			ERR(diff, "%s", strerror(error));
			range_trans_free(rt);
			errno = error;
			return -1;
		}
	}
	if (form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_REMOVE_TYPE || form == POLDIFF_FORM_MODIFIED) {
		rt->source_type[0] = get_valid_name(diff, prt->source_type, POLDIFF_POLICY_ORIG);
		rt->target_type[0] = get_valid_name(diff, prt->target_type, POLDIFF_POLICY_ORIG);
		rt->target_class[0] = prt->target_class;
		if ((rt->range[0] = apol_mls_range_create_from_mls_range(prt->range)) == NULL) {
			int error = errno;
			ERR(diff, "%s", strerror(error));
			range_trans_free(rt);
			errno = error;
			return -1;
		}
	}
	if (apol_vector_append(diff->range_trans_diffs->diffs, rt) < 0) {
		int error = errno;
		ERR(diff, "%s", strerror(error));
		range_trans_free(rt);
		errno = error;
		return -1;
	}
	/* increment appropriate counter */
	switch (form) {
	case POLDIFF_FORM_ADDED:
		{
			diff->range_trans_diffs->num_added++;
			break;
		}
	case POLDIFF_FORM_ADD_TYPE:
		{
			diff->range_trans_diffs->num_added_type++;
			break;
		}
	case POLDIFF_FORM_REMOVED:
		{
			diff->range_trans_diffs->num_removed++;
			break;
		}
	case POLDIFF_FORM_REMOVE_TYPE:
		{
			diff->range_trans_diffs->num_removed_type++;
			break;
		}
	case POLDIFF_FORM_MODIFIED:
		{
			diff->range_trans_diffs->num_modified++;
			break;
		}
	case POLDIFF_FORM_NONE:
	default:
		{
			/* not reachable */
			assert(0);
		}
	}
	return 0;
}

/**
 *  Compare two pseudo range transition rules from the same policy.
 *  Compares the pseudo source type, pseudo target type, and target
 *  class.
 *
 *  @param x A pseudo_range_trans_t entry.
 *  @param y A pseudo_range_trans_t entry.
 *  @param arg The policy difference structure.
 *
 *  @return < 0, 0, or > 0 if the first rule is respectively less than,
 *  equal to, or greater than the second. If the return value would be 0
 *  but the default role is different a warning is issued.
 */
static int pseudo_range_trans_comp(const void *x, const void *y, void *arg)
{
	const pseudo_range_trans_t *a = x;
	const pseudo_range_trans_t *b = y;
	poldiff_t *diff = arg;
	return range_trans_comp(a, b, diff);
}

/**
 * Convert a type to a vector of one element, or an attribute into a
 * vector of its types.
 */
/* FIX ME
static apol_vector_t *range_trans_get_type_vector(poldiff_t * diff, int which_pol, qpol_type_t * type) {
	unsigned char isattr = 0;
        apol_vector_t *v = NULL;
        int error;
        qpol_type_get_isattr(q, tmp_type, &isattr);
        if (!isattr) {
                if ((v = apol_vector_create_with_capacity(1)) == NULL ||
                    apol_vector_append(v, type) < 0) { 
                        error = errno;
                        apol_vector_destroy(&v, NULL);
                        ERR(diff, "%s", strerror(error));
                        errno = error;
                        return NULL;
                }
        }
        qpol_iterator_t *attr_types = NULL;
        qpol_type_get_type_iter(q, type, &attr_types);
        if ((v = apol_vector_create_from_iter(attr_types)) == NULL) {
                error = errno;
                ERR(diff, "%s", strerror(error));
                errno = error;
                return NULL;
        }
        return v;
}
*/

apol_vector_t *range_trans_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	apol_vector_t *v = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_range_trans_t *qrt = NULL;
	qpol_type_t *source_type, *target_type;
	qpol_class_t *target_class;
	char *class_name;
	qpol_mls_range_t *range;
	pseudo_range_trans_t *prt = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0, which_pol;

	which_pol = (policy == diff->orig_pol ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
	if (qpol_policy_get_range_trans_iter(q, &iter)) {
		error = errno;
		goto err;
	}
	if ((v = apol_vector_create()) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto err;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&qrt) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		if (qpol_range_trans_get_source_type(q, qrt, &source_type) < 0 ||
		    qpol_range_trans_get_target_type(q, qrt, &target_type) < 0 ||
		    qpol_range_trans_get_target_class(q, qrt, &target_class) < 0 ||
		    qpol_range_trans_get_range(q, qrt, &range) < 0 || qpol_class_get_name(q, target_class, &class_name) < 0) {
			error = errno;
			goto err;
		}
		if (!(prt = calloc(1, sizeof(*prt)))) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		prt->source_type = type_map_lookup(diff, source_type, which_pol);
		prt->target_type = type_map_lookup(diff, target_type, which_pol);
		prt->target_class = class_name;
		if ((prt->range = apol_mls_range_create_from_qpol_mls_range(policy, range)) == NULL) {
			error = errno;
			goto err;
		}
		if (apol_vector_append(v, prt)) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		prt = NULL;
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort_uniquify(v, pseudo_range_trans_comp, diff, range_trans_free_item);
	return v;

      err:
	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&v, free);
	free(prt);
	errno = error;
	return NULL;
}

int range_trans_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
#if 0
	/* FIX ME */
	const pseudo_role_trans_t *prt1 = x;
	const pseudo_role_trans_t *prt2 = y;
	char *default1 = NULL, *default2 = NULL;
	poldiff_role_trans_t *rt = NULL;
	apol_vector_t *mapped_tgts = NULL;
	qpol_type_t *tgt_type = NULL;
	char *tgt = NULL;
	int error = 0;

	default1 = prt1->default_role;
	default2 = prt2->default_role;

	if (!strcmp(default1, default2))
		return 0;	       /* no difference */

	mapped_tgts = type_map_lookup_reverse(diff, prt1->pseudo_target, POLDIFF_POLICY_ORIG);
	if (!mapped_tgts)
		return -1;	       /* errors already reported */
	tgt_type = apol_vector_get_element(mapped_tgts, 0);
	if (!tgt_type) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}
	qpol_type_get_name(diff->orig_qpol, tgt_type, &tgt);
	rt = make_rt_diff(diff, POLDIFF_FORM_MODIFIED, prt1->source_role, tgt);
	if (!rt)
		return -1;	       /* errors already reported */
	rt->orig_default = default1;
	rt->mod_default = default2;
	if (apol_vector_append(diff->role_trans_diffs->diffs, rt)) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		free(rt);
		errno = error;
		return -1;
	};
	diff->role_trans_diffs->num_modified++;
#endif
	return 0;
}
