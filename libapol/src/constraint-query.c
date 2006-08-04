/**
 * @file constraint-query.c
 *
 * Provides a way for setools to make queries about constraint and
 * validatetrans statements within a policy.  The caller obtains a
 * query object, fills in its parameters, and then runs the query; it
 * obtains a vector of results.  Searches are conjunctive -- all
 * fields of the search query must match for a datum to be added to
 * the results.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

#include "policy-query-internal.h"
#include <errno.h>
#include <string.h>

struct apol_constraint_query {
	char *class_name, *perm_name;
	unsigned int flags;
	regex_t *class_regex, *perm_regex;
};

struct apol_validatetrans_query {
	char *class_name;
	unsigned int flags;
	regex_t *regex;
};

/******************** constraint queries ********************/

int apol_get_constraint_by_query(apol_policy_t *p,
				 apol_constraint_query_t *c,
				 apol_vector_t **v)
{
	qpol_iterator_t *iter = NULL, *perm_iter = NULL;
	int retval = -1;
	*v = NULL;
	if (qpol_policy_get_constraint_iter(p->qh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_constraint_t *constraint;
		if (qpol_iterator_get_item(iter, (void **) &constraint) < 0) {
			goto cleanup;
		}
		if (c != NULL) {
			qpol_class_t *class_datum;
			char *class_name;
			int compval;
			if (qpol_constraint_get_class(p->qh, p->p, constraint, &class_datum) < 0 ||
			    qpol_class_get_name(p->qh, p->p, class_datum, &class_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, class_name, c->class_name,
					       c->flags, &(c->class_regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				free(constraint);
				continue;
			}

			if (qpol_constraint_get_perm_iter(p->qh, p->p, constraint, &perm_iter) < 0) {
				goto cleanup;
			}
			compval = apol_compare_iter(p, perm_iter, c->perm_name,
						    c->flags, &(c->perm_regex));
			qpol_iterator_destroy(&perm_iter);
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				free(constraint);
				continue;
			}
		}
		if (apol_vector_append(*v, constraint)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

apol_constraint_query_t *apol_constraint_query_create(void)
{
	return calloc(1, sizeof(apol_constraint_query_t));
}

void apol_constraint_query_destroy(apol_constraint_query_t **c)
{
	if (*c != NULL) {
		free((*c)->class_name);
		free((*c)->perm_name);
		apol_regex_destroy(&(*c)->class_regex);
		apol_regex_destroy(&(*c)->perm_regex);
		free(*c);
		*c = NULL;
	}
}

int apol_constraint_query_set_class(apol_policy_t *p, apol_constraint_query_t *c, const char *name)
{
	return apol_query_set(p, &c->class_name, &c->class_regex, name);
}

int apol_constraint_query_set_perm(apol_policy_t *p, apol_constraint_query_t *c, const char *name)
{
	return apol_query_set(p, &c->perm_name, &c->perm_regex, name);
}

int apol_constraint_query_set_regex(apol_policy_t *p, apol_constraint_query_t *c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}

/******************** validatetrans queries ********************/

int apol_get_validatetrans_by_query(apol_policy_t *p,
				    apol_validatetrans_query_t *vt,
				    apol_vector_t **v)
{
	qpol_iterator_t *iter = NULL;
	int retval = -1;
	*v = NULL;
	if (qpol_policy_get_validatetrans_iter(p->qh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_validatetrans_t *validatetrans;
		if (qpol_iterator_get_item(iter, (void **) &validatetrans) < 0) {
			goto cleanup;
		}
		if (vt != NULL) {
			qpol_class_t *class_datum;
			char *class_name;
			int compval;
			if (qpol_validatetrans_get_class(p->qh, p->p, validatetrans, &class_datum) < 0 ||
			    qpol_class_get_name(p->qh, p->p, class_datum, &class_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, class_name, vt->class_name,
					       vt->flags, &(vt->regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				free(validatetrans);
				continue;
			}
		}
		if (apol_vector_append(*v, validatetrans)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_validatetrans_query_t *apol_validatetrans_query_create(void)
{
	return calloc(1, sizeof(apol_validatetrans_query_t));
}

void apol_validatetrans_query_destroy(apol_validatetrans_query_t **vt)
{
	if (*vt != NULL) {
		free((*vt)->class_name);
		apol_regex_destroy(&(*vt)->regex);
		free(*vt);
		*vt = NULL;
	}
}

int apol_validatetrans_query_set_class(apol_policy_t *p, apol_validatetrans_query_t *vt, const char *name)
{
	return apol_query_set(p, &vt->class_name, &vt->regex, name);
}

int apol_validatetrans_query_set_regex(apol_policy_t *p, apol_validatetrans_query_t *vt, int is_regex)
{
	return apol_query_set_regex(p, &vt->flags, is_regex);
}