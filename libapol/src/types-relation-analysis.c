/**
 * @file types-relation-analysis.c
 * Implementation of the two-types relationship analysis.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

struct apol_types_relation_analysis {
	char *typeA, *typeB;
	unsigned int analyses;
};

struct apol_types_relation_result {
	/** vector of qpol_type_t pointers */
	apol_vector_t *attribs;
	/** vector of qpol_role_t pointers */
	apol_vector_t *roles;
	/** vector of qpol_user_t pointers */
	apol_vector_t *users;
};

/******************** actual analysis rountines ********************/

/**
 * Find the attributes that both typeA and typeB have.  Create a
 * vector of those attributes (as represented as qpol_type_t pointers
 * relative to the provided policy) and set r->attribs with that
 * vector.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_common_attribs(apol_policy_t *p,
					      qpol_type_t *typeA,
					      qpol_type_t *typeB,
					      apol_types_relation_result_t *r)
{
	qpol_iterator_t *iA = NULL, *iB = NULL;
	apol_vector_t *vA = NULL, *vB = NULL;
	int retval = -1;

	if (qpol_type_get_attr_iter(p->qh, p->p, typeA, &iA) < 0 ||
	    qpol_type_get_attr_iter(p->qh, p->p, typeB, &iB) < 0) {
		goto cleanup;
	}
	if ((vA = apol_vector_create_from_iter(iA)) == NULL ||
	    (vB = apol_vector_create_from_iter(iB)) == NULL ||
	    (r->attribs = apol_vector_create_from_intersection(vA, vB)) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
	}
	    
	retval = 0;
 cleanup:
	qpol_iterator_destroy(&iA);
	qpol_iterator_destroy(&iB);
	apol_vector_destroy(&vA, NULL);
	apol_vector_destroy(&vB, NULL);
	return retval;
}


/******************** public functions below ********************/

int apol_types_relation_analysis_do(apol_policy_t *p,
				    apol_types_relation_analysis_t *tr,
				    apol_types_relation_result_t **r)
{
	qpol_type_t *typeA, *typeB;
	unsigned char isattrA, isattrB;
	int retval = -1;
	*r = NULL;

	if (tr->typeA == NULL || tr->typeB) {
		ERR(p, "%s", strerror(EINVAL));
		goto cleanup;
	}
	if (apol_query_get_type(p, tr->typeA, &typeA) < 0 ||
	    apol_query_get_type(p, tr->typeB, &typeB) < 0 ||
	    qpol_type_get_isattr(p->qh, p->p, typeA, &isattrA) < 0 ||
	    qpol_type_get_isattr(p->qh, p->p, typeB, &isattrB) < 0) {
		goto cleanup;
	}
	if (isattrA) {
		ERR(p, "Symbol %s is an attribute.", tr->typeA);
		goto cleanup;
	}
	if (isattrB) {
		ERR(p, "Symbol %s is an attribute.", tr->typeB);
		goto cleanup;
	}
	if ((*r = calloc(1, sizeof(**r))) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if ((tr->analyses & APOL_TYPES_RELATION_COMMON_ATTRIBS) &&
	    apol_types_relation_common_attribs(p, typeA, typeB, *r) < 0) {
		goto cleanup;
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_types_relation_result_destroy(r);
	}
	return retval;
}

apol_types_relation_analysis_t *apol_types_relation_analysis_create(void)
{
	return calloc(1, sizeof(apol_types_relation_analysis_t));
}

void apol_types_relation_analysis_destroy(apol_types_relation_analysis_t **tr)
{
	if (*tr != NULL) {
		free((*tr)->typeA);
		free((*tr)->typeB);
		free(*tr);
		*tr = NULL;
	}
}

int apol_types_relation_analysis_set_first_type(apol_policy_t *p,
						apol_types_relation_analysis_t *tr,
						const char *name)
{
	if (name == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		return -1;
	}
	return apol_query_set(p, &tr->typeA, NULL, name);
}

int apol_types_relation_analysis_set_other_type(apol_policy_t *p,
						apol_types_relation_analysis_t *tr,
						const char *name)
{
	if (name == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		return -1;
	}
	return apol_query_set(p, &tr->typeB, NULL, name);
}

int apol_types_relation_analysis_set_analyses(apol_policy_t *p __attribute__((unused)),
					      apol_types_relation_analysis_t *tr,
					      unsigned int analyses)
{
	if (analyses != 0) {
		tr->analyses = analyses;
	}
	else {
		tr->analyses = ~0U;
	}
	return 0;
}

/*************** functions to access type relation results ***************/

void apol_types_relation_result_destroy(apol_types_relation_result_t **result)
{
	if (*result != NULL) {
		apol_vector_destroy(&(*result)->attribs, NULL);
		apol_vector_destroy(&(*result)->roles, NULL);
		apol_vector_destroy(&(*result)->users, NULL);
		free(*result);
		*result = NULL;
	}
}

apol_vector_t *apol_types_relation_result_get_attributes(apol_types_relation_result_t *result)
{
	return result->attribs;
}

apol_vector_t *apol_types_relation_result_get_roles(apol_types_relation_result_t *result)
{
	return result->roles;
}

apol_vector_t *apol_types_relation_result_get_users(apol_types_relation_result_t *result)
{
	return result->users;
}
