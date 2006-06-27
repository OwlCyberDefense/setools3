/**
 * @file relabel-analysis.c
 * Implementation of the direct relabelling analysis.
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

#include "policy-query.h"

#include <errno.h>
#include <string.h>

/* defines for mode */
#define APOL_RELABEL_MODE_OBJ	0x01
#define APOL_RELABEL_MODE_SUBJ	0x02

struct apol_relabel_analysis {
	unsigned int mode, direction;
	char *type, *result;
	regex_t *result_regex;
};

struct apol_relabel_result {
	/** vector of qpol_rule_t */
	apol_vector_t *to, *from, *both;
};

#define PERM_RELABELTO "relabelto"
#define PERM_RELABELFROM "relabelfrom"

/******************** actual analysis rountines ********************/

/**
 * Given an avrule, determine which relabel direction it has (to,
 * from, or both).
 *
 * @param p Policy containing avrule.
 * @param avrule Rule to examine.
 *
 * @return One of APOL_RELABEL_DIR_TO, APOL_RELABEL_DIR_FROM,
 * APOL_RELABEL_DIR_BOTH, or < 0 it direction could not be determined.
 */
static int relabel_analysis_get_direction(apol_policy_t *p,
                                          qpol_avrule_t *avrule)
{
	qpol_iterator_t *iter;
	int to = 0, from = 0, retval = -1;

	if (qpol_avrule_get_perm_iter(p->qh, p->p, avrule, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		char *perm;
		if (qpol_iterator_get_item(iter, (void **) &perm) < 0) {
			goto cleanup;
		}
		if (strcmp(perm, PERM_RELABELTO) == 0) {
			to = 1;
		}
		else if (strcmp(perm, PERM_RELABELFROM) == 0) {
			from = 1;
		}
	}
	if (to && from) {
		retval = APOL_RELABEL_DIR_BOTH;
	}
	else if (to) {
		retval = APOL_RELABEL_DIR_TO;
	}
	else if (from) {
		retval = APOL_RELABEL_DIR_FROM;
	}
 cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}


/**
 * Given an avrule, append it to the result object, onto the
 * appropriate rules vector.
 *
 * @param p Policy containing avrule.
 * @param avrule AV rule to add.
 * @param result Pointer to the result object being built.
 *
 * @return 0 on success, < 0 on error.
 */
static int append_avrule_to_result(apol_policy_t *p,
				   qpol_avrule_t *avrule,
				   apol_relabel_result_t *result)
{
	qpol_type_t *type;
	int retval = -1;
	if (qpol_avrule_get_source_type(p->qh, p->p, avrule, &type) < 0) {
		goto cleanup;
	}
	switch (relabel_analysis_get_direction(p, avrule)) {
	case APOL_RELABEL_DIR_TO:
		if ((apol_vector_append(result->to, avrule)) < 0) {
			goto cleanup;
		}
		break;
	case APOL_RELABEL_DIR_FROM:
		if ((apol_vector_append(result->from, avrule)) < 0) {
			goto cleanup;
		}
		break;
	case APOL_RELABEL_DIR_BOTH:
		if ((apol_vector_append(result->both, avrule)) < 0) {
			goto cleanup;
		}
		break;
	default:
		goto cleanup;
	}

	retval = 0;
 cleanup:
	return retval;
}

static int relabel_analysis_object(apol_policy_t *p,
				   apol_relabel_analysis_t *r,
				   apol_relabel_result_t *result,
				   unsigned int direction)
{
        return 0;
}


/**
 * Get a list of all allow rules, whose source type matches r->type
 * and whose permission list has either "relabelto" or "relabelfrom".
 * Add instances of those to the result vector.
 *
 * @param p Policy to which look up rules.
 * @param r Structure containing parameters for subject relabel analysis.
 * @param result Target result to which append discovered rules.
 *
 * @return 0 on success, < 0 on error.
 */
static int relabel_analysis_subject(apol_policy_t *p,
				    apol_relabel_analysis_t *r,
				    apol_relabel_result_t *result)
{
	apol_avrule_query_t *a = NULL;
	apol_vector_t *avrules_v = NULL;
	qpol_avrule_t *avrule;
	size_t i;
	int retval = -1;

	if ((a = apol_avrule_query_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	if (apol_avrule_query_set_rules(p, a, QPOL_RULE_ALLOW) < 0 ||
	    apol_avrule_query_set_source(p, a, r->type, 0) < 0 ||
	    apol_avrule_query_append_perm(p, a, PERM_RELABELTO) < 0 ||
	    apol_avrule_query_append_perm(p, a, PERM_RELABELFROM) < 0) {
		goto cleanup;
	}

	if (apol_get_avrule_by_query(p, a, &avrules_v) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(avrules_v); i++) {
		avrule = (qpol_avrule_t *) apol_vector_get_element(avrules_v, i);
		if (append_avrule_to_result(p, avrule, result) < 0) {
			goto cleanup;
		}
	}

        retval = 0;
 cleanup:
        apol_avrule_query_destroy(&a);
        apol_vector_destroy(&avrules_v, NULL);
        return retval;
}

/******************** public functions below ********************/

int apol_relabel_analysis_do(apol_policy_t *p,
			     apol_relabel_analysis_t *r,
			     apol_relabel_result_t **result)
{
	qpol_type_t *start_type;
	int retval = -1;
	*result = NULL;

	if (r->mode == 0 || r->type == NULL) {
		ERR(p, strerror(EINVAL));
		goto cleanup;
	}
	if (apol_query_get_type(p, r->type, &start_type) < 0) {
		goto cleanup;
	}

	if ((*result = calloc(1, sizeof(**result))) == NULL ||
	    ((*result)->to = apol_vector_create()) == NULL ||
	    ((*result)->from = apol_vector_create()) == NULL ||
	    ((*result)->both = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}

	if (r->mode == APOL_RELABEL_MODE_OBJ) {
		if ((r->direction & APOL_RELABEL_DIR_TO) &&
		    relabel_analysis_object(p, r, *result, APOL_RELABEL_DIR_TO) < 0) {
			goto cleanup;
		}
		if ((r->direction & APOL_RELABEL_DIR_FROM) &&
		    relabel_analysis_object(p, r, *result, APOL_RELABEL_DIR_FROM) < 0) {
			goto cleanup;
		}
	}
	else {
		if (relabel_analysis_subject(p, r, *result) < 0) {
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_relabel_result_destroy(result);
	}
	return retval;
}

apol_relabel_analysis_t *apol_relabel_analysis_create(void)
{
	return calloc(1, sizeof(apol_relabel_analysis_t));
}

void apol_relabel_analysis_destroy(apol_relabel_analysis_t **r)
{
	if (*r != NULL) {
		free((*r)->type);
		apol_regex_destroy(&(*r)->result_regex);
		free(*r);
		*r = NULL;
	}
}

int apol_relabel_analysis_set_dir(apol_policy_t *p,
				  apol_relabel_analysis_t *r,
				  unsigned int dir)
{
        switch (dir) {
        case APOL_RELABEL_DIR_BOTH:
        case APOL_RELABEL_DIR_TO:
        case APOL_RELABEL_DIR_FROM: {
                r->mode = APOL_RELABEL_MODE_OBJ;
                r->direction = dir;
                break;
        }
        case APOL_RELABEL_DIR_SUBJECT: {
                r->mode = APOL_RELABEL_MODE_SUBJ;
                r->direction = APOL_RELABEL_DIR_BOTH;
                break;
        }
        default: {
                ERR(p, strerror(EINVAL));
                return -1;
        }
        }
        return 0;
}

int apol_relabel_analysis_set_type(apol_policy_t *p,
				   apol_relabel_analysis_t *r,
				   const char *name)
{
	if (name == NULL) {
		ERR(p, strerror(EINVAL));
		return -1;
	}
	return apol_query_set(p, &r->type, NULL, name);
}

int apol_relabel_analysis_set_result_regexp(apol_policy_t *p,
					    apol_relabel_analysis_t *r,
					    const char *result)
{
	return apol_query_set(p, &r->result, &r->result_regex, result);
}

/******************** functions to access relabel results ********************/

void apol_relabel_result_destroy(apol_relabel_result_t **result)
{
	if (result != NULL && *result != NULL) {
		apol_vector_destroy(&(*result)->to, NULL);
		apol_vector_destroy(&(*result)->from, NULL);
		apol_vector_destroy(&(*result)->both, NULL);
		free(*result);
		*result = NULL;
	}
}

apol_vector_t *apol_relabel_result_get_to(apol_relabel_result_t *r)
{
	return r->to;
}

apol_vector_t *apol_relabel_result_get_from(apol_relabel_result_t *r)
{
	return r->from;
}

apol_vector_t *apol_relabel_result_get_both(apol_relabel_result_t *r)
{
	return r->both;
}


#if 0


/* query mode functions */
static int ap_relabel_object_mode_query(int start_type, unsigned char requested_direction,
	ap_relabel_result_t *res, int *excluded_types, int num_excluded_types,
	int *class_filter, int class_filter_sz, policy_t *policy)
{
	unsigned char direction_flag = AP_RELABEL_DIR_NONE;
	ap_relabel_possible_start_t *starting_points = NULL;
	avh_idx_t *index = NULL;
	int i, j, k, relabelto_index = -1, relabelfrom_index = -1;
	int num_starting_points = 0;
	avh_rule_t *current_rule = NULL;

	relabelto_index = get_perm_idx(AP_RELABEL_RELABELTO, policy);
	relabelfrom_index = get_perm_idx(AP_RELABEL_RELABELFROM, policy);

	index = avh_tgt_type_idx_find(&(policy->avh), start_type);
	if (!index)
		return 0;
	for (i = 0; i < index->num_nodes; i++) {
		direction_flag = AP_RELABEL_DIR_NONE;
		if(index->nodes[i]->key.rule_type != RULE_TE_ALLOW)
			continue;
		if (class_filter && class_filter_sz > 0 &&
			find_int_in_array(index->nodes[i]->key.cls, class_filter, class_filter_sz) == -1)
			continue;
		if (excluded_types && num_excluded_types > 0 &&
			find_int_in_array(index->nodes[i]->key.src, excluded_types, num_excluded_types) != -1)
			continue;
		for (j = 0; j < index->nodes[i]->num_data; j++) {
			if(index->nodes[i]->data[j] == relabelto_index)
				direction_flag |= AP_RELABEL_DIR_TO;
			if(index->nodes[i]->data[j] == relabelfrom_index)
				direction_flag |= AP_RELABEL_DIR_FROM;
		}
		/* rule does not relabel */
		if (direction_flag == AP_RELABEL_DIR_NONE)
			continue;
		/* rule for starting point must contain opposite direction from requested */
		if(direction_flag != AP_RELABEL_DIR_BOTH && direction_flag == requested_direction )
			continue;
		starting_points = (ap_relabel_possible_start_t*)realloc(starting_points, (num_starting_points + 1) * sizeof(ap_relabel_possible_start_t));
		if (!starting_points)
			return -1;
		if (ap_relabel_possible_start_init(&(starting_points[num_starting_points])) == -1)
			return -1;
		starting_points[num_starting_points].source_type = index->nodes[i]->key.src;
		starting_points[num_starting_points].object_class = index->nodes[i]->key.cls;
		for (current_rule = index->nodes[i]->rules; current_rule != NULL; current_rule = current_rule->next) {
			direction_flag = ap_relabel_determine_rule_direction(current_rule->rule, policy, relabelto_index, relabelfrom_index);
			if (direction_flag == AP_RELABEL_DIR_NONE)
				continue;
			/* rule must either be both or opposite requested direction */
			if(direction_flag == AP_RELABEL_DIR_BOTH || direction_flag ^ requested_direction) {
				if (ap_relabel_add_rule_to_possible_start(current_rule->rule, direction_flag, &(starting_points[num_starting_points])) == -1)
					return -1;
			}
		}
		num_starting_points++;
	}
	for (i = 0; i < num_starting_points; i++) {
		index = avh_src_type_idx_find(&(policy->avh), starting_points[i].source_type);
		if (!index)
			return -1;
		for (j = 0; j < index->num_nodes; j++) {
			if(index->nodes[j]->key.rule_type != RULE_TE_ALLOW)
				continue;
			if (index->nodes[j]->key.cls != starting_points[i].object_class)
				continue;
			direction_flag = AP_RELABEL_DIR_NONE;
			for (k = 0; k < index->nodes[j]->num_data; k++) {
				if (index->nodes[j]->data[k] == relabelto_index)
					direction_flag |= AP_RELABEL_DIR_TO;
				if (index->nodes[j]->data[k] == relabelfrom_index)
					direction_flag |= AP_RELABEL_DIR_FROM;
			}
			if (direction_flag == AP_RELABEL_DIR_NONE || !(direction_flag & requested_direction))
				continue;
			for (current_rule = index->nodes[j]->rules; current_rule != NULL; current_rule = current_rule->next) {
				direction_flag = ap_relabel_determine_rule_direction(current_rule->rule, policy, relabelto_index, relabelfrom_index);
				if ( !(direction_flag & requested_direction) )
					continue;
				if (ap_relabel_add_entry_to_result(index->nodes[j]->key.tgt, index->nodes[j]->key.cls, index->nodes[j]->key.src, direction_flag, current_rule->rule, res, &(starting_points[i])) == -1)
					return -1;
			}
		}
	}

	for (i =0; i < num_starting_points; i++) {
		ap_relabel_possible_start_destroy(&(starting_points[i]));
	}
	free(starting_points);

	return 0;
};

static int ap_relabel_subject_mode_query(int start_type, ap_relabel_result_t *res,
	int *class_filter, int class_filter_sz, policy_t *policy)
{
	avh_idx_t *index = NULL;
	int i, j, relabelto_index = -1, relabelfrom_index = -1;
	unsigned char direction_flag = AP_RELABEL_DIR_NONE;
	avh_rule_t *current_rule = NULL;

	relabelto_index = get_perm_idx(AP_RELABEL_RELABELTO, policy);
	relabelfrom_index = get_perm_idx(AP_RELABEL_RELABELFROM, policy);

	index = avh_src_type_idx_find(&(policy->avh), start_type);
	if(!index)
		return 0;
	for (i = 0; i < index->num_nodes; i++) {
		if (index->nodes[i]->key.rule_type != RULE_TE_ALLOW)
			continue;
		if (class_filter && class_filter_sz > 0 &&
			find_int_in_array(index->nodes[i]->key.cls, class_filter, class_filter_sz) == -1)
			continue;
		for (j = 0; j < index->nodes[i]->num_data; j++) {
			if(index->nodes[i]->data[j] == relabelto_index)
				direction_flag |= AP_RELABEL_DIR_TO;
			if(index->nodes[i]->data[j] == relabelfrom_index)
				direction_flag |= AP_RELABEL_DIR_FROM;
		}
		if (direction_flag == AP_RELABEL_DIR_NONE)
			continue;
		for (current_rule = index->nodes[i]->rules; current_rule != NULL; current_rule = current_rule->next) {
			direction_flag = ap_relabel_determine_rule_direction(current_rule->rule, policy, relabelto_index, relabelfrom_index);
			if (direction_flag != AP_RELABEL_DIR_NONE)
				if(ap_relabel_add_entry_to_result(index->nodes[i]->key.tgt, index->nodes[i]->key.cls, index->nodes[i]->key.src, direction_flag, current_rule->rule, res, NULL) == -1)
					return -1;
		}
	}

	return 0;
};

#endif
