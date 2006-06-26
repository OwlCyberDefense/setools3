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

/* defines for mode */
#define APOL_RELABEL_MODE_OBJ	0x01
#define APOL_RELABEL_MODE_SUBJ	0x02

struct apol_relabel_analysis {
        int mode;
        char *type;
        int flags;
};

#if 0
#include "policy.h"
#include "relabel_analysis.h"
#include "semantic/avhash.h"
#include "semantic/avsemantics.h"

#define AP_RELABEL_MODE_NONE	0x00
#define AP_RELABEL_NOT_HERE	-2

/* relabeling permission names */
#define AP_RELABEL_RELABELTO	"relabelto"
#define AP_RELABEL_RELABELFROM	"relabelfrom"

typedef struct ap_relabel_possible_start {
	int			source_type;
	int			object_class;
	ap_relabel_rule_t	*rules;
	int		num_rules;
} ap_relabel_possible_start_t;

/* initialization functions */
static int ap_relabel_rule_init(ap_relabel_rule_t *rule)
{
	if (!rule)
		return -1;
	rule->rule_index = -1;
	rule->direction = AP_RELABEL_DIR_NONE;
	return 0;
};

static int ap_relabel_subject_init(ap_relabel_subject_t *subj)
{
	if (!subj)
		return -1;
	subj->source_type = -1;
	subj->rules = NULL;
	subj->num_rules = 0;
	subj->direction = AP_RELABEL_DIR_NONE;
	return 0;
};

static int ap_relabel_object_init(ap_relabel_object_t *obj)
{
	if (!obj)
		return -1;
	obj->object_class = -1;
	obj->subjects = NULL;
	obj->num_subjects = 0;
	obj->direction = AP_RELABEL_DIR_NONE;
	return 0;
};

static int ap_relabel_target_init(ap_relabel_target_t *tgt)
{
	if (!tgt)
		return -1;
	tgt->target_type = -1;
	tgt->objects = NULL;
	tgt->num_objects = 0;
	tgt->direction = AP_RELABEL_DIR_NONE;
	return 0;
};

static int ap_relabel_result_init(ap_relabel_result_t *res)
{
	if (!res)
		return -1;
	res->start_type = -1;
	res->mode = AP_RELABEL_MODE_NONE;
	res->requested_direction = AP_RELABEL_DIR_NONE;
	res->targets = NULL;
	res->num_targets = 0;
	return 0;
};

static int ap_relabel_possible_start_init(ap_relabel_possible_start_t *pos)
{
	if (!pos)
		return -1;
	pos->source_type = -1;
	pos->object_class = -1;
	pos->rules = NULL;
	pos->num_rules = 0;
	return 0;
};

/* clean-up functions */
static void ap_relabel_subject_destroy(ap_relabel_subject_t *subj)
{
	if (!subj)
		return;
	if (subj->rules)
		free(subj->rules);
	ap_relabel_subject_init(subj);
};

static void ap_relabel_object_destroy(ap_relabel_object_t *obj)
{
	int i;
	if (!obj)
		return;
	if (obj->subjects) {
		for (i = 0; i < obj->num_subjects; i++)
			ap_relabel_subject_destroy(&(obj->subjects[i]));
		free(obj->subjects);
	}
	ap_relabel_object_init(obj);
};

static void ap_relabel_target_destroy(ap_relabel_target_t *tgt)
{
	int i;
	if (!tgt)
		return;
	if (tgt->objects) {
		for (i = 0; i < tgt->num_objects; i++)
			ap_relabel_object_destroy(&(tgt->objects[i]));
		free(tgt->objects);
	}
	ap_relabel_target_init(tgt);
};

/* should not be static */
void ap_relabel_result_destroy(ap_relabel_result_t *res)
{
	int i;
	if (!res)
		return;
	if (res->targets) {
		for (i = 0; i < res->num_targets; i++)
			ap_relabel_target_destroy(&(res->targets[i]));
		free(res->targets);
	}
	ap_relabel_result_init(res);
}

static void ap_relabel_possible_start_destroy(ap_relabel_possible_start_t *pos)
{
	if (!pos)
		return;
	free(pos->rules);
	ap_relabel_possible_start_init(pos);
};

/* find functions - return -1 on error, AP_RELABEL_NOT_HERE on not found, index otherwise */
static int ap_relabel_find_target_in_results(int target_type, ap_relabel_result_t *res)
{
	int i;
	if (!res)
		return -1;
	for (i = 0; i < res->num_targets; i++)
		if (res->targets[i].target_type == target_type)
			return i;
	return AP_RELABEL_NOT_HERE;
};

static int ap_relabel_find_object_in_target(int object_class, ap_relabel_target_t *tgt)
{
	int i;
	if (!tgt)
		return -1;
	for (i = 0; i < tgt->num_objects; i++)
		if (tgt->objects[i].object_class == object_class)
			return i;
	return AP_RELABEL_NOT_HERE;
};

static int ap_relabel_find_subject_in_object(int source_type, ap_relabel_object_t *obj)
{
	int i;
	if (!obj)
		return -1;
	for (i = 0; i < obj->num_subjects; i++)
		if (obj->subjects[i].source_type == source_type)
			return i;
	return AP_RELABEL_NOT_HERE;
};

static int ap_relabel_find_rule_in_subject(int rule_index, ap_relabel_subject_t *subj)
{
	int i;
	if (!subj)
		return -1;
	for (i = 0; i < subj->num_rules; i++)
		if (subj->rules[i].rule_index == rule_index)
			return i;
	return AP_RELABEL_NOT_HERE;
};

/* add functions:
 * return -1 on error
 * otherwise return index of item added
 * except add_entry and add_start which return 0 on success
 * NOTE: add_entry is the only function that checks for duplicates
 */
static int ap_relabel_add_rule_to_subject(int rule, unsigned char direction, ap_relabel_subject_t * subj)
{
	int where  = -1;

	if(!subj)
		return -1;

	subj->rules = (ap_relabel_rule_t*)realloc(subj->rules, (subj->num_rules + 1) * sizeof(ap_relabel_rule_t));
	if (!subj->rules)
		return -1;
	where = subj->num_rules;
	(subj->num_rules)++;
	if (ap_relabel_rule_init(&(subj->rules[where])) == -1)
		return -1;
	subj->rules[where].rule_index = rule;
	subj->rules[where].direction = direction;

	return where;
};

static int ap_relabel_add_subject_to_object(int subj, ap_relabel_object_t *obj)
{
	int where = -1;

	if(!obj)
		return -1;

	obj->subjects = (ap_relabel_subject_t*)realloc(obj->subjects, (obj->num_subjects + 1) * sizeof(ap_relabel_subject_t));
	if(!obj->subjects)
		return -1;
	where = obj->num_subjects;
	(obj->num_subjects)++;
	if (ap_relabel_subject_init(&(obj->subjects[where])) == -1)
		return -1;
	obj->subjects[where].source_type = subj;

	return where;
};

static int ap_relabel_add_object_to_target(int obj, ap_relabel_target_t *tgt)
{
	int where = -1;

	if (!tgt)
		return -1;

	tgt->objects = (ap_relabel_object_t*)realloc(tgt->objects, (tgt->num_objects + 1) * sizeof(ap_relabel_object_t));
	if (!tgt->objects)
		return -1;
	where = tgt->num_objects;
	(tgt->num_objects)++;
	if (ap_relabel_object_init(&(tgt->objects[where])) == -1)
		return -1;
	tgt->objects[where].object_class = obj;

	return where;
};

static int ap_relabel_add_target_to_result(int tgt, ap_relabel_result_t *res)
{
	int where = -1;

	if (!res)
		return -1;

	res->targets = (ap_relabel_target_t*)realloc(res->targets, (res->num_targets + 1) * sizeof(ap_relabel_target_t));
	if (!res->targets)
		return -1;
	where = res->num_targets;
	(res->num_targets)++;
	if (ap_relabel_target_init(&(res->targets[where])) == -1)
		return -1;
	res->targets[where].target_type = tgt;

	return where;
};

static int ap_relabel_add_rule_to_possible_start(int rule, unsigned char direction, ap_relabel_possible_start_t *pos)
{
	int where = -1;

	if (!pos)
		return -1;
	pos->rules = (ap_relabel_rule_t*)realloc(pos->rules, (pos->num_rules + 1) * sizeof(ap_relabel_rule_t));
	if (!pos->rules)
		return -1;
	where = pos->num_rules;
	(pos->num_rules)++;
	if (ap_relabel_rule_init(&(pos->rules[where])) == -1)
		return -1;
	pos->rules[where].rule_index = rule;
	pos->rules[where].direction = direction;

	return where;
};

static int ap_relabel_add_start_to_subject(ap_relabel_possible_start_t *pos, ap_relabel_subject_t *subj)
{
	int i, retv, where = -1;

	for (i = 0; i < pos->num_rules; i++) {
		if ((where = ap_relabel_find_rule_in_subject(pos->rules[i].rule_index, subj)) == AP_RELABEL_NOT_HERE) {
			retv = ap_relabel_add_rule_to_subject(pos->rules[i].rule_index, (pos->rules[i].direction | AP_RELABEL_DIR_START), subj);
			if (retv == -1)
				return -1;
		} else if (where == -1) {
			return -1;
		} else {
			subj->rules[where].direction |= AP_RELABEL_DIR_START;
		}
	}

	return 0;
};

static int ap_relabel_add_entry_to_result(int target_type, int object_class, int subject, unsigned char direction, int rule_index, ap_relabel_result_t *res, ap_relabel_possible_start_t *pos)
{
	int target_index = -1, object_index = -1, source_index = -1, rule_number = -1, retv;

	target_index = ap_relabel_find_target_in_results(target_type, res);
	if (target_index == AP_RELABEL_NOT_HERE)
		target_index = ap_relabel_add_target_to_result(target_type, res);
	if (target_index == -1)
		return -1;

	object_index = ap_relabel_find_object_in_target(object_class, &(res->targets[target_index]));
	if (object_index == AP_RELABEL_NOT_HERE)
		object_index = ap_relabel_add_object_to_target(object_class, &(res->targets[target_index]));
	if (object_index == -1)
		return -1;

	source_index = ap_relabel_find_subject_in_object(subject, &(res->targets[target_index].objects[object_index]));
	if (source_index == AP_RELABEL_NOT_HERE)
		source_index = ap_relabel_add_subject_to_object(subject, &(res->targets[target_index].objects[object_index]));
	if (source_index == -1)
		return -1;

	rule_number = ap_relabel_find_rule_in_subject(rule_index, &(res->targets[target_index].objects[object_index].subjects[source_index]));
	if (rule_number == AP_RELABEL_NOT_HERE)
		rule_number = ap_relabel_add_rule_to_subject(rule_index, direction, &(res->targets[target_index].objects[object_index].subjects[source_index]));
	if (rule_number == -1)
		return -1;

	if (res->mode == AP_RELABEL_MODE_OBJ) {
		retv = ap_relabel_add_start_to_subject(pos, &(res->targets[target_index].objects[object_index].subjects[source_index]));
		if (retv == -1)
			return -1;
	}

	/* set direction for parents of rule */
	res->targets[target_index].objects[object_index].subjects[source_index].direction |= res->targets[target_index].objects[object_index].subjects[source_index].rules[rule_number].direction;
	res->targets[target_index].objects[object_index].direction |= res->targets[target_index].objects[object_index].subjects[source_index].direction;
	res->targets[target_index].direction |= res->targets[target_index].objects[object_index].direction;

	return 0;
};

static unsigned char ap_relabel_determine_rule_direction(int rule_index, policy_t *policy, int relabelto_index, int relabelfrom_index)
{
	unsigned char direction = AP_RELABEL_DIR_NONE;

	if (relabelto_index < 0 || relabelfrom_index < 0)
		return direction;

	if (policy->av_access[rule_index].flags & AVFLAG_PERM_STAR)
		return AP_RELABEL_DIR_BOTH;

	if (does_av_rule_use_perms(rule_index, 1, &relabelto_index, 1, policy))
		direction |= AP_RELABEL_DIR_TO;
	if (does_av_rule_use_perms(rule_index, 1, &relabelfrom_index, 1, policy))
		direction |= AP_RELABEL_DIR_FROM;

	/* does_av_rule_use_perms ignores ~ if found reverse direction */
	if(policy->av_access[rule_index].flags & AVFLAG_PERM_TILDA) {
		direction ^= AP_RELABEL_DIR_BOTH;
		direction &= AP_RELABEL_DIR_BOTH;
	}

	return direction;
};

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

/* main query function */
int ap_relabel_query(int start_type, unsigned char mode, unsigned char direction,
	int *excluded_types, int num_excluded_types, int *class_filter, int class_filter_sz,
	ap_relabel_result_t *res, policy_t *policy)
{
	if (!policy || !res)
		return -1;
	if (mode != AP_RELABEL_MODE_OBJ && mode != AP_RELABEL_MODE_SUBJ)
		return -1;
	if (!is_valid_type(policy, start_type, 0))
		return -1;


	ap_relabel_result_init(res);
	res->start_type = start_type;
	res->mode = mode;

	if ( !avh_hash_table_present((policy->avh)) ){
		avh_build_hashtab(policy);
	}

	if (mode == AP_RELABEL_MODE_OBJ) {
		if (!(direction & AP_RELABEL_DIR_BOTH) )
			return -1;
		res->requested_direction = direction;
		if (direction == AP_RELABEL_DIR_BOTH) {
			if (ap_relabel_object_mode_query(start_type, AP_RELABEL_DIR_TO, res,
				excluded_types, num_excluded_types, class_filter, class_filter_sz, policy))
				return -1;
			return ap_relabel_object_mode_query(start_type, AP_RELABEL_DIR_FROM, res,
				excluded_types, num_excluded_types, class_filter, class_filter_sz, policy);
		} else {
			return ap_relabel_object_mode_query(start_type, direction, res,
				excluded_types, num_excluded_types, class_filter, class_filter_sz, policy);
		}
	} else if (mode == AP_RELABEL_MODE_SUBJ) {
		res->requested_direction = AP_RELABEL_DIR_BOTH;
		return ap_relabel_subject_mode_query(start_type, res, class_filter, class_filter_sz, policy);
	} else {
		return -1;
	}
}
#endif
