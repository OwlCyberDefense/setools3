/*
 * Author: Kevin Carr <kcarr@tresys.com
 * Date: October 15, 2003
 *
 * this file contains the implementation of querypol.h
 *
 * querypol.c
 */

#include <libapol/policy.h>
#include <libapol/policy-io.h>
#include "querypol.h"
#include "parse.h"

static int get_policy_type_indx(int seaudit_type_idx, app_t *app_struct)
{
	char *type;
	int policy_type_idx;

	if (seaudit_type_idx <= 0 || app_struct == NULL)
		return -1;
	if (!app_struct->log)
		return -2;
	type = audit_log_get_type(app_struct->log, seaudit_type_idx);
	policy_type_idx = get_type_idx(type, app_struct->policy);
	return policy_type_idx;
}


const av_item_t** app_struct_querypol_types(int *seaudit_types, int num_types, int *num_results, app_t *app_struct)
{
	const av_item_t **rules = NULL;
	if (seaudit_types == NULL || num_results == NULL || app_struct == NULL || num_types <= 0) {
		return NULL;
	}
	*num_results = 0;
	// TODO: finish
	return rules;
}


const av_item_t** app_struct_querypol_objs(int *seaudit_objs, int num_objs, int *num_results, app_t *app_struct);

int app_struct_policy_load(app_t *app_struct, const char *filename)
{
	policy_t **policy_ptr;
	*policy_ptr = app_struct->policy;
	if (app_struct == NULL)
		return -1;
	return open_partial_policy(filename, POLOPT_TE_RULES & POLOPT_CLASSES, policy_ptr);
}


int app_struct_audit_log_load(app_t *app_struct, const char *filename)
{
	if (app_struct == NULL)
		return -1;
	return parse_audit(filename, app_struct->log);
}
