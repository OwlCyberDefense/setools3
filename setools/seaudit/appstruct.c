/*
 * Author: Kevin Carr <kcarr@tresys.com
 * Date: October 15, 2003
 *
 * this file contains the implementation of appstruct.h
 *
 * appstruct.c
 */

#include <libapol/policy.h>
#include <libapol/policy-io.h>
#include "appstruct.h"
#include "parse.h"
#include <glade/glade.h>

app_t* app_struct_create()
{
	app_t *ptr = (app_t*)malloc(sizeof(app_t));
	if (ptr == NULL)
		return NULL;
	ptr->policy = NULL;
	ptr->xml = NULL;
	ptr->log = audit_log_create();
	if (!ptr->log)
		return NULL;
	return ptr;
}

void app_struct_destroy(app_t *app_struct)
{
	if (!app_struct)
		return;
	audit_log_destroy(app_struct->log);
	free_policy(&app_struct->policy);
	// TODO xml destroy ??

	free(app_struct);
	return;
}

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
	int pol_type;
	if (seaudit_types == NULL || num_results == NULL || app_struct == NULL || num_types <= 0) {
		return NULL;
	}
	pol_type = get_policy_type_indx(seaudit_types[0], app_struct);
	*num_results = 0;
	// TODO: finish
	return rules;
}


const av_item_t** app_struct_querypol_objs(int *seaudit_objs, int num_objs, int *num_results, app_t *app_struct)
{
	return NULL;
}

int app_struct_policy_load(app_t *app_struct, const char *filename)
{
	if (app_struct == NULL)
		return -1;
	return open_partial_policy(filename, POLOPT_TE_RULES & POLOPT_CLASSES, &app_struct->policy);
}

void app_struct_policy_close(app_t *app_struct)
{
	close_policy(app_struct->policy);
	app_struct->policy = NULL;
	return;
}

int app_struct_audit_log_load(app_t *app_struct, const char *filename)
{
	if (app_struct == NULL)
		return -1;
	return parse_audit(filename, app_struct->log);
}

void app_struct_audit_log_close(app_t *app_struct)
{
  //	audit_log_destroy(app_struct->log);
  //	app_struct->log = audit_log_create();
	return;
}

int app_struct_xml_load(app_t *app_struct, const char *filename)
{
	if (app_struct == NULL)
		return -1;
	app_struct->xml = glade_xml_new(filename, NULL, NULL);
	if (!app_struct->xml)
		return -1;
	return 0;
}
