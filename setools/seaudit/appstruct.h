/* 
 * Author: Kevin Carr <kcarr@tresys.com
 * Date: October 15, 2003
 *
 * this file contains definitions of functions used to interface with the
 * policy from seaudit.
 * appstruct.h
 */
#ifndef LIBSEAUDIT_QUERYPOL_H
#define LIBSEAUDIT_QUERYPOL_H

#include <libapol/policy.h>
#include <glade/glade.h>
#include "auditlog.h"

typedef struct app {
	policy_t *policy;
	audit_log_t *log;
	GladeXML *xml;
} app_t;

app_t* app_struct_create(void);
void app_struct_destroy(app_t*);
const av_item_t** app_struct_querypol_types(int *seaudit_types, int num_types, int *num_results, app_t *app_struct);
const av_item_t** app_struct_querypol_objs(int *seaudit_objs, int num_objs, int *num_results, app_t *app_struct);
int app_struct_policy_load(app_t *app_struct, const char *filename);
void app_struct_policy_close(app_t *app_struct);
void app_struct_audit_log_close(app_t *app_struct);
int app_struct_audit_log_load(app_t *app_struct, const char *filename);
int app_struct_xml_load(app_t *app_struct, const char *filename);

#endif
