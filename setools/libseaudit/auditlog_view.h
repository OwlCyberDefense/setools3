/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: January 14, 2004
 * 
 * This file contains the data structure definitions for storing
 * audit log views.
 *
 * auditlog_view.h
 */

#include "auditlog.h"
#include "sort.h"
#include "filters.h"

#ifndef LIBSEAUDIT_AUDITLOG_VIEW_H
#define LIBSEAUDIT_AUDITLOG_VIEW_H

typedef struct filter_info {
	int orig_indx;
	bool_t filtered;
} filter_info_t;

typedef struct audit_log_view {
	audit_log_t *my_log;
	struct filter *filters; /* filters */
	int *fltr_msgs;         /* filtered and sorted messages */
	bool_t fltr_out;
	bool_t fltr_and;
	int fltr_msgs_types; /* the message types stored in the fltr_msgs array */
	int num_fltr_msgs;   /* num of filtered and sorted messages */
	int fltr_msgs_sz;    /* size of filtered messages array */
	struct sort_action_node *sort_actions; /* sort functions */
	struct sort_action_node *last_sort_action;
} audit_log_view_t;

audit_log_view_t* audit_log_view_create(void);
void audit_log_view_destroy(audit_log_view_t* view);

void audit_log_view_set_log(audit_log_view_t *view, audit_log_t *log);
int audit_log_view_add_filter(audit_log_view_t *log, struct filter *filter);
void audit_log_view_purge_filters(audit_log_view_t *log);
void audit_log_view_purge_fltr_msgs(audit_log_view_t *view);
int audit_log_view_do_filter(audit_log_view_t *log, int **deleted, int *num_deleted);
#endif
