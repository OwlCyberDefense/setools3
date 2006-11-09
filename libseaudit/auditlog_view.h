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
#include "multifilter.h"

#ifndef LIBSEAUDIT_AUDITLOG_VIEW_H
#define LIBSEAUDIT_AUDITLOG_VIEW_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct filter_info
{
	int orig_indx;
	bool_t filtered;
} filter_info_t;

typedef struct audit_log_view
{
	audit_log_t *my_log;	       /* reference to the log */
	int *fltr_msgs;		       /* filtered and sorted messages */
	int num_fltr_msgs;	       /* num of filtered and sorted messages */
	int fltr_msgs_sz;	       /* size of filtered messages array */
	struct sort_action_node *sort_actions;	/* sort functions */
	struct sort_action_node *last_sort_action;
	seaudit_multifilter_t *multifilter;
} audit_log_view_t;

audit_log_view_t *audit_log_view_create(void);
void audit_log_view_destroy(audit_log_view_t * view);
void audit_log_view_set_log(audit_log_view_t * view, audit_log_t * log);
void audit_log_view_purge_fltr_msgs(audit_log_view_t * view);
int audit_log_view_do_filter(audit_log_view_t * log, int **deleted, int *num_deleted);
void audit_log_view_set_multifilter(audit_log_view_t * view, seaudit_multifilter_t * multifilter);

#ifdef	__cplusplus
}
#endif

#endif
