/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: January 14, 2004
 * 
 * This file contains the data structure definitions for storing
 * audit log views.
 *
 * auditlog_view.c
 */

#include "auditlog_view.h"
#include <stdlib.h>
#include <string.h>

static void sort_kept_messages(int *kept, int num_kept, filter_info_t *info);

/* create an audit_log_view */
audit_log_view_t* audit_log_view_create(void)
{
	audit_log_view_t *view;

	view = (audit_log_view_t*) malloc(sizeof(audit_log_view_t));
	if (!view) {
		printf("out of memory\n");
		return NULL;
	}
	memset(view, 0, sizeof(audit_log_view_t));
	return view;
}

void audit_log_view_destroy(audit_log_view_t* view)
{
	sort_action_list_destroy(view->sort_actions);
	if (view->fltr_msgs)
		free(view->fltr_msgs);
	free(view);
	view = NULL;
	return;
}

void audit_log_view_set_log(audit_log_view_t *view, audit_log_t *log)
{
	int num_deleted, *deleted = NULL;

	audit_log_view_purge_fltr_msgs(view);
	view->my_log = log;

	if (log != NULL) {
		audit_log_view_do_filter(view, &deleted, &num_deleted);
		if(deleted)
			free(deleted);
	}	
	
}

void audit_log_view_set_multifilter(audit_log_view_t *view, seaudit_multifilter_t *multifilter)
{
	seaudit_multifilter_destroy(view->multifilter);
	view->multifilter = multifilter;
}

void audit_log_view_purge_fltr_msgs(audit_log_view_t *view)
{
	if (view->fltr_msgs) {
		free(view->fltr_msgs);
		view->fltr_msgs = NULL;
		view->num_fltr_msgs = 0;
		view->fltr_msgs_sz = 0;
	}
	return;
}

/* filter the log into the view */
int audit_log_view_do_filter(audit_log_view_t *view, int **deleted, int *num_deleted) 
{
	filter_info_t *info;
	bool_t found, show;
	int i, j, msg_index, *kept, num_kept, *added, num_added;

	if (!view || !view->my_log)
		return -1;

	/* by default append everything that is not already filtered */
	if (!view->multifilter) {
		view->fltr_msgs = (int*)realloc(view->fltr_msgs, sizeof(int) * apol_vector_get_size(view->my_log->msg_list));
		for(i = 0; i < apol_vector_get_size(view->my_log->msg_list); i++) {
			found = FALSE;
			for (j = 0; j < view->num_fltr_msgs; j++)
				if (view->fltr_msgs[j] == i)
					found = TRUE;
			if (!found) {
				view->fltr_msgs[view->num_fltr_msgs] = i;
				view->num_fltr_msgs++;
			}
		}
		(*num_deleted) = 0;
		(*deleted) = NULL;
		return 0;
	}

	(*deleted) = (int*)malloc(sizeof(int)*view->num_fltr_msgs);
	if (!(*deleted)) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	(*num_deleted) = 0;
	kept = (int*)malloc(sizeof(int)*view->num_fltr_msgs);
	if (!kept) {
		free(*deleted);
		fprintf(stderr, "out of memory");
		return -1;
	}
	num_kept = 0;
	added = (int*)malloc(sizeof(int)*apol_vector_get_size(view->my_log->msg_list));
	if (!added) {
		free(*deleted); free(kept);
		fprintf(stderr, "out of memory");
		return -1;
	}
	num_added = 0;
	info = (filter_info_t*)malloc(sizeof(filter_info_t)*apol_vector_get_size(view->my_log->msg_list));
	if (!info) {
		free(*deleted); free(kept); free(added);
		fprintf(stderr, "out of memory");
		return -1;
	}
	memset(info, 0, sizeof(filter_info_t) * apol_vector_get_size(view->my_log->msg_list));
	for (i = 0; i < view->num_fltr_msgs; i++) {
		msg_index = view->fltr_msgs[i];
		info[msg_index].orig_indx = i;
		info[msg_index].filtered = TRUE;
	}
	/* filter log into view */
	audit_log_view_purge_fltr_msgs(view);
        seaudit_multifilter_make_dirty_filters(view->multifilter);
	for (i = 0; i < apol_vector_get_size(view->my_log->msg_list); i++) {
		msg_t *msg;
		msg = apol_vector_get_element(view->my_log->msg_list, i);
		show = seaudit_multifilter_should_message_show(view->multifilter, msg, view->my_log);
		if (show) {
			if (info[i].filtered == TRUE) {
				kept[num_kept] = i;
				num_kept++;
			} else {
				added[num_added] = i;
				num_added++;
			}
			view->num_fltr_msgs++;
		} else {
			if (info[i].filtered == TRUE) {
				(*deleted)[(*num_deleted)] = info[i].orig_indx;
				(*num_deleted)++;
			}
		}
	}

	sort_kept_messages(kept, num_kept, info);
	free(info);
	view->fltr_msgs = (int*)malloc(sizeof(int)*(num_kept+num_added));
	if (!view->fltr_msgs) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	memcpy(view->fltr_msgs, kept, sizeof(int) * num_kept);
	memcpy(&view->fltr_msgs[num_kept], added, sizeof(int) * (num_added));
	free(added); free(kept);
	return 0;
}

static void sort_kept_messages(int *kept, int num_kept, filter_info_t *info)
{
	int i, j, msg_a, msg_b, tmp;
	for (j = 0; j < num_kept; j++) {
		for (i = 0; i < num_kept-1-j; i++) {
			msg_a = kept[i];
			msg_b = kept[i+1];
			if (info[msg_a].orig_indx > info[msg_b].orig_indx) {
				tmp = kept[i];
				kept[i] = kept[i+1];
				kept[i+1] = tmp;
			}
		}
	}
	return;
}
