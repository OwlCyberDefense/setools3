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
	audit_log_view_purge_filters(view);
	sort_action_list_destroy(view->sort_actions);
	if (view->fltr_msgs)
		free(view->fltr_msgs);
	free(view);
	view = NULL;
	return;
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

/* add a filter to the list of active filters */
int audit_log_view_add_filter(audit_log_view_t *view, filter_t *filter)
{
	if (view == NULL || filter == NULL)
		return -1;
	if (view->filters == NULL) {
		filter->next = NULL;
		filter->prev = NULL;
		view->filters = filter;
		return 0;
	}
	filter->next = view->filters;
	filter->prev = NULL;
	view->filters->prev = filter;
	view->filters = filter;
	return 0;
}

/* remove all the filters */
void audit_log_view_purge_filters(audit_log_view_t *view)
{
	filter_t *cur, *next;

	if (view->filters) {
		cur = view->filters;
		while (cur) {
			next = cur->next;
			if (next)
				next->prev = NULL;
			filter_destroy(cur);
			cur = next;
		}
		view->filters = NULL;
	}	
	return;
}

/* filter the log into the view */
int audit_log_view_do_filter(audit_log_view_t *view, bool_t details, int **deleted, int *num_deleted) 
{
	int i, j, msg, *kept=NULL, num_kept=0, *added=NULL, num_added=0, *ptr=NULL, *delptr=NULL;
	bool_t err, all_match, any_match, match, found; 
	filter_t *cur_fltr; 
	filter_info_t *info;

	if (view->my_log == NULL)
		return -1;
	if (view->my_log->msg_list == NULL)
		return -1;

	/* by default append everything that is not already filtered */
	if (view->filters == NULL) {
		view->fltr_msgs = (int*)realloc(view->fltr_msgs, sizeof(int) * view->my_log->num_msgs);
		for(i = 0; i < view->my_log->num_msgs; i++) {
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

	/* we need to keep these buffers around to keep track of 
	 * deleted, added, and kept messages */
	if (!num_deleted)
		return -1;

	delptr = (int*)malloc(sizeof(int) * view->num_fltr_msgs);
	*num_deleted = 0;
	if (!delptr) {
		return -1;
	}
	*deleted = delptr;
	kept = (int*)malloc(sizeof(int) * view->num_fltr_msgs);
	if (!kept) {
		free(delptr);
		return -1;
	}
	added = (int*)malloc(sizeof(int) * view->my_log->num_msgs);
	if (!added) {
		free(delptr);
		free(kept);
		return -1;
	}
	info = (filter_info_t*)malloc(sizeof(filter_info_t)*view->my_log->num_msgs);
	if (!info) {
		free(delptr);
		free(kept);
		free(added);
		return -1;
	}
	memset(info, 0, sizeof(filter_info_t) * view->my_log->num_msgs);
	for (i = 0; i < view->num_fltr_msgs; i++) {
		msg = view->fltr_msgs[i];
		info[msg].orig_indx = i;
		info[msg].filtered = TRUE;
	}

	audit_log_view_purge_fltr_msgs(view);

       	for (cur_fltr = view->filters; cur_fltr != NULL; cur_fltr = cur_fltr->next)
		cur_fltr->dirty = TRUE;


	if (view->fltr_and) { /* match all filters */
		
		for (i = 0; i < view->my_log->num_msgs; i++) {
			all_match = TRUE;
			any_match = FALSE;
			for (cur_fltr = view->filters; cur_fltr != NULL && all_match; cur_fltr = cur_fltr->next) {
				if (cur_fltr->filter_act) {
					if (!(cur_fltr->msg_types & view->my_log->msg_list[i]->msg_type))
						match = FALSE;
					else
						match = cur_fltr->filter_act(view->my_log->msg_list[i], 
									     cur_fltr, view->my_log, &err);
					all_match = all_match && match;
				}
			}			
			if (view->fltr_out) { /* Filter out messages */
				if (all_match) {
					if (info[i].filtered == TRUE) {
						delptr[*num_deleted] = info[i].orig_indx;
						(*num_deleted)++;
					} 	
				} else {
					if (info[i].filtered == TRUE) {
						kept[num_kept] = i;
						num_kept++;
					} else {
						added[num_added] = i;
						num_added++;
					}
				}
			} else {             /* Filter in messages */
				if (all_match) {
					if (info[i].filtered == TRUE) {
						kept[num_kept] = i;
						num_kept++;
					} else {
						added[num_added] = i;
						num_added++;
					}
				} else {
					if (info[i].filtered == TRUE) {
						delptr[*num_deleted] = info[i].orig_indx;
						(*num_deleted)++;
					} 
				}
			}
		}
		
	} else { /* match any filter */
		
		for (i = 0; i < view->my_log->num_msgs; i++) {
			all_match = TRUE;
			any_match = FALSE;
			for (cur_fltr = view->filters; cur_fltr != NULL; cur_fltr = cur_fltr->next) {
				if (cur_fltr->filter_act) {
					if (!(cur_fltr->msg_types & view->my_log->msg_list[i]->msg_type))
						match = FALSE;
					else
						match = cur_fltr->filter_act(view->my_log->msg_list[i], cur_fltr, 
									     view->my_log, &err);
					any_match = any_match || match;
				}
			}
			if (view->fltr_out) { /* Filter out messages */
				if (any_match) {
					if (info[i].filtered == TRUE) {
						delptr[*num_deleted] = info[i].orig_indx;
						(*num_deleted)++;
					} 	
				} else {
					if (info[i].filtered == TRUE) {
						kept[num_kept] = i;
						num_kept++;
					} else {
						added[num_added] = i;
						num_added++;
					}
				}
			} else {            /* Filter in messages*/
				if (any_match) {
					if (info[i].filtered == TRUE) {
						kept[num_kept] = i;
						num_kept++;
					} else {
						added[num_added] = i;
						num_added++;
					}
				} else {
					if (info[i].filtered == TRUE) {
						delptr[*num_deleted] = info[i].orig_indx;
						(*num_deleted)++;
					} 
				}
			}
		} /* end for loop */
	}
	
	sort_kept_messages(kept, num_kept, info);
	free(info);

	/* merge kept and added to form fltr_msgs */
        ptr = (int*)malloc(sizeof(int) * ( (num_added) + num_kept));
	if (!ptr) {
		free(delptr);
		free(kept);
		free(added);
		return -1;
	}	
	view->fltr_msgs = ptr;
	view->num_fltr_msgs = num_kept + num_added;
	memcpy(view->fltr_msgs, kept, sizeof(int) * num_kept);
	memcpy(&view->fltr_msgs[num_kept], added, sizeof(int) * (num_added));
	free(added);
	free(kept);

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
