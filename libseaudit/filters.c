/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: February 06, 2004
 *
 * This file contains the implementation of filters.h
 *
 * filters.c
 */

#include "filters.h"
#include <string.h>
#include <libapol/util.h>

static void dummy_free(void *foo) {  }

seaudit_filter_t* seaudit_filter_create(void)
{
	seaudit_filter_t *rt;

	rt = (seaudit_filter_t*)malloc(sizeof(seaudit_filter_t));
	if (!rt) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	seaudit_filter_init(rt);
	return rt;
}

void seaudit_filter_init(seaudit_filter_t *seaudit_filter)
{
	if (seaudit_filter == NULL)
		return;

	memset(seaudit_filter, 0, sizeof(seaudit_filter_t));
}

void seaudit_filter_destroy(seaudit_filter_t *seaudit_filter)
{
	llist_node_t *node;
	llist_t *list;

	if (seaudit_filter == NULL)
		return;

	list = seaudit_filter_get_list(seaudit_filter);
	for (node = list->head; node != NULL;)
		/* free current and return next */
		node = ll_node_free(node, (void (*)(void*))seaudit_criteria_destroy);

}

void seaudit_filter_set_match(seaudit_filter_t *seaudit_filter, enum seaudit_filter_match_t match)
{
	if (seaudit_filter == NULL || (match != SEAUDIT_FILTER_MATCH_ALL && match != SEAUDIT_FILTER_MATCH_ANY))
		return;

	seaudit_filter->match = match;
}

void seaudit_filter_make_dirty_criterias(seaudit_filter_t *seaudit_filter)
{
	llist_t *list;
	llist_node_t *node;
	seaudit_criteria_t *criteria;

	list = seaudit_filter_get_list(seaudit_filter);
	for (node = list->head; node != NULL; node = node->next) {
		criteria = (seaudit_criteria_t*)node->data;
		if (criteria)
			criteria->dirty = TRUE;
	}
}

bool_t seaudit_filter_does_message_match(seaudit_filter_t *filter, msg_t *message, audit_log_t *log)
{
	llist_node_t *node;
	llist_t *list;
	seaudit_criteria_t *criteria;
	bool_t match = TRUE;

	if (filter == NULL || message == NULL || log == NULL)
		return FALSE;

	list = seaudit_filter_get_list(filter);
	for (node = list->head; node != NULL; node = node->next) {
		if (!node->data)
			continue;
		criteria = (seaudit_criteria_t*)node->data;
		if (message->msg_type & criteria->msg_types) {
			if (!criteria->criteria_act(message, criteria, log)) {
				match = FALSE;
				if (filter->match == SEAUDIT_FILTER_MATCH_ALL) 
					return FALSE;
			} else {
				if (filter->match == SEAUDIT_FILTER_MATCH_ANY)
					return TRUE;
			}       
		} else {
			match = FALSE;
			if (filter->match == SEAUDIT_FILTER_MATCH_ALL)
				return FALSE;
		}
	}
	if (filter->match == SEAUDIT_FILTER_MATCH_ANY)
		match = FALSE;
	ll_free(list, dummy_free);
	return match;
}

llist_t* seaudit_filter_get_list(seaudit_filter_t *filter)
{
	llist_t* list;
	list = ll_new();
	ll_append_data(list, filter->src_type_criteria);
	ll_append_data(list, filter->tgt_type_criteria);
	ll_append_data(list, filter->src_role_criteria);
	ll_append_data(list, filter->tgt_role_criteria);
	ll_append_data(list, filter->src_user_criteria);
	ll_append_data(list, filter->tgt_user_criteria);
	ll_append_data(list, filter->class_criteria);
	ll_append_data(list, filter->exe_criteria);
	ll_append_data(list, filter->path_criteria);
	ll_append_data(list, filter->netif_criteria);
	ll_append_data(list, filter->ipaddr_criteria);
	ll_append_data(list, filter->ports_criteria);
	return list;
}

