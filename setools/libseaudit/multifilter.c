/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: February 06, 2004
 *
 * This file contains the implementation of multifilter.h
 *
 * multifilter.c
 */

#include "multifilter.h"

seaudit_multifilter_t* seaudit_multifilter_create(void)
{
	seaudit_multifilter_t *rt;

	rt = (seaudit_multifilter_t*)malloc(sizeof(seaudit_multifilter_t));
	if (!rt) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	seaudit_multifilter_init(rt);
	return rt;
}

void seaudit_multifilter_init(seaudit_multifilter_t *multifilter)
{
	if (multifilter == NULL)
		return;

	multifilter->filters = ll_new();
	multifilter->match = SEAUDIT_FILTER_MATCH_ALL;
}

void seaudit_multifilter_destroy(seaudit_multifilter_t *multifilter)
{
	llist_node_t *node;
	llist_t *list;

	if (multifilter == NULL)
		return;

	if ((list = multifilter->filters) != NULL)
		for (node = list->head; node != NULL; )
			/* free current and return next */
			node = ll_node_free(node, (void (*)(void*))seaudit_filter_destroy);

}

void seaudit_multifilter_add_filter(seaudit_multifilter_t *multifilter, seaudit_filter_t *filter)
{
	if (multifilter == NULL || filter == NULL)
		return;

	ll_append_data(multifilter->filters, filter);	
}

void seaudit_multifitler_set_match(seaudit_multifilter_t *multifilter, enum seaudit_filter_match_t match)
{
	if (multifilter == NULL || (match != SEAUDIT_FILTER_MATCH_ALL && match != SEAUDIT_FILTER_MATCH_ANY))
		return;

	multifilter->match = match;
}

void seaudit_multifilter_make_dirty_filters(seaudit_multifilter_t *multifilter)
{
	llist_t *list;
	llist_node_t *node;

	if ((list = multifilter->filters) != NULL)
		for (node = list->head; node != NULL; node = node->next)
			seaudit_filter_make_dirty_criterias((seaudit_filter_t*)node->data);
}

bool_t seaudit_multifilter_does_message_match(seaudit_multifilter_t *multifilter, msg_t *message, audit_log_t *log)
{
	llist_node_t *node;
	llist_t *list;
	seaudit_filter_t *filter;
	bool_t match = TRUE;

	if (multifilter == NULL || message == NULL || log == NULL)
		return FALSE;

	list = multifilter->filters;
	if (!list)
		return TRUE;
		
	for (node = list->head; node != NULL; node = node->next) {
		filter = (seaudit_filter_t*)node->data;
		if (seaudit_filter_does_message_match(filter, message, log)) {
			if (multifilter->match == SEAUDIT_FILTER_MATCH_ANY)
				return TRUE;
		} else {
			match = FALSE;
			if (multifilter->match == SEAUDIT_FILTER_MATCH_ALL)
				return FALSE;
		}
	}
	return match;
}
