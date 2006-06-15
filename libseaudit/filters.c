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
#include "libapol/util.h"
#include <libxml/uri.h>

static void dummy_free(void *foo) {  }


seaudit_filter_t* seaudit_filter_create(void)
{
	seaudit_filter_t *rt = NULL;

	rt = (seaudit_filter_t*)malloc(sizeof(seaudit_filter_t));
	if (rt == NULL) {
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
	
	free(list);
}

void seaudit_filter_set_match(seaudit_filter_t *seaudit_filter, enum seaudit_filter_match_t match)
{
	if (seaudit_filter == NULL || (match != SEAUDIT_FILTER_MATCH_ALL && match != SEAUDIT_FILTER_MATCH_ANY))
		return;

	seaudit_filter->match = match;
}

void seaudit_filter_set_name(seaudit_filter_t *seaudit_filter, const char *name)
{
	if (!seaudit_filter)
		return;
	if (seaudit_filter->name)
		free(seaudit_filter->name);
	seaudit_filter->name = strdup(name);
}

void seaudit_filter_set_desc(seaudit_filter_t *seaudit_filter, const char *desc)
{
	if (!seaudit_filter)
		return;
	if (seaudit_filter->desc)
		free(seaudit_filter->desc);
	seaudit_filter->desc = strdup(desc);
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
	llist_node_t *node = NULL;
	llist_t *list = NULL;
	seaudit_criteria_t *criteria = NULL;
	bool_t match = TRUE;

	if (filter == NULL || message == NULL || log == NULL)
		return FALSE;

	list = seaudit_filter_get_list(filter);
	if (list == NULL) {
		return FALSE;
	}
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
	if (filter->match == SEAUDIT_FILTER_MATCH_ALL)
		match = TRUE;
	ll_free(list, dummy_free);
	return match;
}

llist_t* seaudit_filter_get_list(seaudit_filter_t *filter)
{
	llist_t* list = NULL;
	
	list = ll_new();
	if (list == NULL) {
		return NULL;
	}
	ll_append_data(list, filter->src_type_criteria);
	ll_append_data(list, filter->tgt_type_criteria);
	ll_append_data(list, filter->src_role_criteria);
	ll_append_data(list, filter->tgt_role_criteria);
	ll_append_data(list, filter->src_user_criteria);
	ll_append_data(list, filter->tgt_user_criteria);
	ll_append_data(list, filter->class_criteria);
	ll_append_data(list, filter->exe_criteria);
	ll_append_data(list, filter->comm_criteria);
	ll_append_data(list, filter->msg_criteria);
	ll_append_data(list, filter->path_criteria);
	ll_append_data(list, filter->netif_criteria);
	ll_append_data(list, filter->ipaddr_criteria);
	ll_append_data(list, filter->ports_criteria);
	ll_append_data(list, filter->host_criteria);
	ll_append_data(list, filter->date_time_criteria);	
	return list;
}

int seaudit_filter_save_to_file(seaudit_filter_t *filter, const char *filename)
{
	FILE *file;
	const char *XML_VER = "<?xml version=\"1.0\"?>\n";

	if (!filter || !filename)
		return -1;
	file = fopen(filename, "w");
	if (!file)
		return -1;
	fprintf(file, XML_VER);
	fprintf(file, "<view xmlns=\"http://www.tresys.com/setools/seaudit/%s/\">\n", 
		FILTER_FILE_FORMAT_VERSION);
	seaudit_filter_append_to_file(filter, file, 1);
	fprintf(file, "</view>\n");
	fclose(file);	
	return 0;
}

void seaudit_filter_append_to_file(seaudit_filter_t *filter, FILE *file, int tabs)
{
	seaudit_criteria_t *criteria;
	llist_t *list;
	llist_node_t *node;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (!filter || !file)
		return;

	str_xml = xmlCharStrdup(filter->name);
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(file, "\t");
	fprintf(file, "<filter name=\"%s\" match=\"%s\">\n", escaped, 
		filter->match == SEAUDIT_FILTER_MATCH_ALL? "all" : "any");
	free(escaped);
	free(str_xml);

	if (filter->desc) {
		str_xml = xmlCharStrdup(filter->desc);
		escaped = xmlURIEscapeStr(str_xml, NULL);
		for (i = 0; i < tabs+1; i++)
			fprintf(file, "\t");
		fprintf(file, "<desc>%s</desc>\n", escaped);
		free(escaped);
		free(str_xml);
	}
	list = seaudit_filter_get_list(filter);
	for (node = list->head; node != NULL; node = node->next) {
		criteria = (seaudit_criteria_t*)node->data;
		if (criteria)
			seaudit_criteria_print(criteria, file, tabs+2);
	}
	fprintf(file, "\t</filter>\n"); 
}



