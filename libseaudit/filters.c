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
#include <libxml/uri.h>

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
	apol_vector_t *criteria_vector;
	seaudit_criteria_t *criteria;
	int i;

	if (seaudit_filter == NULL)
		return;

	criteria_vector = (apol_vector_t *)seaudit_filter_get_list(seaudit_filter);
	for (i = 0; i < apol_vector_get_size(criteria_vector); i++) {
		/* free current and return next */
		criteria = apol_vector_get_element(criteria_vector, i);
		seaudit_criteria_destroy(criteria);
	}
	apol_vector_destroy(&criteria_vector, 0);
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
	seaudit_criteria_t *criteria;
	apol_vector_t *criteria_vector;
	int i;

	criteria_vector = (apol_vector_t *)seaudit_filter_get_list(seaudit_filter);
	for (i = 0; i < apol_vector_get_size(criteria_vector); i++) {
		criteria = apol_vector_get_element(criteria_vector, i);
		if (criteria)
			criteria->dirty = TRUE;
	}
	apol_vector_destroy(&criteria_vector, 0);
}

bool_t seaudit_filter_does_message_match(seaudit_filter_t *filter, msg_t *message, audit_log_t *log)
{
	seaudit_criteria_t *criteria = NULL;
	bool_t match = TRUE;
	apol_vector_t *criteria_vector;
	int i;

	if (filter == NULL || message == NULL || log == NULL)
		return FALSE;

	criteria_vector = (apol_vector_t *)seaudit_filter_get_list(filter);
	if (criteria_vector == NULL) {
		return FALSE;
	}
	for (i = 0; i < apol_vector_get_size(criteria_vector); i++) {
		criteria = apol_vector_get_element(criteria_vector, i);
		if (!criteria)
			continue;
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
	apol_vector_destroy(&criteria_vector, 0);
	return match;
}

apol_vector_t *seaudit_filter_get_list(seaudit_filter_t *filter)
{
	apol_vector_t *criterias;

	if (!(criterias = apol_vector_create())) {
		return NULL;
	}
	apol_vector_append(criterias, (void *)filter->src_type_criteria);
	apol_vector_append(criterias, (void *)filter->tgt_type_criteria);
	apol_vector_append(criterias, (void *)filter->src_role_criteria);
	apol_vector_append(criterias, (void *)filter->tgt_role_criteria);
	apol_vector_append(criterias, (void *)filter->src_user_criteria);
	apol_vector_append(criterias, (void *)filter->tgt_user_criteria);
	apol_vector_append(criterias, (void *)filter->class_criteria);
	apol_vector_append(criterias, (void *)filter->exe_criteria);
	apol_vector_append(criterias, (void *)filter->comm_criteria);
	apol_vector_append(criterias, (void *)filter->msg_criteria);
	apol_vector_append(criterias, (void *)filter->path_criteria);
	apol_vector_append(criterias, (void *)filter->netif_criteria);
	apol_vector_append(criterias, (void *)filter->ipaddr_criteria);
	apol_vector_append(criterias, (void *)filter->ports_criteria);
	apol_vector_append(criterias, (void *)filter->host_criteria);
	apol_vector_append(criterias, (void *)filter->date_time_criteria);
	return criterias;
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
	fprintf(file, "<view xmlns=\"http://oss.tresys.com/projects/setools/seaudit-%s/\">\n",
		FILTER_FILE_FORMAT_VERSION);
	seaudit_filter_append_to_file(filter, file, 1);
	fprintf(file, "</view>\n");
	fclose(file);
	return 0;
}

void seaudit_filter_append_to_file(seaudit_filter_t *filter, FILE *file, int tabs)
{
	seaudit_criteria_t *criteria;
	apol_vector_t *criteria_vector;
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
	criteria_vector = (apol_vector_t *)seaudit_filter_get_list(filter);
	for (i = 0; i < apol_vector_get_size(criteria_vector); i++) {
		criteria = apol_vector_get_element(criteria_vector, i);
		if (criteria)
			seaudit_criteria_print(criteria, file, tabs+2);
	}
	apol_vector_destroy(&criteria_vector, 0);
	fprintf(file, "\t</filter>\n");
}
