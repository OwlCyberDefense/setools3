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
#include <string.h>
#include <libxml/parser.h>
#include <libxml/uri.h>

/* xml parser data structures */
enum seaudit_multifilter_parser_state_t {
	PARSING_NONE,
	PARSING_SRC_TYPES,
	PARSING_TGT_TYPES,
	PARSING_SRC_USERS,
	PARSING_TGT_USERS,
	PARSING_SRC_ROLES,
	PARSING_TGT_ROLES,
	PARSING_CLASSES,
	PARSING_EXE,
	PARSING_PATH,
	PARSING_NETIF,
	PARSING_IPADDR,
	PARSING_PORTS,
	PARSING_DESC,
	PARSING_HOST
};

const char *parser_valid_names[] = { "item", "criteria", "view", "filter", "desc", NULL };

typedef struct seaudit_multifilter_parser_data {
	seaudit_multifilter_t *multifilter;
	bool_t is_multi;
	seaudit_filter_t *cur_filter;
	enum seaudit_multifilter_parser_state_t state;
	bool_t parsing_item;
	char **strs; /* parser data */
	int num_strs;
	bool_t invalid_names; /* true if invalid names are found */
} seaudit_multifilter_parser_data_t;

static bool_t seaudit_multifilter_parser_is_valid_name(const char *name)
{
	int i;

	for (i = 0; parser_valid_names[i] != NULL; i++)
		if (strcmp(parser_valid_names[i], name) == 0)
			return TRUE;
	return FALSE;
}

static void seaudit_multifilter_parser_data_free(seaudit_multifilter_parser_data_t *data)
{
	int i;

	if (data->strs) {
		for (i = 0; i < data->num_strs; i++)
			if (data->strs[i])
				free(data->strs[i]);
		free(data->strs);
		data->strs = NULL;
		data->num_strs = 0;
	}
}

/* implementation of xml parser callback functions */
static void my_parse_characters(void *user_data, const xmlChar *ch, int len)
{
	seaudit_multifilter_parser_data_t *data = (seaudit_multifilter_parser_data_t *)user_data;

	switch(data->state) {
	case PARSING_NONE:
		break;
	case PARSING_SRC_TYPES:
	case PARSING_TGT_TYPES:
	case PARSING_SRC_ROLES:
	case PARSING_TGT_ROLES:
	case PARSING_SRC_USERS:
	case PARSING_TGT_USERS:
	case PARSING_CLASSES:
	case PARSING_EXE:
	case PARSING_PATH:
	case PARSING_NETIF:
	case PARSING_IPADDR:
	case PARSING_PORTS:
	case PARSING_HOST:
		if (!data->parsing_item)
			break;
	case PARSING_DESC:
		data->strs = (char**)realloc(data->strs, sizeof(char*)*((data->num_strs)+2));
		data->strs[data->num_strs] = xmlURIUnescapeString(ch, len, NULL);
		data->strs[data->num_strs+1] = NULL;
		data->num_strs++;
		break;
	}
}

static void my_parse_startElement(void *user_data, const xmlChar *name, const xmlChar **attrs)
{
	seaudit_multifilter_parser_data_t *data = (seaudit_multifilter_parser_data_t *)user_data;	
	char *unescaped;

	if (!seaudit_multifilter_parser_is_valid_name(name))
		data->invalid_names = TRUE;
        /* set state and process attributes.
	 * attributes are passed in by name value pairs. */
	if (strcmp(name, "view") == 0) {
		data->multifilter = seaudit_multifilter_create();
		if (!attrs[0] || !attrs[1]) /* xmlns= */
			return;
		if (!attrs[2] || !attrs[3]) /* name= */
			return;
		if (strcmp(attrs[2], "name") == 0)
			seaudit_multifilter_set_name(data->multifilter, attrs[3]);
		if (!attrs[4] || !attrs[4]) /* match= */
			return;
		if (strcmp(attrs[4], "match") == 0)
			seaudit_multifilter_set_match(data->multifilter, 
						      (strcmp(attrs[5], "all") == 0)? SEAUDIT_FILTER_MATCH_ALL : SEAUDIT_FILTER_MATCH_ANY);
		if (!attrs[6] || !attrs[7]) /* show= */
			return;
		if (strcmp(attrs[6], "show") == 0)
			seaudit_multifilter_set_show_matches(data->multifilter, 
							     (strcmp(attrs[7], "true") == 0)? TRUE : FALSE);
		data->is_multi = TRUE;
	} else if (strcmp(name, "filter") == 0) {
		data->cur_filter = seaudit_filter_create();
		if (!attrs[0] || !attrs[1])
			return;
		if (strcmp(attrs[0], "name") == 0) {
			unescaped = xmlURIUnescapeString(attrs[1], -1, NULL);
			seaudit_filter_set_name(data->cur_filter, unescaped);
			free(unescaped);
		}

		if (!attrs[2] || !attrs[3])
			return;
		if (strcmp(attrs[2], "match") == 0) {
			if (strcmp(attrs[3], "all") == 0)
				data->cur_filter->match = SEAUDIT_FILTER_MATCH_ALL;
			else 
				data->cur_filter->match = SEAUDIT_FILTER_MATCH_ANY;
		}

	} else if (strcmp(name, "desc") == 0) {
		data->state = PARSING_DESC;

	} else if (strcmp(name, "criteria") == 0) {
		if (!attrs[0] || !attrs[1] || strcmp(attrs[0], "type") != 0)
			data->state = PARSING_NONE;
		else if (strcmp(attrs[1], "src_type") == 0)
			data->state = PARSING_SRC_TYPES;
		else if (strcmp(attrs[1], "tgt_type") == 0)
			data->state = PARSING_TGT_TYPES;
		else if (strcmp(attrs[1], "src_user") == 0)
			data->state = PARSING_SRC_USERS;
		else if (strcmp(attrs[1], "tgt_user") == 0)
			data->state = PARSING_TGT_USERS;
		else if (strcmp(attrs[1], "src_role") == 0)
			data->state = PARSING_SRC_ROLES;
		else if (strcmp(attrs[1], "tgt_role") == 0)
			data->state = PARSING_TGT_ROLES;
		else if (strcmp(attrs[1], "obj_class") == 0)
			data->state = PARSING_CLASSES;
		else if (strcmp(attrs[1], "exe") == 0)
			data->state = PARSING_EXE;
		else if (strcmp(attrs[1], "path") == 0)
			data->state = PARSING_PATH;
		else if (strcmp(attrs[1], "netif") == 0)
			data->state = PARSING_NETIF;
		else if (strcmp(attrs[1], "ipaddr") == 0)
			data->state = PARSING_IPADDR;
		else if (strcmp(attrs[1], "port") == 0)
			data->state = PARSING_PORTS;
		else if (strcmp(attrs[1], "host") == 0)
			data->state = PARSING_HOST;
		else
			data->state = PARSING_NONE;

        } else if (strcmp(name, "item") == 0) {
		data->parsing_item = TRUE;
	}
}

static void my_parse_endElement(void *user_data, const xmlChar *name)
{
	seaudit_multifilter_parser_data_t *data = (seaudit_multifilter_parser_data_t *)user_data;

	if (!seaudit_multifilter_parser_is_valid_name(name))
		data->invalid_names = TRUE;

	if (strcmp(name, "desc") == 0) {
		if (data->strs[0])
			seaudit_filter_set_desc(data->cur_filter, data->strs[0]);
		seaudit_multifilter_parser_data_free(data);
		data->state = PARSING_NONE;
		return;
	}

	if (strcmp(name, "item") == 0) {
		data->parsing_item = FALSE;
		return;
	}
	
	if (strcmp(name, "filter") == 0) {
		seaudit_multifilter_add_filter(data->multifilter, data->cur_filter);
		data->cur_filter = NULL;
	}

	if (strcmp(name, "criteria") == 0) {
		switch (data->state) {
		case PARSING_NONE:
		case PARSING_DESC: /* should never get here */
			break;
		case PARSING_SRC_TYPES:
			data->cur_filter->src_type_criteria = src_type_criteria_create(data->strs, data->num_strs);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_TGT_TYPES:
			data->cur_filter->tgt_type_criteria = tgt_type_criteria_create(data->strs, data->num_strs);
			seaudit_multifilter_parser_data_free(data);		
			data->state = PARSING_NONE;
			break;
		case PARSING_SRC_ROLES:
			data->cur_filter->src_role_criteria = src_role_criteria_create(data->strs, data->num_strs);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_TGT_ROLES:
			data->cur_filter->tgt_role_criteria = tgt_role_criteria_create(data->strs, data->num_strs);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_SRC_USERS:
			data->cur_filter->src_user_criteria = src_user_criteria_create(data->strs, data->num_strs);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_TGT_USERS:
			data->cur_filter->tgt_user_criteria = tgt_user_criteria_create(data->strs, data->num_strs);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_CLASSES:
			data->cur_filter->class_criteria = class_criteria_create(data->strs, data->num_strs);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_EXE:
			if (data->strs[0])
				data->cur_filter->exe_criteria = exe_criteria_create(data->strs[0]);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_PATH:
			if (data->strs[0])
				data->cur_filter->path_criteria = path_criteria_create(data->strs[0]);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_NETIF:
			if (data->strs[0])
				data->cur_filter->netif_criteria = netif_criteria_create(data->strs[0]);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_IPADDR:
			if (data->strs[0])
				data->cur_filter->ipaddr_criteria = ipaddr_criteria_create(data->strs[0]);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_HOST:
			if (data->strs[0])
				data->cur_filter->host_criteria = host_criteria_create(data->strs[0]);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_PORTS:
			if (data->strs[0])
				data->cur_filter->ports_criteria = ports_criteria_create(atoi(data->strs[0]));
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
		}
	}

}

seaudit_multifilter_t* seaudit_multifilter_create(void)
{
	seaudit_multifilter_t *rt = NULL;

	rt = (seaudit_multifilter_t*)malloc(sizeof(seaudit_multifilter_t));
	if (rt == NULL) {
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
	multifilter->name = NULL;
	multifilter->show = TRUE;
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
	free(list);
	
	if (multifilter->name)
		free(multifilter->name);

}

void seaudit_multifilter_add_filter(seaudit_multifilter_t *multifilter, seaudit_filter_t *filter)
{
	if (multifilter == NULL || filter == NULL)
		return;

	ll_append_data(multifilter->filters, filter);	
}

void seaudit_multifilter_set_match(seaudit_multifilter_t *multifilter, enum seaudit_filter_match_t match)
{
	if (multifilter == NULL || (match != SEAUDIT_FILTER_MATCH_ALL && match != SEAUDIT_FILTER_MATCH_ANY))
		return;

	multifilter->match = match;
}

void seaudit_multifilter_set_show_matches(seaudit_multifilter_t *multifilter, bool_t show)
{
	if (!multifilter)
		return;
	multifilter->show = show;
}

void seaudit_multifilter_set_name(seaudit_multifilter_t *multifilter, const char *name)
{
	if (multifilter == NULL || name == NULL)
		return;

	if (multifilter->name)
		free(multifilter->name);
	multifilter->name = strdup(name);
}

void seaudit_multifilter_make_dirty_filters(seaudit_multifilter_t *multifilter)
{
	llist_t *list;
	llist_node_t *node;

	if ((list = multifilter->filters) != NULL)
		for (node = list->head; node != NULL; node = node->next)
			seaudit_filter_make_dirty_criterias((seaudit_filter_t*)node->data);
}

static bool_t seaudit_multifilter_does_message_match(seaudit_multifilter_t *multifilter, msg_t *message, audit_log_t *log)
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

bool_t seaudit_multifilter_should_message_show(seaudit_multifilter_t *multifilter, msg_t *message, audit_log_t *log)
{
	bool_t matches; 

	matches = seaudit_multifilter_does_message_match(multifilter, message, log);
	return matches == multifilter->show;
}

int seaudit_multifilter_load_from_file(seaudit_multifilter_t **multifilter, bool_t *is_multi, const char *filename)
{
	seaudit_multifilter_parser_data_t parse_data;
	xmlSAXHandler handler;
	int err;

	if (!filename)
		return 1;
	memset(&handler, 0, sizeof(xmlSAXHandler));
	handler.startElement = my_parse_startElement;
	handler.endElement = my_parse_endElement;
	handler.characters = my_parse_characters;
	memset(&parse_data, 0, sizeof(seaudit_multifilter_parser_data_t));
	parse_data.multifilter = seaudit_multifilter_create();
	err = xmlSAXUserParseFile(&handler, &parse_data, filename);
	seaudit_multifilter_parser_data_free(&parse_data);
	if (err || parse_data.invalid_names == TRUE) {
		seaudit_multifilter_destroy(parse_data.multifilter);
		*is_multi = FALSE;
		*multifilter = NULL;
		if (err)
			return err;
		else 
			return 1; /* invalid file */
	}

	*is_multi = parse_data.is_multi;
	*multifilter = parse_data.multifilter;
	
	return 0;
}

int seaudit_multifilter_save_to_file(seaudit_multifilter_t *multifilter, const char *filename)
{
	FILE *file;
	const char *XML_VER = "<?xml version=\"1.0\"?>\n";
	seaudit_filter_t *filter;
	llist_node_t *node;
	llist_t *list;

	if (!multifilter || !filename)
		return -1;
	file = fopen(filename, "w");
	if (!file)
		return -1;

	fprintf(file, XML_VER);
	fprintf(file, "<view xmlns=\"http://www.tresys.com/setools/seaudit/%s/\" name=\"%s\" match=\"%s\" show=\"%s\">\n", 
		FILTER_FILE_FORMAT_VERSION, multifilter->name, 
		multifilter->match == SEAUDIT_FILTER_MATCH_ALL? "all" : "any",
		multifilter->show == TRUE? "true" : "false");
	
	list = multifilter->filters;
	for (node = list->head; node != NULL; node = node->next) {
		filter = (seaudit_filter_t*)node->data;
		seaudit_filter_append_to_file(filter, file, 1);
	}
	fprintf(file, "</view>\n");
	fclose(file);
	return 0;
}
