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
#include <libxml/parser.h>
#include <libxml/uri.h>

static void dummy_free(void *foo) {  }

/* xml parser data structures */
enum seaudit_filter_parser_state_t {
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
	PARSING_DESC
};
	       
typedef struct seaudit_filter_parser_data {
	seaudit_filter_t *filter;
	enum seaudit_filter_parser_state_t state;
	bool_t parsing_item;
	char **strs; /* parser data */
	int num_strs;
} seaudit_filter_parser_data_t;

static void seaudit_filter_parser_data_free(seaudit_filter_parser_data_t *data)
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
	seaudit_filter_parser_data_t *data = (seaudit_filter_parser_data_t *)user_data;

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

static void my_parse_endElement(void *user_data, const xmlChar *name)
{
	seaudit_filter_parser_data_t *data = (seaudit_filter_parser_data_t *)user_data;

	if (!data->strs)
		return;

	if (strcmp(name, "desc") == 0) {
		if (data->strs[0])
			seaudit_filter_set_desc(data->filter, data->strs[0]);
		seaudit_filter_parser_data_free(data);
		data->state = PARSING_NONE;
		return;
	}

	if (strcmp(name, "item") == 0) {
		data->parsing_item = FALSE;
		return;
	}

	if (strcmp(name, "criteria") == 0) {
		switch (data->state) {
		case PARSING_NONE:
		case PARSING_DESC: /* should never get here */
			break;
		case PARSING_SRC_TYPES:
			data->filter->src_type_criteria = src_type_criteria_create(data->strs, data->num_strs);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_TGT_TYPES:
			data->filter->tgt_type_criteria = tgt_type_criteria_create(data->strs, data->num_strs);
			seaudit_filter_parser_data_free(data);		
			data->state = PARSING_NONE;
			break;
		case PARSING_SRC_ROLES:
			data->filter->src_role_criteria = src_role_criteria_create(data->strs, data->num_strs);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_TGT_ROLES:
			data->filter->tgt_role_criteria = tgt_role_criteria_create(data->strs, data->num_strs);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_SRC_USERS:
			data->filter->src_user_criteria = src_user_criteria_create(data->strs, data->num_strs);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_TGT_USERS:
			data->filter->tgt_user_criteria = tgt_user_criteria_create(data->strs, data->num_strs);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_CLASSES:
			data->filter->class_criteria = class_criteria_create(data->strs, data->num_strs);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_EXE:
			if (data->strs[0])
				data->filter->exe_criteria = exe_criteria_create(data->strs[0]);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_PATH:
			if (data->strs[0])
				data->filter->path_criteria = path_criteria_create(data->strs[0]);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_NETIF:
			if (data->strs[0])
				data->filter->netif_criteria = netif_criteria_create(data->strs[0]);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_IPADDR:
			if (data->strs[0])
				data->filter->ipaddr_criteria = ipaddr_criteria_create(data->strs[0]);
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_PORTS:
			if (data->strs[0])
				data->filter->ports_criteria = ports_criteria_create(atoi(data->strs[0]));
			seaudit_filter_parser_data_free(data);
			data->state = PARSING_NONE;
		}
	}

}

static void my_parse_startElement(void *user_data, const xmlChar *name, const xmlChar **attrs)
{
	seaudit_filter_parser_data_t *data = (seaudit_filter_parser_data_t *)user_data;	
	char *unescaped;

        /* set state and process attributes.
	 * attributes are passed in by name value pairs. */
	if (strcmp(name, "filter") == 0) {
		data->state = PARSING_NONE;
		if (!attrs[0] || !attrs[1] || !attrs[2] || !attrs[3])
			return;
		if (strcmp(attrs[0], "name") == 0)
			if (data->filter->name)
				free(data->filter->name);
		unescaped = xmlURIUnescapeString(attrs[1], -1, NULL);
		data->filter->name = strdup(unescaped);
		free(unescaped);
		if (strcmp(attrs[2], "match") == 0) {
			if (strcmp(attrs[3], "all") == 0)
				data->filter->match = SEAUDIT_FILTER_MATCH_ALL;
			else 
				data->filter->match = SEAUDIT_FILTER_MATCH_ANY;
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
		else
			data->state = PARSING_NONE;

        } else if (strcmp(name, "item") == 0) {
		data->parsing_item = TRUE;
	}
}

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

int seaudit_filter_save_to_file(seaudit_filter_t *filter, const char *filename)
{
	FILE *file;
	const char *XML_VER = "<?xml version=\"1.0\"?>\n";
	char *escaped;

	if (!filter || !filename)
		return -1;
	file = fopen(filename, "w");
	if (!file)
		return -1;
	fprintf(file, XML_VER);
	fprintf(file, "<structure xmlns=\"http://www.tresys.com/setools/seaudit/%s/\">\n", 
		LIBSEAUDIT_VERSION_STRING);
	escaped = xmlURIEscapeStr(filter->name, NULL);
	fprintf(file, "\t<filter name=\"%s\" match=\"%s\">\n", escaped, 
		filter->match == SEAUDIT_FILTER_MATCH_ALL? "all" : "any");
	free(escaped);

	if (filter->desc) {
		escaped = xmlURIEscapeStr(filter->desc, NULL);
		fprintf(file, "\t\t<desc>%s</desc>\n", escaped);
		free(escaped);
	}

	seaudit_criteria_print(filter->src_type_criteria, file, 2);
	seaudit_criteria_print(filter->tgt_type_criteria, file, 2);
	seaudit_criteria_print(filter->src_user_criteria, file, 2);
	seaudit_criteria_print(filter->tgt_user_criteria, file, 2);
	seaudit_criteria_print(filter->src_role_criteria, file, 2);
	seaudit_criteria_print(filter->tgt_role_criteria, file, 2);
	seaudit_criteria_print(filter->class_criteria, file, 2);
	seaudit_criteria_print(filter->exe_criteria, file, 2);
	seaudit_criteria_print(filter->path_criteria, file, 2);
	seaudit_criteria_print(filter->netif_criteria, file, 2);
	seaudit_criteria_print(filter->ipaddr_criteria, file, 2);
	seaudit_criteria_print(filter->ports_criteria, file, 2);

	fprintf(file, "\t</filter>\n</structure>\n");
	fclose(file);	
	return 0;

}

int seaudit_filter_load_from_file(seaudit_filter_t **filter, const char *filename)
{
	seaudit_filter_parser_data_t parse_data;
	xmlSAXHandler handler;
	int err;

	if (!filename)
		return -1;

	memset(&handler, 0, sizeof(xmlSAXHandler));
	handler.startElement = my_parse_startElement;
	handler.endElement = my_parse_endElement;
	handler.characters = my_parse_characters;
	memset(&parse_data, 0, sizeof(seaudit_filter_parser_data_t));
	parse_data.filter = seaudit_filter_create();
	err = xmlSAXUserParseFile(&handler, &parse_data, filename);
	seaudit_filter_parser_data_free(&parse_data);
	if (err)
		return err;
	*filter = parse_data.filter;
	return 0;
}


