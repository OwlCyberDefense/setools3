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
	enum seaudit_filter_parser_state_t state; /* parser state */
	char *exe;        /* parser data .. */
	char *path;
	char *ipaddr;
	char *netif;
	char *name;
	char *desc;
	char **src_types;
	int num_src_types;
	char **tgt_types;
	int num_tgt_types;
	char **src_roles;
	int num_src_roles;
	char **tgt_roles;
	int num_tgt_roles;
	char **src_users;
	int num_src_users;
	char **tgt_users;
	int num_tgt_users;
	char **classes;
	int num_classes;
	int port;
	enum seaudit_filter_match_t match;
} seaudit_filter_parser_data_t;

static void seaudit_filter_parser_data_free(seaudit_filter_parser_data_t *parse_data);
static seaudit_filter_t* seaudit_filter_parser_data_get_filter(seaudit_filter_parser_data_t *parse_data);
/* xml parser callbacks */
static void characters(void *user_data, const xmlChar *ch, int len);
static void startElement(void *user_data, const xmlChar *name, const xmlChar **attrs);


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

	if (!filter || !filename)
		return -1;
	file = fopen(filename, "w");
	if (!file)
		return -1;
	fprintf(file, XML_VER);
	fprintf(file, "<structure xmlns=\"http://www.tresys.com/setools/seaudit/%s/\">\n", 
		LIBSEAUDIT_VERSION_STRING);
	fprintf(file, "<filter name=\"%s\" match=\"%s\">\n", filter->name, 
		filter->match == SEAUDIT_FILTER_MATCH_ALL? "all" : "any");

	if (filter->desc)
		fprintf(file, "<desc>%s</desc>\n", filter->desc);

	seaudit_criteria_print(filter->src_type_criteria, file);
	seaudit_criteria_print(filter->tgt_type_criteria, file);
	seaudit_criteria_print(filter->src_user_criteria, file);
	seaudit_criteria_print(filter->tgt_user_criteria, file);
	seaudit_criteria_print(filter->src_role_criteria, file);
	seaudit_criteria_print(filter->tgt_role_criteria, file);
	seaudit_criteria_print(filter->class_criteria, file);
	seaudit_criteria_print(filter->exe_criteria, file);
	seaudit_criteria_print(filter->path_criteria, file);
	seaudit_criteria_print(filter->netif_criteria, file);
	seaudit_criteria_print(filter->ipaddr_criteria, file);
	seaudit_criteria_print(filter->ports_criteria, file);

	fprintf(file, "</filter>\n</structure>\n");
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
	handler.startElement = startElement;
	handler.characters = characters;
	memset(&parse_data, 0, sizeof(seaudit_filter_parser_data_t));
	parse_data.port = -1;
	err = xmlSAXUserParseFile(&handler, &parse_data, filename);
	if (err) {
		seaudit_filter_parser_data_free(&parse_data);
		return err;
	}
	*filter = seaudit_filter_parser_data_get_filter(&parse_data);
	seaudit_filter_parser_data_free(&parse_data);
	return 0;
}

static seaudit_filter_t* seaudit_filter_parser_data_get_filter(seaudit_filter_parser_data_t *parse_data)
{
	seaudit_filter_t *filter;

	filter = seaudit_filter_create();
	if (!filter)
		return NULL;
	seaudit_filter_set_match(filter, parse_data->match);
	if (parse_data->name)
		seaudit_filter_set_name(filter, parse_data->name);
	if (parse_data->desc)
		seaudit_filter_set_desc(filter, parse_data->desc);
	if (parse_data->src_types)
		filter->src_type_criteria = src_type_criteria_create(parse_data->src_types, parse_data->num_src_types);
	if (parse_data->tgt_types)
		filter->tgt_type_criteria = tgt_type_criteria_create(parse_data->tgt_types, parse_data->num_tgt_types);
	if (parse_data->src_roles)
		filter->src_role_criteria = src_role_criteria_create(parse_data->src_roles, parse_data->num_src_roles);
	if (parse_data->tgt_roles)
		filter->tgt_role_criteria = tgt_role_criteria_create(parse_data->tgt_roles, parse_data->num_tgt_roles);
	if (parse_data->src_users)
		filter->src_user_criteria = src_user_criteria_create(parse_data->src_users, parse_data->num_src_users);
	if (parse_data->tgt_users)
		filter->tgt_user_criteria = tgt_user_criteria_create(parse_data->tgt_users, parse_data->num_tgt_users);
	if (parse_data->classes)
		filter->class_criteria = class_criteria_create(parse_data->classes, parse_data->num_classes);
	if (parse_data->exe)
		filter->exe_criteria = exe_criteria_create(parse_data->exe);
	if (parse_data->path)
		filter->path_criteria = path_criteria_create(parse_data->path);
	if (parse_data->netif)
		filter->netif_criteria = netif_criteria_create(parse_data->netif);
	if (parse_data->ipaddr)
		filter->ipaddr_criteria = ipaddr_criteria_create(parse_data->ipaddr);
	if (parse_data->port >= 0)
		filter->ports_criteria = ports_criteria_create(parse_data->port);

	return filter;
}

static void seaudit_filter_parser_data_free(seaudit_filter_parser_data_t *data)
{
	int i;

	if (data->exe)
		free(data->exe);
	if (data->path)
		free(data->path);
	if (data->ipaddr)
		free(data->ipaddr);
	if (data->netif)
		free(data->netif);
	if (data->desc)
		free(data->desc);
	if (data->src_types) {
		for (i = 0; i < data->num_src_types; i++)
			if (data->src_types[i])
				free(data->src_types[i]);
		free(data->src_types);
	}
	if (data->tgt_types) {
		for (i = 0; i < data->num_tgt_types; i++)
			if (data->tgt_types[i])
				free(data->tgt_types[i]);
		free(data->tgt_types);
	}
	if (data->src_roles) {
		for (i = 0; i < data->num_src_roles; i++) 
			if (data->src_roles[i])
				free(data->src_roles[i]);
		free(data->src_roles);
	}
	if (data->tgt_roles) {
		for (i = 0; i < data->num_tgt_roles; i++)
			if (data->tgt_roles[i])
				free(data->tgt_roles[i]);
		free(data->tgt_roles);
	}
	if (data->src_users) {
		for (i = 0; i < data->num_src_users; i++)
			if (data->src_users[i])
				free(data->src_users[i]);
		free(data->src_users);
	}
	if (data->tgt_users) {
		for (i = 0; i < data->num_tgt_users; i++)
			if (data->tgt_users[i])
				free(data->tgt_users[i]);
		free(data->tgt_users);
	}
	if (data->classes) {
		for (i = 0; i < data->num_classes; i++)
			if (data->classes[i])
				free(data->classes[i]);
		free(data->classes);
	}
}

/* implementation of xml parser callback functions */
static void characters(void *user_data, const xmlChar *ch, int len)
{
	seaudit_filter_parser_data_t *data = (seaudit_filter_parser_data_t *)user_data;
	char *tmpstr;

	if (strncmp(ch, "\n", len) == 0)
		return;

	switch(data->state) {
	case PARSING_NONE:
		break;
	case PARSING_SRC_TYPES:
		data->src_types = (char**)realloc(data->src_types, sizeof(char*)*(data->num_src_types+1));
		data->src_types[data->num_src_types] = strndup(ch, len);
		data->num_src_types++;
		break;
	case PARSING_TGT_TYPES:
		data->tgt_types = (char**)realloc(data->tgt_types, sizeof(char*)*(data->num_tgt_types+1));
		data->tgt_types[data->num_tgt_types] = strndup(ch, len);
		data->num_tgt_types++;
		break;
	case PARSING_SRC_ROLES:
		data->src_roles = (char**)realloc(data->src_roles, sizeof(char*)*(data->num_src_roles+1));
		data->src_roles[data->num_src_roles] = strndup(ch, len);
		data->num_src_roles++;
		break;
	case PARSING_TGT_ROLES:
		data->tgt_roles = (char**)realloc(data->tgt_roles, sizeof(char*)*(data->num_tgt_roles+1));
		data->tgt_roles[data->num_tgt_roles] = strndup(ch, len);
		data->num_tgt_roles++;
		break;
	case PARSING_SRC_USERS:
		data->src_users = (char**)realloc(data->src_users, sizeof(char*)*(data->num_src_users+1));
		data->src_users[data->num_src_users] = strndup(ch, len);
		data->num_src_users++;
		break;
	case PARSING_TGT_USERS:
		data->tgt_users = (char**)realloc(data->tgt_users, sizeof(char*)*(data->num_tgt_users+1));
		data->tgt_users[data->num_tgt_users] = strndup(ch, len);
		data->num_tgt_users++;
		break;
	case PARSING_CLASSES:
		data->classes = (char**)realloc(data->classes, sizeof(char*)*(data->num_classes+1));
		data->classes[data->num_classes] = strndup(ch, len);
		data->num_classes++;
		break;
	case PARSING_EXE:
		if (data->exe)
			free(data->exe);
		data->exe = strndup(ch, len);
		break;
	case PARSING_PATH:
		if (data->path)
			free(data->path);
		data->path = strndup(ch, len);
		break;
	case PARSING_NETIF:
		if (data->netif)
			free(data->netif);
		data->netif = strndup(ch, len);
		break;
	case PARSING_IPADDR:
		if (data->ipaddr)
			free(data->ipaddr);
		data->ipaddr = strndup(ch, len);
		break;
	case PARSING_PORTS:
		tmpstr = strndup(ch, len);
		data->port = atoi(tmpstr);
		free(tmpstr);
		break;
	case PARSING_DESC:
		if (data->desc)
			free(data->desc);
		data->desc = strndup(ch, len);
	}
}

static void startElement(void *user_data, const xmlChar *name, const xmlChar **attrs)
{
	seaudit_filter_parser_data_t *data = (seaudit_filter_parser_data_t *)user_data;	

        /* set state and process attributes.
	 * attributes are passed in by name value pairs. */
	if (strcmp(name, "filter") == 0) {
		if (!attrs[0] || !attrs[1] || !attrs[2] || !attrs[3]) {
			data->state = PARSING_NONE;
			return;
		}
		if (strcmp(attrs[0], "name") == 0)
			data->name = strdup(attrs[1]);
		if (strcmp(attrs[2], "match") == 0)
			data->match = (strcmp(attrs[3], "all") == 0) ? SEAUDIT_FILTER_MATCH_ALL : SEAUDIT_FILTER_MATCH_ANY;
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
        }
}
