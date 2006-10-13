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
#include <time.h>

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
	PARSING_MSG,
	PARSING_COMM,
	PARSING_PATH,
	PARSING_NETIF,
	PARSING_IPADDR,
	PARSING_PORTS,
	PARSING_DESC,
	PARSING_HOST,
	PARSING_DATE_TIME
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

static bool_t seaudit_multifilter_parser_is_valid_name(const xmlChar *name)
{
	int i;
	xmlChar *str_xml;

	for (i = 0; parser_valid_names[i] != NULL; i++) {
		str_xml = xmlCharStrdup(parser_valid_names[i]);
		if (xmlStrcmp(str_xml, name) == 0) {
			free(str_xml);
			return TRUE;
		}
		free(str_xml);
	}
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
	case PARSING_COMM:
	case PARSING_MSG:
	case PARSING_PATH:
	case PARSING_NETIF:
	case PARSING_IPADDR:
	case PARSING_PORTS:
	case PARSING_DATE_TIME:
	case PARSING_HOST:
		if (!data->parsing_item)
			break;
	case PARSING_DESC:
		data->strs = (char**)realloc(data->strs, sizeof(char*)*((data->num_strs)+2));
		data->strs[data->num_strs] = xmlURIUnescapeString((const char *)ch, len, NULL);
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
	if (xmlStrcmp(name,(unsigned char*)"view") == 0) {
		data->multifilter = seaudit_multifilter_create();
		if (!attrs[0] || !attrs[1]) /* xmlns= */
			return;
		if (!attrs[2] || !attrs[3]) /* name= */
			return;
		if (xmlStrcmp(attrs[2], (unsigned char*)"name") == 0)
			seaudit_multifilter_set_name(data->multifilter, (const char *)attrs[3]);
		if (!attrs[4] || !attrs[4]) /* match= */
			return;
		if (xmlStrcmp(attrs[4], (unsigned char*)"match") == 0)
			seaudit_multifilter_set_match(data->multifilter,
						      (strcmp((char *)attrs[5], "all") == 0)? SEAUDIT_FILTER_MATCH_ALL : SEAUDIT_FILTER_MATCH_ANY);
		if (!attrs[6] || !attrs[7]) /* show= */
			return;
		if (xmlStrcmp(attrs[6],(unsigned char*) "show") == 0)
			seaudit_multifilter_set_show_matches(data->multifilter,
							     (strcmp((char *)attrs[7], "true") == 0)? TRUE : FALSE);
		data->is_multi = TRUE;
	} else if (xmlStrcmp(name, (unsigned char*)"filter") == 0) {
		data->cur_filter = seaudit_filter_create();
		if (!attrs[0] || !attrs[1])
			return;
		if (xmlStrcmp(attrs[0],(unsigned char*) "name") == 0) {
			unescaped = xmlURIUnescapeString((char *)attrs[1], -1, NULL);
			seaudit_filter_set_name(data->cur_filter, unescaped);
			free(unescaped);
		}

		if (!attrs[2] || !attrs[3])
			return;
		if (xmlStrcmp(attrs[2], (unsigned char*)"match") == 0) {
			if (xmlStrcmp(attrs[3],(unsigned char*) "all") == 0)
				data->cur_filter->match = SEAUDIT_FILTER_MATCH_ALL;
			else
				data->cur_filter->match = SEAUDIT_FILTER_MATCH_ANY;
		}

	} else if (xmlStrcmp(name, (unsigned char*)"desc") == 0) {
		data->state = PARSING_DESC;

	} else if (xmlStrcmp(name, (unsigned char*)"criteria") == 0) {
		if (!attrs[0] || !attrs[1] || xmlStrcmp(attrs[0], (unsigned char*)"type") != 0)
			data->state = PARSING_NONE;
		else if (xmlStrcmp(attrs[1],(unsigned char*)"src_type") == 0)
			data->state = PARSING_SRC_TYPES;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"tgt_type") == 0)
			data->state = PARSING_TGT_TYPES;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"src_user") == 0)
			data->state = PARSING_SRC_USERS;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"tgt_user") == 0)
			data->state = PARSING_TGT_USERS;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"src_role") == 0)
			data->state = PARSING_SRC_ROLES;
		else if (xmlStrcmp(attrs[1],(unsigned char*) "tgt_role") == 0)
			data->state = PARSING_TGT_ROLES;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"obj_class") == 0)
			data->state = PARSING_CLASSES;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"exe") == 0)
			data->state = PARSING_EXE;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"comm") == 0)
			data->state = PARSING_COMM;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"msg") == 0)
			data->state = PARSING_MSG;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"path") == 0)
			data->state = PARSING_PATH;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"netif") == 0)
			data->state = PARSING_NETIF;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"ipaddr") == 0)
			data->state = PARSING_IPADDR;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"port") == 0)
			data->state = PARSING_PORTS;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"host") == 0)
			data->state = PARSING_HOST;
		else if (xmlStrcmp(attrs[1], (unsigned char*)"date_time") == 0)
			data->state = PARSING_DATE_TIME;
		else
			data->state = PARSING_NONE;

        } else if (xmlStrcmp(name, (unsigned char*)"item") == 0) {
		data->parsing_item = TRUE;
	}
}

static void my_parse_endElement(void *user_data, const xmlChar *name)
{
	seaudit_multifilter_parser_data_t *data = (seaudit_multifilter_parser_data_t *)user_data;
	struct tm *t1, *t2;
	int i;

	t1 = (struct tm*)calloc(1, sizeof(struct tm));
	t2 = (struct tm*)calloc(1, sizeof(struct tm));

	if (!seaudit_multifilter_parser_is_valid_name(name))
		data->invalid_names = TRUE;

	if (xmlStrcmp(name, (unsigned char*)"desc") == 0) {
		if (data->strs[0])
			seaudit_filter_set_desc(data->cur_filter, data->strs[0]);
		seaudit_multifilter_parser_data_free(data);
		data->state = PARSING_NONE;
		return;
	}

	if (xmlStrcmp(name, (unsigned char*)"item") == 0) {
		data->parsing_item = FALSE;
		return;
	}

	if (xmlStrcmp(name, (unsigned char*)"filter") == 0) {
		seaudit_multifilter_add_filter(data->multifilter, data->cur_filter);
		data->cur_filter = NULL;
	}

	if (xmlStrcmp(name, (unsigned char*)"criteria") == 0) {
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
		case PARSING_COMM:
			if (data->strs[0])
				data->cur_filter->comm_criteria = comm_criteria_create(data->strs[0]);
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
			break;
		case PARSING_DATE_TIME:
			/* here we have the elements */
			if (data->strs[0])
				strptime(data->strs[0], "%a %b %d %T %Y", t1);
			if (data->strs[1])
				strptime(data->strs[1], "%a %b %d %T %Y", t2);
			if (data->strs[2])
				i = atoi(data->strs[2]);
			data->cur_filter->date_time_criteria = date_time_criteria_create(t1, t2, i);
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
			break;
		case PARSING_MSG:
			if (data->strs[0])
				data->cur_filter->msg_criteria = msg_criteria_create(atoi(data->strs[0]));
			seaudit_multifilter_parser_data_free(data);
			data->state = PARSING_NONE;
		}
	}
	free(t1);
	free(t2);
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

	multifilter->filters = apol_vector_create();
	multifilter->match = SEAUDIT_FILTER_MATCH_ALL;
	multifilter->name = NULL;
	multifilter->show = TRUE;
}

void seaudit_multifilter_destroy(seaudit_multifilter_t *multifilter)
{
	seaudit_filter_t *filter;
	int i;

	if (multifilter == NULL)
		return;

	for (i = 0; i < apol_vector_get_size(multifilter->filters); i++)  {
		/* free current and return next */
		filter = apol_vector_get_element(multifilter->filters, i);
		seaudit_filter_destroy(filter);
	}
	free(multifilter->filters);

	if (multifilter->name)
		free(multifilter->name);
}

void seaudit_multifilter_add_filter(seaudit_multifilter_t *multifilter, seaudit_filter_t *filter)
{
	if (multifilter == NULL || filter == NULL)
		return;

	apol_vector_append(multifilter->filters, (void *)filter);
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
	seaudit_filter_t *filter;
	int i;

	for (i = 0; i < apol_vector_get_size(multifilter->filters); i++) {
		filter = apol_vector_get_element(multifilter->filters, i);
		seaudit_filter_make_dirty_criterias(filter);
	}
}

static bool_t seaudit_multifilter_does_message_match(seaudit_multifilter_t *multifilter, msg_t *message, audit_log_t *log)
{
	seaudit_filter_t *filter;
	bool_t match = TRUE;
	int i;

	if (multifilter == NULL || message == NULL || log == NULL)
		return FALSE;

	if (!multifilter->filters)
		return TRUE;

	for (i = 0; i < apol_vector_get_size(multifilter->filters); i++) {
		filter = apol_vector_get_element(multifilter->filters, i);

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
	int i;

	if (!multifilter || !filename)
		return -1;
	file = fopen(filename, "w");
	if (!file)
		return -1;

	fprintf(file, XML_VER);
	fprintf(file, "<view xmlns=\"http://oss.tresys.com/projects/setools/seaudit-%s/\" name=\"%s\" match=\"%s\" show=\"%s\">\n",
		FILTER_FILE_FORMAT_VERSION, multifilter->name,
		multifilter->match == SEAUDIT_FILTER_MATCH_ALL? "all" : "any",
		multifilter->show == TRUE? "true" : "false");

	for (i = 0; i < apol_vector_get_size(multifilter->filters); i++) {
		filter = apol_vector_get_element(multifilter->filters, i);
		seaudit_filter_append_to_file(filter, file, 1);
	}
	fprintf(file, "</view>\n");
	fclose(file);
	return 0;
}
