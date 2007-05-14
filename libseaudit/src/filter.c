/**
 *  @file
 *  Implementation of seaudit filters.
 *
 * If adding new filter criteria, make sure you do the following:
 *
 * 0. add field(s) to seaudit_filter_t
 * 1. update filter constructor, seaudit_filter_create()
 * 2. update copy-constructor, seaudit_filter_create_from_filter()
 * 3. update destructor, seaudit_filter_destroy()
 * 4. add accessor(s) and modifier(s) as necessary
 * 5. add a record to filter_criteria table, implementing the four
 *    necessary functions.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "seaudit_internal.h"

#include <apol/util.h>

#include <errno.h>
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <libxml/uri.h>

struct seaudit_filter
{
	seaudit_filter_match_e match;
	char *name;
	char *desc;
	/** model that is watching this filter */
	seaudit_model_t *model;
	/** vector of strings, for source users */
	apol_vector_t *src_users;
	/** vector of strings, for source roles */
	apol_vector_t *src_roles;
	/** vector of strings, for source types */
	apol_vector_t *src_types;
	/** vector of strings, for target users */
	apol_vector_t *tgt_users;
	/** vector of strings, for target roles */
	apol_vector_t *tgt_roles;
	/** vector of strings, for target types */
	apol_vector_t *tgt_types;
	/** vector of strings, for target object classes */
	apol_vector_t *tgt_classes;
	/** criteria for executable, glob expression */
	char *exe;
	/** criteria for host, glob expression */
	char *host;
	/** criteria for path, glob expression */
	char *path;
	/** criteria for command, glob expression */
	char *comm;
	/** criteria for IP address, glob expression */
	char *ipaddr;
	/** criteria for port, exact match */
	int port;
	/** criteria for netif, exact match */
	char *netif;
	/** criteria for AVC message type */
	seaudit_avc_message_type_e avc_msg_type;
	struct tm *start, *end;
	seaudit_filter_date_match_e date_match;
};

seaudit_filter_t *seaudit_filter_create(const char *name)
{
	seaudit_filter_t *s = calloc(1, sizeof(*s));
	if (s == NULL) {
		return NULL;
	}
	if (name == NULL) {
		name = "Untitled";
	}
	if ((s->name = strdup(name)) == NULL) {
		int error = errno;
		seaudit_filter_destroy(&s);
		errno = error;
		return NULL;
	}
	return s;
}

seaudit_filter_t *seaudit_filter_create_from_filter(const seaudit_filter_t * filter)
{
	seaudit_filter_t *f = NULL;
	int error = 0;
	if (filter == NULL) {
		error = EINVAL;
		goto cleanup;
	}
	if ((f = seaudit_filter_create(filter->name)) == NULL || (filter->desc != NULL && (f->desc = strdup(filter->desc)) == NULL)) {
		error = errno;
		goto cleanup;
	}
	if ((filter->src_users != NULL
	     && (f->src_users = apol_vector_create_from_vector(filter->src_users, apol_str_strdup, NULL, free)) == NULL)
	    || (filter->src_roles != NULL
		&& (f->src_roles = apol_vector_create_from_vector(filter->src_roles, apol_str_strdup, NULL, free)) == NULL)
	    || (filter->src_types != NULL
		&& (f->src_types = apol_vector_create_from_vector(filter->src_types, apol_str_strdup, NULL, free)) == NULL)
	    || (filter->tgt_users != NULL
		&& (f->tgt_users = apol_vector_create_from_vector(filter->tgt_users, apol_str_strdup, NULL, free)) == NULL)
	    || (filter->tgt_roles != NULL
		&& (f->tgt_roles = apol_vector_create_from_vector(filter->tgt_roles, apol_str_strdup, NULL, free)) == NULL)
	    || (filter->tgt_types != NULL
		&& (f->tgt_types = apol_vector_create_from_vector(filter->tgt_types, apol_str_strdup, NULL, free)) == NULL)
	    || (filter->tgt_classes != NULL
		&& (f->tgt_classes = apol_vector_create_from_vector(filter->tgt_classes, apol_str_strdup, NULL, free)) == NULL)) {
		error = errno;
		goto cleanup;
	}
	if ((filter->exe != NULL && (f->exe = strdup(filter->exe)) == NULL) ||
	    (filter->host != NULL && (f->host = strdup(filter->host)) == NULL) ||
	    (filter->path != NULL && (f->path = strdup(filter->path)) == NULL) ||
	    (filter->comm != NULL && (f->comm = strdup(filter->comm)) == NULL) ||
	    (filter->ipaddr != NULL && (f->ipaddr = strdup(filter->ipaddr)) == NULL) ||
	    (filter->netif != NULL && (f->netif = strdup(filter->netif)) == NULL)) {
		error = errno;
		goto cleanup;
	}
	f->match = filter->match;
	f->port = filter->port;
	f->avc_msg_type = filter->avc_msg_type;
	if (filter->start != NULL) {
		if ((f->start = calloc(1, sizeof(*f->start))) == NULL) {
			error = errno;
			goto cleanup;
		}
		memcpy(f->start, filter->start, sizeof(*f->start));
	}
	if (filter->end != NULL) {
		if ((f->end = calloc(1, sizeof(*f->end))) == NULL) {
			error = errno;
			goto cleanup;
		}
		memcpy(f->end, filter->end, sizeof(*f->end));
	}
	f->date_match = filter->date_match;
	f->model = NULL;
      cleanup:
	if (error != 0) {
		seaudit_filter_destroy(&f);
		errno = error;
		return NULL;
	}
	return f;
}

/**
 * Callback invoked when free()ing a vector of filters.
 *
 * @param v Filter object to free.
 */
static void filter_free(void *v)
{
	seaudit_filter_t *f = v;
	seaudit_filter_destroy(&f);
}

apol_vector_t *seaudit_filter_create_from_file(const char *filename)
{
	struct filter_parse_state state;
	int retval, error;
	memset(&state, 0, sizeof(state));
	if ((state.filters = apol_vector_create(filter_free)) == NULL) {
		return NULL;
	}
	retval = filter_parse_xml(&state, filename);
	error = errno;
	free(state.view_name);
	if (retval < 0) {
		apol_vector_destroy(&state.filters);
		errno = error;
		return NULL;
	}
	return state.filters;
}

void seaudit_filter_destroy(seaudit_filter_t ** filter)
{
	if (filter != NULL && *filter != NULL) {
		free((*filter)->name);
		free((*filter)->desc);
		apol_vector_destroy(&(*filter)->src_users);
		apol_vector_destroy(&(*filter)->src_roles);
		apol_vector_destroy(&(*filter)->src_types);
		apol_vector_destroy(&(*filter)->tgt_users);
		apol_vector_destroy(&(*filter)->tgt_roles);
		apol_vector_destroy(&(*filter)->tgt_types);
		apol_vector_destroy(&(*filter)->tgt_classes);
		free((*filter)->exe);
		free((*filter)->host);
		free((*filter)->path);
		free((*filter)->comm);
		free((*filter)->ipaddr);
		free((*filter)->netif);
		free((*filter)->start);
		free((*filter)->end);
		free(*filter);
		*filter = NULL;
	}
}

int seaudit_filter_set_match(seaudit_filter_t * filter, seaudit_filter_match_e match)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	filter->match = match;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

seaudit_filter_match_e seaudit_filter_get_match(seaudit_filter_t * filter)
{
	return filter->match;
}

int seaudit_filter_set_name(seaudit_filter_t * filter, const char *name)
{
	char *new_name = NULL;
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (name != filter->name) {
		if (name != NULL && (new_name = strdup(name)) == NULL) {
			return -1;
		}
		free(filter->name);
		filter->name = new_name;;
	}
	return 0;
}

char *seaudit_filter_get_name(seaudit_filter_t * filter)
{
	return filter->name;
}

int seaudit_filter_set_description(seaudit_filter_t * filter, const char *desc)
{
	char *new_desc = NULL;
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (desc != filter->desc) {
		if (desc != NULL && (new_desc = strdup(desc)) == NULL) {
			return -1;
		}
		free(filter->desc);
		filter->desc = new_desc;
	}
	return 0;
}

char *seaudit_filter_get_description(seaudit_filter_t * filter)
{
	return filter->desc;
}

/**
 * Helper function to set a criterion's vector, by duping the vector
 * and its strings.  Dupe the vector before destroying the existing
 * one, in case v is the same as tgt.
 */
static int filter_set_vector(seaudit_filter_t * filter, apol_vector_t ** tgt, apol_vector_t * v)
{
	apol_vector_t *new_v = NULL;
	if (v != NULL) {
		if ((new_v = apol_vector_create_from_vector(v, apol_str_strdup, NULL, free)) == NULL) {
			return -1;
		}
	}
	apol_vector_destroy(tgt);
	*tgt = new_v;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

/**
 * Helper function to set a criterion string, by dupping the src
 * string.  As a check, if the pointers are already the same then do
 * nothing.
 */
static int filter_set_string(seaudit_filter_t * filter, char **dest, const char *src)
{
	if (src != *dest) {
		char *new_s = NULL;
		if (src != NULL && (new_s = strdup(src)) == NULL) {
			return -1;
		}
		free(*dest);
		*dest = new_s;
		if (filter->model != NULL) {
			model_notify_filter_changed(filter->model, filter);
		}
	}
	return 0;
}

int seaudit_filter_set_source_user(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_users, v);
}

apol_vector_t *seaudit_filter_get_source_user(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_users;
}

int seaudit_filter_set_source_role(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_roles, v);
}

apol_vector_t *seaudit_filter_get_source_role(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_roles;
}

int seaudit_filter_set_source_type(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_types, v);
}

apol_vector_t *seaudit_filter_get_source_type(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_types;
}

int seaudit_filter_set_target_user(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_users, v);
}

apol_vector_t *seaudit_filter_get_target_user(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_users;
}

int seaudit_filter_set_target_role(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_roles, v);
}

apol_vector_t *seaudit_filter_get_target_role(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_roles;
}

int seaudit_filter_set_target_type(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_types, v);
}

apol_vector_t *seaudit_filter_get_target_type(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_types;
}

int seaudit_filter_set_target_class(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_classes, v);
}

apol_vector_t *seaudit_filter_get_target_class(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_classes;
}

int seaudit_filter_set_executable(seaudit_filter_t * filter, const char *exe)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->exe, exe);
}

char *seaudit_filter_get_executable(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->exe;
}

int seaudit_filter_set_host(seaudit_filter_t * filter, const char *host)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->host, host);
}

char *seaudit_filter_get_host(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->host;
}

int seaudit_filter_set_path(seaudit_filter_t * filter, const char *path)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->path, path);
}

char *seaudit_filter_get_path(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->path;
}

int seaudit_filter_set_command(seaudit_filter_t * filter, const char *command)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->comm, command);
}

char *seaudit_filter_get_command(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->comm;
}

int seaudit_filter_set_ipaddress(seaudit_filter_t * filter, const char *ipaddr)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->ipaddr, ipaddr);
}

char *seaudit_filter_get_ipaddress(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->ipaddr;
}

int seaudit_filter_set_port(seaudit_filter_t * filter, const int port)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (port <= 0) {
		filter->port = 0;
	} else {
		filter->port = port;
	}
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

int seaudit_filter_get_port(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->port;
}

int seaudit_filter_set_netif(seaudit_filter_t * filter, const char *netif)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->netif, netif);
}

char *seaudit_filter_get_netif(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->netif;
}

int seaudit_filter_set_message_type(seaudit_filter_t * filter, const seaudit_avc_message_type_e message_type)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	filter->avc_msg_type = message_type;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

seaudit_avc_message_type_e seaudit_filter_get_message_type(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return SEAUDIT_AVC_UNKNOWN;
	}
	return filter->avc_msg_type;
}

int seaudit_filter_set_date(seaudit_filter_t * filter, const struct tm *start, const struct tm *end,
			    seaudit_filter_date_match_e date_match)
{
	struct tm *new_tm = NULL;
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	/* the following weird branching exists because start and end
	 * could be shadowing filter->start and filter->end.  if
	 * filters->start and filter->end are free()d to early, then
	 * there may be a dereference of free()d memory */
	if (filter->start != start) {
		new_tm = NULL;
		if (start != NULL) {
			if ((new_tm = calloc(1, sizeof(*new_tm))) == NULL) {
				return -1;
			}
			memcpy(new_tm, start, sizeof(*start));
		}
		free(filter->start);
		filter->start = new_tm;
	}
	if (start != NULL) {
		if (filter->end != end) {
			new_tm = NULL;
			if (end != NULL) {
				if ((new_tm = calloc(1, sizeof(*new_tm))) == NULL) {
					return -1;
				}
				memcpy(new_tm, end, sizeof(*end));
			}
			free(filter->end);
			filter->end = new_tm;
		}
	} else {
		free(filter->end);
		filter->end = NULL;
	}
	filter->date_match = date_match;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

void seaudit_filter_get_date(seaudit_filter_t * filter, struct tm **start, struct tm **end, seaudit_filter_date_match_e * match)
{
	if (start != NULL) {
		*start = NULL;
	}
	if (end != NULL) {
		*end = NULL;
	}
	if (match != NULL) {
		*match = SEAUDIT_FILTER_DATE_MATCH_BEFORE;
	}
	if (filter == NULL || start == NULL || end == NULL || match == NULL) {
		errno = EINVAL;
		return;
	}
	*start = filter->start;
	*end = filter->end;
	*match = filter->date_match;
}

/*************** filter criteria below (all are private) ***************/

static int filter_string_vector_read(apol_vector_t ** v, const xmlChar * ch)
{
	char *s;
	if (*v == NULL && (*v = apol_vector_create_with_capacity(1, free)) == NULL) {
		return -1;
	}
	if ((s = xmlURIUnescapeString((const char *)ch, 0, NULL)) == NULL || apol_vector_append(*v, s) < 0) {
		free(s);
		return -1;
	}
	return 0;
}

static int filter_string_read(char **dest, const xmlChar * ch)
{
	free(*dest);
	*dest = NULL;
	if ((*dest = xmlURIUnescapeString((const char *)ch, 0, NULL)) == NULL) {
		return -1;
	}
	return 0;
}

static void filter_string_vector_print(const char *criteria_name, apol_vector_t * v, FILE * f, int tabs)
{
	int i;
	size_t j;
	if (v == NULL) {
		return;
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", criteria_name);
	for (j = 0; j < apol_vector_get_size(v); j++) {
		xmlChar *s = xmlCharStrdup(apol_vector_get_element(v, j));
		xmlChar *escaped = xmlURIEscapeStr(s, NULL);
		for (i = 0; i < tabs + 1; i++) {
			fprintf(f, "\t");
		}
		fprintf(f, "<item>%s</item>\n", escaped);
		free(escaped);
		free(s);
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

static void filter_string_print(const char *criteria_name, const char *s, FILE * f, int tabs)
{
	int i;
	xmlChar *t, *escaped;
	if (s == NULL) {
		return;
	}
	t = xmlCharStrdup(s);
	escaped = xmlURIEscapeStr(t, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", criteria_name);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%s</item>\n", escaped);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
	free(escaped);
	free(t);
}

static int filter_src_user_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->src_users != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->suser != NULL;
}

static int filter_src_user_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->src_users, msg->data.avc->suser, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_src_user_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_vector_read(&filter->src_users, ch);
}

static void filter_src_user_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_vector_print(name, filter->src_users, f, tabs);
}

static int filter_src_role_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->src_roles != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->srole != NULL;
}

static int filter_src_role_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->src_roles, msg->data.avc->srole, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_src_role_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_vector_read(&filter->src_roles, ch);
}

static void filter_src_role_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_vector_print(name, filter->src_roles, f, tabs);
}

static int filter_src_type_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->src_types != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->stype != NULL;
}

static int filter_src_type_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_vector_read(&filter->src_types, ch);
}

static int filter_src_type_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->src_types, msg->data.avc->stype, apol_str_strcmp, NULL, &i) == 0;
}

static void filter_src_type_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_vector_print(name, filter->src_types, f, tabs);
}

static int filter_tgt_user_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->tgt_users != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tuser != NULL;
}

static int filter_tgt_user_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->tgt_users, msg->data.avc->tuser, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_tgt_user_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_vector_read(&filter->tgt_users, ch);
}

static void filter_tgt_user_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_vector_print(name, filter->tgt_users, f, tabs);
}

static int filter_tgt_role_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->tgt_roles != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->trole != NULL;
}

static int filter_tgt_role_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->tgt_roles, msg->data.avc->trole, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_tgt_role_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_vector_read(&filter->tgt_roles, ch);
}

static void filter_tgt_role_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_vector_print(name, filter->tgt_roles, f, tabs);
}

static int filter_tgt_type_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->tgt_types != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->ttype != NULL;
}

static int filter_tgt_type_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->tgt_types, msg->data.avc->ttype, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_tgt_type_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_vector_read(&filter->tgt_types, ch);
}

static void filter_tgt_type_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_vector_print(name, filter->tgt_types, f, tabs);
}

static int filter_tgt_class_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->tgt_classes != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tclass != NULL;
}

static int filter_tgt_class_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->tgt_classes, msg->data.avc->tclass, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_tgt_class_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_vector_read(&filter->tgt_classes, ch);
}

static void filter_tgt_class_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_vector_print(name, filter->tgt_classes, f, tabs);
}

static int filter_exe_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->exe != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->exe != NULL;
}

static int filter_exe_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->exe, msg->data.avc->exe, 0) == 0;
}

static int filter_exe_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->exe, ch);
}

static void filter_exe_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->exe, f, tabs);
}

static int filter_host_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->host != NULL && msg->host != NULL;
}

static int filter_host_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->host, msg->host, 0) == 0;
}

static int filter_host_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->host, ch);
}

static void filter_host_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->host, f, tabs);
}

static int filter_path_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->path != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->path != NULL;
}

static int filter_path_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->path, msg->data.avc->path, 0) == 0;
}

static int filter_path_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->path, ch);
}

static void filter_path_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->path, f, tabs);
}

static int filter_comm_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->comm != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->comm != NULL;
}

static int filter_comm_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->comm, msg->data.avc->comm, 0) == 0;
}

static int filter_comm_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->comm, ch);
}

static void filter_comm_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->comm, f, tabs);
}

static int filter_ipaddr_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->ipaddr != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && (msg->data.avc->saddr != NULL
										   || msg->data.avc->daddr != NULL
										   || msg->data.avc->faddr != NULL
										   || msg->data.avc->laddr != NULL);
}

static int filter_ipaddr_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	if (msg->data.avc->saddr && fnmatch(filter->ipaddr, msg->data.avc->saddr, 0) == 0)
		return 1;
	if (msg->data.avc->daddr && fnmatch(filter->ipaddr, msg->data.avc->daddr, 0) == 0)
		return 1;
	if (msg->data.avc->faddr && fnmatch(filter->ipaddr, msg->data.avc->faddr, 0) == 0)
		return 1;
	if (msg->data.avc->laddr && fnmatch(filter->ipaddr, msg->data.avc->laddr, 0) == 0)
		return 1;
	return 0;
}

static int filter_ipaddr_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->ipaddr, ch);
}

static void filter_ipaddr_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->ipaddr, f, tabs);
}

static int filter_port_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->port != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && (msg->data.avc->port != 0 || msg->data.avc->source != 0
									      || msg->data.avc->dest != 0
									      || msg->data.avc->fport != 0
									      || msg->data.avc->lport != 0);
}

static int filter_port_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	if (msg->data.avc->port != 0 && filter->port == msg->data.avc->port) {
		return 1;
	}
	if (msg->data.avc->source != 0 && filter->port == msg->data.avc->source) {
		return 1;
	}
	if (msg->data.avc->dest != 0 && filter->port == msg->data.avc->dest) {
		return 1;
	}
	if (msg->data.avc->fport != 0 && filter->port == msg->data.avc->fport) {
		return 1;
	}
	if (msg->data.avc->lport != 0 && filter->port == msg->data.avc->lport) {
		return 1;
	}
	return 0;
}

static int filter_port_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	char *s;
	if ((s = xmlURIUnescapeString((const char *)ch, 0, NULL)) == NULL) {
		return -1;
	}
	filter->port = atoi(s);
	free(s);
	return 0;
}

static void filter_port_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	int i;
	if (filter->port == 0) {
		return;
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", name);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%d</item>\n", filter->port);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

static int filter_netif_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->netif != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->netif != NULL;
}

static int filter_netif_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return strcmp(filter->netif, msg->data.avc->netif) == 0;
}

static int filter_netif_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->netif, ch);
}

static void filter_netif_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->netif, f, tabs);
}

static int filter_avc_msg_type_support(const seaudit_filter_t * filter, const seaudit_message_t * msg __attribute__ ((unused)))
{
	return filter->avc_msg_type != SEAUDIT_AVC_UNKNOWN;
}

static int filter_avc_msg_type_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && filter->avc_msg_type == msg->data.avc->msg;
}

static int filter_avc_msg_type_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	char *s;
	if ((s = xmlURIUnescapeString((const char *)ch, 0, NULL)) == NULL) {
		return -1;
	}
	filter->avc_msg_type = atoi(s);
	free(s);
	return 0;
}

static void filter_avc_msg_type_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	int i;
	if (filter->avc_msg_type == SEAUDIT_AVC_UNKNOWN) {
		return;
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", name);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%d</item>\n", filter->avc_msg_type);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

static int filter_date_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->start != NULL && msg->date_stamp != NULL;
}

/**
 * Given two dates compare them.  If both structs have years that are
 * not zeroes then also compare their years.
 */
static int filter_date_comp(const struct tm *t1, const struct tm *t2)
{
	/* tm has year, month, day, hour, min, sec */
	/* check if we should compare the years */
	int retval;
	if (t1->tm_year != 0 && t2->tm_year != 0 && (retval = t1->tm_year - t2->tm_year) != 0) {
		return retval;
	}
	if ((retval = t1->tm_mon - t2->tm_mon) != 0) {
		return retval;
	}
	if ((retval = t1->tm_mday - t2->tm_mday) != 0) {
		return retval;
	}
	if ((retval = t1->tm_hour - t2->tm_hour) != 0) {
		return retval;
	}
	if ((retval = t1->tm_min - t2->tm_min) != 0) {
		return retval;
	}
	if ((retval = t1->tm_sec - t2->tm_sec) != 0) {
		return retval;
	}
	return 0;
}

static int filter_date_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	int compval = filter_date_comp(filter->start, msg->date_stamp);
	if (filter->date_match == SEAUDIT_FILTER_DATE_MATCH_BEFORE) {
		return compval > 0;
	} else if (filter->date_match == SEAUDIT_FILTER_DATE_MATCH_AFTER) {
		return compval < 0;
	} else {
		if (compval > 0)
			return 0;
		compval = filter_date_comp(msg->date_stamp, filter->end);
		return compval < 0;
	}
}

static int filter_date_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	char *s;
	if ((s = xmlURIUnescapeString((const char *)ch, 0, NULL)) == NULL) {
		return -1;
	}
	if (filter->start == NULL) {
		if ((filter->start = calloc(1, sizeof(*(filter->start)))) == NULL) {
			free(s);
			return -1;
		}
		strptime(s, "%a %b %d %T %Y", filter->start);
	} else if (filter->end == NULL) {
		if ((filter->end = calloc(1, sizeof(*(filter->end)))) == NULL) {
			free(s);
			return -1;
		}
		strptime(s, "%a %b %d %T %Y", filter->end);
	} else {
		filter->date_match = atoi(s);
	}
	free(s);
	return 0;
}

static void filter_date_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	int i;
	xmlChar *s, *escaped;
	if (filter->start == NULL) {
		return;
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", name);
	s = xmlCharStrdup(asctime(filter->start));
	escaped = xmlURIEscapeStr(s, NULL);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%s</item>\n", escaped);
	free(s);
	free(escaped);
	s = xmlCharStrdup(asctime(filter->end));
	escaped = xmlURIEscapeStr(s, NULL);
	for (i = 0; i < tabs + 1; i++)
		fprintf(f, "\t");
	fprintf(f, "<item>%s</item>\n", escaped);
	free(s);
	free(escaped);
	for (i = 0; i < tabs + 1; i++)
		fprintf(f, "\t");
	fprintf(f, "<item>%d</item>\n", filter->date_match);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

typedef int (filter_support_func) (const seaudit_filter_t * filter, const seaudit_message_t * msg);
typedef int (filter_accept_func) (const seaudit_filter_t * filter, const seaudit_message_t * msg);
typedef void (filter_print_func) (const seaudit_filter_t * filter, const char *name, FILE * f, int tabs);

struct filter_criteria_t
{
	const char *name;
	filter_support_func *support;
	filter_accept_func *accept;
	filter_read_func *read;
	filter_print_func *print;
};

/**
 * Filter criteria are actually implemented as entries within this
 * function pointer table.  During filter_is_accepted() each element
 * of this table is retrieved; if the support functions returns
 * non-zero then the accept function is called.  To add new filter
 * criteria, implement their support and accept functions and then
 * append new entries to this table.
 */
static const struct filter_criteria_t filter_criteria[] = {
	{"src_user", filter_src_user_support, filter_src_user_accept, filter_src_user_read, filter_src_user_print},
	{"src_role", filter_src_role_support, filter_src_role_accept, filter_src_role_read, filter_src_role_print},
	{"src_type", filter_src_type_support, filter_src_type_accept, filter_src_type_read, filter_src_type_print},
	{"tgt_user", filter_tgt_user_support, filter_tgt_user_accept, filter_tgt_user_read, filter_tgt_user_print},
	{"tgt_role", filter_tgt_role_support, filter_tgt_role_accept, filter_tgt_role_read, filter_tgt_role_print},
	{"tgt_type", filter_tgt_type_support, filter_tgt_type_accept, filter_tgt_type_read, filter_tgt_type_print},
	{"obj_class", filter_tgt_class_support, filter_tgt_class_accept, filter_tgt_class_read, filter_tgt_class_print},
	{"exe", filter_exe_support, filter_exe_accept, filter_exe_read, filter_exe_print},
	{"host", filter_host_support, filter_host_accept, filter_host_read, filter_host_print},
	{"path", filter_path_support, filter_path_accept, filter_path_read, filter_path_print},
	{"comm", filter_comm_support, filter_comm_accept, filter_comm_read, filter_comm_print},
	{"ipaddr", filter_ipaddr_support, filter_ipaddr_accept, filter_ipaddr_read, filter_ipaddr_print},
	{"port", filter_port_support, filter_port_accept, filter_port_read, filter_port_print},
	{"netif", filter_netif_support, filter_netif_accept, filter_netif_read, filter_netif_print},
	{"msg", filter_avc_msg_type_support, filter_avc_msg_type_accept, filter_avc_msg_type_read, filter_avc_msg_type_print},
	{"date_time", filter_date_support, filter_date_accept, filter_date_read, filter_date_print}
};

int seaudit_filter_save_to_file(seaudit_filter_t * filter, const char *filename)
{
	FILE *file;
	const char *XML_VER = "<?xml version=\"1.0\"?>\n";

	if (filter == NULL || filename == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((file = fopen(filename, "w")) == NULL) {
		return -1;
	}
	fprintf(file, XML_VER);
	fprintf(file, "<view xmlns=\"http://oss.tresys.com/projects/setools/seaudit-%s/\">\n", FILTER_FILE_FORMAT_VERSION);
	filter_append_to_file(filter, file, 1);
	fprintf(file, "</view>\n");
	fclose(file);
	return 0;
}

/******************** protected functions below ********************/

void filter_set_model(seaudit_filter_t * filter, seaudit_model_t * model)
{
	filter->model = model;
}

int filter_is_accepted(seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	int tried_test = 0, acceptval;
	size_t i;
	for (i = 0; i < sizeof(filter_criteria) / sizeof(filter_criteria[0]); i++) {
		if (filter_criteria[i].support(filter, msg)) {
			tried_test = 1;
			acceptval = filter_criteria[i].accept(filter, msg);
			if (filter->match == SEAUDIT_FILTER_MATCH_ANY && acceptval) {
				return 1;
			}
			if (filter->match == SEAUDIT_FILTER_MATCH_ALL && !acceptval) {
				return 0;
			}
		}
	}
	if (!tried_test) {
		/* if got here, then the filter had no criteria --
		 * empty filters implicitly accept all */
		return 1;
	}
	if (filter->match == SEAUDIT_FILTER_MATCH_ANY) {
		/* if got here, then no criteria were met */
		return 0;
	}
	/* if got here, then all criteria were met */
	return 1;
}

static bool filter_parse_is_valid_tag(const xmlChar * tag)
{
	static const char *parse_valid_tags[] = { "item", "criteria", "view", "filter", "desc", NULL };
	size_t i;
	for (i = 0; parse_valid_tags[i] != NULL; i++) {
		if (xmlStrcmp(tag, (xmlChar *) parse_valid_tags[i]) == 0) {
			return 1;
		}
	}
	return 0;
}

static filter_read_func *filter_get_read_func(const xmlChar * name)
{
	size_t i;
	for (i = 0; i < sizeof(filter_criteria) / sizeof(filter_criteria[0]); i++) {
		if (xmlStrcmp(name, (xmlChar *) filter_criteria[i].name) == 0) {
			return filter_criteria[i].read;
		}
	}
	return NULL;
}

static void filter_parse_start_element(void *user_data, const xmlChar * name, const xmlChar ** attrs)
{
	struct filter_parse_state *state = user_data;
	size_t i;
	if (!filter_parse_is_valid_tag(name)) {
		state->warnings = 1;
		return;
	}
	if (xmlStrcmp(name, (xmlChar *) "view") == 0) {
		for (i = 0; attrs[i] != NULL && attrs[i + 1] != NULL; i += 2) {
			if (xmlStrcmp(attrs[i], (xmlChar *) "name") == 0) {
				free(state->view_name);
				state->view_name = xmlURIUnescapeString((const char *)attrs[i + 1], 0, NULL);
			} else if (xmlStrcmp(attrs[i], (xmlChar *) "match") == 0) {
				if (xmlStrcmp(attrs[i + 1], (xmlChar *) "all") == 0) {
					state->view_match = SEAUDIT_FILTER_MATCH_ALL;
				} else if (xmlStrcmp(attrs[i + 1], (xmlChar *) "any") == 0) {
					state->view_match = SEAUDIT_FILTER_MATCH_ANY;
				}
			} else if (xmlStrcmp(attrs[i], (xmlChar *) "show") == 0) {
				if (xmlStrcmp(attrs[i + 1], (xmlChar *) "true") == 0) {
					state->view_visible = SEAUDIT_FILTER_VISIBLE_SHOW;
				} else if (xmlStrcmp(attrs[i + 1], (xmlChar *) "hide") == 0) {
					state->view_visible = SEAUDIT_FILTER_VISIBLE_HIDE;
				}
			}
		}
	} else if (xmlStrcmp(name, (xmlChar *) "filter") == 0) {
		/* create a new filter and set it to be the one that is currently being parsed */
		char *filter_name = NULL;
		seaudit_filter_match_e match = SEAUDIT_FILTER_MATCH_ALL;
		for (i = 0; attrs[i] != NULL && attrs[i + 1] != NULL; i += 2) {
			if (xmlStrcmp(attrs[i], (xmlChar *) "name") == 0) {
				free(filter_name);
				filter_name = xmlURIUnescapeString((const char *)attrs[i + 1], 0, NULL);
			} else if (xmlStrcmp(attrs[i], (xmlChar *) "match") == 0) {
				if (xmlStrcmp(attrs[i + 1], (xmlChar *) "all") == 0) {
					match = SEAUDIT_FILTER_MATCH_ALL;
				} else if (xmlStrcmp(attrs[i + 1], (xmlChar *) "any") == 0) {
					match = SEAUDIT_FILTER_MATCH_ANY;
				}
			}
		}
		if ((state->cur_filter = seaudit_filter_create(filter_name)) != NULL) {
			if (apol_vector_append(state->filters, state->cur_filter) < 0) {
				seaudit_filter_destroy(&state->cur_filter);
			} else {
				seaudit_filter_set_match(state->cur_filter, match);
			}
		}
		free(filter_name);
	} else if (xmlStrcmp(name, (xmlChar *) "criteria") == 0) {
		for (i = 0; attrs[i] != NULL && attrs[i + 1] != NULL; i += 2) {
			if (xmlStrcmp(attrs[i], (xmlChar *) "type") == 0) {
				state->cur_filter_read = filter_get_read_func(attrs[i + 1]);
			}
		}
	}
	free(state->cur_string);
	state->cur_string = NULL;
}

static void filter_parse_end_element(void *user_data, const xmlChar * name)
{
	struct filter_parse_state *state = user_data;
	char *s;
	if (!filter_parse_is_valid_tag(name)) {
		state->warnings = 1;
		return;
	}
	if (xmlStrcmp(name, (xmlChar *) "desc") == 0) {
		if (state->cur_filter == NULL) {
			state->warnings = 1;
		} else {
			s = xmlURIUnescapeString((const char *)state->cur_string, 0, NULL);
			seaudit_filter_set_description(state->cur_filter, s);
			free(s);
		}
	} else if (xmlStrcmp(name, (xmlChar *) "item") == 0) {
		if (state->cur_filter == NULL || state->cur_filter_read == NULL) {
			state->warnings = 1;
		} else {
			state->cur_filter_read(state->cur_filter, state->cur_string);
		}
	} else if (xmlStrcmp(name, (xmlChar *) "filter") == 0) {
		state->cur_filter = NULL;
	} else if (xmlStrcmp(name, (xmlChar *) "criteria") == 0) {
		state->cur_filter_read = NULL;
	}
	free(state->cur_string);
	state->cur_string = NULL;
}

static void filter_parse_characters(void *user_data, const xmlChar * ch, int len)
{
	struct filter_parse_state *state = user_data;
	free(state->cur_string);
	state->cur_string = xmlStrndup(ch, len);
}

int filter_parse_xml(struct filter_parse_state *state, const char *filename)
{
	xmlSAXHandler handler;
	int err;

	memset(&handler, 0, sizeof(xmlSAXHandler));
	handler.startElement = filter_parse_start_element;
	handler.endElement = filter_parse_end_element;
	handler.characters = filter_parse_characters;
	err = xmlSAXUserParseFile(&handler, state, filename);
	free(state->cur_string);
	state->cur_string = NULL;
	if (err) {
		errno = EIO;
		return -1;
	}
	if (state->warnings) {
		return 1;
	}
	return 0;
}

void filter_append_to_file(seaudit_filter_t * filter, FILE * file, int tabs)
{
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;
	size_t j;

	if (filter == NULL || file == NULL) {
		errno = EINVAL;
		return;
	}

	if (filter->name == NULL) {
		str_xml = xmlCharStrdup("Unnamed");
	} else {
		str_xml = xmlCharStrdup(filter->name);
	}
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(file, "\t");
	fprintf(file, "<filter name=\"%s\" match=\"%s\">\n", escaped, filter->match == SEAUDIT_FILTER_MATCH_ALL ? "all" : "any");
	free(escaped);
	free(str_xml);

	if (filter->desc != NULL) {
		str_xml = xmlCharStrdup(filter->desc);
		escaped = xmlURIEscapeStr(str_xml, NULL);
		for (i = 0; i < tabs + 1; i++)
			fprintf(file, "\t");
		fprintf(file, "<desc>%s</desc>\n", escaped);
		free(escaped);
		free(str_xml);
	}
	for (j = 0; j < sizeof(filter_criteria) / sizeof(filter_criteria[0]); j++) {
		filter_criteria[j].print(filter, filter_criteria[j].name, file, tabs + 1);
	}
	for (i = 0; i < tabs; i++)
		fprintf(file, "\t");
	fprintf(file, "</filter>\n");
}
