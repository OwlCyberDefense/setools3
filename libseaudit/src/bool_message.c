/**
 *  @file
 *  Implementation of a single boolean change log message.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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
#include <stdlib.h>
#include <string.h>

/******************** protected functions below ********************/

static void seaudit_bool_change_free(void *elem)
{
	if (elem != NULL) {
		seaudit_bool_message_change_t *b = elem;
		free(b);
	}
}

seaudit_bool_message_t *bool_message_create(void)
{
	seaudit_bool_message_t *boolm = calloc(1, sizeof(seaudit_bool_message_t));
	if (boolm == NULL) {
		return NULL;
	}
	if ((boolm->changes = apol_vector_create(seaudit_bool_change_free)) == NULL) {
		bool_message_free(boolm);
		return NULL;
	}
	return boolm;
}

int bool_change_append(seaudit_log_t * log, seaudit_bool_message_t * boolm, const char *name, int value)
{
	char *s = strdup(name);
	seaudit_bool_message_change_t *bc = NULL;
	int error;
	if (s == NULL || apol_bst_insert_and_get(log->bools, (void **)&s, NULL) < 0) {
		error = errno;
		free(s);
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	if ((bc = calloc(1, sizeof(*bc))) == NULL || apol_vector_append(boolm->changes, bc) < 0) {
		error = errno;
		free(s);
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	bc->boolean = s;
	bc->value = value;
	return 0;
}

void bool_message_free(seaudit_bool_message_t * boolm)
{
	if (boolm != NULL) {
		apol_vector_destroy(&boolm->changes);
		free(boolm);
	}
}

char *bool_message_to_string(const seaudit_message_t * msg, const char *date)
{
	seaudit_bool_message_t *boolm = msg->data.boolm;
	const char *host = msg->host;
	const char *manager = msg->manager;
	char *s = NULL, *misc_string;
	size_t len = 0;
	char *open_brace = "", *close_brace = "";
	if (apol_vector_get_size(boolm->changes) > 0) {
		open_brace = "{ ";
		close_brace = " }";
	}
	if (apol_str_appendf(&s, &len, "%s %s %s: security: committed booleans: %s", date, host, manager, open_brace) < 0) {
		return NULL;
	}
	if ((misc_string = bool_message_to_misc_string(boolm)) == NULL ||
	    apol_str_appendf(&s, &len, misc_string) < 0 || apol_str_append(&s, &len, close_brace) < 0) {
		free(misc_string);
		return NULL;
	}
	free(misc_string);
	return s;
}

char *bool_message_to_string_html(const seaudit_message_t * msg, const char *date)
{
	seaudit_bool_message_t *boolm = msg->data.boolm;
	const char *host = msg->host;
	const char *manager = msg->manager;
	char *s = NULL, *misc_string;
	size_t len = 0;
	char *open_brace = "", *close_brace = "";
	if (apol_vector_get_size(boolm->changes) > 0) {
		open_brace = "{ ";
		close_brace = " }";
	}
	if (apol_str_appendf(&s, &len,
			     "<font class=\"message_date\">%s</font> "
			     "<font class=\"host_name\">%s</font> "
			     "%s: security: committed booleans: %s", date, host, manager, open_brace) < 0) {
		return NULL;
	}
	if ((misc_string = bool_message_to_misc_string(boolm)) == NULL ||
	    apol_str_appendf(&s, &len, misc_string) < 0 || apol_str_appendf(&s, &len, "%s%s<br>", s, close_brace) < 0) {
		free(misc_string);
		return NULL;
	}
	free(misc_string);
	return s;
}

char *bool_message_to_misc_string(const seaudit_bool_message_t * boolm)
{
	char *s = NULL;
	size_t len = 0, i;
	for (i = 0; i < apol_vector_get_size(boolm->changes); i++) {
		seaudit_bool_message_change_t *bc = apol_vector_get_element(boolm->changes, i);
		if (apol_str_appendf(&s, &len, "%s%s:%d", (i == 0 ? "" : ", "), bc->boolean, bc->value) < 0) {
			return NULL;
		}
	}
	if (s == NULL) {
		return strdup("");
	}
	return s;
}
