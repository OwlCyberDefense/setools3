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

seaudit_bool_message_t *bool_message_create(void)
{
	seaudit_bool_message_t *bool = calloc(1, sizeof(seaudit_bool_message_t));
	if (bool == NULL) {
		return NULL;
	}
	if ((bool->changes = apol_vector_create()) == NULL) {
		bool_message_free(bool);
		return NULL;
	}
	return bool;
}

int bool_change_append(seaudit_log_t * log, seaudit_bool_message_t * bool, char *name, int value)
{
	char *s = strdup(name);
	seaudit_bool_message_change_t *bc = NULL;
	int error;
	if (s == NULL || apol_bst_insert_and_get(log->bools, (void **)&s, NULL, free) < 0) {
		error = errno;
		free(s);
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	if ((bc = calloc(1, sizeof(*bc))) == NULL || apol_vector_append(bool->changes, bc) < 0) {
		error = errno;
		free(s);
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	bc->bool = s;
	bc->value = value;
	return 0;
}

static void seaudit_bool_change_free(void *elem)
{
	if (elem != NULL) {
		seaudit_bool_message_change_t *b = elem;
		free(b);
	}
}

void bool_message_free(seaudit_bool_message_t * bool)
{
	if (bool != NULL) {
		apol_vector_destroy(&bool->changes, seaudit_bool_change_free);
		free(bool);
	}
}

char *bool_message_to_string(seaudit_bool_message_t * bool, const char *date, const char *host)
{
	char *s = NULL, *misc_string;
	size_t len = 0;
	char *open_brace = "", *close_brace = "";
	if (apol_vector_get_size(bool->changes) > 0) {
		open_brace = "{ ";
		close_brace = " }";
	}
	if (apol_str_appendf(&s, &len, "%s %s kernel: security: committed booleans: %s", date, host, open_brace) < 0) {
		return NULL;
	}
	if ((misc_string = bool_message_to_misc_string(bool)) == NULL ||
	    apol_str_appendf(&s, &len, misc_string) < 0 || apol_str_append(&s, &len, close_brace) < 0) {
		free(misc_string);
		return NULL;
	}
	free(misc_string);
	return s;
}

char *bool_message_to_string_html(seaudit_bool_message_t * bool, const char *date, const char *host)
{
	char *s = NULL, *misc_string;
	size_t len = 0;
	char *open_brace = "", *close_brace = "";
	if (apol_vector_get_size(bool->changes) > 0) {
		open_brace = "{ ";
		close_brace = " }";
	}
	if (apol_str_appendf(&s, &len,
			     "<font class=\"message_date\">%s</font> "
			     "<font class=\"host_name\">%s</font> "
			     "kernel: security: committed booleans: %s", date, host, open_brace) < 0) {
		return NULL;
	}
	if ((misc_string = bool_message_to_misc_string(bool)) == NULL ||
	    apol_str_appendf(&s, &len, misc_string) < 0 || apol_str_appendf(&s, &len, "%s%s<br>", s, close_brace) < 0) {
		free(misc_string);
		return NULL;
	}
	free(misc_string);
	return s;
}

char *bool_message_to_misc_string(seaudit_bool_message_t * bool)
{
	char *s = NULL;
	size_t len = 0, i;
	for (i = 0; i < apol_vector_get_size(bool->changes); i++) {
		seaudit_bool_message_change_t *bc = apol_vector_get_element(bool->changes, i);
		if (apol_str_appendf(&s, &len, "%s%s:%d", (i == 0 ? "" : ", "), bc->bool, bc->value) < 0) {
			return NULL;
		}
	}
	if (s == NULL) {
		return strdup("");
	}
	return s;
}
