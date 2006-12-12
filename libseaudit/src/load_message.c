/**
 *  @file load_message.c
 *  Implementation of a single policy load log message.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/******************** protected functions below ********************/

seaudit_load_message_t *load_message_create(void)
{
	return calloc(1, sizeof(seaudit_load_message_t));
}

void load_message_free(seaudit_load_message_t * msg)
{
	if (msg != NULL) {
		free(msg->binary);
		free(msg);
	}
}

char *load_message_to_string(seaudit_load_message_t * load, const char *date, const char *host)
{
	char *s = NULL;
	if (asprintf(&s,
		     "%s %s kernel: security: %d users, %d roles, %d types, %d bools\n"
		     "%s %s kernel: security: %d classes, %d rules",
		     date, host, load->users, load->roles, load->types, load->bools, date, host, load->classes, load->rules) < 0) {
		return NULL;
	}
	return s;
}

char *load_message_to_string_html(seaudit_load_message_t * load, const char *date, const char *host)
{
	char *s = NULL;
	if (asprintf(&s,
		     "<font class=\"message_date\">%s</font> "
		     "<font class=\"host_name\">%s</font> "
		     "kernel: security: %d users, %d roles, %d types, %d bools<br>\n"
		     "<font class=\"message_date\">%s</font> "
		     "<font class=\"host_name\">%s</font> "
		     "kernel: security: %d classes, %d rules<br>",
		     date, host, load->users, load->roles, load->types, load->bools, date, host, load->classes, load->rules) < 0) {
		return NULL;
	}
	return s;
}

char *load_message_to_misc_string(seaudit_load_message_t * load)
{
	char *s = NULL;
	if (asprintf(&s,
		     "users=%d roles=%d types=%d bools=%d classes=%d rules=%d",
		     load->users, load->roles, load->types, load->bools, load->classes, load->rules) < 0) {
		return NULL;
	}
	return s;
}
