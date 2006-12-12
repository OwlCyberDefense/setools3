/**
 *  @file message.c
 *  Implementation of a single seaudit log message.  Because C does
 *  not have RTTI, fake it below.
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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void *seaudit_message_get_data(seaudit_message_t * msg, seaudit_message_type_e * type)
{
	if (type != NULL) {
		*type = SEAUDIT_MESSAGE_TYPE_INVALID;
	}
	if (msg == NULL || type == NULL || msg->type == SEAUDIT_MESSAGE_TYPE_INVALID) {
		errno = EINVAL;
		return NULL;
	}
	switch ((*type = msg->type)) {
	case SEAUDIT_MESSAGE_TYPE_AVC:
		return msg->data.avc;
	case SEAUDIT_MESSAGE_TYPE_BOOL:
		return msg->data.bool;
	case SEAUDIT_MESSAGE_TYPE_LOAD:
		return msg->data.load;
	default:
		errno = EINVAL;
		return NULL;
	}
}

struct tm *seaudit_message_get_time(seaudit_message_t * msg)
{
	if (!msg) {
		errno = EINVAL;
		return NULL;
	}
	return msg->date_stamp;
}

char *seaudit_message_get_host(seaudit_message_t * msg)
{
	if (!msg) {
		errno = EINVAL;
		return NULL;
	}
	return msg->host;
}

#define DATE_STR_SIZE 256

char *seaudit_message_to_string(seaudit_message_t * msg)
{
	char date[DATE_STR_SIZE];
	if (msg == NULL) {
		errno = EINVAL;
		return NULL;
	}
	strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", msg->date_stamp);
	switch (msg->type) {
	case SEAUDIT_MESSAGE_TYPE_AVC:
		return avc_message_to_string(msg->data.avc, date, msg->host);
	case SEAUDIT_MESSAGE_TYPE_BOOL:
		return bool_message_to_string(msg->data.bool, date, msg->host);
	case SEAUDIT_MESSAGE_TYPE_LOAD:
		return load_message_to_string(msg->data.load, date, msg->host);
	default:
		errno = EINVAL;
		return NULL;
	}
}

char *seaudit_message_to_string_html(seaudit_message_t * msg)
{
	char date[DATE_STR_SIZE];
	if (msg == NULL) {
		errno = EINVAL;
		return NULL;
	}
	strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", msg->date_stamp);
	switch (msg->type) {
	case SEAUDIT_MESSAGE_TYPE_AVC:
		return avc_message_to_string_html(msg->data.avc, date, msg->host);
	case SEAUDIT_MESSAGE_TYPE_BOOL:
		return bool_message_to_string_html(msg->data.bool, date, msg->host);
	case SEAUDIT_MESSAGE_TYPE_LOAD:
		return load_message_to_string_html(msg->data.load, date, msg->host);
	default:
		errno = EINVAL;
		return NULL;
	}
}

char *seaudit_message_to_misc_string(seaudit_message_t * msg)
{
	if (msg == NULL) {
		errno = EINVAL;
		return NULL;
	}
	switch (msg->type) {
	case SEAUDIT_MESSAGE_TYPE_AVC:
		return avc_message_to_misc_string(msg->data.avc);
	case SEAUDIT_MESSAGE_TYPE_BOOL:
		return bool_message_to_misc_string(msg->data.bool);
	case SEAUDIT_MESSAGE_TYPE_LOAD:
		return load_message_to_misc_string(msg->data.load);
	default:
		errno = EINVAL;
		return NULL;
	}
}

/******************** protected functions below ********************/

seaudit_message_t *message_create(seaudit_log_t * log, seaudit_message_type_e type)
{
	seaudit_message_t *m;
	int error, rt = 0;
	if (type == SEAUDIT_MESSAGE_TYPE_INVALID) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if ((m = calloc(1, sizeof(*m))) == NULL || apol_vector_append(log->messages, m) < 0) {
		error = errno;
		message_free(m);
		ERR(log, "%s", strerror(error));
		errno = errno;
		return NULL;
	}
	m->type = type;
	switch (m->type) {
	case SEAUDIT_MESSAGE_TYPE_AVC:
		if ((m->data.avc = avc_message_create()) == NULL) {
			rt = -1;
		}
		break;
	case SEAUDIT_MESSAGE_TYPE_BOOL:
		if ((m->data.bool = bool_message_create()) == NULL) {
			rt = -1;
		}
		break;
	case SEAUDIT_MESSAGE_TYPE_LOAD:
		if ((m->data.load = load_message_create()) == NULL) {
			rt = -1;
		}
		break;
	default:		       /* shouldn't get here */
		assert(0);
	}
	if (rt < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = errno;
		return NULL;
	}
	return m;
}

void message_free(void *msg)
{
	if (msg != NULL) {
		seaudit_message_t *m = (seaudit_message_t *) msg;
		free(m->date_stamp);
		switch (m->type) {
		case SEAUDIT_MESSAGE_TYPE_AVC:
			avc_message_free(m->data.avc);
			break;
		case SEAUDIT_MESSAGE_TYPE_BOOL:
			bool_message_free(m->data.bool);
			break;
		case SEAUDIT_MESSAGE_TYPE_LOAD:
			load_message_free(m->data.load);
			break;
		default:
			break;
		}
		free(m);
	}
}
