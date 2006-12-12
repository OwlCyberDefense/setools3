/**
 *  @file avc_message.c
 *  Implementation of a single avc log message.
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

#include <apol/util.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

seaudit_avc_message_type_e seaudit_avc_message_get_message_type(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return SEAUDIT_AVC_UNKNOWN;
	}
	return avc->msg;
}

char *seaudit_avc_message_get_source_user(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->suser;
}

char *seaudit_avc_message_get_source_role(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->srole;
}

char *seaudit_avc_message_get_source_type(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->stype;
}

char *seaudit_avc_message_get_target_user(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->tuser;
}

char *seaudit_avc_message_get_target_role(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->trole;
}

char *seaudit_avc_message_get_target_type(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->ttype;
}

char *seaudit_avc_message_get_object_class(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->tclass;
}

apol_vector_t *seaudit_avc_message_get_perm(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->perms;
}

char *seaudit_avc_message_get_exe(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->exe;
}

char *seaudit_avc_message_get_comm(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->comm;
}

unsigned int seaudit_avc_message_get_pid(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return 0;
	}
	if (!avc->is_pid) {
		return 0;
	}
	return avc->pid;
}

unsigned long seaudit_avc_message_get_inode(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return 0;
	}
	if (!avc->is_inode) {
		return 0;
	}
	return avc->inode;
}

char *seaudit_avc_message_get_path(seaudit_avc_message_t * avc)
{
	if (avc == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return avc->path;
}

/******************** protected functions below ********************/

seaudit_avc_message_t *avc_message_create(void)
{
	seaudit_avc_message_t *avc = calloc(1, sizeof(seaudit_avc_message_t));
	if (avc == NULL) {
		return NULL;
	}
	if ((avc->perms = apol_vector_create_with_capacity(1)) == NULL) {
		int error = errno;
		avc_message_free(avc);
		errno = error;
		return NULL;
	}
	return avc;
}

void avc_message_free(seaudit_avc_message_t * avc)
{
	if (avc != NULL) {
		free(avc->exe);
		free(avc->comm);
		free(avc->path);
		free(avc->dev);
		free(avc->netif);
		free(avc->laddr);
		free(avc->faddr);
		free(avc->saddr);
		free(avc->daddr);
		free(avc->name);
		free(avc->ipaddr);
		apol_vector_destroy(&avc->perms, NULL);
		free(avc);
	}
}

/**
 * Build the misc string sans timestamp and serial number.
 */
static char *avc_message_get_misc_string(seaudit_avc_message_t * avc)
{
	char *s = NULL;
	size_t len = 0;
	if (avc->dev && apol_str_appendf(&s, &len, "dev=%s ", avc->dev) < 0) {
		return NULL;
	}
	if (avc->ipaddr && apol_str_appendf(&s, &len, "ipaddr=%s ", avc->ipaddr) < 0) {
		return NULL;
	}
	if (avc->laddr && apol_str_appendf(&s, &len, "laddr=%s ", avc->laddr) < 0) {
		return NULL;
	}
	if (avc->lport != 0 && apol_str_appendf(&s, &len, "lport=%d ", avc->lport) < 0) {
		return NULL;
	}
	if (avc->faddr && apol_str_appendf(&s, &len, "faddr=%s ", avc->faddr) < 0) {
		return NULL;
	}
	if (avc->fport != 0 && apol_str_appendf(&s, &len, "fport=%d ", avc->fport) < 0) {
		return NULL;
	}
	if (avc->daddr && apol_str_appendf(&s, &len, "daddr=%s ", avc->daddr) < 0) {
		return NULL;
	}
	if (avc->dest != 0 && apol_str_appendf(&s, &len, "dest=%d ", avc->dest) < 0) {
		return NULL;
	}
	if (avc->port != 0 && apol_str_appendf(&s, &len, "port=%d ", avc->port) < 0) {
		return NULL;
	}
	if (avc->saddr && apol_str_appendf(&s, &len, "saddr=%s ", avc->saddr) < 0) {
		return NULL;
	}
	if (avc->source != 0 && apol_str_appendf(&s, &len, "source=%d ", avc->source) < 0) {
		return NULL;
	}
	if (avc->netif && apol_str_appendf(&s, &len, "netif=%s ", avc->netif) < 0) {
		return NULL;
	}
	if (avc->is_key && apol_str_appendf(&s, &len, "key=%d ", avc->key) < 0) {
		return NULL;
	}
	if (avc->is_capability && apol_str_appendf(&s, &len, "capability=%d ", avc->capability) < 0) {
		return NULL;
	}
	if (s == NULL) {
		return strdup("");
	}
	return s;
}

char *avc_message_to_string(seaudit_avc_message_t * avc, const char *date, const char *host)
{
	char *s = NULL, *misc_string = NULL, *perm;
	size_t i, len = 0;
	if (apol_str_appendf(&s, &len, "%s %s kernel: ", date, host) < 0) {
		return NULL;
	}
	if (!(avc->tm_stmp_sec == 0 && avc->tm_stmp_nano == 0 && avc->serial == 0)) {
		if (apol_str_appendf(&s, &len, "audit(%lu.%03lu:%u): ", avc->tm_stmp_sec, avc->tm_stmp_nano, avc->serial) < 0) {
			return NULL;
		}
	}
	if (apol_str_appendf(&s, &len,
			     "avc: %s ",
			     (avc->msg == SEAUDIT_AVC_DENIED ? "denied" :
			      avc->msg == SEAUDIT_AVC_GRANTED ? "granted" : "<unknown>")) < 0) {
		return NULL;
	}

	if (apol_vector_get_size(avc->perms) > 0) {
		if (apol_str_append(&s, &len, "{ ") < 0) {
			return NULL;
		}
		for (i = 0; i < apol_vector_get_size(avc->perms); i++) {
			perm = apol_vector_get_element(avc->perms, i);
			if (apol_str_appendf(&s, &len, "%s ", perm) < 0) {
				return NULL;
			}
		}
		if (apol_str_append(&s, &len, "} for ") < 0) {
			return NULL;
		}
	}
	if (avc->is_pid && apol_str_appendf(&s, &len, "pid=%d ", avc->pid) < 0) {
		return NULL;
	}
	if (avc->exe && apol_str_appendf(&s, &len, "exe=%s ", avc->exe) < 0) {
		return NULL;
	}
	if (avc->path && apol_str_appendf(&s, &len, "path=%s ", avc->path) < 0) {
		return NULL;
	}
	if (avc->is_inode && apol_str_appendf(&s, &len, "ino=%lu ", avc->inode) < 0) {
		return NULL;
	}
	if ((misc_string = avc_message_get_misc_string(avc)) == NULL || apol_str_append(&s, &len, misc_string) < 0) {
		int error = errno;
		free(misc_string);
		errno = error;
		return NULL;
	}
	free(misc_string);
	if (avc->suser && apol_str_appendf(&s, &len, "scontext=%s:%s:%s ", avc->suser, avc->srole, avc->stype) < 0) {
		return NULL;
	}
	if (avc->tuser && apol_str_appendf(&s, &len, "tcontext=%s:%s:%s ", avc->tuser, avc->trole, avc->ttype) < 0) {
		return NULL;
	}
	if (avc->tclass && apol_str_appendf(&s, &len, "tclass=%s ", avc->tclass) < 0) {
		return NULL;
	}
	return s;
}

char *avc_message_to_string_html(seaudit_avc_message_t * avc, const char *date, const char *host)
{
	char *s = NULL, *misc_string = NULL, *perm;
	size_t i, len = 0;
	if (apol_str_appendf(&s, &len,
			     "<font class=\"message_date\">%s</font> "
			     "<font class=\"host_name\">%s</font> " "kernel: ", date, host) < 0) {
		return NULL;
	}
	if (!(avc->tm_stmp_sec == 0 && avc->tm_stmp_nano == 0 && avc->serial == 0)) {
		if (apol_str_appendf(&s, &len,
				     "<font class=\"syscall_timestamp\">audit(%lu.%03lu:%u): </font>",
				     avc->tm_stmp_sec, avc->tm_stmp_nano, avc->serial) < 0) {
			return NULL;
		}
	}
	if (apol_str_appendf(&s, &len,
			     "avc: %s ",
			     (avc->msg == SEAUDIT_AVC_DENIED ? "<font class=\"avc_deny\">denied</font> " :
			      avc->msg == SEAUDIT_AVC_GRANTED ? "<font class=\"avc_grant\">granted</font>" : "<unknown>")) < 0) {
		return NULL;
	}

	if (apol_vector_get_size(avc->perms) > 0) {
		if (apol_str_append(&s, &len, "{ ") < 0) {
			return NULL;
		}
		for (i = 0; i < apol_vector_get_size(avc->perms); i++) {
			perm = apol_vector_get_element(avc->perms, i);
			if (apol_str_appendf(&s, &len, "%s ", perm) < 0) {
				return NULL;
			}
		}
		if (apol_str_append(&s, &len, "} for ") < 0) {
			return NULL;
		}
	}
	if (avc->is_pid && apol_str_appendf(&s, &len, "pid=%d ", avc->pid) < 0) {
		return NULL;
	}
	if (avc->exe && apol_str_appendf(&s, &len, "<font class=\"exe\">exe=%s</font> ", avc->exe) < 0) {
		return NULL;
	}
	if (avc->path && apol_str_appendf(&s, &len, "path=%s ", avc->path) < 0) {
		return NULL;
	}
	if (avc->is_inode && apol_str_appendf(&s, &len, "ino=%lu ", avc->inode) < 0) {
		return NULL;
	}
	if ((misc_string = avc_message_get_misc_string(avc)) == NULL || apol_str_append(&s, &len, misc_string) < 0) {
		int error = errno;
		free(misc_string);
		errno = error;
		return NULL;
	}
	free(misc_string);
	if (avc->suser &&
	    apol_str_appendf(&s, &len, "<font class=\"src_context\">scontext=%s:%s:%s</font> ",
			     avc->suser, avc->srole, avc->stype) < 0) {
		return NULL;
	}
	if (avc->tuser &&
	    apol_str_appendf(&s, &len, "<font class=\"tgt_context\">tcontext=%s:%s:%s</font> ",
			     avc->tuser, avc->trole, avc->ttype) < 0) {
		return NULL;
	}
	if (avc->tclass && apol_str_appendf(&s, &len, "<font class=\"obj_class\">tclass=%s</font> ", avc->tclass) < 0) {
		return NULL;
	}
	if (apol_str_appendf(&s, &len, "<br>") < 0) {
		return NULL;
	}
	return s;
}

char *avc_message_to_misc_string(seaudit_avc_message_t * avc)
{
	char *s = avc_message_get_misc_string(avc);
	size_t len;
	if (s == NULL) {
		return NULL;
	}
	len = strlen(s) + 1;
	if (!(avc->tm_stmp_sec == 0 && avc->tm_stmp_nano == 0 && avc->serial == 0)) {
		if (apol_str_appendf(&s, &len, "%stimestamp=%lu.%03lu serial=%u",
				     (len > 1 ? " " : ""), avc->tm_stmp_sec, avc->tm_stmp_nano, avc->serial) < 0) {
			return NULL;
		}
	}
	return s;
}
