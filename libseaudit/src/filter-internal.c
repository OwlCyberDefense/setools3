/**
 *  @file
 *  Implementation of seaudit filters private functions.
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
#include "filter-internal.h"

#include <apol/util.h>

#include <errno.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libxml/uri.h>

/******************** support functions ********************/

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

static int filter_ulong_read(unsigned long *dest, const xmlChar * ch)
{
	char *s, *endptr;
	int retval = -1;
	if ((s = xmlURIUnescapeString((const char *)ch, 0, NULL)) == NULL) {
		return -1;
	}
	*dest = strtoul(s, &endptr, 10);
	if (*s != '\0' && *endptr == '\0') {
		retval = 0;
	}
	free(s);
	return retval;
}

static unsigned int filter_uint_read(unsigned int *dest, const xmlChar * ch)
{
	char *s, *endptr;
	int retval = -1;
	if ((s = xmlURIUnescapeString((const char *)ch, 0, NULL)) == NULL) {
		return -1;
	}
	*dest = (unsigned int)(strtoul(s, &endptr, 10));
	if (*s != '\0' && *endptr == '\0') {
		retval = 0;
	}
	free(s);
	return retval;
}

static int filter_int_read(int *dest, const xmlChar * ch)
{
	char *s, *endptr;
	int retval = -1;
	if ((s = xmlURIUnescapeString((const char *)ch, 0, NULL)) == NULL) {
		return -1;
	}
	*dest = (int)(strtol(s, &endptr, 10));
	if (*s != '\0' && *endptr == '\0') {
		retval = 0;
	}
	free(s);
	return retval;
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

static void filter_ulong_print(const char *criteria_name, const unsigned long val, FILE * f, int tabs)
{
	int i;
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", criteria_name);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%lu</item>\n", val);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

static void filter_uint_print(const char *criteria_name, const unsigned int val, FILE * f, int tabs)
{
	int i;
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", criteria_name);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%u</item>\n", val);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

static void filter_int_print(const char *criteria_name, const int val, FILE * f, int tabs)
{
	int i;
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", criteria_name);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%d</item>\n", val);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

/******************** filter private functions ********************/

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

static int filter_perm_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->perm != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->perms != NULL &&
		apol_vector_get_size(msg->data.avc->perms) >= 1;
}

static int filter_perm_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	for (i = 0; i < apol_vector_get_size(msg->data.avc->perms); i++) {
		const char *p = apol_vector_get_element(msg->data.avc->perms, i);
		if (fnmatch(filter->perm, p, 0) == 0) {
			return 1;
		}
	}
	return 0;
}

static int filter_perm_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->perm, ch);
}

static void filter_perm_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->perm, f, tabs);
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

static int filter_inode_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->inode != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->is_inode;
}

static int filter_inode_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->inode == msg->data.avc->inode;
}

static int filter_inode_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_ulong_read(&filter->inode, ch);
}

static void filter_inode_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_ulong_print(name, filter->inode, f, tabs);
}

static int filter_pid_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->pid != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->is_pid;
}

static int filter_pid_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->pid == msg->data.avc->pid;
}

static int filter_pid_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_uint_read(&filter->pid, ch);
}

static void filter_pid_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_uint_print(name, filter->pid, f, tabs);
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

static int filter_anyaddr_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->anyaddr != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && (msg->data.avc->saddr != NULL
										    || msg->data.avc->daddr != NULL
										    || msg->data.avc->faddr != NULL
										    || msg->data.avc->laddr != NULL
										    || msg->data.avc->ipaddr != NULL);
}

static int filter_anyaddr_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	if (msg->data.avc->saddr && fnmatch(filter->anyaddr, msg->data.avc->saddr, 0) == 0)
		return 1;
	if (msg->data.avc->daddr && fnmatch(filter->anyaddr, msg->data.avc->daddr, 0) == 0)
		return 1;
	if (msg->data.avc->faddr && fnmatch(filter->anyaddr, msg->data.avc->faddr, 0) == 0)
		return 1;
	if (msg->data.avc->laddr && fnmatch(filter->anyaddr, msg->data.avc->laddr, 0) == 0)
		return 1;
	if (msg->data.avc->ipaddr && fnmatch(filter->anyaddr, msg->data.avc->ipaddr, 0) == 0)
		return 1;
	return 0;
}

static int filter_anyaddr_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->anyaddr, ch);
}

static void filter_anyaddr_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->anyaddr, f, tabs);
}

static int filter_anyport_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->anyport != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && (msg->data.avc->port != 0 ||
										 msg->data.avc->source != 0 ||
										 msg->data.avc->dest != 0 ||
										 msg->data.avc->fport != 0 ||
										 msg->data.avc->lport != 0);
}

static int filter_anyport_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	if (msg->data.avc->port != 0 && filter->anyport == msg->data.avc->port) {
		return 1;
	}
	if (msg->data.avc->source != 0 && filter->anyport == msg->data.avc->source) {
		return 1;
	}
	if (msg->data.avc->dest != 0 && filter->anyport == msg->data.avc->dest) {
		return 1;
	}
	if (msg->data.avc->fport != 0 && filter->anyport == msg->data.avc->fport) {
		return 1;
	}
	if (msg->data.avc->lport != 0 && filter->anyport == msg->data.avc->lport) {
		return 1;
	}
	return 0;
}

static int filter_anyport_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_int_read(&filter->anyport, ch);
}

static void filter_anyport_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_int_print(name, filter->anyport, f, tabs);
}

static int filter_laddr_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->laddr != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->laddr != NULL;
}

static int filter_laddr_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->laddr, msg->data.avc->laddr, 0) == 0;
}

static int filter_laddr_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->laddr, ch);
}

static void filter_laddr_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->laddr, f, tabs);
}

static int filter_lport_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->lport != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->lport != 0;
}

static int filter_lport_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->lport == msg->data.avc->lport;
}

static int filter_lport_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_int_read(&filter->lport, ch);
}

static void filter_lport_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_int_print(name, filter->lport, f, tabs);
}

static int filter_faddr_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->faddr != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->faddr != NULL;
}

static int filter_faddr_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->faddr, msg->data.avc->faddr, 0) == 0;
}

static int filter_faddr_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->faddr, ch);
}

static void filter_faddr_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->faddr, f, tabs);
}

static int filter_fport_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->fport != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->fport != 0;
}

static int filter_fport_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->fport == msg->data.avc->fport;
}

static int filter_fport_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_int_read(&filter->fport, ch);
}

static void filter_fport_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_int_print(name, filter->fport, f, tabs);
}

static int filter_saddr_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->saddr != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->saddr != NULL;
}

static int filter_saddr_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->saddr, msg->data.avc->saddr, 0) == 0;
}

static int filter_saddr_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->saddr, ch);
}

static void filter_saddr_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->saddr, f, tabs);
}

static int filter_sport_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->sport != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->source != 0;
}

static int filter_sport_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->sport == msg->data.avc->source;
}

static int filter_sport_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_int_read(&filter->sport, ch);
}

static void filter_sport_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_int_print(name, filter->sport, f, tabs);
}

static int filter_daddr_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->daddr != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->daddr != NULL;
}

static int filter_daddr_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->daddr, msg->data.avc->daddr, 0) == 0;
}

static int filter_daddr_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_string_read(&filter->daddr, ch);
}

static void filter_daddr_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_string_print(name, filter->daddr, f, tabs);
}

static int filter_dport_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->dport != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->dest != 0;
}

static int filter_dport_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->dport == msg->data.avc->dest;
}

static int filter_dport_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_int_read(&filter->dport, ch);
}

static void filter_dport_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_int_print(name, filter->dport, f, tabs);
}

static int filter_port_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->port != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->port != 0;
}

static int filter_port_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->port == msg->data.avc->port;
}

static int filter_port_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_int_read(&filter->port, ch);
}

static void filter_port_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_int_print(name, filter->port, f, tabs);
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

static int filter_key_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->key != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->is_key;
}

static int filter_key_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->key == msg->data.avc->key;
}

static int filter_key_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_int_read(&filter->key, ch);
}

static void filter_key_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_int_print(name, filter->key, f, tabs);
}

static int filter_cap_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->cap != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->is_capability;
}

static int filter_cap_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->key == msg->data.avc->capability;
}

static int filter_cap_read(seaudit_filter_t * filter, const xmlChar * ch)
{
	return filter_int_read(&filter->cap, ch);
}

static void filter_cap_print(const seaudit_filter_t * filter, const char *name, FILE * f, int tabs)
{
	filter_int_print(name, filter->cap, f, tabs);
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
	{"perm", filter_perm_support, filter_perm_accept, filter_perm_read, filter_perm_print},
	{"exe", filter_exe_support, filter_exe_accept, filter_exe_read, filter_exe_print},
	{"host", filter_host_support, filter_host_accept, filter_host_read, filter_host_print},
	{"path", filter_path_support, filter_path_accept, filter_path_read, filter_path_print},
	{"inode", filter_inode_support, filter_inode_accept, filter_inode_read, filter_inode_print},
	{"pid", filter_pid_support, filter_pid_accept, filter_pid_read, filter_pid_print},
	{"comm", filter_comm_support, filter_comm_accept, filter_comm_read, filter_comm_print},
	{"ipaddr", filter_anyaddr_support, filter_anyaddr_accept, filter_anyaddr_read, filter_anyaddr_print},
	{"port", filter_anyport_support, filter_anyport_accept, filter_anyport_read, filter_anyport_print},
	{"laddr", filter_laddr_support, filter_laddr_accept, filter_laddr_read, filter_laddr_print},
	{"lport", filter_lport_support, filter_lport_accept, filter_lport_read, filter_lport_print},
	{"faddr", filter_faddr_support, filter_faddr_accept, filter_faddr_read, filter_faddr_print},
	{"fport", filter_fport_support, filter_fport_accept, filter_fport_read, filter_fport_print},
	{"saddr", filter_saddr_support, filter_saddr_accept, filter_saddr_read, filter_saddr_print},
	{"sport", filter_sport_support, filter_sport_accept, filter_sport_read, filter_sport_print},
	{"daddr", filter_daddr_support, filter_daddr_accept, filter_daddr_read, filter_daddr_print},
	{"dport", filter_dport_support, filter_dport_accept, filter_dport_read, filter_dport_print},
	{"port", filter_port_support, filter_port_accept, filter_port_read, filter_port_print},
	{"netif", filter_netif_support, filter_netif_accept, filter_netif_read, filter_netif_print},
	{"key", filter_key_support, filter_key_accept, filter_key_read, filter_key_print},
	{"cap", filter_cap_support, filter_cap_accept, filter_cap_read, filter_cap_print},
	{"msg", filter_avc_msg_type_support, filter_avc_msg_type_accept, filter_avc_msg_type_read, filter_avc_msg_type_print},
	{"date_time", filter_date_support, filter_date_accept, filter_date_read, filter_date_print}
};

/******************** protected functions below ********************/

int filter_is_accepted(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	bool tried_test = false;
	int acceptval;
	size_t i;
	for (i = 0; i < sizeof(filter_criteria) / sizeof(filter_criteria[0]); i++) {
		if (filter_criteria[i].support(filter, msg)) {
			tried_test = true;
			acceptval = filter_criteria[i].accept(filter, msg);
		} else if (filter->strict) {
			/* if filter is being strict, then any unsupported
			   criterion is assumed to not match */
			acceptval = 0;
		} else {
			/* for unstrict filters, unsupported criterion is
			   assumed to be a don't care state */
			acceptval = -1;
		}
		if (filter->match == SEAUDIT_FILTER_MATCH_ANY && acceptval == 1) {
			return 1;
		}
		if (filter->match == SEAUDIT_FILTER_MATCH_ALL && acceptval == 0) {
			return 0;
		}
	}
	if (!tried_test) {
		/* if got here, then the filter had no supported criterion */
		if (filter->strict) {
			return 0;
		}
		return 1;
	}
	if (filter->match == SEAUDIT_FILTER_MATCH_ANY) {
		/* if got here, then no criterion was met */
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
		bool strict = false;
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
			} else if (xmlStrcmp(attrs[i], (xmlChar *) "strict") == 0) {
				if (xmlStrcmp(attrs[i + 1], (xmlChar *) "true") == 0) {
					strict = true;
				} else if (xmlStrcmp(attrs[i + 1], (xmlChar *) "false") == 0) {
					strict = false;
				}
			}
		}
		if ((state->cur_filter = seaudit_filter_create(filter_name)) != NULL) {
			if (apol_vector_append(state->filters, state->cur_filter) < 0) {
				seaudit_filter_destroy(&state->cur_filter);
			} else {
				seaudit_filter_set_match(state->cur_filter, match);
				seaudit_filter_set_strict(state->cur_filter, strict);
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

void filter_append_to_file(const seaudit_filter_t * filter, FILE * file, int tabs)
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
	fprintf(file, "<filter name=\"%s\" match=\"%s\" strict=\"%s\">\n", escaped,
		filter->match == SEAUDIT_FILTER_MATCH_ALL ? "all" : "any", filter->strict ? "true" : "false");
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
