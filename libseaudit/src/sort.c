/**
 *  @file
 *  Implementation of seaudit sort routines.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Jeremy Solt jsolt@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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
#include <string.h>

/**
 * Callback that compares two messages.
 */
typedef int (sort_comp_func) (const seaudit_sort_t * sort, const seaudit_message_t * a, const seaudit_message_t * b);

/**
 * Callback that returns non-zero if the sort routine can handle the
 * given message, 0 if not supported.
 */
typedef int (sort_supported_func) (const seaudit_sort_t * sort, const seaudit_message_t * m);

struct seaudit_sort
{
	const char *name;
	sort_comp_func *comp;
	sort_supported_func *support;
	int direction;
};

seaudit_sort_t *seaudit_sort_create_from_sort(const seaudit_sort_t * sort)
{
	seaudit_sort_t *s;
	if (sort == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((s = calloc(1, sizeof(*s))) == NULL) {
		return NULL;
	}
	s->name = sort->name;
	s->comp = sort->comp;
	s->support = sort->support;
	s->direction = sort->direction;
	return s;
}

void seaudit_sort_destroy(seaudit_sort_t ** sort)
{
	if (sort != NULL && *sort != NULL) {
		free(*sort);
		*sort = NULL;
	}
}

static seaudit_sort_t *sort_create(const char *name, sort_comp_func * comp, sort_supported_func support, const int direction)
{
	seaudit_sort_t *s = calloc(1, sizeof(*s));
	if (s == NULL) {
		return NULL;
	}
	s->name = name;
	s->comp = comp;
	s->support = support;
	s->direction = direction;
	return s;
}

seaudit_sort_t *sort_create_from_sort(const seaudit_sort_t * sort)
{
	if (sort == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return sort_create(sort->name, sort->comp, sort->support, sort->direction);
}

static int sort_message_type_comp(const seaudit_sort_t * sort
				  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	if (a->type != b->type) {
		return a->type - b->type;
	}
	if (a->type == SEAUDIT_MESSAGE_TYPE_AVC) {
		return a->data.avc->msg - b->data.avc->msg;
	}
	return 0;
}

static int sort_message_type_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type != SEAUDIT_MESSAGE_TYPE_INVALID;
}

seaudit_sort_t *seaudit_sort_by_message_type(const int direction)
{
	return sort_create("message_type", sort_message_type_comp, sort_message_type_support, direction);
}

/**
 * Given two dates compare them, checking to see if the dates passed
 * in have valid years and correcting if not before comparing.
 */
static int sort_date_comp(const seaudit_sort_t * sort
			  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	/* tm has year, month, day, hour, min, sec */
	/* if we should compare the years */
	struct tm *t1 = a->date_stamp;
	struct tm *t2 = b->date_stamp;
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

static int sort_date_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->date_stamp != NULL;
}

seaudit_sort_t *seaudit_sort_by_date(const int direction)
{
	return sort_create("date", sort_date_comp, sort_date_support, direction);
}

static int sort_host_comp(const seaudit_sort_t * sort
			  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->host, b->host);
}

static int sort_host_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->host != NULL;
}

seaudit_sort_t *seaudit_sort_by_host(const int direction)
{
	return sort_create("host", sort_host_comp, sort_host_support, direction);
}

static int sort_perm_comp(const seaudit_sort_t * sort
			  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	size_t i;
	return apol_vector_compare(a->data.avc->perms, b->data.avc->perms, apol_str_strcmp, NULL, &i);
}

static int sort_perm_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC &&
		msg->data.avc->perms != NULL && apol_vector_get_size(msg->data.avc->perms) >= 1;
}

seaudit_sort_t *seaudit_sort_by_permission(const int direction)
{
	return sort_create("permission", sort_perm_comp, sort_perm_support, direction);
}

static int sort_source_user_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->suser, b->data.avc->suser);
}

static int sort_source_user_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->suser != NULL;
}

seaudit_sort_t *seaudit_sort_by_source_user(const int direction)
{
	return sort_create("source_user", sort_source_user_comp, sort_source_user_support, direction);
}

static int sort_source_role_comp(const seaudit_sort_t * sort __attribute((unused)), const seaudit_message_t * a,
				 const seaudit_message_t * b)
{
	return strcmp(a->data.avc->srole, b->data.avc->srole);
}

static int sort_source_role_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->srole != NULL;
}

seaudit_sort_t *seaudit_sort_by_source_role(const int direction)
{
	return sort_create("source_role", sort_source_role_comp, sort_source_role_support, direction);
}

static int sort_source_type_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->stype, b->data.avc->stype);
}

static int sort_source_type_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->stype != NULL;
}

seaudit_sort_t *seaudit_sort_by_source_type(const int direction)
{
	return sort_create("source_type", sort_source_type_comp, sort_source_type_support, direction);
}

static int sort_source_mls_lvl_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->smls_lvl, b->data.avc->smls_lvl);
}

static int sort_source_mls_lvl_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->smls_lvl != NULL;
}

seaudit_sort_t *seaudit_sort_by_source_mls_lvl(const int direction)
{
	return sort_create("source_mls_lvl", sort_source_mls_lvl_comp, sort_source_mls_lvl_support, direction);
}

static int sort_source_mls_clr_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->smls_clr, b->data.avc->smls_clr);
}

static int sort_source_mls_clr_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->smls_clr != NULL;
}

seaudit_sort_t *seaudit_sort_by_source_mls_clr(const int direction)
{
	return sort_create("source_mls_clr", sort_source_mls_clr_comp, sort_source_mls_clr_support, direction);
}

static int sort_target_user_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->tuser, b->data.avc->tuser);
}

static int sort_target_user_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tuser != NULL;
}

seaudit_sort_t *seaudit_sort_by_target_user(const int direction)
{
	return sort_create("target_user", sort_target_user_comp, sort_target_user_support, direction);
}

static int sort_target_role_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->trole, b->data.avc->trole);
}

static int sort_target_role_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->trole != NULL;
}

seaudit_sort_t *seaudit_sort_by_target_role(const int direction)
{
	return sort_create("target_role", sort_target_role_comp, sort_target_role_support, direction);
}

static int sort_target_type_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->ttype, b->data.avc->ttype);
}

static int sort_target_type_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->ttype != NULL;
}

seaudit_sort_t *seaudit_sort_by_target_type(const int direction)
{
	return sort_create("target_type", sort_target_type_comp, sort_target_type_support, direction);
}

static int sort_target_mls_lvl_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->tmls_lvl, b->data.avc->tmls_lvl);
}

static int sort_target_mls_lvl_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tmls_lvl != NULL;
}

seaudit_sort_t *seaudit_sort_by_target_mls_lvl(const int direction)
{
	return sort_create("target_mls_lvl", sort_target_mls_lvl_comp, sort_target_mls_lvl_support, direction);
}

static int sort_target_mls_clr_comp(const seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->tmls_clr, b->data.avc->tmls_clr);
}

static int sort_target_mls_clr_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tmls_clr != NULL;
}

seaudit_sort_t *seaudit_sort_by_target_mls_clr(const int direction)
{
	return sort_create("target_mls_clr", sort_target_mls_clr_comp, sort_target_mls_clr_support, direction);
}

static int sort_object_class_comp(const seaudit_sort_t * sort
				  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->tclass, b->data.avc->tclass);
}

static int sort_object_class_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tclass != NULL;
}

seaudit_sort_t *seaudit_sort_by_object_class(const int direction)
{
	return sort_create("object_class", sort_object_class_comp, sort_object_class_support, direction);
}

static int sort_executable_comp(const seaudit_sort_t * sort
				__attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->exe, b->data.avc->exe);
}

static int sort_executable_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->exe != NULL;
}

seaudit_sort_t *seaudit_sort_by_executable(const int direction)
{
	return sort_create("executable", sort_executable_comp, sort_executable_support, direction);
}

static int sort_command_comp(const seaudit_sort_t * sort
			     __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->comm, b->data.avc->comm);
}

static int sort_command_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->comm != NULL;
}

seaudit_sort_t *seaudit_sort_by_command(const int direction)
{
	return sort_create("command", sort_command_comp, sort_command_support, direction);
}

static int sort_name_comp(const seaudit_sort_t * sort
			  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->name, b->data.avc->name);
}

static int sort_name_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->name != NULL;
}

seaudit_sort_t *seaudit_sort_by_name(const int direction)
{
	return sort_create("name", sort_name_comp, sort_name_support, direction);
}

static int sort_path_comp(const seaudit_sort_t * sort
			  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->path, b->data.avc->path);
}

static int sort_path_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->path != NULL;
}

seaudit_sort_t *seaudit_sort_by_path(const int direction)
{
	return sort_create("path", sort_path_comp, sort_path_support, direction);
}

static int sort_device_comp(const seaudit_sort_t * sort
			    __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->dev, b->data.avc->dev);
}

static int sort_device_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->dev != NULL;
}

seaudit_sort_t *seaudit_sort_by_device(const int direction)
{
	return sort_create("device", sort_device_comp, sort_device_support, direction);
}

static int sort_inode_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	/* need this logic because inodes are unsigned, so subtraction
	 * could overflow */
	if (a->data.avc->inode < b->data.avc->inode) {
		return -1;
	}
	return a->data.avc->inode - b->data.avc->inode;
}

static int sort_inode_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->inode > 0;
}

seaudit_sort_t *seaudit_sort_by_inode(const int direction)
{
	return sort_create("inode", sort_inode_comp, sort_inode_support, direction);
}

static int sort_pid_comp(const seaudit_sort_t * sort
			 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	/* need this logic because pids are unsigned, so subtraction
	 * could overflow */
	if (a->data.avc->pid < b->data.avc->pid) {
		return -1;
	}
	return a->data.avc->pid - b->data.avc->pid;
}

static int sort_pid_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->pid > 0;
}

seaudit_sort_t *seaudit_sort_by_pid(const int direction)
{
	return sort_create("pid", sort_pid_comp, sort_pid_support, direction);
}

static int sort_port_comp(const seaudit_sort_t * sort
			  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return a->data.avc->port - b->data.avc->port;
}

static int sort_port_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->port > 0;
}

seaudit_sort_t *seaudit_sort_by_port(const int direction)
{
	return sort_create("port", sort_port_comp, sort_port_support, direction);
}

static int sort_laddr_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->laddr, b->data.avc->laddr);
}

static int sort_laddr_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->laddr != NULL;
}

seaudit_sort_t *seaudit_sort_by_laddr(const int direction)
{
	return sort_create("laddr", sort_laddr_comp, sort_laddr_support, direction);
}

static int sort_lport_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return a->data.avc->lport - b->data.avc->lport;
}

static int sort_lport_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->lport > 0;
}

seaudit_sort_t *seaudit_sort_by_lport(const int direction)
{
	return sort_create("lport", sort_lport_comp, sort_lport_support, direction);
}

static int sort_faddr_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->faddr, b->data.avc->faddr);
}

static int sort_faddr_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->faddr != NULL;
}

seaudit_sort_t *seaudit_sort_by_faddr(const int direction)
{
	return sort_create("faddr", sort_faddr_comp, sort_faddr_support, direction);
}

static int sort_fport_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return a->data.avc->fport - b->data.avc->fport;
}

static int sort_fport_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->fport > 0;
}

seaudit_sort_t *seaudit_sort_by_fport(const int direction)
{
	return sort_create("fport", sort_fport_comp, sort_fport_support, direction);
}

static int sort_saddr_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->saddr, b->data.avc->saddr);
}

static int sort_saddr_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->saddr != NULL;
}

seaudit_sort_t *seaudit_sort_by_saddr(const int direction)
{
	return sort_create("saddr", sort_saddr_comp, sort_saddr_support, direction);
}

static int sort_sport_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return a->data.avc->source - b->data.avc->source;
}

static int sort_sport_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->source > 0;
}

seaudit_sort_t *seaudit_sort_by_sport(const int direction)
{
	return sort_create("sport", sort_sport_comp, sort_sport_support, direction);
}

static int sort_daddr_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->daddr, b->data.avc->daddr);
}

static int sort_daddr_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->daddr != NULL;
}

seaudit_sort_t *seaudit_sort_by_daddr(const int direction)
{
	return sort_create("daddr", sort_daddr_comp, sort_daddr_support, direction);
}

static int sort_dport_comp(const seaudit_sort_t * sort
			   __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return a->data.avc->dest - b->data.avc->dest;
}

static int sort_dport_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->dest > 0;
}

seaudit_sort_t *seaudit_sort_by_dport(const int direction)
{
	return sort_create("dport", sort_dport_comp, sort_dport_support, direction);
}

static int sort_key_comp(const seaudit_sort_t * sort
			 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return a->data.avc->key - b->data.avc->key;
}

static int sort_key_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->is_key;
}

seaudit_sort_t *seaudit_sort_by_key(const int direction)
{
	return sort_create("key", sort_key_comp, sort_key_support, direction);
}

static int sort_cap_comp(const seaudit_sort_t * sort
			 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return a->data.avc->capability - b->data.avc->capability;
}

static int sort_cap_support(const seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->is_capability;
}

seaudit_sort_t *seaudit_sort_by_cap(const int direction)
{
	return sort_create("cap", sort_cap_comp, sort_cap_support, direction);
}

/******************** protected functions below ********************/

struct sort_name_map
{
	const char *name;
	seaudit_sort_t *(*create_fn) (int);
};

static const struct sort_name_map create_map[] = {
	{"message_type", seaudit_sort_by_message_type},
	{"date", seaudit_sort_by_date},
	{"host", seaudit_sort_by_host},
	{"permission", seaudit_sort_by_permission},
	{"source_user", seaudit_sort_by_source_user},
	{"source_role", seaudit_sort_by_source_role},
	{"source_type", seaudit_sort_by_source_type},
	{"target_user", seaudit_sort_by_target_user},
	{"target_role", seaudit_sort_by_target_role},
	{"target_type", seaudit_sort_by_target_type},
	{"object_class", seaudit_sort_by_object_class},
	{"executable", seaudit_sort_by_executable},
	{"name", seaudit_sort_by_name},
	{"command", seaudit_sort_by_command},
	{"path", seaudit_sort_by_path},
	{"device", seaudit_sort_by_device},
	{"inode", seaudit_sort_by_inode},
	{"pid", seaudit_sort_by_pid},
	{"port", seaudit_sort_by_port},
	{"laddr", seaudit_sort_by_laddr},
	{"lport", seaudit_sort_by_lport},
	{"faddr", seaudit_sort_by_faddr},
	{"fport", seaudit_sort_by_fport},
	{"saddr", seaudit_sort_by_saddr},
	{"sport", seaudit_sort_by_sport},
	{"daddr", seaudit_sort_by_daddr},
	{"dport", seaudit_sort_by_dport},
	{"key", seaudit_sort_by_key},
	{"cap", seaudit_sort_by_cap},
	{NULL, NULL}
};

seaudit_sort_t *sort_create_from_name(const char *name, int direction)
{
	size_t i;
	for (i = 0; create_map[i].name != NULL; i++) {
		if (strcmp(create_map[i].name, name) == 0) {
			return create_map[i].create_fn(direction);
		}
	}
	errno = EINVAL;
	return NULL;
}

int sort_is_supported(const seaudit_sort_t * sort, const seaudit_message_t * msg)
{
	return sort->support(sort, msg);
}

int sort_comp(const seaudit_sort_t * sort, const seaudit_message_t * a, const seaudit_message_t * b)
{
	int retval = sort->comp(sort, a, b);
	return (sort->direction >= 0 ? retval : -1 * retval);
}

const char *sort_get_name(const seaudit_sort_t * sort)
{
	return sort->name;
}

int sort_get_direction(const seaudit_sort_t * sort)
{
	return sort->direction;
}
