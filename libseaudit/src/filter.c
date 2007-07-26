/**
 *  @file
 *  Implementation of seaudit filters.
 *
 * If adding new filter criteria, make sure you do the following:
 *
 * <ol>
 *   <li>add field(s) to seaudit_filter_t</li>
 *   <li>update filter constructor, seaudit_filter_create()</li>
 *   <li>update copy-constructor, seaudit_filter_create_from_filter()</li>
 *   <li>update destructor, seaudit_filter_destroy()</li>
 *   <li>add accessor(s) and modifier(s) as necessary</li>
 *   <li>add a record to filter_criteria table, implementing the four
 *       necessary functions</li>
 * </ol>
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
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
	f->strict = filter->strict;
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
	if ((filter->perm != NULL && (f->perm = strdup(filter->perm)) == NULL) ||
	    (filter->exe != NULL && (f->exe = strdup(filter->exe)) == NULL) ||
	    (filter->host != NULL && (f->host = strdup(filter->host)) == NULL) ||
	    (filter->path != NULL && (f->path = strdup(filter->path)) == NULL) ||
	    (filter->comm != NULL && (f->comm = strdup(filter->comm)) == NULL) ||
	    (filter->anyaddr != NULL && (f->anyaddr = strdup(filter->anyaddr)) == NULL) ||
	    (filter->netif != NULL && (f->netif = strdup(filter->netif)) == NULL)) {
		error = errno;
		goto cleanup;
	}
	if ((filter->laddr != NULL && (f->laddr = strdup(filter->laddr)) == NULL) ||
	    (filter->faddr != NULL && (f->faddr = strdup(filter->faddr)) == NULL) ||
	    (filter->saddr != NULL && (f->saddr = strdup(filter->saddr)) == NULL) ||
	    (filter->daddr != NULL && (f->daddr = strdup(filter->daddr)) == NULL)) {
		error = errno;
		goto cleanup;
	}
	f->match = filter->match;
	f->inode = filter->inode;
	f->pid = filter->pid;
	f->anyport = filter->anyport;
	f->lport = filter->lport;
	f->fport = filter->fport;
	f->sport = filter->sport;
	f->dport = filter->dport;
	f->port = filter->port;
	f->key = filter->key;
	f->cap = filter->cap;
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
		free((*filter)->perm);
		free((*filter)->exe);
		free((*filter)->host);
		free((*filter)->path);
		free((*filter)->comm);
		free((*filter)->anyaddr);
		free((*filter)->laddr);
		free((*filter)->faddr);
		free((*filter)->saddr);
		free((*filter)->daddr);
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

seaudit_filter_match_e seaudit_filter_get_match(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
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

const char *seaudit_filter_get_name(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
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

const char *seaudit_filter_get_description(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->desc;
}

int seaudit_filter_set_strict(seaudit_filter_t * filter, bool is_strict)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	filter->strict = is_strict;
	return 0;
}

bool seaudit_filter_get_strict(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return false;
	}
	return filter->strict;
}

/**
 * Helper function to set a criterion's vector, by duping the vector
 * and its strings.  Dupe the vector before destroying the existing
 * one, in case v is the same as tgt.
 */
static int filter_set_vector(seaudit_filter_t * filter, apol_vector_t ** tgt, const apol_vector_t * v)
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

static int filter_set_ulong(seaudit_filter_t * filter, unsigned long *dest, const ulong src)
{
	if (src != *dest) {
		*dest = src;
		if (filter->model != NULL) {
			model_notify_filter_changed(filter->model, filter);
		}
	}
	return 0;
}

static int filter_set_uint(seaudit_filter_t * filter, unsigned int *dest, const ulong src)
{
	if (src != *dest) {
		*dest = src;
		if (filter->model != NULL) {
			model_notify_filter_changed(filter->model, filter);
		}
	}
	return 0;
}

static int filter_set_int(seaudit_filter_t * filter, int *dest, const int src)
{
	int s = src;
	if (src <= 0) {
		s = 0;
	}
	if (s != *dest) {
		*dest = s;
		if (filter->model != NULL) {
			model_notify_filter_changed(filter->model, filter);
		}
	}
	return 0;
}

/******************** public accessors / modifiers ********************/

int seaudit_filter_set_source_user(seaudit_filter_t * filter, const apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_users, v);
}

const apol_vector_t *seaudit_filter_get_source_user(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_users;
}

int seaudit_filter_set_source_role(seaudit_filter_t * filter, const apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_roles, v);
}

const apol_vector_t *seaudit_filter_get_source_role(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_roles;
}

int seaudit_filter_set_source_type(seaudit_filter_t * filter, const apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_types, v);
}

const apol_vector_t *seaudit_filter_get_source_type(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_types;
}

int seaudit_filter_set_target_user(seaudit_filter_t * filter, const apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_users, v);
}

const apol_vector_t *seaudit_filter_get_target_user(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_users;
}

int seaudit_filter_set_target_role(seaudit_filter_t * filter, const apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_roles, v);
}

const apol_vector_t *seaudit_filter_get_target_role(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_roles;
}

int seaudit_filter_set_target_type(seaudit_filter_t * filter, const apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_types, v);
}

const apol_vector_t *seaudit_filter_get_target_type(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_types;
}

int seaudit_filter_set_target_class(seaudit_filter_t * filter, const apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_classes, v);
}

const apol_vector_t *seaudit_filter_get_target_class(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_classes;
}

int seaudit_filter_set_permission(seaudit_filter_t * filter, const char *perm)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->perm, perm);
}

const char *seaudit_filter_get_permission(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->perm;
}

int seaudit_filter_set_executable(seaudit_filter_t * filter, const char *exe)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->exe, exe);
}

const char *seaudit_filter_get_executable(const seaudit_filter_t * filter)
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

const char *seaudit_filter_get_host(const seaudit_filter_t * filter)
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

const char *seaudit_filter_get_path(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->path;
}

int seaudit_filter_set_inode(seaudit_filter_t * filter, unsigned long inode)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_ulong(filter, &filter->inode, inode);
	return 0;
}

unsigned long seaudit_filter_get_inode(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->inode;
}

int seaudit_filter_set_pid(seaudit_filter_t * filter, unsigned int pid)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_uint(filter, &filter->pid, pid);
	return 0;
}

unsigned int seaudit_filter_get_pid(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->pid;
}

int seaudit_filter_set_command(seaudit_filter_t * filter, const char *command)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->comm, command);
}

const char *seaudit_filter_get_command(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->comm;
}

int seaudit_filter_set_anyaddr(seaudit_filter_t * filter, const char *ipaddr)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->anyaddr, ipaddr);
}

const char *seaudit_filter_get_anyaddr(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->anyaddr;
}

int seaudit_filter_set_anyport(seaudit_filter_t * filter, const int port)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter_set_int(filter, &filter->anyport, port);
}

int seaudit_filter_get_anyport(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->anyport;
}

int filter_set_ipaddress_vers_4_1(seaudit_filter_t * filter, const char *ipaddr)
{
	return seaudit_filter_set_anyaddr(filter, ipaddr);
}

const char *filter_get_ipaddress_vers_4_1(const seaudit_filter_t * filter)
{
	return seaudit_filter_get_anyaddr(filter);
}

int filter_set_port_vers_4_1(seaudit_filter_t * filter, const int port)
{
	return seaudit_filter_set_anyport(filter, port);
}

int filter_get_port_vers_4_1(const seaudit_filter_t * filter)
{
	return seaudit_filter_get_anyport(filter);
}

#if LINK_SHARED == 1
__asm__(".symver filter_set_ipaddress_vers_4_1,seaudit_filter_set_ipaddress@VERS_4.1");
__asm__(".symver filter_get_ipaddress_vers_4_1,seaudit_filter_get_ipaddress@VERS_4.1");
__asm__(".symver filter_set_port_vers_4_1,seaudit_filter_set_port@VERS_4.1");
__asm__(".symver filter_get_port_vers_4_1,seaudit_filter_get_port@VERS_4.1");
#endif

int seaudit_filter_set_laddr(seaudit_filter_t * filter, const char *laddr)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->laddr, laddr);
}

const char *seaudit_filter_get_laddr(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->laddr;
}

int seaudit_filter_set_lport(seaudit_filter_t * filter, const int lport)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter_set_int(filter, &filter->lport, lport);
}

int seaudit_filter_get_lport(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->lport;
}

int seaudit_filter_set_faddr(seaudit_filter_t * filter, const char *faddr)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->faddr, faddr);
}

const char *seaudit_filter_get_faddr(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->faddr;
}

int seaudit_filter_set_fport(seaudit_filter_t * filter, const int fport)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter_set_int(filter, &filter->fport, fport);
}

int seaudit_filter_get_fport(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->fport;
}

int seaudit_filter_set_saddr(seaudit_filter_t * filter, const char *saddr)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->saddr, saddr);
}

const char *seaudit_filter_get_saddr(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->saddr;
}

int seaudit_filter_set_sport(seaudit_filter_t * filter, const int sport)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter_set_int(filter, &filter->sport, sport);
}

int seaudit_filter_get_sport(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->sport;
}

int seaudit_filter_set_daddr(seaudit_filter_t * filter, const char *daddr)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->daddr, daddr);
}

const char *seaudit_filter_get_daddr(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->daddr;
}

int seaudit_filter_set_dport(seaudit_filter_t * filter, const int dport)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter_set_int(filter, &filter->dport, dport);
}

int seaudit_filter_get_dport(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->dport;
}

int filter_set_port_vers_4_2(seaudit_filter_t * filter, const int port)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter_set_int(filter, &filter->port, port);
}

int filter_get_port_vers_4_2(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->port;
}

#if LINK_SHARED == 1
__asm__(".symver filter_set_port_vers_4_2,seaudit_filter_set_port@@VERS_4.2");
__asm__(".symver filter_get_port_vers_4_2,seaudit_filter_get_port@@VERS_4.2");
#endif

int seaudit_filter_set_key(seaudit_filter_t * filter, const int key)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter_set_int(filter, &filter->key, key);
}

int seaudit_filter_get_key(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->key;
}

int seaudit_filter_set_cap(seaudit_filter_t * filter, const int cap)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter_set_int(filter, &filter->cap, cap);
}

int seaudit_filter_get_cap(const seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->cap;
}

int seaudit_filter_set_netif(seaudit_filter_t * filter, const char *netif)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->netif, netif);
}

const char *seaudit_filter_get_netif(const seaudit_filter_t * filter)
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

seaudit_avc_message_type_e seaudit_filter_get_message_type(const seaudit_filter_t * filter)
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

void seaudit_filter_get_date(const seaudit_filter_t * filter, const struct tm **start, const struct tm **end,
			     seaudit_filter_date_match_e * match)
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

int seaudit_filter_save_to_file(const seaudit_filter_t * filter, const char *filename)
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
