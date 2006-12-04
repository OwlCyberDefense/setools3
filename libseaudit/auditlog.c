/* Copyright (C) 2003-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 *         Karl MacMillan <kmacmillan@tresys.com>
 *         Jeremy Stitz <jstitz@tresys.com>
 *
 * Date: October 1, 2003
 *
 * This file contains the implementation of message.h
 *
 * auditlog.c
 */

#include "auditlog.h"
#include "filters.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

const char *audit_log_field_strs[] = { "msg_field",
	"exe_field",
	"path_field",
	"dev_field",
	"src_usr_field",
	"src_role_field",
	"src_type_field",
	"tgt_usr_field",
	"tgt_role_field",
	"tgt_type_field",
	"obj_class_field",
	"perm_field",
	"inode_field",
	"ipaddr_field",
	"audit_header_field",
	"pid_field",
	"src_sid_field",
	"tgt_sid_field",
	"comm_field",
	"netif_field",
	"key_field",
	"cap_field",
	"port_field",
	"lport_field",
	"fport_field",
	"dest_field",
	"source_field",
	"laddr_field",
	"faddr_field",
	"daddr_field",
	"saddr_field",
	"src_context",
	"tgt_context",
	"name_field",
	"other_field",
	"policy_usrs_field",
	"policy_roles_field",
	"policy_types_field",
	"policy_classes_field",
	"policy_rules_field",
	"policy_binary_field",
	"boolean_num_field",
	"boolean_bool_field",
	"boolean_value_field",
	"date_field",
	"host_field"
};

int audit_log_add_malformed_msg(char *line, audit_log_t ** log)
{

	assert(line != NULL && log != NULL && *log != NULL);

	if ((*log)->malformed_msgs == NULL) {
		if (!((*log)->malformed_msgs = apol_vector_create())) {
			ERR(NULL, "%s", strerror(ENOMEM));
			return -1;
		}
	}

	/* We subtract 1 from the new size to get the correct index */
	if (apol_vector_append((*log)->malformed_msgs, (void *)line) < 0) {
		apol_vector_destroy(&(*log)->malformed_msgs, NULL);
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	return 0;
}

int audit_log_field_strs_get_index(const char *str)
{
	int i;

	for (i = 0; i < NUM_FIELDS; i++) {
		if (strcmp(str, audit_log_field_strs[i]) == 0)
			return i;
	}
	return -1;
}

const char *libseaudit_get_version(void)
{
	return LIBSEAUDIT_VERSION_STRING;
}

/*
 * dynamically create the audit log structure. */
audit_log_t *audit_log_create(void)
{
	audit_log_t *new;
	new = (audit_log_t *) malloc(sizeof(audit_log_t));
	if (new == NULL)
		goto bad;
	memset(new, 0, sizeof(audit_log_t));
	if (!(new->msg_list = apol_vector_create()))
		goto bad;

	/* New member to hold malformed messages as a list of strings */
	if (!(new->malformed_msgs = apol_vector_create()))
		goto bad;

	/* Create vectors for types/users/roles/classes found in log */
	if (!(new->classes = apol_vector_create()))
		goto bad;

	if (!(new->users = apol_vector_create()))
		goto bad;

	if (!(new->roles = apol_vector_create()))
		goto bad;

	if (!(new->types = apol_vector_create()))
		goto bad;

	if (!(new->hosts = apol_vector_create()))
		goto bad;
	apol_vector_append(new->hosts, (void **)strdup(""));

	if (!(new->bools = apol_vector_create()))
		goto bad;

	if (!(new->perms = apol_vector_create()))
		goto bad;

	return new;
      bad:
	ERR(NULL, "%s", strerror(ENOMEM));
	if (new) {
		if (new->msg_list)
			apol_vector_destroy(&new->msg_list, NULL);
		if (new->classes)
			apol_vector_destroy(&new->classes, NULL);
		if (new->users)
			apol_vector_destroy(&new->users, NULL);
		if (new->roles)
			apol_vector_destroy(&new->roles, NULL);
		if (new->types)
			apol_vector_destroy(&new->types, NULL);
		if (new->malformed_msgs)
			apol_vector_destroy(&new->malformed_msgs, NULL);
		free(new);
	}
	return NULL;
}

static msg_t *msg_create(void)
{
	msg_t *new = NULL;

	new = (msg_t *) malloc(sizeof(msg_t));
	if (new == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return NULL;
	}
	memset(new, 0, sizeof(msg_t));
	new->date_stamp = (struct tm *)malloc(sizeof(struct tm));
	if (!new->date_stamp) {
		ERR(NULL, "%s", strerror(ENOMEM));
		free(new);
		return NULL;
	}
	memset(new->date_stamp, 0, sizeof(struct tm));
	return new;
}

/*
 * dynamically create an AVC_MSG */
msg_t *avc_msg_create(void)
{
	msg_t *msg;
	avc_msg_t *new;

	msg = msg_create();
	if (!msg) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return NULL;
	}
	new = (avc_msg_t *) malloc(sizeof(avc_msg_t));
	if (new == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		msg_destroy(msg);
		return NULL;
	}
	memset(new, 0, sizeof(avc_msg_t));
	new->is_capability = FALSE;
	new->is_key = FALSE;
	new->is_inode = FALSE;
	new->is_src_con = FALSE;
	new->is_tgt_con = FALSE;
	new->is_obj_class = FALSE;
	new->is_src_sid = FALSE;
	new->is_tgt_sid = FALSE;
	new->is_pid = FALSE;
	msg->msg_type = AVC_MSG;
	msg->msg_data.avc_msg = new;
	return msg;
}

/*
 * dynamically create a LOAD_POLICY_MSG */
msg_t *load_policy_msg_create(void)
{
	msg_t *msg;
	load_policy_msg_t *new;

	msg = msg_create();
	if (!msg) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return NULL;
	}

	new = (load_policy_msg_t *) malloc(sizeof(load_policy_msg_t));
	if (new == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		msg_destroy(msg);
		return NULL;
	}
	memset(new, 0, sizeof(load_policy_msg_t));
	msg->msg_type = LOAD_POLICY_MSG;
	msg->msg_data.load_policy_msg = new;
	return msg;
}

msg_t *boolean_msg_create(void)
{
	msg_t *msg;
	boolean_msg_t *new;

	msg = msg_create();
	if (!msg) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return NULL;
	}

	new = (boolean_msg_t *) malloc(sizeof(boolean_msg_t));
	if (new == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		msg_destroy(msg);
		return NULL;
	}
	memset(new, 0, sizeof(boolean_msg_t));
	msg->msg_type = BOOLEAN_MSG;
	msg->msg_data.boolean_msg = new;
	return msg;
}

/*
 * destroy an audit log, previously created by audit_log_create */
void audit_log_destroy(audit_log_t * tmp)
{
	if (tmp == NULL)
		return;

	apol_vector_destroy(&tmp->msg_list, NULL);
	apol_vector_destroy(&tmp->malformed_msgs, NULL);
	apol_vector_destroy(&tmp->users, NULL);
	apol_vector_destroy(&tmp->classes, NULL);
	apol_vector_destroy(&tmp->roles, NULL);
	apol_vector_destroy(&tmp->types, NULL);
	apol_vector_destroy(&tmp->bools, NULL);
	apol_vector_destroy(&tmp->hosts, NULL);
	apol_vector_destroy(&tmp->perms, NULL);
	free(tmp);
}

/*
 * destroy an AVC_MSG previously created by avc_msg_create */
static void avc_msg_destroy(avc_msg_t * tmp)
{
	if (tmp == NULL)
		return;
	free(tmp->exe);
	free(tmp->path);
	free(tmp->dev);
	free(tmp->perms);
	free(tmp->comm);
	free(tmp->netif);
	free(tmp->laddr);
	free(tmp->faddr);
	free(tmp->daddr);
	free(tmp->saddr);
	free(tmp->name);
	free(tmp->ipaddr);
	free(tmp);
}

/*
 * destroy a LOAD_POLICY_MSG previously create by load_policy_msg_create */
static void load_policy_msg_destroy(load_policy_msg_t * tmp)
{
	if (tmp == NULL)
		return;
	free(tmp->binary);
	free(tmp);
}

static void boolean_msg_destroy(boolean_msg_t * tmp)
{
	if (tmp == NULL)
		return;
	free(tmp->booleans);
	free(tmp->values);
	free(tmp);
}

/*
 * destroy a message previosly created by msg_create */
void msg_destroy(msg_t * tmp)
{
	if (tmp == NULL)
		return;
	free(tmp->date_stamp);
	switch (tmp->msg_type) {
	case AVC_MSG:
		avc_msg_destroy((avc_msg_t *) tmp->msg_data.avc_msg);
		break;
	case LOAD_POLICY_MSG:
		load_policy_msg_destroy((load_policy_msg_t *) tmp->msg_data.load_policy_msg);
		break;
	case BOOLEAN_MSG:
		boolean_msg_destroy((boolean_msg_t *) tmp->msg_data.boolean_msg);
		break;
	default:
		/* this probably means that that we were called from *create funcs above */
		break;
	}
	free(tmp);
}

/*
 * set the log type, syslog or auditd
 */
void audit_log_set_log_type(audit_log_t * log, int logtype)
{
	if (!log || (logtype != AUDITLOG_SYSLOG && logtype != AUDITLOG_AUDITD))
		return;
	log->logtype = logtype;
}

int audit_log_get_log_type(audit_log_t * log)
{
	if (!log)
		return -1;
	return log->logtype;
}

/*
 * return if this log has valid years or not
 */
bool_t audit_log_has_valid_years(audit_log_t * log)
{
	if (!log)
		return FALSE;
	if (log->logtype == AUDITLOG_AUDITD)
		return TRUE;
	return FALSE;
}

/*
 * add a string to the audit log database.
 */

int audit_log_add_str(audit_log_t * log, char *string, int *id, int which)
{
	int i;
	if (string == NULL || log == NULL || which >= NUM_VECTORS)
		return -1;
	switch (which) {
	case TYPE_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->types); i++) {
			if (!strcmp(string, (char *)apol_vector_get_element(log->types, i))) {
				*id = i;
				return i;
			}
		}
		apol_vector_append(log->types, strdup(string));
		*id = apol_vector_get_size(log->types) - 1;
		break;
	case USER_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->users); i++) {
			if (!strcmp(string, (char *)apol_vector_get_element(log->users, i))) {
				*id = i;
				return i;
			}
		}
		apol_vector_append(log->users, strdup(string));
		*id = apol_vector_get_size(log->users) - 1;
		break;
	case ROLE_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->roles); i++) {
			if (!strcmp(string, (char *)apol_vector_get_element(log->roles, i))) {
				*id = i;
				return i;
			}
		}
		apol_vector_append(log->roles, (void **)strdup(string));
		*id = apol_vector_get_size(log->roles) - 1;
		break;
	case OBJ_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->classes); i++) {
			if (!strcmp(string, (char *)apol_vector_get_element(log->classes, i))) {
				*id = i;
				return i;
			}
		}
		apol_vector_append(log->classes, strdup(string));
		*id = apol_vector_get_size(log->classes) - 1;
		break;
	case PERM_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->perms); i++) {
			if (!strcmp(string, (char *)apol_vector_get_element(log->perms, i))) {
				*id = i;
				return i;
			}
		}
		apol_vector_append(log->perms, strdup(string));
		*id = apol_vector_get_size(log->perms) - 1;
		break;
	case HOST_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->hosts); i++) {
			if (!strcmp(string, (char *)apol_vector_get_element(log->hosts, i))) {
				*id = i;
				return i;
			}
		}
		apol_vector_append(log->hosts, strdup(string));
		*id = apol_vector_get_size(log->hosts) - 1;
		break;
	case BOOL_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->bools); i++) {
			if (!strcmp(string, (char *)apol_vector_get_element(log->bools, i))) {
				*id = i;
				return i;
			}
		}
		apol_vector_append(log->bools, strdup(string));
		*id = apol_vector_get_size(log->bools) - 1;
		break;
	default:
		/* shouldn't get here */
		assert(0);
		return -1;
	}
	return 0;
}

/*
 * get the integer handle for a string in the audit log database. */
int audit_log_get_str_idx(audit_log_t * log, const char *str, int which)
{
	int i;

	if (log == NULL || str == NULL || which >= NUM_VECTORS)
		return -1;
	switch (which) {
	case TYPE_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->types); i++) {
			char *type;
			type = apol_vector_get_element(log->types, i);
			if (!strcmp(type, str))
				return i;
		}
		break;
	case ROLE_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->roles); i++) {
			char *role;
			role = apol_vector_get_element(log->roles, i);
			if (!strcmp(role, str))
				return i;
		}
		break;
	case USER_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->users); i++) {
			char *user;
			user = apol_vector_get_element(log->users, i);
			if (!strcmp(user, str))
				return i;
		}
		break;
	case OBJ_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->classes); i++) {
			char *obj;
			obj = apol_vector_get_element(log->classes, i);
			if (!strcmp(obj, str))
				return i;
		}
		break;
	case PERM_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->perms); i++) {
			char *perm;
			perm = apol_vector_get_element(log->perms, i);
			if (!strcmp(perm, str))
				return i;
		}
		break;
	case HOST_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->hosts); i++) {
			char *host;
			host = apol_vector_get_element(log->hosts, i);
			if (!strcmp(host, str))
				return i;
		}
		break;
	case BOOL_VECTOR:
		for (i = 0; i < apol_vector_get_size(log->bools); i++) {
			char *bool;
			bool = apol_vector_get_element(log->bools, i);
			if (!strcmp(bool, str))
				return i;
		}
		break;
	}
	return -1;
}

/*
 * get a string from the audit log database, based on the integer handle. */
const char *audit_log_get_str(audit_log_t * log, int idx, int which)
{
	if (log == NULL || idx < 0)
		return NULL;
	switch (which) {
	case TYPE_VECTOR:
		return apol_vector_get_element(log->types, idx);
		break;
	case ROLE_VECTOR:
		return apol_vector_get_element(log->roles, idx);
		break;
	case USER_VECTOR:
		return apol_vector_get_element(log->users, idx);
		break;
	case OBJ_VECTOR:
		return apol_vector_get_element(log->classes, idx);
		break;
	case PERM_VECTOR:
		return apol_vector_get_element(log->perms, idx);
		break;
	case HOST_VECTOR:
		return apol_vector_get_element(log->hosts, idx);
		break;
	case BOOL_VECTOR:
		return apol_vector_get_element(log->bools, idx);
		break;
	}
	return NULL;
}

/*
 * add a message to the audit log database.  user must first dynamically create the
 * message and audit log keeps the pointer. */
int audit_log_add_msg(audit_log_t * log, msg_t * msg)
{
	if (log == NULL || msg == NULL)
		return -1;

	if (apol_vector_append(log->msg_list, (void *)msg) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	return 0;
}

enum avc_msg_class_t which_avc_msg_class(msg_t * msg)
{
	avc_msg_t *avc_msg = msg->msg_data.avc_msg;
	if (msg->msg_type != AVC_MSG)
		return AVC_AUDIT_DATA_NO_VALUE;
	if (avc_msg->dev != NULL || avc_msg->is_inode != FALSE)
		return AVC_AUDIT_DATA_FS;
	if (avc_msg->is_key != FALSE)
		return AVC_AUDIT_DATA_IPC;
	if (avc_msg->capability != -1)
		return AVC_AUDIT_DATA_CAP;
	if (avc_msg->laddr != NULL || avc_msg->faddr != NULL || avc_msg->daddr != NULL)
		return AVC_AUDIT_DATA_NET;
	return AVC_AUDIT_DATA_NO_VALUE;
}

#if 0
static void avc_msg_print(msg_t * msg, FILE * file)
{
	avc_msg_t *d = msg->msg_data.avc_msg;
	if (msg->msg_type != AVC_MSG)
		return;
	if (d->msg == AVC_DENIED)
		fprintf(file, "denied: ");
	else
		fprintf(file, "granted: ");
	fprintf(file, "pid=%d ", msg->msg_data.avc_msg->pid);
	if (d->exe)
		fprintf(file, "exe=%s ", msg->msg_data.avc_msg->exe);
	if (d->comm)
		fprintf(file, "comm=%s ", msg->msg_data.avc_msg->comm);
	if (d->name)
		fprintf(file, "name=%s ", msg->msg_data.avc_msg->comm);
	if (d->dev)
		fprintf(file, "dev=%s ", msg->msg_data.avc_msg->dev);
	if (d->netif)
		fprintf(file, "netif=%s ", msg->msg_data.avc_msg->netif);
	if (d->path)
		fprintf(file, "path=%s ", msg->msg_data.avc_msg->path);
	if (d->laddr)
		fprintf(file, "laddr=%s ", msg->msg_data.avc_msg->laddr);
	if (d->faddr)
		fprintf(file, "faddr=%s ", msg->msg_data.avc_msg->faddr);
	if (d->daddr)
		fprintf(file, "daddr=%s ", msg->msg_data.avc_msg->daddr);
	if (d->saddr)
		fprintf(file, "saddr=%s ", msg->msg_data.avc_msg->saddr);
}
#endif

void msg_print(msg_t * msg, FILE * file)
{
	printf("msg_printf() - not implemented.\n");
}
