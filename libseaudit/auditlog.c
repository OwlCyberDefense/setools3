
/* Copyright (C) 2003 Tresys Technology, LLC
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
				       "date_field" ,
                                       "host_field" };

static void audit_log_malformed_msg_list_free(audit_log_malformed_msg_list_t *list)
{
	int i;

	if (!list->list)
		return;
	for (i = 0; i < list->size; i++)
		if (list->list[i])
			free(list->list[i]);
	if (list->list)
		free(list->list);
	return;
}

int audit_log_add_malformed_msg(char *line, audit_log_t **log) {
	int idx, new_sz, strsz;
	
	assert(line != NULL && log != NULL && *log != NULL);
	strsz = strlen(line) + 1;
	new_sz = (*log)->malformed_msgs->size + 1;
	if ((*log)->malformed_msgs->list == NULL) {
		(*log)->malformed_msgs->list = (char **)malloc(sizeof(char*));
		if((*log)->malformed_msgs->list == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
	} else {
		(*log)->malformed_msgs->list = (char **)realloc((*log)->malformed_msgs->list, new_sz * sizeof(char*));
		if ((*log)->malformed_msgs->list == NULL) {
			audit_log_malformed_msg_list_free((*log)->malformed_msgs);
			fprintf(stderr, "out of memory\n");
			return -1;
		}
	}
	/* We subtract 1 from the new size to get the correct index */
	idx = new_sz - 1;
	(*log)->malformed_msgs->list[idx] = (char *)malloc(strlen((const char*)line) + 1);
	if ((*log)->malformed_msgs->list[idx] == NULL) {
		audit_log_malformed_msg_list_free((*log)->malformed_msgs);
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strncpy((*log)->malformed_msgs->list[idx], (const char*)line, strsz);
	(*log)->malformed_msgs->size = new_sz;
	
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

const char* libseaudit_get_version(void)
{
	return LIBSEAUDIT_VERSION_STRING;
}

/*
 * helper functions for the avl_tree in audit_log_t */
static int strs_compare(void *user_data, const void *a, int idx, int which)
{
	strs_t *d = &((audit_log_t*)user_data)->symbols[which];
	assert(idx < d->num_strs);
	return strcmp(d->strs[idx], (char*)a);
} 

static int strs_grow(void *user_data, int sz, int which)
{
	int prev_sz;
	strs_t *d = &((audit_log_t*)user_data)->symbols[which];

	if (sz > d->strs_sz) {
		prev_sz = d->strs_sz;
	        d->strs_sz += ARRAY_SZ;
	        d->strs = (char**)realloc(d->strs, sizeof(char*) * d->strs_sz);
		if (d->strs == NULL) {
			fprintf(stderr, "Out of memory");
		        return -1;
	        }
	        memset(&d->strs[prev_sz], 0, sizeof(char*) * ARRAY_SZ);
	}
	return 0;
}

static int strs_add(void *user_data, const void *key, int idx, int which)
{
	char *newstr;
	strs_t *d = &((audit_log_t*)user_data)->symbols[which];
	char *string = (char*)key;

	newstr = (char*)malloc(sizeof(char) * (strlen(string) + 1));
	if (newstr == NULL){
		fprintf(stderr, "Out of memory");
		return -1;
	}

	strcpy(newstr, string);
	d->strs[idx] = newstr; 
	d->num_strs++;
	return 0;
}

static int type_compare(void *user_data, const void *key, int idx)
{
	return strs_compare(user_data, key, idx, TYPE_TREE);
}

static int type_grow(void *user_data, int sz)
{
	return strs_grow(user_data, sz, TYPE_TREE);
}

static int type_add(void *user_data, const void *key, int idx)
{
	return strs_add(user_data, key, idx, TYPE_TREE);
}

static int user_compare(void *user_data, const void *key, int idx)
{
	return strs_compare(user_data, key, idx, USER_TREE);
}

static int user_grow(void *user_data, int sz)
{
	return strs_grow(user_data, sz, USER_TREE);
}

static int user_add(void *user_data, const void *key, int idx)
{
	return strs_add(user_data, key, idx, USER_TREE);
}

static int role_compare(void *user_data, const void *key, int idx)
{
	return strs_compare(user_data, key, idx, ROLE_TREE);
}

static int role_grow(void *user_data, int sz)
{
	return strs_grow(user_data, sz, ROLE_TREE);
}

static int role_add(void *user_data, const void *key, int idx)
{
	return strs_add(user_data, key, idx, ROLE_TREE);
}

static int obj_compare(void *user_data, const void *key, int idx)
{
	return strs_compare(user_data, key, idx, OBJ_TREE);
}

static int obj_grow(void *user_data, int sz)
{
	return strs_grow(user_data, sz, OBJ_TREE);
}

static int obj_add(void *user_data, const void *key, int idx)
{
	return strs_add(user_data, key, idx, OBJ_TREE);
}

static int perm_compare(void *user_data, const void *key, int idx)
{
	return strs_compare(user_data, key, idx, PERM_TREE);
}

static int perm_grow(void *user_data, int sz)
{
	return strs_grow(user_data, sz, PERM_TREE);
}

static int perm_add(void *user_data, const void *key, int idx)
{
	return strs_add(user_data, key, idx, PERM_TREE);
}

static int host_compare(void *user_data, const void *key, int idx)
{
	return strs_compare(user_data, key, idx, HOST_TREE);
}

static int host_grow(void *user_data, int sz)
{
	return strs_grow(user_data, sz, HOST_TREE);
}

static int host_add(void *user_data, const void *key, int idx)
{
	return strs_add(user_data, key, idx, HOST_TREE);
}

static int bool_compare(void *user_data, const void *key, int idx)
{
        return strs_compare(user_data, key, idx, BOOL_TREE);
}

static int bool_grow(void *user_data, int sz)
{
        return strs_grow(user_data, sz, BOOL_TREE);
}

static int bool_add(void *user_data, const void *key, int idx)
{
        return strs_add(user_data, key, idx, BOOL_TREE);
}

static int audit_log_str_init(audit_log_t *log, int which)
{

	log->symbols[which].strs = (char**)malloc(sizeof(char*) * ARRAY_SZ);

	if (log->symbols[which].strs == NULL) { 
		fprintf(stderr, "Out of memory"); 
		return -1;
	}
        memset(log->symbols[which].strs, 0, sizeof(char*) * ARRAY_SZ); 
	log->symbols[which].strs_sz = ARRAY_SZ;
	log->symbols[which].num_strs = 0;
	return 0;
}

/*
 * dynamically create the audit log structure. */
audit_log_t* audit_log_create(void) 
{
	int i;
	audit_log_t *new;
	new = (audit_log_t*)malloc(sizeof(audit_log_t));
	if (new == NULL) 
		goto bad;
	memset(new, 0, sizeof(audit_log_t));
	new->msg_list = (msg_t**)malloc(sizeof(msg_t*) * ARRAY_SZ);
	if (new->msg_list == NULL)
		goto bad;
	memset(new->msg_list, 0, sizeof(msg_t*) * ARRAY_SZ);
	new->msg_list_sz = ARRAY_SZ;
	
	if (audit_log_str_init(new, TYPE_TREE))
		goto bad;
	avl_init(&new->trees[TYPE_TREE], new, type_compare, type_grow, type_add);

	if (audit_log_str_init(new, USER_TREE))
		goto bad;
	avl_init(&new->trees[USER_TREE], new, user_compare, user_grow, user_add);

	if (audit_log_str_init(new, ROLE_TREE))
		goto bad;
	avl_init(&new->trees[ROLE_TREE], new, role_compare, role_grow, role_add);

	if (audit_log_str_init(new, OBJ_TREE))
		goto bad;
	avl_init(&new->trees[OBJ_TREE], new, obj_compare, obj_grow, obj_add);

	if (audit_log_str_init(new, PERM_TREE))
		goto bad;
	avl_init(&new->trees[PERM_TREE], new, perm_compare, perm_grow, perm_add);

	if (audit_log_str_init(new, HOST_TREE))
		goto bad;
	avl_init(&new->trees[HOST_TREE], new, host_compare, host_grow, host_add);
	if (audit_log_str_init(new, BOOL_TREE))
	        goto bad;
	avl_init(&new->trees[BOOL_TREE], new, bool_compare, bool_grow, bool_add);
	
	/* New member to hold malformed messages as a list of strings */
	new->malformed_msgs = (audit_log_malformed_msg_list_t *)malloc(sizeof(audit_log_malformed_msg_list_t));
	if (new->malformed_msgs == NULL) {
		goto bad;
	}
	memset(new->malformed_msgs, 0, sizeof(audit_log_malformed_msg_list_t));
	
	return new;

bad:
	fprintf(stderr, "Out of memory");
	if (new) {
		if (new->msg_list)
			free(new->msg_list);
		for (i = 0; i < NUM_TREES; i++) {
			if (new->symbols[i].strs)
				free(new->symbols[i].strs);
			avl_free(&new->trees[i]);
		}
		free(new);
	}
	return NULL;
}

static msg_t* msg_create(void)
{
	msg_t *new = NULL;
	
	new = (msg_t*)malloc(sizeof(msg_t));
	if (new == NULL) {
		fprintf(stderr, "Out of memory");
		return NULL;
	}
	memset(new, 0, sizeof(msg_t));
	new->host = -1;
	new->date_stamp = (struct tm*)malloc(sizeof(struct tm));
	if (!new->date_stamp) {
		fprintf(stderr, "Out of memory");
		free(new);
		return NULL;
	}
	memset(new->date_stamp, 0, sizeof(struct tm));
	return new;
}

/*
 * dynamically create an AVC_MSG */
msg_t* avc_msg_create(void)
{
	msg_t *msg;
	avc_msg_t *new;

	msg = msg_create();
	if (!msg) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	new = (avc_msg_t*)malloc(sizeof(avc_msg_t));
	if (new == NULL) {
		fprintf(stderr, "Out of memory.");
		msg_destroy(msg);
		return NULL;
	}
	memset (new, 0, sizeof(avc_msg_t));
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
msg_t* load_policy_msg_create(void)
{
	msg_t *msg;
	load_policy_msg_t *new;

	msg = msg_create();
	if (!msg) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}

	new = (load_policy_msg_t*)malloc(sizeof(load_policy_msg_t));
	if (new == NULL) {
		fprintf(stderr, "Out of memory.");
		msg_destroy(msg);
		return NULL;
	}
	memset (new, 0, sizeof(load_policy_msg_t));
	msg->msg_type = LOAD_POLICY_MSG;
	msg->msg_data.load_policy_msg = new;
	return msg;
}

msg_t* boolean_msg_create(void)
{
        msg_t *msg;
        boolean_msg_t *new;

        msg = msg_create();
        if (!msg) {
                fprintf(stderr, "Out of memory,");
                return NULL;
        }

        new = (boolean_msg_t*)malloc(sizeof(boolean_msg_t));
        if(new == NULL) {
                fprintf(stderr, "Out of memory.");
                msg_destroy(msg);
                return NULL;
        }
        memset (new, 0, sizeof(boolean_msg_t));
        msg->msg_type = BOOLEAN_MSG;
        msg->msg_data.boolean_msg = new;
        return msg;
}

/*
 * destroy an audit log, previously created by audit_log_create */
void audit_log_destroy(audit_log_t *tmp)
{
	int i, j;
	if (tmp == NULL)
		return;

	for (i = 0; i < NUM_TREES; i++) {
		if (tmp->symbols[i].strs) {
			for (j = 0; j < tmp->symbols[i].num_strs; j++) {
				if (tmp->symbols[i].strs[j] != NULL)
					free(tmp->symbols[i].strs[j]);
			}
			free(tmp->symbols[i].strs);
		}
		avl_free(&tmp->trees[i]);
	}
	for (i = 0; i < tmp->num_msgs; i++) {
		if (tmp->msg_list[i] == NULL)
			break;
		msg_destroy(tmp->msg_list[i]);
	}
	if (tmp->msg_list)
		free(tmp->msg_list);
	
	if (tmp->malformed_msgs) 
		audit_log_malformed_msg_list_free(tmp->malformed_msgs);
	
	free(tmp);
}

/*
 * destroy an AVC_MSG previously created by avc_msg_create */
static void avc_msg_destroy(avc_msg_t* tmp)
{
	if (tmp == NULL)
		return;
	if (tmp->exe)
		free(tmp->exe);
	if (tmp->path)
		free(tmp->path);
	if (tmp->dev)
		free(tmp->dev);
	if (tmp->perms)
		free(tmp->perms);
	if (tmp->comm)
		free(tmp->comm);
	if (tmp->netif)
		free(tmp->netif);
	if (tmp->laddr)
		free(tmp->laddr);
	if (tmp->faddr)
		free(tmp->faddr);
	if (tmp->daddr)
		free(tmp->daddr);
	if (tmp->saddr)
		free(tmp->saddr);
	if (tmp->name)
		free(tmp->name);
	if (tmp->ipaddr)
		free(tmp->ipaddr);
	free(tmp);
	return;
}

/*
 * destroy a LOAD_POLICY_MSG previously create by load_policy_msg_create */
static void load_policy_msg_destroy(load_policy_msg_t* tmp)
{
	if (tmp == NULL)
		return;
	if (tmp->binary)
	  free(tmp->binary);

	free(tmp);
	return;
}

static void boolean_msg_destroy(boolean_msg_t* tmp)
{
        if (tmp == NULL)
                return;
        if (tmp->booleans)
                free (tmp->booleans);
        if (tmp->values)
                free (tmp->values);
	free(tmp);
        return;
}


/*
 * destroy a message previosly created by msg_create */
void msg_destroy(msg_t* tmp)
{
	if (tmp == NULL)
		return;
	if (tmp->date_stamp)
		free(tmp->date_stamp);
	switch (tmp->msg_type) {
 	case AVC_MSG:
	 	avc_msg_destroy((avc_msg_t*)tmp->msg_data.avc_msg);
		break;
 	case LOAD_POLICY_MSG:
 		load_policy_msg_destroy((load_policy_msg_t*)tmp->msg_data.load_policy_msg);
 		break;
	case BOOLEAN_MSG:
	        boolean_msg_destroy((boolean_msg_t*)tmp->msg_data.boolean_msg);
	        break;
	default:
		/* this probably means that that we were called from *create funcs above */
		break;
 	}
 	free(tmp);
 	return;
}

/*
 * add a string to the audit log database.
 */
int audit_log_add_str(audit_log_t *log, char *string, int *id, int which)
{
	if (string == NULL || log == NULL || id == NULL || which >= NUM_TREES)
		return -1;
	return avl_insert(&log->trees[which], string, id);
}

/*
 * get the integer handle for a string in the audit log database. */
int audit_log_get_str_idx(audit_log_t *log, const char *str, int which)
{
	if (log == NULL || str == NULL || which >= NUM_TREES)
		return -1;
	return avl_get_idx(str, &log->trees[which]);
}

/*
 * get a string from the audit log database, based on the integer handle. */
const char* audit_log_get_str(audit_log_t *log, int idx, int which)
{
	if (log == NULL || idx < 0 || idx >= log->symbols[which].num_strs)
		return NULL;
	return log->symbols[which].strs[idx];
}

/*
 * add a message to the audit log database.  user must first dynamically create the 
 * message and audit log keeps the pointer. */
int audit_log_add_msg(audit_log_t *log, msg_t *msg)
{
	if (log == NULL || msg == NULL)
		return -1;
	if (log->num_msgs >= log->msg_list_sz) {
		log->msg_list = (msg_t**)realloc(log->msg_list, sizeof(msg_t*)*(log->msg_list_sz+ ARRAY_SZ));
		if (log->msg_list == NULL) {
			fprintf(stderr, "Out of memory");
			return -1;
		}
		log->msg_list_sz += ARRAY_SZ;
		memset(&log->msg_list[log->num_msgs],0, sizeof(msg_t*) * ARRAY_SZ);
	}
	log->msg_list[log->num_msgs] = msg;
	log->num_msgs++;
	return 0;
}

enum avc_msg_class_t which_avc_msg_class(msg_t *msg)
{
	avc_msg_t *avc_msg = msg->msg_data.avc_msg;
	if ( msg->msg_type != AVC_MSG)
		return AVC_AUDIT_DATA_NO_VALUE;
	if ( avc_msg->dev != NULL || avc_msg->is_inode != FALSE)
		return AVC_AUDIT_DATA_FS;
	if ( avc_msg->is_key != FALSE)
		return AVC_AUDIT_DATA_IPC;
	if ( avc_msg->capability != -1)
		return AVC_AUDIT_DATA_CAP;
	if ( avc_msg->laddr != NULL || avc_msg->faddr != NULL || avc_msg->daddr != NULL)
		return AVC_AUDIT_DATA_NET;
	return AVC_AUDIT_DATA_NO_VALUE;
}

#if 0
static void avc_msg_print(msg_t *msg, FILE *file)
{
	avc_msg_t *d = msg->msg_data.avc_msg;
	if (msg->msg_type != AVC_MSG)
		return;
	if (d->msg == AVC_DENIED)
		fprintf(file,"denied: ");
	else
		fprintf(file,"granted: ");
	fprintf(file,"pid=%d ", msg->msg_data.avc_msg->pid);
	if (d->exe)
		fprintf(file,"exe=%s ", msg->msg_data.avc_msg->exe);
	if (d->comm)
	        fprintf(file,"comm=%s ", msg->msg_data.avc_msg->comm);
	if (d->name)
		fprintf(file,"name=%s ", msg->msg_data.avc_msg->comm);
	if (d->dev)
		fprintf(file,"dev=%s ", msg->msg_data.avc_msg->dev);
	if (d->netif)
		fprintf(file,"netif=%s ", msg->msg_data.avc_msg->netif);
	if (d->path)
		fprintf(file,"path=%s ", msg->msg_data.avc_msg->path);
	if (d->laddr)
		fprintf(file,"laddr=%s ", msg->msg_data.avc_msg->laddr);
	if (d->faddr)
		fprintf(file,"faddr=%s ", msg->msg_data.avc_msg->faddr);
	if (d->daddr)
		fprintf(file,"daddr=%s ", msg->msg_data.avc_msg->daddr);  
	if (d->saddr)
		fprintf(file,"saddr=%s ", msg->msg_data.avc_msg->saddr);
}
#endif

void msg_print(msg_t *msg, FILE *file)
{
	printf("msg_printf() - not implemented.\n");
}
