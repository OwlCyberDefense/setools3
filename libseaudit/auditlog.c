
/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: kcarr@tresys.com and Karl MacMillan <kmacmillan@tresys.com>
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

const char *audit_log_field_strs[] = { "msg_field", "exe_field", "path_field", "dev_field", 
				       "src_usr_field", "src_role_field", "src_type_field",
				       "tgt_usr_field", "tgt_role_field", "tgt_type_field",
				       "obj_class_field", "perm_field", "inode_field", 
				       "pid_field", "src_sid_field", "tgt_sid_field", 
				       "comm_field", "netif_field", "key_field", "cap_field",
				       "port_field", "lport_field", "fport_field", "dest_field",
				       "source_field", "laddr_field", "faddr_field", "daddr_field",
				       "saddr_field", "src_context", "tgt_context", "name_field",
				       "other_field", "policy_usrs_field", "policy_roles_field",
				       "policy_types_field", "policy_classes_field", 
				       "policy_rules_field", "policy_binary_field" , "date_field" ,
                                       "host_field" };

int audit_log_field_strs_get_index(const char *str)
{
	int i;

	for (i = 0; i < NUM_FIELDS; i++)
		if (strcmp(str, audit_log_field_strs[i]) == 0)
			return i;
	return -1;
}

static void audit_log_purge_fltr_msgs(audit_log_t *log)
{
	if (log->fltr_msgs) {
		free(log->fltr_msgs);
		log->fltr_msgs = NULL;
		log->num_fltr_msgs = 0;
		log->fltr_msgs_sz = 0;
	}
	return;
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
	new->filters = NULL;
	new->fltr_msgs = NULL;

	new->num_fltr_msgs = 0;
	new->fltr_msgs_sz = 0;
	
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
	msg_t *new;
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
	new->src_user = -1;
	new->src_role = -1;
	new->src_type = -1;
	new->tgt_user = -1;
	new->tgt_role = -1;
	new->tgt_type = -1;
	new->obj_class = -1;
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

/*
 * destroy an audit log, previously created by audit_log_create */
void audit_log_destroy(audit_log_t *tmp)
{
	int i, j;
	filter_t *cur, *next;
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
	if (tmp->filters) {
		cur = tmp->filters;
		while (cur) {
			next = cur->next;
			if (next)
				next->prev = NULL;
			filter_destroy(cur);
			cur = next;
		}
	}
	for (i = 0; i < tmp->num_msgs; i++) {
		if (tmp->msg_list[i] == NULL)
			break;
		msg_destroy(tmp->msg_list[i]);
	}
	if (tmp->fltr_msgs)
		free(tmp->fltr_msgs);
	if (tmp->msg_list)
		free(tmp->msg_list);
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

/*
 * add a filter to the audit log list of active filters */
int audit_log_add_filter(audit_log_t *log, filter_t *filter)
{
	if (log == NULL || filter == NULL)
		return -1;
	if (log->filters == NULL) {
		filter->next = NULL;
		filter->prev = NULL;
		log->filters = filter;
		return 0;
	}
	filter->next = log->filters;
	filter->prev = NULL;
	log->filters->prev = filter;
	log->filters = filter;
	return 0;
}

/*
 * remove all the filters from the audit log. */
void audit_log_purge_filters(audit_log_t *log)
{
	filter_t *cur, *next;

	if (log->filters) {
		cur = log->filters;
		while (cur) {
			next = cur->next;
			if (next)
				next->prev = NULL;
			filter_destroy(cur);
			cur = next;
		}
		log->filters = NULL;
	}	
	return;
}

static void sort_kept_messages(int *kept, int num_kept, filt_info_t *info)
{
	int i, j, msg_a, msg_b, tmp;
	for (j = 0; j < num_kept; j++) {
		for (i = 0; i < num_kept-1-j; i++) {
			msg_a = kept[i];
			msg_b = kept[i+1];
			if (info[msg_a].orig_indx > info[msg_b].orig_indx) {
				tmp = kept[i];
				kept[i] = kept[i+1];
				kept[i+1] = tmp;
			}
		}
	}
	return;
}


/*
 * this function will do a filter or a search depending on log->fltr_out */
int audit_log_do_filter(audit_log_t *log, bool_t details, int **deleted, int *num_deleted) 
{
	int i, j, msg, *kept=NULL, num_kept=0, *added=NULL, num_added=0, *ptr=NULL, *delptr=NULL;
	bool_t err, all_match, any_match, match, found; 
	filter_t *cur_fltr; 
	filt_info_t *info;

	if (log == NULL)
		return -1;
	if (log->msg_list == NULL)
		return -1;

	/* by default append everything that is not already filtered */
	if (log->filters == NULL) {
		log->fltr_msgs = (int*)realloc(log->fltr_msgs, sizeof(int) * log->num_msgs);
		for(i = 0; i < log->num_msgs; i++) {
			found = FALSE;
			for (j = 0; j < log->num_fltr_msgs; j++)
				if (log->fltr_msgs[j] == i)
					found = TRUE;
			if (!found) {
				log->fltr_msgs[log->num_fltr_msgs] = i;
				log->num_fltr_msgs++;
			}
		}
		(*num_deleted) = 0;
		(*deleted) = NULL;
		return 0;
	}

	/* we need to keep these buffers around to keep track of 
	 * deleted, added, and kept messages */
	if (!num_deleted)
		return -1;
	delptr = (int*)malloc(sizeof(int) * log->num_msgs);
	*num_deleted = 0;
	if (!delptr) {
		return -1;
	}
	*deleted = delptr;
	kept = (int*)malloc(sizeof(int) * log->num_fltr_msgs);
	if (!kept) {
		free(delptr);
		return -1;
	}
	added = (int*)malloc(sizeof(int) * log->num_msgs);
	if (!added) {
		free(delptr);
		free(kept);
		return -1;
	}
	info = (filt_info_t*)malloc(sizeof(filt_info_t)*log->num_msgs );
	if (!info) {
		free(delptr);
		free(kept);
		free(added);
		return -1;
	}
	memset(info, 0, sizeof(filt_info_t) * log->num_msgs);
	for (i = 0; i < log->num_fltr_msgs; i++) {
		msg = log->fltr_msgs[i];
		info[msg].orig_indx = i;
		info[msg].filtered = TRUE;
	}

	audit_log_purge_fltr_msgs(log);

       	for (cur_fltr = log->filters; cur_fltr != NULL; cur_fltr = cur_fltr->next)
		cur_fltr->dirty = TRUE;


	if (log->fltr_and) { /* match all filters */
		
		for (i = 0; i < log->num_msgs; i++) {
			all_match = TRUE;
			any_match = FALSE;
			for (cur_fltr = log->filters; cur_fltr != NULL && all_match; cur_fltr = cur_fltr->next) {
				if (cur_fltr->filter_act) {
					if (!(cur_fltr->msg_types & log->msg_list[i]->msg_type))
						match = FALSE;
					else
						match = cur_fltr->filter_act(log->msg_list[i], cur_fltr, log, &err);
					all_match = all_match && match;
				}
			}			
			if (log->fltr_out) { /* Filter out messages */
				if (all_match) {
					if (info[i].filtered == TRUE) {
						delptr[*num_deleted] = info[i].orig_indx;
						(*num_deleted)++;
					} 	
				} else {
					if (info[i].filtered == TRUE) {
						kept[num_kept] = i;
						num_kept++;
					} else {
						added[num_added] = i;
						num_added++;
					}
				}
			} else {             /* Filter in messages */
				if (all_match) {
					if (info[i].filtered == TRUE) {
						kept[num_kept] = i;
						num_kept++;
					} else {
						added[num_added] = i;
						num_added++;
					}
				} else {
					if (info[i].filtered == TRUE) {
						delptr[*num_deleted] = info[i].orig_indx;
						(*num_deleted)++;
					} 
				}
			}
		}
		
	} else { /* match any filter */
		
		for (i = 0; i < log->num_msgs; i++) {
			all_match = TRUE;
			any_match = FALSE;
			for (cur_fltr = log->filters; cur_fltr != NULL; cur_fltr = cur_fltr->next) {
				if (cur_fltr->filter_act) {
					if (!(cur_fltr->msg_types & log->msg_list[i]->msg_type))
						match = FALSE;
					else
						match = cur_fltr->filter_act(log->msg_list[i], cur_fltr, log, &err);
					any_match = any_match || match;
				}
			}
			if (log->fltr_out) { /* Filter out messages */
				if (any_match) {
					if (info[i].filtered == TRUE) {
						delptr[*num_deleted] = info[i].orig_indx;
						(*num_deleted)++;
					} 	
				} else {
					if (info[i].filtered == TRUE) {
						kept[num_kept] = i;
						num_kept++;
					} else {
						added[num_added] = i;
						num_added++;
					}
				}
			} else {            /* Filter in messages*/
				if (any_match) {
					if (info[i].filtered == TRUE) {
						kept[num_kept] = i;
						num_kept++;
					} else {
						added[num_added] = i;
						num_added++;
					}
				} else {
					if (info[i].filtered == TRUE) {
						delptr[*num_deleted] = info[i].orig_indx;
						(*num_deleted)++;
					} 
				}
			}
		} /* end for loop */
	}
	
	sort_kept_messages(kept, num_kept, info);
	free(info);

	/* merge kept and added to form fltr_msgs */
        ptr = (int*)malloc(sizeof(int) * ( (num_added) + num_kept));
	if (!ptr) {
		free(delptr);
		free(kept);
		free(added);
		return -1;
	}	
	log->fltr_msgs = ptr;
	log->num_fltr_msgs = num_kept + num_added;
	memcpy(log->fltr_msgs, kept, sizeof(int) * num_kept);
	memcpy(&log->fltr_msgs[num_kept], added, sizeof(int) * (num_added));
	free(added);
	free(kept);

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


void audit_log_msgs_print(audit_log_t *log, FILE *file)
{
	int i;
	fprintf(file, "\n*Printing all AVC messages in the log..*\n");
	for (i = 0; i < log->num_msgs; i++) {
		fprintf(file, "\n");
		avc_msg_print(log->msg_list[i], file);
	}
}

void audit_log_fltr_msgs_print(audit_log_t *log, FILE *file)
{
	int i, indx;

	fprintf(file, "\n*Printing all filtered AVC messages in the log..*\n");
	for (i = 0; i < log->num_fltr_msgs; i++) {
		fprintf(file, "\n");
		indx = log->fltr_msgs[i];
		avc_msg_print(log->msg_list[indx], file);
	}
}
