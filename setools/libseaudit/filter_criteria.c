/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 * Date: February 06, 2004
 *
 * This file contains the implementation of filter_criteria.h
 *
 * filter_criteria.c
 */

#include "filter_criteria.h"
#include "auditlog.h"
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <fnmatch.h>

typedef struct strs_criteria {
	char **strs;
	int num_strs;
	int *indexes;
} strs_criteria_t;

typedef strs_criteria_t type_criteria_t;
typedef strs_criteria_t role_criteria_t;
typedef strs_criteria_t user_criteria_t;
typedef strs_criteria_t class_criteria_t;

typedef struct glob_criteria {
	char *globex;
} glob_criteria_t;

typedef glob_criteria_t exe_criteria_t;
typedef glob_criteria_t path_criteria_t;
typedef glob_criteria_t ipaddr_criteria_t;

typedef struct ports_criteria {
	int val;
} ports_criteria_t;

typedef struct netif_criteria {
	char *netif;
} netif_criteria_t;

static bool_t netif_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	netif_criteria_t *netif_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	netif_criteria = (netif_criteria_t*)criteria->data;
	if (!netif_criteria->netif || !msg->msg_data.avc_msg->netif)
		return FALSE;
	return strcmp(netif_criteria->netif, msg->msg_data.avc_msg->netif) == 0 ? TRUE : FALSE;
}

static bool_t ports_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	ports_criteria_t *ports_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	ports_criteria = (ports_criteria_t*)criteria->data;
	if (ports_criteria->val == msg->msg_data.avc_msg->port)
		return TRUE;
	if (ports_criteria->val == msg->msg_data.avc_msg->source)
		return TRUE;
	if (ports_criteria->val == msg->msg_data.avc_msg->dest)
		return TRUE;
	if (ports_criteria->val == msg->msg_data.avc_msg->fport)
		return TRUE;
	if (ports_criteria->val == msg->msg_data.avc_msg->lport)
		return TRUE;
	return FALSE;
}

static bool_t ipaddr_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	ipaddr_criteria_t *ipaddr_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	ipaddr_criteria = (ipaddr_criteria_t*)criteria->data;
	if (!ipaddr_criteria->globex)
		return FALSE;
	if (msg->msg_data.avc_msg->saddr)
		if (fnmatch(ipaddr_criteria->globex, msg->msg_data.avc_msg->saddr, 0) == 0)
			return TRUE;
	if (msg->msg_data.avc_msg->daddr)
		if (fnmatch(ipaddr_criteria->globex, msg->msg_data.avc_msg->daddr, 0) == 0)
			return TRUE;
	if (msg->msg_data.avc_msg->faddr)
		if (fnmatch(ipaddr_criteria->globex, msg->msg_data.avc_msg->faddr, 0) == 0)
			return TRUE;
	if (msg->msg_data.avc_msg->laddr)
		if (fnmatch(ipaddr_criteria->globex, msg->msg_data.avc_msg->laddr, 0) == 0)
			return TRUE;
	return FALSE;
}

static bool_t exe_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)  
{ 
	exe_criteria_t *exe_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL || !msg->msg_data.avc_msg->exe)
		return FALSE;

	exe_criteria = (exe_criteria_t*)criteria->data;
	if (!exe_criteria->globex)
		return FALSE;
	if (fnmatch(exe_criteria->globex, msg->msg_data.avc_msg->exe, 0) == 0)
		return TRUE;
	return FALSE;
} 

static bool_t path_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)  
{ 
	path_criteria_t *path_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL || !msg->msg_data.avc_msg->path)
		return FALSE;

	path_criteria = (path_criteria_t*)criteria->data;
	if (!path_criteria->globex)
		return FALSE;
	if (fnmatch(path_criteria->globex, msg->msg_data.avc_msg->path, 0) == 0)
		return TRUE;
	return FALSE;
} 

static bool_t src_user_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i;
	user_criteria_t *user_criteria;
	const char *user;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	user = audit_log_get_user(log, msg->msg_data.avc_msg->src_user);
	if (!user)
		return FALSE;
	user_criteria = (user_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < user_criteria->num_strs; i++)
			user_criteria->indexes[i] = audit_log_get_user_idx(log, user_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < user_criteria->num_strs; i++) { 
		if (user_criteria->indexes[i] == -1)
			if (fnmatch(user_criteria->strs[i], user, 0) == 0)
				return TRUE;			
		if (user_criteria->indexes[i] == msg->msg_data.avc_msg->src_user)
			return TRUE; 
	} 
	return FALSE;
}

static bool_t tgt_user_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i;
	user_criteria_t *user_criteria;
	const char *user;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	user = audit_log_get_user(log, msg->msg_data.avc_msg->tgt_user);
	if (!user)
		return FALSE;
	user_criteria = (user_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < user_criteria->num_strs; i++)
			user_criteria->indexes[i] = audit_log_get_user_idx(log, user_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < user_criteria->num_strs; i++) { 
		if (user_criteria->indexes[i] == -1)
			if (fnmatch(user_criteria->strs[i], user, 0) == 0)
				return TRUE;
		if (user_criteria->indexes[i] == msg->msg_data.avc_msg->tgt_user)
			return TRUE; 
	} 
	return FALSE;
}

static bool_t src_role_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i; 
	role_criteria_t *role_criteria;
	const char *role;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	role = audit_log_get_role(log, msg->msg_data.avc_msg->src_role);
	if (!role)
		return FALSE;
	role_criteria = (role_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < role_criteria->num_strs; i++)
			role_criteria->indexes[i] = audit_log_get_role_idx(log, role_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < role_criteria->num_strs; i++) { 
		if (role_criteria->indexes[i] == -1)
			if (fnmatch(role_criteria->strs[i], role, 0) == 0)
				return TRUE;		       
		if (role_criteria->indexes[i] == msg->msg_data.avc_msg->src_role) 
			return TRUE; 
	} 
	return FALSE;
}

static bool_t tgt_role_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i; 
	role_criteria_t *role_criteria;
	const char *role;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	role = audit_log_get_role(log, msg->msg_data.avc_msg->tgt_role);
	if (!role)
		return FALSE;
	role_criteria = (role_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < role_criteria->num_strs; i++)
			role_criteria->indexes[i] = audit_log_get_role_idx(log, role_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < role_criteria->num_strs; i++) { 
		if (role_criteria->indexes[i] == -1)
			if (fnmatch(role_criteria->strs[i], role, 0) == 0)
				return TRUE;
		if (role_criteria->indexes[i] == msg->msg_data.avc_msg->tgt_role) 
			return TRUE; 
	} 
	return FALSE;
}

static bool_t src_type_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i; 
	type_criteria_t *type_criteria;
	const char *type;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	type = audit_log_get_type(log, msg->msg_data.avc_msg->src_type);
	if (!type)
		return FALSE;
	type_criteria = (type_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < type_criteria->num_strs; i++)
			type_criteria->indexes[i] = audit_log_get_type_idx(log, type_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < type_criteria->num_strs; i++) { 
		if (type_criteria->indexes[i] == -1)
			if (fnmatch(type_criteria->strs[i], type, 0) == 0)
				return TRUE;
		if (type_criteria->indexes[i] == msg->msg_data.avc_msg->src_type)
			return TRUE;
	} 
	return FALSE;
}

static bool_t tgt_type_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i; 
	type_criteria_t *type_criteria;
	const char *type;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	type = audit_log_get_type(log, msg->msg_data.avc_msg->tgt_type);
	if (!type)
		return FALSE;
	type_criteria = (type_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < type_criteria->num_strs; i++)
			type_criteria->indexes[i] = audit_log_get_type_idx(log, type_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < type_criteria->num_strs; i++) { 
		if (type_criteria->indexes[i] == -1)
			if (fnmatch(type_criteria->strs[i], type, 0) == 0)
				return TRUE;
		if (type_criteria->indexes[i] == msg->msg_data.avc_msg->tgt_type)
			return TRUE;
	} 
	return FALSE;
}

static bool_t class_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log) 
{ 
	int i; 
	class_criteria_t *class_criteria;
	const char *class;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	class = audit_log_get_obj(log, msg->msg_data.avc_msg->obj_class);
	if (!class)
		return FALSE;
	class_criteria = (class_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < class_criteria->num_strs; i++)
			class_criteria->indexes[i] = audit_log_get_obj_idx(log, class_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < class_criteria->num_strs; i++) { 
		if (class_criteria->indexes[i] == -1)
			if (fnmatch(class_criteria->strs[i], class, 0) == 0)
				return TRUE;
		if (class_criteria->indexes[i] == msg->msg_data.avc_msg->obj_class) 
			return TRUE; 
	} 
	return FALSE;	
} 

/*
 * create the container struct */
static seaudit_criteria_t* criteria_create(void)
{
	seaudit_criteria_t *new;

	new = (seaudit_criteria_t*)malloc(sizeof(seaudit_criteria_t));
	if (new == NULL) 
		return NULL;
	memset(new, 0, sizeof(seaudit_criteria_t));
	return new;
}

/*
 * destroy the entire criteria */
void seaudit_criteria_destroy(seaudit_criteria_t *ftr) 
{
	if (ftr == NULL)
		return;
	if (ftr->destroy)
		ftr->destroy(ftr);
	free(ftr);
	return;
}

static void strs_criteria_destroy(strs_criteria_t *strs_criteria)
{
	int i;

	if (strs_criteria->indexes)
		free(strs_criteria->indexes);
	if (strs_criteria->strs) {
		for (i = 0; i < strs_criteria->num_strs; i++) {
			if (strs_criteria->strs[i])
				free(strs_criteria->strs[i]);
		}
		free(strs_criteria->strs);
	}
	free(strs_criteria);	
}

static strs_criteria_t *strs_criteria_create(char **strs, int num_strs)
{
	strs_criteria_t *d;
	int i;

	d = (strs_criteria_t*)malloc(sizeof(strs_criteria_t));
	if (!d) {
		goto bad;
	}
	memset(d, 0, sizeof(type_criteria_t));
	/* alloc strs and deep copy */
	d->strs = (char**)calloc(num_strs, sizeof(char*));
	if (!d->strs) {
		goto bad;
	}
	for (i = 0; i < num_strs; i++) {
		d->strs[i] = strdup(strs[i]);
		if (!d->strs[i])
			goto bad;
	}
	/* alloc indexes */
	d->indexes = (int*)malloc(sizeof(int) * num_strs);
	if (!d->indexes)
		goto bad;
	d->num_strs = num_strs;
	return d;
 bad:
	if (d) {
		if (d->indexes)
			free(d->indexes);
		if (d->strs) {
			for (i = 0; i < num_strs; i++)
				if (d->strs[i])
					free(d->strs[i]);
			free(d->strs);
		}
		free(d);
	}
	return NULL;
}

static void type_criteria_destroy(seaudit_criteria_t* ftr)
{
	type_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (type_criteria_t*)ftr->data;
	strs_criteria_destroy(d);
	return;
}

seaudit_criteria_t* src_type_criteria_create(char **types, int num_types)
{
        seaudit_criteria_t *new_criteria;
	type_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(types, num_types);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &src_type_criteria_action; 
	new_criteria->destroy = &type_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

seaudit_criteria_t* tgt_type_criteria_create(char **types, int num_types)
{
        seaudit_criteria_t *new_criteria;
	type_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(types, num_types);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &tgt_type_criteria_action; 
	new_criteria->destroy = &type_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

static void role_criteria_destroy(seaudit_criteria_t* ftr)
{
	role_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (role_criteria_t*)ftr->data;
	strs_criteria_destroy(d);
	return;
}

seaudit_criteria_t* src_role_criteria_create(char **roles, int num_roles)
{
        seaudit_criteria_t *new_criteria;
	role_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(roles, num_roles);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &src_role_criteria_action; 
	new_criteria->destroy = &role_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

seaudit_criteria_t* tgt_role_criteria_create(char **roles, int num_roles)
{
        seaudit_criteria_t *new_criteria;
	role_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(roles, num_roles);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &tgt_role_criteria_action; 
	new_criteria->destroy = &role_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

static void user_criteria_destroy(seaudit_criteria_t* ftr)
{
	user_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (user_criteria_t*)ftr->data;
	strs_criteria_destroy(d);
	return;
}

seaudit_criteria_t* src_user_criteria_create(char **users, int num_users)
{
        seaudit_criteria_t *new_criteria;
	user_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(users, num_users);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &src_user_criteria_action; 
	new_criteria->destroy = &user_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

seaudit_criteria_t* tgt_user_criteria_create(char **users, int num_users)
{
        seaudit_criteria_t *new_criteria;
	user_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(users, num_users);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &tgt_user_criteria_action; 
	new_criteria->destroy = &user_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}


static void class_criteria_destroy(seaudit_criteria_t* ftr)
{
	class_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (class_criteria_t*)ftr->data;
	strs_criteria_destroy(d);
	return;
}

seaudit_criteria_t* class_criteria_create(char **classes, int num_classes)
{
        seaudit_criteria_t *new_criteria;
	class_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(classes, num_classes);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &class_criteria_action; 
	new_criteria->destroy = &class_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

/*
 * destroy the exe criteria, not the container struct */
static void exe_criteria_destroy(seaudit_criteria_t *ftr)
{
	exe_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (exe_criteria_t*)ftr->data;
	if (d->globex)
		free(d->globex);
	free(d);
	return;
}

/*
 * create the entire exe criteria */
seaudit_criteria_t* exe_criteria_create(const char* exe)
{
        seaudit_criteria_t *new;
	exe_criteria_t *d;
	int i;

	d = (exe_criteria_t*)malloc(sizeof(exe_criteria_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(exe_criteria_t));
	i = strlen(exe);
	d->globex = (char*)malloc(sizeof(char) * (i+1));
	if (d->globex == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &exe_criteria_action; 
	new->destroy = &exe_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	strcpy(d->globex, exe);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->globex)
			free(d->globex);
		free(d);
	}
	return NULL;
}

static void netif_criteria_destroy(seaudit_criteria_t *ftr) 
{
	netif_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (netif_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->netif != NULL)
		free(d->netif);
	free(d);
	return;
}

seaudit_criteria_t* netif_criteria_create(const char *netif)
{
        seaudit_criteria_t *new;
	netif_criteria_t *d;
	int i;
	d = (netif_criteria_t*)malloc(sizeof(netif_criteria_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(netif_criteria_t));
	i = strlen(netif);
	d->netif = (char*)malloc(sizeof(char) * (i+1));
	if (d->netif == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &netif_criteria_action; 
	new->destroy = &netif_criteria_destroy;
	new->data = d; 
	/* set criteria variables */
	strcpy(d->netif, netif);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->netif)
			free(d->netif);
		free(d);
	}
	return NULL;
}

static void ipaddr_criteria_destroy(seaudit_criteria_t *ftr)
{
	ipaddr_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (ipaddr_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->globex != NULL)
		free(d->globex);
	free(d);
	return;
}

seaudit_criteria_t* ipaddr_criteria_create(const char *ipaddr)
{
        seaudit_criteria_t *new;
	ipaddr_criteria_t *d;
	int i;
	d = (ipaddr_criteria_t*)malloc(sizeof(ipaddr_criteria_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(ipaddr_criteria_t));
	i = strlen(ipaddr);
	d->globex = (char*)malloc(sizeof(char) * (i+1));
	if (d->globex == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &ipaddr_criteria_action; 
	new->destroy = &ipaddr_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	strcpy(d->globex, ipaddr);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->globex)
			free(d->globex);
		free(d);
	}
	return NULL;
}

static void path_criteria_destroy(seaudit_criteria_t *ftr)
{
	path_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (path_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->globex != NULL)
		free(d->globex);
	free(d);
	return;
}

/*
 * create the entire path criteria */
seaudit_criteria_t* path_criteria_create(const char *path)
{
        seaudit_criteria_t *new;
	path_criteria_t *d;
	int i;
	d = (path_criteria_t*)malloc(sizeof(path_criteria_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(path_criteria_t));
	i = strlen(path);
	d->globex = (char*)malloc(sizeof(char) * (i+1));
	if (d->globex == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) 
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &path_criteria_action; 
	new->destroy = &path_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	strcpy(d->globex, path);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->globex)
			free(d->globex);
		free(d);
	}
	return NULL;
}

static void ports_criteria_destroy(seaudit_criteria_t *ftr)
{
	ports_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (ports_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

seaudit_criteria_t* ports_criteria_create(int port)
{
        seaudit_criteria_t *new;
	ports_criteria_t *d;
	d = (ports_criteria_t*)malloc(sizeof(ports_criteria_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(ports_criteria_t));
	new = criteria_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &ports_criteria_action; 
	new->destroy = &ports_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	d->val = port;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}
