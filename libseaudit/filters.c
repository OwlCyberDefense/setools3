/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: kcarr@tresys.com and Karl MacMillan <kmacmillan@tresys.com>
 * Date: October 6, 2003
 * 
 * This file contains the implementation of filters.h
 *
 * filters.c
 */

#include "filters.h"
#include "auditlog.h"
#include <string.h>
#include <sys/types.h>
#include <regex.h>
/*
 * structure for date filters */
typedef struct date_filter { 
	struct tm start_date;
	struct tm end_date;
} date_filter_t;

/* structure for type filters */
typedef struct type_filter {
	char **type_strs;/* list of type strings */
	int *types;      /* list of types */
	int num_types;   /* number of types */
} type_filter_t;

/* structure for role filters */
typedef struct role_filter {
	char **role_strs;/* list of role strings */
	int *roles;      /* list of roles */
	int num_roles;   /* number of roles */
} role_filter_t;

/* structure for user filters */
typedef struct user_filter {
	char **user_strs;/* list of user strings */
	int *users;      /* list of users */
	int num_users;   /* number of users */
} user_filter_t;

/* structure for class filters */
typedef struct class_filter {
	char **class_strs;/* list of class strings */
	int *classes;    /* list of classes */
	int num_classes; /* number of classes */
} class_filter_t;

/* structure for permissions filters */
typedef struct perms_filter {
	char **perm_strs;/* list of perm strings */
	int *perms;      /* list of permissions */
	int num_perms;   /* number of permissions */
} perms_filter_t;

/* structure for filters on executable */
typedef struct exe_filter {
	char *exe;
} exe_filter_t;

/* structure for filters on path */
typedef struct path_filter {
	char *path;
} path_filter_t;

/* structure for filters on device */
typedef struct dev_filter {
	char *dev;
} dev_filter_t;

/* structure for filters on message */
typedef struct msg_filter {
	int msg;
} msg_filter_t;

/* structure for filters on pid */
typedef struct pid_filter {
	unsigned int pid;
} pid_filter_t;

/* structure for filters on inode */
typedef struct inode_filter {
	unsigned int inode;
} inode_filter_t;

/* structure for filters on ssid */
typedef struct ssid_filter {
	unsigned int ssid;
} ssid_filter_t;

/* structure for filters on ssid */
typedef struct tsid_filter {
	unsigned int tsid;
} tsid_filter_t;

/* structure for filters on comm */
typedef struct comm_filter {
	char *comm;
} comm_filter_t;

/* structure for filters on netif */
typedef struct netif_filter {
	char *netif;
} netif_filter_t;

/* structure for filters on key */
typedef struct key_filter {
	int key;
} key_filter_t;

/* structure for filters on capability */
typedef struct capability_filter {
	int capability;
} capability_filter_t;

/* structure for filters on capability */
typedef struct port_filter {
	int port;
} port_filter_t;

/* structure for filters on capability */
typedef struct lport_filter {
	int lport;
} lport_filter_t;

/* structure for filters on capability */
typedef struct fport_filter {
	int fport;
} fport_filter_t;

/* structure for filters on dest */
typedef struct dest_filter {
	int dest;
} dest_filter_t;

/* structure for filters on source */
typedef struct source_filter {
	int source;
} source_filter_t;

/* structure for filters on laddr */
typedef struct laddr_filter {
	char *laddr;
} laddr_filter_t;

/* structure for filters on faddr */
typedef struct faddr_filter {
	char *faddr;
} faddr_filter_t;

/* structure for filters on daddr */
typedef struct daddr_filter {
	char *daddr;
} daddr_filter_t;

/* structure for filters on saddr */
typedef struct saddr_filter {
	char *saddr;
} saddr_filter_t;

typedef struct ipaddr_filter {
	char *ipaddr;
} ipaddr_filter_t;

typedef struct ports_filter {
	int port;
} ports_filter_t;

/*
 * filter based on message ie. denied, allowed */
static bool_t msg_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	msg_filter_t *filter = (msg_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->msg == msg->msg_data.avc_msg->msg ? TRUE : FALSE;
}

static bool_t ssid_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	ssid_filter_t *filter = (ssid_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->ssid == msg->msg_data.avc_msg->src_sid ? TRUE : FALSE;
}

static bool_t tsid_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	tsid_filter_t *filter = (tsid_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->tsid == msg->msg_data.avc_msg->tgt_sid ? TRUE : FALSE;
}

static bool_t comm_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	comm_filter_t *filter = (comm_filter_t*)(d->data);
	regex_t preg;
	int rt;
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->comm || !msg->msg_data.avc_msg->comm)
		return FALSE;
	rt = regcomp(&preg, filter->comm, 0);
	if (rt != 0)
		return FALSE;
	rt = regexec(&preg, msg->msg_data.avc_msg->comm, 0, NULL, REG_NOTBOL & REG_NOTEOL);
	if (rt == 0)
		return TRUE;
	return FALSE;
}
static bool_t netif_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	netif_filter_t *filter = (netif_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->netif || !msg->msg_data.avc_msg->netif)
		return FALSE;
	return strcmp(filter->netif, msg->msg_data.avc_msg->netif) == 0 ? TRUE : FALSE;
}

static bool_t key_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	key_filter_t *filter = (key_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->key == msg->msg_data.avc_msg->key ? TRUE : FALSE;
}

static bool_t capability_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	capability_filter_t *filter = (capability_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->capability == msg->msg_data.avc_msg->capability ? TRUE : FALSE;
}

static bool_t port_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	port_filter_t *filter = (port_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->port == msg->msg_data.avc_msg->port ? TRUE : FALSE;
}

static bool_t lport_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	lport_filter_t *filter = (lport_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->lport == msg->msg_data.avc_msg->lport ? TRUE : FALSE;
}

static bool_t fport_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	fport_filter_t *filter = (fport_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->fport == msg->msg_data.avc_msg->fport ? TRUE : FALSE;
}

static bool_t dest_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
        dest_filter_t *filter = (dest_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->dest == msg->msg_data.avc_msg->dest ? TRUE : FALSE;
}

static bool_t source_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
        source_filter_t *filter = (source_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return filter->source == msg->msg_data.avc_msg->source ? TRUE : FALSE;
}

static bool_t ports_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	if (source_filter_action(msg, data, log, err))
		return TRUE;
	if (dest_filter_action(msg, data, log, err))
		return TRUE;
	if (fport_filter_action(msg, data, log, err))
		return TRUE;
	if (lport_filter_action(msg, data, log, err))
		return TRUE;
	if (port_filter_action(msg, data, log, err))
		return TRUE;
	return FALSE;
}

static bool_t laddr_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	laddr_filter_t *filter = (laddr_filter_t*)(d->data);
	regex_t preg;
	int rt;
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->laddr || !msg->msg_data.avc_msg->laddr)
		return FALSE;
	rt = regcomp(&preg, filter->laddr, 0);
	if (rt != 0)
		return FALSE;
	rt = regexec(&preg, msg->msg_data.avc_msg->laddr, 0, NULL, REG_NOTBOL & REG_NOTEOL);
	if (rt == 0)
		return TRUE;
	return FALSE;
}
static bool_t faddr_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	faddr_filter_t *filter = (faddr_filter_t*)(d->data);
	regex_t preg;
	int rt;
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->faddr || !msg->msg_data.avc_msg->faddr)
		return FALSE;
	rt = regcomp(&preg, filter->faddr, 0);
	if (rt != 0)
		return FALSE;
	rt = regexec(&preg, msg->msg_data.avc_msg->faddr, 0, NULL, REG_NOTBOL & REG_NOTEOL);
	if (rt == 0)
		return TRUE;
	return FALSE;
}
static bool_t daddr_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	daddr_filter_t *filter = (daddr_filter_t*)(d->data);
	regex_t preg;
	int rt;
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->daddr || !msg->msg_data.avc_msg->daddr)
		return FALSE;
	rt = regcomp(&preg, filter->daddr, 0);
	if (rt != 0)
		return FALSE;
	rt = regexec(&preg, msg->msg_data.avc_msg->daddr, 0, NULL, REG_NOTBOL & REG_NOTEOL);
	if (rt == 0)
		return TRUE;
	return FALSE;
}

static bool_t saddr_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	saddr_filter_t *filter = (saddr_filter_t*)(d->data);
	regex_t preg;
	int rt;
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->saddr || !msg->msg_data.avc_msg->saddr)
		return FALSE;
	rt = regcomp(&preg, filter->saddr, 0);
	if (rt != 0)
		return FALSE;
	rt = regexec(&preg, msg->msg_data.avc_msg->saddr, 0, NULL, REG_NOTBOL & REG_NOTEOL);
	if (rt == 0)
		return TRUE;
	return FALSE;
}

static bool_t ipaddr_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	if (saddr_filter_action(msg, data, log, err))
		return TRUE;
	if (daddr_filter_action(msg, data, log, err))
		return TRUE;
	if (faddr_filter_action(msg, data, log, err))
		return TRUE;
	if (laddr_filter_action(msg, data, log, err))
		return TRUE;
	return FALSE;
}

static bool_t date_filter_action(msg_t *msg, void *date, audit_log_t *log, bool_t *err)
{/* TODO - implement date_filter_action() */
	*err = TRUE;
	return FALSE;
}

/*
 * filter based on executable */
static bool_t exe_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)  
{ 
	filter_t *d = (filter_t*)data;
	exe_filter_t *filter = (exe_filter_t*)(d->data);
	regex_t preg;
	int rt;
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->exe || !msg->msg_data.avc_msg->exe)
		return FALSE;
	rt = regcomp(&preg, filter->exe, 0);
	if (rt != 0)
		return FALSE;
	rt = regexec(&preg, msg->msg_data.avc_msg->exe, 0, NULL, REG_NOTBOL & REG_NOTEOL);
	if (rt == 0)
		return TRUE;
	return FALSE;
} 

/*
 * filter based on object path */
static bool_t path_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)  
{ 
	filter_t *d = (filter_t*)data;
	path_filter_t *filter = (path_filter_t*)(d->data);
	regex_t preg;
	int rt;
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->path || !msg->msg_data.avc_msg->path)
		return FALSE;
	rt = regcomp(&preg, filter->path, REG_NOSUB);
	if (rt != 0)
		return FALSE;
	rt = regexec(&preg, msg->msg_data.avc_msg->path, 0, NULL, REG_NOTBOL & REG_NOTEOL);
	if (rt == 0)
		return TRUE;
	return FALSE;
} 

/*
 * filter based on device of object */
static bool_t dev_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err) 
{ 
	filter_t *d = (filter_t*)data;
	dev_filter_t *filter = (dev_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (!filter->dev || !msg->msg_data.avc_msg->dev)
		return FALSE;
	return strcmp(filter->dev, msg->msg_data.avc_msg->dev) == 0 ? TRUE : FALSE;
} 

/*
 * filter based on a source user */
static bool_t src_user_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	int i;
	filter_t *d = (filter_t*)data; 
	user_filter_t *filter = (user_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (d->dirty == TRUE) {
		for (i = 0; i < filter->num_users; i++)
			filter->users[i] = audit_log_get_user_idx(log, filter->user_strs[i]);
	}
	d->dirty = FALSE;
	for (i = 0; i < filter->num_users; i++) { 
		if (filter->users[i] == msg->msg_data.avc_msg->src_user) 
			return TRUE; 
	} 
	return FALSE;
}

/*
 * filter based on a target user */
static bool_t tgt_user_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	int i;
	filter_t *d = (filter_t*)data; 
	user_filter_t *filter = (user_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (d->dirty == TRUE) {
		for (i = 0; i < filter->num_users; i++)
			filter->users[i] = audit_log_get_user_idx(log, filter->user_strs[i]);
	}
	for (i = 0; i < filter->num_users; i++) { 
		if (filter->users[i] == msg->msg_data.avc_msg->tgt_user) 
			return TRUE; 
	} 
	return FALSE;
}

/*
 * filter based on a source role */
static bool_t src_role_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	int i; 
	filter_t *d = (filter_t*)data; 
	role_filter_t *filter = (role_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (d->dirty == TRUE) {
		for (i = 0; i < filter->num_roles; i++)
			filter->roles[i] = audit_log_get_role_idx(log, filter->role_strs[i]);
	}
	for (i = 0; i < filter->num_roles; i++) { 
		if (filter->roles[i] == msg->msg_data.avc_msg->src_role) 
			return TRUE; 
	} 
	return FALSE;
}

/*
 * filter based on a target role */
static bool_t tgt_role_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	int i; 
	filter_t *d = (filter_t*)data; 
	role_filter_t *filter = (role_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (d->dirty == TRUE) {
		for (i = 0; i < filter->num_roles; i++)
			filter->roles[i] = audit_log_get_role_idx(log, filter->role_strs[i]);
	}
	for (i = 0; i < filter->num_roles; i++) { 
		if (filter->roles[i] == msg->msg_data.avc_msg->tgt_role) 
			return TRUE; 
	} 
	return FALSE;
}

/*
 * filter based on a source type */
static bool_t src_type_filter_action(msg_t *msg, void *data, audit_log_t *log,  bool_t *err)
{
	int i; 
	filter_t *d = (filter_t*)data;
	type_filter_t *filter = (type_filter_t*)(d->data);
	
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (d->dirty == TRUE) {
		for (i = 0; i < filter->num_types; i++)
			filter->types[i] = audit_log_get_type_idx(log, filter->type_strs[i]);
	}
	d->dirty = FALSE;
	for (i = 0; i < filter->num_types; i++) { 
		if (filter->types[i] >= 0) /* if the type was in an audit message */
			if (filter->types[i] == msg->msg_data.avc_msg->src_type)
				return TRUE;
	} 
	return FALSE;
}

/*
 * filter based on a source type */
static bool_t tgt_type_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	int i; 
	filter_t *d = (filter_t*)data;
	type_filter_t *filter = (type_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (d->dirty == TRUE) {
		for (i = 0; i < filter->num_types; i++)
			filter->types[i] = audit_log_get_type_idx(log, filter->type_strs[i]);
	}
	d->dirty = FALSE;
	for (i = 0; i < filter->num_types; i++) { 
		if (filter->types[i] >= 0)
			if (filter->types[i] == msg->msg_data.avc_msg->tgt_type)
				return TRUE;
	} 
	return FALSE;
}

/*
 * filter based on object class */
static bool_t class_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err) 
{ 
	int i; 
        filter_t *d = (filter_t*)data; 
	class_filter_t *filter = (class_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	if (d->dirty == TRUE) {
		for (i = 0; i < filter->num_classes; i++)
			filter->classes[i] = audit_log_get_obj_idx(log, filter->class_strs[i]);
	}
	d->dirty = FALSE;
	for (i = 0; i < filter->num_classes; i++) { 
		if (filter->classes[i] == msg->msg_data.avc_msg->obj_class) 
			return TRUE; 
	} 
	return FALSE;	
} 


static bool_t perms_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{ /* TODO - implement perms_filter_action() */
	*err = TRUE;
	return FALSE; 
} 

/*
 * filter based on an inode for the object */
static bool_t inode_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	inode_filter_t *filter = (inode_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
      	return msg->msg_data.avc_msg->inode == filter->inode ? TRUE : FALSE;
} 

/*
 * filter based on a process ID */
static bool_t pid_filter_action(msg_t *msg, void *data, audit_log_t *log, bool_t *err)
{
	filter_t *d = (filter_t*)data;
	pid_filter_t *filter = (pid_filter_t*)(d->data);
	if (msg == NULL || data == NULL) {
		*err = TRUE;
		return FALSE;
	}
	*err = FALSE;
	return msg->msg_data.avc_msg->pid == filter->pid ? TRUE : FALSE;
}

/*
 * create the container struct */
filter_t* filter_create(void)
{
	filter_t *new;

	new = (filter_t*)malloc(sizeof(filter_t));
	if (new == NULL) 
		return NULL;
	memset(new, 0, sizeof(filter_t));
	return new;
}

/*
 * destroy the entire filter */
void filter_destroy(filter_t *ftr) 
{
	if (ftr == NULL)
		return;
	if (ftr->destroy)
		ftr->destroy(ftr);
	free(ftr);
	return;
}

/*
 * destroy the type filter, not the container struct */
static void type_filter_destroy(filter_t* ftr)
{
	type_filter_t *d;
	int i;

	if (ftr == NULL)
		return;
	d = (type_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->types)
		free(d->types);
	if (d->type_strs) {
		for (i = 0; i < d->num_types; i++) {
			if (d->type_strs[i])
				free(d->type_strs[i]);
		}
		free(d->type_strs);
	}
	free(d);
	return;
}

/*
 * create the entire source type filter */
filter_t* src_type_filter_create(char **types, int num_types)
{
        filter_t *new;
	type_filter_t *d;
	int i;
	d = (type_filter_t*)malloc(sizeof(type_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(type_filter_t));
	d->types = (int*)malloc(sizeof(int) * num_types);
	if (d->types == NULL)
		goto bad;
	d->type_strs = (char**)calloc(num_types, sizeof(char*));
	if (d->type_strs == NULL)
		goto bad;
	for (i = 0; i < num_types; i++) {
		d->type_strs[i] = (char*)malloc(sizeof(char) * (strlen(types[i])+1));
		if (!d->type_strs[i])
			goto bad;
		strcpy(d->type_strs[i], types[i]);
	}
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &src_type_filter_action; 
	new->destroy = &type_filter_destroy; 
	new->data = (type_filter_t*)d; 
	new->dirty = TRUE;
	d->num_types = num_types;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->types)
			free(d->types);
		if (d->type_strs) {
			for (i = 0; i < num_types; i++)
				if (d->type_strs[i])
					free(d->type_strs[i]);
			free(d->type_strs);
		}
		free(d);
	}
	return NULL;
}

/*
 * create the entire target type filter */
filter_t* tgt_type_filter_create(char **types, int num_types)
{
        filter_t *new;
	type_filter_t *d;
	int i;
	d = (type_filter_t*)malloc(sizeof(type_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(type_filter_t));
	d->types = (int*)malloc(sizeof(int) * num_types);
	if (d->types == NULL)
		goto bad;
	d->type_strs = (char**)calloc(num_types, sizeof(char*));
	if (d->type_strs == NULL)
		goto bad;
	for (i = 0; i < num_types; i++) {
		d->type_strs[i] = (char*)malloc(sizeof(char) * (strlen(types[i])+1));
		if (!d->type_strs[i])
			goto bad;
		strcpy(d->type_strs[i], types[i]);
	}
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &tgt_type_filter_action; 
	new->destroy = &type_filter_destroy; 
	new->data = (type_filter_t*)d; 
	new->dirty = TRUE;
	d->num_types = num_types;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->types)
			free(d->types);
		if (d->type_strs) {
			for (i = 0; i < num_types; i++)
				if (d->type_strs[i])
					free(d->type_strs[i]);
			free(d->type_strs);
		}
		free(d);
	}
	return NULL;
}

/*
 * destroy the date filter, not the container struct */
static void date_filter_destroy(filter_t* ftr)
{
	date_filter_t *d;
	if (ftr == NULL)
		return;
	d = (date_filter_t*)ftr->data;
	free(d);
	return;
}

/*
 * create the entire date filter */
filter_t* date_filter_create(struct tm start_date, struct tm end_date)
{
        filter_t *new;
	date_filter_t *d;
	d = (date_filter_t*)malloc(sizeof(date_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(date_filter_t));
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types = AVC_MSG | LOAD_POLICY_MSG;
	new->filter_act = &date_filter_action; 
	new->destroy = &date_filter_destroy; 
	new->data = d; 
	/* set date_filter variables */
	d->start_date = start_date;
	d->end_date = end_date;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

/*
 * destroy the role filter, not the container struct */
static void role_filter_destroy(filter_t *ftr)
{
	role_filter_t *d;
	int i;
	if (ftr == NULL)
		return;
	d = (role_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->roles != NULL)
		free(d->roles);
	if (d->role_strs) {
		for (i = 0; i < d->num_roles; i++)
			if (d->role_strs[i])
				free(d->role_strs[i]);
		free(d->role_strs);
	}
	free(d);
	return;
}

/*
 * create the entire source role filter */
filter_t* src_role_filter_create(char **roles, int num_roles)
{
        filter_t *new;
	role_filter_t *d;
	int i;
	d = (role_filter_t*)malloc(sizeof(role_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(role_filter_t));
	d->roles = (int*)malloc(sizeof(int) * num_roles);
	if (d->roles == NULL)
		goto bad;
	d->role_strs = (char**)calloc(num_roles, sizeof(char*));
	if (!d->role_strs)
		goto bad;
	for (i = 0; i < num_roles; i++) {
		d->role_strs[i] = (char*)malloc(sizeof(char) * (strlen(roles[i])+1));
		if (!d->role_strs[i])
			goto bad;
		strcpy(d->role_strs[i], roles[i]);
	}
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &src_role_filter_action; 
	new->destroy = &role_filter_destroy; 
	new->data = d; 
	d->num_roles = num_roles;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->roles)
			free(d->roles);
		if (d->role_strs) {
			for (i = 0; i < num_roles; i++)
				if (d->role_strs[i])
					free(d->role_strs[i]);
			free(d->role_strs);
		}
		free(d);
	}
	return NULL;
}
/*
 * create the entire target role filter */
filter_t* tgt_role_filter_create(char **roles, int num_roles)
{
        filter_t *new;
	role_filter_t *d;
	int i;
	d = (role_filter_t*)malloc(sizeof(role_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(role_filter_t));
	d->roles = (int*)malloc(sizeof(int) * num_roles);
	if (d->roles == NULL)
		goto bad;
	d->role_strs = (char**)calloc(num_roles, sizeof(char*));
	if (!d->role_strs)
		goto bad;
	for (i = 0; i < num_roles; i++) {
		d->role_strs[i] = (char*)malloc(sizeof(char) * (strlen(roles[i])+1));
		if (!d->role_strs[i])
			goto bad;
		strcpy(d->role_strs[i], roles[i]);
	}
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &tgt_role_filter_action; 
	new->destroy = &role_filter_destroy; 
	new->data = d; 

	d->num_roles = num_roles;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->roles)
			free(d->roles);
		if (d->role_strs) {
			for (i = 0; i < num_roles; i++)
				if (d->role_strs[i])
					free(d->role_strs[i]);
			free(d->role_strs);
		}
		free(d);
	}
	return NULL;   
}

/*
 * destroy the user filter, not the container struct */
static void user_filter_destroy(filter_t *ftr)
{
	user_filter_t *d;
	int i;
	if (ftr == NULL)
		return;
	d = (user_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->users)
		free(d->users);
	if (d->user_strs) {
		for (i = 0; i < d->num_users; i++)
			if (d->user_strs[i])
				free(d->user_strs[i]);
		free(d->user_strs);
	}
	free(d);
	return;
}

/*
 * create the entire source user filter */
filter_t* src_user_filter_create(char **users, int num_users)
{
        filter_t *new;
	user_filter_t *d;
	int i;
	d = (user_filter_t*)malloc(sizeof(user_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(user_filter_t));
	d->users = (int*)malloc(sizeof(int) * num_users);
	if (d->users == NULL) 
		goto bad;
	d->user_strs = (char**)calloc(num_users, sizeof(char*));
	if (!d->user_strs)
		goto bad;
	for (i = 0; i < num_users; i++) {
		d->user_strs[i] = (char*)malloc(sizeof(char) * (strlen(users[i])+1));
		if (!d->user_strs[i])
			goto bad;
		strcpy(d->user_strs[i], users[i]);
	}
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &src_user_filter_action; 
	new->destroy = &user_filter_destroy; 
	new->data = d; 
	/* set user_filter variables */
	for (i = 0; i < num_users; i++) {
		strcpy(d->user_strs[i], users[i]);
	}
	d->num_users = num_users;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->users)
			free(d->users);
		if (d->user_strs) {
			for (i = 0; i < num_users; i++)
				if (d->user_strs[i])
					free(d->user_strs[i]);
			free(d->user_strs);
		}
		free(d);
	}
	return NULL;
}


/*
 * create the entire target user filter */
filter_t* tgt_user_filter_create(char **users, int num_users)
{
        filter_t *new;
	user_filter_t *d;
	int i;
	d = (user_filter_t*)malloc(sizeof(user_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(user_filter_t));
	d->users = (int*)malloc(sizeof(int) * num_users);
	if (d->users == NULL) 
		goto bad;
	d->user_strs = (char**)calloc(num_users, sizeof(char*));
	if (!d->user_strs)
		goto bad;
	for (i = 0; i < num_users; i++) {
		d->user_strs[i] = (char*)malloc(sizeof(char) * (strlen(users[i])+1));
		if (!d->user_strs[i])
			goto bad;
		strcpy(d->user_strs[i], users[i]);
	}
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &tgt_user_filter_action;
	new->destroy = &user_filter_destroy;
	new->data = d; 

	d->num_users = num_users;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->users)
			free(d->users);
		if (d->user_strs) {
			for (i = 0; i < num_users; i++)
				if (d->user_strs[i])
					free(d->user_strs[i]);
			free(d->user_strs);
		}			
		free(d);
	}
	return NULL;
}

/*
 * destroy the class filter, not the container struct */
static void class_filter_destroy(filter_t *ftr)
{
	class_filter_t *d;
	int i;
	if (ftr == NULL)
		return;
	d = (class_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->classes)
		free(d->classes);
	if (d->class_strs) {
		for (i = 0; i < d->num_classes; i++)
			if (d->class_strs[i])
				free(d->class_strs[i]);
		free(d->class_strs);
	}
	free(d);
	return;
}

/*
 * create the entire class filter */
filter_t* class_filter_create(char **strs, int num_classes)
{
        filter_t *new;
	class_filter_t *d;
	int i;

	d = (class_filter_t*)malloc(sizeof(class_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(class_filter_t));
	d->classes = (int*)malloc(sizeof(int) * num_classes);
	if (d->classes == NULL)
		goto bad;
	d->class_strs = (char**)calloc(num_classes, sizeof(char*));
	if (d->class_strs == NULL) 
		goto bad;
	for (i = 0; i < num_classes; i++) {
		d->class_strs[i] = (char*)malloc(sizeof(char) * (strlen(strs[i])+1));
		if (!d->class_strs[i])
			goto bad;
		strcpy(d->class_strs[i], strs[i]);
	}
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &class_filter_action; 
	new->destroy = &class_filter_destroy; 
	new->data = d; 
	/* set class_filter variables */
	for (i = 0; i < num_classes; i++) {
		strcpy(d->class_strs[i], strs[i]);
	}
	d->num_classes = num_classes;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->classes)
			free(d->classes);
		if (d->class_strs) {
			for (i = 0; i < num_classes; i++)
				if (d->class_strs[i])
					free(d->class_strs[i]);
			free(d->class_strs);
		}
		free(d);
	}
	return NULL;
}

/*
 * destroy the perms filter, not the container struct */
static void perms_filter_destroy(filter_t *ftr)
{
	perms_filter_t *d;
	if (ftr == NULL)
		return;
	d = (perms_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->perms != NULL)
		free(d->perms);
	free(d);
	return;
}

/*
 * create the entire perms filter */
filter_t* perms_filter_create(int *perms, int num_perms)
{ 
        filter_t *new;
	perms_filter_t *d;
	int i;
	d = (perms_filter_t*)malloc(sizeof(perms_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(perms_filter_t));
	d->perms = (int*)malloc(sizeof(int) * num_perms);
	if (d->perms == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &perms_filter_action; 
	new->destroy = &perms_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	for (i = 0; i < num_perms; i++) {
		d->perms[i] = perms[i];
	}
	d->num_perms = num_perms;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->perms)
			free(d->perms);
		free(d);
	}
	return NULL;
}

/*
 * destroy the exe filter, not the container struct */
static void exe_filter_destroy(filter_t *ftr)
{
	exe_filter_t *d;
	if (ftr == NULL)
		return;
	d = (exe_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->exe != NULL)
		free(d->exe);
	free(d);
	return;
}

/*
 * create the entire exe filter */
filter_t* exe_filter_create(const char* exe)
{
        filter_t *new;
	exe_filter_t *d;
	int i;
	d = (exe_filter_t*)malloc(sizeof(exe_filter_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(exe_filter_t));
	i = strlen(exe);
	d->exe = (char*)malloc(sizeof(char) * (i+1));
	if (d->exe == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &exe_filter_action; 
	new->destroy = &exe_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->exe, exe);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->exe)
			free(d->exe);
		free(d);
	}
	return NULL;
}

static void netif_filter_destroy(filter_t *ftr) 
{
	netif_filter_t *d;
	if (ftr == NULL)
		return;
	d = (netif_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->netif != NULL)
		free(d->netif);
	free(d);
	return;
}

filter_t* netif_filter_create(const char *netif)
{
        filter_t *new;
	netif_filter_t *d;
	int i;
	d = (netif_filter_t*)malloc(sizeof(netif_filter_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(netif_filter_t));
	i = strlen(netif);
	d->netif = (char*)malloc(sizeof(char) * (i+1));
	if (d->netif == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &netif_filter_action; 
	new->destroy = &netif_filter_destroy;
	new->data = d; 
	/* set filter variables */
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

static void comm_filter_destroy(filter_t *ftr) 
{
	comm_filter_t *d;
	if (ftr == NULL)
		return;
	d = (comm_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->comm != NULL)
		free(d->comm);
	free(d);
	return;
}

filter_t* comm_filter_create(const char *comm)
{
        filter_t *new;
	comm_filter_t *d;
	int i;
	d = (comm_filter_t*)malloc(sizeof(comm_filter_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(comm_filter_t));
	i = strlen(comm);
	d->comm = (char*)malloc(sizeof(char) * (i+1));
	if (d->comm == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &comm_filter_action; 
	new->destroy = &comm_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->comm, comm);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->comm)
			free(d->comm);
		free(d);
	}
	return NULL;
}

static void laddr_filter_destroy(filter_t *ftr) 
{
	laddr_filter_t *d;
	if (ftr == NULL)
		return;
	d = (laddr_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->laddr != NULL)
		free(d->laddr);
	free(d);
	return;
}

filter_t* laddr_filter_create(const char *laddr)
{
        filter_t *new;
	laddr_filter_t *d;
	int i;
	d = (laddr_filter_t*)malloc(sizeof(laddr_filter_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(laddr_filter_t));
	i = strlen(laddr);
	d->laddr = (char*)malloc(sizeof(char) * (i+1));
	if (d->laddr == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &laddr_filter_action; 
	new->destroy = &laddr_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->laddr, laddr);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->laddr)
			free(d->laddr);
		free(d);
	}
	return NULL;
}

static void faddr_filter_destroy(filter_t *ftr) 
{
	faddr_filter_t *d;
	if (ftr == NULL)
		return;
	d = (faddr_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->faddr != NULL)
		free(d->faddr);
	free(d);
	return;
}

filter_t* faddr_filter_create(const char *faddr)
{
        filter_t *new;
	faddr_filter_t *d;
	int i;
	d = (faddr_filter_t*)malloc(sizeof(faddr_filter_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(faddr_filter_t));
	i = strlen(faddr);
	d->faddr = (char*)malloc(sizeof(char) * (i+1));
	if (d->faddr == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &faddr_filter_action; 
	new->destroy = &faddr_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->faddr, faddr);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->faddr)
			free(d->faddr);
		free(d);
	}
	return NULL;
}

static void daddr_filter_destroy(filter_t *ftr) 
{
	daddr_filter_t *d;
	if (ftr == NULL)
		return;
	d = (daddr_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->daddr != NULL)
		free(d->daddr);
	free(d);
	return;
}

filter_t* daddr_filter_create(const char *daddr)
{
        filter_t *new;
	daddr_filter_t *d;
	int i;
	d = (daddr_filter_t*)malloc(sizeof(daddr_filter_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(daddr_filter_t));
	i = strlen(daddr);
	d->daddr = (char*)malloc(sizeof(char) * (i+1));
	if (d->daddr == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &daddr_filter_action; 
	new->destroy = &daddr_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->daddr, daddr);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->daddr)
			free(d->daddr);
		free(d);
	}
	return NULL;
}

static void ipaddr_filter_destroy(filter_t *ftr)
{
	ipaddr_filter_t *d;
	if (ftr == NULL)
		return;
	d = (ipaddr_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->ipaddr != NULL)
		free(d->ipaddr);
	free(d);
	return;
}

filter_t* ipaddr_filter_create(const char *ipaddr)
{
        filter_t *new;
	ipaddr_filter_t *d;
	int i;
	d = (ipaddr_filter_t*)malloc(sizeof(ipaddr_filter_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(ipaddr_filter_t));
	i = strlen(ipaddr);
	d->ipaddr = (char*)malloc(sizeof(char) * (i+1));
	if (d->ipaddr == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &ipaddr_filter_action; 
	new->destroy = &ipaddr_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->ipaddr, ipaddr);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->ipaddr)
			free(d->ipaddr);
		free(d);
	}
	return NULL;
}

static void saddr_filter_destroy(filter_t *ftr) 
{
	saddr_filter_t *d;
	if (ftr == NULL)
		return;
	d = (saddr_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->saddr != NULL)
		free(d->saddr);
	free(d);
	return;
}

filter_t* saddr_filter_create(const char *saddr)
{
        filter_t *new;
	saddr_filter_t *d;
	int i;
	d = (saddr_filter_t*)malloc(sizeof(saddr_filter_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(saddr_filter_t));
	i = strlen(saddr);
	d->saddr = (char*)malloc(sizeof(char) * (i+1));
	if (d->saddr == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &saddr_filter_action; 
	new->destroy = &saddr_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->saddr, saddr);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->saddr)
			free(d->saddr);
		free(d);
	}
	return NULL;
}

static void path_filter_destroy(filter_t *ftr)
{
	path_filter_t *d;
	if (ftr == NULL)
		return;
	d = (path_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->path != NULL)
		free(d->path);
	free(d);
	return;
}

/*
 * create the entire path filter */
filter_t* path_filter_create(const char *path)
{
        filter_t *new;
	path_filter_t *d;
	int i;
	d = (path_filter_t*)malloc(sizeof(path_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(path_filter_t));
	i = strlen(path);
	d->path = (char*)malloc(sizeof(char) * (i+1));
	if (d->path == NULL) 
		goto bad;
	new = filter_create();
	if (new == NULL) 
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &path_filter_action; 
	new->destroy = &path_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->path, path);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->path)
			free(d->path);
		free(d);
	}
	return NULL;
}

static void dev_filter_destroy(filter_t *ftr)
{
	dev_filter_t *d;
	if (ftr == NULL)
		return;
	d = (dev_filter_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->dev != NULL)
		free(d->dev);
	free(d);
	return;
}

/*
 * create the entire dev filter */
filter_t* dev_filter_create(const char *dev)
{
        filter_t *new;
	dev_filter_t *d;
	int i;
	d = (dev_filter_t*)malloc(sizeof(dev_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(dev_filter_t));
	i = strlen(dev);
	d->dev = (char*)malloc(sizeof(char) * (i+1));
	if (d->dev == NULL)
		goto bad;
	new = filter_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &dev_filter_action; 
	new->destroy = &dev_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	strcpy(d->dev, dev);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->dev)
			free(d->dev);
		free(d);
	}
	return NULL;
}

static void msg_filter_destroy(filter_t *ftr)
{
	msg_filter_t *d;
	if (ftr == NULL)
		return;
	d = (msg_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

/*
 * create the entire msg filter */
filter_t* msg_filter_create(int msg)
{
        filter_t *new;
	msg_filter_t *d;

	d = (msg_filter_t*)malloc(sizeof(msg_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(msg_filter_t));
	d->msg = msg;

	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &msg_filter_action; 
	new->destroy = &msg_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void pid_filter_destroy(filter_t *ftr)
{
	pid_filter_t *d;
	if (ftr == NULL)
		return;
	d = (pid_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* pid_filter_create(unsigned int pid)
{
        filter_t *new;
	pid_filter_t *d;
	d = (pid_filter_t*)malloc(sizeof(pid_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(pid_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &pid_filter_action; 
	new->destroy = &pid_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->pid = pid;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void ssid_filter_destroy(filter_t *ftr)
{
	ssid_filter_t *d;
	if (ftr == NULL)
		return;
	d = (ssid_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* ssid_filter_create(unsigned int ssid)
{
        filter_t *new;
	ssid_filter_t *d;
	d = (ssid_filter_t*)malloc(sizeof(ssid_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(ssid_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &ssid_filter_action; 
	new->destroy = &ssid_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->ssid = ssid;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void tsid_filter_destroy(filter_t *ftr)
{
	tsid_filter_t *d;
	if (ftr == NULL)
		return;
	d = (tsid_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* tsid_filter_create(unsigned int tsid)
{
        filter_t *new;
	tsid_filter_t *d;
	d = (tsid_filter_t*)malloc(sizeof(tsid_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(tsid_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &tsid_filter_action; 
	new->destroy = &tsid_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->tsid = tsid;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void key_filter_destroy(filter_t *ftr)
{
	key_filter_t *d;
	if (ftr == NULL)
		return;
	d = (key_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* key_filter_create(int key)
{
        filter_t *new;
	key_filter_t *d;
	d = (key_filter_t*)malloc(sizeof(key_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(key_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &key_filter_action; 
	new->destroy = &key_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->key = key;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void capability_filter_destroy(filter_t *ftr)
{
	capability_filter_t *d;
	if (ftr == NULL)
		return;
	d = (capability_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* capability_filter_create(int capability)
{
        filter_t *new;
	capability_filter_t *d;
	d = (capability_filter_t*)malloc(sizeof(capability_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(capability_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &capability_filter_action; 
	new->destroy = &capability_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->capability = capability;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void ports_filter_destroy(filter_t *ftr)
{
	ports_filter_t *d;
	if (ftr == NULL)
		return;
	d = (ports_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* ports_filter_create(int port)
{
        filter_t *new;
	ports_filter_t *d;
	d = (ports_filter_t*)malloc(sizeof(ports_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(ports_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &ports_filter_action; 
	new->destroy = &ports_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->port = port;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void port_filter_destroy(filter_t *ftr)
{
	port_filter_t *d;
	if (ftr == NULL)
		return;
	d = (port_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* port_filter_create(int port)
{
        filter_t *new;
	port_filter_t *d;
	d = (port_filter_t*)malloc(sizeof(port_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(port_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &port_filter_action; 
	new->destroy = &port_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->port = port;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void lport_filter_destroy(filter_t *ftr)
{
	lport_filter_t *d;
	if (ftr == NULL)
		return;
	d = (lport_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* lport_filter_create(int lport)
{
        filter_t *new;
	lport_filter_t *d;
	d = (lport_filter_t*)malloc(sizeof(lport_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(lport_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &lport_filter_action; 
	new->destroy = &lport_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->lport = lport;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void fport_filter_destroy(filter_t *ftr)
{
	fport_filter_t *d;
	if (ftr == NULL)
		return;
	d = (fport_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* fport_filter_create(int fport)
{
        filter_t *new;
	fport_filter_t *d;
	d = (fport_filter_t*)malloc(sizeof(fport_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(fport_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &fport_filter_action; 
	new->destroy = &fport_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->fport = fport;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void dest_filter_destroy(filter_t *ftr)
{
	dest_filter_t *d;
	if (ftr == NULL)
		return;
	d = (dest_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* dest_filter_create(int dest)
{
        filter_t *new;
	dest_filter_t *d;
	d = (dest_filter_t*)malloc(sizeof(dest_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(dest_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &dest_filter_action; 
	new->destroy = &dest_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->dest = dest;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void source_filter_destroy(filter_t *ftr)
{
	source_filter_t *d;
	if (ftr == NULL)
		return;
	d = (source_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* source_filter_create(int source)
{
        filter_t *new;
	source_filter_t *d;
	d = (source_filter_t*)malloc(sizeof(source_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(source_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &source_filter_action; 
	new->destroy = &source_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->source = source;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void inode_filter_destroy(filter_t *ftr)
{
	inode_filter_t *d;
	if (ftr == NULL)
		return;
	d = (inode_filter_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

filter_t* inode_filter_create(unsigned int inode)
{
        filter_t *new;
	inode_filter_t *d;
	d = (inode_filter_t*)malloc(sizeof(inode_filter_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(inode_filter_t));
	new = filter_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->filter_act = &inode_filter_action; 
	new->destroy = &inode_filter_destroy; 
	new->data = d; 
	/* set filter variables */
	d->inode = inode;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}
