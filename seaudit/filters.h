/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: kcarr@tresys.com and Karl MacMillan <kmacmillan@tresys.com>
 * Date: October 6, 2003
 * 
 * This file contains the data structure definitions for storing
 * audit log filters.
 *
 * filters.h
 */

#ifndef LIBAUDIT_FILTERS_H
#define LIBAUDIT_FILTERS_H

#include <time.h>
#include "auditlog.h"
#include "../libapol/util.h"

struct filter;
/* callback type for filter */
typedef bool_t(*filter_action_t)(msg_t *msg, void *data, bool_t *err); 
/* callback type for filter cleanup */
typedef void(*filter_destroy_t)(struct filter *myfilter);

/*
 * generic filter structure */
typedef struct filter {  
	unsigned int msg_types;     /* message types for the filter */
	filter_action_t filter_act; /* function to perform the filter */
	filter_destroy_t destroy;   /* function to free the filter type */
	void *data;                 /* data for the filter ie. date_filter_t */
	struct filter *prev;
	struct filter *next;
} filter_t;

/*
 * the following functions are for creating filters */
filter_t* filter_create(void);
void filter_destroy(filter_t *ftr);
filter_t* src_type_filter_create(int *types, int num_types);
filter_t* tgt_type_filter_create(int *types, int num_types);
filter_t* date_filter_create(struct tm start_date, struct tm end_date);
filter_t* src_role_filter_create(int *roles, int num_roles);
filter_t* tgt_role_filter_create(int *roles, int num_roles);
filter_t* src_user_filter_create(int *users, int num_users);
filter_t* tgt_user_filter_create(int *users, int num_users);
filter_t* class_filter_create(int *classes, int num_classes);
filter_t* perms_filter_create(int *perms, int num_perms);
filter_t* exe_filter_create(const char *exe);
filter_t* path_filter_create(const char *path);
filter_t* dev_filter_create(const char *dev);
filter_t* msg_filter_create(int msg);
filter_t* pid_filter_create(unsigned int pid);
filter_t* inode_filter_create(unsigned int inode);

#endif
