/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: February 06, 2004
 *
 * This file contains the data structure definitions for storing
 * filters.
 *
 * filters.h
 */

#ifndef LIBSEAUDIT_FILTER_H
#define LIBSEAUDIT_FILTER_H

#include <libapol/util.h>
#include "filter_criteria.h"

enum seaudit_filter_match_t {
	SEAUDIT_FILTER_MATCH_ALL,
	SEAUDIT_FILTER_MATCH_ANY
};

typedef struct seaudit_filter {
	seaudit_criteria_t *src_type_criteria;
	seaudit_criteria_t *tgt_type_criteria;
	seaudit_criteria_t *src_role_criteria;
	seaudit_criteria_t *tgt_role_criteria;
	seaudit_criteria_t *src_user_criteria;
	seaudit_criteria_t *tgt_user_criteria;
	seaudit_criteria_t *class_criteria;
	seaudit_criteria_t *exe_criteria;
	seaudit_criteria_t *path_criteria;
	seaudit_criteria_t *netif_criteria;
	seaudit_criteria_t *ipaddr_criteria;
	seaudit_criteria_t *ports_criteria;
	enum seaudit_filter_match_t match;
	char *name;
	char *desc;
} seaudit_filter_t;

seaudit_filter_t* seaudit_filter_create(void);  /* create and init */
void seaudit_filter_init(seaudit_filter_t *seaudit_filter);
void seaudit_filter_destroy(seaudit_filter_t *seaudit_filter);
void seaudit_filter_set_match(seaudit_filter_t *seaudit_filter, enum seaudit_filter_match_t match);
void seaudit_filter_set_name(seaudit_filter_t *seaudit_filter, const char *name);
void seaudit_filter_set_desc(seaudit_filter_t *seaudit_filter, const char *desc);
void seaudit_filter_make_dirty_criterias(seaudit_filter_t *seaudit_filter);
bool_t seaudit_filter_does_message_match(seaudit_filter_t *filter, msg_t *message, audit_log_t *log);
int seaudit_filter_save_to_file(seaudit_filter_t *filter, const char *filename);
int seaudit_filter_load_from_file(seaudit_filter_t **filter, const char *filename);
llist_t* seaudit_filter_get_list(seaudit_filter_t *filter);

#endif
