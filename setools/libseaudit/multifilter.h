/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: February 06, 2004
 *
 * This file contains the data structure definitions for storing
 * multifilters.
 *
 * multifilter.h
 */

#ifndef LIBSEAUDIT_MULTIFILTER_H
#define LIBSEAUDIT_MULTIFILTER_H

#include "filters.h"
#include <libapol/util.h>

typedef struct seaudit_multifilter {
	llist_t *filters;
	enum seaudit_filter_match_t match;
} seaudit_multifilter_t;

seaudit_multifilter_t* seaudit_multifilter_create(void);  /* create and init */
void seaudit_multifilter_init(seaudit_multifilter_t *multifilter);
void seaudit_multifilter_destroy(seaudit_multifilter_t *multifilter);
void seaudit_multifilter_add_filter(seaudit_multifilter_t *multifilter, seaudit_filter_t *filter);
void seaudit_multifitler_set_match(seaudit_multifilter_t *multifilter, enum seaudit_filter_match_t match);
void seaudit_multifilter_make_dirty_filters(seaudit_multifilter_t *multifilter);
bool_t seaudit_multifilter_does_message_match(seaudit_multifilter_t *filter, msg_t *message, audit_log_t *log);

#endif 
