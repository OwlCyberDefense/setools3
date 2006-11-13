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

#ifdef	__cplusplus
extern "C"
{
#endif

#include "filters.h"
#include <apol/util.h>
#include <apol/vector.h>

	typedef struct seaudit_multifilter
	{
		apol_vector_t *filters;
		enum seaudit_filter_match_t match;	/* SEAUDIT_FILTER_MATCH_ALL, 
							 * SEAUDIT_FILTER_MATCH_ANY */
		bool_t show;	       /* show matches */
		char *name;
	} seaudit_multifilter_t;

	seaudit_multifilter_t *seaudit_multifilter_create(void);	/* create and init */
	void seaudit_multifilter_init(seaudit_multifilter_t * multifilter);
	void seaudit_multifilter_destroy(seaudit_multifilter_t * multifilter);
	void seaudit_multifilter_add_filter(seaudit_multifilter_t * multifilter, seaudit_filter_t * filter);
	void seaudit_multifilter_set_match(seaudit_multifilter_t * multifilter, enum seaudit_filter_match_t match);
	void seaudit_multifilter_set_show_matches(seaudit_multifilter_t * multifilter, bool_t show);
	void seaudit_multifilter_set_name(seaudit_multifilter_t * multifilter, const char *name);
	void seaudit_multifilter_make_dirty_filters(seaudit_multifilter_t * multifilter);
	bool_t seaudit_multifilter_should_message_show(seaudit_multifilter_t * multifilter, msg_t * message, audit_log_t * log);
	int seaudit_multifilter_save_to_file(seaudit_multifilter_t * multifilter, const char *filename);
	int seaudit_multifilter_load_from_file(seaudit_multifilter_t ** multifilter, bool_t * is_multi, const char *filename);

#ifdef	__cplusplus
}
#endif

#endif
