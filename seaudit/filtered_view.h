/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date : January 22, 2004
 *
 */

#include <gtk/gtk.h>
#include <glade/glade.h>
#include "filter_window.h"

#ifndef SEAUDIT_FILTERED_VIEW_H
#define SEAUDIT_FILTERED_VIEW_H

typedef struct seaudit_filtered_view {
	filters_t *filters;
	SEAuditLogViewStore *store;
	GtkTreeView *tree_view;
	gint notebook_index;
} seaudit_filtered_view_t;

/*
 * Public member functions
 */
seaudit_filtered_view_t* seaudit_filtered_view_create(audit_log_t *log, GtkTreeView *tree_view);
void seaudit_filtered_view_set_log(seaudit_filtered_view_t *view, audit_log_t *log);
void seaudit_filtered_view_display(seaudit_filtered_view_t* filters_view);
void seaudit_filtered_view_set_notebook_index(seaudit_filtered_view_t *filters_view, gint index);
void seaudit_filtered_view_do_filter(seaudit_filtered_view_t *view, gpointer user_data); /* this can be used as a callback from g_list_foreach() */


#endif
