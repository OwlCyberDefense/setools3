/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date : January 22, 2004
 *
 */

#ifndef SEAUDIT_FILTERED_VIEW_H
#define SEAUDIT_FILTERED_VIEW_H

#include <gtk/gtk.h>
#include <glade/glade.h>
#include "multifilter_window.h"
#include "auditlogmodel.h"

typedef struct seaudit_filtered_view {
	multifilter_window_t *multifilter_window;
	SEAuditLogViewStore *store;
	GtkTreeView *tree_view;
	gint notebook_index;
	GString *name;
} seaudit_filtered_view_t;

/*
 * Public member functions
 */
seaudit_filtered_view_t* seaudit_filtered_view_create(audit_log_t *log, GtkTreeView *tree_view, const char *view_name);
void seaudit_filtered_view_destroy(seaudit_filtered_view_t *view);
void seaudit_filtered_view_set_log(seaudit_filtered_view_t *view, audit_log_t *log);
void seaudit_filtered_view_display(seaudit_filtered_view_t* filters_view);
void seaudit_filtered_view_save_view(seaudit_filtered_view_t* filtered_view, gboolean saveas);
void seaudit_filtered_view_set_notebook_index(seaudit_filtered_view_t *filtered_view, gint index);
void seaudit_filtered_view_set_multifilter_window(seaudit_filtered_view_t *filtered_view, multifilter_window_t *window);
void seaudit_filtered_view_do_filter(seaudit_filtered_view_t *view, gpointer user_data); /* this can be used as a callback from g_list_foreach() */
void seaudit_filtered_view_set_name(seaudit_filtered_view_t* filtered_view, const char *name);

#endif
