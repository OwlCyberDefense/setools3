/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date : January 22, 2004
 *
 */

#include "filtered_view.h"
#include "filter_window.h"
#include "utilgui.h"
#include <string.h>

seaudit_filtered_view_t* seaudit_filtered_view_create(audit_log_t *log, GtkTreeView *tree_view, const char *view_name)
{
	seaudit_filtered_view_t *filtered_view;

	if (tree_view == NULL)
		return NULL;

	filtered_view = (seaudit_filtered_view_t *)malloc(sizeof(seaudit_filtered_view_t));
	if (filtered_view == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	memset(filtered_view, 0, sizeof(seaudit_filtered_view_t));
	if ((filtered_view->multifilter_window = multifilter_window_create(filtered_view, view_name)) == NULL) {
		fprintf(stderr, "out of memory");
		free(filtered_view);
		return NULL;
	}
	if ((filtered_view->store = seaudit_log_view_store_create()) == NULL) {
		fprintf(stderr, "out of memory");
		free(filtered_view->multifilter_window);
		free(filtered_view);
		return NULL;
	}
	filtered_view->notebook_index = -1;
	filtered_view->tree_view = tree_view;
	filtered_view->name = g_string_new(view_name);
	seaudit_log_view_store_open_log(filtered_view->store, log);
	gtk_tree_view_set_model(tree_view, GTK_TREE_MODEL(filtered_view->store));

	return filtered_view;
}

void seaudit_filtered_view_destroy(seaudit_filtered_view_t *view)
{
	multifilter_window_destroy(view->multifilter_window);
	seaudit_log_view_store_close_log(view->store);
	g_string_free(view->name, TRUE);
}

void seaudit_filtered_view_display(seaudit_filtered_view_t* filtered_view, GtkWindow *parent)
{
	if(!filtered_view)
		return;
	multifilter_window_display(filtered_view->multifilter_window, parent);
}

void seaudit_filtered_view_set_log(seaudit_filtered_view_t *view, audit_log_t *log)
{
	if (view == NULL)
		return ;
	seaudit_log_view_store_close_log(view->store);
	seaudit_log_view_store_open_log(view->store, log);
}

void seaudit_filtered_view_save_view(seaudit_filtered_view_t* filtered_view, gboolean saveas)
{
	if (!filtered_view)
		return;
	multifilter_window_save_multifilter(filtered_view->multifilter_window, saveas, FALSE);
}

void seaudit_filtered_view_set_multifilter_window(seaudit_filtered_view_t *filtered_view, multifilter_window_t *window)
{
	multifilter_window_destroy(filtered_view->multifilter_window);
	filtered_view->multifilter_window = window;
	g_string_assign(window->name, filtered_view->name->str);
	window->parent = filtered_view;
}

void seaudit_filtered_view_set_notebook_index(seaudit_filtered_view_t *filtered_view, gint index)
{
	if (filtered_view == NULL)
		return;
	filtered_view->notebook_index = index;
}

void seaudit_filtered_view_do_filter(seaudit_filtered_view_t *view, gpointer user_data)
{
	if (!view)
		return;
	multifilter_window_apply_multifilter(view->multifilter_window);
}


