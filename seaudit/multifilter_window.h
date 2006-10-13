/* Copyright (C) 2004-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: February 11, 2004
 *
 */

#ifndef SEAUDIT_MULTIFILTER_WINDOW_H
#define SEAUDIT_MULTIFILTER_WINDOW_H

#include <gtk/gtk.h>
#include <glade/glade.h>

struct filter_window;
struct seaudit_filtered_view;

typedef struct multifilter_window {
	GladeXML *xml;
	GtkWindow *window;
	GtkListStore *liststore;
	GtkTreeView *treeview;
	gint num_filter_windows;
	GList *filter_windows;
	GString *name;
	GString *match;
	GString *show;
	GString *filename;
	struct seaudit_filtered_view *parent;
} multifilter_window_t;

multifilter_window_t* multifilter_window_create(struct seaudit_filtered_view *parent, const gchar *view_name);
void multifilter_window_init(multifilter_window_t *window, struct seaudit_filtered_view *parent, const gchar *view_name);
void multifilter_window_display(multifilter_window_t *window, GtkWindow *parent);
void multifilter_window_hide(multifilter_window_t *window);
void multifilter_window_destroy(multifilter_window_t *window);
void multifilter_window_save_multifilter(multifilter_window_t *window, gboolean saveas, gboolean multifilter_is_parent_window);
int multifilter_window_load_multifilter(multifilter_window_t *window);
void multifilter_window_set_filter_name_in_list(multifilter_window_t *window, struct filter_window *filter_window);
void multifilter_window_apply_multifilter(multifilter_window_t *window);

#endif
