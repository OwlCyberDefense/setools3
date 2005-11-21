/* Copyright (C) 2003-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: October 23, 2003
 *
 * Modified by Don Patterson <don.patterson@tresys.com>
 * and Karl MacMillan <kmacmillan@tresys.com>
 *
 *
 */

#ifndef SEAUDIT_FILTER_WINDOW_H
#define SEAUDIT_FILTER_WINDOW_H

#include "auditlogmodel.h"
#include "multifilter_window.h"
#include <libseaudit/filters.h>
#include <glib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

struct filters_select_items;

typedef struct filter_window {
	struct filters_select_items *src_types_items;
	struct filters_select_items *src_users_items;
	struct filters_select_items *src_roles_items;
	struct filters_select_items *tgt_types_items;
	struct filters_select_items *tgt_users_items;
	struct filters_select_items *tgt_roles_items;
	struct filters_select_items *obj_class_items;
	GString *ip_address;
	GString *port;
	GString *interface;
	GString *executable;
	GString *path;
	GString *name;
	GString *match;
	GString *notes;
	GString *host;
	GtkWindow *window;
	GladeXML *xml;
	multifilter_window_t *parent;
	gint parent_index;
} filter_window_t;

/***************************
 * Public member functions *
 ***************************/
filter_window_t* filter_window_create(multifilter_window_t *parent, gint parent_index, const char *name);
void filter_window_destroy(filter_window_t* filter_window);
void filter_window_display(filter_window_t* filter_window, GtkWindow *parent);
void filter_window_hide(filter_window_t *filter_window);
seaudit_filter_t* filter_window_get_filter(filter_window_t *filter_window);
void filter_window_set_values_from_filter(filter_window_t *filter_window, seaudit_filter_t *filter);

#endif
