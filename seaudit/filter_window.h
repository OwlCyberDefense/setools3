/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: October 23, 2003
 *
 * Modified by Don Patterson <don.patterson@tresys.com>
 * and Karl MacMillan <kmacmillan@tresys.com>
 *
 */

#ifndef SEAUDIT_FILTER_WINDOW_H
#define SEAUDIT_FILTER_WINDOW_H

#include <glib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

struct filters_select_items;

typedef struct filters {
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
	GtkWindow *window;
	GladeXML *xml;
} filters_t;

/***************************
 * Public member functions *
 ***************************/
filters_t* filters_create(void);
void filters_destroy(filters_t* filters);
void filters_display(filters_t* filters);

#endif
