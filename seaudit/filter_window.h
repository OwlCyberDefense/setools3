/* Copyright (C) 2003 Tresys Technology, LLC
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
#include <glib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

enum {
	ITEMS_LIST_COLUMN, 
	NUMBER_ITEMS_LIST_COLUMNS
};

enum items_list_types_t {
	SEAUDIT_SRC_TYPES,
	SEAUDIT_SRC_USERS,
	SEAUDIT_SRC_ROLES,
	SEAUDIT_TGT_TYPES,
	SEAUDIT_TGT_USERS,
	SEAUDIT_TGT_ROLES,
	SEAUDIT_OBJECTS
};

enum select_values_source_t {
	SEAUDIT_FROM_LOG,
	SEAUDIT_FROM_POLICY,
	SEAUDIT_FROM_UNION
};

typedef struct  seaudit_filter_list {
	char **list;
	int size;
} seaudit_filter_list_t;

void filters_seaudit_filter_list_free(seaudit_filter_list_t *list);

struct filters;

typedef struct filters_select_items {
	GtkListStore *selected_items;
	GtkListStore *unselected_items;
	enum items_list_types_t items_list_type;
        enum select_values_source_t items_source;
	GtkWindow *window;
	GladeXML *xml;
	struct filters *parent;
} filters_select_items_t;

void filters_select_items_parse_entry(filters_select_items_t *s);

typedef struct filters {
	filters_select_items_t *src_types_items;
	filters_select_items_t *src_users_items;
	filters_select_items_t *src_roles_items;
	filters_select_items_t *tgt_types_items;
	filters_select_items_t *tgt_users_items;
	filters_select_items_t *tgt_roles_items;
	filters_select_items_t *obj_class_items;
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
seaudit_filter_list_t* filters_seaudit_filter_list_get(filters_select_items_t *filters_select_item);

#endif
