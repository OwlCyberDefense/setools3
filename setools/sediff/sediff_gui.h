/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 28, 2004
 */
 
#ifndef SEDIFF_GUI_H
#define SEDIFF_GUI_H

#include "sediff_treemodel.h"
#include <gtk/gtk.h>
#include <glade/glade.h>

typedef struct summary_node {
	int added;
	int removed;
	int changed;
} summary_node_t;

typedef struct sediff_summary {
	summary_node_t permissions;
	summary_node_t commons;
	summary_node_t classes;
	summary_node_t types;
	summary_node_t attributes;
	summary_node_t users;
	summary_node_t roles;
	summary_node_t booleans;
	summary_node_t rbac;
	summary_node_t te_rules;
} sediff_summary_t;

typedef struct sediff_app {
	GtkWindow *window;		/* the main window */
	GtkWindow *open_dlg;
	GladeXML *window_xml;
	GladeXML *open_dlg_xml;
	GtkWidget *tree_view;	
	GtkTextBuffer *policy1_text;
	GtkTextBuffer *policy2_text;
	GList *callbacks;
	gint progress_completed;
	GtkTextBuffer *classes_buffer;
	GtkTextBuffer *types_buffer;
	GtkTextBuffer *roles_buffer;
	GtkTextBuffer *users_buffer;
	GtkTextBuffer *booleans_buffer;
	GtkTextBuffer *attribs_buffer;
	GtkTextBuffer *te_buffer;
	GtkTextBuffer *rbac_buffer;

	sediff_summary_t summary;

} sediff_app_t;

#endif
