/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Author: Brandon Whalen <bwhalen@tresys.com>
 * Date: January 31, 2005
 */
 
#ifndef SEDIFF_GUI_H
#define SEDIFF_GUI_H

#include "sediff_treemodel.h"
#include "sediff_rename_types.h"
#include <gtk/gtk.h>
#include <glade/glade.h>

#define GLADEFILE "sediff.glade"

#define MAIN_WINDOW_ID 	       "sediff_main_window"
#define OPEN_DIALOG_ID 	       "sediff_policies_dialog"
#define RENAME_TYPES_DIALOG_ID "sediff_rename_types_dialog"

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
	summary_node_t rallow;
	summary_node_t rtrans;
	summary_node_t te_rules;
	summary_node_t conds;
} sediff_summary_t;

typedef struct sediff_app {
	GtkWindow *window;		/* the main window */
	GtkWindow *open_dlg; 
	GtkWidget *loading_dlg;
	GtkWidget *dummy_view;
	GladeXML *window_xml;
	GladeXML *open_dlg_xml;
	GtkWidget *tree_view;	
	GtkTextBuffer *policy1_text;
	GtkTextBuffer *policy2_text;
	GList *callbacks;
	gint progress_completed;
	GtkTextBuffer *summary_buffer;
	GtkTextBuffer *classes_buffer;
	GtkTextBuffer *types_buffer;
	GtkTextBuffer *roles_buffer;
	GtkTextBuffer *users_buffer;
	GtkTextBuffer *booleans_buffer;
	GtkTextBuffer *attribs_buffer;
	GtkTextBuffer *te_buffer;
	GtkTextBuffer *rbac_buffer;
	GtkTextBuffer *conditionals_buffer;
	GString *p1_filename;
	GString *p2_filename;
	struct sediff_rename_types *rename_types;
	policy_t *p1;
	policy_t *p2;
	sediff_summary_t summary;
} sediff_app_t;

#endif
