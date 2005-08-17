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
#include "sediff_find_window.h"
#include "poldiff.h"
#include <gtk/gtk.h>
#include <glade/glade.h>

#define GLADEFILE "sediff.glade"

#define MAIN_WINDOW_ID 	       "sediff_main_window"
#define OPEN_DIALOG_ID 	       "sediff_policies_dialog"
#define RENAME_TYPES_DIALOG_ID "sediff_rename_types_dialog"
#define FIND_DIALOG_ID       "sediff_find_dialog"
#define FIND_FORWARD_ID      "sediff_find_forward"
#define FIND_ENTRY_ID        "sediff_find_text_entry"

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
	GtkTextBuffer *main_buffer;
	GtkTextBuffer *te_buffer;
	GtkTextBuffer *te_add_buffer;
	GtkTextBuffer *te_rem_buffer;
	GtkTextBuffer *te_chg_buffer;
	GtkTextBuffer *te_add_type_buffer;
	GtkTextBuffer *te_rem_type_buffer;
	GtkTextBuffer *summary_buffer;
	GtkTextBuffer *cond_buffer;
	GtkTextBuffer *cond_add_buffer;
	GtkTextBuffer *cond_rem_buffer;
	GtkTextBuffer *cond_chg_buffer;
	GString *p1_filename;
	GString *p2_filename;
	ap_single_view_diff_t *svd;
	apol_diff_result_t *diff_results;
	struct sediff_rename_types *rename_types_window;
	struct sediff_find_window *find_window;
	policy_t *p1;
	policy_t *p2;
} sediff_app_t;

GtkTextView *sediff_get_current_view(sediff_app_t *app);

#endif
