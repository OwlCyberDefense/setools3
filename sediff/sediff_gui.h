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

/* STRUCT: sediff_app_t
   This structure is used to control the gui.  It contains the links
   to all necessary buffers, textviews, dlgs, etc that are needed.  */
typedef struct sediff_app {
	GtkWindow *window;		  /* the main window */
	GtkWindow *open_dlg;              /* dialog box used when opening up the policies */
	GtkWidget *modal_dlg;             /* a modal dlg used for keeping user input from happening on long computations */
	GtkWidget *dummy_view;            /* this is a view we put in the left hand pane when we have no diff, and therefore no treeview */
	GladeXML *window_xml;             /* the main windows xml */
	GladeXML *open_dlg_xml;           /* the open dialogs xml */
	GtkWidget *tree_view;	          /* the treeview seen on left hand pane */
	GList *callbacks;               
	gint progress_completed;
	GtkTextBuffer *main_buffer;       /* the generic buffer used for everything but te rules and conditionals(because they take so long to draw */
	GtkTextBuffer *te_buffer;         /* the top level node in the te diff */
	GtkTextBuffer *te_add_buffer;     /* the added te rules buffer */
	GtkTextBuffer *te_rem_buffer;     /* the removed te rules buffer */
	GtkTextBuffer *te_chg_buffer;     /* the changed te rules buffer */
	GtkTextBuffer *te_add_type_buffer;/* the te rules added because of a new type buffer */
	GtkTextBuffer *te_rem_type_buffer;/* the te rules removed because of a missing type buffer */
	GtkTextBuffer *summary_buffer;    /* the summary buffer */
	GtkTextBuffer *cond_buffer;       /* the top level conditional buffer */
	GtkTextBuffer *cond_add_buffer;   /* the added conditionals buffer */
	GtkTextBuffer *cond_rem_buffer;   /* the removed conditionals buffer */
	GtkTextBuffer *cond_chg_buffer;   /* the changed conditionals buffer */
	GString *p1_filename;             /* the name of policy 1 */
	GString *p2_filename;             /* the name of policy 2 */
	ap_single_view_diff_t *svd;       /* the single view diff struct */
	struct sediff_rename_types *rename_types_window; /* the renamed types window reference */
	struct sediff_find_window *find_window;          /* the find window reference */
	policy_t *p1;                     /* the policy 1 struct */
	policy_t *p2;                     /* the policy 2 struct */
} sediff_app_t;

/* return the textview currently displayed to the user */
GtkTextView *sediff_get_current_view(sediff_app_t *app);

#endif
