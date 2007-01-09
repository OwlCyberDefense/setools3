/**
 *  @file
 *  Headers for main toplevel window.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef SEDIFF_TOPLEVEL_H
#define SEDIFF_TOPLEVEL_H

#include <apol/policy-path.h>

typedef struct toplevel toplevel_t;

/**
 * Allocate and return an instance of the toplevel window object.
 * This will create the window, set up the menus and icons, then
 * display the window.
 *
 * @param s Main sediffx object that will control the toplevel.
 *
 * @return An initialized toplevel object, or NULL upon error.  The
 * caller must call toplevel_destroy() afterwards.
 */
toplevel_t *toplevel_create(sediffx_t * s);

/**
 * Destroy the toplevel window.  This function will recursively
 * destroy all other windows.  This does nothing if the pointer is set
 * to NULL.
 *
 * @param top Reference to a toplevel object.  Afterwards the pointer
 * will be set to NULL.
 */
void toplevel_destroy(toplevel_t ** top);

int toplevel_open_policies(toplevel_t * top, apol_policy_path_t * orig_path, apol_policy_path_t * mod_path);
void toplevel_run_diff(toplevel_t * top);

/**
 * Pop-up an error dialog with a line of text and wait for the user to
 * dismiss the dialog.
 *
 * @param top Toplevel window; this message dialog will be centered
 * upon it.
 * @param format Format string to print, using syntax of printf(3).
 */
void toplevel_ERR(toplevel_t * top, const char *format, ...) __attribute__ ((format(printf, 2, 3)));

/**
 * Pop-up a warning dialog with a line of text and wait for the user
 * to dismiss the dialog.
 *
 * @param top Toplevel window; this message dialog will be centered
 * upon it.
 * @param format Format string to print, using syntax of printf(3).
 */
void toplevel_WARN(toplevel_t * top, const char *format, ...) __attribute__ ((format(printf, 2, 3)));

#if 0

#include "sediff_treemodel.h"
#include "sediff_remap_types.h"
#include "sediff_find_window.h"
#include <poldiff/poldiff.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#define GLADEFILE "sediff.glade"

#define MAIN_WINDOW_ID	       "sediff_main_window"
#define OPEN_DIALOG_ID	       "sediff_policies_dialog"
#define REMAP_TYPES_DIALOG_ID "sediff_remap_types_dialog"
#define FIND_DIALOG_ID       "sediff_find_dialog"
#define FIND_FORWARD_ID      "sediff_find_forward"
#define FIND_ENTRY_ID        "sediff_find_text_entry"

typedef struct sediff_file_data
{
	GString *name;		       /* the filename */
	char *data;		       /* the data inside the file */
	size_t size;		       /* the size of the data inside the file */
} sediff_file_data_t;

struct sediff_progress;
struct sediff_results;

/* STRUCT: sediff_app_t
   This structure is used to control the gui.  It contains the links
   to all necessary buffers, textviews, dlgs, etc that are needed.  */
typedef struct sediff_app
{
	GtkWindow *window;	       /* the main window */
	GtkWindow *open_dlg;	       /* dialog box used when opening up the policies */
	struct sediff_progress *progress;	/* dialog to show progress */
	struct sediff_results *results;	/* results display */
	GtkWidget *dummy_view;	       /* this is a view we put in the left hand pane when we have no diff, and therefore no treeview */
	GladeXML *window_xml;	       /* the main windows xml */
	GladeXML *open_dlg_xml;	       /* the open dialogs xml */
	GtkWidget *tree_view;	       /* the treeview seen on left hand pane */
	GList *callbacks;
	gint progress_completed;
	sediff_file_data_t p1_sfd;     /* file info for policy 1 */
	sediff_file_data_t p2_sfd;     /* file info for policy 2 */
	apol_policy_t *orig_pol, *mod_pol;
	poldiff_t *diff;
	struct sediff_remap_types *remap_types_window;	/* the remapped types window reference */
	struct sediff_find_window *find_window;	/* the find window reference */
	int tv_curr_buf;	       /* the buffer currently displayed for the treeview */
} sediff_app_t;

typedef struct sediff_item_record
{
	const char *label;
	uint32_t bit_pos;
	int has_add_type;
	apol_vector_t *(*get_vector) (poldiff_t *);
	 poldiff_form_e(*get_form) (const void *);
	char *(*get_string) (poldiff_t *, const void *);
} sediff_item_record_t;

/* constants that denote how to sort rules within the results buffer */
#define SORT_DEFAULT 0
#define SORT_SOURCE 1
#define SORT_TARGET 2
#define SORT_CLASS 3
#define SORT_COND 4
#define SORT_ASCEND 1
#define SORT_DESCEND -1

/* return the textview currently displayed to the user */
GtkTextView *sediff_get_current_view(sediff_app_t * app);

void sediff_clear_text_buffer(GtkTextBuffer * txt);
void sediff_main_notebook_raise_policy_tab_goto_line(unsigned long line, int whichview);
void sediff_initialize_diff(void);
void sediff_initialize_policies(void);
void run_diff_clicked(void);
#endif

#endif
