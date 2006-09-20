/**
 *  @file sediff_gui.c
 *  Main program for running sediff in a GTK+ environment.
 *
 *  @author Don Patterson don.patterson@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

#include <config.h>

#include "sediff_gui.h"
#include "sediff_policy_open.h"
#include "sediff_progress.h"
#include "sediff_results.h"
#include "sediff_treemodel.h"
#include "utilgui.h"

#include <apol/policy.h>
#include <apol/util.h>

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>

#ifndef VERSION
	#define VERSION "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004-2006 Tresys Technology, LLC"

sediff_app_t *sediff_app = NULL;
gboolean toggle = TRUE;
gint curr_option = POLDIFF_DIFF_SUMMARY;

static struct option const longopts[] =
{
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {"run-diff", no_argument, NULL, 'd' },
  {NULL, 0, NULL, 0}
};

const sediff_item_record_t sediff_items[] = {
	{"Classes", POLDIFF_DIFF_CLASSES, 0,
	 poldiff_get_class_vector, poldiff_class_get_form, poldiff_class_to_string},
	{"Commons", POLDIFF_DIFF_COMMONS, 0,
	 poldiff_get_common_vector, poldiff_common_get_form, poldiff_common_to_string},
	{"Types", POLDIFF_DIFF_TYPES, 0,
	 poldiff_get_type_vector, poldiff_type_get_form, poldiff_type_to_string},
	{"Attributes", POLDIFF_DIFF_ATTRIBS, 0,
	 poldiff_get_attrib_vector, poldiff_attrib_get_form, poldiff_attrib_to_string},
	{"Roles", POLDIFF_DIFF_ROLES, 0,
	 poldiff_get_role_vector, poldiff_role_get_form, poldiff_role_to_string},
	{"Users", POLDIFF_DIFF_USERS, 0,
	 poldiff_get_user_vector, poldiff_user_get_form, poldiff_user_to_string},
	{"Booleans", POLDIFF_DIFF_BOOLS, 0,
	 poldiff_get_bool_vector, poldiff_bool_get_form, poldiff_bool_to_string},
	{"Role Allows", POLDIFF_DIFF_ROLE_ALLOWS, 0,
	 poldiff_get_role_allow_vector, poldiff_role_allow_get_form, poldiff_role_allow_to_string},
	{"Role Transitions", POLDIFF_DIFF_ROLE_TRANS, 1,
	 poldiff_get_role_trans_vector, poldiff_role_trans_get_form, poldiff_role_trans_to_string},
	{"TE Rules", POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES, 1,
	 NULL, NULL, NULL  /* special case because this is from two datum */ },
	{NULL, 0, 0, NULL, NULL, NULL}
};

/* Generic function prototype for getting policy components */
typedef struct registered_callback {
	GSourceFunc function;	/* gboolean (*GSourceFunc)(gpointer data); */
	void *user_data;
	unsigned int type;

/* callback types */
#define LISTBOX_SELECTED_CALLBACK   0
#define LISTBOX_SELECTED_SIGNAL     LISTBOX_SELECTED_CALLBACK
} registered_callback_t;

#define row_selected_signal_emit() sediff_callback_signal_emit(LISTBOX_SELECTED_SIGNAL)

static void usage(const char *program_name, int brief)
{
	printf("%s (sediffx ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
	printf("Usage: %s [-h|-v]\n", program_name);
	printf("Usage: %s [-d] [POLICY1 POLICY2]\n",program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Semantically differentiate two policies.  The policies can be either source\n \
or binary policy files, version 15 or later.  By default, all supported\n \
policy elements are examined.  The following diff options are available:\n \
", stdout);
	fputs("\n\
  -h, --help       display this help and exit\n\
  -v, --version    output version information and exit\n\
  -d, --diff-now   diff the policies immediately\n\n\
", stdout);
	return;
}

/* clear text from passed in text buffer */
void sediff_clear_text_buffer(GtkTextBuffer *txt)
{
	GtkTextIter start, end;

	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	gtk_text_buffer_remove_all_tags(txt, &start, &end);
	gtk_text_buffer_delete(txt, &start, &end);
}

static void sediff_callback_signal_emit_1(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *)data;
	unsigned int type = *(unsigned int*)user_data;
	if (callback->type == type) {
		data = &callback->user_data;
		g_idle_add_full(G_PRIORITY_HIGH_IDLE+10, callback->function, &data, NULL);
	}
	return;
}

/* the signal emit function executes each function registered with
 * sediff_callback_register() */
static void sediff_callback_signal_emit(unsigned int type)
{
	g_list_foreach(sediff_app->callbacks, &sediff_callback_signal_emit_1, &type);
	return;
}

/* show the help message in the bottom-left corner */
static void sediff_populate_key_buffer(void)
{
	GtkTextView *txt_view;
	GtkTextBuffer *txt;
	GString *string = g_string_new("");
	GtkTextTag *added_tag,*removed_tag,*changed_tag,*mono_tag,*header_tag;
	GtkTextTagTable *table;
	GtkTextIter iter;

	txt_view = GTK_TEXT_VIEW((glade_xml_get_widget(sediff_app->window_xml, "sediff_key_txt_view")));
	txt = gtk_text_view_get_buffer(txt_view);
	sediff_clear_text_buffer(txt);
	gtk_text_buffer_get_end_iter(txt, &iter);

	table = gtk_text_buffer_get_tag_table(txt);
	added_tag = gtk_text_tag_table_lookup(table, "added-tag");
	if (!added_tag) {
		added_tag = gtk_text_buffer_create_tag(txt, "added-tag",
						       "family", "monospace",
						       "foreground", "dark green",
						       NULL);
	}
	removed_tag = gtk_text_tag_table_lookup(table, "removed-tag");
	if (!removed_tag) {
		removed_tag = gtk_text_buffer_create_tag(txt, "removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 NULL);
	}
	changed_tag = gtk_text_tag_table_lookup(table, "changed-tag");
	if (!changed_tag) {
		changed_tag = gtk_text_buffer_create_tag(txt, "changed-tag",
							 "family", "monospace",
							 "foreground", "dark blue",
							 NULL);
	}
	mono_tag = gtk_text_tag_table_lookup(table, "mono-tag");
	if (!mono_tag) {
		mono_tag = gtk_text_buffer_create_tag(txt, "mono-tag",
						      "family", "monospace",
						      NULL);
	}
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
							 "family", "monospace",
							 "weight", PANGO_WEIGHT_BOLD,
							 "underline", PANGO_UNDERLINE_SINGLE,NULL);
	}

	g_string_printf(string," Added(+):\n  Items added\n  in policy 2.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "added-tag", NULL);
	g_string_printf(string," Removed(-):\n  Items removed\n  in policy 2.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,
						 -1, "removed-tag", NULL);
	g_string_printf(string," Changed(*):\n  Items changed\n  in policy 2.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,
						 -1, "changed-tag", NULL);
	g_string_free(string, TRUE);
}


/* Callback used to switch our text view based on user input from the
 * treeview.
 */
static gboolean sediff_results_txt_view_switch_results(gpointer data)
{
	uint32_t diffbit = 0;
	poldiff_form_e form = POLDIFF_FORM_NONE;
	if (sediff_get_current_treeview_selected_row(GTK_TREE_VIEW(sediff_app->tree_view), &diffbit, &form)) {
		/* Configure text_view */
		sediff_results_select(sediff_app, diffbit, form);
	}
	return FALSE;
}


static void sediff_treeview_on_row_double_clicked(GtkTreeView *tree_view,
						  GtkTreePath *path,
						  GtkTreeViewColumn *col,
						  gpointer user_data)
{
	/* Finish later */

	g_idle_add_full(G_PRIORITY_HIGH_IDLE, &sediff_results_txt_view_switch_results, NULL, NULL);
	row_selected_signal_emit();
}


static gboolean sediff_treeview_on_row_selected(GtkTreeSelection *selection,
						GtkTreeModel     *model,
						GtkTreePath      *path,
						gboolean          path_currently_selected,
						gpointer          userdata)
{

	/* if the row is not selected, then its about to be selected ! */
	/* we put in this toggle because for some reason if we have a previously selected path
	   then this callback is called like this
	   1  new_path is not selected
	   2  old_path is selected
	   3  new_path is not selected
	   This messes up our te rules stuff so I just put in a check to make sure we're not called
	   2 times when we are really only selected once
	*/
	if (toggle && gtk_tree_selection_path_is_selected(selection,path) == FALSE) {
		g_idle_add_full(G_PRIORITY_HIGH_IDLE, &sediff_results_txt_view_switch_results, NULL, NULL);
		row_selected_signal_emit();

	}
	else
		toggle = !toggle;
	return TRUE; /* allow selection state to change */
}

static void sediff_callbacks_free_elem_data(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t*)data;
	if (callback)
		free(callback);
	return;
}

static void sediff_destroy(void)
{

	if (sediff_app == NULL)
		return;

	if (sediff_app->dummy_view && gtk_widget_get_parent(GTK_WIDGET(sediff_app->dummy_view)) == NULL)
		gtk_widget_unref(sediff_app->dummy_view);
	if (sediff_app->tree_view != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->tree_view));
	if (sediff_app->window != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->window));
	if (sediff_app->open_dlg != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->open_dlg));
	if (sediff_app->window_xml != NULL)
		g_object_unref(G_OBJECT(sediff_app->window_xml));
	if (sediff_app->open_dlg_xml != NULL)
		g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_progress_destroy(sediff_app);
	if (sediff_app->p1_sfd.name)
		g_string_free(sediff_app->p1_sfd.name, TRUE);
	if (sediff_app->p2_sfd.name)
		g_string_free(sediff_app->p2_sfd.name, TRUE);
	if (sediff_app->p1_sfd.data)
		munmap(sediff_app->p1_sfd.data, sediff_app->p1_sfd.size);
	if (sediff_app->p2_sfd.data)
		munmap(sediff_app->p2_sfd.data, sediff_app->p2_sfd.size);
	if (sediff_app->rename_types_window) {
		sediff_rename_types_window_unref_members(sediff_app->rename_types_window);
		free(sediff_app->rename_types_window);
	}
	poldiff_destroy(&sediff_app->diff);

	g_list_foreach(sediff_app->callbacks, &sediff_callbacks_free_elem_data, NULL);
	g_list_free(sediff_app->callbacks);

	/* destroy our stored buffers */
	sediff_results_clear(sediff_app);
	free(sediff_app->results);
	free(sediff_app);
	sediff_app = NULL;
}

static void sediff_exit_app(void)
{
	sediff_destroy();
	gtk_main_quit();
}

static void sediff_main_window_on_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	sediff_exit_app();
}

/* this function is used to determine whether we allow
   a window click events to happen, if there is nothing in the
   buffer we don't */
gboolean sediff_textview_button_event(GtkWidget *widget,
			       GdkEventButton *event,
			       gpointer user_data)
{
        GtkTextBuffer *txt = NULL;
        GtkTextView *view = NULL;
        GtkTextIter start,end;

	if ( strcmp("GtkTextView", gtk_type_name(GTK_WIDGET_TYPE( widget ))) == 0 )
		view = GTK_TEXT_VIEW(widget);
	else
		return FALSE;
        if (view == NULL)
                return FALSE;
        txt = gtk_text_view_get_buffer(view);

	/* check to see if there is anything currently in this buffer that can be selected */
	gtk_text_buffer_get_start_iter(txt,&start);
	gtk_text_buffer_get_end_iter(txt,&end);
	if (gtk_text_iter_get_offset(&start) == gtk_text_iter_get_offset(&end)) {
		return TRUE;
	} else {
		return FALSE;
	}

	return TRUE;
}

/* This function resets the treemodel, recreates our stored buffers
 * (this is faster than clearing them), clears out the keys, and
 * results textviews, resets the indexes into diff buffers, and resets
 * the diff pointer itself.
 */
void sediff_initialize_diff(void)
{
	GtkTextView *textview;
	GtkTextBuffer *textbuf;
	GtkWidget *container = NULL;
	GtkLabel *label = NULL;
	GtkTreeSelection *selection = NULL;
	GtkWidget *widget;

	if (sediff_app->tree_view) {
		/* unselect the selected items */
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(sediff_app->tree_view));
		gtk_tree_selection_unselect_all(selection);
		/* delete tree_view */
		gtk_widget_destroy(GTK_WIDGET(sediff_app->tree_view));
		sediff_app->tree_view = NULL;
	}

	/*deselect the sort te rules menu item */
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_sort_menu");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, FALSE);

	/* get the scrolled window and replace the text_view with a blank dummy view */
	container = glade_xml_get_widget(sediff_app->window_xml, "scrolledwindow_list");
	g_assert(container);
	if (sediff_app->dummy_view == NULL) {
		sediff_app->dummy_view = gtk_text_view_new();
		g_assert(sediff_app->dummy_view);
		gtk_text_view_set_editable(GTK_TEXT_VIEW(sediff_app->dummy_view),FALSE);
		gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(sediff_app->dummy_view),FALSE);
		g_signal_connect(G_OBJECT(sediff_app->dummy_view), "button-press-event",
				 G_CALLBACK(sediff_textview_button_event), sediff_app);
		gtk_container_add(GTK_CONTAINER(container), sediff_app->dummy_view);
		gtk_widget_show_all(container);
	} else if (gtk_widget_get_parent(GTK_WIDGET(sediff_app->dummy_view)) == NULL) {
		/* If the dummy view has been removed, then re-add it to the container */
		gtk_container_add(GTK_CONTAINER(container), sediff_app->dummy_view);
		gtk_widget_show_all(container);
	}

	sediff_results_clear(sediff_app);
	sediff_results_create(sediff_app);

	textview = GTK_TEXT_VIEW((glade_xml_get_widget(sediff_app->window_xml, "sediff_key_txt_view")));
	g_assert(textview);
	textbuf = gtk_text_view_get_buffer(textview);
	g_assert(textbuf);
	sediff_clear_text_buffer(textbuf);

	label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
	gtk_label_set_text(label, "");
}

/*
   populate the main window
*/
static gboolean sediff_populate_main_window()
{
	GtkWidget *container = NULL;
	GtkTreeModel *tree_model;
	GtkTreeSelection *sel;
	GtkTreeIter iter;
	GtkNotebook *notebook1, *notebook2;

	/* load up the status bar */
	sediff_results_update_stats(sediff_app);

	/* populate the key */
	sediff_populate_key_buffer();

	/* get the scrolled window we are going to put the tree_store in */
	container = glade_xml_get_widget(sediff_app->window_xml, "scrolledwindow_list");
	g_assert(container);
	if (sediff_app->dummy_view != NULL) {
		/* Add a reference to the dummy view widget before removing it from the container so we can add it later */
		sediff_app->dummy_view = gtk_widget_ref(sediff_app->dummy_view);
		gtk_container_remove(GTK_CONTAINER(container), sediff_app->dummy_view);
	}

	/* create the tree_view */
	sediff_app->tree_view = sediff_create_view_and_model(sediff_app->diff);

	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(sediff_app->tree_view));
        gtk_tree_selection_set_mode(sel,GTK_SELECTION_BROWSE);
	gtk_tree_selection_set_select_function(sel, sediff_treeview_on_row_selected, sediff_app->tree_view, NULL);
	g_signal_connect(G_OBJECT(sediff_app->tree_view), "row-activated",
			 G_CALLBACK(sediff_treeview_on_row_double_clicked), NULL);

	notebook1 = (GtkNotebook *)glade_xml_get_widget(sediff_app->window_xml, "notebook1");
	g_assert(notebook1);
	notebook2 = (GtkNotebook *)glade_xml_get_widget(sediff_app->window_xml, "notebook2");
	g_assert(notebook2);

	/* make it viewable */
	gtk_container_add(GTK_CONTAINER(container), sediff_app->tree_view);
	gtk_widget_show_all(container);

	/* select the first element in the tree */
	tree_model = gtk_tree_view_get_model(GTK_TREE_VIEW(sediff_app->tree_view));
	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(sediff_app->tree_view));
	if (gtk_tree_model_get_iter_first(tree_model, &iter)) {
		gtk_tree_selection_select_iter(sel, &iter);
	}

	/* set the buffer to the summary page */
	sediff_results_select(sediff_app, POLDIFF_DIFF_SUMMARY, 0);

	return FALSE;
}

struct run_datum {
	sediff_app_t *app;
	uint32_t run_flags;
};

static gpointer sediff_run_diff_runner(gpointer data)
{
	struct run_datum *r = data;
	if (poldiff_run(r->app->diff, r->run_flags) < 0) {
		sediff_progress_abort(r->app, "Error running diff.");
	}
	else {
		sediff_progress_done(r->app);
	}
	return NULL;
}

void run_diff_clicked(void)
{
	GdkCursor *cursor = NULL;
	struct run_datum r;

	sediff_initialize_diff();

	/* set the cursor to a hourglass */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();

	/* make sure we clear everything out before we run the diff */
	while (gtk_events_pending ())
		gtk_main_iteration ();

	if (sediff_app->rename_types_window) {
                /* FIX ME
                   renamed_types = sediff_app->rename_types_window->renamed_types;
                */
	}

	r.run_flags = POLDIFF_DIFF_ALL;
	if (apol_policy_is_binary(sediff_app->orig_pol) ||
	    apol_policy_is_binary(sediff_app->mod_pol)) {
		message_display(sediff_app->window,
				GTK_MESSAGE_INFO,
				"Attribute diffs are not supported for binary policies.");
		while (gtk_events_pending ())
			gtk_main_iteration ();
		r.run_flags &= ~POLDIFF_DIFF_ATTRIBS;
	}

	sediff_progress_show(sediff_app, "Running Diff");
	r.app = sediff_app;
	g_thread_create(sediff_run_diff_runner, &r, FALSE, NULL);
	sediff_progress_wait(sediff_app);
	sediff_populate_main_window();

	sediff_progress_hide(sediff_app);
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	if (sediff_app->window != NULL)
		gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
}

void sediff_menu_on_default_sort_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_DEFAULT, SORT_ASCEND);
}

void sediff_menu_on_src_type_asc_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_SOURCE, SORT_ASCEND);
}

void sediff_menu_on_src_type_des_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_SOURCE, SORT_DESCEND);
}

void sediff_menu_on_tgt_type_asc_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_TARGET, SORT_ASCEND);
}

void sediff_menu_on_tgt_type_des_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_TARGET, SORT_DESCEND);
}

void sediff_menu_on_oclass_asc_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_CLASS, SORT_ASCEND);
}

void sediff_menu_on_oclass_des_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_CLASS, SORT_DESCEND);
}

void sediff_menu_on_cond_asc_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_COND, SORT_ASCEND);
}

void sediff_menu_on_cond_des_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_COND, SORT_DESCEND);
}

void sediff_menu_on_find_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	if (sediff_app->find_window == NULL)
		sediff_app->find_window = sediff_find_window_new(sediff_app);
	g_assert(sediff_app->find_window);
	sediff_find_window_display(sediff_app->find_window);
}

void sediff_menu_on_edit_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
        GtkTextBuffer *txt = NULL;
        GtkTextView *view = NULL;
        GtkTextIter start,end;
	GtkWidget *widget = NULL;
        if (sediff_app == NULL)
                return;
        view = sediff_get_current_view(sediff_app);
        if (view == NULL)
                return;
        txt = gtk_text_view_get_buffer(view);
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_menu_copy");
	g_assert(widget);

	/* check to see if anything has been selected and set copy button up*/
	if (gtk_text_buffer_get_selection_bounds(txt,&start,&end)) {
		gtk_widget_set_sensitive(widget, TRUE);
	} else {
		gtk_widget_set_sensitive(widget, FALSE);
	}
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_select_all");
	g_assert(widget);
	/* check to see if there is anything currently in this buffer that can be selected */
	gtk_text_buffer_get_start_iter(txt,&start);
	gtk_text_buffer_get_end_iter(txt,&end);
	if (gtk_text_iter_get_offset(&start) == gtk_text_iter_get_offset(&end)) {
		gtk_widget_set_sensitive(widget, FALSE);
	} else {
		gtk_widget_set_sensitive(widget, TRUE);
	}
}

void sediff_menu_on_select_all_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkTextBuffer *txt = NULL;
	GtkTextView *view = NULL;
	GtkTextIter start,end;
	if (sediff_app == NULL)
		return;
	view = sediff_get_current_view(sediff_app);
	if (view == NULL)
		return;
	txt = gtk_text_view_get_buffer(view);
	gtk_text_buffer_get_start_iter(txt,&start);
	gtk_text_buffer_get_end_iter(txt,&end);
	gtk_text_buffer_select_range(txt,&start,&end);
}

void sediff_menu_on_copy_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkClipboard *clipboard = NULL;
	GtkTextBuffer *txt = NULL;
	GtkTextView *view = NULL;
	if (sediff_app == NULL)
		return;
	clipboard = gtk_clipboard_get(NULL);
	if (clipboard == NULL)
		return;
	view = sediff_get_current_view(sediff_app);
	if (view == NULL)
		return;
	txt = gtk_text_view_get_buffer(view);
	if (txt == NULL)
		return;
	gtk_text_buffer_copy_clipboard(txt,clipboard);
}

void sediff_menu_on_rundiff_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	run_diff_clicked();
}

void sediff_toolbar_on_rundiff_button_clicked(GtkButton *button, gpointer user_data)
{
	run_diff_clicked();
}

static void sediff_rename_types_window_show()
{
	if (sediff_app->rename_types_window == NULL)
		sediff_app->rename_types_window = sediff_rename_types_window_new(sediff_app);
	g_assert(sediff_app->rename_types_window);
	sediff_rename_types_window_display(sediff_app->rename_types_window);
}

void sediff_menu_on_renametypes_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_rename_types_window_show();
}

void sediff_toolbar_on_renametypes_button_clicked(GtkToolButton *button, gpointer user_data)
{
	sediff_rename_types_window_show();
}

void sediff_toolbar_on_open_button_clicked(GtkToolButton *button, gpointer user_data)
{
	sediff_open_button_clicked();
}

void sediff_menu_on_open_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_open_button_clicked();
}

void sediff_menu_on_quit_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_exit_app();
}

void sediff_menu_on_help_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget *window;
	GtkWidget *scroll;
	GtkWidget *text_view;
	GtkTextBuffer *buffer;
	GString *string;
	char *help_text = NULL;
	size_t len;
	int rt;
	char *dir;

	window = gtk_dialog_new_with_buttons("SEDiff Help",
					     GTK_WINDOW(sediff_app->window),
					     GTK_DIALOG_DESTROY_WITH_PARENT,
					     GTK_STOCK_CLOSE,
					     GTK_RESPONSE_NONE,
					     NULL);
	g_signal_connect_swapped(window, "response", G_CALLBACK(gtk_widget_destroy), window);
	scroll = gtk_scrolled_window_new(NULL, NULL);
	text_view = gtk_text_view_new();
	gtk_window_set_default_size(GTK_WINDOW(window), 480, 320);
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(window)->vbox), scroll);
	gtk_container_add(GTK_CONTAINER(scroll), text_view);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view),GTK_WRAP_WORD);
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
	dir = apol_file_find("sediff_help.txt");
	if (!dir) {
		string = g_string_new("");
		g_string_append(string, "Cannot find help file");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return;
	}
	string = g_string_new(dir);
	free(dir);
	g_string_append(string, "/sediff_help.txt");
	rt = apol_file_read_to_buffer(string->str, &help_text, &len);
	g_string_free(string, TRUE);
	if (rt != 0) {
		if (help_text)
			free(help_text);
		return;
	}
	gtk_text_buffer_set_text(buffer, help_text, len);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_widget_show(text_view);
	gtk_widget_show(scroll);
	gtk_widget_show(window);
	return;

}

void sediff_menu_on_about_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget *dialog;
	GString *str;

	str = g_string_new("");
	g_string_assign(str, "Policy Semantic Diff Tool for Security Enhanced Linux");
        g_string_append(str, "\n\n" COPYRIGHT_INFO "\nwww.tresys.com/selinux");
	g_string_append(str, "\n\nGUI version ");
	g_string_append(str, VERSION);
	g_string_append(str, "\nlibapol version ");
	g_string_append(str, libapol_get_version()); /* the libapol version */

	dialog = gtk_message_dialog_new(sediff_app->window,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_INFO,
					GTK_BUTTONS_CLOSE,
					str->str);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_string_free(str, TRUE);
}


static void sediff_policy_notebook_on_switch_page(GtkNotebook *notebook, GtkNotebookPage *page, guint pagenum, gpointer user_data)
{
	GtkTextView *txt;
	int main_pagenum;
	GtkNotebook *main_notebook;
	sediff_file_data_t *sfd = NULL;

	/* if we don't have filenames we can't open anything... */
	if (!sediff_app->p1_sfd.name && !sediff_app->p2_sfd.name)
		return;

	/* if we aren't looking at the policy tab of the noteboook return */
	if (pagenum == 0)
		return;

	main_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));
	assert(main_notebook);

	/* here we know pagenum is going to be 1 or 2 */
	main_pagenum = gtk_notebook_get_current_page(main_notebook);

	if (main_pagenum == 1) {
		/* if we are looking at policy 1 */
		txt = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text"));
		g_assert(txt);
		sfd = &(sediff_app->p1_sfd);
	} else {
		/* if we are looking at policy 2 */
		txt = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text"));
		g_assert(txt);
		sfd = &(sediff_app->p2_sfd);
	}

	/* if the buffer has already been modified, i.e. its had the policy put into it
	   just return we have already printed*/
	if (gtk_text_buffer_get_modified(gtk_text_view_get_buffer(txt)) == TRUE)
		return;

	/* set the modified bit immediately because of gtk is asynchronous
	 and this fcn might be called again before its set in the populate fcn*/
	gtk_text_buffer_set_modified(gtk_text_view_get_buffer(txt), TRUE);

	/* show our loading dialog */
	sediff_progress_message(sediff_app, "Loading Policy", "Loading text - this may take a while.");
	if (main_pagenum ==1)
		sediff_policy_file_textview_populate(sfd, txt, sediff_app->orig_pol);
	else
		sediff_policy_file_textview_populate(sfd, txt, sediff_app->mod_pol);
	sediff_progress_hide(sediff_app);
	return;
}

void sediff_initialize_policies(void)
{
	GtkTextView *textview;
	GtkTextBuffer *txt;

	if (sediff_app->diff) {
		poldiff_destroy(&sediff_app->diff);
	}
	else {
		apol_policy_destroy(&sediff_app->orig_pol);
		apol_policy_destroy(&sediff_app->mod_pol);
	}
	sediff_app->orig_pol = NULL;
	sediff_app->mod_pol = NULL;
	if (sediff_app->p1_sfd.name)
		g_string_free(sediff_app->p1_sfd.name, TRUE);
	if (sediff_app->p2_sfd.name)
		g_string_free(sediff_app->p2_sfd.name, TRUE);
	sediff_app->p1_sfd.name = NULL;
	sediff_app->p2_sfd.name = NULL;

	sediff_rename_types_window_unref_members(sediff_app->rename_types_window);

	/* Grab the 2 policy textviews */
	textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	/* Set modified bit to zero, so line numbers won't show while in initialized mode. */
	gtk_text_buffer_set_modified(txt, FALSE);

	textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	/* Set modified bit to zero, so line numbers won't show while in initialized mode. */
	gtk_text_buffer_set_modified(txt, FALSE);

	textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_stats_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);

	textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_stats_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);

	sediff_set_open_policies_gui_state(FALSE);
}

typedef struct delayed_main_data {
	GString *p1_file;
	GString *p2_file;
	bool_t run_diff;
} delayed_data_t;

/*
 * We don't want to do the heavy work of loading and displaying
 * the diff before the main loop has started because it will freeze
 * the gui for too long. To solve this, the function is called from an
 * idle callback set-up in main.
 */
static gboolean delayed_main(gpointer data)
{
	int rt;
	delayed_data_t *delay_data = (delayed_data_t *)data;
	const char *p1_file = delay_data->p1_file->str;
	const char *p2_file = delay_data->p2_file->str;

	rt = sediff_load_policies(p1_file, p2_file);
	g_string_free(delay_data->p1_file, TRUE);
	g_string_free(delay_data->p2_file, TRUE);
	if (rt < 0)
		return FALSE;

	if (delay_data->run_diff == TRUE)
		run_diff_clicked();

	return FALSE;

}

static void sediff_main_notebook_on_switch_page(GtkNotebook *notebook, GtkNotebookPage *page, guint pagenum, gpointer user_data)
{
	sediff_app_t *app = (sediff_app_t*)user_data;
	GtkLabel *label = NULL;

	if (pagenum == 0) {
		label = (GtkLabel*)glade_xml_get_widget(app->window_xml, "line_label");
		gtk_label_set_text(label, "");
	}
}

/* return the textview currently displayed to the user */
GtkTextView *sediff_get_current_view(sediff_app_t *app)
{
	GtkNotebook *notebook = NULL;
	GtkNotebook *tab_notebook = NULL;
	int pagenum;
	GtkTextView *text_view = NULL;

	notebook = GTK_NOTEBOOK(glade_xml_get_widget(app->window_xml, "main_notebook"));
	pagenum = gtk_notebook_get_current_page(notebook);
	/* do we need to use the treeview */
	if (pagenum == 0) {
		text_view = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_results_txt_view"));
	} else if (pagenum == 1) {
		/* is this one of the other notebooks */
		tab_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook1"));
		pagenum = gtk_notebook_get_current_page(tab_notebook);
		if (pagenum == 0)
			text_view = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_main_p1_stats_text"));
		else
			text_view = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_main_p1_text"));
	} else {
		/* is this one of the other notebooks */
		tab_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook2"));
		pagenum = gtk_notebook_get_current_page(tab_notebook);
		if (pagenum == 0)
			text_view = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_main_p2_stats_text"));
		else
			text_view = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_main_p2_text"));
	}
	return text_view;

}

int main(int argc, char **argv)
{
	char *dir = NULL;
	GString *path = NULL;
	delayed_data_t delay_data;
	bool_t havefiles = FALSE;
	int optc;
        delay_data.p1_file = delay_data.p2_file = NULL;
	delay_data.run_diff = FALSE;
	GtkNotebook *notebook = NULL;

	if (!g_thread_supported ())
		g_thread_init (NULL);

	while ((optc = getopt_long (argc, argv, "hvd", longopts, NULL)) != -1)  {
		switch (optc) {
		case 0:
			break;
		case 'd': /* run the diff only for gui */
			delay_data.run_diff = TRUE;
			break;
		case 'h': /* help */
			usage(argv[0], 0);
			exit(0);
			break;
		case 'v': /* version */
			printf("\n%s (sediffx ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
			exit(0);
			break;
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	/* sediff with file names */
	if (argc - optind == 2) {
		havefiles = TRUE;
		delay_data.p1_file = g_string_new(argv[optind]);
		delay_data.p2_file = g_string_new(argv[optind+1]);
	}
	else if (argc - optind != 0){
		usage(argv[0],0);
		return -1;
	} else {
		/* here we have found no missing arguments, but perhaps the user specified -d with no files */
		if (delay_data.run_diff == TRUE) {
			usage(argv[0], 0);
			return -1;
		}
	}

	gtk_init(&argc, &argv);
	glade_init();
	dir = apol_file_find(GLADEFILE);
	if (!dir){
		fprintf(stderr, "Could not find %s!", GLADEFILE);
		return -1;
	}

	path = g_string_new(dir);
	free(dir);
	g_string_append_printf(path, "/%s", GLADEFILE);

	sediff_app = calloc(1, sizeof(*sediff_app));
	if (!sediff_app) {
		g_warning("Out of memory!");
		exit(-1);
	}

	gtk_set_locale();
	gtk_init(&argc, &argv);
	sediff_app->window_xml = glade_xml_new(path->str, MAIN_WINDOW_ID, NULL);
	if (!sediff_app->window_xml) {
		free(sediff_app);
		g_warning("Unable to create interface");
		return -1;
	}
	sediff_app->window = GTK_WINDOW(glade_xml_get_widget(sediff_app->window_xml, MAIN_WINDOW_ID));
	g_signal_connect(G_OBJECT(sediff_app->window), "delete_event",
			 G_CALLBACK(sediff_main_window_on_destroy), sediff_app);
	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));
	g_assert(notebook);
	g_signal_connect_after(G_OBJECT(notebook), "switch-page",
			 G_CALLBACK(sediff_main_notebook_on_switch_page), sediff_app);

	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook1"));
	g_assert(notebook);
	g_signal_connect_after(G_OBJECT(notebook), "switch-page",
			 G_CALLBACK(sediff_policy_notebook_on_switch_page), sediff_app);
	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook2"));
	g_assert(notebook);
	g_signal_connect_after(G_OBJECT(notebook), "switch-page",
			 G_CALLBACK(sediff_policy_notebook_on_switch_page), sediff_app);


	glade_xml_signal_autoconnect(sediff_app->window_xml);

	sediff_initialize_policies();
	sediff_initialize_diff();

	if (havefiles)
		g_idle_add(&delayed_main, &delay_data);

	sediff_results_select(sediff_app, POLDIFF_DIFF_SUMMARY, 0);

	gtk_main();

	if (path != NULL)
		g_string_free(path,1);
	return 0;
}
