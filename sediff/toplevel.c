/**
 *  @file
 *  Implementation for sediffx's main toplevel window.
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

#include <config.h>

#include "policy_view.h"
#include "progress.h"
#include "sediffx.h"
#include "toplevel.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <apol/util.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

struct toplevel
{
	sediffx_t *s;
	progress_t *progress;
	policy_view_t *views[SEDIFFX_POLICY_NUM];
	GladeXML *xml;
	/** filename for glade file */
	char *xml_filename;
	/** toplevel window widget */
	GtkWindow *w;
	/* non-zero if the currently opened policies are capable of
	 * diffing attributes */
	int can_diff_attributes;
};

/**
 * Enable/disable all items (menus and buttons) that depend upon if a
 * policy is loaded.
 *
 * @param top Toplevel object containing menu widgets.
 * @param TRUE to enable items, FALSE to disable.
 */
static void toplevel_enable_policy_items(toplevel_t * top, gboolean sens)
{
	static const char *items[] = {
		"Copy", "Select All",
		"Find", "Run Diff", "Remap Types", "sort menu item",
		"run diff button", "remap types button",
		NULL
	};
	size_t i;
	const char *s;
	for (i = 0, s = items[0]; s != NULL; s = items[++i]) {
		GtkWidget *w = glade_xml_get_widget(top->xml, s);
		assert(w != NULL);
		gtk_widget_set_sensitive(w, sens);
	}
}

/**
 * Update the toplevel's title bar to list the policies currently
 * opened.
 *
 * @param top Toplevel to modify.
 */
static void toplevel_update_title_bar(toplevel_t * top)
{
	const apol_policy_path_t *paths[SEDIFFX_POLICY_NUM];
	char *types[SEDIFFX_POLICY_NUM] = { "Policy", "Policy" }, *s;
	const char *primaries[SEDIFFX_POLICY_NUM] = { NULL, NULL };
	sediffx_policy_e i;

	paths[SEDIFFX_POLICY_ORIG] = sediffx_get_policy_path(top->s, SEDIFFX_POLICY_ORIG);
	paths[SEDIFFX_POLICY_MOD] = sediffx_get_policy_path(top->s, SEDIFFX_POLICY_MOD);

	for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
		if (paths[i] == NULL) {
			primaries[i] = "No Policy";
		} else {
			if (apol_policy_path_get_type(paths[i]) == APOL_POLICY_PATH_TYPE_MODULAR) {
				types[i] = "Base";
			}
			primaries[i] = apol_policy_path_get_primary(paths[i]);
		}
	}
	if (asprintf(&s, "sediffx - [%s file: %s] [%s file: %s]",
		     types[SEDIFFX_POLICY_ORIG], primaries[SEDIFFX_POLICY_ORIG],
		     types[SEDIFFX_POLICY_MOD], primaries[SEDIFFX_POLICY_MOD]) < 0) {
		toplevel_ERR(top, "%s", strerror(errno));
		return;
	}
	gtk_window_set_title(top->w, s);
	free(s);
}

/**
 * Initialize the application icons for the program.  These icons are
 * the ones shown by the window manager within title bars and pagers.
 * The last icon listed in the array will be displayed in the About
 * dialog.
 *
 * @param top Toplevel whose icon to set.  All child windows will
 * inherit these icons.
 */
static void init_icons(toplevel_t * top)
{
	static const char *icon_names[] = { "sediffx-small.png", "sediffx.png" };
	GdkPixbuf *icon;
	char *path;
	GList *icon_list = NULL;
	size_t i;
	for (i = 0; i < sizeof(icon_names) / sizeof(icon_names[0]); i++) {
		if ((path = apol_file_find_path(icon_names[i])) == NULL) {
			continue;
		}
		icon = gdk_pixbuf_new_from_file(path, NULL);
		free(path);
		if (icon == NULL) {
			continue;
		}
		icon_list = g_list_append(icon_list, icon);
	}
	gtk_window_set_default_icon_list(icon_list);
	gtk_window_set_icon_list(top->w, icon_list);
}

toplevel_t *toplevel_create(sediffx_t * s)
{
	toplevel_t *top;
	int error = 0;
	sediffx_policy_e i;
	if ((top = calloc(1, sizeof(*top))) == NULL) {
		error = errno;
		goto cleanup;
	}
	top->s = s;
	if ((top->xml_filename = apol_file_find_path("sediffx.glade")) == NULL ||
	    (top->xml = glade_xml_new(top->xml_filename, "toplevel", NULL)) == NULL) {
		fprintf(stderr, "Could not open sediffx.glade.\n");
		error = EIO;
		goto cleanup;
	}
	top->w = GTK_WINDOW(glade_xml_get_widget(top->xml, "toplevel"));
	init_icons(top);
	g_object_set_data(G_OBJECT(top->w), "toplevel", top);
	gtk_widget_show(GTK_WIDGET(top->w));

	/* initialize sub-windows, now that glade XML file has been
	 * read */
	if ((top->progress = progress_create(top)) == NULL) {
		error = errno;
		goto cleanup;
	}

	for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
		if ((top->views[i] = policy_view_create(top, i)) == NULL) {
			fprintf(stderr, "%s\n", strerror(errno));
			error = errno;
			goto cleanup;
		}
	}

	glade_xml_signal_autoconnect(top->xml);

      cleanup:
	if (error != 0) {
		toplevel_destroy(&top);
		errno = error;
		return NULL;
	}
	return top;
}

void toplevel_destroy(toplevel_t ** top)
{
	if (top != NULL && *top != NULL) {
		sediffx_policy_e i;
		for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
			policy_view_destroy(&(*top)->views[i]);
		}
		free((*top)->xml_filename);
		progress_destroy(&(*top)->progress);
		free(*top);
		*top = NULL;
	}
}

struct policy_run_datum
{
	toplevel_t *top;
	apol_policy_path_t *paths[2];
	apol_policy_t *policies[2];
	int result;
};

/**
 * Thread that loads and parses a policy file.  It will write to
 * progress_seaudit_handle_func() its status during the load.
 *
 * @param data Pointer to a struct policy_run_datum, for control
 * information.
 */
static gpointer toplevel_open_policy_runner(gpointer data)
{
	struct policy_run_datum *run = (struct policy_run_datum *)data;
	sediffx_policy_e i;
	for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
		apol_policy_path_t *path = run->paths[i];
		char *title = util_policy_path_to_string(path);
		if (title == NULL) {
			run->result = -1;
			progress_abort(run->top->progress, "%s", strerror(errno));
			return NULL;
		}
		progress_update(run->top->progress, "Opening %s", title);
		free(title);
		run->policies[i] = apol_policy_create_from_policy_path(path, 0, progress_apol_handle_func, run->top->progress);
		if (run->policies[i] == NULL) {
			run->result = -1;
			progress_abort(run->top->progress, NULL);
			return NULL;
		}
	}
	run->result = 0;
	progress_done(run->top->progress);
	return NULL;
}

int toplevel_open_policies(toplevel_t * top, apol_policy_path_t * orig_path, apol_policy_path_t * mod_path)
{
	struct policy_run_datum run;
	memset(&run, 0, sizeof(run));
	run.top = top;
	run.paths[0] = orig_path;
	run.paths[1] = mod_path;
	sediffx_policy_e i;

	util_cursor_wait(GTK_WIDGET(top->w));
	progress_show(top->progress, "Loading Policies");
	g_thread_create(toplevel_open_policy_runner, &run, FALSE, NULL);
	progress_wait(top->progress);
	progress_hide(top->progress);
	util_cursor_clear(GTK_WIDGET(top->w));
	if (run.result < 0) {
		apol_policy_path_destroy(&run.paths[0]);
		apol_policy_path_destroy(&run.paths[1]);
		return run.result;
	}
	top->can_diff_attributes = 1;
	for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
		qpol_policy_t *q = apol_policy_get_qpol(run.policies[i]);
		if (!qpol_policy_has_capability(q, QPOL_CAP_ATTRIB_NAMES)) {
			top->can_diff_attributes = 0;
		}
		policy_view_update(top->views[i], run.policies[i], run.paths[i]);
		sediffx_set_policy(top->s, i, run.policies[i], run.paths[i]);
	}
	toplevel_enable_policy_items(top, TRUE);
	toplevel_update_title_bar(top);
	/*        toplevel_update_status_bar(top); */
	return 0;
}

struct run_datum
{
	toplevel_t *top;
	uint32_t run_flags;
	int result;
};

static gpointer toplevel_run_diff_runner(gpointer data)
{
	struct run_datum *run = data;
	poldiff_t *diff = sediffx_get_poldiff(run->top->s, progress_poldiff_handle_func, run->top->progress);
	if (diff == NULL) {
		run->result = -1;
		progress_abort(run->top->progress, "Could not get a poldiff object: %s", strerror(errno));
		return NULL;
	}
	if ((run->result = poldiff_run(diff, run->run_flags)) < 0) {
		progress_abort(run->top->progress, NULL);
	} else {
		progress_done(run->top->progress);
	}
	return NULL;
}

void toplevel_run_diff(toplevel_t * top)
{
	struct run_datum r;
	GtkWidget *dialog = NULL;

	r.top = top;
	r.run_flags = POLDIFF_DIFF_ALL;
	r.result = 0;
	if (!top->can_diff_attributes) {
		dialog = gtk_message_dialog_new(top->w, GTK_DIALOG_DESTROY_WITH_PARENT,
						GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE,
						"Attribute diffs are not supported for the currently loaded policies.");
		g_signal_connect_swapped(dialog, "response", G_CALLBACK(gtk_widget_destroy), dialog);
		r.run_flags &= ~POLDIFF_DIFF_ATTRIBS;
	}

	util_cursor_wait(GTK_WIDGET(top->w));
	progress_show(top->progress, "Running Diff");
	/* pop the attribute warning over the progress dialog */
	if (dialog != NULL) {
		gtk_widget_show(dialog);
	}
	g_thread_create(toplevel_run_diff_runner, &r, FALSE, NULL);
	progress_wait(top->progress);
	progress_hide(top->progress);
	util_cursor_clear(GTK_WIDGET(top->w));
	/* FIX ME
	 * if (run.result == 0) {
	 * populate_main_window();
	 * }
	 */
}

char *toplevel_get_glade_xml(toplevel_t * top)
{
	return top->xml_filename;
}

GtkWindow *toplevel_get_window(toplevel_t * top)
{
	return top->w;
}

/**
 * Pop-up a dialog with a line of text and wait for the user to
 * dismiss the dialog.
 *
 * @param top Toplevel window; this message dialog will be centered
 * upon it.
 * @param msg_type Type of message being displayed.
 * @param fmt Format string to print, using syntax of printf(3).
 */
static void toplevel_message(toplevel_t * top, GtkMessageType msg_type, const char *fmt, va_list ap)
{
	GtkWidget *dialog;
	char *msg;
	if (vasprintf(&msg, fmt, ap) < 0) {
		ERR(NULL, "%s", strerror(errno));
		return;
	}
	dialog = gtk_message_dialog_new(top->w, GTK_DIALOG_DESTROY_WITH_PARENT, msg_type, GTK_BUTTONS_CLOSE, msg);
	free(msg);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

void toplevel_ERR(toplevel_t * top, const char *format, ...)
{
	va_list(ap);
	va_start(ap, format);
	toplevel_message(top, GTK_MESSAGE_ERROR, format, ap);
	va_end(ap);
}

void toplevel_WARN(toplevel_t * top, const char *format, ...)
{
	va_list(ap);
	va_start(ap, format);
	toplevel_message(top, GTK_MESSAGE_WARNING, format, ap);
	va_end(ap);
}

/******************** menu callbacks below ********************/

void toplevel_on_quit_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	top->w = NULL;
	gtk_main_quit();
}

void toplevel_on_run_diff_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	toplevel_run_diff(top);
}

void toplevel_on_help_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	GtkWidget *window;
	GtkWidget *scroll;
	GtkWidget *text_view;
	GtkTextBuffer *buffer;
	char *help_text = NULL;
	size_t len;
	int rt;
	char *dir;

	window = gtk_dialog_new_with_buttons("sediffx Help",
					     GTK_WINDOW(top->w),
					     GTK_DIALOG_DESTROY_WITH_PARENT, GTK_STOCK_CLOSE, GTK_RESPONSE_CLOSE, NULL);
	gtk_dialog_set_default_response(GTK_DIALOG(window), GTK_RESPONSE_CLOSE);
	g_signal_connect_swapped(window, "response", G_CALLBACK(gtk_widget_destroy), window);
	scroll = gtk_scrolled_window_new(NULL, NULL);
	text_view = gtk_text_view_new();
	gtk_window_set_default_size(GTK_WINDOW(window), 520, 300);
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(window)->vbox), scroll);
	gtk_container_add(GTK_CONTAINER(scroll), text_view);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_NONE);
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
	if ((dir = apol_file_find_path("sediff_help.txt")) == NULL) {
		toplevel_ERR(top, "Cannot find help file.");
		return;
	}
	rt = apol_file_read_to_buffer(dir, &help_text, &len);
	free(dir);
	if (rt != 0) {
		free(help_text);
		return;
	}
	gtk_text_buffer_set_text(buffer, help_text, len);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_widget_show(text_view);
	gtk_widget_show(scroll);
	gtk_widget_show(window);
}

void toplevel_on_about_sediffx_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	gtk_show_about_dialog(top->w,
			      "comments", "Policy Semantic Difference Tool for Security Enhanced Linux",
			      "copyright", COPYRIGHT_INFO,
			      "name", "sediffx", "version", VERSION, "website", "http://oss.tresys.com/projects/setools", NULL);
}

void toplevel_on_run_diff_button_click(gpointer user_data, GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
				       __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	toplevel_run_diff(top);
}

void toplevel_on_destroy(gpointer user_data, GtkObject * object __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	top->w = NULL;
	gtk_main_quit();
}

#if 0

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
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <sys/mman.h>

gboolean toggle = TRUE;

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
	 NULL, NULL, NULL /* special case because this is from two datum */ },
	{NULL, 0, 0, NULL, NULL, NULL}
};

/* Generic function prototype for getting policy components */
typedef struct registered_callback
{
	GSourceFunc function;	       /* gboolean (*GSourceFunc)(gpointer data); */
	void *user_data;
	unsigned int type;

/* callback types */
#define LISTBOX_SELECTED_CALLBACK   0
#define LISTBOX_SELECTED_SIGNAL     LISTBOX_SELECTED_CALLBACK
} registered_callback_t;

#define row_selected_signal_emit() sediff_callback_signal_emit(LISTBOX_SELECTED_SIGNAL)

static void sediff_callback_signal_emit_1(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *) data;
	unsigned int type = *(unsigned int *)user_data;
	if (callback->type == type) {
		data = &callback->user_data;
		g_idle_add_full(G_PRIORITY_HIGH_IDLE + 10, callback->function, &data, NULL);
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
	GtkTextTag *added_tag, *removed_tag, *changed_tag, *mono_tag, *header_tag;
	GtkTextTagTable *table;
	GtkTextIter iter;

	txt_view = GTK_TEXT_VIEW((glade_xml_get_widget(sediff_app->window_xml, "sediff_key_txt_view")));
	txt = gtk_text_view_get_buffer(txt_view);
	sediff_clear_text_buffer(txt);
	gtk_text_buffer_get_end_iter(txt, &iter);

	table = gtk_text_buffer_get_tag_table(txt);
	added_tag = gtk_text_tag_table_lookup(table, "added-tag");
	if (!added_tag) {
		added_tag = gtk_text_buffer_create_tag(txt, "added-tag", "family", "monospace", "foreground", "dark green", NULL);
	}
	removed_tag = gtk_text_tag_table_lookup(table, "removed-tag");
	if (!removed_tag) {
		removed_tag = gtk_text_buffer_create_tag(txt, "removed-tag", "family", "monospace", "foreground", "red", NULL);
	}
	changed_tag = gtk_text_tag_table_lookup(table, "changed-tag");
	if (!changed_tag) {
		changed_tag = gtk_text_buffer_create_tag(txt, "changed-tag",
							 "family", "monospace", "foreground", "dark blue", NULL);
	}
	mono_tag = gtk_text_tag_table_lookup(table, "mono-tag");
	if (!mono_tag) {
		mono_tag = gtk_text_buffer_create_tag(txt, "mono-tag", "family", "monospace", NULL);
	}
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if (!header_tag) {
		header_tag = gtk_text_buffer_create_tag(txt, "header-tag",
							"family", "monospace",
							"weight", PANGO_WEIGHT_BOLD, "underline", PANGO_UNDERLINE_SINGLE, NULL);
	}

	g_string_printf(string, " Added(+):\n  Items added\n  in policy 2.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "added-tag", NULL);
	g_string_printf(string, " Removed(-):\n  Items removed\n  from policy 1.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "removed-tag", NULL);
	g_string_printf(string, " Modified(*):\n  Items modified\n  from policy 1\n  to policy 2.");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "changed-tag", NULL);
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

static void sediff_treeview_on_row_double_clicked(GtkTreeView * tree_view,
						  GtkTreePath * path, GtkTreeViewColumn * col, gpointer user_data)
{
	/* Finish later */

	g_idle_add_full(G_PRIORITY_HIGH_IDLE, &sediff_results_txt_view_switch_results, NULL, NULL);
	row_selected_signal_emit();
}

static gboolean sediff_treeview_on_row_selected(GtkTreeSelection * selection,
						GtkTreeModel * model,
						GtkTreePath * path, gboolean path_currently_selected, gpointer userdata)
{

	/* if the row is not selected, then its about to be selected ! */
	/* we put in this toggle because for some reason if we have a previously selected path
	 * then this callback is called like this
	 * 1  new_path is not selected
	 * 2  old_path is selected
	 * 3  new_path is not selected
	 * This messes up our te rules stuff so I just put in a check to make sure we're not called
	 * 2 times when we are really only selected once
	 */
	if (toggle && gtk_tree_selection_path_is_selected(selection, path) == FALSE) {
		g_idle_add_full(G_PRIORITY_HIGH_IDLE, &sediff_results_txt_view_switch_results, NULL, NULL);
		row_selected_signal_emit();

	} else
		toggle = !toggle;
	return TRUE;		       /* allow selection state to change */
}

static void sediff_callbacks_free_elem_data(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *) data;
	if (callback)
		free(callback);
	return;
}

/* this function is used to determine whether we allow
   a window click events to happen, if there is nothing in the
   buffer we don't */
gboolean sediff_textview_button_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data)
{
	GtkTextBuffer *txt = NULL;
	GtkTextView *view = NULL;
	GtkTextIter start, end;

	if (strcmp("GtkTextView", gtk_type_name(GTK_WIDGET_TYPE(widget))) == 0)
		view = GTK_TEXT_VIEW(widget);
	else
		return FALSE;
	if (view == NULL)
		return FALSE;
	txt = gtk_text_view_get_buffer(view);

	/* check to see if there is anything currently in this buffer that can be selected */
	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
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
		gtk_text_view_set_editable(GTK_TEXT_VIEW(sediff_app->dummy_view), FALSE);
		gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(sediff_app->dummy_view), FALSE);
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

	label = (GtkLabel *) glade_xml_get_widget(sediff_app->window_xml, "line_label");
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
	gtk_tree_selection_set_mode(sel, GTK_SELECTION_BROWSE);
	gtk_tree_selection_set_select_function(sel, sediff_treeview_on_row_selected, sediff_app->tree_view, NULL);
	g_signal_connect(G_OBJECT(sediff_app->tree_view), "row-activated", G_CALLBACK(sediff_treeview_on_row_double_clicked), NULL);

	notebook1 = (GtkNotebook *) glade_xml_get_widget(sediff_app->window_xml, "notebook1");
	g_assert(notebook1);
	notebook2 = (GtkNotebook *) glade_xml_get_widget(sediff_app->window_xml, "notebook2");
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

void sediff_menu_on_default_sort_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_DEFAULT, SORT_ASCEND);
}

void sediff_menu_on_src_type_asc_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_SOURCE, SORT_ASCEND);
}

void sediff_menu_on_src_type_des_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_SOURCE, SORT_DESCEND);
}

void sediff_menu_on_tgt_type_asc_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_TARGET, SORT_ASCEND);
}

void sediff_menu_on_tgt_type_des_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_TARGET, SORT_DESCEND);
}

void sediff_menu_on_oclass_asc_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_CLASS, SORT_ASCEND);
}

void sediff_menu_on_oclass_des_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_CLASS, SORT_DESCEND);
}

void sediff_menu_on_cond_asc_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_COND, SORT_ASCEND);
}

void sediff_menu_on_cond_des_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_results_sort_current(sediff_app, SORT_COND, SORT_DESCEND);
}

void sediff_menu_on_find_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	if (sediff_app->find_window == NULL)
		sediff_app->find_window = sediff_find_window_new(sediff_app);
	g_assert(sediff_app->find_window);
	sediff_find_window_display(sediff_app->find_window);
}

void sediff_menu_on_edit_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	GtkTextBuffer *txt = NULL;
	GtkTextView *view = NULL;
	GtkTextIter start, end;
	GtkWidget *widget = NULL;
	if (sediff_app == NULL)
		return;
	view = sediff_get_current_view(sediff_app);
	if (view == NULL)
		return;
	txt = gtk_text_view_get_buffer(view);
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_menu_copy");
	g_assert(widget);

	/* check to see if anything has been selected and set copy button up */
	if (gtk_text_buffer_get_selection_bounds(txt, &start, &end)) {
		gtk_widget_set_sensitive(widget, TRUE);
	} else {
		gtk_widget_set_sensitive(widget, FALSE);
	}
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_select_all");
	g_assert(widget);
	/* check to see if there is anything currently in this buffer that can be selected */
	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	if (gtk_text_iter_get_offset(&start) == gtk_text_iter_get_offset(&end)) {
		gtk_widget_set_sensitive(widget, FALSE);
	} else {
		gtk_widget_set_sensitive(widget, TRUE);
	}
}

void sediff_menu_on_select_all_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	GtkTextBuffer *txt = NULL;
	GtkTextView *view = NULL;
	GtkTextIter start, end;
	if (sediff_app == NULL)
		return;
	view = sediff_get_current_view(sediff_app);
	if (view == NULL)
		return;
	txt = gtk_text_view_get_buffer(view);
	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	gtk_text_buffer_select_range(txt, &start, &end);
}

void sediff_menu_on_copy_clicked(GtkMenuItem * menuitem, gpointer user_data)
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
	gtk_text_buffer_copy_clipboard(txt, clipboard);
}

static void sediff_remap_types_window_show()
{
	if (sediff_app->remap_types_window == NULL)
		sediff_app->remap_types_window = sediff_remap_types_window_new(sediff_app);
	g_assert(sediff_app->remap_types_window);
	sediff_remap_types_window_display(sediff_app->remap_types_window);
}

void sediff_menu_on_remaptypes_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_remap_types_window_show();
}

void sediff_menu_on_open_clicked(GtkMenuItem * menuitem, gpointer user_data)
{
	sediff_open_button_clicked();
}

/* raise the correct policy tab on the gui, and go to the line clicked
 * by the user */
void sediff_main_notebook_raise_policy_tab_goto_line(unsigned long line, int whichview)
{
	GtkNotebook *main_notebook, *tab_notebook;
	GtkTextBuffer *buffer;
	GtkTextIter iter, end_iter;
	GtkTextView *text_view = NULL;
	GtkTextTagTable *table = NULL;
	GtkTextMark *mark = NULL;
	GtkLabel *lbl = NULL;
	GString *string = g_string_new("");

	main_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));
	g_assert(main_notebook);

	if (whichview == 0) {
		gtk_notebook_set_current_page(main_notebook, 1);
		text_view = (GtkTextView *) (glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text"));
		tab_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook1"));
		g_assert(tab_notebook);
		gtk_notebook_set_current_page(tab_notebook, 1);
	} else {
		gtk_notebook_set_current_page(main_notebook, 2);
		text_view = (GtkTextView *) (glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text"));
		tab_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook2"));
		g_assert(tab_notebook);
		gtk_notebook_set_current_page(tab_notebook, 1);
	}

	/* when moving the buffer we must use marks to scroll because
	 * goto_line if called before the line height has been
	 * calculated can produce undesired results, in our case we
	 * get no scrolling at all */
	buffer = gtk_text_view_get_buffer(text_view);
	g_assert(buffer);

	table = gtk_text_buffer_get_tag_table(buffer);
	gtk_text_buffer_get_start_iter(buffer, &iter);
	gtk_text_iter_set_line(&iter, line);
	gtk_text_buffer_get_start_iter(buffer, &end_iter);
	gtk_text_iter_set_line(&end_iter, line);
	while (!gtk_text_iter_ends_line(&end_iter))
		gtk_text_iter_forward_char(&end_iter);

	mark = gtk_text_buffer_create_mark(buffer, "line-position", &iter, TRUE);
	assert(mark);

	gtk_text_view_scroll_to_mark(text_view, mark, 0.0, TRUE, 0.0, 0.5);

	/* destroying the mark and recreating is faster than doing a
	 * move on a mark that still exists, so we always destroy it
	 * once we're done */
	gtk_text_buffer_delete_mark(buffer, mark);
	gtk_text_view_set_cursor_visible(text_view, TRUE);
	gtk_text_buffer_place_cursor(buffer, &iter);
	gtk_text_buffer_select_range(buffer, &iter, &end_iter);

	gtk_container_set_focus_child(GTK_CONTAINER(tab_notebook), GTK_WIDGET(text_view));

	g_string_printf(string, "Line: %d", gtk_text_iter_get_line(&iter) + 1);
	lbl = (GtkLabel *) glade_xml_get_widget(sediff_app->window_xml, "line_label");
	gtk_label_set_text(lbl, string->str);
	g_string_free(string, TRUE);
	return;
}

void sediff_initialize_policies(void)
{
	GtkTextView *textview;
	GtkTextBuffer *txt;

	if (sediff_app->diff) {
		poldiff_destroy(&sediff_app->diff);
	} else {
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

	sediff_remap_types_window_unref_members(sediff_app->remap_types_window);

	/* Grab the 2 policy textviews */
	textview = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	/* Set modified bit to zero, so line numbers won't show while in initialized mode. */
	gtk_text_buffer_set_modified(txt, FALSE);

	textview = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	/* Set modified bit to zero, so line numbers won't show while in initialized mode. */
	gtk_text_buffer_set_modified(txt, FALSE);

	textview = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_stats_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);

	textview = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_stats_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);

	sediff_set_open_policies_gui_state(FALSE);
}

/* return the textview currently displayed to the user */
GtkTextView *sediff_get_current_view(sediff_app_t * app)
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
#endif
