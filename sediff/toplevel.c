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
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include "find_dialog.h"
#include "open_policies_dialog.h"
#include "policy_view.h"
#include "remap_types_dialog.h"
#include "sediffx.h"
#include "select_diff_dialog.h"
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
	find_dialog_t *find;
	results_t *results;
	policy_view_t *views[SEDIFFX_POLICY_NUM];
	GladeXML *xml;
	/** filename for glade file */
	char *xml_filename;
	/** toplevel window widget */
	GtkWindow *w;
	/** toplevel notebook widget */
	GtkNotebook *notebook;
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
		"Find", "Run Diff", "Remap Types",
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

static void toplevel_on_switch_page(GtkNotebook * notebook __attribute__ ((unused)), GtkNotebookPage * page
				    __attribute__ ((unused)), guint page_num, gpointer user_data)
{
	toplevel_t *top = (toplevel_t *) user_data;
	if (page_num != 0) {
		toplevel_set_sort_menu_sensitivity(top, FALSE);
	} else {
		results_switch_to_page(top->results);
	}
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
	top->notebook = GTK_NOTEBOOK(glade_xml_get_widget(top->xml, "toplevel main notebook"));
	assert(top->w != NULL && top->notebook != NULL);
	init_icons(top);
	g_object_set_data(G_OBJECT(top->w), "toplevel", top);
	gtk_widget_show(GTK_WIDGET(top->w));
	g_signal_connect(G_OBJECT(top->notebook), "switch-page", G_CALLBACK(toplevel_on_switch_page), top);

	/* initialize sub-windows, now that glade XML file has been
	 * read */
	if ((top->find = find_dialog_create(top)) == NULL ||
	    (top->progress = progress_create(top)) == NULL || (top->results = results_create(top)) == NULL) {
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
		find_dialog_destroy(&(*top)->find);
		progress_destroy(&(*top)->progress);
		results_destroy(&(*top)->results);
		for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
			policy_view_destroy(&(*top)->views[i]);
		}
		free((*top)->xml_filename);
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
	if (remap_types_update(run.policies[SEDIFFX_POLICY_ORIG], run.policies[SEDIFFX_POLICY_MOD]) < 0) {
		toplevel_ERR(top, "%s", strerror(errno));
		apol_policy_path_destroy(&run.paths[0]);
		apol_policy_path_destroy(&run.paths[1]);
		return -1;
	}
	results_open_policies(top->results, run.policies[SEDIFFX_POLICY_ORIG], run.policies[SEDIFFX_POLICY_MOD]);
	for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
		policy_view_update(top->views[i], run.policies[i], run.paths[i]);
		sediffx_set_policy(top->s, i, run.policies[i], run.paths[i]);
	}
	results_update(top->results);
	toplevel_enable_policy_items(top, TRUE);
	toplevel_update_title_bar(top);
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
	run->result = poldiff_run(diff, run->run_flags);
	sediffx_set_poldiff_run_flags(run->top->s, run->run_flags);
	if (run->result < 0) {
		progress_abort(run->top->progress, NULL);
	} else {
		progress_done(run->top->progress);
	}
	return NULL;
}

void toplevel_run_diff(toplevel_t * top)
{
	struct run_datum r;

	r.run_flags = select_diff_dialog_run(top);
	if (r.run_flags == 0) {
		return;
	}
	r.top = top;
	r.result = 0;

	results_clear(top->results);
	util_cursor_wait(GTK_WIDGET(top->w));
	progress_show(top->progress, "Running Diff");
	g_thread_create(toplevel_run_diff_runner, &r, FALSE, NULL);
	progress_wait(top->progress);
	progress_hide(top->progress);
	util_cursor_clear(GTK_WIDGET(top->w));
	if (r.result == 0) {
		results_update(top->results);
	}
}

void toplevel_show_policy_line(toplevel_t * top, sediffx_policy_e which, unsigned long line)
{
	gtk_notebook_set_current_page(top->notebook, 1 + which);
	policy_view_show_policy_line(top->views[which], line);
}

void toplevel_set_sort_menu_sensitivity(toplevel_t * top, gboolean sens)
{
	GtkWidget *w = glade_xml_get_widget(top->xml, "sort menu item");
	assert(w != NULL);
	gtk_widget_set_sensitive(w, sens);
}

void toplevel_set_sort_menu_selection(toplevel_t * top, results_sort_e field, results_sort_dir_e dir)
{
	static const char *menu_items[][2] = {
		{"Default Sort", "Default Sort"},
		{"Ascending source type", "Descending source type"},
		{"Ascending target type", "Descending target type"},
		{"Ascending object class", "Descending object class"},
		{"Ascending conditional", "Descending conditonal"}
	};
	int direction = 1;
	if (dir == RESULTS_SORT_ASCEND) {
		direction = 0;
	}
	GtkWidget *w = glade_xml_get_widget(top->xml, menu_items[field][direction]);
	assert(w != NULL);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(w), TRUE);
}

char *toplevel_get_glade_xml(toplevel_t * top)
{
	return top->xml_filename;
}

gint toplevel_get_notebook_page(toplevel_t * top)
{
	return gtk_notebook_get_current_page(top->notebook);
}

progress_t *toplevel_get_progress(toplevel_t * top)
{
	return top->progress;
}

GtkWindow *toplevel_get_window(toplevel_t * top)
{
	return top->w;
}

GtkTextView *toplevel_get_text_view(toplevel_t * top)
{
	gint pagenum = gtk_notebook_get_current_page(top->notebook);
	switch (pagenum) {
	case 0:
		return results_get_text_view(top->results);
	case 1:
		return policy_view_get_text_view(top->views[SEDIFFX_POLICY_ORIG]);
	case 2:
		return policy_view_get_text_view(top->views[SEDIFFX_POLICY_MOD]);
	}
	/* should never get here */
	assert(0);
	return NULL;
}

poldiff_t *toplevel_get_poldiff(toplevel_t * top)
{
	return sediffx_get_poldiff(top->s, progress_poldiff_handle_func, top->progress);
}

uint32_t toplevel_get_poldiff_run_flags(toplevel_t * top)
{
	return sediffx_get_poldiff_run_flags(top->s);
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

void toplevel_on_open_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	const apol_policy_path_t *orig_path = sediffx_get_policy_path(top->s, SEDIFFX_POLICY_ORIG);
	const apol_policy_path_t *mod_path = sediffx_get_policy_path(top->s, SEDIFFX_POLICY_MOD);
	open_policies_dialog_run(top, orig_path, mod_path);
}

void toplevel_on_quit_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	top->w = NULL;
	gtk_main_quit();
}

void toplevel_on_edit_menu_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	GtkTextView *view = toplevel_get_text_view(top);
	GtkTextBuffer *txt = gtk_text_view_get_buffer(view);
	GtkWidget *copy = glade_xml_get_widget(top->xml, "Copy");
	GtkWidget *select_all = glade_xml_get_widget(top->xml, "Select All");
	GtkTextIter start, end;
	assert(copy != NULL && select_all != NULL);

	/* check to see if anything has been selected and set copy
	 * button up */
	if (gtk_text_buffer_get_selection_bounds(txt, &start, &end)) {
		gtk_widget_set_sensitive(copy, TRUE);
	} else {
		gtk_widget_set_sensitive(copy, FALSE);
	}
	/* check to see if there is anything currently in this buffer
	 * that can be selected */
	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	if (gtk_text_iter_get_offset(&start) == gtk_text_iter_get_offset(&end)) {
		gtk_widget_set_sensitive(select_all, FALSE);
	} else {
		gtk_widget_set_sensitive(select_all, TRUE);
	}
}

void toplevel_on_copy_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	GtkClipboard *clipboard = gtk_clipboard_get(NULL);
	GtkTextView *view = toplevel_get_text_view(top);
	GtkTextBuffer *txt = gtk_text_view_get_buffer(view);
	if (gtk_text_buffer_get_selection_bounds(txt, NULL, NULL)) {
		gtk_text_buffer_copy_clipboard(txt, clipboard);
	}
}

void toplevel_on_select_all_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	GtkTextView *view = toplevel_get_text_view(top);
	GtkTextBuffer *txt = gtk_text_view_get_buffer(view);
	GtkTextIter start, end;
	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	gtk_text_buffer_select_range(txt, &start, &end);
}

void toplevel_on_find_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	find_dialog_show(top->find);
}

void toplevel_on_run_diff_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	toplevel_run_diff(top);
}

void toplevel_on_remap_types_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	remap_types_run(top);
}

void toplevel_on_default_sort_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_DEFAULT, RESULTS_SORT_ASCEND);
	}
}

void toplevel_on_source_type_asc_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_SOURCE, RESULTS_SORT_ASCEND);
	}
}

void toplevel_on_source_type_des_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_SOURCE, RESULTS_SORT_DESCEND);
	}
}

void toplevel_on_target_type_asc_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_TARGET, RESULTS_SORT_ASCEND);
	}
}

void toplevel_on_target_type_des_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_TARGET, RESULTS_SORT_DESCEND);
	}
}

void toplevel_on_class_asc_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_CLASS, RESULTS_SORT_ASCEND);
	}
}

void toplevel_on_class_des_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_CLASS, RESULTS_SORT_DESCEND);
	}
}

void toplevel_on_conditional_asc_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_COND, RESULTS_SORT_ASCEND);
	}
}

void toplevel_on_conditional_des_activate(gpointer user_data, GtkMenuItem * menuitem)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
		results_sort(top->results, RESULTS_SORT_COND, RESULTS_SORT_DESCEND);
	}
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

void toplevel_on_open_policies_button_click(gpointer user_data, GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
					    __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	const apol_policy_path_t *orig_path = sediffx_get_policy_path(top->s, SEDIFFX_POLICY_ORIG);
	const apol_policy_path_t *mod_path = sediffx_get_policy_path(top->s, SEDIFFX_POLICY_MOD);
	open_policies_dialog_run(top, orig_path, mod_path);
}

void toplevel_on_run_diff_button_click(gpointer user_data, GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
				       __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	toplevel_run_diff(top);
}

void toplevel_on_remap_types_button_click(gpointer user_data, GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
					  __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	remap_types_run(top);
}

void toplevel_on_destroy(gpointer user_data, GtkObject * object __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	top->w = NULL;
	gtk_main_quit();
}
