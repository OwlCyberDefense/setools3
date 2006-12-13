/**
 *  @file toplevel.c
 *  Implementation for the main toplevel window.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "message_view.h"
#include "open_policy_window.h"
#include "policy_view.h"
#include "preferences_view.h"
#include "report_window.h"
#include "toplevel.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <apol/util.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <seaudit/parse.h>

struct toplevel
{
	seaudit_t *s;
	policy_view_t *pv;
	progress_t *progress;
	/** vector of message_view_t that are in the toplevel's notebook */
	apol_vector_t *views;
	GladeXML *xml;
	/** filename for glade file */
	char *xml_filename;
	/** toplevel window widget */
	GtkWindow *w;
	GtkNotebook *notebook;
	/** non-zero if the log file should be polled for changes */
	int do_monitor_log;
	/** event id for the monitor callback */
	guint monitor_id;
	/** serial number for models created, such that new models
	 * will be named Untitled <number> */
	int next_model_number;
	/** filename for most recently opened view */
	char *view_filename;
};

/**
 * Given a view, return its index within the toplevel notebook pages.
 *
 * @param top Toplevel containing the notebook.
 * @param view View to look up.
 *
 * @return Index of the view (zero-indexed), or -1 if not found.
 */
static gint toplevel_notebook_find_view(toplevel_t * top, message_view_t * view)
{
	gint num_pages = gtk_notebook_get_n_pages(top->notebook);
	while (num_pages >= 1) {
		GtkWidget *child = gtk_notebook_get_nth_page(top->notebook, num_pages - 1);
		GtkWidget *tab = gtk_notebook_get_tab_label(top->notebook, child);
		message_view_t *v = g_object_get_data(G_OBJECT(tab), "view-object");
		if (v == view) {
			return num_pages - 1;
		}
		num_pages--;
	}
	return -1;
}

/**
 * Return the view on the page that is currently raised, or NULL if
 * there are no views.
 */
static message_view_t *toplevel_get_current_view(toplevel_t * top)
{
	gint current = gtk_notebook_get_current_page(top->notebook);
	if (current >= 0) {
		GtkWidget *child = gtk_notebook_get_nth_page(top->notebook, current);
		GtkWidget *tab = gtk_notebook_get_tab_label(top->notebook, child);
		return g_object_get_data(G_OBJECT(tab), "view-object");
	}
	return NULL;
}

static void toplevel_on_notebook_switch_page(GtkNotebook * notebook __attribute__ ((unused)), GtkNotebookPage * page
					     __attribute__ ((unused)), guint pagenum __attribute__ ((unused)), toplevel_t * top)
{
	toplevel_update_selection_menu_item(top);
	toplevel_update_status_bar(top);
}

/**
 * Callback invoked when a tab close button is clicked.
 */
static void toplevel_on_tab_close(GtkButton * button, toplevel_t * top)
{
	/* disallow the close if this is the last tab */
	if (top->views == NULL || apol_vector_get_size(top->views) <= 1) {
		return;
	} else {
		message_view_t *view = g_object_get_data(G_OBJECT(button), "view-object");
		gint idx = toplevel_notebook_find_view(top, view);
		size_t i;
		assert(idx >= 0);
		gtk_notebook_remove_page(top->notebook, idx);
		apol_vector_get_index(top->views, view, NULL, NULL, &i);
		message_view_destroy(&view);
		apol_vector_remove(top->views, i);
	}
}

/**
 * Create a new view associated with the given model, then create a
 * tab to place that view.  The newly created tab will then be raised.
 *
 * @param top Toplevel containing notebook to which add the view and tab.
 * @param model Model from which to create a view.
 * @param filename Initial filename for the view.
 */
static void toplevel_add_new_view(toplevel_t * top, seaudit_model_t * model, const char *filename)
{
	message_view_t *view;
	GtkWidget *tab, *button, *label, *image;
	gint idx;
	if ((view = message_view_create(top, model, filename)) == NULL) {
		return;
	}
	if (apol_vector_append(top->views, view) < 0) {
		toplevel_ERR(top, "%s", strerror(errno));
		message_view_destroy(&view);
		return;
	}
	tab = gtk_hbox_new(FALSE, 5);
	g_object_set_data(G_OBJECT(tab), "view-object", view);
	button = gtk_button_new();
	g_object_set_data(G_OBJECT(button), "view-object", view);
	image = gtk_image_new_from_stock(GTK_STOCK_CLOSE, GTK_ICON_SIZE_MENU);
	gtk_container_add(GTK_CONTAINER(button), image);
	gtk_widget_set_size_request(image, 8, 8);
	g_signal_connect(G_OBJECT(button), "pressed", G_CALLBACK(toplevel_on_tab_close), top);
	label = gtk_label_new(seaudit_model_get_name(model));
	g_object_set_data(G_OBJECT(tab), "label", label);
	gtk_box_pack_start(GTK_BOX(tab), label, TRUE, TRUE, 5);
	gtk_box_pack_end(GTK_BOX(tab), button, FALSE, FALSE, 5);
	gtk_widget_show(label);
	gtk_widget_show(button);
	gtk_widget_show(image);
	idx = gtk_notebook_append_page(top->notebook, message_view_get_view(view), tab);
	gtk_notebook_set_current_page(top->notebook, idx);
}

/**
 * Create a new model for the currently loaded log file (which could
 * be NULL), then create a view that watches that model.
 */
static void toplevel_add_new_model(toplevel_t * top)
{
	seaudit_log_t *log = seaudit_get_log(top->s);
	char *model_name = NULL;
	seaudit_model_t *model = NULL;
	if (asprintf(&model_name, "Untitled %d", top->next_model_number) < 0) {
		toplevel_ERR(top, "%s", strerror(errno));
		return;
	}
	model = seaudit_model_create(model_name, log);
	free(model_name);
	if (model == NULL) {
		toplevel_ERR(top, "%s", strerror(errno));
		return;
	} else {
		top->next_model_number++;
		toplevel_add_new_view(top, model, NULL);
	}
}

/**
 * Callback whenever an item from the recent logs submenu is activated.
 */
static void toplevel_on_open_recent_log_activate(GtkWidget * widget, gpointer user_data)
{
	GtkWidget *label = gtk_bin_get_child(GTK_BIN(widget));
	const char *path = gtk_label_get_text(GTK_LABEL(label));
	toplevel_t *top = (toplevel_t *) user_data;
	toplevel_open_log(top, path);
}

/**
 * Update the entries within recent logs submenu to match those in the
 * preferences object.
 */
static void toplevel_set_recent_logs_submenu(toplevel_t * top)
{
	GtkMenuItem *recent = GTK_MENU_ITEM(glade_xml_get_widget(top->xml, "OpenRecentLog"));
	apol_vector_t *paths = preferences_get_recent_logs(toplevel_get_prefs(top));
	GtkWidget *submenu, *submenu_item;
	size_t i;

	gtk_menu_item_remove_submenu(recent);
	submenu = gtk_menu_new();
	for (i = 0; i < apol_vector_get_size(paths); i++) {
		char *path = (char *)apol_vector_get_element(paths, i);
		submenu_item = gtk_menu_item_new_with_label(path);
		gtk_menu_shell_prepend(GTK_MENU_SHELL(submenu), submenu_item);
		gtk_widget_show(submenu_item);
		g_signal_connect(G_OBJECT(submenu_item), "activate", G_CALLBACK(toplevel_on_open_recent_log_activate), top);
	}
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(recent), submenu);
}

/**
 * Callback whenever an item from the recent policies submenu is
 * activated.
 */
static void toplevel_on_open_recent_policy_activate(GtkWidget * widget, gpointer user_data)
{
	GtkWidget *label = gtk_bin_get_child(GTK_BIN(widget));
	const char *path = gtk_label_get_text(GTK_LABEL(label));
	toplevel_t *top = (toplevel_t *) user_data;
	//TODO handle modules with recent policy list
	toplevel_open_policy(top, path, NULL);
}

/**
 * Update the entries within recent policies submenu to match those in
 * the preferences object.
 */
static void toplevel_set_recent_policies_submenu(toplevel_t * top)
{
	GtkMenuItem *recent = GTK_MENU_ITEM(glade_xml_get_widget(top->xml, "OpenRecentPolicy"));
	apol_vector_t *paths = preferences_get_recent_policies(toplevel_get_prefs(top));
	GtkWidget *submenu, *submenu_item;
	size_t i;

	gtk_menu_item_remove_submenu(recent);
	submenu = gtk_menu_new();
	for (i = 0; i < apol_vector_get_size(paths); i++) {
		char *path = (char *)apol_vector_get_element(paths, i);
		submenu_item = gtk_menu_item_new_with_label(path);
		gtk_menu_shell_prepend(GTK_MENU_SHELL(submenu), submenu_item);
		gtk_widget_show(submenu_item);
		g_signal_connect(G_OBJECT(submenu_item), "activate", G_CALLBACK(toplevel_on_open_recent_policy_activate), top);
	}
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(recent), submenu);
}

/**
 * Enable/disable all items (menus and buttons) that depend upon if a
 * log is loaded.
 *
 * @param top Toplevel object containing menu items.
 * @param TRUE to enable items, FALSE to disable.
 */
static void toplevel_enable_log_items(toplevel_t * top, gboolean sens)
{
	static const char *items[] = {
		"NewView", "OpenView", "SaveView", "SaveViewAs", "ModifyView",
		"ExportAll", "ExportSelected", "ViewMessage",
		"CreateReport", "MonitorLog", "ModifyViewButton", "MonitorLogButton",
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
 * Enable/disable all items (menus and buttons) that depend upon if a
 * policy is loaded.
 *
 * @param top Toplevel object containing menu items.
 * @param TRUE to enable items, FALSE to disable.
 */
static void toplevel_enable_policy_items(toplevel_t * top, gboolean sens)
{
	static const char *items[] = {
		"FindTERules", "FindTERulesButton",
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
 * Update the toplevel's title bar to list the log and policy files
 * opened.
 *
 * @param top Toplevel to modify.
 */
static void toplevel_update_title_bar(toplevel_t * top)
{
	char *log_path = seaudit_get_log_path(top->s);
	char *policy_path = seaudit_get_policy_path(top->s);
	char *s;

	if (log_path == NULL) {
		log_path = "No Log";
	}
	if (policy_path == NULL) {
		policy_path = "No Policy";
	}
	if (asprintf(&s, "seaudit - [Log file: %s] [Policy file: %s]", log_path, policy_path) < 0) {
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
	static const char *icon_names[] = { "seaudit-small.png", "seaudit.png" };
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

toplevel_t *toplevel_create(seaudit_t * s)
{
	toplevel_t *top;
	GtkWidget *vbox;
	int error = 0;

	if ((top = calloc(1, sizeof(*top))) == NULL || (top->views = apol_vector_create()) == NULL) {
		error = errno;
		goto cleanup;
	}
	top->s = s;
	top->next_model_number = 1;

	if ((top->xml_filename = apol_file_find_path("seaudit.glade")) == NULL ||
	    (top->xml = glade_xml_new(top->xml_filename, "TopLevel", NULL)) == NULL) {
		fprintf(stderr, "Could not open seaudit.glade.\n");
		error = EIO;
		goto cleanup;
	}
	top->w = GTK_WINDOW(glade_xml_get_widget(top->xml, "TopLevel"));
	g_object_set_data(G_OBJECT(top->w), "toplevel", top);
	init_icons(top);
	top->notebook = GTK_NOTEBOOK(gtk_notebook_new());
	g_signal_connect_after(G_OBJECT(top->notebook), "switch-page", G_CALLBACK(toplevel_on_notebook_switch_page), top);
	vbox = glade_xml_get_widget(top->xml, "NotebookVBox");
	gtk_container_add(GTK_CONTAINER(vbox), GTK_WIDGET(top->notebook));
	gtk_widget_show(GTK_WIDGET(top->notebook));
	gtk_widget_show(GTK_WIDGET(top->w));
	toplevel_set_recent_logs_submenu(top);
	toplevel_set_recent_policies_submenu(top);

	glade_xml_signal_autoconnect(top->xml);

	/* create initial blank tab for the notebook */
	toplevel_add_new_model(top);

	/* initialize sub-windows, now that glade XML file has been
	 * read */
	if ((top->pv = policy_view_create(top)) == NULL || (top->progress = progress_create(top)) == NULL) {
		error = errno;
		goto cleanup;
	}
      cleanup:
	if (error != 0) {
		toplevel_destroy(&top);
		errno = error;
		return NULL;
	}
	return top;
}

static void message_view_free(void *elem)
{
	message_view_t *view = elem;
	message_view_destroy(&view);
}

void toplevel_destroy(toplevel_t ** top)
{
	if (top != NULL && *top != NULL) {
		if ((*top)->monitor_id > 0) {
			g_source_remove((*top)->monitor_id);
		}
		policy_view_destroy(&(*top)->pv);
		apol_vector_destroy(&(*top)->views, message_view_free);
		free((*top)->xml_filename);
		g_free((*top)->view_filename);
		progress_destroy(&(*top)->progress);
		if ((*top)->w != NULL) {
			gtk_widget_destroy(GTK_WIDGET((*top)->w));
		}
		free(*top);
		*top = NULL;
	}
}

struct log_run_datum
{
	toplevel_t *top;
	FILE *file;
	const char *filename;
	seaudit_log_t *log;
	int result;
};

/**
 * Update the seaudit log, then refresh all views as necessary.  Note
 * that this only works in a single-threaded environment; otherwise
 * there are two possible race conditions:
 *   - monitor is disabled while this function is being executed
 *   - a new log file is loaded while the function is being executed
 *
 * But what happens if this function is scheduled and then a new log
 * is opened?  In toplevel_open_log(), do_monitor_log is temporarily
 * disabled because that function is threaded.  It is then re-enabled
 * afterwards.
 *
 * To make this function fully thread-safe requires making this entire
 * function synchronized, and then employ locking every time
 * do_monitor_log and monitor_id are set.
 */
static gboolean toplevel_monitor_log_timer(gpointer data)
{
	toplevel_t *top = (toplevel_t *) data;
	if (top->do_monitor_log) {
		int retval;
		gint i = gtk_notebook_get_n_pages(top->notebook) - 1;
		uint delay;
		retval = seaudit_parse_log(top->s);
		if (retval < 0) {
			GtkCheckMenuItem *w;
			toplevel_ERR(top, "Error while monitoring log: %s", strerror(errno));
			w = GTK_CHECK_MENU_ITEM(glade_xml_get_widget(top->xml, "MonitorLog"));
			top->monitor_id = 0;
			gtk_check_menu_item_set_active(w, 0);
			return FALSE;
		}
		while (i >= 0) {
			GtkWidget *child = gtk_notebook_get_nth_page(top->notebook, i);
			GtkWidget *tab = gtk_notebook_get_tab_label(top->notebook, child);
			message_view_t *v = g_object_get_data(G_OBJECT(tab), "view-object");
			message_view_update_rows(v);
			i--;
		}

		/* reschedule another timer callback */
		delay = preferences_get_real_time_interval(toplevel_get_prefs(top));
		top->monitor_id = g_timeout_add(delay, toplevel_monitor_log_timer, top);
	} else {
		top->monitor_id = 0;
	}
	return FALSE;
}

/**
 * Enable or disable the log monitoring feature.  While enabled, the
 * log file will be periodically polled; new lines will be parsed and
 * inserted into the seaudit log object.  All models and their views
 * will then be notified of the changes.
 *
 * @param top Toplevel object whose widgets to update.
 */
static void toplevel_monitor_log(toplevel_t * top)
{
	GtkLabel *label = GTK_LABEL(glade_xml_get_widget(top->xml, "MonitorLogLabel"));
	assert(label != NULL);
	if (top->do_monitor_log) {
		gtk_label_set_markup(label, "Monitor Status: <span foreground=\"green\">ON</span>");
		if (top->monitor_id == 0) {
			uint delay = preferences_get_real_time_interval(toplevel_get_prefs(top));
			top->monitor_id = g_timeout_add(delay, toplevel_monitor_log_timer, top);
		}
	} else {
		if (top->monitor_id > 0) {
			g_source_remove(top->monitor_id);
			top->monitor_id = 0;
		}
		gtk_label_set_markup(label, "Monitor Status: <span foreground=\"red\">OFF</span>");
	}
}

/**
 * Thread that loads and parses a log file.  It will write to
 * progress_seaudit_handle_func() its status during the load.  Note
 * that the file handle is not closed upon completion; it is left open
 * so that subsequent calls to seaudit_log_parse(), such as
 * forreal-time monitoring.
 *
 * @param data Pointer to a struct log_run_datum, for control
 * information.
 */
static gpointer toplevel_open_log_runner(gpointer data)
{
	struct log_run_datum *run = (struct log_run_datum *)data;
	progress_update(run->top->progress, "Parsing %s", run->filename);
	if ((run->file = fopen(run->filename, "r")) == NULL) {
		progress_update(run->top->progress, "Could not open %s for reading.", run->filename);
		run->result = -1;
		goto cleanup;
	}
	if ((run->log = seaudit_log_create(progress_seaudit_handle_func, run->top->progress)) == NULL) {
		progress_update(run->top->progress, "%s", strerror(errno));
		run->result = -1;
		goto cleanup;
	}
	run->result = seaudit_log_parse(run->log, run->file);
      cleanup:
	if (run->result < 0) {
		if (run->file != NULL) {
			fclose(run->file);
		}
		run->file = NULL;
		seaudit_log_destroy(&run->log);
		progress_abort(run->top->progress, NULL);
	} else if (run->result > 0) {
		progress_warn(run->top->progress, NULL);
	} else {
		progress_done(run->top->progress);
	}
	return NULL;
}

/**
 * Destroy all views and their notebook tabs.
 */
static void toplevel_destroy_views(toplevel_t * top)
{
	gint num_pages = gtk_notebook_get_n_pages(top->notebook);
	while (num_pages >= 1) {
		message_view_t *view = apol_vector_get_element(top->views, num_pages - 1);
		gtk_notebook_remove_page(top->notebook, num_pages - 1);
		message_view_destroy(&view);
		apol_vector_remove(top->views, num_pages - 1);
		num_pages--;
	}
}

void toplevel_open_log(toplevel_t * top, const char *filename)
{
	struct log_run_datum run = { top, NULL, filename, NULL, 0 };
	int was_monitor_running;
	GtkCheckMenuItem *w;

	/* disable monitoring during the threaded part of this code */
	was_monitor_running = top->do_monitor_log;
	top->do_monitor_log = 0;
	toplevel_monitor_log(top);

	util_cursor_wait(GTK_WIDGET(top->w));
	progress_show(top->progress, "Opening Log");
	g_thread_create(toplevel_open_log_runner, &run, FALSE, NULL);
	progress_wait(top->progress);
	progress_hide(top->progress);
	util_cursor_clear(GTK_WIDGET(top->w));

	if (run.result < 0) {
		top->do_monitor_log = was_monitor_running;
		toplevel_monitor_log(top);
		return;
	}

	toplevel_destroy_views(top);
	top->next_model_number = 1;
	seaudit_set_log(top->s, run.log, run.file, filename);
	toplevel_set_recent_logs_submenu(top);
	toplevel_enable_log_items(top, TRUE);
	toplevel_add_new_model(top);
	toplevel_update_title_bar(top);
	toplevel_update_status_bar(top);
	toplevel_update_selection_menu_item(top);
	top->do_monitor_log = preferences_get_real_time_at_startup(toplevel_get_prefs(top));

	w = GTK_CHECK_MENU_ITEM(glade_xml_get_widget(top->xml, "MonitorLog"));

	gtk_check_menu_item_set_active(w, top->do_monitor_log);
	/* call this again because the check item could have already
	 * been active, thus its handler would not run */
	toplevel_monitor_log(top);
}

struct policy_run_datum
{
	toplevel_t *top;
	const char *filename;
	apol_policy_t *policy;
	apol_vector_t *modules;
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
	run->policy = NULL;
	progress_update(run->top->progress, "Opening policy.");
	run->result = apol_policy_open(run->filename, &run->policy, progress_apol_handle_func, run->top->progress);
	if (run->result < 0) {
		apol_policy_destroy(&run->policy);
		progress_abort(run->top->progress, NULL);
		return NULL;
	}
	if (run->result > 0) {
		progress_warn(run->top->progress, NULL);
	}
	if (run->modules) {
		size_t i;
		if (!qpol_policy_has_capability(apol_policy_get_qpol(run->policy), QPOL_CAP_MODULES)) {
			apol_policy_destroy(&run->policy);
			run->result = -1;
			progress_abort(run->top->progress, "Polcy %s does not support loadable modules.", run->filename);
			return NULL;
		}
		for (i = 0; i < apol_vector_get_size(run->modules); i++) {
			char *module_filename = apol_vector_get_element(run->modules, i);
			qpol_module_t *mod = NULL;
			if (qpol_module_create_from_file(module_filename, &mod)) {
				run->result = -1;
				progress_abort(run->top->progress, "Unable to open module %s", module_filename);
				return NULL;
			}
			if (qpol_policy_append_module(apol_policy_get_qpol(run->policy), mod)) {
				qpol_module_destroy(&mod);
				run->result = -1;
				progress_abort(run->top->progress, "Error appending module: %s", strerror(ENOMEM));
				return NULL;
			}
		}

		progress_update(run->top->progress, "Linking policy modules.");
		run->result = qpol_policy_rebuild(apol_policy_get_qpol(run->policy));
		if (run->result) {
			progress_abort(run->top->progress, NULL);
		} else {
			progress_done(run->top->progress);
		}
	} else {
		progress_done(run->top->progress);
	}
	return NULL;
}

int toplevel_open_policy(toplevel_t * top, const char *filename, apol_vector_t * modules)
{
	struct policy_run_datum run = { top, filename, NULL, modules, 0 };

	util_cursor_wait(GTK_WIDGET(top->w));
	progress_show(top->progress, filename);
	g_thread_create(toplevel_open_policy_runner, &run, FALSE, NULL);
	progress_wait(top->progress);
	progress_hide(top->progress);
	util_cursor_clear(GTK_WIDGET(top->w));
	if (run.result < 0) {
		return run.result;
	}
	seaudit_set_policy(top->s, run.policy, filename);
	toplevel_set_recent_policies_submenu(top);
	toplevel_enable_policy_items(top, TRUE);
	toplevel_update_title_bar(top);
	toplevel_update_status_bar(top);
	policy_view_update(top->pv, filename);
	return 0;
}

void toplevel_update_status_bar(toplevel_t * top)
{
	apol_policy_t *policy = seaudit_get_policy(top->s);
	GtkLabel *policy_version = (GtkLabel *) glade_xml_get_widget(top->xml, "PolicyVersionLabel");
	GtkLabel *log_num = (GtkLabel *) glade_xml_get_widget(top->xml, "LogNumLabel");
	GtkLabel *log_dates = (GtkLabel *) glade_xml_get_widget(top->xml, "LogDateLabel");
	seaudit_log_t *log = toplevel_get_log(top);

	if (policy == NULL) {
		gtk_label_set_text(policy_version, "Policy: No policy");
	} else {
		char *policy_str = apol_policy_get_version_type_mls_str(policy);
		if (policy_str == NULL) {
			toplevel_ERR(top, "%s", strerror(errno));
		} else {
			char *s;
			if (asprintf(&s, "Policy: %s", policy_str) < 0) {
				toplevel_ERR(top, "%s", strerror(errno));
			} else {
				gtk_label_set_text(policy_version, s);
				free(s);
			}
			free(policy_str);
		}
	}

	if (log == NULL) {
		gtk_label_set_text(log_num, "Log Messages: No log");
		gtk_label_set_text(log_dates, "Dates: No log");
	} else {
		message_view_t *view = toplevel_get_current_view(top);
		size_t num_messages = seaudit_get_num_log_messages(top->s);
		size_t num_view_messages;
		struct tm *first = seaudit_get_log_first(top->s);
		struct tm *last = seaudit_get_log_last(top->s);
		assert(view != NULL);
		num_view_messages = message_view_get_num_log_messages(view);
		char *s, t1[256], t2[256];
		if (asprintf(&s, "Log Messages: %zd/%zd", num_view_messages, num_messages) < 0) {
			toplevel_ERR(top, "%s", strerror(errno));
		} else {
			gtk_label_set_text(log_num, s);
			free(s);
		}
		if (first == NULL || last == NULL) {
			gtk_label_set_text(log_dates, "Dates: No messages");
		} else {
			strftime(t1, 256, "%b %d %H:%M:%S", first);
			strftime(t2, 256, "%b %d %H:%M:%S", last);
			if (asprintf(&s, "Dates: %s - %s", t1, t2) < 0) {
				toplevel_ERR(top, "%s", strerror(errno));
			} else {
				gtk_label_set_text(log_dates, s);
				free(s);
			}
		}
	}
}

void toplevel_update_tabs(toplevel_t * top)
{
	gint i = gtk_notebook_get_n_pages(top->notebook) - 1;
	while (i >= 0) {
		GtkWidget *child = gtk_notebook_get_nth_page(top->notebook, i);
		GtkWidget *tab = gtk_notebook_get_tab_label(top->notebook, child);
		GtkWidget *label = g_object_get_data(G_OBJECT(tab), "label");
		message_view_t *v = g_object_get_data(G_OBJECT(tab), "view-object");
		seaudit_model_t *model = message_view_get_model(v);
		char *name = seaudit_model_get_name(model);
		gtk_label_set_text(GTK_LABEL(label), name);
		i--;
	}
}

void toplevel_update_selection_menu_item(toplevel_t * top)
{
	static const char *items[] = {
		"ExportSelected", "ViewMessage",
		NULL
	};
	message_view_t *view = toplevel_get_current_view(top);
	gboolean sens = FALSE;
	size_t i;
	const char *s;
	if (view != NULL) {
		sens = message_view_is_message_selected(view);
	}
	for (i = 0, s = items[0]; s != NULL; s = items[++i]) {
		GtkWidget *w = glade_xml_get_widget(top->xml, s);
		assert(s != NULL);
		gtk_widget_set_sensitive(w, sens);
	}
}

preferences_t *toplevel_get_prefs(toplevel_t * top)
{
	return seaudit_get_prefs(top->s);
}

seaudit_log_t *toplevel_get_log(toplevel_t * top)
{
	return seaudit_get_log(top->s);
}

apol_vector_t *toplevel_get_log_users(toplevel_t * top)
{
	return seaudit_get_log_users(top->s);
}

apol_vector_t *toplevel_get_log_roles(toplevel_t * top)
{
	return seaudit_get_log_roles(top->s);
}

apol_vector_t *toplevel_get_log_types(toplevel_t * top)
{
	return seaudit_get_log_types(top->s);
}

apol_vector_t *toplevel_get_log_classes(toplevel_t * top)
{
	return seaudit_get_log_classes(top->s);
}

apol_policy_t *toplevel_get_policy(toplevel_t * top)
{
	return seaudit_get_policy(top->s);
}

char *toplevel_get_glade_xml(toplevel_t * top)
{
	return top->xml_filename;
}

progress_t *toplevel_get_progress(toplevel_t * top)
{
	return top->progress;
}

GtkWindow *toplevel_get_window(toplevel_t * top)
{
	return top->w;
}

void toplevel_find_terules(toplevel_t * top, seaudit_message_t * message)
{
	policy_view_find_terules(top->pv, message);
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

/************* below are callbacks for the toplevel menu items *************/

void toplevel_on_destroy(gpointer user_data, GtkObject * object __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	top->w = NULL;
	gtk_main_quit();
}

void toplevel_on_open_log_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	char *path = util_open_file(top->w, "Open Log", seaudit_get_log_path(top->s));
	if (path != NULL) {
		toplevel_open_log(top, path);
		g_free(path);
	}
}

void toplevel_on_open_policy_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	open_policy_window_run(top, seaudit_get_policy_path(top->s));
}

void toplevel_on_preferences_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (preferences_view_run(top)) {
		size_t i;
		for (i = 0; i < apol_vector_get_size(top->views); i++) {
			message_view_t *v = apol_vector_get_element(top->views, i);
			message_view_update_visible_columns(v);
		}
	}
}

void toplevel_on_quit_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	top->w = NULL;
	gtk_main_quit();
}

void toplevel_on_new_view_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	toplevel_add_new_model(top);
}

void toplevel_on_open_view_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	char *path = util_open_file(top->w, "Open View", top->view_filename);
	seaudit_model_t *model = NULL;
	if (path == NULL) {
		return;
	}
	g_free(top->view_filename);
	top->view_filename = path;
	if ((model = seaudit_model_create_from_file(top->view_filename)) == NULL ||
	    seaudit_model_append_log(model, seaudit_get_log(top->s)) < 0) {
		toplevel_ERR(top, "Error opening view: %s", strerror(errno));
		seaudit_model_destroy(&model);
	} else {
		toplevel_add_new_view(top, model, top->view_filename);
	}
}

void toplevel_on_save_view_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	message_view_t *view = toplevel_get_current_view(top);
	assert(view != NULL);
	message_view_save(view);
}

void toplevel_on_save_viewas_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	message_view_t *view = toplevel_get_current_view(top);
	assert(view != NULL);
	message_view_saveas(view);
}

void toplevel_on_modify_view_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	message_view_t *view = toplevel_get_current_view(top);
	assert(view != NULL);
	message_view_modify(view);
}

void toplevel_on_export_all_messages_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	message_view_t *view = toplevel_get_current_view(top);
	assert(view != NULL);
	message_view_export_all_messages(view);
}

void toplevel_on_export_selected_messages_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	message_view_t *view = toplevel_get_current_view(top);
	assert(view != NULL);
	message_view_export_selected_messages(view);
}

void toplevel_on_view_entire_message_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	message_view_t *view = toplevel_get_current_view(top);
	assert(view != NULL);
	message_view_entire_message(view);
}

void toplevel_on_find_terules_activate(gpointer user_data, GtkWidget * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	toplevel_find_terules(top, NULL);
}

void toplevel_on_create_report_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	message_view_t *view = toplevel_get_current_view(top);
	assert(view != NULL);
	report_window_run(top, view);
}

void toplevel_on_monitor_log_activate(gpointer user_data, GtkMenuItem * widget)
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(widget))) {
		top->do_monitor_log = 1;
	} else {
		top->do_monitor_log = 0;
	}
	toplevel_monitor_log(top);
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

	window = gtk_dialog_new_with_buttons("seaudit Help",
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
	dir = apol_file_find_path("seaudit_help.txt");
	if (!dir) {
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

void toplevel_on_about_seaudit_activate(gpointer user_data, GtkMenuItem * widget __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	gtk_show_about_dialog(top->w,
			      "comments", "Audit Log Analysis Tool for Security Enhanced Linux",
			      "copyright", COPYRIGHT_INFO,
			      "name", "seaudit", "version", VERSION, "website", "http://oss.tresys.com/projects/setools", NULL);
}

void toplevel_on_find_terules_click(gpointer user_data, GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
				    __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	toplevel_find_terules(top, NULL);
}

void toplevel_on_modify_view_click(gpointer user_data, GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
				   __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	message_view_t *view = toplevel_get_current_view(top);
	assert(view != NULL);
	message_view_modify(view);
}

void toplevel_on_monitor_log_click(gpointer user_data, GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
				   __attribute__ ((unused)))
{
	toplevel_t *top = g_object_get_data(G_OBJECT(user_data), "toplevel");
	GtkCheckMenuItem *w = GTK_CHECK_MENU_ITEM(glade_xml_get_widget(top->xml, "MonitorLog"));
	gboolean old_state;
	assert(w != NULL);
	old_state = gtk_check_menu_item_get_active(w);
	gtk_check_menu_item_set_active(w, !old_state);
}
