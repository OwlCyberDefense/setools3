/**
 *  @file report_window.c
 *  Run the dialog that generates reports.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#include "report_window.h"
#include "utilgui.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <glade/glade.h>
#include <seaudit/report.h>

struct report_window
{
	GladeXML *xml;
	GtkDialog *dialog;
	GtkRadioButton *all_messages_radio, *text_radio;
	GtkToggleButton *malformed_toggle, *use_stylesheet_toggle;
	GtkWidget *stylesheet_label, *stylesheet_browse, *config_browse;
	GtkEntry *stylesheet_entry, *config_entry;
	char *filename;
	message_view_t *current_view;
	seaudit_log_t *log;
	int result;
	progress_t *progress;
};

static void report_window_on_all_messages_toggle(GtkToggleButton * toggle, gpointer user_data)
{
	gboolean sens = gtk_toggle_button_get_active(toggle);
	struct report_window *rw = (struct report_window *)user_data;
	gtk_widget_set_sensitive(GTK_WIDGET(rw->malformed_toggle), sens);
}

static void report_window_on_use_stylesheet_toggle(GtkToggleButton * toggle, gpointer user_data)
{
	gboolean sens = gtk_toggle_button_get_active(toggle);
	struct report_window *rw = (struct report_window *)user_data;
	gtk_widget_set_sensitive(rw->stylesheet_label, sens);
	gtk_widget_set_sensitive(GTK_WIDGET(rw->stylesheet_entry), sens);
	gtk_widget_set_sensitive(rw->stylesheet_browse, sens);
}

static void report_window_on_output_format_toggle(GtkToggleButton * toggle, gpointer user_data)
{
	gboolean sens = gtk_toggle_button_get_active(toggle);
	struct report_window *rw = (struct report_window *)user_data;
	gtk_widget_set_sensitive(GTK_WIDGET(rw->use_stylesheet_toggle), !sens);
	if (sens == TRUE) {
		gtk_widget_set_sensitive(rw->stylesheet_label, FALSE);
		gtk_widget_set_sensitive(GTK_WIDGET(rw->stylesheet_entry), FALSE);
		gtk_widget_set_sensitive(rw->stylesheet_browse, FALSE);
	} else {
		report_window_on_use_stylesheet_toggle(rw->use_stylesheet_toggle, rw);
	}
}

static void report_window_browse(GtkEntry * entry, GtkWindow * parent, const char *title)
{
	const char *current_path = gtk_entry_get_text(entry);
	char *new_path = util_open_file(parent, title, current_path);
	if (new_path != NULL) {
		gtk_entry_set_text(entry, new_path);
		g_free(new_path);
	}
}

static void report_window_on_stylesheet_browse_click(GtkWidget * widget, gpointer user_data)
{
	struct report_window *rw = (struct report_window *)user_data;
	report_window_browse(rw->stylesheet_entry, GTK_WINDOW(rw->dialog), "Select Style Sheet");
}

static void report_window_on_config_browse_click(GtkWidget * widget, gpointer user_data)
{
	struct report_window *rw = (struct report_window *)user_data;
	report_window_browse(rw->config_entry, GTK_WINDOW(rw->dialog), "Select Report Configuration");
}

/**
 * Set up report window struct's widget pointers.
 */
static void report_window_init_dialog(struct report_window *rw, toplevel_t * top)
{
	rw->dialog = GTK_DIALOG(glade_xml_get_widget(rw->xml, "ReportWindow"));
	assert(rw->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(rw->dialog), toplevel_get_window(top));

	rw->all_messages_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(rw->xml, "ReportWindowAllMessagesRadio"));
	rw->malformed_toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(rw->xml, "ReportWindowMalformedCheck"));
	assert(rw->all_messages_radio != NULL && rw->malformed_toggle != NULL);

	rw->text_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(rw->xml, "ReportWindowTextRadio"));
	rw->use_stylesheet_toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(rw->xml, "ReportWindowUseStylesheetCheck"));
	assert(rw->text_radio != NULL && rw->use_stylesheet_toggle != NULL);

	rw->stylesheet_label = glade_xml_get_widget(rw->xml, "ReportWindowStylesheetLabel");
	rw->stylesheet_entry = GTK_ENTRY(glade_xml_get_widget(rw->xml, "ReportWindowStylesheetEntry"));
	rw->stylesheet_browse = glade_xml_get_widget(rw->xml, "ReportWindowStylesheetBrowse");
	assert(rw->stylesheet_label != NULL && rw->stylesheet_entry && rw->stylesheet_browse);

	rw->config_entry = GTK_ENTRY(glade_xml_get_widget(rw->xml, "ReportWindowConfigEntry"));
	rw->config_browse = glade_xml_get_widget(rw->xml, "ReportWindowConfigBrowse");
	assert(rw->config_entry != NULL && rw->config_browse != NULL);

	/* set up signal handlers */
	g_signal_connect(rw->all_messages_radio, "toggled", G_CALLBACK(report_window_on_all_messages_toggle), rw);
	g_signal_connect(rw->text_radio, "toggled", G_CALLBACK(report_window_on_output_format_toggle), rw);
	g_signal_connect(rw->use_stylesheet_toggle, "toggled", G_CALLBACK(report_window_on_use_stylesheet_toggle), rw);
	g_signal_connect(rw->stylesheet_browse, "clicked", G_CALLBACK(report_window_on_stylesheet_browse_click), rw);
	g_signal_connect(rw->config_browse, "clicked", G_CALLBACK(report_window_on_config_browse_click), rw);

}

/**
 * The first time the report window is shown, populate its entry boxes
 * with values from the user's preferences.  On subsequent times
 * remember the user's entries.
 */
static void report_window_copy_prefs(struct report_window *rw, toplevel_t * top)
{
	static int report_window_initialized = 0;
	if (!report_window_initialized) {
		preferences_t *prefs = toplevel_get_prefs(top);
		gtk_entry_set_text(rw->stylesheet_entry, preferences_get_stylesheet(prefs));
		gtk_entry_set_text(rw->config_entry, preferences_get_report(prefs));
	}
	report_window_initialized = 1;
}

static gpointer report_window_create_report_runner(gpointer data)
{
	struct report_window *rw = (struct report_window *)data;
	seaudit_model_t *model = NULL;
	seaudit_report_t *report = NULL;
	seaudit_report_format_e format = SEAUDIT_REPORT_FORMAT_TEXT;
	int do_malformed = 0, do_stylesheet = 0;
	const char *config_name = NULL, *stylesheet_name = NULL;

	rw->result = -1;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rw->all_messages_radio))) {
		model = seaudit_model_create("All Messages", rw->log);
		if (gtk_toggle_button_get_active(rw->malformed_toggle)) {
			do_malformed = 1;
		}
	} else {
		seaudit_model_t *view_model = message_view_get_model(rw->current_view);
		model = seaudit_model_create_from_model(view_model);
	}
	if (model == NULL) {
		progress_abort(rw->progress, "%s", strerror(errno));
		goto cleanup;
	}
	if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rw->text_radio))) {
		format = SEAUDIT_REPORT_FORMAT_HTML;
	}
	if (gtk_toggle_button_get_active(rw->use_stylesheet_toggle)) {
		do_stylesheet = 1;
	}
	stylesheet_name = gtk_entry_get_text(rw->stylesheet_entry);
	if (strcmp(stylesheet_name, "") == 0) {
		stylesheet_name = NULL;
	}
	config_name = gtk_entry_get_text(rw->config_entry);
	if (strcmp(config_name, "") == 0) {
		config_name = NULL;
	}

	if ((report = seaudit_report_create(model, rw->filename)) == NULL) {
		progress_abort(rw->progress, "%s", strerror(errno));
		goto cleanup;
	}
	if (seaudit_report_set_format(rw->log, report, format) < 0 ||
	    seaudit_report_set_configuration(rw->log, report, config_name) < 0 ||
	    seaudit_report_set_stylesheet(rw->log, report, stylesheet_name, do_stylesheet) < 0 ||
	    seaudit_report_set_malformed(rw->log, report, do_malformed) < 0) {
		goto cleanup;
	}
	progress_update(rw->progress, "Writing");
	if (seaudit_report_write(rw->log, report) < 0) {
		goto cleanup;
	}
	rw->result = 0;
      cleanup:
	seaudit_report_destroy(&report);
	seaudit_model_destroy(&model);
	if (rw->result == 0) {
		progress_done(rw->progress);
	} else {
		progress_abort(rw->progress, NULL);
	}
	return NULL;
}

void report_window_run(toplevel_t * top, message_view_t * view)
{
	struct report_window rw;
	/** keey track of most recently used report filename */
	static char *filename = NULL;

	memset(&rw, 0, sizeof(rw));
	rw.xml = glade_xml_new(toplevel_get_glade_xml(top), "ReportWindow", NULL);
	report_window_init_dialog(&rw, top);
	report_window_copy_prefs(&rw, top);

	rw.current_view = view;
	rw.log = toplevel_get_log(top);
	rw.progress = toplevel_get_progress(top);
	rw.filename = filename;
	do {
		gint response = gtk_dialog_run(rw.dialog);
		if (response != GTK_RESPONSE_OK) {
			break;
		}
		if ((filename = util_save_file(GTK_WINDOW(rw.dialog), "Save Report to File", rw.filename)) == NULL) {
			continue;
		}
		g_free(rw.filename);
		rw.filename = filename;
		util_cursor_wait(GTK_WIDGET(rw.dialog));
		progress_show(rw.progress, "Creating Report");
		g_thread_create(report_window_create_report_runner, &rw, FALSE, NULL);
		progress_wait(rw.progress);
		progress_hide(rw.progress);
		util_cursor_clear(GTK_WIDGET(rw.dialog));
		if (rw.result == 0) {
			break;
		}
	} while (1);
	gtk_widget_destroy(GTK_WIDGET(rw.dialog));
}
