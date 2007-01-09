/**
 *  @file
 *  Implementation of preferences editor.
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

#include "preferences_view.h"
#include "utilgui.h"
#include <assert.h>
#include <string.h>
#include <glade/glade.h>

struct pref_view
{
	GladeXML *xml;
	toplevel_t *top;
	preferences_t *prefs;
	GtkDialog *dialog;
	const char *current_log;
	const apol_policy_path_t *current_policy;
	apol_policy_path_t *policy_path;
};

struct pref_entry
{
	const char *entry_name, *browse_name;
	const char *(*accessor) (preferences_t *);
	int (*modifier) (preferences_t *, const char *);
	const char *title;
	/* next field is for callbacks to the browse button */
	struct pref_view *pv;
};

static struct pref_entry pref_entry_data[] = {
	{"PrefsViewLogEntry", "PrefsViewLogBrowseButton", preferences_get_log, preferences_set_log, "Select Default Log"},
	{"PrefsViewConfigEntry", "PrefsViewConfigBrowseButton", preferences_get_report, preferences_set_report,
	 "Select Report Configuration File"},
	{"PrefsViewStylesheetEntry", "PrefsViewStylesheetBrowseButton", preferences_get_stylesheet, preferences_set_stylesheet,
	 "Select HTML Report Style File"}
};
static const size_t num_entries = sizeof(pref_entry_data) / sizeof(pref_entry_data[0]);

struct pref_toggle
{
	const char *widget_name;
	preference_field_e preference_field;
};

static const struct pref_toggle pref_toggle_map[] = {
	{"HostCheck", HOST_FIELD},
	{"MessageCheck", MESSAGE_FIELD},
	{"DateCheck", DATE_FIELD},
	{"SourceUserCheck", SUSER_FIELD},
	{"SourceRoleCheck", SROLE_FIELD},
	{"SourceTypeCheck", STYPE_FIELD},
	{"TargetUserCheck", TUSER_FIELD},
	{"TargetRoleCheck", TROLE_FIELD},
	{"TargetTypeCheck", TTYPE_FIELD},
	{"ObjectClassCheck", OBJCLASS_FIELD},
	{"PermissionCheck", PERM_FIELD},
	{"ExecutableCheck", EXECUTABLE_FIELD},
	{"CommandCheck", COMMAND_FIELD},
	{"PIDCheck", PID_FIELD},
	{"InodeCheck", INODE_FIELD},
	{"PathCheck", PATH_FIELD},
	{"OtherCheck", OTHER_FIELD}
};
static const size_t num_toggles = sizeof(pref_toggle_map) / sizeof(pref_toggle_map[0]);

static void preferences_view_on_browse_click(GtkWidget * widget, gpointer user_data)
{
	const struct pref_entry *pe = (const struct pref_entry *)user_data;
	struct pref_view *pv = pe->pv;
	GtkEntry *entry = GTK_ENTRY(glade_xml_get_widget(pv->xml, pe->entry_name));
	const char *current_path = gtk_entry_get_text(entry);
	GtkWindow *parent = GTK_WINDOW(pv->dialog);
	const char *title = pe->title;
	char *new_path = util_open_file(parent, title, current_path);
	if (new_path != NULL) {
		gtk_entry_set_text(entry, new_path);
		free(new_path);
	}
}

static void preferences_view_on_log_current_click(GtkWidget * widget, gpointer user_data)
{
	struct pref_view *pv = (struct pref_view *)user_data;
	GtkEntry *entry = GTK_ENTRY(glade_xml_get_widget(pv->xml, "PrefsViewLogEntry"));
	assert(entry != NULL);
	if (pv->current_log == NULL) {
		gtk_entry_set_text(entry, "");
	} else {
		gtk_entry_set_text(entry, pv->current_log);
	}
}

static void preferences_view_on_policy_current_click(GtkWidget * widget, gpointer user_data)
{
	struct pref_view *pv = (struct pref_view *)user_data;
	GtkEntry *entry = GTK_ENTRY(glade_xml_get_widget(pv->xml, "PrefsViewPolicyEntry"));
	assert(entry != NULL);
	apol_policy_path_destroy(&pv->policy_path);
	if (pv->current_policy != NULL) {
		pv->policy_path = apol_policy_path_create_from_policy_path(pv->current_policy);
		char *path_string = util_policy_path_to_string(pv->policy_path);
		gtk_entry_set_text(entry, path_string);
		free(path_string);
	} else {
		gtk_entry_set_text(entry, "");
	}
}

static void preferences_view_init_widgets(struct pref_view *pv)
{
	GtkWidget *w;
	size_t i;

	w = glade_xml_get_widget(pv->xml, "PreferencesWindow");
	assert(w != NULL);
	pv->dialog = GTK_DIALOG(w);
	gtk_window_set_transient_for(GTK_WINDOW(pv->dialog), toplevel_get_window(pv->top));

	for (i = 0; i < num_entries; i++) {
		struct pref_entry *pe = pref_entry_data + i;
		w = glade_xml_get_widget(pv->xml, pe->browse_name);
		assert(w != NULL);
		pe->pv = pv;
		g_signal_connect(w, "clicked", G_CALLBACK(preferences_view_on_browse_click), pe);
	}

	w = glade_xml_get_widget(pv->xml, "PrefsViewLogCurrentButton");
	assert(w != NULL);
	if (pv->current_log == NULL) {
		gtk_widget_set_sensitive(w, FALSE);
	}
	g_signal_connect(w, "clicked", G_CALLBACK(preferences_view_on_log_current_click), pv);

	w = glade_xml_get_widget(pv->xml, "PrefsViewPolicyCurrentButton");
	assert(w != NULL);
	if (pv->current_policy == NULL) {
		gtk_widget_set_sensitive(w, FALSE);
	}
	g_signal_connect(w, "clicked", G_CALLBACK(preferences_view_on_policy_current_click), pv);
}

/**
 * Copy values from preferences object to dialog widgets.
 */
static void preferences_view_init_values(struct pref_view *pv)
{
	GtkWidget *w;
	const char *current_value;
	const apol_policy_path_t *current_path;
	char *s;
	size_t i;

	for (i = 0; i < num_entries; i++) {
		const struct pref_entry *pe = pref_entry_data + i;
		w = glade_xml_get_widget(pv->xml, pe->entry_name);
		assert(w != NULL);
		current_value = pe->accessor(pv->prefs);
		gtk_entry_set_text(GTK_ENTRY(w), current_value);
	}
	if ((current_path = preferences_get_policy(pv->prefs)) != NULL) {
		pv->policy_path = apol_policy_path_create_from_policy_path(current_path);
		w = glade_xml_get_widget(pv->xml, "PrefsViewPolicyEntry");
		char *path_string = util_policy_path_to_string(pv->policy_path);
		assert(w != NULL);
		gtk_entry_set_text(GTK_ENTRY(w), path_string);
		free(path_string);
	}
	for (i = 0; i < num_toggles; i++) {
		int visible;
		w = glade_xml_get_widget(pv->xml, pref_toggle_map[i].widget_name);
		assert(w != NULL);
		visible = preferences_is_column_visible(pv->prefs, pref_toggle_map[i].preference_field);
		if (visible) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), TRUE);
		} else {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), FALSE);
		}
	}
	w = glade_xml_get_widget(pv->xml, "PrefsViewIntervalEntry");
	assert(w != NULL);
	if (asprintf(&s, "%d", preferences_get_real_time_interval(pv->prefs)) >= 0) {
		gtk_entry_set_text(GTK_ENTRY(w), s);
		free(s);
	} else {
		gtk_entry_set_text(GTK_ENTRY(w), "");
	}
	w = glade_xml_get_widget(pv->xml, "RealTimeCheck");
	assert(w != NULL);
	if (preferences_get_real_time_at_startup(pv->prefs)) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), TRUE);
	} else {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), FALSE);
	}
}

/**
 * Copy values from dialog widget to the preferences object.
 */
static void preferences_view_get_from_dialog(struct pref_view *pv)
{
	GtkWidget *w;
	const gchar *entry;
	size_t i;

	for (i = 0; i < num_entries; i++) {
		const struct pref_entry *pe = pref_entry_data + i;
		w = glade_xml_get_widget(pv->xml, pe->entry_name);
		entry = gtk_entry_get_text(GTK_ENTRY(w));
		pe->modifier(pv->prefs, entry);
	}
	preferences_set_policy(pv->prefs, pv->policy_path);
	for (i = 0; i < num_toggles; i++) {
		gboolean active;
		w = glade_xml_get_widget(pv->xml, pref_toggle_map[i].widget_name);
		active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));
		if (active) {
			preferences_set_column_visible(pv->prefs, pref_toggle_map[i].preference_field, 1);
		} else {
			preferences_set_column_visible(pv->prefs, pref_toggle_map[i].preference_field, 0);
		}
	}
	w = glade_xml_get_widget(pv->xml, "PrefsViewIntervalEntry");
	entry = gtk_entry_get_text(GTK_ENTRY(w));
	if (strcmp(entry, "") == 0) {
		entry = "0";
	}
	preferences_set_real_time_interval(pv->prefs, atoi(entry));
	w = glade_xml_get_widget(pv->xml, "RealTimeCheck");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w))) {
		preferences_set_real_time_at_startup(pv->prefs, 1);
	} else {
		preferences_set_real_time_at_startup(pv->prefs, 0);
	}
}

int preferences_view_run(toplevel_t * top, const char *current_log, const apol_policy_path_t * current_policy)
{
	struct pref_view pv;
	gint response;

	memset(&pv, 0, sizeof(pv));
	pv.top = top;
	pv.xml = glade_xml_new(toplevel_get_glade_xml(top), "PreferencesWindow", NULL);
	pv.prefs = toplevel_get_prefs(top);
	pv.current_log = current_log;
	pv.current_policy = current_policy;

	preferences_view_init_widgets(&pv);
	preferences_view_init_values(&pv);

	response = gtk_dialog_run(pv.dialog);
	if (response != GTK_RESPONSE_OK) {
		gtk_widget_destroy(GTK_WIDGET(pv.dialog));
		return 0;
	}
	preferences_view_get_from_dialog(&pv);
	gtk_widget_destroy(GTK_WIDGET(pv.dialog));
	return 1;
}
