/**
 *  @file preferences_view.c
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

struct pref_entry
{
	const char *entry_name, *browse_name;
	char *(*accessor) (preferences_t *);
	int (*modifier) (preferences_t *, const char *);
	const char *title;
	/* these next two are for callbacks to the browse button */
	GladeXML *xml;
	GtkWindow *parent;
};

static struct pref_entry pref_entry_data[] = {
	{"PrefsViewLogEntry", "PrefsViewLogBrowseButton", preferences_get_log, preferences_set_log, "Select Default Log"},
	{"PrefsViewPolicyEntry", "PrefsViewPolicyBrowseButton", preferences_get_policy, preferences_set_policy,
	 "Select Default Policy"},
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

static void display_browse_dialog_for_entry_box(GtkEntry * entry, GtkWindow * parent, const char *title)
{
	const char *current_path = gtk_entry_get_text(entry);
	char *new_path = util_open_file(parent, title, current_path);
	if (new_path != NULL) {
		gtk_entry_set_text(entry, new_path);
		g_free(new_path);
	}
}

static void preferences_view_on_browse_click(GtkWidget * widget, gpointer user_data)
{
	const struct pref_entry *pe = (const struct pref_entry *)user_data;
	GtkEntry *entry = GTK_ENTRY(glade_xml_get_widget(pe->xml, pe->entry_name));
	display_browse_dialog_for_entry_box(entry, pe->parent, pe->title);
}

/**
 * Copy values from preferences object to dialog widgets.
 */
static void preferences_view_init_dialog(preferences_t * prefs, GladeXML * xml)
{
	GtkWidget *w;
	char *s;
	size_t i;

	for (i = 0; i < num_entries; i++) {
		const struct pref_entry *pe = pref_entry_data + i;
		w = glade_xml_get_widget(xml, pe->entry_name);
		assert(w != NULL);
		s = pe->accessor(prefs);
		gtk_entry_set_text(GTK_ENTRY(w), s);
	}
	for (i = 0; i < num_toggles; i++) {
		int visible;
		w = glade_xml_get_widget(xml, pref_toggle_map[i].widget_name);
		assert(w != NULL);
		visible = preferences_is_column_visible(prefs, pref_toggle_map[i].preference_field);
		if (visible) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), TRUE);
		} else {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), FALSE);
		}
	}
	w = glade_xml_get_widget(xml, "PrefsViewIntervalEntry");
	if (asprintf(&s, "%d", preferences_get_real_time_interval(prefs)) >= 0) {
		gtk_entry_set_text(GTK_ENTRY(w), s);
		free(s);
	} else {
		gtk_entry_set_text(GTK_ENTRY(w), "");
	}
	w = glade_xml_get_widget(xml, "RealTimeCheck");
	if (preferences_get_real_time_at_startup(prefs)) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), TRUE);
	} else {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), FALSE);
	}
}

/**
 * Copy values from dialog widget to the preferences object.
 */
static void preferences_view_get_from_dialog(GladeXML * xml, preferences_t * prefs)
{
	GtkWidget *w;
	const gchar *entry;
	size_t i;

	for (i = 0; i < num_entries; i++) {
		const struct pref_entry *pe = pref_entry_data + i;
		w = glade_xml_get_widget(xml, pe->entry_name);
		entry = gtk_entry_get_text(GTK_ENTRY(w));
		pe->modifier(prefs, entry);
	}
	for (i = 0; i < num_toggles; i++) {
		gboolean active;
		w = glade_xml_get_widget(xml, pref_toggle_map[i].widget_name);
		active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));
		if (active) {
			preferences_set_column_visible(prefs, pref_toggle_map[i].preference_field, 1);
		} else {
			preferences_set_column_visible(prefs, pref_toggle_map[i].preference_field, 0);
		}
	}
	w = glade_xml_get_widget(xml, "PrefsViewIntervalEntry");
	entry = gtk_entry_get_text(GTK_ENTRY(w));
	if (strcmp(entry, "") == 0) {
		entry = "0";
	}
	preferences_set_real_time_interval(prefs, atoi(entry));
	w = glade_xml_get_widget(xml, "RealTimeCheck");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w))) {
		preferences_set_real_time_at_startup(prefs, 1);
	} else {
		preferences_set_real_time_at_startup(prefs, 0);
	}
}

int preferences_view_run(toplevel_t * top)
{
	GladeXML *xml;
	preferences_t *prefs = toplevel_get_prefs(top);
	GtkWidget *dialog, *browse;
	gint response;
	size_t i;

	xml = glade_xml_new(toplevel_get_glade_xml(top), "PreferencesWindow", NULL);
	dialog = glade_xml_get_widget(xml, "PreferencesWindow");
	assert(dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(dialog), toplevel_get_window(top));

	preferences_view_init_dialog(prefs, xml);
	for (i = 0; i < num_entries; i++) {
		struct pref_entry *pe = pref_entry_data + i;
		pe->xml = xml;
		pe->parent = GTK_WINDOW(dialog);
		browse = glade_xml_get_widget(xml, pe->browse_name);
		g_signal_connect(browse, "clicked", G_CALLBACK(preferences_view_on_browse_click), pe);
	}
	response = gtk_dialog_run(GTK_DIALOG(dialog));
	if (response != GTK_RESPONSE_OK) {
		gtk_widget_destroy(dialog);
		return 0;
	}
	preferences_view_get_from_dialog(xml, prefs);
	gtk_widget_destroy(dialog);
	return 1;
}
