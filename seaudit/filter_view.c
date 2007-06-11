/**
 *  @file
 *  Run the dialog to modify a particular filter.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#include "filter_view.h"
#include "policy_components_view.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <apol/policy-query.h>
#include <apol/util.h>
#include <glade/glade.h>

struct context_item
{
	GtkButton *button;
	GtkEntry *entry;
	apol_vector_t *items;
};

struct date_item
{
	GtkComboBox *month;
	GtkSpinButton *day, *hour, *minute, *second;
	GtkFrame *frame;
};

struct filter_view
{
	toplevel_t *top;
	seaudit_filter_t *filter;
	GladeXML *xml;

	GtkDialog *dialog;

	GtkEntry *name_entry;
	GtkComboBox *match_combo;

	struct context_item suser, srole, stype, tuser, trole, ttype, obj_class;
	GtkButton *context_clear_button;

	GtkEntry *ipaddr_entry, *port_entry, *netif_entry, *exe_entry, *path_entry, *host_entry, *comm_entry;
	GtkComboBox *message_combo;
	GtkButton *other_clear_button;

	GtkRadioButton *date_none_radio, *date_before_radio, *date_after_radio, *date_between_radio;
	struct date_item dates[2];
	GtkTextBuffer *description_buffer;
};

/**
 * Initialize pointers to widgets on the context tab.
 */
static void filter_view_init_widgets_context(struct filter_view *fv)
{
	fv->suser.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewSUserButton"));
	fv->srole.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewSRoleButton"));
	fv->stype.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewSTypeButton"));
	fv->tuser.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewTUserButton"));
	fv->trole.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewTRoleButton"));
	fv->ttype.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewTTypeButton"));
	fv->obj_class.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewClassButton"));
	assert(fv->suser.button != NULL && fv->srole.button != NULL && fv->stype.button != NULL &&
	       fv->tuser.button != NULL && fv->trole.button != NULL && fv->ttype.button != NULL && fv->obj_class.button != NULL);

	fv->suser.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewSUserEntry"));
	fv->srole.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewSRoleEntry"));
	fv->stype.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewSTypeEntry"));
	fv->tuser.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewTUserEntry"));
	fv->trole.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewTRoleEntry"));
	fv->ttype.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewTTypeEntry"));
	fv->obj_class.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewClassEntry"));
	assert(fv->suser.entry != NULL && fv->srole.entry != NULL && fv->stype.entry != NULL &&
	       fv->tuser.entry != NULL && fv->trole.entry != NULL && fv->ttype.entry != NULL && fv->obj_class.entry != NULL);
	g_object_set_data(G_OBJECT(fv->suser.entry), "data", &fv->suser);
	g_object_set_data(G_OBJECT(fv->srole.entry), "data", &fv->srole);
	g_object_set_data(G_OBJECT(fv->stype.entry), "data", &fv->stype);
	g_object_set_data(G_OBJECT(fv->tuser.entry), "data", &fv->tuser);
	g_object_set_data(G_OBJECT(fv->trole.entry), "data", &fv->trole);
	g_object_set_data(G_OBJECT(fv->ttype.entry), "data", &fv->ttype);
	g_object_set_data(G_OBJECT(fv->obj_class.entry), "data", &fv->obj_class);

	fv->context_clear_button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewContextClearButton"));
	assert(fv->context_clear_button != NULL);
}

/**
 * Initialize pointers to widgets on the other tab.
 */
static void filter_view_init_widgets_other(struct filter_view *fv)
{
	fv->ipaddr_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewIPAddrEntry"));
	fv->port_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewPortEntry"));
	fv->netif_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewNetIfEntry"));
	assert(fv->ipaddr_entry != NULL && fv->port_entry != NULL && fv->netif_entry != NULL);

	fv->exe_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewExeEntry"));
	fv->path_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewPathEntry"));
	fv->host_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewHostEntry"));
	fv->comm_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewCommEntry"));
	assert(fv->exe_entry != NULL && fv->path_entry != NULL && fv->host_entry != NULL && fv->comm_entry != NULL);

	fv->message_combo = GTK_COMBO_BOX(glade_xml_get_widget(fv->xml, "FilterViewMessageCombo"));
	assert(fv->message_combo != NULL);

	fv->other_clear_button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewOtherClearButton"));
	assert(fv->other_clear_button != NULL);
}

/**
 * Initialize pointers to widgets on the date tab.
 */
static void filter_view_init_widgets_date(struct filter_view *fv)
{
	static const char *widgets[2][6] = {
		{"FilterViewDateStartFrame", "FilterViewDateStartMonthCombo", "FilterViewDateStartDaySpin",
		 "FilterViewDateStartHourSpin", "FilterViewDateStartMinuteSpin", "FilterViewDateStartSecondSpin"},
		{"FilterViewDateEndFrame", "FilterViewDateEndMonthCombo", "FilterViewDateEndDaySpin",
		 "FilterViewDateEndHourSpin", "FilterViewDateEndMinuteSpin", "FilterViewDateEndSecondSpin"}
	};
	size_t i;
	fv->date_none_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewDateNoneRadio"));
	fv->date_before_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewDateBeforeRadio"));
	fv->date_after_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewDateAfterRadio"));
	fv->date_between_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewDateBetweenRadio"));
	assert(fv->date_none_radio != NULL && fv->date_before_radio != NULL && fv->date_after_radio != NULL
	       && fv->date_between_radio != NULL);

	for (i = 0; i < 2; i++) {
		fv->dates[i].frame = GTK_FRAME(glade_xml_get_widget(fv->xml, widgets[i][0]));
		fv->dates[i].month = GTK_COMBO_BOX(glade_xml_get_widget(fv->xml, widgets[i][1]));
		fv->dates[i].day = GTK_SPIN_BUTTON(glade_xml_get_widget(fv->xml, widgets[i][2]));
		fv->dates[i].hour = GTK_SPIN_BUTTON(glade_xml_get_widget(fv->xml, widgets[i][3]));
		fv->dates[i].minute = GTK_SPIN_BUTTON(glade_xml_get_widget(fv->xml, widgets[i][4]));
		fv->dates[i].second = GTK_SPIN_BUTTON(glade_xml_get_widget(fv->xml, widgets[i][5]));
		assert(fv->dates[i].frame != NULL && fv->dates[i].month != NULL && fv->dates[i].day != NULL &&
		       fv->dates[i].hour != NULL && fv->dates[i].minute != NULL && fv->dates[i].second != NULL);
	}
}

static void filter_view_init_widgets(struct filter_view *fv, GtkWindow * parent)
{
	GtkTextView *description_view;

	fv->dialog = GTK_DIALOG(glade_xml_get_widget(fv->xml, "FilterWindow"));
	assert(fv->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(fv->dialog), parent);

	fv->name_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewNameEntry"));
	fv->match_combo = GTK_COMBO_BOX(glade_xml_get_widget(fv->xml, "FilterViewMatchCombo"));
	assert(fv->name_entry != NULL && fv->match_combo);

	filter_view_init_widgets_context(fv);
	filter_view_init_widgets_other(fv);
	filter_view_init_widgets_date(fv);

	fv->description_buffer = gtk_text_buffer_new(NULL);
	g_object_ref_sink(fv->description_buffer);
	description_view = GTK_TEXT_VIEW(glade_xml_get_widget(fv->xml, "FilterViewDescView"));
	assert(description_view != NULL);
	gtk_text_view_set_buffer(description_view, fv->description_buffer);
}

/********** functions that copies filter object values to widget **********/

/**
 * Get the vector of strings from the accessor function.  If the
 * vector is NULL then clear the entry's contents; otherwies set the
 * entry to the vector of strings, comma delimited.
 */
static void filter_view_context_item_to_entry(struct filter_view *fv, struct context_item *item)
{
	if (item->items == NULL) {
		gtk_entry_set_text(item->entry, "");
	} else {
		GString *s = g_string_new("");
		size_t i;
		for (i = 0; i < apol_vector_get_size(item->items); i++) {
			char *t = apol_vector_get_element(item->items, i);
			if (i > 0) {
				g_string_append(s, ", ");
			}
			g_string_append(s, t);
		}
		gtk_entry_set_text(item->entry, s->str);
		g_string_free(s, TRUE);
	}
}

static void filter_view_context_items_to_entries(struct filter_view *fv)
{
	filter_view_context_item_to_entry(fv, &fv->suser);
	filter_view_context_item_to_entry(fv, &fv->srole);
	filter_view_context_item_to_entry(fv, &fv->stype);
	filter_view_context_item_to_entry(fv, &fv->tuser);
	filter_view_context_item_to_entry(fv, &fv->trole);
	filter_view_context_item_to_entry(fv, &fv->ttype);
	filter_view_context_item_to_entry(fv, &fv->obj_class);
}

static void filter_view_init_context(struct filter_view *fv)
{
	apol_vector_t *v;
	v = seaudit_filter_get_source_user(fv->filter);
	if (v != NULL && (fv->suser.items = apol_vector_create_from_vector(v, apol_str_strdup, NULL, free)) == NULL) {
		toplevel_ERR(fv->top, "Error initializing context tab: %s", strerror(errno));
		return;
	}
	v = seaudit_filter_get_source_role(fv->filter);
	if (v != NULL && (fv->srole.items = apol_vector_create_from_vector(v, apol_str_strdup, NULL, free)) == NULL) {
		toplevel_ERR(fv->top, "Error initializing context tab: %s", strerror(errno));
		return;
	}
	v = seaudit_filter_get_source_type(fv->filter);
	if (v != NULL && (fv->stype.items = apol_vector_create_from_vector(v, apol_str_strdup, NULL, free)) == NULL) {
		toplevel_ERR(fv->top, "Error initializing context tab: %s", strerror(errno));
		return;
	}
	v = seaudit_filter_get_target_user(fv->filter);
	if (v != NULL && (fv->tuser.items = apol_vector_create_from_vector(v, apol_str_strdup, NULL, free)) == NULL) {
		toplevel_ERR(fv->top, "Error initializing context tab: %s", strerror(errno));
		return;
	}
	v = seaudit_filter_get_target_role(fv->filter);
	if (v != NULL && (fv->trole.items = apol_vector_create_from_vector(v, apol_str_strdup, NULL, free)) == NULL) {
		toplevel_ERR(fv->top, "Error initializing context tab: %s", strerror(errno));
		return;
	}
	v = seaudit_filter_get_target_type(fv->filter);
	if (v != NULL && (fv->ttype.items = apol_vector_create_from_vector(v, apol_str_strdup, NULL, free)) == NULL) {
		toplevel_ERR(fv->top, "Error initializing context tab: %s", strerror(errno));
		return;
	}
	v = seaudit_filter_get_target_class(fv->filter);
	if (v != NULL && (fv->obj_class.items = apol_vector_create_from_vector(v, apol_str_strdup, NULL, free)) == NULL) {
		toplevel_ERR(fv->top, "Error initializing context tab: %s", strerror(errno));
		return;
	}
	filter_view_context_items_to_entries(fv);
}

/**
 * Get the string from the accessor function.  If the returned string
 * is NULL then clear the entry's contents; otherwise set the entry to
 * the returned string.
 */
static void filter_view_init_entry(struct filter_view *fv, char *(*accessor) (seaudit_filter_t *), GtkEntry * entry)
{
	char *s = accessor(fv->filter);
	if (s == NULL) {
		s = "";
	}
	gtk_entry_set_text(entry, s);
}

static void filter_view_init_other(struct filter_view *fv)
{
	char s[32];
	filter_view_init_entry(fv, seaudit_filter_get_ipaddress, fv->ipaddr_entry);
	if (seaudit_filter_get_port(fv->filter) <= 0) {
		s[0] = '\0';
	} else {
		snprintf(s, 32, "%d", seaudit_filter_get_port(fv->filter));
	}
	gtk_entry_set_text(fv->port_entry, s);
	filter_view_init_entry(fv, seaudit_filter_get_netif, fv->netif_entry);
	filter_view_init_entry(fv, seaudit_filter_get_executable, fv->exe_entry);
	filter_view_init_entry(fv, seaudit_filter_get_path, fv->path_entry);
	filter_view_init_entry(fv, seaudit_filter_get_host, fv->host_entry);
	filter_view_init_entry(fv, seaudit_filter_get_command, fv->comm_entry);
	switch (seaudit_filter_get_message_type(fv->filter)) {
	case SEAUDIT_AVC_DENIED:
		gtk_combo_box_set_active(fv->message_combo, 1);
		break;
	case SEAUDIT_AVC_GRANTED:
		gtk_combo_box_set_active(fv->message_combo, 2);
		break;
	default:
		gtk_combo_box_set_active(fv->message_combo, 0);
	}
}

static void filter_view_init_date(struct filter_view *fv)
{
	struct tm *start, *end, values[2];
	int has_value[2] = { 0, 0 };
	seaudit_filter_date_match_e match;
	size_t i;

	seaudit_filter_get_date(fv->filter, &start, &end, &match);
	if (start == NULL && end == NULL) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fv->date_none_radio), TRUE);
	} else {
		if (match == SEAUDIT_FILTER_DATE_MATCH_BEFORE) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fv->date_before_radio), TRUE);
		} else if (match == SEAUDIT_FILTER_DATE_MATCH_AFTER) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fv->date_after_radio), TRUE);
		}
		memcpy(values + 0, start, sizeof(values[0]));
		has_value[0] = 1;
	}
	if (match == SEAUDIT_FILTER_DATE_MATCH_BETWEEN) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fv->date_between_radio), TRUE);
		memcpy(values + 1, end, sizeof(values[1]));
		has_value[1] = 1;
	}
	for (i = 0; i < 2; i++) {
		if (has_value[i]) {
			gtk_combo_box_set_active(fv->dates[i].month, values[i].tm_mon);
			gtk_spin_button_set_value(fv->dates[i].day, values[i].tm_mday);
			gtk_spin_button_set_value(fv->dates[i].hour, values[i].tm_hour);
			gtk_spin_button_set_value(fv->dates[i].minute, values[i].tm_min);
			gtk_spin_button_set_value(fv->dates[i].second, values[i].tm_sec);
		} else {
			gtk_combo_box_set_active(fv->dates[i].month, 0);
		}
	}
}

/**
 * Copy values from seaudit filter object to GTK+ widgets.
 */
static void filter_view_init_dialog(struct filter_view *fv)
{
	char *name = seaudit_filter_get_name(fv->filter);
	char *desc = seaudit_filter_get_description(fv->filter);;
	if (name == NULL) {
		name = "Untitled";
	}
	gtk_entry_set_text(fv->name_entry, name);
	gtk_combo_box_set_active(fv->match_combo, seaudit_filter_get_match(fv->filter));

	filter_view_init_context(fv);
	filter_view_init_other(fv);
	filter_view_init_date(fv);

	if (desc == NULL) {
		desc = "";
	}
	gtk_text_buffer_set_text(fv->description_buffer, desc, -1);
}

/********** functions that copies widget values to filter object **********/

static void filter_view_apply_context(struct filter_view *fv)
{
	if (seaudit_filter_set_source_user(fv->filter, fv->suser.items) < 0 ||
	    seaudit_filter_set_source_role(fv->filter, fv->srole.items) < 0 ||
	    seaudit_filter_set_source_type(fv->filter, fv->stype.items) < 0 ||
	    seaudit_filter_set_target_user(fv->filter, fv->tuser.items) < 0 ||
	    seaudit_filter_set_target_role(fv->filter, fv->trole.items) < 0 ||
	    seaudit_filter_set_target_type(fv->filter, fv->ttype.items) < 0 ||
	    seaudit_filter_set_target_class(fv->filter, fv->obj_class.items) < 0) {
		toplevel_ERR(fv->top, "Error applying context: %s", strerror(errno));
	}
}

/**
 * If the entry is empty, then call the modifier function passing NULL
 * as the second parameter.  Else call the function with the entry's
 * contents.
 */
static void filter_view_apply_entry(struct filter_view *fv, GtkEntry * entry, int (*modifier) (seaudit_filter_t *, const char *))
{
	const char *s = gtk_entry_get_text(entry);
	if (strcmp(s, "") == 0) {
		s = NULL;
	}
	if (modifier(fv->filter, s) < 0) {
		toplevel_ERR(fv->top, "Error apply settings: %s", strerror(errno));
	}
}

/**
 * Copy values from the other tab to filter object.
 */
static void filter_view_apply_other(struct filter_view *fv)
{
	const char *s;
	int port = 0;
	seaudit_avc_message_type_e message_type;

	filter_view_apply_entry(fv, fv->ipaddr_entry, seaudit_filter_set_ipaddress);
	s = gtk_entry_get_text(fv->port_entry);
	if (strcmp(s, "") != 0) {
		port = atoi(s);
	}
	if (seaudit_filter_set_port(fv->filter, port) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
		return;
	}
	filter_view_apply_entry(fv, fv->netif_entry, seaudit_filter_set_netif);
	filter_view_apply_entry(fv, fv->exe_entry, seaudit_filter_set_executable);
	filter_view_apply_entry(fv, fv->path_entry, seaudit_filter_set_path);
	filter_view_apply_entry(fv, fv->host_entry, seaudit_filter_set_host);
	filter_view_apply_entry(fv, fv->comm_entry, seaudit_filter_set_command);
	switch (gtk_combo_box_get_active(fv->message_combo)) {
	case 1:
		message_type = SEAUDIT_AVC_DENIED;
		break;
	case 2:
		message_type = SEAUDIT_AVC_GRANTED;
		break;
	default:
		message_type = SEAUDIT_AVC_UNKNOWN;
	}
	if (seaudit_filter_set_message_type(fv->filter, message_type) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
		return;
	}
}

/**
 * Returns which date radio button is active:
 *
 *   -1 if date_none_radio,
 *   else something that can be casted to seaudit_filter_date_match
 */
static int filter_view_get_date_match(struct filter_view *fv)
{
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(fv->date_before_radio))) {
		return SEAUDIT_FILTER_DATE_MATCH_BEFORE;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(fv->date_after_radio))) {
		return SEAUDIT_FILTER_DATE_MATCH_AFTER;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(fv->date_between_radio))) {
		return SEAUDIT_FILTER_DATE_MATCH_BETWEEN;
	}
	return -1;
}

/**
 * Copy values from date tab to the seaudit filter object.
 */
static void filter_view_apply_date(struct filter_view *fv)
{
	struct tm tm[2];
	size_t i;
	int date_match = filter_view_get_date_match(fv);
	memset(&tm, 0, sizeof(tm));
	for (i = 0; i < 2; i++) {
		tm[i].tm_mon = gtk_combo_box_get_active(fv->dates[i].month);
		tm[i].tm_mday = gtk_spin_button_get_value_as_int(fv->dates[i].day);
		tm[i].tm_year = 0;
		tm[i].tm_hour = gtk_spin_button_get_value_as_int(fv->dates[i].hour);
		tm[i].tm_min = gtk_spin_button_get_value_as_int(fv->dates[i].minute);
		tm[i].tm_sec = gtk_spin_button_get_value_as_int(fv->dates[i].second);
	}
	if (date_match < 0) {
		seaudit_filter_set_date(fv->filter, NULL, NULL, 0);
	} else {
		seaudit_filter_set_date(fv->filter, tm + 0, tm + 1, (seaudit_filter_date_match_e) date_match);
	}
}

/**
 * Copy values from GTK+ widgets to the seaudit filter object.
 */
static void filter_view_apply(struct filter_view *fv)
{
	GtkTextIter start, end;
	char *s;
	seaudit_filter_match_e match = SEAUDIT_FILTER_MATCH_ALL;

	filter_view_apply_entry(fv, fv->name_entry, seaudit_filter_set_name);
	if (gtk_combo_box_get_active(fv->match_combo) == 1) {
		match = SEAUDIT_FILTER_MATCH_ANY;
	}
	if (seaudit_filter_set_match(fv->filter, match) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
	}

	filter_view_apply_context(fv);
	filter_view_apply_other(fv);
	filter_view_apply_date(fv);

	gtk_text_buffer_get_bounds(fv->description_buffer, &start, &end);
	s = gtk_text_buffer_get_text(fv->description_buffer, &start, &end, FALSE);
	if (strcmp(s, "") == 0) {
		free(s);
		s = NULL;
	}
	if (seaudit_filter_set_description(fv->filter, s) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
	}
	free(s);
}

/******************** signal handlers for dialog ********************/

/**
 * Return a list of users within the currently loaded policy, sorted
 * alphabetically.  If there is no policy loaded then return NULL.
 */
static apol_vector_t *filter_view_get_policy_users(struct filter_view *fv)
{
	apol_vector_t *policy_items = NULL, *v = NULL;
	apol_policy_t *p = toplevel_get_policy(fv->top);
	size_t i;
	if (p == NULL) {
		return NULL;
	}
	if (apol_user_get_by_query(p, NULL, &v) < 0 || (policy_items = apol_vector_create(NULL)) == NULL) {
		toplevel_ERR(fv->top, "Error getting a list of policy users: %s", strerror(errno));
		apol_vector_destroy(&policy_items);
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const qpol_user_t *e = apol_vector_get_element(v, i);
		const char *name;
		qpol_user_get_name(apol_policy_get_qpol(p), e, &name);
		if (apol_vector_append(policy_items, (void *)name) < 0) {
			toplevel_ERR(fv->top, "Error getting a list of policy users: %s", strerror(errno));
			apol_vector_destroy(&v);
			apol_vector_destroy(&policy_items);
		}
	}
	apol_vector_destroy(&v);
	apol_vector_sort(policy_items, apol_str_strcmp, NULL);
	return policy_items;
}

/**
 * Return a list of roles within the currently loaded policy, sorted
 * alphabetically.  If there is no policy loaded then return NULL.
 */
static apol_vector_t *filter_view_get_policy_roles(struct filter_view *fv)
{
	apol_vector_t *policy_items = NULL, *v = NULL;
	apol_policy_t *p = toplevel_get_policy(fv->top);
	size_t i;
	if (p == NULL) {
		return NULL;
	}
	if (apol_role_get_by_query(p, NULL, &v) < 0 || (policy_items = apol_vector_create(NULL)) == NULL) {
		toplevel_ERR(fv->top, "Error getting a list of policy roles: %s", strerror(errno));
		apol_vector_destroy(&policy_items);
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const qpol_role_t *e = apol_vector_get_element(v, i);
		const char *name;
		qpol_role_get_name(apol_policy_get_qpol(p), e, &name);
		if (apol_vector_append(policy_items, (void *)name) < 0) {
			toplevel_ERR(fv->top, "Error getting a list of policy roles: %s", strerror(errno));
			apol_vector_destroy(&v);
			apol_vector_destroy(&policy_items);
		}
	}
	apol_vector_destroy(&v);
	apol_vector_sort(policy_items, apol_str_strcmp, NULL);
	return policy_items;
}

/**
 * Return a list of types (not attributes nor aliases) within the
 * currently loaded policy, sorted alphabetically.  If there is no
 * policy loaded then return NULL.
 */
static apol_vector_t *filter_view_get_policy_types(struct filter_view *fv)
{
	apol_vector_t *policy_items = NULL, *v = NULL;
	apol_policy_t *p = toplevel_get_policy(fv->top);
	size_t i;
	if (p == NULL) {
		return NULL;
	}
	if (apol_type_get_by_query(p, NULL, &v) < 0 || (policy_items = apol_vector_create(NULL)) == NULL) {
		toplevel_ERR(fv->top, "Error getting a list of policy types: %s", strerror(errno));
		apol_vector_destroy(&policy_items);
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const qpol_type_t *e = apol_vector_get_element(v, i);
		const char *name;
		qpol_type_get_name(apol_policy_get_qpol(p), e, &name);
		if (apol_vector_append(policy_items, (void *)name) < 0) {
			toplevel_ERR(fv->top, "Error getting a list of policy types: %s", strerror(errno));
			apol_vector_destroy(&v);
			apol_vector_destroy(&policy_items);
		}
	}
	apol_vector_destroy(&v);
	apol_vector_sort(policy_items, apol_str_strcmp, NULL);
	return policy_items;
}

/**
 * Return a list of object classeswithin the currently loaded policy,
 * sorted alphabetically.  If there is no policy loaded then return
 * NULL.
 */
static apol_vector_t *filter_view_get_policy_classes(struct filter_view *fv)
{
	apol_vector_t *policy_items = NULL, *v = NULL;
	apol_policy_t *p = toplevel_get_policy(fv->top);
	size_t i;
	if (p == NULL) {
		return NULL;
	}
	if (apol_class_get_by_query(p, NULL, &v) < 0 || (policy_items = apol_vector_create(NULL)) == NULL) {
		toplevel_ERR(fv->top, "Error getting a list of policy classes: %s", strerror(errno));
		apol_vector_destroy(&policy_items);
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const qpol_class_t *e = apol_vector_get_element(v, i);
		const char *name;
		qpol_class_get_name(apol_policy_get_qpol(p), e, &name);
		if (apol_vector_append(policy_items, (void *)name) < 0) {
			toplevel_ERR(fv->top, "Error getting a list of policy classes: %s", strerror(errno));
			apol_vector_destroy(&v);
			apol_vector_destroy(&policy_items);
		}
	}
	apol_vector_destroy(&v);
	apol_vector_sort(policy_items, apol_str_strcmp, NULL);
	return policy_items;
}

static void filter_view_on_suser_context_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	apol_vector_t *log_items = toplevel_get_log_users(fv->top);
	apol_vector_t *policy_items = filter_view_get_policy_users(fv);
	fv->suser.items =
		policy_components_view_run(fv->top, GTK_WINDOW(fv->dialog), "Source User Items", log_items, policy_items,
					   fv->suser.items);
	apol_vector_destroy(&log_items);
	apol_vector_destroy(&policy_items);
	filter_view_context_item_to_entry(fv, &fv->suser);
}

static void filter_view_on_srole_context_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	apol_vector_t *log_items = toplevel_get_log_roles(fv->top);
	apol_vector_t *policy_items = filter_view_get_policy_roles(fv);
	fv->srole.items =
		policy_components_view_run(fv->top, GTK_WINDOW(fv->dialog), "Source Role Items", log_items, policy_items,
					   fv->srole.items);
	apol_vector_destroy(&log_items);
	apol_vector_destroy(&policy_items);
	filter_view_context_item_to_entry(fv, &fv->srole);
}

static void filter_view_on_stype_context_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	apol_vector_t *log_items = toplevel_get_log_types(fv->top);
	apol_vector_t *policy_items = filter_view_get_policy_types(fv);
	fv->stype.items =
		policy_components_view_run(fv->top, GTK_WINDOW(fv->dialog), "Source Type Items", log_items, policy_items,
					   fv->stype.items);
	apol_vector_destroy(&log_items);
	apol_vector_destroy(&policy_items);
	filter_view_context_item_to_entry(fv, &fv->stype);
}

static void filter_view_on_tuser_context_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	apol_vector_t *log_items = toplevel_get_log_users(fv->top);
	apol_vector_t *policy_items = filter_view_get_policy_users(fv);
	fv->tuser.items =
		policy_components_view_run(fv->top, GTK_WINDOW(fv->dialog), "Target User Items", log_items, policy_items,
					   fv->tuser.items);
	apol_vector_destroy(&log_items);
	apol_vector_destroy(&policy_items);
	filter_view_context_item_to_entry(fv, &fv->tuser);
}

static void filter_view_on_trole_context_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	apol_vector_t *log_items = toplevel_get_log_roles(fv->top);
	apol_vector_t *policy_items = filter_view_get_policy_roles(fv);
	fv->trole.items =
		policy_components_view_run(fv->top, GTK_WINDOW(fv->dialog), "Target Role Items", log_items, policy_items,
					   fv->trole.items);
	apol_vector_destroy(&log_items);
	apol_vector_destroy(&policy_items);
	filter_view_context_item_to_entry(fv, &fv->trole);
}

static void filter_view_on_ttype_context_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	apol_vector_t *log_items = toplevel_get_log_types(fv->top);
	apol_vector_t *policy_items = filter_view_get_policy_types(fv);
	fv->ttype.items =
		policy_components_view_run(fv->top, GTK_WINDOW(fv->dialog), "Target Type Items", log_items, policy_items,
					   fv->ttype.items);
	apol_vector_destroy(&log_items);
	apol_vector_destroy(&policy_items);
	filter_view_context_item_to_entry(fv, &fv->ttype);
}

static void filter_view_on_class_context_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	apol_vector_t *log_items = toplevel_get_log_classes(fv->top);
	apol_vector_t *policy_items = filter_view_get_policy_classes(fv);
	fv->obj_class.items =
		policy_components_view_run(fv->top, GTK_WINDOW(fv->dialog), "Object Class Items", log_items, policy_items,
					   fv->obj_class.items);
	apol_vector_destroy(&log_items);
	apol_vector_destroy(&policy_items);
	filter_view_context_item_to_entry(fv, &fv->obj_class);
}

/**
 * Whenever the user finished manually editing a context entry,
 * convert the entry's string into the underlying vector.
 */
static gboolean filter_view_on_entry_focus_out(GtkWidget * widget, GdkEventFocus * event
					       __attribute__ ((unused)), gpointer user_data)
{
	struct context_item *item = g_object_get_data(G_OBJECT(widget), "data");
	struct filter_view *fv = (struct filter_view *)user_data;
	gchar **strs = g_strsplit(gtk_entry_get_text(GTK_ENTRY(widget)), ",", -1);
	gchar *s;
	size_t i = 0;
	char *t;
	apol_vector_t *new_v = NULL;
	while (1) {
		s = strs[i++];
		if (s == NULL) {
			break;
		}
		if (new_v == NULL && (new_v = apol_vector_create(free)) == NULL) {
			toplevel_ERR(fv->top, "Could not interpret entry contents: %s", strerror(errno));
			break;
		}
		if ((t = strdup(s)) == NULL) {
			toplevel_ERR(fv->top, "Could not interpret entry contents: %s", strerror(errno));
			free(t);
			break;
		}
		apol_str_trim(t);
		if (apol_vector_append(new_v, t) < 0) {
			toplevel_ERR(fv->top, "Could not interpret entry contents: %s", strerror(errno));
			free(t);
			break;
		}
	}
	g_strfreev(strs);
	apol_vector_destroy(&item->items);
	item->items = new_v;
	filter_view_context_item_to_entry(fv, item);
	return FALSE;
}

static void filter_view_destroy_context_vectors(struct filter_view *fv)
{
	apol_vector_destroy(&fv->suser.items);
	apol_vector_destroy(&fv->srole.items);
	apol_vector_destroy(&fv->stype.items);
	apol_vector_destroy(&fv->tuser.items);
	apol_vector_destroy(&fv->trole.items);
	apol_vector_destroy(&fv->ttype.items);
	apol_vector_destroy(&fv->obj_class.items);
}

static void filter_view_on_context_clear_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	filter_view_destroy_context_vectors(fv);
	filter_view_context_items_to_entries(fv);
}

static void filter_view_init_context_signals(struct filter_view *fv)
{
	g_signal_connect(fv->suser.button, "clicked", G_CALLBACK(filter_view_on_suser_context_click), fv);
	g_signal_connect(fv->suser.entry, "focus_out_event", G_CALLBACK(filter_view_on_entry_focus_out), fv);
	g_signal_connect(fv->srole.button, "clicked", G_CALLBACK(filter_view_on_srole_context_click), fv);
	g_signal_connect(fv->srole.entry, "focus_out_event", G_CALLBACK(filter_view_on_entry_focus_out), fv);
	g_signal_connect(fv->stype.button, "clicked", G_CALLBACK(filter_view_on_stype_context_click), fv);
	g_signal_connect(fv->stype.entry, "focus_out_event", G_CALLBACK(filter_view_on_entry_focus_out), fv);
	g_signal_connect(fv->tuser.button, "clicked", G_CALLBACK(filter_view_on_tuser_context_click), fv);
	g_signal_connect(fv->tuser.entry, "focus_out_event", G_CALLBACK(filter_view_on_entry_focus_out), fv);
	g_signal_connect(fv->trole.button, "clicked", G_CALLBACK(filter_view_on_trole_context_click), fv);
	g_signal_connect(fv->trole.entry, "focus_out_event", G_CALLBACK(filter_view_on_entry_focus_out), fv);
	g_signal_connect(fv->ttype.button, "clicked", G_CALLBACK(filter_view_on_ttype_context_click), fv);
	g_signal_connect(fv->ttype.entry, "focus_out_event", G_CALLBACK(filter_view_on_entry_focus_out), fv);
	g_signal_connect(fv->obj_class.button, "clicked", G_CALLBACK(filter_view_on_class_context_click), fv);
	g_signal_connect(fv->obj_class.entry, "focus_out_event", G_CALLBACK(filter_view_on_entry_focus_out), fv);
	g_signal_connect(fv->context_clear_button, "clicked", G_CALLBACK(filter_view_on_context_clear_click), fv);
}

static void filter_view_on_other_clear_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	gtk_entry_set_text(fv->ipaddr_entry, "");
	gtk_entry_set_text(fv->port_entry, "");
	gtk_entry_set_text(fv->netif_entry, "");
	gtk_entry_set_text(fv->exe_entry, "");
	gtk_entry_set_text(fv->path_entry, "");
	gtk_entry_set_text(fv->host_entry, "");
	gtk_entry_set_text(fv->comm_entry, "");
	gtk_combo_box_set_active(fv->message_combo, 0);
}

static void filter_view_on_date_toggle(GtkToggleButton * widget, gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	int match;
	/* clicking on the radio buttons emit two toggle signals, one for
	 * the original button and one for the new one.  thus only need to
	 * handle half of all signals */
	if (!gtk_toggle_button_get_active(widget)) {
		return;
	}
	match = filter_view_get_date_match(fv);
	gtk_widget_set_sensitive(GTK_WIDGET(fv->dates[0].frame), (match != -1));
	gtk_widget_set_sensitive(GTK_WIDGET(fv->dates[1].frame), (match == SEAUDIT_FILTER_DATE_MATCH_BETWEEN));
}

/* Given the year and the month set the spin button to have the
   correct number of days for that month */
static void filter_view_date_set_number_days(int month, GtkSpinButton * button)
{
	static const int days[] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int cur_day;
	/* get the current day because set_range moves the current day
	 * by the difference minus 1 day.  e.g., going from jan 20 to
	 * february the day would automatically become 18 */
	cur_day = gtk_spin_button_get_value_as_int(button);
	gtk_spin_button_set_range(button, 1, days[month]);
	/* return to current day, or to the max value allowed in range */
	gtk_spin_button_set_value(button, cur_day);
}

static void filter_view_on_month0_change(GtkComboBox * widget, gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	filter_view_date_set_number_days(gtk_combo_box_get_active(widget), fv->dates[0].day);
}

static void filter_view_on_month1_change(GtkComboBox * widget, gpointer user_data)
{
	struct filter_view *fv = (struct filter_view *)user_data;
	filter_view_date_set_number_days(gtk_combo_box_get_active(widget), fv->dates[1].day);
}

static void filter_view_init_signals(struct filter_view *fv)
{
	filter_view_init_context_signals(fv);
	g_signal_connect(fv->other_clear_button, "clicked", G_CALLBACK(filter_view_on_other_clear_click), fv);
	g_signal_connect(fv->date_none_radio, "toggled", G_CALLBACK(filter_view_on_date_toggle), fv);
	g_signal_connect(fv->date_before_radio, "toggled", G_CALLBACK(filter_view_on_date_toggle), fv);
	g_signal_connect(fv->date_after_radio, "toggled", G_CALLBACK(filter_view_on_date_toggle), fv);
	g_signal_connect(fv->date_between_radio, "toggled", G_CALLBACK(filter_view_on_date_toggle), fv);
	g_signal_connect(fv->dates[0].month, "changed", G_CALLBACK(filter_view_on_month0_change), fv);
	g_signal_connect(fv->dates[1].month, "changed", G_CALLBACK(filter_view_on_month1_change), fv);
}

/******************** public function below ********************/

void filter_view_run(seaudit_filter_t * filter, toplevel_t * top, GtkWindow * parent)
{
	struct filter_view fv;
	gint response;

	memset(&fv, 0, sizeof(fv));
	fv.top = top;
	fv.filter = filter;
	fv.xml = glade_xml_new(toplevel_get_glade_xml(top), "FilterWindow", NULL);
	filter_view_init_widgets(&fv, parent);
	filter_view_init_signals(&fv);
	filter_view_init_dialog(&fv);
	do {
		response = gtk_dialog_run(fv.dialog);
	} while (response != GTK_RESPONSE_CLOSE);

	filter_view_apply(&fv);
	g_object_unref(fv.description_buffer);
	gtk_widget_destroy(GTK_WIDGET(fv.dialog));
	filter_view_destroy_context_vectors(&fv);
}
