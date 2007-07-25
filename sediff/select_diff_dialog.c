/**
 *  @file
 *  Run the dialog to allow the user to select components.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#include "select_diff_dialog.h"

#include <assert.h>
#include <glade/glade.h>

struct component
{
	const char *name;
	const uint32_t bit;
};

static const struct component comps[] = {
	{"attribs checkbutton", POLDIFF_DIFF_ATTRIBS},
	{"allow checkbutton", POLDIFF_DIFF_AVALLOW},
	{"auditallow checkbutton", POLDIFF_DIFF_AVAUDITALLOW},
	{"dontaudit checkbutton", POLDIFF_DIFF_AVDONTAUDIT},
	{"neverallow checkbutton", POLDIFF_DIFF_AVNEVERALLOW},
	{"bools checkbutton", POLDIFF_DIFF_BOOLS},
	{"cats checkbutton", POLDIFF_DIFF_CATS},
	{"classes checkbutton", POLDIFF_DIFF_CLASSES},
	{"commons checkbutton", POLDIFF_DIFF_COMMONS},
	{"levels checkbutton", POLDIFF_DIFF_LEVELS},
	{"rangetrans checkbutton", POLDIFF_DIFF_RANGE_TRANS},
	{"roles checkbutton", POLDIFF_DIFF_ROLES},
	{"roleallows checkbutton", POLDIFF_DIFF_ROLE_ALLOWS},
	{"roletrans checkbutton", POLDIFF_DIFF_ROLE_TRANS},
	{"users checkbutton", POLDIFF_DIFF_USERS},
	{"type_change checkbutton", POLDIFF_DIFF_TECHANGE},
	{"type_member checkbutton", POLDIFF_DIFF_TEMEMBER},
	{"type_transition checkbutton", POLDIFF_DIFF_TETRANS},
	{"types checkbutton", POLDIFF_DIFF_TYPES},
	{NULL, 0}
};

static uint32_t prev_selection = POLDIFF_DIFF_ALL & ~POLDIFF_DIFF_AVNEVERALLOW;

static void select_diff_on_select_all_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	GladeXML *xml = (GladeXML *) user_data;
	size_t i;
	const struct component *c;
	for (i = 0; comps[i].name != NULL; i++) {
		c = comps + i;
		GtkToggleButton *cb = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, c->name));
		gtk_toggle_button_set_active(cb, TRUE);
	}
}

static void select_diff_on_select_none_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	GladeXML *xml = (GladeXML *) user_data;
	size_t i;
	const struct component *c;
	for (i = 0; comps[i].name != NULL; i++) {
		c = comps + i;
		GtkToggleButton *cb = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, c->name));
		gtk_toggle_button_set_active(cb, FALSE);
	}
}

int select_diff_dialog_run(toplevel_t * top)
{
	GladeXML *xml = glade_xml_new(toplevel_get_glade_xml(top), "select_components", NULL);
	GtkDialog *dialog = GTK_DIALOG(glade_xml_get_widget(xml, "select_components"));
	assert(dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(dialog), toplevel_get_window(top));

	size_t i;
	const struct component *c;
	for (i = 0; comps[i].name != NULL; i++) {
		c = comps + i;
		GtkToggleButton *cb = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, c->name));
		assert(cb != NULL);
		gtk_toggle_button_set_active(cb, c->bit & prev_selection ? TRUE : FALSE);
	}

	GtkButton *b = GTK_BUTTON(glade_xml_get_widget(xml, "select all button"));
	assert(b != NULL);
	g_signal_connect(b, "clicked", G_CALLBACK(select_diff_on_select_all_click), xml);
	b = GTK_BUTTON(glade_xml_get_widget(xml, "select none button"));
	assert(b != NULL);
	g_signal_connect(b, "clicked", G_CALLBACK(select_diff_on_select_none_click), xml);

	uint32_t result = 0;
	while (result == 0) {
		result = 0;
		if (gtk_dialog_run(dialog) != GTK_RESPONSE_OK) {
			gtk_widget_destroy(GTK_WIDGET(dialog));
			return 0;
		}

		for (i = 0; comps[i].name != NULL; i++) {
			c = comps + i;
			GtkToggleButton *cb = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, c->name));
			if (gtk_toggle_button_get_active(cb)) {
				result |= c->bit;
			}
		}

		if (result == 0) {
			toplevel_ERR(top, "%s", "At least one component must be selected.");
		}
	}

	gtk_widget_destroy(GTK_WIDGET(dialog));
	prev_selection = result;
	return result;
}
