/**
 *  @file
 *  Display a dialog to let the user search through results.
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

#include "find_dialog.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <gdk/gdkkeysyms.h>
#include <glade/glade.h>

struct find_dialog
{
	toplevel_t *top;
	GladeXML *xml;
	/** offset to start searching from if searching up and the
         *  start of the offset to select from */
	gint start_offset;
	/** the offset to start searching from if searching down and
         *  the offset to end selecting from */
	gint end_offset;
	/** the main window */
	GtkDialog *w;
	GtkEntry *entry;
	GtkRadioButton *forward, *reverse;
};

static void find_dialog_search(find_dialog_t * f)
{
	GtkTextView *view = toplevel_get_text_view(f->top);
	GtkTextBuffer *tb = gtk_text_view_get_buffer(view);
	GtkTextMark *mark = gtk_text_buffer_get_insert(tb);
	GtkTextIter iter, start, end;
	const gchar *search_text = gtk_entry_get_text(f->entry);
	gboolean text_found;
	gtk_text_buffer_get_iter_at_mark(tb, &iter, mark);
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(f->forward))) {
		text_found = gtk_text_iter_forward_search(&iter, search_text, GTK_TEXT_SEARCH_VISIBLE_ONLY, &start, &end, NULL);
		if (!text_found) {
			/* wrap search */
			gtk_text_buffer_get_start_iter(tb, &iter);
			text_found =
				gtk_text_iter_forward_search(&iter, search_text, GTK_TEXT_SEARCH_VISIBLE_ONLY, &start, &end, NULL);
		}
	} else {
		text_found = gtk_text_iter_backward_search(&iter, search_text, GTK_TEXT_SEARCH_VISIBLE_ONLY, &start, &end, NULL);
		if (!text_found) {
			/* wrap search */
			gtk_text_buffer_get_end_iter(tb, &iter);
			text_found =
				gtk_text_iter_backward_search(&iter, search_text, GTK_TEXT_SEARCH_VISIBLE_ONLY, &start, &end, NULL);
		}
	}
	if (!text_found) {
		GString *string = g_string_new("");
		g_string_printf(string, "Text \"%s\" not found.", search_text);
		util_message(GTK_WINDOW(f->w), GTK_MESSAGE_INFO, string->str);
		g_string_free(string, TRUE);
	} else {
		gtk_text_view_scroll_to_iter(view, &start, 0.0, FALSE, 0.0, 0.5);
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(f->forward))) {
			gtk_text_buffer_select_range(tb, &end, &start);
		} else {
			gtk_text_buffer_select_range(tb, &start, &end);
		}
	}
}

static void find_dialog_on_response(GtkDialog * dialog __attribute__ ((unused)), gint response, gpointer user_data)
{
	find_dialog_t *f = (find_dialog_t *) user_data;
	if (response == GTK_RESPONSE_CLOSE) {
		gtk_widget_hide(GTK_WIDGET(f->w));
	} else if (response == GTK_RESPONSE_OK) {
		find_dialog_search(f);
	}
}

static gboolean find_dialog_on_key_press_event(GtkWidget * widget __attribute__ ((unused)), GdkEventKey * event, gpointer user_data)
{
	find_dialog_t *f = (find_dialog_t *) user_data;
	if (event->keyval == GDK_Escape) {
		gtk_widget_hide(GTK_WIDGET(f->w));
		return TRUE;
	}
	return FALSE;
}

static void find_dialog_on_entry_activate(GtkEntry * entry __attribute__ ((unused)), gpointer user_data)
{
	find_dialog_t *f = (find_dialog_t *) user_data;
	find_dialog_search(f);
}

find_dialog_t *find_dialog_create(toplevel_t * top)
{
	find_dialog_t *f;
	int error = 0;

	if ((f = calloc(1, sizeof(*f))) == NULL) {
		error = errno;
		goto cleanup;
	}
	f->top = top;
	f->xml = glade_xml_new(toplevel_get_glade_xml(f->top), "find_dialog", NULL);

	f->w = GTK_DIALOG(glade_xml_get_widget(f->xml, "find_dialog"));
	assert(f->w != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(f->w), toplevel_get_window(f->top));
	g_signal_connect_swapped(G_OBJECT(f->w), "delete-event", G_CALLBACK(gtk_widget_hide_on_delete), f->w);
	g_signal_connect(G_OBJECT(f->w), "response", G_CALLBACK(find_dialog_on_response), f);
	g_signal_connect(G_OBJECT(f->w), "key-press-event", G_CALLBACK(find_dialog_on_key_press_event), f);

	f->entry = GTK_ENTRY(glade_xml_get_widget(f->xml, "find entry"));
	f->forward = GTK_RADIO_BUTTON(glade_xml_get_widget(f->xml, "find forward radio"));
	f->reverse = GTK_RADIO_BUTTON(glade_xml_get_widget(f->xml, "find reverse radio"));
	assert(f->entry != NULL && f->forward != NULL && f->reverse != NULL);

	/* connect the text entry callback events */
	g_signal_connect(G_OBJECT(f->entry), "activate", G_CALLBACK(find_dialog_on_entry_activate), f);

      cleanup:
	if (error != 0) {
		find_dialog_destroy(&f);
		errno = error;
		return NULL;
	}
	return f;
}

void find_dialog_destroy(find_dialog_t ** f)
{
	if (f != NULL && *f != NULL) {
		free(*f);
		*f = NULL;
	}
}

void find_dialog_show(find_dialog_t * f)
{
	gtk_widget_show(GTK_WIDGET(f->w));
	gtk_widget_grab_focus(GTK_WIDGET(f->entry));
	gtk_editable_set_position(GTK_EDITABLE(f->entry), -1);
	gtk_editable_select_region(GTK_EDITABLE(f->entry), 0, -1);
	gtk_window_present(GTK_WINDOW(f->w));
}
