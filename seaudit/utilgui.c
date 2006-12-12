/**
 *  @file
 *  Miscellaneous helper functions for GTK+ applications.
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

#include "utilgui.h"

void util_message(GtkWindow * parent, GtkMessageType msg_type, const char *msg)
{
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(parent, GTK_DIALOG_DESTROY_WITH_PARENT, msg_type, GTK_BUTTONS_CLOSE, msg);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

void util_cursor_wait(GtkWidget * widget)
{
	GdkCursor *cursor;
	if (widget->window != NULL) {
		cursor = gdk_cursor_new(GDK_WATCH);
		gdk_window_set_cursor(widget->window, cursor);
		gdk_cursor_unref(cursor);
	}
}

/**
 * WARNING: this is sort of a hack
 *
 * If we reset the pointer at the end of a callback, it gets reset too
 * soon (i.e. before all of the pending events have been processed. To
 * avoid this, this function is put in an idle handler by
 * clear_wait_cursor.
 */
static gboolean pointer_reset(gpointer data)
{
	gdk_window_set_cursor(GTK_WIDGET(data)->window, NULL);
	return FALSE;
}

void util_cursor_clear(GtkWidget * widget)
{
	g_idle_add(&pointer_reset, widget);
}

char *util_open_file(GtkWindow * parent, const char *title, const char *init_path)
{
	GtkWidget *dialog = gtk_file_chooser_dialog_new(title, parent, GTK_FILE_CHOOSER_ACTION_OPEN, GTK_STOCK_CANCEL,
							GTK_RESPONSE_CANCEL,
							GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT, NULL);
	char *path = NULL;
	if (init_path != NULL) {
		gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(dialog), init_path);
	}
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
	}
	gtk_widget_destroy(dialog);
	return path;
}

char *util_save_file(GtkWindow * parent, const char *title, const char *init_path)
{
	GtkWidget *dialog = gtk_file_chooser_dialog_new(title, parent, GTK_FILE_CHOOSER_ACTION_SAVE, GTK_STOCK_CANCEL,
							GTK_RESPONSE_CANCEL,
							GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT, NULL);
	char *path = NULL;
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
	if (init_path != NULL) {
		gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(dialog), init_path);
	} else {
		gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "Untitled");
	}
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
	}
	gtk_widget_destroy(dialog);
	return path;
}
