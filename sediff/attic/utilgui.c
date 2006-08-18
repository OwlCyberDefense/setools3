/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: December 31, 2003
 */

#include "utilgui.h"

void message_display(GtkWindow *parent, GtkMessageType msg_type, const char *msg)
{
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(parent,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					msg_type,
					GTK_BUTTONS_CLOSE,
					msg);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}

void get_dialog_response(GtkDialog *dialog, gint id, gpointer response)
{
	*((gint*)response) = id;
	return;
}

void show_wait_cursor(GtkWidget *widget)
{
	GdkCursor *cursor = NULL;

	/* set the cursor to a watch */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(widget->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();
}

/*
 * WARNING: this is sort of a hack
 *
 * If we reset the pointer at the end of a callback, it
 * gets reset too soon (i.e. before all of the pending events have
 * been processed. To avoid this, this function is put in an idle
 * handler by clear_wait_cursor.
 */
static gboolean pointer_reset(gpointer data)
{
	gdk_window_set_cursor(GTK_WIDGET(data)->window, NULL);
	return FALSE;
}

void clear_wait_cursor(GtkWidget *widget)
{
	g_idle_add(&pointer_reset, widget);
}

GString* get_filename_from_user(GtkWindow *parent, const char *title, const gchar *startfilename)
{
	GtkWidget *file_selector;
	gint response;
	GString *filename;

	file_selector = gtk_file_selection_new(title);
	gtk_window_set_transient_for(GTK_WINDOW(file_selector), GTK_WINDOW(parent));
	gtk_window_set_position(GTK_WINDOW(file_selector), GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_file_selection_hide_fileop_buttons (GTK_FILE_SELECTION(file_selector));
	if (startfilename)
		gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_selector), startfilename);

	g_signal_connect(GTK_OBJECT(file_selector), "response", 
			 G_CALLBACK(get_dialog_response), &response);
	while (1) {
		gtk_dialog_run(GTK_DIALOG(file_selector));
		if (response != GTK_RESPONSE_OK) {
			gtk_widget_destroy(file_selector);
			return NULL;
		}
		filename = g_string_new(gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_selector)));
		/* If the filename specified is a directory, then simply list the files in that directory
		 * under the Files list. */
		if (g_file_test(filename->str, G_FILE_TEST_IS_DIR))
			gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), filename->str);
		else 
			break;
	}
	gtk_widget_destroy(file_selector);
	return filename;
}

/* Get response to a yes/no dialog message */
gint get_user_response_to_message(GtkWindow *window, const char *message)
{
	GtkWidget *dialog;
	gint response;

	dialog = gtk_message_dialog_new(window,
					GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_WARNING,
					GTK_BUTTONS_YES_NO,
					message);
	g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(get_dialog_response), &response);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
	return response;
}
