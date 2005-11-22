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

GString* get_filename_from_user(const char *title, const gchar *startfilename, GtkWindow *window, gboolean overwrite)
{
	GtkWidget *file_selector = NULL;
	gint response;
	GString *filename = NULL;
	GString *overwrite_warning = NULL;

	file_selector = gtk_file_selection_new(title);
	if (window)
		/* set this window to be transient window, so that when it pops up it gets centered on it */
		gtk_window_set_transient_for(GTK_WINDOW(file_selector), window);
	
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
		else if (overwrite && g_file_test(filename->str, G_FILE_TEST_EXISTS)) {
			overwrite_warning = g_string_new("");
			g_string_printf(overwrite_warning, "Overwrite File:\n%s?", filename->str);
			response = get_user_response_to_message(GTK_WINDOW(gtk_widget_get_toplevel(file_selector)), overwrite_warning->str);	
			g_string_free(overwrite_warning, 1);
			if (response == GTK_RESPONSE_YES)
				break;				
		} else
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
