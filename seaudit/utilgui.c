/* Copyright (C) 2004 Tresys Technology, LLC
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
