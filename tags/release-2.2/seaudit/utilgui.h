/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: December 31, 2003
 */

#include <gtk/gtk.h>
#include <glade/glade.h>

#ifndef UTILGUI_H
#define UTILGUI_H

void get_dialog_response(GtkDialog *dialog, gint id, gpointer response);
void show_wait_cursor(GtkWidget *widget);
void clear_wait_cursor(GtkWidget *widget);
void message_display(GtkWindow *parent, GtkMessageType msg_type, const char *msg);
GString* get_filename_from_user(const char *title, const gchar *startfilename);
gint get_user_response_to_message(GtkWindow *window, const char *message);

#endif
