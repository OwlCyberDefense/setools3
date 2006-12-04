/**
 *  @file
 *  Header for miscellaneous GTK utility functions.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *
 *  Copyright (C) 2004-2006 Tresys Technology, LLC
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

#include <gtk/gtk.h>
#include <glade/glade.h>

#ifndef UTILGUI_H
#define UTILGUI_H

#ifdef	__cplusplus
extern "C"
{
#endif

	void get_dialog_response(GtkDialog * dialog, gint id, gpointer response);
	void show_wait_cursor(GtkWidget * widget);
	void clear_wait_cursor(GtkWidget * widget);
	void message_display(GtkWindow * parent, GtkMessageType msg_type, const char *msg);
	GString *get_filename_from_user(GtkWindow * parent, const char *title, const gchar * startfilename);
	gint get_user_response_to_message(GtkWindow * window, const char *message);

#ifdef	__cplusplus
}
#endif

#endif
