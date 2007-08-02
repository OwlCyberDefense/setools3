/**
 *  @file
 *  Miscellaneous helper functions for GTK+ applications.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#ifndef UTILGUI_H
#define UTILGUI_H

#include <apol/policy-path.h>
#include <gtk/gtk.h>

/**
 * Pop-up a dialog with a line of text and wait for the user to
 * dismiss the dialog.
 *
 * @param parent Parent window; this message dialog will be centered
 * upon the parent.
 * @param msg_type Type of message being displayed.
 * @param msg Text of message to display.
 */
void util_message(GtkWindow * parent, GtkMessageType msg_type, const char *msg);
/**
 * Set the cursor over a widget to the watch cursor.
 *
 * @param widget Widget whose cursor to set.
 */
void util_cursor_wait(GtkWidget * widget);

/**
 * Clear the cursor over a widget, setting it to the default arrow.
 *
 * @param widget Widget whose cursor to set.
 */
void util_cursor_clear(GtkWidget * widget);

/**
 * Given some arbitrary GtkTextBuffer, remove all of its text and
 * attributes.  This will not delete the buffer's tag table.
 *
 * @param txt Text buffer to clear.
 */
void util_text_buffer_clear(GtkTextBuffer * txt);

/**
 * Allow the user select an existing file.  Run the dialog and return
 * the selected filename.
 *
 * @param parent Parent window; this dialog will be centered upon the
 * parent.
 * @param title Name of the dialog.
 * @param init_path If not NULL, the default filename.
 * @param multiple If true, allow the user to select multiple files.
 * Otherwise only one file at a time may be chosen.
 *
 * @return Name of the file selected, or NULL if no file was selected.
 * The caller must free the returned value with g_free().
 */
apol_vector_t *util_open_file(GtkWindow * parent, const char *title, const char *init_path, gboolean multiple);

/**
 * Allow the user select an existing file or enter a new file for
 * writing.  Run the dialog and return the selected filename.
 *
 * @param parent Parent window; this dialog will be centered upon the
 * parent.
 * @param title Name of the dialog.
 * @param init_path If not NULL, the default filename.
 *
 * @return Name of the file selected, or NULL if no file was selected.
 * The caller must free the returned value with g_free().
 */
char *util_save_file(GtkWindow * parent, const char *title, const char *init_path);

/**
 * Given a policy path, return a newly allocated string that briefly
 * describes the path.  This string is suitable for showing to the
 * user.
 *
 * @param path Policy path to describe.
 *
 * @return String describing the path, or NULL upon error.  The caller
 * must free the string afterwards.
 */
char *util_policy_path_to_string(const apol_policy_path_t * path);

/**
 * Given a policy path, return a newly allocated string that fully
 * describes the path.  This string is suitable for showing to the
 * user.
 *
 * @param path Policy path to describe.
 *
 * @return String describing the path, or NULL upon error.  The caller
 * must free the string afterwards.
 */
char *util_policy_path_to_full_string(const apol_policy_path_t * path);

/**
 * Get the active text from a GtkComboBox.
 *
 * Whereas GTK 2.6 has gtk_combo_box_get_active_text(), GTK 2.4
 * (another supported platform) does not.
 */
const gchar *util_combo_box_get_active_text(GtkComboBox * w);

#endif
