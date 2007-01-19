/**
 *  @file
 *  Declaration of the main toplevel window for seaudit.
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

#ifndef TOPLEVEL_H
#define TOPLEVEL_H

typedef struct toplevel toplevel_t;

#include "progress.h"
#include "seaudit.h"
#include <apol/policy-path.h>
#include <gtk/gtk.h>
#include <seaudit/message.h>

/**
 * Allocate and return an instance of the toplevel window object.
 * This will create the window, set up the menus and icons, create an
 * empty notebook, then display the window.
 *
 * @param s Main seaudit object that will control the toplevel.
 *
 * @return An initialized toplevel object, or NULL upon error.  The
 * caller must call toplevel_destroy() afterwards.
 */
toplevel_t *toplevel_create(seaudit_t * s);

/**
 * Destroy the toplevel window.  This function will recursively
 * destroy all other windows.  This does nothing if the pointer is set
 * to NULL.
 *
 * @param top Reference to a toplevel object.  Afterwards the pointer
 * will be set to NULL.
 */
void toplevel_destroy(toplevel_t ** top);

/**
 * Open a log file, destroying any existing logs and views first.
 * Afterwards, create a new view for the log.
 *
 * @param top Toplevel object, used for UI control.
 * @param filename Name of the log to open.
 */
void toplevel_open_log(toplevel_t * top, const char *filename);

/**
 * Open a policy file, destroying any existing policies upon success.
 *
 * @param top Toplevel object, used for UI control.
 * @param path Path to the policy to open.  This function takes
 * ownership of this object.
 *
 * @return 0 on successful open, < 0 on error.
 */
int toplevel_open_policy(toplevel_t * top, apol_policy_path_t * path);

/**
 * Update the status bar to show the current policy, number of log
 * messages in the current view, range of messages in current view,
 * and monitor status.
 *
 * @param top Toplevel whose status bar to update.
 */
void toplevel_update_status_bar(toplevel_t * top);

/**
 * Update the menu items whenever a message is selected/deselected.
 * Certain commands are legal only when one or more messages are
 * selected.
 *
 * @param top Toplevel whose menu to update.
 */
void toplevel_update_selection_menu_item(toplevel_t * top);

/**
 * Update the tab names for all views.
 *
 * @param top Toplevel whose notebook tabs to update.
 */
void toplevel_update_tabs(toplevel_t * top);

/**
 * Return the current preferences object for the toplevel object.
 *
 * @param top Toplevel containing preferences.
 *
 * @return Pointer to a preferences object.  Do not free() this pointer.
 */
preferences_t *toplevel_get_prefs(toplevel_t * top);

/**
 * Return a seaudit_log_t object used for error reporting by
 * libseaudit.
 *
 * @param top Toplevel containing seaudit log object.
 *
 * @return libseaudit reporting object, or NULL if no log exists yet.
 * Treat this as a const pointer.
 */
seaudit_log_t *toplevel_get_log(toplevel_t * top);

/**
 * Return a vector of strings corresponding to all users found within
 * the current log file.  The vector will be sorted alphabetically.
 *
 * @param top Toplevel containing seaudit log object.
 *
 * @return Vector of sorted users, or NULL if no log is loaded.  The
 * caller must call apol_vector_destroy() upon the return value,
 * passing NULL as the second parameter.
 */
apol_vector_t *toplevel_get_log_users(toplevel_t * top);

/**
 * Return a vector of strings corresponding to all roles found within
 * the current log file.  The vector will be sorted alphabetically.
 *
 * @param top Toplevel containing seaudit log object.
 *
 * @return Vector of sorted roles, or NULL if no log is loaded.  The
 * caller must call apol_vector_destroy() upon the return value,
 * passing NULL as the second parameter.
 */
apol_vector_t *toplevel_get_log_roles(toplevel_t * top);

/**
 * Return a vector of strings corresponding to all types found within
 * the current log file.  The vector will be sorted alphabetically.
 *
 * @param top Toplevel containing seaudit log object.
 *
 * @return Vector of sorted types, or NULL if no log is loaded.  The
 * caller must call apol_vector_destroy() upon the return value,
 * passing NULL as the second parameter.
 */
apol_vector_t *toplevel_get_log_types(toplevel_t * top);

/**
 * Return a vector of strings corresponding to all object classes
 * found within the current log file.  The vector will be sorted
 * alphabetically.
 *
 * @param top Toplevel containing seaudit log object.
 *
 * @return Vector of sorted classes, or NULL if no log is loaded.  The
 * caller must call apol_vector_destroy() upon the return value,
 * passing NULL as the second parameter.
 */
apol_vector_t *toplevel_get_log_classes(toplevel_t * top);

/**
 * Return the currently loaded policy.
 *
 * @param top Toplevel containing policy.
 *
 * @return Current policy, or NULL if no policy is loaded yet.  Treat
 * this as a const pointer.
 */
apol_policy_t *toplevel_get_policy(toplevel_t * top);

/**
 * Return the filename containing seaudit's glade file.
 *
 * @param top Toplevel containing glade XML declarations.
 *
 * @return Name of the glade file.  Do not modify this string.
 */
char *toplevel_get_glade_xml(toplevel_t * top);

/**
 * Return the progress object, so that sub-windows may also show the
 * threaded progress object.
 *
 * @param top Toplevel containing progress object.
 *
 * @return Progress object.  Do not free() this pointer.
 */
progress_t *toplevel_get_progress(toplevel_t * top);

/**
 * Return the main application window.  Sub-windows should be set
 * transient to this window.
 *
 * @param top Toplevel containing main window.
 *
 * @return Main window.
 */
GtkWindow *toplevel_get_window(toplevel_t * top);

/**
 * (Re)open a dialog that allows the user to search for TE rules in
 * the currently opened policy.  If message is not NULL then set the
 * query's initial parameters to the message's source type, target
 * type, and object class.
 *
 * @param top Toplevel containing policy.
 * @param message If non-NULL, the initial parameters for query.
 */
void toplevel_find_terules(toplevel_t * top, seaudit_message_t * message);

/**
 * Pop-up an error dialog with a line of text and wait for the user to
 * dismiss the dialog.
 *
 * @param top Toplevel window; this message dialog will be centered
 * upon it.
 * @param format Format string to print, using syntax of printf(3).
 */
void toplevel_ERR(toplevel_t * top, const char *format, ...) __attribute__ ((format(printf, 2, 3)));

/**
 * Pop-up a warning dialog with a line of text and wait for the user
 * to dismiss the dialog.
 *
 * @param top Toplevel window; this message dialog will be centered
 * upon it.
 * @param format Format string to print, using syntax of printf(3).
 */
void toplevel_WARN(toplevel_t * top, const char *format, ...) __attribute__ ((format(printf, 2, 3)));

#endif
