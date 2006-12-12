/**
 *  @file message_view.h
 *  Declaration of a single tab within the main notebook, showing
 *  all messages within a libseaudit model.
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

#ifndef MESSAGE_VIEW_H
#define MESSAGE_VIEW_H

#include "toplevel.h"

#include <gtk/gtk.h>
#include <seaudit/model.h>

typedef struct message_view message_view_t;

/**
 * Allocate a new view for a particular model.
 *
 * @param top Handle to the controlling toplevel widget.
 * @param model libseaudit model to display.  The view takes ownership
 * of the model afterwards.
 * @param filename Initial filename for the view, or NULL if none.
 * This function will duplicate the string.
 *
 * @return A newly allocated view, or NULL upon error.  The caller is
 * responsible for calling message_view_destroy() afterwards.
 */
message_view_t *message_view_create(toplevel_t * top, seaudit_model_t * model, const char *filename);

/**
 * Destroy a view and free its memory.  This does nothing if the
 * pointer is set to NULL.
 *
 * @param view Reference to a toplevel object.  Afterwards the pointer
 * will be set to NULL.
 */
void message_view_destroy(message_view_t ** view);

/**
 * Get the message view's model.  If the caller changes the model then
 * he is responsible for calling message_view_update_rows() to update
 * the view.
 *
 * @param view View whose model to obtain.
 *
 * @return View's model.
 */
seaudit_model_t *message_view_get_model(message_view_t * view);

/**
 * Replace a message view's model with a different model.  The
 * previous model will be destroyed.  Afterwards the view will update
 * its rows.
 *
 * @param view View to modify.
 * @param libseaudit model to display.  The view takes ownership
 * of the model afterwards.
 */
void message_view_set_model(message_view_t * view, seaudit_model_t * model);

/**
 * Get the message view's widget display.  This widget will be placed
 * in a container for the user to see.
 *
 * @param view View whose widget to obtain.
 *
 * @return View's widget.
 */
GtkWidget *message_view_get_view(message_view_t * view);

/**
 * Return the number of messages currently in this view.
 *
 * @param view View object to query.
 *
 * @return Number of log messages, or 0 if no model is associated with
 * the view.
 */
size_t message_view_get_num_log_messages(message_view_t * view);

/**
 * Return TRUE if the message view has one or more messages selected,
 * FALSE if not.
 *
 * @param view View object to query.
 *
 * @return TRUE if any messages are selected.
 */
gboolean message_view_is_message_selected(message_view_t * view);

/**
 * Save the current view to disk.
 *
 * @param view View to save.
 */
void message_view_save(message_view_t * view);

/**
 * Save the current view to disk under a new filename.
 *
 * @param view View to save.
 */
void message_view_saveas(message_view_t * view);

/**
 * Modify the settings for this view.
 *
 * @param view View to modify.
 */
void message_view_modify(message_view_t * view);

/**
 * Export to file all messages in a particular view.
 *
 * @param view View whose messages to export.
 */
void message_view_export_all_messages(message_view_t * view);

/**
 * Export to file all messages selected in a particular view.
 *
 * @param view View whose messages to export.
 */
void message_view_export_selected_messages(message_view_t * view);

/**
 * Open a dialog that shows an approximation of the message(s)
 * currently selected.
 *
 * @param view View whose messages to show.
 */
void message_view_entire_message(message_view_t * view);

/**
 * Show/hide columns in a view based upon the user's current
 * preferences.
 *
 * @param view View's columns to update.
 */
void message_view_update_visible_columns(message_view_t * view);

/**
 * (Re)synchronize the messages displayed in a view with its
 * underlying model.  This needs to be called when a model's filter
 * changes or if new messages are found within the model's log.
 *
 * @param view View's rows to update.
 */
void message_view_update_rows(message_view_t * view);

#endif
