/**
 *  @file
 *  Headers for displaying a find dialog.
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

#ifndef FIND_DIALOG_H
#define FIND_DIALOG_H

typedef struct find_dialog find_dialog_t;

#include "toplevel.h"

/**
 * Create a find dialog object.  The dialog will float above the rest
 * of sediffx; it allows the user to search for text either forwards
 * or backwards in the currently visible text buffer.
 *
 * @param top Toplevel object that will control the newly opened find
 * dialog.
 *
 * @return An initialized find dialog object, or NULL upon error.  The
 * caller must call find_dialog_destroy() upon the returned value.
 */
find_dialog_t *find_dialog_create(toplevel_t * top);

/**
 * Destroy the find_dialog object.  This does nothing if the pointer
 * is set to NULL.
 *
 * @param f Reference to a find dialog object.  Afterwards the
 * pointer will be set to NULL.
 */
void find_dialog_destroy(find_dialog_t ** f);

/**
 * (Re)show the find dialog.
 *
 * @param f Find dialog to show.
 */
void find_dialog_show(find_dialog_t * f);

#endif
