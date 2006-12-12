/**
 *  @file policy_components_view.h
 *  Dialog that shows two columns of strings, an included list and an
 *  excluded list.  The user then moves items between the two lists.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#ifndef POLICY_COMPONENTS_VIEW_H
#define POLICY_COMPONENTS_VIEW_H

#include "toplevel.h"
#include <apol/vector.h>
#include <gtk/gtk.h>

/**
 * Display and run a dialog that allows the user to select items from
 * arrays of strings.
 *
 * @param top Toplevel containing message view.
 * @param parent Parent window upon which to center this dialog.
 * @param title Title for the dialog window.
 * @param log_items Vector of strings that the log has.  The function
 * will not modify this vector.
 * @param policy_items Vector of strings that the policy has.  If
 * NULL, then no policy is loaded.  The function will not modify this
 * vector.
 * @param include List of strings to be included.  The strings are
 * assumed to have been strdup()ped from some other source.  This
 * function takes ownership of the vector and its contents.
 *
 * @return A vector newly allocated strings corresponding to the items
 * to be included, or NULL upon error.  The caller must call
 * apol_vector_destroy() upon the return value, passing free as the
 * second parameter.
 */
apol_vector_t *policy_components_view_run(toplevel_t * top, GtkWindow * parent, const char *title,
					  apol_vector_t * log_items, apol_vector_t * policy_items, apol_vector_t * included);

#endif
