/**
 *  @file filter_view.h
 *  Dialog that allows the user to modify a particular filter.
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

#ifndef FILTER_VIEW_H
#define FILTER_VIEW_H

#include "toplevel.h"
#include <seaudit/filter.h>
#include <gtk/gtk.h>

/**
 * Display and run a dialog that allows the user to modify a single
 * filter.
 *
 * @param top Toplevel containing message view.
 * @param view Message view to modify.
 * @param parent Parent window upon which to center this dialog.
 */
void filter_view_run(seaudit_filter_t * filter, toplevel_t * top, GtkWindow * parent);

#endif
