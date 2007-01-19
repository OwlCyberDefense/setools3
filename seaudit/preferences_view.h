/**
 *  @file
 *  Declaration of preferences editor.
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

#ifndef PREFERENCES_VIEW_H
#define PREFERENCES_VIEW_H

#include "toplevel.h"
#include <gtk/gtk.h>

/**
 * Display a dialog from which the user may edit his preferences.
 *
 * @param top Toplevel object containing preferences to modify
 * @param current_log Path to the currently loaded log file, or NULL
 * if none loaded.
 * @param current_policy Path to the currently loaded policy, or NULL
 * if none loaded.
 *
 * @return Non-zero if preferences changed, zero if not.
 */
int preferences_view_run(toplevel_t * top, const char *current_log, const apol_policy_path_t * current_policy);

#endif
