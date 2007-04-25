/**
 *  @file
 *  Dialog that allows the user to select which policy components to
 *  diff.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#ifndef SELECT_DIFF_DIALOG_H
#define SELECT_DIFF_DIALOG_H

#include "toplevel.h"

/**
 * Display and run a dialog that allows the user to select which
 * policy components to diff.
 *
 * @param top Toplevel for the application.
 *
 * @return Bitmap of which components to diff; the bits correspond to
 * those defined in poldiff/poldiff.h
 */
int select_diff_dialog_run(toplevel_t * top);

#endif
