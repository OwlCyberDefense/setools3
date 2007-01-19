/**
 *  @file
 *  Dialog that generates reports from all messages or only those in
 *  the current view.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#ifndef REPORT_WINDOW_H
#define REPORT_WINDOW_H

#include "toplevel.h"
#include "message_view.h"

/**
 * Display and run a dialog that allows the user to generate a report.
 *
 * @param top Toplevel containing preferences and log file for report
 * writer.
 * @param view Current message view.
 */
void report_window_run(toplevel_t * top, message_view_t * view);

#endif
