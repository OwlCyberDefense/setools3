/**
 *  @file sediff_rename_types.h
 *  Headers for a dialog that allows users to explicitly rename/remap
 *  types.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

#ifndef SEDIFF_RENAME_TYPES_H
#define SEDIFF_RENAME_TYPES_H

#define SEDIFF_RENAME_POLICY_ONE_COLUMN 0
#define SEDIFF_RENAME_POLICY_TWO_COLUMN 1
#define SEDIFF_RENAME_NUM_COLUMNS       2

#include "sediff_gui.h"
#include <poldiff/poldiff.h>
#include <glade/glade.h>
#include <gtk/gtk.h>

typedef struct sediff_rename_types {
	GtkTreeView *view;
	GtkListStore *store;
	GtkCombo *p1_combo;
	GtkCombo *p2_combo;
	GtkWindow *window;
	GladeXML *xml;
	struct sediff_app *sediff_app;
/*
	ap_diff_rename_t *renamed_types;
*/
} sediff_rename_types_t;

sediff_rename_types_t* sediff_rename_types_window_new(struct sediff_app *sediff_app);
void sediff_rename_types_window_display(sediff_rename_types_t *rename_types);
void sediff_rename_types_window_unref_members(sediff_rename_types_t *rename_types);


#endif
