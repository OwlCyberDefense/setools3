/**
 *  @file sediff_remap_types.h
 *  Headers for a dialog that allows users to explicitly remap/remap
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

#ifndef SEDIFF_REMAP_TYPES_H
#define SEDIFF_REMAP_TYPES_H

#define SEDIFF_REMAP_POLICY_ONE_COLUMN 0
#define SEDIFF_REMAP_POLICY_TWO_COLUMN 1
#define SEDIFF_REMAP_NUM_COLUMNS       2

#include "sediff_gui.h"
#include <glade/glade.h>
#include <gtk/gtk.h>
#include <qpol/type_query.h>
#include <apol/policy.h>
#include <apol/type-query.h>
#include <poldiff/poldiff.h>
#include <poldiff/type_map.h>

typedef struct sediff_remapped_types
{
	apol_vector_t *orig;
	apol_vector_t *mod;
} sediff_remapped_types_t;

typedef struct sediff_remap_types
{
	GtkTreeView *view;
	GtkListStore *store;
	GtkCombo *p1_combo;
	GtkCombo *p2_combo;
	GtkWindow *window;
	GladeXML *xml;
	struct sediff_app *sediff_app;
	apol_vector_t *remapped_types;
} sediff_remap_types_t;

sediff_remap_types_t *sediff_remap_types_window_new(struct sediff_app *sediff_app);
void sediff_remap_types_window_display(sediff_remap_types_t * remap_types);
void sediff_remap_types_window_unref_members(sediff_remap_types_t * remap_types);

#endif
