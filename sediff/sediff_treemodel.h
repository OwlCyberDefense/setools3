/**
 *  @file sediff_treemodel.h
 *  Header for a tree from which the user can show the results of a
 *  particular diff.
 *
 *  @author Don Patterson don.patterson@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2004-2006 Tresys Technology, LLC
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
#ifndef SEDIFF_TREE_MODEL_H
#define SEDIFF_TREE_MODEL_H

#include <gtk/gtk.h>
#include <poldiff/poldiff.h>

/* defines for the sediff tree options */

#define POLDIFF_DIFF_SUMMARY  0

/* The data columns that we export via the tree model interface */
enum
{
  SEDIFF_LABEL_COLUMN = 0,
  SEDIFF_DIFFBIT_COLUMN,
  SEDIFF_FORM_COLUMN,
  SEDIFF_NUM_COLUMNS
};

GtkWidget *sediff_create_view_and_model(poldiff_t *diff);

/**
 * Return the currently selected row for the tree view.  Write to
 * diffbit the bit representing this particular policy item.  Write to
 * form the form being checked.
 *
 * @param tree_view View of the differences.
 * @param diffbit Reference to which bit is selected, or 0 to indicate
 * the diff summary.
 * @param form Reference to the form of the difference, or 0 if the
 * item's summary was selected.
 *
 * @return 1 if something is selected, 0 or not (and diffbit and form
 * remain unchanged).
 */
int sediff_get_current_treeview_selected_row(GtkTreeView *tree_view,
					     uint32_t *diffbit,
					     poldiff_form_e *form);
#endif
