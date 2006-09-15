/**
 *  @file sediff_treemodel.c
 *  Display a tree from which the user can show the results of a
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

#include "sediff_treemodel.h"
#include "sediff_gui.h"
#include <poldiff/poldiff.h>
#include <stdlib.h>

static gboolean widget_event(GtkWidget *widget,GdkEventMotion *event,
			     gpointer user_data)
{
	GtkTreeView *treeview;
	gint x, ex, ey, y;
	GtkTreePath *path = NULL;
	GtkTreeViewColumn *column = NULL;
	treeview = GTK_TREE_VIEW(widget);
	int row;
	GdkEventButton *event_button;
	GtkTreeIter iter;
	GtkTreeModel *treemodel = NULL;

	if (event->type == GDK_BUTTON_PRESS) {
		/* is this a right click event */
		event_button = (GdkEventButton*)event;
		if (event->is_hint) {
			gdk_window_get_pointer(event->window, &ex, &ey, NULL);
		} else {
			ex = event->x;
			ey = event->y;
		}

		gtk_tree_view_get_path_at_pos   (treeview,
						 ex,
						 ey,
						 &path,
						 &column,
						 &x,
						 &y);

		if (path == NULL || column == NULL)
			return FALSE;
		if (event_button->button == 1) {
			treemodel = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
			gtk_tree_model_get_iter(treemodel,&iter,path);
			gtk_tree_model_get(treemodel, &iter, SEDIFF_DIFFBIT_COLUMN, &row, -1);

		}
	}

	return FALSE;
}

struct diff_tree {
	const char *label;
	int bit_pos;
	int has_add_type;
};

extern sediff_item_record_t sediff_items[];

static GtkTreeModel *sediff_create_and_fill_model (poldiff_t *diff)
{
	GtkTreeStore *treestore;
	GtkTreeIter topiter, childiter;
	size_t stats[5] = {0,0,0,0,0}, i;
	GString *s = g_string_new("");

	treestore = gtk_tree_store_new(SEDIFF_NUM_COLUMNS,
				       G_TYPE_STRING,
				       G_TYPE_INT,
				       G_TYPE_INT);

	/* Append a top level row and leave it empty */
	gtk_tree_store_append(treestore, &topiter, NULL);
	gtk_tree_store_set(treestore, &topiter,
			   SEDIFF_LABEL_COLUMN, "Summary",
			   SEDIFF_DIFFBIT_COLUMN, 0,
			   SEDIFF_FORM_COLUMN, POLDIFF_FORM_NONE,
			   -1);

	for (i = 0; sediff_items[i].label != NULL; i++) {
		poldiff_get_stats(diff, sediff_items[i].bit_pos, stats);

		gtk_tree_store_append(treestore, &topiter, NULL);
		g_string_printf(s, "%s %zd", sediff_items[i].label,
				stats[0] + stats[1] + stats[2] + stats[3] + stats[4]);
		gtk_tree_store_set(treestore, &topiter,
				   SEDIFF_LABEL_COLUMN, s->str,
				   SEDIFF_DIFFBIT_COLUMN, sediff_items[i].bit_pos,
				   SEDIFF_FORM_COLUMN, POLDIFF_FORM_NONE,
				   -1);

		gtk_tree_store_append(treestore, &childiter, &topiter);
		g_string_printf(s, "Added %zd", stats[0]);
		gtk_tree_store_set(treestore, &childiter,
				   SEDIFF_LABEL_COLUMN, s->str,
				   SEDIFF_DIFFBIT_COLUMN, sediff_items[i].bit_pos,
				   SEDIFF_FORM_COLUMN, POLDIFF_FORM_ADDED,
				   -1);

		if (sediff_items[i].has_add_type) {
			gtk_tree_store_append(treestore, &childiter, &topiter);
			g_string_printf(s, "Added Type %zd", stats[3]);
			gtk_tree_store_set(treestore, &childiter,
					   SEDIFF_LABEL_COLUMN, s->str,
					   SEDIFF_DIFFBIT_COLUMN, sediff_items[i].bit_pos,
					   SEDIFF_FORM_COLUMN, POLDIFF_FORM_ADD_TYPE,
					   -1);
		}

		gtk_tree_store_append(treestore, &childiter, &topiter);
		g_string_printf(s, "Removed %zd", stats[1]);
		gtk_tree_store_set(treestore, &childiter,
				   SEDIFF_LABEL_COLUMN, s->str,
				   SEDIFF_DIFFBIT_COLUMN, sediff_items[i].bit_pos,
				   SEDIFF_FORM_COLUMN, POLDIFF_FORM_REMOVED,
				   -1);

		if (sediff_items[i].has_add_type) {
			gtk_tree_store_append(treestore, &childiter, &topiter);
			g_string_printf(s, "Removed Type %zd", stats[4]);
			gtk_tree_store_set(treestore, &childiter,
					   SEDIFF_LABEL_COLUMN, s->str,
					   SEDIFF_DIFFBIT_COLUMN, sediff_items[i].bit_pos,
					   SEDIFF_FORM_COLUMN, POLDIFF_FORM_REMOVE_TYPE,
					   -1);
		}
		gtk_tree_store_append(treestore, &childiter, &topiter);
		g_string_printf(s, "Modified %zd", stats[2]);
		gtk_tree_store_set(treestore, &childiter,
				   SEDIFF_LABEL_COLUMN, s->str,
				   SEDIFF_DIFFBIT_COLUMN, sediff_items[i].bit_pos,
				   SEDIFF_FORM_COLUMN, POLDIFF_FORM_MODIFIED,
				   -1);
	}

	g_string_free(s,TRUE);
	return GTK_TREE_MODEL(treestore);
}

static GtkWidget *sediff_create_treeview()
{
	GtkTreeViewColumn   *col;
	GtkCellRenderer     *renderer;
	GtkWidget           *view;

	view = gtk_tree_view_new();
	g_signal_connect_after(G_OBJECT(view), "event", GTK_SIGNAL_FUNC(widget_event), NULL);
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_sizing (col, GTK_TREE_VIEW_COLUMN_GROW_ONLY);
	gtk_tree_view_column_set_title(col, "Differences");
	/* pack tree view column into tree view */
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	renderer = gtk_cell_renderer_text_new();
	/* pack cell renderer into tree view column */
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	/* connect 'text' property of the cell renderer to
	 *  model column that contains the first name */
	gtk_tree_view_column_add_attribute(col, renderer, "text", SEDIFF_LABEL_COLUMN);
	return view;
}

int sediff_get_current_treeview_selected_row(GtkTreeView *tree_view,
					     uint32_t *diffbit,
					     poldiff_form_e *form)
{
	GtkTreeIter iter;
	GtkTreeModel *tree_model;
	GtkTreeSelection *sel;

	tree_model = gtk_tree_view_get_model(tree_view);
	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	if (gtk_tree_selection_get_selected(sel, &tree_model, &iter)) {
		gtk_tree_model_get(tree_model, &iter,
				   SEDIFF_DIFFBIT_COLUMN, diffbit,
				   SEDIFF_FORM_COLUMN, form,
				   -1);
		return 1;
	}
	else {
		return 0;
	}
}

GtkWidget *sediff_create_view_and_model (poldiff_t *diff)
{
	GtkWidget           *view;
	GtkTreeModel        *model;

	model = sediff_create_and_fill_model(diff);
	view = sediff_create_treeview();
	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	return view;
}
