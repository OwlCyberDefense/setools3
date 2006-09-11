/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 28, 2004
 */
#include "sediff_treemodel.h"
#include <poldiff/poldiff.h>
#include <stdlib.h>

gboolean widget_event(GtkWidget *widget,GdkEventMotion *event,
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
			gtk_tree_model_get(treemodel, &iter, SEDIFF_HIDDEN_COLUMN,&row,-1);

		}
	}

	return FALSE;
}

int sediff_tree_store_add_row(GtkTreeStore *treestore,const char *str,int *row)
{
	GtkTreeIter   toplevel,child;
	gchar **split_line_array = NULL;
	int i = 0;
	if (treestore == NULL || str == NULL)
		return -1;

	split_line_array = g_strsplit(str,":", 0);   
	gtk_tree_store_append(treestore,&toplevel,NULL);
	gtk_tree_store_set(treestore, &toplevel,
			   SEDIFF_HIDDEN_COLUMN,*row,
			   SEDIFF_LABEL_COLUMN,split_line_array[0],
			   -1);
	*row += 1;

	i = 1;
	while (split_line_array[i] != NULL) {					
		gtk_tree_store_append(treestore,&child,&toplevel);
		gtk_tree_store_set(treestore, &child,
			   SEDIFF_HIDDEN_COLUMN,*row,
			   SEDIFF_LABEL_COLUMN,split_line_array[i],
			   -1);

		*row += 1;
		i++;
	}
	g_strfreev(split_line_array);
	return 0;
}

GtkTreeModel *sediff_create_and_fill_model (poldiff_t *diff)
{
	GtkTreeStore  *treestore;
	int i = 0;
	size_t stats[5] = {0,0,0,0,0};
	GString *string = g_string_new("");

	treestore = gtk_tree_store_new(SEDIFF_NUM_COLUMNS,
				       G_TYPE_STRING,
				       G_TYPE_INT);

	/* Append a top level row and leave it empty */
	sediff_tree_store_add_row(treestore,"Summary",&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_CLASSES, stats);
	g_string_printf(string,"Classes %d:Added %d:Removed %d:Changed %d", 
			stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_COMMONS, stats);
	g_string_printf(string,"Common Permissions %d:Added %d:Removed %d:Changed %d",
			stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_TYPES, stats);
	g_string_printf(string,"Types %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_ATTRIBS, stats);
	g_string_printf(string,"Attributes %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_ROLES, stats);
	g_string_printf(string,"Roles %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_USERS, stats);
	g_string_printf(string,"Users %d:Added %d :Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_BOOLS, stats);
	g_string_printf(string,"Booleans %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_ROLE_ALLOWS, stats);
	g_string_printf(string,"Role Allows %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_ROLE_TRANS, stats);
	g_string_printf(string,"Role Transitions %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_AVRULES, stats);
	g_string_printf(string,"AV Rules %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_TERULES, stats);
	g_string_printf(string,"TE Rules %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	poldiff_get_stats(diff, POLDIFF_DIFF_CONDS, stats);
	g_string_printf(string,"Conditionals %d:Added %d:Removed %d:Changed %d",
                        stats[0]+stats[1]+stats[2], stats[0], stats[1], stats[2]);
	sediff_tree_store_add_row(treestore,string->str,&i);

	g_string_free(string,TRUE);
	return GTK_TREE_MODEL(treestore);
}

int sediff_get_model_option_iter(GtkTreeModel *tree_model,GtkTreeIter *parent,GtkTreeIter *child,int opt)
{
	int option;

	if(gtk_tree_model_get_iter_first(tree_model,parent)) {
		gtk_tree_model_get(tree_model, parent, SEDIFF_HIDDEN_COLUMN,&option,-1);
		while (option != opt && gtk_tree_model_iter_next(tree_model,parent)) {
			if (gtk_tree_model_iter_children(tree_model,child,parent)) {
				gtk_tree_model_get(tree_model, child, SEDIFF_HIDDEN_COLUMN,&option,-1);
				while (option != opt && gtk_tree_model_iter_next(tree_model,child))
					gtk_tree_model_get(tree_model, child, SEDIFF_HIDDEN_COLUMN,&option,-1); 
				if (option == opt) {				       
					return 0;
				}
			}
			gtk_tree_model_get(tree_model, parent, SEDIFF_HIDDEN_COLUMN,&option,-1);
		}
		if (option == opt) {
			child = parent;
			return 0;
				
		}
	}
	return -1;
}

GtkWidget *sediff_create_treeview()
{
	GtkTreeViewColumn   *col;
	GtkCellRenderer     *renderer;
	GtkWidget           *view;

	view = gtk_tree_view_new();
	g_signal_connect_after(G_OBJECT(view), "event", GTK_SIGNAL_FUNC(widget_event), NULL);
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_sizing (col,GTK_TREE_VIEW_COLUMN_GROW_ONLY);
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

int sediff_get_current_treeview_selected_row(GtkTreeView *tree_view)
{
	int row;
	GtkTreeIter iter;
	GtkTreeModel *tree_model;
	GtkTreeSelection *sel;
	GList *glist = NULL, *item = NULL;
	GtkTreePath *path = NULL;

	tree_model = gtk_tree_view_get_model(tree_view);
	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	glist = gtk_tree_selection_get_selected_rows(sel, &tree_model);
	if (glist == NULL) {
		return FALSE;
	}
	/* Only grab the top-most selected item */
	item = glist;
	path = item->data;
	
	/* if we can't get the iterator, then we need to just exit */
	if (!gtk_tree_model_get_iter(tree_model, &iter, path)) {
		if (glist) {	
			g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
			g_list_free(glist);			
		}	
		return FALSE;
	}
	if (glist) {	
		g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
		g_list_free(glist);			
	}

	gtk_tree_model_get(tree_model, &iter, SEDIFF_HIDDEN_COLUMN,&row,-1);
	return row;

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


