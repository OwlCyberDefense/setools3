/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information 
 *
 * Author: Don Patterson <don.patterson@tresys.com>
 */

#include "seaudit.h"
#include "customize_filter_window.h"
#include "filter_window.h"
#include <string.h>
#include <libapol/render.h>
#include <stdlib.h>

extern seaudit_t *seaudit_app;
GtkWidget *window = NULL;
enum filter_items_t curr_filter;
bool_t changed = FALSE;

static gint get_insert_position(GtkTreeModel *model, gchar *insert_str)
{
	GtkTreeIter iter;
	gchar *str_data = NULL;
	gint row_count = 0;
	gboolean valid;

	valid = gtk_tree_model_get_iter_first(model, &iter);
	while(valid) {
		gtk_tree_model_get(model, &iter, ITEM_COLUMN, &str_data, -1);
		if(strcmp((const char*)insert_str, (const char*)str_data) < 0) 
			break;
		valid = gtk_tree_model_iter_next (model, &iter);
		row_count++;
	}
	return row_count;
}

static void apply_list_changes(GladeXML *xml)
{
	GtkTreeView *include_tree;
	GtkTreeModel *incl_model;
	GtkTreeIter iter;
	GList *incl_items = NULL;
	gboolean valid;
	gchar *str_data = NULL;
	
	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "IncludeTreeView"));
	g_assert(include_tree);
	/* Get the model and the create a GList */
	incl_model = gtk_tree_view_get_model(include_tree);
	valid = gtk_tree_model_get_iter_first(incl_model, &iter);
	while(valid) {
		gtk_tree_model_get(incl_model, &iter, ITEM_COLUMN, &str_data, -1);
		incl_items = g_list_append(incl_items, str_data);
		valid = gtk_tree_model_iter_next (incl_model, &iter);
	}
	
	/* Update the stored included items with the intermediate included items list */
	if(curr_filter == SRC_TYPES_FILTER)
		src_type_list_set(incl_items);
	else if(curr_filter == TGT_TYPES_FILTER) 
	  	tgt_type_list_set(incl_items);
	else if(curr_filter == OBJECTS_FILTER)
	  	obj_class_list_set(incl_items);
	else {
		g_assert(window);
		message_display(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Wrong filter parameter specified.\n");
	}
	g_list_free(incl_items);
}

void on_ok_button_clicked(GtkButton *button, GladeXML *xml)
{
	if (changed)
		apply_list_changes(xml);
	gtk_widget_destroy(window);
	gtk_widget_destroyed(window, &window);
}

void on_apply_button_clicked(GtkButton *button, GladeXML *xml)
{
	if (changed) {
		apply_list_changes(xml);
		/* Disable the apply button */
		gtk_widget_set_sensitive(glade_xml_get_widget(xml, "ApplyButton"), 0);
		changed = FALSE;
	}
}

void on_cancel_button_clicked(GtkButton *button, GladeXML *xml)
{
	gtk_widget_destroy(window);
	gtk_widget_destroyed(window, &window);
}

void on_add_button_clicked(GtkButton *button, GladeXML *xml)
{
	GtkTreeView *include_tree, *exclude_tree;
        GtkTreeModel *incl_model, *excl_model;
        GtkTreeIter iter;
	GList *sel_rows = NULL;
	GtkTreePath *path;
	gchar *item_str = NULL;
	gint position;
	                           
	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "IncludeTreeView"));
	g_assert(include_tree);
	exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "ExcludeTreeView"));
	g_assert(exclude_tree);
	
	/* Get the model and the selection from the tree view */
	incl_model = gtk_tree_view_get_model(include_tree);
	excl_model = gtk_tree_view_get_model(exclude_tree);
	sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(exclude_tree), &excl_model);
	
	if(sel_rows == NULL) 
		return;
		
	/* Now that we have the selection and the model, we want to remove this from the model and add the the excluded list store. */
	while(sel_rows != NULL) {
		path = g_list_nth_data(sel_rows, 0);
		assert(path != NULL);
		if(gtk_tree_model_get_iter(excl_model, &iter, path) == 0) {
			g_assert(window);
			message_display(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Could not get valid iterator for the selected path.\n");
			return;	
		}
		gtk_tree_model_get(excl_model, &iter, ITEM_COLUMN, &item_str, -1);
		gtk_list_store_remove(GTK_LIST_STORE(excl_model), &iter);
		
		position = get_insert_position(incl_model, item_str);
		/* now insert it into the included list */
		gtk_list_store_insert(GTK_LIST_STORE(incl_model), &iter, position);
		gtk_list_store_set(GTK_LIST_STORE(incl_model), &iter, ITEM_COLUMN, item_str, -1);
		g_free(item_str);
		
		/* Free the list of selected tree paths; we have to get the list of selected items again */
		/* since the list has changed */
		g_list_foreach(sel_rows, (GFunc) gtk_tree_path_free, NULL);
		g_list_free (sel_rows);
		sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(exclude_tree), &excl_model);
	}
		
	/* Enable the apply button since there are changes */
	gtk_widget_set_sensitive(glade_xml_get_widget(xml, "ApplyButton"), 1);
	changed = TRUE;
}

void on_remove_button_clicked(GtkButton *button, GladeXML *xml)
{
	GtkTreeView *include_tree, *exclude_tree;
        GtkTreeModel *incl_model, *excl_model;
        GtkTreeIter iter;
	GList *sel_rows = NULL;
	GtkTreePath *path = NULL;
	gchar *item_str = NULL;
	gint position;
	                                           
	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "IncludeTreeView"));
	g_assert(include_tree);
	exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "ExcludeTreeView"));
	g_assert(exclude_tree);
	
	/* Get the model and the selection from the tree view */
	incl_model = gtk_tree_view_get_model(include_tree);
	excl_model = gtk_tree_view_get_model(exclude_tree);
	sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(include_tree), &incl_model);
	
	if(sel_rows == NULL) 
		return;
		
	/* Now that we have the selection and the model, we want to remove this from the model and add the the excluded list store. */
	while(sel_rows != NULL) {
		path = g_list_nth_data(sel_rows, 0);
		assert(path != NULL);
		if(gtk_tree_model_get_iter(incl_model, &iter, path) == 0) {
			g_assert(window);
			message_display(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Could not get valid iterator for the selected path.\n");
			return;	
		}
		gtk_tree_model_get(incl_model, &iter, ITEM_COLUMN, &item_str, -1);
		gtk_list_store_remove(GTK_LIST_STORE(incl_model), &iter);

		position = get_insert_position(excl_model, item_str);
		/* now insert it into the excluded list */
		gtk_list_store_insert(GTK_LIST_STORE(excl_model), &iter, position);
		gtk_list_store_set(GTK_LIST_STORE(excl_model), &iter, ITEM_COLUMN, item_str, -1);
		g_free(item_str);
		
		/* Free the list of selected tree paths; we have to get the list of selected items again */
		/* since the list has changed */
		g_list_foreach(sel_rows, (GFunc) gtk_tree_path_free, NULL);
		g_list_free (sel_rows);
		sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(include_tree), &incl_model);
	}	
	
	/* Enable the apply button since there are changes */
	gtk_widget_set_sensitive(glade_xml_get_widget(xml, "ApplyButton"), 1);
	changed = TRUE;
}

static int populate_list_models(GtkTreeView *include_tree, GtkTreeView *exclude_tree, enum filter_items_t which_filter)
{
	int i, found = 0; 
	GtkTreeModel *incl_model, *excl_model;
	GtkTreeIter iter;
	gint position;
	GList *incl_items = NULL;
	guint j;
	
	/* Get the model and the selection from the tree view */
	incl_model = gtk_tree_view_get_model(include_tree);
	excl_model = gtk_tree_view_get_model(exclude_tree);
	
	if (which_filter == SRC_TYPES_FILTER || which_filter == TGT_TYPES_FILTER) {
		if(which_filter == SRC_TYPES_FILTER) 
			incl_items = src_type_list_get();
		else 
			incl_items = tgt_type_list_get();

		/* Default case - all types excluded */
		if(incl_items == NULL) {
			for (i = 0; i < seaudit_app->cur_policy->num_types; i++) {
				/* Add to excluded types list store */
				position = get_insert_position(excl_model, seaudit_app->cur_policy->types[i].name);
				gtk_list_store_insert(GTK_LIST_STORE(excl_model), &iter, position);
				gtk_list_store_set(GTK_LIST_STORE(excl_model), &iter, ITEM_COLUMN, seaudit_app->cur_policy->types[i].name, -1);
			}
		} 
		else {
			for (i = 0; i < seaudit_app->cur_policy->num_types; i++) {
				for (j = 0; j < g_list_length(incl_items); j++) {
					/* If the current policy type is found in the included items list then put in included store */
					if(strcmp(seaudit_app->cur_policy->types[i].name, (char *) g_list_nth_data(incl_items, j)) == 0) {
						position = get_insert_position(incl_model, seaudit_app->cur_policy->types[i].name);
						gtk_list_store_insert(GTK_LIST_STORE(incl_model), &iter, position);
						gtk_list_store_set (GTK_LIST_STORE(incl_model), &iter, ITEM_COLUMN, seaudit_app->cur_policy->types[i].name, -1);
						found = 1;
						break;
					} 		
				}
				if(!found) {
					/* This is an exluded type, so add to excluded types list store */
					position = get_insert_position(excl_model, seaudit_app->cur_policy->types[i].name);
					gtk_list_store_insert(GTK_LIST_STORE(excl_model), &iter, position);
					gtk_list_store_set(GTK_LIST_STORE(excl_model), &iter, ITEM_COLUMN, seaudit_app->cur_policy->types[i].name, -1);	 
				} 
				found = 0;
				j = 0;
			}
		}
	}
	else if (which_filter == OBJECTS_FILTER) {
		incl_items = obj_class_list_get();
		/* Default case - all objects excluded */
		if(incl_items == NULL) {
			for (i = 0; i < seaudit_app->cur_policy->num_obj_classes; i++) {
				/* Add to excluded objects list store */
				position = get_insert_position(excl_model, seaudit_app->cur_policy->obj_classes[i].name);
				gtk_list_store_insert(GTK_LIST_STORE(excl_model), &iter, position);
				gtk_list_store_set(GTK_LIST_STORE(excl_model), &iter, ITEM_COLUMN, seaudit_app->cur_policy->obj_classes[i].name, -1);
			}
		} else {
			for (i = 0; i < seaudit_app->cur_policy->num_obj_classes; i++) {
				for (j = 0; j < g_list_length(incl_items); j++) {
					if(strcmp(seaudit_app->cur_policy->obj_classes[i].name, (char *) g_list_nth_data(incl_items, j)) == 0) {
						/* This is an included object, so add to included objects list store */
						position = get_insert_position(incl_model, seaudit_app->cur_policy->obj_classes[i].name);
						gtk_list_store_insert(GTK_LIST_STORE(incl_model), &iter, position);
						gtk_list_store_set (GTK_LIST_STORE(incl_model), &iter, ITEM_COLUMN, seaudit_app->cur_policy->obj_classes[i].name, -1);
						found = 1;
						break;
					}
				}
				if(!found) {
					/* This is an exluded object, so add to excluded objects list store */
					position = get_insert_position(excl_model, seaudit_app->cur_policy->obj_classes[i].name);
					gtk_list_store_insert(GTK_LIST_STORE(excl_model), &iter, position);
					gtk_list_store_set(GTK_LIST_STORE(excl_model), &iter, ITEM_COLUMN, seaudit_app->cur_policy->obj_classes[i].name, -1);
				}
				found = 0;
				j = 0;
			}
		}
	}
	else {
		g_assert(window);
		message_display(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Wrong filter parameter specified.\n");
		return -1;
	}
		
	return 0;
}

int custom_window_create(enum filter_items_t which_filter)
{
	GladeXML *xml;
	GtkTreeView *include_tree, *exclude_tree;
	GtkListStore *incl_list_store, *excl_list_store;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *excl_column, *incl_column;
	
	if(window != NULL) {
		/* Raise the window; Need to handle the user pressing another different filters list */
		gtk_window_present(GTK_WINDOW(window));
		return 0;
	}
	if (!seaudit_app->cur_policy) {
		g_assert(window);
		message_display(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "You must load a policy first.\n");
		return -1;
	}
			
	/* Load the glade interface specifications */
	xml = glade_xml_new("customize_filter_window.glade", NULL, NULL);
	
	/* Configure window labels to reflect the specified filter. */
	window = glade_xml_get_widget(xml, "CreateFilterWindow");
	GtkLabel *lbl = GTK_LABEL(glade_xml_get_widget(xml, "TitleFrameLabel"));
	GtkLabel *incl_lbl = GTK_LABEL(glade_xml_get_widget(xml, "IncludeLabel"));
	GtkLabel *excl_lbl = GTK_LABEL(glade_xml_get_widget(xml, "ExcludeLabel"));
	
	/* Connect all signals to callback functions */
	glade_xml_signal_connect_data(xml, "on_ok_button_clicked",
				  G_CALLBACK(on_ok_button_clicked),
				  xml);
	glade_xml_signal_connect_data(xml, "on_apply_button_clicked",
				  G_CALLBACK(on_apply_button_clicked),
				  xml);
	glade_xml_signal_connect_data(xml, "on_cancel_button_clicked",
				  G_CALLBACK(on_cancel_button_clicked),
				  xml);
	glade_xml_signal_connect_data(xml, "on_add_button_clicked",
				  G_CALLBACK(on_add_button_clicked),
				  xml);
	glade_xml_signal_connect_data(xml, "on_remove_button_clicked",
				  G_CALLBACK(on_remove_button_clicked),
				  xml);
	glade_xml_signal_connect_data(xml, "gtk_widget_destroyed",
				  GTK_SIGNAL_FUNC(gtk_widget_destroyed),
				  &window);
				  
	/* Label accordingly */
	if (which_filter == SRC_TYPES_FILTER) {			
		gtk_window_set_title(GTK_WINDOW(window), "Select Source Types");
		gtk_label_set_text(lbl, "Source types:");
	} else if (which_filter == TGT_TYPES_FILTER) {
		gtk_window_set_title(GTK_WINDOW(window), "Select Target Types");
		gtk_label_set_text(lbl, "Target types:");
	}
	else if (which_filter == OBJECTS_FILTER) {
		gtk_window_set_title(GTK_WINDOW(window), "Select Object Classes");
		gtk_label_set_text(lbl, "Object classes:");
	}
	else {
		g_assert(window);
		message_display(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Wrong filter parameter specified.\n");
		gtk_widget_destroy (glade_xml_get_widget(xml, "CreateFilterWindow"));
		return -1;
	}
	gtk_label_set_text(incl_lbl, "Selected:");
	gtk_label_set_text(excl_lbl, "Unselected:");
	curr_filter = which_filter;
	
	/* Create the views */
	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "IncludeTreeView"));
	g_assert(include_tree);
	exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "ExcludeTreeView"));
	g_assert(exclude_tree);
	
	/* Create list stores and then populate */
	incl_list_store = gtk_list_store_new (N_COLUMNS, G_TYPE_STRING);
	excl_list_store = gtk_list_store_new (N_COLUMNS, G_TYPE_STRING);
	gtk_tree_view_set_model(include_tree, GTK_TREE_MODEL(incl_list_store));
	gtk_tree_view_set_model(exclude_tree, GTK_TREE_MODEL(excl_list_store));
	
	if (populate_list_models(include_tree, exclude_tree, which_filter) != 0) {
		gtk_widget_destroy (glade_xml_get_widget(xml, "CreateFilterWindow"));
		return -1;
	}
	
	/* Each view now holds a reference.  We can get rid of our own references. */
	g_object_unref(G_OBJECT(incl_list_store));
	g_object_unref(G_OBJECT(excl_list_store));
	
	/* Display the model with cell render; specify what column to use (ITEM_COLUMN). */
	renderer = gtk_cell_renderer_text_new ();
	incl_column = gtk_tree_view_column_new_with_attributes ("", renderer, "text", ITEM_COLUMN, NULL);
	excl_column = gtk_tree_view_column_new_with_attributes ("", renderer, "text", ITEM_COLUMN, NULL);
	
	/* Add the column to the view. */
	gtk_tree_view_append_column (GTK_TREE_VIEW (include_tree), incl_column);
	gtk_tree_view_append_column (GTK_TREE_VIEW (exclude_tree), excl_column);
	gtk_tree_view_column_set_clickable (incl_column, TRUE);
	gtk_tree_view_column_set_clickable (excl_column, TRUE);
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(include_tree), GTK_SELECTION_MULTIPLE);
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(exclude_tree), GTK_SELECTION_MULTIPLE);
	
	/* Disable the apply button since there are no changes */
	gtk_widget_set_sensitive(glade_xml_get_widget(xml, "ApplyButton"), 0);
	changed = FALSE;

	return 0;
}

