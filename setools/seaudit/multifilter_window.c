/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: February 11, 2004
 *
 */

#include "multifilter_window.h"
#include "filtered_view.h"
#include "filter_window.h"
#include "utilgui.h"
#include <libapol/util.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void multifilter_window_on_add_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_edit_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_remove_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_apply_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_close_button_pressed(GtkButton *button, multifilter_window_t *window);
static gboolean multifilter_window_on_delete_event(GtkWidget *widget, GdkEvent *event, multifilter_window_t *window);

multifilter_window_t* multifilter_window_create(seaudit_filtered_view_t *parent, const gchar *view_name)
{
	multifilter_window_t *rt;

	rt = (multifilter_window_t*)malloc(sizeof(multifilter_window_t));
	if (!rt) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	multifilter_window_init(rt, parent, view_name);
	return rt;
}

void multifilter_window_init(multifilter_window_t *window, seaudit_filtered_view_t *parent, const gchar *view_name)
{
	memset(window, 0, sizeof(multifilter_window_t));
	window->parent = parent;
	window->name = g_string_new(view_name);
}

void multifilter_window_destroy(multifilter_window_t *window)
{
	GList *item;

	if (!window)
		return;

	for (item = window->filter_windows; item != NULL; item = g_list_next(item))
		filter_window_destroy((filter_window_t*)item->data);
	g_list_free(window->filter_windows);
	if (window->window) {
		/* if there is an idle function for this window
		 * then we must remove it to avoid that function
		 * being executed after we delete the window. */
		while(g_idle_remove_by_data(window->window));	       
		gtk_widget_destroy(GTK_WIDGET(window->window));
	}

}

void multifilter_window_display(multifilter_window_t *window)
{
	char *dir;
	GString *path;
	GtkWidget *widget;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GString *title;

	if (!window)
		return;

	if (window->window) {
		gtk_window_present(window->window);
		return;
	}

	dir = find_file("multifilter_window.glade");
	if (!dir){
		fprintf(stderr, "could not find multifilter_window.glade\n");
		return;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/multifilter_window.glade");
	window->xml = glade_xml_new(path->str, NULL, NULL);	
	g_assert(window->xml);
	window->window = GTK_WINDOW(glade_xml_get_widget(window->xml, "MultifilterWindow"));
	g_assert(window->window);
	title = g_string_new("View - ");
	title = g_string_append(title, window->name->str);
	gtk_window_set_title(window->window, title->str);
	g_string_free(title, TRUE);
	window->liststore = gtk_list_store_new(1, G_TYPE_STRING);
	widget = glade_xml_get_widget(window->xml, "NamesTreeView");
	g_assert(widget);
	window->treeview = GTK_TREE_VIEW(widget);
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Filter names", renderer, "text", 0, NULL);
	gtk_tree_view_append_column(window->treeview, column);
	gtk_tree_view_column_set_clickable (column, FALSE);
	gtk_tree_view_column_set_resizable(column, FALSE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_GROW_ONLY);
	gtk_tree_view_column_set_visible(column, TRUE);
	gtk_tree_view_set_model(window->treeview, GTK_TREE_MODEL(window->liststore));

	widget = glade_xml_get_widget(window->xml, "CloseButton");
	g_signal_connect(G_OBJECT(widget), "pressed", 
			 G_CALLBACK(multifilter_window_on_close_button_pressed), window);
	widget = glade_xml_get_widget(window->xml, "RemoveButton");
	g_signal_connect(G_OBJECT(widget), "pressed", 
			 G_CALLBACK(multifilter_window_on_remove_button_pressed), window);
	gtk_widget_set_sensitive(widget, FALSE);
	widget = glade_xml_get_widget(window->xml, "EditButton");
	g_signal_connect(G_OBJECT(widget), "pressed",
			 G_CALLBACK(multifilter_window_on_edit_button_pressed), window);
	gtk_widget_set_sensitive(widget, FALSE);
	widget = glade_xml_get_widget(window->xml, "ApplyButton");
	g_signal_connect(G_OBJECT(widget), "pressed", 
			 G_CALLBACK(multifilter_window_on_apply_button_pressed), window);
	gtk_widget_set_sensitive(widget, FALSE);
	widget = glade_xml_get_widget(window->xml, "AddButton");
	g_signal_connect(G_OBJECT(widget), "pressed", 
			 G_CALLBACK(multifilter_window_on_add_button_pressed), window);
	g_signal_connect(G_OBJECT(window->window), "delete_event", 
			 G_CALLBACK(multifilter_window_on_delete_event), window);
	g_string_free(path, TRUE);

}

void multifilter_window_hide(multifilter_window_t *window)
{
	if (!window || !window->window)
		return;
	gtk_widget_hide(GTK_WIDGET(window->window));
}

void multifilter_window_set_filter_name_in_list(multifilter_window_t *window, filter_window_t *filter_window)
{
	GtkTreePath *path;
	GtkTreeIter iter;
	gint index;
	char *name;

	name = filter_window->name->str;
	index = filter_window->parent_index;
	if (index < 0 || index >= window->num_filter_windows)
		return;
	path = gtk_tree_path_new_from_indices(index, -1);
	if (!gtk_tree_model_get_iter(GTK_TREE_MODEL(window->liststore), &iter, path))
		return;
	gtk_list_store_set(window->liststore, &iter, 0, name, -1);
}

static void multifilter_window_on_add_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	filter_window_t *filter_window;
	GtkTreeIter iter;
	GtkWidget *widget;

	filter_window = filter_window_create(window, window->num_filter_windows, "Untitled");
	gtk_list_store_append(window->liststore, &iter);
	window->filter_windows = g_list_append(window->filter_windows, filter_window);
	window->num_filter_windows++;
	multifilter_window_set_filter_name_in_list(window, filter_window);
	filter_window_display(filter_window);
	widget = glade_xml_get_widget(window->xml, "EditButton");
	gtk_widget_set_sensitive(widget, TRUE);
	widget = glade_xml_get_widget(window->xml, "RemoveButton");
	gtk_widget_set_sensitive(widget, TRUE);	
	widget = glade_xml_get_widget(window->xml, "ApplyButton");
	gtk_widget_set_sensitive(widget, TRUE);
}

static void multifilter_window_on_edit_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeIter iter;
	GtkWidget *widget;
	filter_window_t *filter_window;
	gint *index;

	selection = gtk_tree_view_get_selection(window->treeview);
	model = GTK_TREE_MODEL(window->liststore);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		message_display(window->window, GTK_MESSAGE_ERROR, "You must select a filter to edit.");
		return;
	}
	path = gtk_tree_path_new();
        path = gtk_tree_model_get_path(model, &iter);
	index = gtk_tree_path_get_indices(path);
	filter_window = (filter_window_t*)g_list_nth_data(window->filter_windows, index[0]);
	if (filter_window)
		filter_window_display(filter_window);

	gtk_tree_path_free(path);
	widget = glade_xml_get_widget(window->xml, "ApplyButton");
	gtk_widget_set_sensitive(widget, TRUE);
}

static void multifilter_window_on_remove_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeIter iter;
	GList *item;
	GtkWidget *widget;
	filter_window_t *filter_window;
	gint *index;

	selection = gtk_tree_view_get_selection(window->treeview);
	model = GTK_TREE_MODEL(window->liststore);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		message_display(window->window, GTK_MESSAGE_ERROR, "You must select a filter to remove.");
		return;
	}
	path = gtk_tree_path_new();
        path = gtk_tree_model_get_path(model, &iter);
	index = gtk_tree_path_get_indices(path);
	
	for (item = window->filter_windows; item != NULL; item = g_list_next(item)) {
		filter_window = (filter_window_t*)item->data;
		if (filter_window->parent_index >= *index)
			filter_window->parent_index--;
	}
	item = g_list_nth(window->filter_windows, index[0]);
	gtk_list_store_remove(window->liststore, &iter);
	window->filter_windows = g_list_remove_link(window->filter_windows, item);
	filter_window_destroy(item->data);
	window->num_filter_windows--;
	if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(window->liststore), &iter)) {
		widget = glade_xml_get_widget(window->xml, "EditButton");
		gtk_widget_set_sensitive(widget, FALSE);
		widget = glade_xml_get_widget(window->xml, "RemoveButton");
		gtk_widget_set_sensitive(widget, FALSE);      
	}
}

static void multifilter_window_on_apply_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	GtkWidget *widget;
	seaudit_filter_t *seaudit_filter;
	seaudit_multifilter_t *multifilter;
	GList *item;
	SEAuditLogViewStore *store;

	show_wait_cursor(GTK_WIDGET(window->window));
	store = window->parent->store;
	multifilter = seaudit_multifilter_create();
	for (item = window->filter_windows; item != NULL; item = g_list_next(item)) {
		seaudit_filter = filter_window_get_filter(item->data);
		seaudit_multifilter_add_filter(multifilter, seaudit_filter);
	}
	widget = glade_xml_get_widget(window->xml, "ShowEntry");
	g_assert(widget);
	if (strcmp("Show", gtk_entry_get_text(GTK_ENTRY(widget))) == 0)
		audit_log_view_set_show_matches(store->log_view, TRUE);
	else
		audit_log_view_set_show_matches(store->log_view, FALSE);

	widget = glade_xml_get_widget(window->xml, "MatchEntry");
	g_assert(widget);
	if (strcmp("All", gtk_entry_get_text(GTK_ENTRY(widget))) == 0)
		seaudit_multifitler_set_match(multifilter, SEAUDIT_FILTER_MATCH_ALL);
	else 
		seaudit_multifitler_set_match(multifilter, SEAUDIT_FILTER_MATCH_ANY);

	audit_log_view_set_multifilter(store->log_view, multifilter);
	seaudit_log_view_store_do_filter(store);
	clear_wait_cursor(GTK_WIDGET(window->window));
	
}

static void multifilter_window_on_close_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	GList *item;
	
	show_wait_cursor(GTK_WIDGET(window->window));
	for (item = window->filter_windows; item != NULL; item = g_list_next(item))
		filter_window_hide((filter_window_t*)item->data);
	gtk_widget_hide(GTK_WIDGET(window->window));
	clear_wait_cursor(GTK_WIDGET(window->window));
}

static gboolean multifilter_window_on_delete_event(GtkWidget *widget, GdkEvent *event, multifilter_window_t *window)
{
	GtkWidget *button;

	button = glade_xml_get_widget(window->xml, "CloseButton");
	multifilter_window_on_close_button_pressed(GTK_BUTTON(button), window);
	return TRUE;
}
