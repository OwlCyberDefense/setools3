/* Copyright (C) 2004-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: February 11, 2004
 *
 */

#include "multifilter_window.h"
#include "filtered_view.h"
#include "filter_window.h"
#include "seaudit.h"
#include "utilgui.h"
#include <libapol/util.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

extern seaudit_t *seaudit_app;

static void multifilter_window_on_add_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_edit_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_remove_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_apply_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_close_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_import_button_pressed(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_on_export_button_pressed(GtkButton *button, multifilter_window_t *window);
static gboolean multifilter_window_on_delete_event(GtkWidget *widget, GdkEvent *event, multifilter_window_t *window);
static void multifilter_window_add_filter_window(multifilter_window_t *window, filter_window_t *filter_window);
static void multifilter_window_on_row_activated(GtkTreeView *treeview, GtkTreePath *path, GtkTreeViewColumn *column, multifilter_window_t *window);
static gboolean seaudit_window_on_name_entry_text_changed(GtkWidget *widget, GdkEventKey *event, multifilter_window_t *window);
static void multifilter_window_set_title(multifilter_window_t *window);
static void multifilter_window_update_buttons_sensitivity(multifilter_window_t *window);
static void multifilter_window_get_selected_filters(multifilter_window_t *window, seaudit_multifilter_t *multifilter, GString *filename);
static void multifilter_window_get_selected_filters_on_cancel_clicked(GtkButton *button, multifilter_window_t *window);
static void multifilter_window_get_selected_filters_on_ok_clicked(GtkButton *button, multifilter_window_t *window);
static gboolean multifilter_window_get_selected_on_delete_event(GtkWidget *widget, GdkEvent *event, seaudit_multifilter_t *user_data);
static void multifilter_window_on_save_button_pressed(GtkButton *button, multifilter_window_t *user_data);

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
	window->match = g_string_new("All");
	window->show = g_string_new("Show");
	window->filename = g_string_new("");
	window->liststore = gtk_list_store_new(1, G_TYPE_STRING);
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
	g_string_free(window->name, TRUE);
	g_string_free(window->match, TRUE);
	g_string_free(window->show, TRUE);
	g_string_free(window->filename, TRUE);
}

void multifilter_window_display(multifilter_window_t *window, GtkWindow *parent)
{
	char *dir;
	GString *path;
	GtkWidget *widget;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;

	if (!window || !parent)
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

	/* set this window to be transient on the parent window, so that when it pops up it gets centered on it */
	/* however to have it "appear" to be centered we have to hide and then show */
	gtk_window_set_transient_for(window->window, parent);
	gtk_window_set_position(window->window, GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_widget_hide(GTK_WIDGET(window->window));
	gtk_window_present(window->window);

	widget = glade_xml_get_widget(window->xml, "NameEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), window->name->str);
	multifilter_window_set_title(window);
	widget = glade_xml_get_widget(window->xml, "MatchEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), window->match->str);
	widget = glade_xml_get_widget(window->xml, "ShowEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), window->show->str);
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

	g_signal_connect(G_OBJECT(window->treeview), "row-activated", 
			 G_CALLBACK(multifilter_window_on_row_activated), window);

	widget = glade_xml_get_widget(window->xml, "NameEntry");
	g_signal_connect(G_OBJECT(widget), "key-release-event",
			 G_CALLBACK(seaudit_window_on_name_entry_text_changed), window);
	widget = glade_xml_get_widget(window->xml, "CloseButton");
	g_signal_connect(G_OBJECT(widget), "pressed", 
			 G_CALLBACK(multifilter_window_on_close_button_pressed), window);
	widget = glade_xml_get_widget(window->xml, "RemoveButton");
	g_signal_connect(G_OBJECT(widget), "pressed", 
			 G_CALLBACK(multifilter_window_on_remove_button_pressed), window);
	widget = glade_xml_get_widget(window->xml, "EditButton");
	g_signal_connect(G_OBJECT(widget), "pressed",
			 G_CALLBACK(multifilter_window_on_edit_button_pressed), window);
	widget = glade_xml_get_widget(window->xml, "ApplyButton");
	g_signal_connect(G_OBJECT(widget), "pressed", 
			 G_CALLBACK(multifilter_window_on_apply_button_pressed), window);
	widget = glade_xml_get_widget(window->xml, "AddButton");
	g_signal_connect(G_OBJECT(widget), "pressed", 
			 G_CALLBACK(multifilter_window_on_add_button_pressed), window);
	widget = glade_xml_get_widget(window->xml, "ImportButton");
	g_signal_connect(G_OBJECT(widget), "pressed",
			 G_CALLBACK(multifilter_window_on_import_button_pressed), window);
	widget = glade_xml_get_widget(window->xml, "ExportButton");
	g_signal_connect(G_OBJECT(widget), "pressed",
			 G_CALLBACK(multifilter_window_on_export_button_pressed), window);
	widget = glade_xml_get_widget(window->xml, "SaveButton");
	g_signal_connect(G_OBJECT(widget), "pressed",
			 G_CALLBACK(multifilter_window_on_save_button_pressed), window);

	g_signal_connect(G_OBJECT(window->window), "delete_event", 
			 G_CALLBACK(multifilter_window_on_delete_event), window);
	g_string_free(path, TRUE);
	multifilter_window_update_buttons_sensitivity(window);
}

void multifilter_window_save_multifilter(multifilter_window_t *window, gboolean saveas, gboolean multifilter_is_parent_window)
{
	seaudit_multifilter_t *multifilter;
	filter_window_t *filter_window;
	seaudit_filter_t *filter;
	GList *item;
	GString *filename, *message;
	GtkWidget *widget;
	gint response, err;

	if (!window)
		return;
	
	/* If this is not a 'Save As' request and the multifilter is a loaded saved multifilter,
	 * then just save using it's original filename. Otherwise, it has no filename and so get 
	 * the filename from the user, while appending the default seaudit view extension. */
	if (!saveas && strcmp(window->filename->str, "") != 0)
		filename = g_string_new(window->filename->str);
	else {
		if (multifilter_is_parent_window)
			filename = get_filename_from_user("Save View", window->name->str, window->window, TRUE);
		else
			filename = get_filename_from_user("Save View", window->name->str, seaudit_app->window->window, TRUE);
		if (filename == NULL)
			return;
		/* Append the default seaudit view extension (defined in seaudit.h). */
		g_string_append(filename, SEAUDIT_VIEW_EXT);
		
		if (g_file_test(filename->str, G_FILE_TEST_EXISTS)) {
			message = g_string_new("");
			g_string_printf(message, "The file %s\nalready exists.  Are you sure you wish to continue?", filename->str);
			response = get_user_response_to_message(window->window, message->str);
			g_string_free(message, TRUE);
			if (response != GTK_RESPONSE_YES)
				return;
		}
	}
	g_assert(filename);
	multifilter = seaudit_multifilter_create();
	seaudit_multifilter_set_name(multifilter, window->name->str);
	if (window->xml) {
		widget = glade_xml_get_widget(window->xml, "MatchEntry");
		g_assert(widget);
		if (strcmp("All", gtk_entry_get_text(GTK_ENTRY(widget))) == 0)
			seaudit_multifilter_set_match(multifilter, SEAUDIT_FILTER_MATCH_ALL);
		else 
			seaudit_multifilter_set_match(multifilter, SEAUDIT_FILTER_MATCH_ANY);
		widget = glade_xml_get_widget(window->xml, "ShowEntry");
		g_assert(widget);
		if (strcmp("Show", gtk_entry_get_text(GTK_ENTRY(widget))) == 0)
			seaudit_multifilter_set_show_matches(multifilter, TRUE);
		else 
			seaudit_multifilter_set_show_matches(multifilter, FALSE);
	} else {
		seaudit_multifilter_set_match(multifilter, SEAUDIT_FILTER_MATCH_ALL);
		seaudit_multifilter_set_show_matches(multifilter, TRUE);
	}
	for (item = window->filter_windows; item != NULL; item = g_list_next(item)) {
		filter_window = (filter_window_t*)item->data;
		filter = filter_window_get_filter(filter_window);
		seaudit_multifilter_add_filter(multifilter, filter);
	}
	err = seaudit_multifilter_save_to_file(multifilter, filename->str);
	if (err) {
		message = g_string_new("");
	        g_string_printf(message, "Unable to save view to %s\n%s", filename->str, strerror(errno));
		message_display(window->window, GTK_MESSAGE_ERROR, message->str);
		g_string_free(message, TRUE);
	} else {
		window->filename = g_string_assign(window->filename, filename->str);
		multifilter_window_set_title(window);
	}

	seaudit_multifilter_destroy(multifilter);
	g_string_free(filename, TRUE);
}

int multifilter_window_load_multifilter(multifilter_window_t *window)
{
	seaudit_multifilter_t *multifilter;
	filter_window_t *filter_window;
	seaudit_filter_t *filter;
	llist_t *list;
	llist_node_t *node;
	GString *filename, *message;
	bool_t is_multi;
	gint response, err;

	if (!window)
		return -1;

	filename = get_filename_from_user("Open View", NULL, seaudit_app->window->window, FALSE);
	if (filename == NULL)
		return -1;
	err = seaudit_multifilter_load_from_file(&multifilter, &is_multi, filename->str);
	if (err < 0) {
		message = g_string_new("");
		g_string_printf(message, "Unable to import from %s\n%s", filename->str, strerror(errno));
		message_display(window->window, GTK_MESSAGE_ERROR, message->str);
		g_string_free(message, TRUE);
		return err;
	} else if (err > 0) {
		message = g_string_new("");
		g_string_printf(message, "Unable to import from %s\ninvalid file.", filename->str);
		message_display(window->window, GTK_MESSAGE_ERROR, message->str);
		g_string_free(message, TRUE);
		return err;
	}	
	g_assert(multifilter);
	if (!is_multi) {
		message = g_string_new("");
		g_string_printf(message, "The file %s\ndoes not contain all the information required for a view.\nWould you like to load the available information as a new view anyway?", filename->str);
		response = get_user_response_to_message(window->window, message->str);
		g_string_free(message, TRUE);
		if (response != GTK_RESPONSE_YES)
			return -1;
	}
	list = multifilter->filters;
	for (node = list->head; node != NULL; node = node->next) {
		filter = (seaudit_filter_t*)node->data;
		filter_window = filter_window_create(window, window->num_filter_windows, filter->name);
		filter_window_set_values_from_filter(filter_window, filter);
		multifilter_window_add_filter_window(window, filter_window);
	}
	if (multifilter->name)
		window->name = g_string_assign(window->name, multifilter->name);
	if (multifilter->match == SEAUDIT_FILTER_MATCH_ALL)
		window->match = g_string_assign(window->match, "All");
	else 
		window->match = g_string_assign(window->match, "Any");

	if (multifilter->show == TRUE)
		window->show = g_string_assign(window->show, "Show");
	else 
		window->show = g_string_assign(window->show, "Hide");
	seaudit_multifilter_destroy(multifilter);
	window->filename = g_string_assign(window->filename, filename->str);

	return 0;

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

void multifilter_window_apply_multifilter(multifilter_window_t *window)
{
	GtkWidget *widget;
	seaudit_filter_t *seaudit_filter;
	seaudit_multifilter_t *multifilter;
	GList *item;
	SEAuditLogViewStore *store;

       	store = window->parent->store;
	multifilter = seaudit_multifilter_create();
	for (item = window->filter_windows; item != NULL; item = g_list_next(item)) {
		seaudit_filter = filter_window_get_filter(item->data);
		seaudit_multifilter_add_filter(multifilter, seaudit_filter);
	}
	if (window->xml) {
		widget = glade_xml_get_widget(window->xml, "ShowEntry");
		g_assert(widget);
		if (strcmp("Show", gtk_entry_get_text(GTK_ENTRY(widget))) == 0)
			seaudit_multifilter_set_show_matches(multifilter, TRUE);
		else
			seaudit_multifilter_set_show_matches(multifilter, FALSE);
		
		widget = glade_xml_get_widget(window->xml, "MatchEntry");
		g_assert(widget);
		if (strcmp("All", gtk_entry_get_text(GTK_ENTRY(widget))) == 0)
			seaudit_multifilter_set_match(multifilter, SEAUDIT_FILTER_MATCH_ALL);
		else 
			seaudit_multifilter_set_match(multifilter, SEAUDIT_FILTER_MATCH_ANY);
	} else {
		seaudit_multifilter_set_match(multifilter, (strcmp(window->match->str, "All")==0)? 
					      SEAUDIT_FILTER_MATCH_ALL : SEAUDIT_FILTER_MATCH_ANY);
		seaudit_multifilter_set_show_matches(multifilter, (strcmp(window->show->str, "Show")==0)? 
						     TRUE : FALSE);
	}
	audit_log_view_set_multifilter(store->log_view, multifilter);
	seaudit_log_view_store_do_filter(store);
}

static void multifilter_window_add_filter_window(multifilter_window_t *window, filter_window_t *filter_window)
{
	GtkTreeIter iter;

	gtk_list_store_append(window->liststore, &iter);
	window->filter_windows = g_list_append(window->filter_windows, filter_window);
	window->num_filter_windows++;
	multifilter_window_set_filter_name_in_list(window, filter_window);
}

static void multifilter_window_on_add_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	filter_window_t *filter_window;

	filter_window = filter_window_create(window, window->num_filter_windows, "Untitled");
	multifilter_window_add_filter_window(window, filter_window);
	filter_window_display(filter_window, window->window);
	multifilter_window_update_buttons_sensitivity(window);
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
		filter_window_display(filter_window, window->window);

	gtk_tree_path_free(path);
	widget = glade_xml_get_widget(window->xml, "ApplyButton");
}

static void multifilter_window_on_remove_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeIter iter;
	GList *item;
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
	multifilter_window_update_buttons_sensitivity(window);
}

static void multifilter_window_on_apply_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	show_wait_cursor(GTK_WIDGET(window->window));
	multifilter_window_apply_multifilter(window);
	clear_wait_cursor(GTK_WIDGET(window->window));
}

static void multifilter_window_on_import_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	seaudit_multifilter_t *multifilter;
	filter_window_t *filter_window;
	seaudit_filter_t *filter;
	llist_t *list;
	bool_t is_multi;
	GString *filename, *message;
	gint err;

	filename = get_filename_from_user("Import Filter", NULL, window->window, FALSE);
	if (!filename)
		return;
	err = seaudit_multifilter_load_from_file(&multifilter, &is_multi, filename->str);
	if (err < 0) {
		message = g_string_new("");
		g_string_printf(message, "Unable to import from %s\n%s", filename->str, strerror(errno));
		message_display(window->window, GTK_MESSAGE_ERROR, message->str);
		g_string_free(message, TRUE);
		goto exit;
	} else if (err > 0) {
		message = g_string_new("");
		g_string_printf(message, "Unable to import from %s\ninvalid file.", filename->str);
		message_display(window->window, GTK_MESSAGE_ERROR, message->str);
		g_string_free(message, TRUE);
		goto exit;
	}
	if (!multifilter)
		goto exit;
	list = multifilter->filters;
	g_assert(list);
	if (list->head == NULL) {
		seaudit_multifilter_destroy(multifilter);
		goto exit;
	}
	if (list->num == 1) {
		filter = (seaudit_filter_t*)list->head->data;
		filter_window = filter_window_create(window, window->num_filter_windows, filter->name);
		filter_window_set_values_from_filter(filter_window, filter);
		multifilter_window_add_filter_window(window, filter_window);
		seaudit_multifilter_destroy(multifilter);
		multifilter_window_update_buttons_sensitivity(window);
	} else 
		multifilter_window_get_selected_filters(window, multifilter, filename);
 exit:
	if (filename)
		g_string_free(filename, TRUE);
}

static void multifilter_window_on_export_button_pressed(GtkButton *button, multifilter_window_t *window)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreePath *path;
	gint *index;
	filter_window_t *filter_window;
	seaudit_filter_t *filter;
	GString *filename, *message;
	gint response, err;

	selection = gtk_tree_view_get_selection(window->treeview);
	model = GTK_TREE_MODEL(window->liststore);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		message_display(window->window, GTK_MESSAGE_ERROR, "You must select a filter to export.");
		return;
	}
	path = gtk_tree_path_new();
        path = gtk_tree_model_get_path(model, &iter);
	index = gtk_tree_path_get_indices(path);
	filter_window = g_list_nth_data(window->filter_windows, index[0]);
	filter = filter_window_get_filter(filter_window);
	filename = get_filename_from_user("Export filter", filter->name, window->window, TRUE);
	if (filename == NULL)
		return;
	/* Append the default seaudit filter extension (defined in seaudit.h). */
	g_string_append(filename, SEAUDIT_FILTER_EXT);
		
	if (g_file_test(filename->str, G_FILE_TEST_EXISTS)) {
		message = g_string_new("");
		g_string_printf(message, "The file %s\nalready exists.  Are you sure you wish to continue?", filename->str);
		response = get_user_response_to_message(window->window, message->str);
		g_string_free(message, TRUE);
		if (response != GTK_RESPONSE_YES) {
			g_string_free(filename, TRUE);
			return;
		}
	}
	err = seaudit_filter_save_to_file(filter, filename->str);
	if (err) {
		message = g_string_new("");
	        g_string_printf(message, "Unable to export to %s\n%s", filename->str, strerror(errno));
		message_display(window->window, GTK_MESSAGE_ERROR, message->str);
		g_string_free(message, TRUE);
	}
	seaudit_filter_destroy(filter);
	g_string_free(filename, TRUE);
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

static void multifilter_window_on_row_activated(GtkTreeView *treeview, GtkTreePath *path, GtkTreeViewColumn *column, multifilter_window_t *window) 
{	
	GtkWidget *button;

	button = glade_xml_get_widget(window->xml, "EditButton");
	multifilter_window_on_edit_button_pressed(GTK_BUTTON(button), window);
}

static gboolean seaudit_window_on_name_entry_text_changed(GtkWidget *widget, GdkEventKey *event, multifilter_window_t *window)
{
	const gchar *name;
	seaudit_filtered_view_t *view;
	GtkWidget *page, *tab_widget;
	GtkLabel *label;

	name = gtk_entry_get_text(GTK_ENTRY(widget));
	g_string_assign(window->name, name);
	multifilter_window_set_title(window);	
	view = window->parent;
	page = gtk_notebook_get_nth_page(seaudit_app->window->notebook, view->notebook_index);
	tab_widget = gtk_notebook_get_tab_label(seaudit_app->window->notebook, page);
	label = g_object_get_data(G_OBJECT(tab_widget), "label");
	g_assert(label);
	gtk_label_set_text(label, name);
	return FALSE;
}

static void multifilter_window_set_title(multifilter_window_t *window)
{
	GString *title;

	if (!window || !window->window)
		return;

	if (strcmp(window->filename->str, "") == 0) {
		title = g_string_new("View - ");
		title = g_string_append(title, window->name->str);
	} else {
		title = g_string_new("Save to - ");
		title = g_string_append(title, window->filename->str);
	}
	gtk_window_set_title(window->window, title->str);
	g_string_free(title, TRUE);

}

static void multifilter_window_update_buttons_sensitivity(multifilter_window_t *window)
{
	GtkWidget *widget;
	GtkTreeIter iter;
	gboolean state;

	if (!window || !window->xml)
		return;
	
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(window->liststore), &iter))
		state = TRUE;
	else
		state = FALSE;

	widget = glade_xml_get_widget(window->xml, "ExportButton");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, state);
	widget = glade_xml_get_widget(window->xml, "RemoveButton");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, state);		
	widget = glade_xml_get_widget(window->xml, "EditButton");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, state);
}

static void multifilter_window_get_selected_filters(multifilter_window_t *window, seaudit_multifilter_t *multifilter, GString *filename)
{
	GtkWidget *select_window, *vbox, *ok_button, *cancel_button, *button_box,
		*label, *treeview, *scrolled_window;
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	GtkListStore *store;
	llist_t *list;
	llist_node_t *node;
	seaudit_filter_t *filter;
	GtkTreeIter iter;
	GString *title;

	select_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	g_assert(filename);
	title = g_string_new("");
	g_string_printf(title, "File - %s", filename->str);
	gtk_window_set_title(GTK_WINDOW(select_window), title->str);
	g_string_free(title, TRUE);
	gtk_widget_set_size_request(select_window, 280, 350);
	label = gtk_label_new("The file contained multiple filters.  Select the\n"
"filters you want to import and then click 'OK'.");
	treeview = gtk_tree_view_new();
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview)), GTK_SELECTION_MULTIPLE);
	store = gtk_list_store_new(1, G_TYPE_STRING);
	list = multifilter->filters;
	for (node = list->head; node != NULL; node = node->next) {
		filter = (seaudit_filter_t*)node->data;
		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter, 0, filter->name, -1);
	}
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Filter names", renderer, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
	gtk_tree_view_column_set_clickable (column, FALSE);
	gtk_tree_view_column_set_resizable(column, FALSE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_GROW_ONLY);
	gtk_tree_view_column_set_visible(column, TRUE);
	gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(store));

	scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_window), treeview);
	vbox = gtk_vbox_new(FALSE, 0);
	button_box = gtk_hbutton_box_new();
	gtk_button_box_set_layout(GTK_BUTTON_BOX(button_box), GTK_BUTTONBOX_SPREAD);
	ok_button = gtk_button_new_from_stock(GTK_STOCK_OK);
	cancel_button = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
	
	g_object_set_data(G_OBJECT(select_window), "multifilter", multifilter);
	g_object_set_data(G_OBJECT(select_window), "treeview", treeview);
	g_object_set_data(G_OBJECT(cancel_button), "window", select_window);
	g_object_set_data(G_OBJECT(ok_button), "window", select_window);

	g_signal_connect(G_OBJECT(ok_button), "pressed", 
			 G_CALLBACK(multifilter_window_get_selected_filters_on_ok_clicked), window);
	g_signal_connect(G_OBJECT(cancel_button), "pressed", 
			 G_CALLBACK(multifilter_window_get_selected_filters_on_cancel_clicked), window);	
     	g_signal_connect(G_OBJECT(select_window), "delete_event", 
			 G_CALLBACK(multifilter_window_get_selected_on_delete_event), multifilter);

	gtk_container_add(GTK_CONTAINER(select_window), vbox);
	gtk_box_pack_end(GTK_BOX(vbox), button_box, FALSE, TRUE, 5);
	gtk_box_pack_end(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 5);
	gtk_box_pack_end(GTK_BOX(vbox), label, FALSE, TRUE, 5);

	gtk_box_pack_end(GTK_BOX(button_box), cancel_button, FALSE, FALSE, 5);
	gtk_box_pack_end(GTK_BOX(button_box), ok_button, FALSE, FALSE, 5);
	gtk_widget_show(label);
	gtk_widget_show(scrolled_window);
	gtk_widget_show(treeview);
	gtk_widget_show(vbox);
	gtk_widget_show(button_box);
	gtk_widget_show(ok_button);
	gtk_widget_show(cancel_button);
	gtk_widget_show(select_window);
}

static void multifilter_window_get_selected_filters_on_cancel_clicked(GtkButton *button, multifilter_window_t *window)
{
	GtkWidget *select_window;
	seaudit_multifilter_t *multifilter;

	select_window = g_object_get_data(G_OBJECT(button), "window");
	g_assert(window);
	multifilter = g_object_get_data(G_OBJECT(select_window), "multifilter");
	g_assert(multifilter);
	seaudit_multifilter_destroy(multifilter);
	gtk_widget_destroy(select_window);
}

static void multifilter_window_get_selected_filters_on_ok_clicked(GtkButton *button, multifilter_window_t *window)
{
	GtkTreeView *treeview;
	GtkWindow *select_window;
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreePath *path;
	GList *glist, *item;
	llist_t *list;
	llist_node_t *node;
	seaudit_multifilter_t *multifilter;
	seaudit_filter_t **filters, *filter;
	filter_window_t *filter_window;
	int i, *index;

        select_window = g_object_get_data(G_OBJECT(button), "window");
	g_assert(select_window);
	treeview = g_object_get_data(G_OBJECT(select_window), "treeview");
	g_assert(treeview);
	multifilter = g_object_get_data(G_OBJECT(select_window), "multifilter");
	g_assert(multifilter);
	g_assert(multifilter->filters);
	filters = (seaudit_filter_t**)malloc(sizeof(seaudit_filter_t*) * multifilter->filters->num);
	if (!filters) {
		message_display(select_window, GTK_MESSAGE_ERROR, "out of memory");
		return;
	}
	memset(filters, 0, sizeof(seaudit_filter_t*)*multifilter->filters->num);
	list = multifilter->filters;
	i = 0;
	for (node = list->head; node != NULL; node = node->next)
		filters[i++] = (seaudit_filter_t*)node->data;
	model = gtk_tree_view_get_model(treeview);
	selection = gtk_tree_view_get_selection(treeview);
	glist = gtk_tree_selection_get_selected_rows(selection, &model);
	if (!glist) {
		message_display(select_window, GTK_MESSAGE_ERROR, "You must select a filter to import.");
		return;
	} else {
		for (item = glist; item != NULL; item = g_list_next(item)) {
			path = item->data;
			index = gtk_tree_path_get_indices(path);
			assert(index[0] >= 0 && index[0] < multifilter->filters->num);
			filter = filters[index[0]];
			assert(filter);
			filter_window = filter_window_create(window, window->num_filter_windows, filter->name);
			filter_window_set_values_from_filter(filter_window, filter);
			multifilter_window_add_filter_window(window, filter_window);
		}
	}
	free(filters);
	seaudit_multifilter_destroy(multifilter);
	g_list_foreach(glist, (GFunc)gtk_tree_path_free, NULL);
	g_list_free(glist);
	gtk_widget_destroy(GTK_WIDGET(select_window));
	multifilter_window_update_buttons_sensitivity(window);
}

static gboolean multifilter_window_get_selected_on_delete_event(GtkWidget *widget, GdkEvent *event, seaudit_multifilter_t *user_data)
{
	seaudit_multifilter_destroy(user_data);
	gtk_widget_destroy(widget);
	return TRUE;
}

static void multifilter_window_on_save_button_pressed(GtkButton *button, multifilter_window_t *user_data)
{
	multifilter_window_save_multifilter(user_data, FALSE, TRUE);
	
}
