/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date : January 22, 2004
 *
 */

#include "seaudit_window.h"
#include "seaudit.h"
#include "utilgui.h"
#include "query_window.h"
#include <string.h>

static int seaudit_window_view_matches_tab_index(gconstpointer data, gconstpointer index);
static int seaudit_window_create_list(GtkTreeView *view, bool_t visibility[]);
static GtkTreeViewColumn *seaudit_window_create_column(GtkTreeView *view, const char *name,
						       GtkCellRenderer *renderer, int field,
						       int max_width, bool_t visibility[]);
static void seaudit_window_on_log_column_clicked(GtkTreeViewColumn *column, gpointer user_data);
static void seaudit_window_on_log_row_activated(GtkTreeView *treeview, GtkTreePath *path, GtkTreeViewColumn *col, gpointer user_data);
static void seaudit_window_close_view(GtkButton *button, seaudit_window_t *window);
static void seaudit_window_on_notebook_switch_page(GtkNotebook *notebook, GtkNotebookPage *page, guint pagenum, seaudit_window_t *window);

extern seaudit_t *seaudit_app;

/*
 * seaudit_window_t public functions
 */
seaudit_window_t* seaudit_window_create(audit_log_t *log, bool_t column_visibility[])
{
	seaudit_window_t *window;
	GString *path; 
	char *dir;
	GtkWidget *vbox;

	dir = find_file("seaudit.glade");
	if (!dir){
		fprintf(stderr, "could not find seaudit.glade\n");
		return NULL;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/seaudit.glade");

	window = malloc(sizeof(seaudit_window_t));
	if (!window) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	memset(window, 0, sizeof(seaudit_window_t));
	window->xml = glade_xml_new(path->str, NULL, NULL);
	window->window = GTK_WINDOW(glade_xml_get_widget(window->xml, "TopWindow"));
	window->notebook = GTK_NOTEBOOK(gtk_notebook_new());
	g_signal_connect_after(G_OBJECT(window->notebook), "switch-page", 
			 G_CALLBACK(seaudit_window_on_notebook_switch_page), window);
	vbox = glade_xml_get_widget(window->xml, "NotebookVBox");
	gtk_container_add(GTK_CONTAINER(vbox), GTK_WIDGET(window->notebook));
	gtk_widget_show(GTK_WIDGET(window->notebook));
	seaudit_window_add_new_view(window, log, column_visibility, NULL);

	/* connect signal handlers */
	glade_xml_signal_autoconnect(window->xml);
	return window;
}

seaudit_filtered_view_t* seaudit_window_add_new_view(seaudit_window_t *window, audit_log_t *log, bool_t *column_visibility, const char *view_name)
{
	seaudit_filtered_view_t *view;
	GtkWidget *scrolled_window, *tree_view, *button, *label;
	gint page_index;
	GtkWidget *hbox, *image;
	char tab_title[24];
	GtkTreeSelection  *selection;

	if (window == NULL)
		return NULL;
	if (window->window == NULL || window->notebook == NULL || window->xml == NULL)
		return NULL;
		
	show_wait_cursor(GTK_WIDGET(window->window));
	scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	tree_view = gtk_tree_view_new();
	
	/* Set selection mode for tree view to multiple selection. */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	
	g_signal_connect(G_OBJECT(tree_view), "row_activated", G_CALLBACK(seaudit_window_on_log_row_activated), NULL);
	gtk_container_add(GTK_CONTAINER(scrolled_window), tree_view);
	seaudit_window_create_list(GTK_TREE_VIEW(tree_view), column_visibility);
	                  
	if (view_name == NULL) {
		window->num_untitled_views++;
		snprintf(tab_title, 24, "Untitled %d", window->num_untitled_views);
		view_name = tab_title;
	}
	view = seaudit_filtered_view_create(log, GTK_TREE_VIEW(tree_view), view_name);
	hbox = gtk_hbox_new(FALSE, 5);
	button = gtk_button_new();
	g_object_set_data(G_OBJECT(button), "view", view);
	image = gtk_image_new_from_stock(GTK_STOCK_CLOSE, GTK_ICON_SIZE_MENU);
	gtk_container_add(GTK_CONTAINER(button), image);
	gtk_widget_set_size_request(image, 8, 8);
	g_signal_connect(G_OBJECT(button), "pressed", G_CALLBACK(seaudit_window_close_view), window);
	label = gtk_label_new(view_name);
	g_object_set_data(G_OBJECT(hbox), "label", label);
	gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 5);
	gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 5);
	gtk_notebook_append_page(window->notebook, GTK_WIDGET(scrolled_window), hbox);
	gtk_widget_show(label);
	gtk_widget_show(button);
	gtk_widget_show(image);
	gtk_widget_show(scrolled_window);
	gtk_widget_show(tree_view);
	page_index = gtk_notebook_get_n_pages(window->notebook)-1;
	seaudit_filtered_view_set_notebook_index(view, page_index);
	window->views = g_list_append(window->views, view);
	gtk_notebook_set_current_page(window->notebook, page_index);
		
	clear_wait_cursor(GTK_WIDGET(window->window));
	return view;
}

void seaudit_window_open_view(seaudit_window_t *window, audit_log_t *log, bool_t *column_visibility)
{
	multifilter_window_t *multifilter_window;
	seaudit_filtered_view_t *view;

	if (!window)
		return;
	multifilter_window = multifilter_window_create(NULL, NULL);
	if (multifilter_window_load_multifilter(multifilter_window) != 0) {
		multifilter_window_destroy(multifilter_window);
		return;
	}
	if (strcmp(multifilter_window->name->str, "") != 0)
		view = seaudit_window_add_new_view(window, log, column_visibility, multifilter_window->name->str);
	else 
		view = seaudit_window_add_new_view(window, log, column_visibility, NULL);

	seaudit_filtered_view_set_multifilter_window(view, multifilter_window);
	seaudit_filtered_view_do_filter(view, NULL);
}

int seaudit_window_get_num_views(seaudit_window_t *window)
{
	if (!window)
		return -1;
	return gtk_notebook_get_n_pages(window->notebook);
}

void seaudit_window_save_current_view(seaudit_window_t *window, gboolean saveas)
{
	seaudit_filtered_view_t *view;

	if (!window)
		return;
	view = seaudit_window_get_current_view(window);
	g_assert(view);
	seaudit_filtered_view_save_view(view, saveas);
}

seaudit_filtered_view_t* seaudit_window_get_current_view(seaudit_window_t *window)
{
	gint index;
	GList *node;

	if (!window)
		return NULL;
	index = gtk_notebook_get_current_page(window->notebook);
	node = g_list_find_custom(window->views, GINT_TO_POINTER(index), &seaudit_window_view_matches_tab_index);
	if (!node) {
		return NULL;
	}
	return node->data;
}

void seaudit_window_filter_views(seaudit_window_t *window)
{
	if (!window)
		return;
	g_list_foreach(window->views, (GFunc)seaudit_filtered_view_do_filter, NULL);
}


/*
 * Helper function for seaudit_window_t object
 */
static int seaudit_window_view_matches_tab_index(gconstpointer data, gconstpointer index)
{
	seaudit_filtered_view_t *view;
	if (!data) {
		return -1;
	}
	view = (seaudit_filtered_view_t*) data;
	if (view->notebook_index == GPOINTER_TO_INT(index))
		return 0;
	return 1;
}

/*
 * Gtk Callbacks registered by seaudit_window_t
 */
static void seaudit_window_on_log_column_clicked(GtkTreeViewColumn *column, gpointer user_data)
{
	GtkTreeSelection *selection;
	GList *selected_rows;
	GtkTreePath *path;
	GtkTreeModel *model;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(user_data));
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(user_data));
	selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
	if (selected_rows == NULL)
		return;
	path = selected_rows->data;
	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(user_data), 
				     path, NULL, FALSE, 0.0, 0.0);
}

static void seaudit_window_on_log_row_activated(GtkTreeView *treeview, GtkTreePath *path, GtkTreeViewColumn *col, gpointer user_data)
{
	query_window_create();
}

static void seaudit_window_on_notebook_switch_page(GtkNotebook *notebook, GtkNotebookPage *page, guint pagenum, seaudit_window_t *window)
{
	seaudit_update_status_bar(seaudit_app);

}

/*
 * Functions to setup a treeview widget for log viewing
 */
static GtkTreeViewColumn *seaudit_window_create_column(GtkTreeView *view, const char *name,
						       GtkCellRenderer *renderer, int field,
						       int max_width, bool_t visibility[])
{
	GtkTreeViewColumn *column;
	
	column = gtk_tree_view_column_new_with_attributes(name, renderer, "text", field, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_clickable (column, TRUE);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sort_column_id(column, field);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_fixed_width(column, max_width);
	gtk_tree_view_column_set_visible(column, visibility[field]);
	g_signal_connect_after(G_OBJECT(column), "clicked", G_CALLBACK(seaudit_window_on_log_column_clicked),
			       view);
	return column;
}

static void seaudit_window_close_view(GtkButton *button, seaudit_window_t *window)
{
	seaudit_filtered_view_t *view;
	GList *item;
	gint index;

	if (!window)
		return;

	if (gtk_notebook_get_n_pages(window->notebook) <= 1)
		return;

	view = g_object_get_data(G_OBJECT(button), "view");
	g_assert(view);
	index = view->notebook_index;
	item = g_list_find(window->views, view);
	window->views = g_list_remove_link(window->views, item);
	seaudit_filtered_view_destroy(item->data);
	g_list_free(item);
	gtk_notebook_remove_page(window->notebook, index);
	for (item = window->views; item != NULL; item = g_list_next(item)){
		view = (seaudit_filtered_view_t*)item->data;
		if (view->notebook_index >= index)
			view->notebook_index--;
	}
}

static int seaudit_window_create_list(GtkTreeView *view, bool_t visibility[])
{
	GtkCellRenderer *renderer;
	PangoLayout *layout;
	GtkTreeViewColumn *column;
	int width;

	gtk_tree_view_set_rules_hint(view, TRUE);
	renderer = gtk_cell_renderer_text_new();
	g_object_set(G_OBJECT(renderer), "xpad", 8, NULL);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Hostname");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Hostname", renderer, HOST_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Message");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Message", renderer, AVC_MSG_FIELD, width, visibility);
	
	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Sep 16 10:51:20");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Date", renderer, DATE_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Source");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Source\nUser", renderer, AVC_SRC_USER_FIELD, width, visibility);
	seaudit_window_create_column(view, "Source\nRole", renderer, AVC_SRC_ROLE_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "unlabeled_t");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Source\nType", renderer, AVC_SRC_TYPE_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Source");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Target\nUser", renderer, AVC_TGT_USER_FIELD, width, visibility);
	seaudit_window_create_column(view, "Target\nRole", renderer, AVC_TGT_ROLE_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "unlabeled_t");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Target\nType", renderer, AVC_TGT_TYPE_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Object  ");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Object\nClass", renderer, AVC_OBJ_CLASS_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Permission");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Permission", renderer, AVC_PERM_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "/usr/bin/cat");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Executable", renderer, AVC_EXE_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "12345");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "PID", renderer, AVC_PID_FIELD, width, visibility);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "123456");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Inode", renderer, AVC_INODE_FIELD, width, visibility);
	
	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "/home/username/foo");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	seaudit_window_create_column(view, "Path", renderer, AVC_PATH_FIELD, width, visibility);

	column = gtk_tree_view_column_new_with_attributes("Other", renderer, "text", AVC_MISC_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_clickable (column, FALSE);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_GROW_ONLY);
	gtk_tree_view_column_set_sort_column_id(column, AVC_MISC_FIELD );
	gtk_tree_view_column_set_sort_indicator(column, FALSE);
	gtk_tree_view_column_set_visible(column, visibility[AVC_MISC_FIELD]);

	return 0;
}
