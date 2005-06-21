/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr kcarr@tresys.com
 * Date:   June 14, 2005
 */

#include "sediff_gui.h"
#include "sediff_rename_types.h"
#include <libapol/policy.h>

static void sediff_rename_types_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data);
static gint sediff_str_compare_func(gconstpointer a, gconstpointer b);
static int sediff_rename_types_init(sediff_rename_types_t *rename_types);

/* 'Public' methods */

void sediff_rename_types_display_window(sediff_rename_types_t *rename_types)
{
	if (rename_types == NULL)
		return;
	if (rename_types->xml == NULL)
		sediff_rename_types_init(rename_types);

	gtk_window_present(rename_types->window);
}

sediff_rename_types_t*  sediff_rename_types_new(sediff_app_t *sediff_app)
{
	sediff_rename_types_t *rename_types = NULL;

	rename_types = (sediff_rename_types_t*)malloc(sizeof(sediff_rename_types_t));
	if (!rename_types) {
		g_warning("Out of memory!");
		exit(-1);
	}
	memset(rename_types, 0, sizeof(sediff_rename_types_t));
	rename_types->sediff_app = sediff_app;
	return rename_types;
}

void sediff_rename_types_unref_members(sediff_rename_types_t *rename_types)
{	
	if (rename_types == NULL)
		return;
	if (rename_types->xml) {
		g_object_unref(G_OBJECT(rename_types->xml));
		rename_types->xml = NULL;
	}
	if (rename_types->window) {
		gtk_widget_destroy(GTK_WIDGET(rename_types->window));
		rename_types->window = NULL;
	}
	rename_types->p1_combo = NULL;
	rename_types->p2_combo = NULL;
	rename_types->store = NULL;
	rename_types->view = NULL;
}

/* 'Private' methods */

static void sediff_rename_types_on_remove_button_clicked(GtkButton *button, gpointer user_data)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *dialog;
	sediff_rename_types_t *rename_types;
	char *p1_str, *p2_str;
	int p1_idx, p2_idx;

	rename_types = (sediff_rename_types_t*)user_data;
	g_assert(rename_types);
	selection = gtk_tree_view_get_selection(rename_types->view);
	if (gtk_tree_selection_get_selected(selection, &model, &iter) == FALSE) {
		dialog = gtk_message_dialog_new(rename_types->window, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, 
						"You must select an item to remove.");
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}
	gtk_tree_model_get(model, &iter, SEDIFF_RENAME_POLICY_ONE_COLUMN, &p1_str,
			   SEDIFF_RENAME_POLICY_TWO_COLUMN, &p2_str, -1);

	p1_idx = get_type_idx(p1_str, rename_types->sediff_app->p1);
	g_assert(p1_idx >= 0);
	p2_idx = get_type_idx(p2_str, rename_types->sediff_app->p2);
	g_assert(p2_idx >= 0);

	remove_alias(p1_idx, p2_str, rename_types->sediff_app->p1);
	remove_alias(p2_idx, p1_str, rename_types->sediff_app->p2);

	gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
}

static void sediff_rename_types_on_close_button_clicked(GtkButton *button, gpointer user_data)
{
	sediff_rename_types_t *rename_types;

	rename_types = (sediff_rename_types_t*)user_data;
	gtk_widget_hide(GTK_WIDGET(rename_types->window));
}

static void sediff_rename_types_on_add_button_clicked(GtkButton *button, gpointer user_data)
{
	GtkEntry *p1_entry, *p2_entry;
	GtkTreeIter iter;
	GtkListStore *store;
	GtkWidget *dialog;
	const char *p1_str, *p2_str;
	int p1_type, p2_type;
	sediff_rename_types_t *rename_types;

	/* cast user_data */
	rename_types = (sediff_rename_types_t*)user_data;
	g_assert(rename_types);

	/* validate the gui data is entered properly */
	p1_entry = GTK_ENTRY(glade_xml_get_widget(rename_types->xml, "sediff_rename_types_entry1"));
	g_assert(p1_entry);
	p2_entry = GTK_ENTRY(glade_xml_get_widget(rename_types->xml, "sediff_rename_types_entry2"));
	g_assert(p2_entry);
	
	p1_str = gtk_entry_get_text(p1_entry);
	p2_str = gtk_entry_get_text(p2_entry);

	if (strcmp(p1_str, "") == 0 || strcmp(p2_str, "") == 0) {
		dialog = gtk_message_dialog_new(rename_types->window, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, 
						"You must select a type from Policy 1 AND Policy 2 to continue.");
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	/* get the type indexes from the policies */
	p1_type = get_type_idx(p1_str, rename_types->sediff_app->p1);
	g_assert(p1_type >= 0);
	p2_type = get_type_idx(p2_str, rename_types->sediff_app->p2);
	g_assert(p2_type >= 0);

	/* show an error if the alias already exists in policy 1 */
	if (get_type_idx_by_alias_name(p2_str, rename_types->sediff_app->p1) >= 0) {
		dialog = gtk_message_dialog_new(rename_types->window, GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, 
						"Alias %s already exists in policy 1.", p2_str);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	/* show an error if the alias already exists in policy 2 */
	if (get_type_idx_by_alias_name(p1_str, rename_types->sediff_app->p2) >= 0) {
		dialog = gtk_message_dialog_new(rename_types->window, GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, 
						"Alias %s already exists in policy 2.", p1_str);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	add_alias(p2_type, p1_str, rename_types->sediff_app->p2);
	add_alias(p1_type, p2_str, rename_types->sediff_app->p1);

	/* add the rename to the display */
	store = GTK_LIST_STORE(gtk_tree_view_get_model(rename_types->view));
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, SEDIFF_RENAME_POLICY_ONE_COLUMN, p1_str, 
			                 SEDIFF_RENAME_POLICY_TWO_COLUMN, p2_str, -1);
}

static int sediff_rename_types_init(sediff_rename_types_t *rename_types)//, sediff_app_t *sediff_app)
{
	GList *items;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkButton *button;
	GString *path;
	int i;
	char *dir = NULL;

	if (rename_types == NULL)
		return -1;

	dir = find_file(GLADEFILE);
	if (!dir){
		fprintf(stderr, "Could not find %s!", GLADEFILE);
		return -1;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append_printf(path, "/%s", GLADEFILE);

	/* get the xml */
	rename_types->xml = glade_xml_new(path->str, RENAME_TYPES_DIALOG_ID, NULL);
	g_assert(rename_types->xml);
	g_string_free(path, TRUE);

	/* get a window reference from xml*/
	rename_types->window = GTK_WINDOW(glade_xml_get_widget(rename_types->xml, RENAME_TYPES_DIALOG_ID));
	g_assert(rename_types->window);
	gtk_window_set_transient_for(rename_types->window, rename_types->sediff_app->window);
	gtk_window_set_position(rename_types->window, GTK_WIN_POS_CENTER_ON_PARENT);

        /* connect to the window delete event */
	g_signal_connect(G_OBJECT(rename_types->window), "delete_event", 
			 G_CALLBACK(sediff_rename_types_dialog_on_window_destroy), rename_types);
	glade_xml_signal_autoconnect(rename_types->xml);

	/* connect the button events */
	button = GTK_BUTTON(glade_xml_get_widget(rename_types->xml, "sediff_rename_types_close_button"));
	g_signal_connect(G_OBJECT(button), "clicked", 
			 G_CALLBACK(sediff_rename_types_on_close_button_clicked), rename_types);
	button = GTK_BUTTON(glade_xml_get_widget(rename_types->xml, "sediff_rename_types_remove_button"));
	g_signal_connect(G_OBJECT(button), "clicked", 
			 G_CALLBACK(sediff_rename_types_on_remove_button_clicked), rename_types);
	button = GTK_BUTTON(glade_xml_get_widget(rename_types->xml, "sediff_rename_types_add_button"));
	g_signal_connect(G_OBJECT(button), "clicked", 
			 G_CALLBACK(sediff_rename_types_on_add_button_clicked), rename_types);

	/* get the combo boxes that we use */
        rename_types->p1_combo = GTK_COMBO(glade_xml_get_widget(rename_types->xml, "sediff_rename_types_combo1"));
        g_assert(rename_types->p1_combo);
	rename_types->p2_combo = GTK_COMBO(glade_xml_get_widget(rename_types->xml, "sediff_rename_types_combo2"));
	g_assert(rename_types->p2_combo);

	/* populate data into the combo boxes */
	items = g_list_alloc();
	for (i = 0; i < rename_types->sediff_app->p1->num_types; i++) {
		if (i == 0)
			continue; /* ignore self */
		g_list_append(items, rename_types->sediff_app->p1->types[i].name);
	}
	items = g_list_sort(items, &sediff_str_compare_func);
	gtk_combo_set_popdown_strings(GTK_COMBO(rename_types->p1_combo), items);
	g_list_free(items);

	items = g_list_alloc();
	for (i = 0; i < rename_types->sediff_app->p2->num_types; i++) {
		if (i == 0)
			continue; /* ignore self */
		g_list_append(items, rename_types->sediff_app->p2->types[i].name);
        }
	items = g_list_sort(items, &sediff_str_compare_func);
	gtk_combo_set_popdown_strings(GTK_COMBO(rename_types->p2_combo), items);
	g_list_free(items);
		
	/* get the listview */
	rename_types->view = GTK_TREE_VIEW(glade_xml_get_widget(rename_types->xml, "sediff_renamed_types_treeview"));
	g_assert(rename_types->view);

	/* create the list store */
	rename_types->store = gtk_list_store_new(SEDIFF_RENAME_NUM_COLUMNS, G_TYPE_STRING, G_TYPE_STRING);
	gtk_tree_view_set_model(rename_types->view, GTK_TREE_MODEL(rename_types->store));

	/* create columns */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes ("Policy 1 Types", renderer, "text", SEDIFF_RENAME_POLICY_ONE_COLUMN, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(rename_types->view), column);
		
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes ("Policy 2 Types", renderer, "text", SEDIFF_RENAME_POLICY_TWO_COLUMN, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(rename_types->view), column);

	return 0;
}

static void sediff_rename_types_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_hide(widget);
}

static gint sediff_str_compare_func(gconstpointer a, gconstpointer b)
{
	if (a == NULL)
		return -1;
	else if (b == NULL)
		return 1;
	return (gint)strcmp((const char*)a, (const char*)b);
}
