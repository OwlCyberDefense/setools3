/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date : January 22, 2004
 *
 */

#include "filtered_view.h"
#include "filter_window.h"
#include "utilgui.h"
#include <string.h>

static void filtered_view_on_do_filter_button_clicked(GtkButton *button, seaudit_filtered_view_t *filtered_view);

seaudit_filtered_view_t* seaudit_filtered_view_create(audit_log_t *log, GtkTreeView *tree_view)
{
	seaudit_filtered_view_t *filtered_view;

	if (tree_view == NULL)
		return NULL;

	filtered_view = (seaudit_filtered_view_t *)malloc(sizeof(seaudit_filtered_view_t));
	if (filtered_view == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}

	if ((filtered_view->filters = filters_create()) == NULL) {
		fprintf(stderr, "out of memory");
		free(filtered_view);
		return NULL;
	}
	if ((filtered_view->store = seaudit_log_view_store_create()) == NULL) {
		fprintf(stderr, "out of memory");
		free(filtered_view->filters);
		free(filtered_view);
		return NULL;
	}
	filtered_view->notebook_index = -1;
	filtered_view->tree_view = tree_view;
	seaudit_log_view_store_open_log(filtered_view->store, log);
	gtk_tree_view_set_model(tree_view, GTK_TREE_MODEL(filtered_view->store));

	return filtered_view;
}

void seaudit_filtered_view_display(seaudit_filtered_view_t* filtered_view)
{
	if (filtered_view->filters->window != NULL) {
		gtk_window_present(filtered_view->filters->window); 
		return;
	}

	filters_display(filtered_view->filters);
	glade_xml_signal_connect_data(filtered_view->filters->xml, "filtered_view_on_do_filter_button_clicked",
				      G_CALLBACK(filtered_view_on_do_filter_button_clicked),
				      filtered_view);
				      	
	filtered_view->store->log_view->fltr_out = TRUE;
	filtered_view->store->log_view->fltr_and = TRUE;
}

void seaudit_filtered_view_set_log(seaudit_filtered_view_t *view, audit_log_t *log)
{
	if (view == NULL)
		return ;
	seaudit_log_view_store_close_log(view->store);
	seaudit_log_view_store_open_log(view->store, log);
}

void seaudit_filtered_view_set_notebook_index(seaudit_filtered_view_t *filtered_view, gint index)
{
	if (filtered_view == NULL)
		return;
	filtered_view->notebook_index = index;
}

void seaudit_filtered_view_do_filter(seaudit_filtered_view_t *view, gpointer user_data)
{
	seaudit_log_view_store_do_filter(view->store);
}

static void filtered_view_on_do_filter_button_clicked(GtkButton *button, seaudit_filtered_view_t *filtered_view)
{
	GtkWidget *widget;
	GtkWidget *window;
	GtkTreeIter iter;
	GladeXML *xml;
	SEAuditLogViewStore *store;
	seaudit_filter_list_t *items_list = NULL;
	filter_t *filter;
	char *text;
	int int_val;
	
	window = GTK_WIDGET(filtered_view->filters->window);
	g_assert(window);
	show_wait_cursor(window);	
	
	audit_log_view_purge_filters(filtered_view->store->log_view);
	store = filtered_view->store;

	/* Result message value */
	xml = filtered_view->filters->xml;
	widget = glade_xml_get_widget(xml, "ResultComboEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "SHOW messages that match ALL criteria") == 0) {
		store->log_view->fltr_out = FALSE;
		store->log_view->fltr_and = TRUE;
	} else if (strcmp(text, "SHOW messages that match ANY criteria") == 0) {
		store->log_view->fltr_out = FALSE;
		store->log_view->fltr_and = FALSE;
	} else if (strcmp(text, "HIDE messages that match ALL criteria") == 0) {
		store->log_view->fltr_out = TRUE;
		store->log_view->fltr_and = TRUE;
	} else if (strcmp(text, "HIDE messages that match ANY criteria") == 0) {
		store->log_view->fltr_out = TRUE;
		store->log_view->fltr_and = FALSE;
	} else {
		message_display(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Invalid results message combobox value.\n");
		return;		
	}
	
	/* check for src type filter */
	filters_select_items_parse_entry(filtered_view->filters->src_types_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filtered_view->filters->src_types_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_get(filtered_view->filters->src_types_items);
		if (items_list == NULL) 
			return;
		filter = src_type_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_view_add_filter(store->log_view, filter);	
	}

	/* check for tgt type filter */
	filters_select_items_parse_entry(filtered_view->filters->tgt_types_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filtered_view->filters->tgt_types_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_get(filtered_view->filters->tgt_types_items);
		if (items_list == NULL) 
			return;
		filter = tgt_type_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_view_add_filter(store->log_view, filter);
	}
	/* check for obj class filter */
	filters_select_items_parse_entry(filtered_view->filters->obj_class_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filtered_view->filters->obj_class_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_get(filtered_view->filters->obj_class_items);
		if (items_list == NULL) 
			return;
		filter = class_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_view_add_filter(store->log_view, filter);
	}

	/* check for src user filter */
	filters_select_items_parse_entry(filtered_view->filters->src_users_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filtered_view->filters->src_users_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_get(filtered_view->filters->src_users_items);
		if (items_list == NULL) 
			return;
		filter = src_user_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_view_add_filter(store->log_view, filter);
	}

	/* check for src role filter */
	filters_select_items_parse_entry(filtered_view->filters->src_roles_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filtered_view->filters->src_roles_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_get(filtered_view->filters->src_roles_items);
		if (items_list == NULL) 
			return;
		filter = src_role_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_view_add_filter(store->log_view, filter);
	}

	/* check for tgt user filter */
	filters_select_items_parse_entry(filtered_view->filters->tgt_users_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filtered_view->filters->tgt_users_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_get(filtered_view->filters->tgt_users_items);
		if (items_list == NULL) 
			return;
		filter = tgt_user_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_view_add_filter(store->log_view, filter);
	}

	/* check for tgt role filter */
	filters_select_items_parse_entry(filtered_view->filters->tgt_roles_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filtered_view->filters->tgt_roles_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_get(filtered_view->filters->tgt_roles_items);
		if (items_list == NULL) 
			return;
		filter = tgt_role_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_view_add_filter(store->log_view, filter);
	}
	
	/* check for network address filter */
	widget = glade_xml_get_widget(xml, "IPAddressEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		filter = ipaddr_filter_create(text);
		audit_log_view_add_filter(store->log_view, filter);
	}

	/* check for network port filter */
	widget = glade_xml_get_widget(xml, "PortEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		int_val = atoi(text);
		filter = ports_filter_create(int_val);
		audit_log_view_add_filter(store->log_view, filter);
	}
	
	/* check for network interface filter */
	widget = glade_xml_get_widget(xml, "InterfaceEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		filter = netif_filter_create(text);
		audit_log_view_add_filter(store->log_view, filter);
	}
	
	/* check for executable filter */
	widget = glade_xml_get_widget(xml, "ExeEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		filter = exe_filter_create(text);
		audit_log_view_add_filter(store->log_view, filter);
	}
	
	/* check for path filter */
	widget = glade_xml_get_widget(xml, "PathEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		filter = path_filter_create(text);
		audit_log_view_add_filter(store->log_view, filter);
	}
	
	show_wait_cursor(window);

	/* do the filter on the model */
 	seaudit_log_view_store_do_filter(store);
	clear_wait_cursor(window);
}
