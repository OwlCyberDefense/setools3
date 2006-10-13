/**
 *  @file sediff_remap_types.c
 *  Displays a dialog that allows users to explicitly remap/remap
 *  types from one policy to the other.
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

#include "sediff_gui.h"
#include "sediff_remap_types.h"
#include <apol/policy.h>
#include <apol/util.h>
#include <string.h>

static void sediff_remap_types_window_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data);
static gint sediff_str_compare_func(gconstpointer a, gconstpointer b);
static int sediff_remap_types_window_init(sediff_remap_types_t *remap_types_window);

void sediff_remap_types_window_display(sediff_remap_types_t *remap_types_window)
{
	if (remap_types_window == NULL)
		return;
	if (remap_types_window->xml == NULL)
		sediff_remap_types_window_init(remap_types_window);

	gtk_window_present(remap_types_window->window);
}

sediff_remap_types_t*  sediff_remap_types_window_new(sediff_app_t *sediff_app)
{
	sediff_remap_types_t *remap_types_window = NULL;

	remap_types_window = (sediff_remap_types_t*)calloc(1, sizeof(sediff_remap_types_t));
	if (!remap_types_window) {
		g_warning("Out of memory!");
		goto err;
	}
	remap_types_window->sediff_app = sediff_app;
	remap_types_window->remapped_types = apol_vector_create();
	if (remap_types_window->remapped_types == NULL) {
		g_warning("Out of memory!");
		goto err;
	}
exit:
	return remap_types_window;
err:
	if (remap_types_window) {
		if (remap_types_window->remapped_types) 
			apol_vector_destroy(&remap_types_window->remapped_types, NULL);
		free(remap_types_window);
		remap_types_window = NULL;
	}
	goto exit;
}

void sediff_remap_types_window_unref_members(sediff_remap_types_t *remap_types_window)
{
	if (remap_types_window == NULL)
		return;
	if (remap_types_window->xml) {
		g_object_unref(G_OBJECT(remap_types_window->xml));
		remap_types_window->xml = NULL;
	}
	if (remap_types_window->window) {
		gtk_widget_destroy(GTK_WIDGET(remap_types_window->window));
		remap_types_window->window = NULL;
	}
	if (remap_types_window->remapped_types){
		apol_vector_destroy(&remap_types_window->remapped_types, NULL);
	}
	remap_types_window->p1_combo = NULL;
	remap_types_window->p2_combo = NULL;
	remap_types_window->store = NULL;
	remap_types_window->view = NULL;
}

/* static functions */
static int sediff_remap_types_remove(poldiff_t *diff, char *orig_name, char *mod_name) {
	int i;
	apol_vector_t *entry_vector, *orig, *mod;

	entry_vector = poldiff_type_remap_get_entries(diff);
	for (i=0;i<apol_vector_get_size(entry_vector);i++) {
		poldiff_type_remap_entry_t *entry;
		char *entry_orig_name, *entry_mod_name;
		
		entry = apol_vector_get_element(entry_vector, i);
		orig = poldiff_type_remap_entry_get_original_types(diff, entry);
		mod = poldiff_type_remap_entry_get_modified_types(diff, entry);
		entry_orig_name = apol_vector_get_element(orig, 0);
		entry_mod_name = apol_vector_get_element(mod, 0);
		if (!strcmp(orig_name, entry_orig_name) && 
		    !strcmp(mod_name, entry_mod_name)) {
			poldiff_type_remap_entry_remove(diff, entry);
			return 1;
		}
	}
	return 0;
}
	
static void sediff_remap_types_window_on_remove_button_clicked(GtkButton *button, gpointer user_data)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *dialog;
	sediff_remap_types_t *remap_types_window;
	char *p1_str, *p2_str;

	remap_types_window = (sediff_remap_types_t*)user_data;
	g_assert(remap_types_window);
	selection = gtk_tree_view_get_selection(remap_types_window->view);
	if (gtk_tree_selection_get_selected(selection, &model, &iter) == FALSE) {
		dialog = gtk_message_dialog_new(remap_types_window->window, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
						"You must select an item to remove.");
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}
	gtk_tree_model_get(model, &iter, SEDIFF_REMAP_POLICY_ONE_COLUMN, &p1_str,
			   SEDIFF_REMAP_POLICY_TWO_COLUMN, &p2_str, -1);

	if (sediff_remap_types_remove(remap_types_window->sediff_app->diff, (char *)p1_str, (char *)p2_str) == 0) {
		dialog = gtk_message_dialog_new(remap_types_window->window, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
						"Could not remove the selected item.");
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
}

static void sediff_remap_types_window_on_close_button_clicked(GtkButton *button, gpointer user_data)
{
	sediff_remap_types_t *remap_types_window;
	apol_vector_t *remap_vector;
	int i;

	remap_types_window = (sediff_remap_types_t*)user_data;
	gtk_widget_hide(GTK_WIDGET(remap_types_window->window));
	remap_vector = poldiff_type_remap_get_entries(remap_types_window->sediff_app->diff);
	for (i=0;i<apol_vector_get_size(remap_vector);i++) {
		poldiff_type_remap_entry_t *entry;
		
		entry = apol_vector_get_element(remap_vector, i);
		poldiff_type_remap_entry_set_enabled(entry, 1);
	}
}

static void sediff_remap_types_window_on_add_button_clicked(GtkButton *button, gpointer user_data)
{
	GtkEntry *p1_entry, *p2_entry;
	GtkTreeIter iter;
	GtkListStore *store;
	GtkWidget *dialog;
	const char *p1_str, *p2_str;
	sediff_remap_types_t *remap_types_window;
	apol_vector_t *orig, *mod;
	qpol_type_t *orig_type, *mod_type;

	/* cast user_data */
	remap_types_window = (sediff_remap_types_t*)user_data;
	g_assert(remap_types_window);

	/* validate the gui data is entered properly */
	p1_entry = GTK_ENTRY(glade_xml_get_widget(remap_types_window->xml, "sediff_remap_types_entry1"));
	g_assert(p1_entry);
	p2_entry = GTK_ENTRY(glade_xml_get_widget(remap_types_window->xml, "sediff_remap_types_entry2"));
	g_assert(p2_entry);

	p1_str = gtk_entry_get_text(p1_entry);
	p2_str = gtk_entry_get_text(p2_entry);

	if (strcmp(p1_str, "") == 0 || strcmp(p2_str, "") == 0) {
		dialog = gtk_message_dialog_new(remap_types_window->window, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
						"You must select a type from Policy 1 AND Policy 2 to continue.");
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	qpol_policy_get_type_by_name(remap_types_window->sediff_app->orig_pol->p, p1_str, &orig_type);
	qpol_policy_get_type_by_name(remap_types_window->sediff_app->mod_pol->p, p2_str, &mod_type);
	
	orig = apol_vector_create();
	mod = apol_vector_create();
	apol_vector_append(orig, (void *)p1_str);
	apol_vector_append(mod,  (void *)p2_str);
	poldiff_type_remap_create(remap_types_window->sediff_app->diff, orig, mod);
	store = GTK_LIST_STORE(gtk_tree_view_get_model(remap_types_window->view));
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, SEDIFF_REMAP_POLICY_ONE_COLUMN, p1_str,
			   SEDIFF_REMAP_POLICY_TWO_COLUMN, p2_str, -1);
}

static int sediff_remap_types_window_init(sediff_remap_types_t *remap_types_window)
{
	GList *items;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkButton *button;
	GString *path;
	int i;
	char *dir=NULL;
	apol_vector_t *type_vector;

	if (remap_types_window == NULL)
		return -1;

	dir = apol_file_find(GLADEFILE);
	if (!dir){
		fprintf(stderr, "Could not find %s!", GLADEFILE);
		return -1;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append_printf(path, "/%s", GLADEFILE);

	/* get the xml */
	remap_types_window->xml = glade_xml_new(path->str, REMAP_TYPES_DIALOG_ID, NULL);
	g_assert(remap_types_window->xml);
	g_string_free(path, TRUE);

	/* get a window reference from xml*/
	remap_types_window->window = GTK_WINDOW(glade_xml_get_widget(remap_types_window->xml, REMAP_TYPES_DIALOG_ID));
	g_assert(remap_types_window->window);
	gtk_window_set_transient_for(remap_types_window->window, remap_types_window->sediff_app->window);
	gtk_window_set_position(remap_types_window->window, GTK_WIN_POS_CENTER_ON_PARENT);

        /* connect to the window delete event */
	g_signal_connect(G_OBJECT(remap_types_window->window), "delete_event",
			 G_CALLBACK(sediff_remap_types_window_dialog_on_window_destroy), remap_types_window);
	glade_xml_signal_autoconnect(remap_types_window->xml);

	/* connect the button events */
	button = GTK_BUTTON(glade_xml_get_widget(remap_types_window->xml, "sediff_remap_types_close_button"));
	g_signal_connect(G_OBJECT(button), "clicked",
			 G_CALLBACK(sediff_remap_types_window_on_close_button_clicked), remap_types_window);
	button = GTK_BUTTON(glade_xml_get_widget(remap_types_window->xml, "sediff_remap_types_remove_button"));
	g_signal_connect(G_OBJECT(button), "clicked",
			 G_CALLBACK(sediff_remap_types_window_on_remove_button_clicked), remap_types_window);
	button = GTK_BUTTON(glade_xml_get_widget(remap_types_window->xml, "sediff_remap_types_add_button"));
	g_signal_connect(G_OBJECT(button), "clicked",
			 G_CALLBACK(sediff_remap_types_window_on_add_button_clicked), remap_types_window);

	/* get the combo boxes that we use */
        remap_types_window->p1_combo = GTK_COMBO(glade_xml_get_widget(remap_types_window->xml, "sediff_remap_types_combo1"));
        g_assert(remap_types_window->p1_combo);
	remap_types_window->p2_combo = GTK_COMBO(glade_xml_get_widget(remap_types_window->xml, "sediff_remap_types_combo2"));
	g_assert(remap_types_window->p2_combo);

	/* populate data into the combo boxes */
	items = g_list_alloc();
	apol_get_type_by_query(remap_types_window->sediff_app->orig_pol, NULL, &type_vector);
	for (i=0; i<apol_vector_get_size(type_vector); i++) {
		qpol_type_t *type = NULL, *t = NULL; 
		char *type_name;
		
		type = apol_vector_get_element(type_vector, i);
		qpol_type_get_name(remap_types_window->sediff_app->orig_pol->p, type, &type_name);
		g_assert(type_name != NULL);
		qpol_policy_get_type_by_name(remap_types_window->sediff_app->mod_pol->p, type_name, &t);
		if (!t)
			items = g_list_append(items, type_name);
	}

	items = g_list_sort(items, &sediff_str_compare_func);
	gtk_combo_set_popdown_strings(GTK_COMBO(remap_types_window->p1_combo), items);
	g_list_free(items);

	items = g_list_alloc();
        apol_get_type_by_query(remap_types_window->sediff_app->mod_pol, NULL, &type_vector);
        for (i=0; i<apol_vector_get_size(type_vector); i++) {
                qpol_type_t *type = NULL, *t = NULL;
                char *type_name;

                type = apol_vector_get_element(type_vector, i);
                qpol_type_get_name(remap_types_window->sediff_app->mod_pol->p, type, &type_name);
                g_assert(type_name != NULL);
                qpol_policy_get_type_by_name(remap_types_window->sediff_app->orig_pol->p,type_name, &t);
                if (!t)
                        items = g_list_append(items, type_name);
        }

	items = g_list_sort(items, &sediff_str_compare_func);
	gtk_combo_set_popdown_strings(GTK_COMBO(remap_types_window->p2_combo), items);
	g_list_free(items);

	/* get the listview */
	remap_types_window->view = GTK_TREE_VIEW(glade_xml_get_widget(remap_types_window->xml, "sediff_remapped_types_treeview"));
	g_assert(remap_types_window->view);

	/* create the list store */
	remap_types_window->store = gtk_list_store_new(SEDIFF_REMAP_NUM_COLUMNS, G_TYPE_STRING, G_TYPE_STRING);
	gtk_tree_view_set_model(remap_types_window->view, GTK_TREE_MODEL(remap_types_window->store));

	/* create columns */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes ("Policy 1 Types", renderer, "text", SEDIFF_REMAP_POLICY_ONE_COLUMN, NULL);
	gtk_tree_view_column_set_expand(column, TRUE);
	gtk_tree_view_append_column(GTK_TREE_VIEW(remap_types_window->view), column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes ("Policy 2 Types", renderer, "text", SEDIFF_REMAP_POLICY_TWO_COLUMN, NULL);
	gtk_tree_view_column_set_expand(column, TRUE);
	gtk_tree_view_append_column(GTK_TREE_VIEW(remap_types_window->view), column);

	/* create the remap types structure*/
	if (remap_types_window->remapped_types == NULL) 
		remap_types_window->remapped_types = apol_vector_create();
	return 0;
}

static void sediff_remap_types_window_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data)
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
