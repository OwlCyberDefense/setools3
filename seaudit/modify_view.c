/**
 *  @file
 *  Run the dialog to modify a view.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include "filter_view.h"
#include "modify_view.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <glade/glade.h>

struct modify_view
{
	toplevel_t *top;
	message_view_t *view;
	GladeXML *xml;
	/** the model currently being modified -- note that this is a
         * deep copy of the message_view's model */
	seaudit_model_t *model;

	/** model containing a list of filter names, needs to be
         * destroyed afterwords */
	GtkListStore *filter_store;
	GtkDialog *dialog;
	GtkEntry *name_entry;
	GtkComboBox *visible_combo, *match_combo;
	GtkTreeView *filter_view;
	GtkButton *add_button, *edit_button, *remove_button, *import_button, *export_button;

	/** keep track of most recent filter filename */
	char *filter_filename;
};

/**
 * Return the currently selected filter, or NULL if no filter is
 * selected.
 */
static seaudit_filter_t *modify_view_get_current_filter(struct modify_view *mv)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(mv->filter_view);
	GtkTreeIter iter;
	seaudit_filter_t *filter;
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		return NULL;
	}
	gtk_tree_model_get(GTK_TREE_MODEL(mv->filter_store), &iter, 0, &filter, -1);
	return filter;
}

/**
 * Rebuild the filter store, preserving the current selection if
 * possible.
 */
static void modify_view_update_filter_store(struct modify_view *mv)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(mv->filter_view);
	GtkTreeIter old_iter, iter;
	gboolean selection_existed = gtk_tree_selection_get_selected(selection, NULL, &old_iter);
	const apol_vector_t *filters = seaudit_model_get_filters(mv->model);
	size_t i;
	gtk_list_store_clear(mv->filter_store);
	for (i = 0; i < apol_vector_get_size(filters); i++) {
		seaudit_filter_t *filter = apol_vector_get_element(filters, i);
		gtk_list_store_append(mv->filter_store, &iter);
		gtk_list_store_set(mv->filter_store, &iter, 0, filter, 1, seaudit_filter_get_name(filter), -1);
	}
	/* initially select the last thing, then reset selection */
	if (i > 0) {
		gtk_tree_selection_select_iter(selection, &iter);
	}
	if (selection_existed && gtk_list_store_iter_is_valid(mv->filter_store, &old_iter)) {
		gtk_tree_selection_select_iter(selection, &old_iter);
	}
}

static void modify_view_on_selection_change(GtkTreeSelection * selection, gpointer user_data)
{
	struct modify_view *mv = (struct modify_view *)user_data;
	gboolean sens = gtk_tree_selection_get_selected(selection, NULL, NULL);
	gtk_widget_set_sensitive(GTK_WIDGET(mv->edit_button), sens);
	gtk_widget_set_sensitive(GTK_WIDGET(mv->remove_button), sens);
	gtk_widget_set_sensitive(GTK_WIDGET(mv->export_button), sens);
}

static void modify_view_on_add_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct modify_view *mv = (struct modify_view *)user_data;
	seaudit_filter_t *filter = NULL;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(mv->filter_view);

	if ((filter = seaudit_filter_create("Untitled")) == NULL || (seaudit_model_append_filter(mv->model, filter) < 0)) {
		toplevel_ERR(mv->top, "Error adding new filter: %s", strerror(errno));
		seaudit_filter_destroy(&filter);
		return;
	}
	/* select the filter that was just created, by removing the
	 * selection and letting the following function select it */
	gtk_tree_selection_unselect_all(selection);
	modify_view_update_filter_store(mv);
	filter_view_run(filter, mv->top, GTK_WINDOW(mv->dialog));
	modify_view_update_filter_store(mv);
}

static void modify_view_on_edit_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct modify_view *mv = (struct modify_view *)user_data;
	seaudit_filter_t *filter = modify_view_get_current_filter(mv);
	assert(filter != NULL);
	filter_view_run(filter, mv->top, GTK_WINDOW(mv->dialog));
	modify_view_update_filter_store(mv);
}

static void modify_view_on_remove_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct modify_view *mv = (struct modify_view *)user_data;
	seaudit_filter_t *filter = modify_view_get_current_filter(mv);
	assert(filter != NULL);
	seaudit_model_remove_filter(mv->model, filter);
	modify_view_update_filter_store(mv);
}

static void modify_view_on_import_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct modify_view *mv = (struct modify_view *)user_data;
	apol_vector_t *paths = util_open_file(GTK_WINDOW(mv->dialog), "Import Filter", mv->filter_filename, 0);
	apol_vector_t *filters;
	size_t i;
	if (paths == NULL) {
		return;
	}
	free(mv->filter_filename);
	if ((mv->filter_filename = strdup(apol_vector_get_element(paths, 0))) == NULL) {
		toplevel_ERR(mv->top, "Error importing filter: %s", strerror(errno));
		apol_vector_destroy(&paths);
		return;
	}
	apol_vector_destroy(&paths);
	if ((filters = seaudit_filter_create_from_file(mv->filter_filename)) == NULL) {
		toplevel_ERR(mv->top, "Error importing filter: %s", strerror(errno));
		apol_vector_destroy(&paths);
		return;
	}
	for (i = 0; i < apol_vector_get_size(filters); i++) {
		seaudit_filter_t *filter = apol_vector_get_element(filters, i);
		seaudit_filter_t *new_f = NULL;
		if ((new_f = seaudit_filter_create_from_filter(filter)) == NULL ||
		    seaudit_model_append_filter(mv->model, new_f) < 0) {
			toplevel_ERR(mv->top, "Error importing filter: %s", strerror(errno));
			seaudit_filter_destroy(&new_f);
			apol_vector_destroy(&filters);
			return;
		}
		modify_view_update_filter_store(mv);
	}
	apol_vector_destroy(&filters);
}

static void modify_view_on_export_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct modify_view *mv = (struct modify_view *)user_data;
	char *path = util_save_file(GTK_WINDOW(mv->dialog), "Export Filter", mv->filter_filename);
	seaudit_filter_t *filter = modify_view_get_current_filter(mv);
	assert(filter != NULL);
	if (path == NULL) {
		return;
	}
	g_free(mv->filter_filename);
	mv->filter_filename = path;
	if (seaudit_filter_save_to_file(filter, mv->filter_filename) < 0) {
		toplevel_ERR(mv->top, "Error exporting filter: %s", strerror(errno));
	}
}

/**
 * Make libglade calls to fill in struct modify_view widget
 * references.
 */
static void modify_view_init_widgets(struct modify_view *mv)
{
	mv->dialog = GTK_DIALOG(glade_xml_get_widget(mv->xml, "ModifyViewWindow"));
	assert(mv->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(mv->dialog), toplevel_get_window(mv->top));

	mv->name_entry = GTK_ENTRY(glade_xml_get_widget(mv->xml, "ModifyViewNameEntry"));
	assert(mv->name_entry != NULL);

	mv->visible_combo = GTK_COMBO_BOX(glade_xml_get_widget(mv->xml, "ModifyViewVisibleCombo"));
	mv->match_combo = GTK_COMBO_BOX(glade_xml_get_widget(mv->xml, "ModifyViewMatchCombo"));
	assert(mv->visible_combo != NULL && mv->match_combo != NULL);

	mv->filter_view = GTK_TREE_VIEW(glade_xml_get_widget(mv->xml, "ModifyViewFilterView"));
	assert(mv->filter_view != NULL);
	mv->filter_store = gtk_list_store_new(2, G_TYPE_POINTER, G_TYPE_STRING);
	gtk_tree_view_set_model(mv->filter_view, GTK_TREE_MODEL(mv->filter_store));

	mv->add_button = GTK_BUTTON(glade_xml_get_widget(mv->xml, "ModifyViewAddButton"));
	mv->edit_button = GTK_BUTTON(glade_xml_get_widget(mv->xml, "ModifyViewEditButton"));
	mv->remove_button = GTK_BUTTON(glade_xml_get_widget(mv->xml, "ModifyViewRemoveButton"));
	mv->import_button = GTK_BUTTON(glade_xml_get_widget(mv->xml, "ModifyViewImportButton"));
	mv->export_button = GTK_BUTTON(glade_xml_get_widget(mv->xml, "ModifyViewExportButton"));
	assert(mv->add_button != NULL && mv->edit_button != NULL && mv->remove_button != NULL &&
	       mv->import_button != NULL && mv->export_button != NULL);
}

static void modify_view_init_signals(struct modify_view *mv)
{
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkTreeSelection *selection;

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Filter names", renderer, "text", 1, NULL);
	gtk_tree_view_column_set_clickable(column, FALSE);
	gtk_tree_view_column_set_resizable(column, FALSE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_column_set_visible(column, TRUE);
	gtk_tree_view_append_column(mv->filter_view, column);

	selection = gtk_tree_view_get_selection(mv->filter_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);
	g_signal_connect(selection, "changed", G_CALLBACK(modify_view_on_selection_change), mv);

	g_signal_connect(mv->add_button, "clicked", G_CALLBACK(modify_view_on_add_click), mv);
	g_signal_connect(mv->edit_button, "clicked", G_CALLBACK(modify_view_on_edit_click), mv);
	g_signal_connect(mv->remove_button, "clicked", G_CALLBACK(modify_view_on_remove_click), mv);
	g_signal_connect(mv->import_button, "clicked", G_CALLBACK(modify_view_on_import_click), mv);
	g_signal_connect(mv->export_button, "clicked", G_CALLBACK(modify_view_on_export_click), mv);
}

/**
 * Set up the window to reflect the current view's values.
 */
static void modify_view_init_dialog(struct modify_view *mv)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(mv->filter_view);
	GtkTreeIter iter;

	gtk_entry_set_text(mv->name_entry, seaudit_model_get_name(mv->model));

	gtk_combo_box_set_active(mv->visible_combo, seaudit_model_get_filter_visible(mv->model));
	gtk_combo_box_set_active(mv->match_combo, seaudit_model_get_filter_match(mv->model));

	gtk_tree_selection_unselect_all(selection);
	modify_view_update_filter_store(mv);
	/* automatically select the first filter upon dialog
	 * startup */

	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(mv->filter_store), &iter)) {
		gtk_tree_selection_select_iter(selection, &iter);
	}
}

int modify_view_run(toplevel_t * top, message_view_t * view)
{
	struct modify_view mv;
	seaudit_model_t *orig_model = message_view_get_model(view);
	gint response;
	int retval;

	memset(&mv, 0, sizeof(mv));
	mv.top = top;
	mv.view = view;
	mv.xml = glade_xml_new(toplevel_get_glade_xml(top), "ModifyViewWindow", NULL);
	mv.filter_filename = NULL;
	if ((mv.model = seaudit_model_create_from_model(orig_model)) == NULL) {
		toplevel_ERR(mv.top, "Error duplicating model: %s", strerror(errno));
		return 0;
	}
	modify_view_init_widgets(&mv);
	modify_view_init_signals(&mv);
	modify_view_init_dialog(&mv);

	do {
		response = gtk_dialog_run(mv.dialog);
		const gchar *text = gtk_entry_get_text(mv.name_entry);

		if (seaudit_model_set_name(mv.model, text) < 0) {
			toplevel_ERR(mv.top, "Could not set name: %s", strerror(errno));
		}
		seaudit_model_set_filter_visible(mv.model, gtk_combo_box_get_active(mv.visible_combo));
		seaudit_model_set_filter_match(mv.model, gtk_combo_box_get_active(mv.match_combo));
		if (response == GTK_RESPONSE_APPLY) {
			seaudit_model_t *new_model;
			if ((new_model = seaudit_model_create_from_model(mv.model)) == NULL) {
				toplevel_ERR(mv.top, "Error applying model: %s", strerror(errno));
				break;
			}
			message_view_set_model(mv.view, new_model);
			toplevel_update_status_bar(mv.top);
		}
	} while (response == GTK_RESPONSE_APPLY);

	if (response == GTK_RESPONSE_OK) {
		message_view_set_model(mv.view, mv.model);
		retval = 1;
	} else {
		seaudit_model_destroy(&mv.model);
		retval = 0;
	}
	gtk_widget_destroy(GTK_WIDGET(mv.dialog));
	g_object_unref(mv.filter_store);
	return retval;
}
