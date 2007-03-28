/**
 *  @file
 *  Run the dialog to allow the user to open a policy.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#include "open_policy_window.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <apol/util.h>
#include <apol/vector.h>
#include <glade/glade.h>
#include <gtk/gtk.h>

struct open_policy
{
	GladeXML *xml;
	toplevel_t *top;
	char *last_module_path;
	GtkDialog *dialog;

	GtkRadioButton *monolithic_radio, *modular_radio;
	GtkLabel *main_label;

	GtkHBox *bottom_hbox;
	GtkListStore *module_store;

	GtkEntry *base_entry;
	GtkButton *base_browse_button;

	GtkTreeView *module_view;
	GtkButton *add_button, *remove_button, *import_button, *export_button;
	GtkButton *ok_button;
};

enum module_columns
{
	PATH_COLUMN = 0, NAME_COLUMN, VERSION_COLUMN, NUM_COLUMNS
};

/**
 * Sort columns in alphabetical order.
 */
static gint open_policy_sort(GtkTreeModel * model, GtkTreeIter * a, GtkTreeIter * b, gpointer user_data)
{
	GValue value_a = { 0 }, value_b = {
	0};
	const char *name_a, *name_b;
	int retval, column_id = GPOINTER_TO_INT(user_data);

	gtk_tree_model_get_value(model, a, column_id, &value_a);
	gtk_tree_model_get_value(model, b, column_id, &value_b);
	name_a = g_value_get_string(&value_a);
	name_b = g_value_get_string(&value_b);
	retval = strcmp(name_a, name_b);
	g_value_unset(&value_a);
	g_value_unset(&value_b);
	return retval;
}

static void open_policy_init_widgets(struct open_policy *op)
{
	GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
	GtkTreeViewColumn *column;
	GtkTreeSelection *selection;

	op->dialog = GTK_DIALOG(glade_xml_get_widget(op->xml, "PolicyOpenWindow"));
	assert(op->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(op->dialog), toplevel_get_window(op->top));

	op->monolithic_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(op->xml, "monolithic radio"));
	op->modular_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(op->xml, "modular radio"));
	op->main_label = GTK_LABEL(glade_xml_get_widget(op->xml, "main filename label"));
	assert(op->monolithic_radio != NULL && op->modular_radio != NULL && op->main_label != NULL);

	op->base_entry = GTK_ENTRY(glade_xml_get_widget(op->xml, "base entry"));
	op->base_browse_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "base browse"));
	assert(op->base_entry != NULL && op->base_browse_button != NULL);

	op->bottom_hbox = GTK_HBOX(glade_xml_get_widget(op->xml, "hbox.3"));
	assert(op->bottom_hbox != NULL);

	op->module_view = GTK_TREE_VIEW(glade_xml_get_widget(op->xml, "module view"));
	assert(op->module_view != NULL);
	op->module_store = gtk_list_store_new(NUM_COLUMNS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	gtk_tree_view_set_model(op->module_view, GTK_TREE_MODEL(op->module_store));

	op->add_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "module add button"));
	op->remove_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "module remove button"));
	op->import_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "module list import button"));
	op->export_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "module list export button"));
	op->ok_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "ok button"));
	assert(op->add_button != NULL && op->remove_button != NULL &&
	       op->import_button != NULL && op->export_button != NULL && op->ok_button != NULL);

	selection = gtk_tree_view_get_selection(op->module_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);

	column = gtk_tree_view_column_new_with_attributes("Module", renderer, "text", NAME_COLUMN, NULL);
	gtk_tree_view_column_set_sort_column_id(column, NAME_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_append_column(op->module_view, column);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(op->module_store), NAME_COLUMN, open_policy_sort, (gpointer) NAME_COLUMN,
					NULL);

	column = gtk_tree_view_column_new_with_attributes("Version", renderer, "text", VERSION_COLUMN, NULL);
	gtk_tree_view_column_set_sort_column_id(column, VERSION_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_append_column(op->module_view, column);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(op->module_store), VERSION_COLUMN, open_policy_sort,
					(gpointer) VERSION_COLUMN, NULL);

	column = gtk_tree_view_column_new_with_attributes("Path", renderer, "text", PATH_COLUMN, NULL);
	gtk_tree_view_column_set_sort_column_id(column, PATH_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_append_column(op->module_view, column);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(op->module_store), PATH_COLUMN, open_policy_sort, (gpointer) PATH_COLUMN,
					NULL);

	gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(op->module_store), NAME_COLUMN, GTK_SORT_ASCENDING);
}

static void open_policy_on_policy_type_toggle(GtkToggleButton * widget, gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	/* clicking on the radio buttons emit two toggle signals, one for
	 * the original button and one for the new one.  thus only need to
	 * handle half of all signals */
	if (!gtk_toggle_button_get_active(widget)) {
		return;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(op->monolithic_radio))) {
		gtk_widget_set_sensitive(GTK_WIDGET(op->bottom_hbox), FALSE);
		gtk_label_set_markup(op->main_label, "<b>Policy Filename:</b>");
	} else {
		gtk_widget_set_sensitive(GTK_WIDGET(op->bottom_hbox), TRUE);
		gtk_label_set_markup(op->main_label, "<b>Base Filename:</b>");
	}
}

static void open_policy_on_entry_event_after(GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
					     __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	gboolean sens = FALSE;
	if (strcmp(gtk_entry_get_text(op->base_entry), "") != 0) {
		sens = TRUE;
	}
	gtk_widget_set_sensitive(GTK_WIDGET(op->export_button), sens);
	gtk_widget_set_sensitive(GTK_WIDGET(op->ok_button), sens);
}

static void open_policy_on_base_browse_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	const char *current_path = gtk_entry_get_text(op->base_entry);
	char *title;
	apol_vector_t *paths;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(op->monolithic_radio))) {
		title = "Open Monolithic Policy";
	} else {
		title = "Open Modular Policy";
	}
	if (strcmp(current_path, "") == 0) {
		current_path = NULL;
	}
	if ((paths = util_open_file(GTK_WINDOW(op->dialog), title, current_path, 0)) == NULL) {
		return;
	}
	gtk_entry_set_text(op->base_entry, apol_vector_get_element(paths, 0));
	apol_vector_destroy(&paths);
}

/**
 * Attempt to load a module and retrieve its name and version.  Upon
 * success add an entry to the list store.
 *
 * @return 0 on success, < 0 on error.
 */
static int open_policy_load_module(struct open_policy *op, const char *path)
{
	char *module_name, *version_string;
	int module_type;
	qpol_module_t *module = NULL;
	GtkTreeIter iter;

	/* check if modulue was already loaded */
	gboolean iter_valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(op->module_store), &iter);
	while (iter_valid) {
		char *s;
		gtk_tree_model_get(GTK_TREE_MODEL(op->module_store), &iter, PATH_COLUMN, &s, -1);
		if (strcmp(s, path) == 0) {
			toplevel_ERR(op->top, "Module %s was already added.", path);
			return -1;
		}
		iter_valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(op->module_store), &iter);
	}
	if ((qpol_module_create_from_file(path, &module)) < 0) {
		toplevel_ERR(op->top, "Error opening module %s: %s", path, strerror(errno));
		return -1;
	}
	if (qpol_module_get_name(module, &module_name) < 0 ||
	    qpol_module_get_version(module, &version_string) < 0 || qpol_module_get_type(module, &module_type) < 0) {
		toplevel_ERR(op->top, "Error reading module %s: %s", path, strerror(errno));
		qpol_module_destroy(&module);
		return -1;
	}
	if (module_type != QPOL_MODULE_OTHER) {
		toplevel_ERR(op->top, "%s is not a loadable module.", path);
		qpol_module_destroy(&module);
		return -1;
	}
	gtk_list_store_append(op->module_store, &iter);
	gtk_list_store_set(op->module_store, &iter, PATH_COLUMN, path, NAME_COLUMN, module_name, VERSION_COLUMN, version_string,
			   -1);
	qpol_module_destroy(&module);
	return 0;
}

static void open_policy_on_add_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	apol_vector_t *paths;
	const char *path = NULL, *prev_path;
	size_t i;
	if ((prev_path = op->last_module_path) == NULL) {
		prev_path = gtk_entry_get_text(op->base_entry);
		if (strcmp(prev_path, "") == 0) {
			prev_path = NULL;
		}
	}
	paths = util_open_file(GTK_WINDOW(op->dialog), "Open Module", prev_path, 1);
	if (paths == NULL) {
		return;
	}
	int all_succeed = 1;
	for (i = 0; i < apol_vector_get_size(paths); i++) {
		path = apol_vector_get_element(paths, i);
		if (open_policy_load_module(op, path) < 0) {
			all_succeed = 0;
		}
	}
	if (all_succeed) {
		assert(path != NULL);
		free(op->last_module_path);
		op->last_module_path = strdup(path);
	}
	apol_vector_destroy(&paths);
}

static void open_policy_on_remove_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(op->module_view);
	GtkTreeIter iter;
	char *path;
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		return;
	}
	gtk_tree_model_get(GTK_TREE_MODEL(op->module_store), &iter, 0, &path, -1);
	gtk_list_store_remove(op->module_store, &iter);
}

static void open_policy_on_import_click(GtkButton * button __attribute__ ((unused)), gpointer user_data);
static void open_policy_on_export_click(GtkButton * button __attribute__ ((unused)), gpointer user_data);

static void open_policy_on_selection_change(GtkTreeSelection * selection, gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	gboolean sens = gtk_tree_selection_get_selected(selection, NULL, NULL);
	gtk_widget_set_sensitive(GTK_WIDGET(op->remove_button), sens);
}

static void open_policy_init_signals(struct open_policy *op)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(op->module_view);
	g_signal_connect(op->monolithic_radio, "toggled", G_CALLBACK(open_policy_on_policy_type_toggle), op);
	g_signal_connect(op->modular_radio, "toggled", G_CALLBACK(open_policy_on_policy_type_toggle), op);
	g_signal_connect(op->base_entry, "event-after", G_CALLBACK(open_policy_on_entry_event_after), op);
	g_signal_connect(op->base_browse_button, "clicked", G_CALLBACK(open_policy_on_base_browse_click), op);
	g_signal_connect(selection, "changed", G_CALLBACK(open_policy_on_selection_change), op);
	g_signal_connect(op->add_button, "clicked", G_CALLBACK(open_policy_on_add_click), op);
	g_signal_connect(op->remove_button, "clicked", G_CALLBACK(open_policy_on_remove_click), op);
	g_signal_connect(op->import_button, "clicked", G_CALLBACK(open_policy_on_import_click), op);
	g_signal_connect(op->export_button, "clicked", G_CALLBACK(open_policy_on_export_click), op);
}

static void open_policy_init_values(struct open_policy *op, const apol_policy_path_t * path)
{
	if (path != NULL) {
		apol_policy_path_type_e path_type = apol_policy_path_get_type(path);
		const char *primary_path = apol_policy_path_get_primary(path);
		gtk_entry_set_text(op->base_entry, primary_path);
		if (path_type == APOL_POLICY_PATH_TYPE_MONOLITHIC) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(op->monolithic_radio), TRUE);
		} else if (path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
			const apol_vector_t *modules = apol_policy_path_get_modules(path);
			size_t i;
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(op->modular_radio), TRUE);
			for (i = 0; i < apol_vector_get_size(modules); i++) {
				char *module_path = apol_vector_get_element(modules, i);
				if (open_policy_load_module(op, module_path) < 0) {
					break;
				}
			}
		} else {
			/* should never get here */
			toplevel_ERR(op->top, "Unknown policy path type %d.", path_type);
		}
	}
}

/**
 * Build the policy path corresponding to the user's inputs on this
 * dialog.
 *
 * @return path for the dialog, or NULL upon error.  The caller must
 * call apol_policy_path_destroy() afterwards.
 */
static apol_policy_path_t *open_policy_build_path(struct open_policy *op)
{
	const char *primary_path = gtk_entry_get_text(op->base_entry);
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	apol_vector_t *modules = NULL;
	apol_policy_path_t *path = NULL;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(op->modular_radio))) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
		GtkTreeIter iter;
		if ((modules = apol_vector_create(free)) == NULL) {
			toplevel_ERR(op->top, "%s", strerror(errno));
			return NULL;
		}
		if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(op->module_store), &iter)) {
			do {
				GValue value = { 0 };
				char *module_path;
				gtk_tree_model_get_value(GTK_TREE_MODEL(op->module_store), &iter, PATH_COLUMN, &value);
				module_path = g_value_dup_string(&value);
				g_value_unset(&value);
				if (apol_vector_append(modules, module_path) < 0) {
					toplevel_ERR(op->top, "%s", strerror(errno));
					free(module_path);
					apol_vector_destroy(&modules);
					return NULL;
				}
			}
			while (gtk_tree_model_iter_next(GTK_TREE_MODEL(op->module_store), &iter));
		}
	}
	path = apol_policy_path_create(path_type, primary_path, modules);
	apol_vector_destroy(&modules);
	if (path == NULL) {
		toplevel_ERR(op->top, "%s", strerror(errno));
		return NULL;
	}
	return path;
}

static void open_policy_on_import_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	apol_vector_t *paths = NULL;
	apol_policy_path_t *ppath = NULL;
	const char *path = NULL, *prev_path;
	if ((prev_path = op->last_module_path) == NULL) {
		prev_path = gtk_entry_get_text(op->base_entry);
		if (strcmp(prev_path, "") == 0) {
			prev_path = NULL;
		}
	}
	paths = util_open_file(GTK_WINDOW(op->dialog), "Import Module List", prev_path, 1);
	if (paths == NULL) {
		return;
	}
	path = apol_vector_get_element(paths, 0);
	ppath = apol_policy_path_create_from_file(path);
	if (ppath == NULL) {
		toplevel_ERR(op->top, "Error importing module list %s: %s", path, strerror(errno));
		goto cleanup;
	}
	open_policy_init_values(op, ppath);
	free(op->last_module_path);
	op->last_module_path = strdup(path);
      cleanup:
	apol_vector_destroy(&paths);
	apol_policy_path_destroy(&ppath);
}

static void open_policy_on_export_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	char *path = util_save_file(GTK_WINDOW(op->dialog), "Export Module List", NULL);
	apol_policy_path_t *ppath = NULL;
	if (path == NULL) {
		return;
	}
	ppath = open_policy_build_path(op);
	if (ppath == NULL) {
		goto cleanup;
	}
	if (apol_policy_path_to_file(ppath, path) < 0) {
		toplevel_ERR(op->top, "Error exporting module list %s: %s", path, strerror(errno));
	}
      cleanup:
	g_free(path);
	apol_policy_path_destroy(&ppath);
}

void open_policy_window_run(toplevel_t * top, const apol_policy_path_t * path, apol_policy_path_t ** selection)
{
	struct open_policy op;
	gint response;
	apol_policy_path_t *input;

	memset(&op, 0, sizeof(op));
	op.top = top;
	op.xml = glade_xml_new(toplevel_get_glade_xml(top), "PolicyOpenWindow", NULL);

	open_policy_init_widgets(&op);
	open_policy_init_signals(&op);
	open_policy_init_values(&op, path);
	if (selection != NULL) {
		*selection = NULL;
	}

	while (1) {
		response = gtk_dialog_run(op.dialog);
		if (response == GTK_RESPONSE_CANCEL || response == GTK_RESPONSE_DELETE_EVENT) {
			break;
		}
		if ((input = open_policy_build_path(&op)) == NULL) {
			continue;
		}
		if (selection == NULL) {
			if (toplevel_open_policy(op.top, input) == 0) {
				break;
			}
		} else {
			*selection = input;
			break;
		}
	}
	gtk_widget_destroy(GTK_WIDGET(op.dialog));
	free(op.last_module_path);
	g_object_unref(op.module_store);
}
