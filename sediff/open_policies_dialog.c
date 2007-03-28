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

#include "open_policies_dialog.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <apol/util.h>
#include <glade/glade.h>

struct open_policy_pane
{
	struct open_policy *op;
	GtkRadioButton *monolithic_radio, *modular_radio;
	GtkLabel *main_label;

	GtkHBox *bottom_hbox;
	GtkListStore *module_store;

	GtkEntry *base_entry;
	GtkButton *base_browse_button;

	GtkTreeView *module_view;
	GtkButton *add_button, *remove_button;
	char *last_module_path;
};

struct open_policy
{
	GladeXML *xml;
	toplevel_t *top;
	GtkDialog *dialog;
	GtkButton *ok_button, *rundiff_button;
	struct open_policy_pane pane[SEDIFFX_POLICY_NUM];
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

static void open_policy_init_pane(struct open_policy *op, sediffx_policy_e which, const char *suffix)
{
	struct open_policy_pane *pane = op->pane + which;
	GString *s = g_string_new(NULL);
	GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
	GtkTreeViewColumn *column;
	GtkTreeSelection *selection;

	g_string_printf(s, "monolithic radio%s", suffix);
	pane->monolithic_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(op->xml, s->str));
	g_string_printf(s, "modular radio%s", suffix);
	pane->modular_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(op->xml, s->str));
	g_string_printf(s, "main filename label%s", suffix);
	pane->main_label = GTK_LABEL(glade_xml_get_widget(op->xml, s->str));
	assert(pane->monolithic_radio != NULL && pane->modular_radio != NULL && pane->main_label != NULL);

	g_string_printf(s, "base entry%s", suffix);
	pane->base_entry = GTK_ENTRY(glade_xml_get_widget(op->xml, s->str));
	g_string_printf(s, "base browse%s", suffix);
	pane->base_browse_button = GTK_BUTTON(glade_xml_get_widget(op->xml, s->str));
	assert(pane->base_entry != NULL && pane->base_browse_button != NULL);

	g_string_printf(s, "hbox.3%s", suffix);
	pane->bottom_hbox = GTK_HBOX(glade_xml_get_widget(op->xml, s->str));
	assert(pane->bottom_hbox != NULL);

	g_string_printf(s, "module view%s", suffix);
	pane->module_view = GTK_TREE_VIEW(glade_xml_get_widget(op->xml, s->str));
	assert(pane->module_view != NULL);
	pane->module_store = gtk_list_store_new(NUM_COLUMNS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	gtk_tree_view_set_model(pane->module_view, GTK_TREE_MODEL(pane->module_store));

	g_string_printf(s, "module add button%s", suffix);
	pane->add_button = GTK_BUTTON(glade_xml_get_widget(op->xml, s->str));
	g_string_printf(s, "module remove button%s", suffix);
	pane->remove_button = GTK_BUTTON(glade_xml_get_widget(op->xml, s->str));
	assert(pane->add_button != NULL && pane->remove_button != NULL);

	g_string_free(s, TRUE);

	selection = gtk_tree_view_get_selection(pane->module_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);

	column = gtk_tree_view_column_new_with_attributes("Module", renderer, "text", NAME_COLUMN, NULL);
	gtk_tree_view_column_set_sort_column_id(column, NAME_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_append_column(pane->module_view, column);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(pane->module_store), NAME_COLUMN, open_policy_sort,
					(gpointer) NAME_COLUMN, NULL);

	column = gtk_tree_view_column_new_with_attributes("Version", renderer, "text", VERSION_COLUMN, NULL);
	gtk_tree_view_column_set_sort_column_id(column, VERSION_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_append_column(pane->module_view, column);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(pane->module_store), VERSION_COLUMN, open_policy_sort,
					(gpointer) VERSION_COLUMN, NULL);

	column = gtk_tree_view_column_new_with_attributes("Path", renderer, "text", PATH_COLUMN, NULL);
	gtk_tree_view_column_set_sort_column_id(column, PATH_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_append_column(pane->module_view, column);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(pane->module_store), PATH_COLUMN, open_policy_sort,
					(gpointer) PATH_COLUMN, NULL);

	gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(pane->module_store), NAME_COLUMN, GTK_SORT_ASCENDING);
}

static void open_policy_init_widgets(struct open_policy *op)
{
	op->dialog = GTK_DIALOG(glade_xml_get_widget(op->xml, "PoliciesOpenWindow"));
	assert(op->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(op->dialog), toplevel_get_window(op->top));
	op->ok_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "ok button"));
	op->rundiff_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "rundiff button"));
	assert(op->ok_button != NULL && op->rundiff_button != NULL);

	open_policy_init_pane(op, SEDIFFX_POLICY_ORIG, "");
	open_policy_init_pane(op, SEDIFFX_POLICY_MOD, " 1");
}

static void open_policy_on_policy_type_toggle(GtkToggleButton * widget, gpointer user_data)
{
	struct open_policy_pane *pane = (struct open_policy_pane *)user_data;
	/* clicking on the radio buttons emit two toggle signals, one for
	 * the original button and one for the new one.  thus only need to
	 * handle half of all signals */
	if (!gtk_toggle_button_get_active(widget)) {
		return;
	}
	char *prefix;
	GString *s = g_string_new(NULL);
	if (pane == &(pane->op->pane[SEDIFFX_POLICY_ORIG])) {
		prefix = "Original";
	} else {
		prefix = "Modified";
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pane->monolithic_radio))) {
		gtk_widget_set_sensitive(GTK_WIDGET(pane->bottom_hbox), FALSE);
		g_string_printf(s, "<b>%s Policy Filename:</b>", prefix);
		gtk_label_set_markup(pane->main_label, s->str);
	} else {
		gtk_widget_set_sensitive(GTK_WIDGET(pane->bottom_hbox), TRUE);
		g_string_printf(s, "<b>%s Base Filename:</b>", prefix);
		gtk_label_set_markup(pane->main_label, s->str);
	}
	g_string_free(s, TRUE);
}

static void open_policy_on_entry_event_after(GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
					     __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	gboolean sens = FALSE;
	if (strcmp(gtk_entry_get_text(op->pane[SEDIFFX_POLICY_ORIG].base_entry), "") != 0
	    && strcmp(gtk_entry_get_text(op->pane[SEDIFFX_POLICY_MOD].base_entry), "") != 0) {
		sens = TRUE;
	}
	gtk_widget_set_sensitive(GTK_WIDGET(op->ok_button), sens);
	gtk_widget_set_sensitive(GTK_WIDGET(op->rundiff_button), sens);
}

static void open_policy_on_base_browse_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy_pane *pane = (struct open_policy_pane *)user_data;
	const char *current_path = gtk_entry_get_text(pane->base_entry);
	char *title;
	apol_vector_t *paths;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pane->monolithic_radio))) {
		title = "Open Monolithic Policy";
	} else {
		title = "Open Modular Policy";
	}
	if (strcmp(current_path, "") == 0) {
		current_path = NULL;
	}
	if ((paths = util_open_file(GTK_WINDOW(pane->op->dialog), title, current_path, 0)) == NULL) {
		return;
	}
	gtk_entry_set_text(pane->base_entry, apol_vector_get_element(paths, 0));
	apol_vector_destroy(&paths);
}

/**
 * Attempt to load a module and retrieve its name and version.  Upon
 * success add an entry to the list store.
 *
 * @return 0 on success, < 0 on error.
 */
static int open_policy_load_module(struct open_policy *op, struct open_policy_pane *pane, const char *path)
{
	char *module_name, *version_string;
	int module_type;
	qpol_module_t *module = NULL;
	GtkTreeIter iter;

	/* check if modulue was already loaded */
	gboolean iter_valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(pane->module_store), &iter);
	while (iter_valid) {
		char *s;
		gtk_tree_model_get(GTK_TREE_MODEL(pane->module_store), &iter, PATH_COLUMN, &s, -1);
		if (strcmp(s, path) == 0) {
			toplevel_ERR(op->top, "Module %s was already added.", path);
			return -1;
		}
		iter_valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(pane->module_store), &iter);
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
	gtk_list_store_append(pane->module_store, &iter);
	gtk_list_store_set(pane->module_store, &iter, PATH_COLUMN, path, NAME_COLUMN, module_name, VERSION_COLUMN, version_string,
			   -1);
	qpol_module_destroy(&module);
	return 0;
}

static void open_policy_on_add_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy_pane *pane = (struct open_policy_pane *)user_data;
	apol_vector_t *paths;
	const char *path = NULL, *prev_path;
	size_t i;
	if ((prev_path = pane->last_module_path) == NULL) {
		prev_path = gtk_entry_get_text(pane->base_entry);
		if (strcmp(prev_path, "") == 0) {
			prev_path = NULL;
		}
	}
	paths = util_open_file(GTK_WINDOW(pane->op->dialog), "Open Module", prev_path, 1);
	if (paths == NULL) {
		return;
	}
	int all_succeed = 1;
	for (i = 0; i < apol_vector_get_size(paths); i++) {
		path = apol_vector_get_element(paths, i);
		if (open_policy_load_module(pane->op, pane, path) < 0) {
			all_succeed = 0;
		}
	}
	if (all_succeed) {
		assert(path != NULL);
		free(pane->last_module_path);
		pane->last_module_path = strdup(path);
	}
	apol_vector_destroy(&paths);
}

static void open_policy_on_remove_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy_pane *pane = (struct open_policy_pane *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(pane->module_view);
	GtkTreeIter iter;
	char *path;
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		return;
	}
	gtk_tree_model_get(GTK_TREE_MODEL(pane->module_store), &iter, 0, &path, -1);
	gtk_list_store_remove(pane->module_store, &iter);
}

static void open_policy_on_selection_change(GtkTreeSelection * selection, gpointer user_data)
{
	struct open_policy_pane *pane = (struct open_policy_pane *)user_data;
	gboolean sens = gtk_tree_selection_get_selected(selection, NULL, NULL);
	gtk_widget_set_sensitive(GTK_WIDGET(pane->remove_button), sens);
}

static void open_policy_init_signals(struct open_policy *op)
{
	sediffx_policy_e i;
	for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
		struct open_policy_pane *pane = op->pane + i;
		GtkTreeSelection *selection = gtk_tree_view_get_selection(pane->module_view);
		g_signal_connect(pane->monolithic_radio, "toggled", G_CALLBACK(open_policy_on_policy_type_toggle), pane);
		g_signal_connect(pane->modular_radio, "toggled", G_CALLBACK(open_policy_on_policy_type_toggle), pane);
		g_signal_connect(pane->base_entry, "event-after", G_CALLBACK(open_policy_on_entry_event_after), op);
		g_signal_connect(pane->base_browse_button, "clicked", G_CALLBACK(open_policy_on_base_browse_click), pane);
		g_signal_connect(selection, "changed", G_CALLBACK(open_policy_on_selection_change), pane);
		g_signal_connect(pane->add_button, "clicked", G_CALLBACK(open_policy_on_add_click), pane);
		g_signal_connect(pane->remove_button, "clicked", G_CALLBACK(open_policy_on_remove_click), pane);
	}
}

static void open_policy_init_value(struct open_policy *op, const apol_policy_path_t * path, struct open_policy_pane *pane)
{
	apol_policy_path_type_e path_type = apol_policy_path_get_type(path);
	const char *primary_path = apol_policy_path_get_primary(path);
	gtk_entry_set_text(pane->base_entry, primary_path);
	if (path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		const apol_vector_t *modules = apol_policy_path_get_modules(path);
		size_t i;
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(pane->modular_radio), TRUE);
		for (i = 0; i < apol_vector_get_size(modules); i++) {
			char *module_path = apol_vector_get_element(modules, i);
			if (open_policy_load_module(op, pane, module_path) < 0) {
				break;
			}
		}
	}
}

static void open_policy_init_values(struct open_policy *op, const apol_policy_path_t * orig_path,
				    const apol_policy_path_t * mod_path)
{
	if (orig_path != NULL) {
		open_policy_init_value(op, orig_path, op->pane + SEDIFFX_POLICY_ORIG);
	}
	if (mod_path != NULL) {
		open_policy_init_value(op, mod_path, op->pane + SEDIFFX_POLICY_MOD);
	}
}

/**
 * Build the policy path corresponding to the user's inputs on this
 * dialog.
 *
 * @return path for the dialog, or NULL upon error.  The caller must
 * call apol_policy_path_destroy() afterwards.
 */
static apol_policy_path_t *open_policy_build_path(struct open_policy *op, sediffx_policy_e which)
{
	struct open_policy_pane *pane = op->pane + which;
	const char *primary_path = gtk_entry_get_text(pane->base_entry);
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	apol_vector_t *modules = NULL;
	apol_policy_path_t *path = NULL;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pane->modular_radio))) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
		GtkTreeIter iter;
		if ((modules = apol_vector_create(free)) == NULL) {
			toplevel_ERR(op->top, "%s", strerror(errno));
			return NULL;
		}
		if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(pane->module_store), &iter)) {
			do {
				GValue value = { 0 };
				char *module_path;
				gtk_tree_model_get_value(GTK_TREE_MODEL(pane->module_store), &iter, PATH_COLUMN, &value);
				module_path = g_value_dup_string(&value);
				g_value_unset(&value);
				if (apol_vector_append(modules, module_path) < 0) {
					toplevel_ERR(op->top, "%s", strerror(errno));
					free(module_path);
					apol_vector_destroy(&modules);
					return NULL;
				}
			}
			while (gtk_tree_model_iter_next(GTK_TREE_MODEL(pane->module_store), &iter));
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

void open_policies_dialog_run(toplevel_t * top, const apol_policy_path_t * orig_path, const apol_policy_path_t * mod_path)
{
	struct open_policy op;
	gint response;
	apol_policy_path_t *input[SEDIFFX_POLICY_NUM];

	memset(&op, 0, sizeof(op));
	op.top = top;
	op.xml = glade_xml_new(toplevel_get_glade_xml(top), "PoliciesOpenWindow", NULL);
	op.pane[SEDIFFX_POLICY_ORIG].op = &op;
	op.pane[SEDIFFX_POLICY_MOD].op = &op;

	open_policy_init_widgets(&op);
	open_policy_init_signals(&op);
	open_policy_init_values(&op, orig_path, mod_path);
	open_policy_on_entry_event_after(NULL, NULL, &op);

	while (1) {
		response = gtk_dialog_run(op.dialog);
		if (response == GTK_RESPONSE_CANCEL || response == GTK_RESPONSE_DELETE_EVENT) {
			break;
		}
		if ((input[SEDIFFX_POLICY_ORIG] = open_policy_build_path(&op, SEDIFFX_POLICY_ORIG)) == NULL ||
		    (input[SEDIFFX_POLICY_MOD] = open_policy_build_path(&op, SEDIFFX_POLICY_MOD)) == NULL) {
			continue;
		}
		if (toplevel_open_policies(op.top, input[SEDIFFX_POLICY_ORIG], input[SEDIFFX_POLICY_MOD]) == 0) {
			break;
		}
	}
	gtk_widget_destroy(GTK_WIDGET(op.dialog));
	free(op.pane[SEDIFFX_POLICY_ORIG].last_module_path);
	free(op.pane[SEDIFFX_POLICY_MOD].last_module_path);
	g_object_unref(op.pane[SEDIFFX_POLICY_ORIG].module_store);
	g_object_unref(op.pane[SEDIFFX_POLICY_MOD].module_store);

	if (response == 0) {
		/* Run Diff button was clicked */
		toplevel_run_diff(op.top);
	}
}
