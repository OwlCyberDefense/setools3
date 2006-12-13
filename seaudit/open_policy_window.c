/**
 *  @file
 *  Run the dialog to allow the user to open a policy.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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
	GtkDialog *dialog;
	char *base_filename;
	apol_vector_t *module_filenames;

	GtkRadioButton *monolithic_radio, *modular_radio;

	GtkHBox *bottom_hbox;
	GtkListStore *module_store;

	GtkEntry *base_entry;
	GtkButton *base_browse_button;

	GtkTreeView *module_view;
	GtkButton *add_button, *remove_button;
};

enum module_columns
{
	POINTER_COLUMN = 0, NAME_COLUMN, VERSION_COLUMN, PATH_COLUMN
};

static void open_policy_init_widgets(struct open_policy *op)
{
	op->dialog = GTK_DIALOG(glade_xml_get_widget(op->xml, "PolicyOpenWindow"));
	assert(op->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(op->dialog), toplevel_get_window(op->top));

	op->monolithic_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(op->xml, "monolithic radio"));
	op->modular_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(op->xml, "modular radio"));
	assert(op->monolithic_radio != NULL && op->modular_radio != NULL);

	op->base_entry = GTK_ENTRY(glade_xml_get_widget(op->xml, "base entry"));
	op->base_browse_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "base browse"));
	assert(op->base_entry != NULL && op->base_browse_button != NULL);

	op->bottom_hbox = GTK_HBOX(glade_xml_get_widget(op->xml, "hbox.3"));
	assert(op->bottom_hbox != NULL);

	op->module_view = GTK_TREE_VIEW(glade_xml_get_widget(op->xml, "module view"));
	assert(op->module_view != NULL);
	op->module_store = gtk_list_store_new(PATH_COLUMN + 1, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	gtk_tree_view_set_model(op->module_view, GTK_TREE_MODEL(op->module_store));

	op->add_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "module add button"));
	op->remove_button = GTK_BUTTON(glade_xml_get_widget(op->xml, "module remove button"));
	assert(op->add_button != NULL && op->remove_button != NULL);
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
	} else {
		gtk_widget_set_sensitive(GTK_WIDGET(op->bottom_hbox), TRUE);
	}
}

static void open_policy_on_base_browse_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	char *title;
	char *path;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(op->monolithic_radio))) {
		title = "Open Monolithic Policy";
	} else {
		title = "Open Modular Policy";
	}
	if ((path = util_open_file(GTK_WINDOW(op->dialog), title, NULL)) == NULL) {
		return;
	}
	gtk_entry_set_text(op->base_entry, path);
	free(op->base_filename);
	op->base_filename = path;
}

static void open_policy_on_add_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{

}

static void open_policy_on_remove_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct open_policy *op = (struct open_policy *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(op->module_view);
	GtkTreeIter iter;
	char *path;
	size_t i;
	int rt;
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		return;
	}
	gtk_tree_model_get(GTK_TREE_MODEL(op->module_store), &iter, 0, &path, -1);
	rt = apol_vector_get_index(op->module_filenames, path, apol_str_strcmp, NULL, &i);
	assert(rt == 0);
	path = apol_vector_get_element(op->module_filenames, i);
	free(path);
	apol_vector_remove(op->module_filenames, i);
	gtk_list_store_remove(op->module_store, &iter);
}

static void open_policy_init_signals(struct open_policy *op)
{
	g_signal_connect(op->monolithic_radio, "toggled", G_CALLBACK(open_policy_on_policy_type_toggle), op);
	g_signal_connect(op->modular_radio, "toggled", G_CALLBACK(open_policy_on_policy_type_toggle), op);
	g_signal_connect(op->base_browse_button, "clicked", G_CALLBACK(open_policy_on_base_browse_click), op);
	g_signal_connect(op->add_button, "clicked", G_CALLBACK(open_policy_on_add_click), op);
	g_signal_connect(op->remove_button, "clicked", G_CALLBACK(open_policy_on_remove_click), op);
}

static void open_policy_init_module_list(struct open_policy *op)
{
	GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
	GtkTreeViewColumn *column;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(op->module_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);

	column = gtk_tree_view_column_new_with_attributes("Module", renderer, "text", 1, NULL);
	gtk_tree_view_column_set_clickable(column, FALSE);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_column_set_visible(column, TRUE);
	gtk_tree_view_append_column(op->module_view, column);
}

/**
 * Attempt to load the policy given the user's inputs.
 *
 * @return Non-zero on successful load, zero on error.
 */
static int open_policy_try_loading(struct open_policy *op)
{
	return 0;
}

void open_policy_window_run(toplevel_t * top, char *filename)
{
	struct open_policy op;
	gint response;

	memset(&op, 0, sizeof(op));
	op.top = top;
	op.xml = glade_xml_new(toplevel_get_glade_xml(top), "PolicyOpenWindow", NULL);
	if ((op.module_filenames = apol_vector_create()) == NULL) {
		toplevel_ERR(top, "%s", strerror(errno));
		return;
	}
	open_policy_init_widgets(&op);
	open_policy_init_signals(&op);
	open_policy_init_module_list(&op);

	while (1) {
		response = gtk_dialog_run(op.dialog);
		if (response == GTK_RESPONSE_CANCEL) {
			break;
		}
		if (open_policy_try_loading(&op)) {
			break;
		}
	}
	gtk_widget_destroy(GTK_WIDGET(op.dialog));
	g_object_unref(op.module_store);
	free(op.base_filename);
	apol_vector_destroy(&op.module_filenames, NULL);
}
