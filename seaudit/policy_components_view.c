/**
 *  @file policy_components_view.c
 *  Run the dialog to select from lists of strings.
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

#include "policy_components_view.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <apol/util.h>
#include <glade/glade.h>

struct polcomp_view
{
	GladeXML *xml;
	toplevel_t *top;
	apol_vector_t *log_items, *policy_items, *both_items, *included_items;
	GtkDialog *dialog;

	GtkRadioButton *log_radio, *policy_radio, *both_radio;

	GtkListStore *master_store;
	GtkTreeModel *inc_store, *exc_store;
	GtkTreeView *inc_view, *exc_view;
	GtkButton *inc_select_button, *inc_unselect_button, *exc_select_button, *exc_unselect_button;

	GtkButton *to_exc_button, *to_inc_button;
};

enum polcom_columns
{
	POINTER_COLUMN = 0, NAME_COLUMN, ISLOG_COLUMN, ISPOLICY_COLUMN, ISINC_COLUMN
};

static void policy_components_view_init_widgets(struct polcomp_view *pv)
{
	pv->dialog = GTK_DIALOG(glade_xml_get_widget(pv->xml, "PolicyComponentListsWindow"));
	assert(pv->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(pv->dialog), toplevel_get_window(pv->top));

	pv->log_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompLogRadio"));
	pv->policy_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompPolicyRadio"));
	pv->both_radio = GTK_RADIO_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompBothRadio"));
	assert(pv->log_radio != NULL && pv->policy_radio != NULL && pv->both_radio != NULL);

	pv->inc_view = GTK_TREE_VIEW(glade_xml_get_widget(pv->xml, "PolicyCompIncView"));
	pv->exc_view = GTK_TREE_VIEW(glade_xml_get_widget(pv->xml, "PolicyCompExcView"));
	assert(pv->inc_view != NULL && pv->exc_view != NULL);

	pv->inc_select_button = GTK_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompIncSelectButton"));
	pv->inc_unselect_button = GTK_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompIncUnselectButton"));
	pv->exc_select_button = GTK_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompExcSelectButton"));
	pv->exc_unselect_button = GTK_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompExcUnselectButton"));
	assert(pv->inc_select_button != NULL && pv->inc_unselect_button &&
	       pv->exc_select_button != NULL && pv->exc_unselect_button);

	pv->to_exc_button = GTK_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompToExcButton"));
	pv->to_inc_button = GTK_BUTTON(glade_xml_get_widget(pv->xml, "PolicyCompToIncButton"));
	assert(pv->to_exc_button != NULL && pv->to_inc_button);
}

/******************** functions to build the lists ********************/

/**
 * Determine if a particular row should be visible based upon the
 * current radio button selection.  If the current item source is
 * 'Log' then return TRUE if the islog attribute is enabled.  If the
 * source is 'Policy' then return TRUE if ispolicy is enabled.
 * Otherwise the item is visible by default.
 */
static gboolean policy_components_view_is_visible_radio(struct polcomp_view *pv, gboolean islog, gboolean ispolicy)
{
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pv->log_radio))) {
		return islog;
	} else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pv->policy_radio))) {
		return ispolicy;
	}
	return TRUE;
}

/**
 * Callback invoked to determine if a row should be visible to the
 * included view.
 */
static gboolean policy_components_view_is_visible_included(GtkTreeModel * model, GtkTreeIter * iter, gpointer data)
{
	struct polcomp_view *pv = (struct polcomp_view *)data;
	gboolean islog, ispolicy, isinc;
	gtk_tree_model_get(model, iter, ISLOG_COLUMN, &islog, ISPOLICY_COLUMN, &ispolicy, ISINC_COLUMN, &isinc, -1);
	if (!isinc) {
		return FALSE;
	}
	return policy_components_view_is_visible_radio(pv, islog, ispolicy);
}

/**
 * Callback invoked to determine if a row should be visible in the
 * included view.
 */
static gboolean policy_components_view_is_visible_excluded(GtkTreeModel * model, GtkTreeIter * iter, gpointer data)
{
	struct polcomp_view *pv = (struct polcomp_view *)data;
	gboolean islog, ispolicy, isinc;
	gtk_tree_model_get(model, iter, ISLOG_COLUMN, &islog, ISPOLICY_COLUMN, &ispolicy, ISINC_COLUMN, &isinc, -1);
	if (isinc) {
		return FALSE;
	}
	return policy_components_view_is_visible_radio(pv, islog, ispolicy);
}

static void policy_components_view_init_lists(struct polcomp_view *pv)
{
	GtkTreeIter iter;
	size_t i, j;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkTreeSelection *selection;

	if ((pv->both_items = apol_vector_create_from_vector(pv->log_items, NULL, NULL)) == NULL) {
		toplevel_ERR(pv->top, "Error generating union list: %s", strerror(errno));
		return;
	}
	if (pv->policy_items == NULL) {
		gtk_widget_set_sensitive(GTK_WIDGET(pv->policy_radio), FALSE);
		gtk_widget_set_sensitive(GTK_WIDGET(pv->both_radio), FALSE);
	} else {
		if (apol_vector_cat(pv->both_items, pv->policy_items) < 0) {
			toplevel_ERR(pv->top, "Error generating union list: %s", strerror(errno));
			return;
		}
		apol_vector_sort_uniquify(pv->both_items, apol_str_strcmp, NULL, NULL);
	}
	pv->master_store =
		gtk_list_store_new(ISINC_COLUMN + 1, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);
	for (i = 0; i < apol_vector_get_size(pv->both_items); i++) {
		char *s = apol_vector_get_element(pv->both_items, i);
		gboolean is_log = FALSE, is_policy = FALSE, is_included = FALSE;
		if (apol_vector_get_index(pv->log_items, s, NULL, NULL, &j) == 0) {
			is_log = TRUE;
		}
		if (pv->policy_items != NULL && apol_vector_get_index(pv->policy_items, s, NULL, NULL, &j) == 0) {
			is_policy = TRUE;
		}
		if (apol_vector_get_index(pv->included_items, s, apol_str_strcmp, NULL, &j) == 0) {
			is_included = TRUE;
		}
		gtk_list_store_append(pv->master_store, &iter);
		gtk_list_store_set(pv->master_store, &iter,
				   POINTER_COLUMN, s,
				   NAME_COLUMN, s, ISLOG_COLUMN, is_log, ISPOLICY_COLUMN, is_policy, ISINC_COLUMN, is_included, -1);
	}

	pv->inc_store = gtk_tree_model_filter_new(GTK_TREE_MODEL(pv->master_store), NULL);
	gtk_tree_model_filter_set_visible_func(GTK_TREE_MODEL_FILTER(pv->inc_store), policy_components_view_is_visible_included, pv,
					       NULL);
	pv->exc_store = gtk_tree_model_filter_new(GTK_TREE_MODEL(pv->master_store), NULL);
	gtk_tree_model_filter_set_visible_func(GTK_TREE_MODEL_FILTER(pv->exc_store), policy_components_view_is_visible_excluded, pv,
					       NULL);
	gtk_tree_view_set_model(pv->inc_view, pv->inc_store);
	gtk_tree_view_set_model(pv->exc_view, pv->exc_store);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Item names", renderer, "text", NAME_COLUMN, NULL);
	gtk_tree_view_column_set_clickable(column, FALSE);
	gtk_tree_view_column_set_resizable(column, FALSE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_column_set_visible(column, TRUE);
	gtk_tree_view_append_column(pv->inc_view, column);
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Item names", renderer, "text", NAME_COLUMN, NULL);
	gtk_tree_view_column_set_clickable(column, FALSE);
	gtk_tree_view_column_set_resizable(column, FALSE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_column_set_visible(column, TRUE);
	gtk_tree_view_append_column(pv->exc_view, column);

	selection = gtk_tree_view_get_selection(pv->inc_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	selection = gtk_tree_view_get_selection(pv->exc_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
}

/******************** signal handlers ********************/

static void policy_components_view_on_source_toggle(GtkToggleButton * widget, gpointer user_data)
{
	struct polcomp_view *pv = (struct polcomp_view *)user_data;
	/* clicking on the radio buttons emit two toggle signals, one for
	 * the original button and one for the new one.  thus only need to
	 * handle half of all signals */
	if (!gtk_toggle_button_get_active(widget)) {
		return;
	}
	gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(pv->inc_store));
	gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(pv->exc_store));
}

static void policy_components_gtk_tree_path_free(gpointer data, gpointer user_data __attribute__ ((unused)))
{
	gtk_tree_path_free((GtkTreePath *) data);
}

static void policy_components_gtk_tree_row_reference_free(gpointer data, gpointer user_data __attribute__ ((unused)))
{
	gtk_tree_row_reference_free((GtkTreeRowReference *) data);
}

static void policy_components_view_on_to_exc_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct polcomp_view *pv = (struct polcomp_view *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(pv->inc_view);
	GList *r, *rows = gtk_tree_selection_get_selected_rows(selection, NULL);
	GList *refs = NULL;

	/* use references because the filtered store will be changing
	 * as master_store's ISINC_COLUMN value changes */
	for (r = rows; r != NULL; r = r->next) {
		GtkTreePath *path = (GtkTreePath *) r->data;
		GtkTreeRowReference *ref = gtk_tree_row_reference_new(pv->inc_store, path);
		refs = g_list_prepend(refs, ref);
	}

	for (r = refs; r != NULL; r = r->next) {
		GtkTreeRowReference *ref = (GtkTreeRowReference *) r->data;
		GtkTreePath *path = gtk_tree_row_reference_get_path(ref);
		GtkTreeIter iter, child_iter;
		char *name;
		size_t i = 0;
		int retval;
		gtk_tree_model_get_iter(pv->inc_store, &iter, path);
		gtk_tree_model_filter_convert_iter_to_child_iter(GTK_TREE_MODEL_FILTER(pv->inc_store), &child_iter, &iter);
		gtk_tree_model_get(GTK_TREE_MODEL(pv->master_store), &child_iter, NAME_COLUMN, &name, -1);
		gtk_list_store_set(pv->master_store, &child_iter, ISINC_COLUMN, FALSE, -1);
		retval = apol_vector_get_index(pv->included_items, name, apol_str_strcmp, NULL, &i);
		assert(retval == 0);
		name = apol_vector_get_element(pv->included_items, i);
		free(name);
		apol_vector_remove(pv->included_items, i);
	}

	g_list_foreach(refs, policy_components_gtk_tree_row_reference_free, NULL);
	g_list_free(refs);
	g_list_foreach(rows, policy_components_gtk_tree_path_free, NULL);
	g_list_free(rows);
	gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(pv->inc_store));
	gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(pv->exc_store));
}

static void policy_components_view_on_to_inc_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	struct polcomp_view *pv = (struct polcomp_view *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(pv->exc_view);
	GList *r, *rows = gtk_tree_selection_get_selected_rows(selection, NULL);

	/* use references because the filtered store will be changing
	 * as master_store's ISINC_COLUMN value changes */
	GList *refs = NULL;
	for (r = rows; r != NULL; r = r->next) {
		GtkTreePath *path = (GtkTreePath *) r->data;
		GtkTreeRowReference *ref = gtk_tree_row_reference_new(pv->exc_store, path);
		refs = g_list_prepend(refs, ref);
	}

	for (r = refs; r != NULL; r = r->next) {
		GtkTreeRowReference *ref = (GtkTreeRowReference *) r->data;
		GtkTreePath *path = gtk_tree_row_reference_get_path(ref);
		GtkTreeIter iter, child_iter;
		char *name;
		gtk_tree_model_get_iter(pv->exc_store, &iter, path);
		gtk_tree_model_filter_convert_iter_to_child_iter(GTK_TREE_MODEL_FILTER(pv->exc_store), &child_iter, &iter);
		gtk_tree_model_get(GTK_TREE_MODEL(pv->master_store), &child_iter, NAME_COLUMN, &name, -1);
		gtk_list_store_set(pv->master_store, &child_iter, ISINC_COLUMN, TRUE, -1);
		apol_vector_append(pv->included_items, strdup(name));
	}
	apol_vector_sort_uniquify(pv->included_items, apol_str_strcmp, NULL, free);
	g_list_foreach(refs, policy_components_gtk_tree_row_reference_free, NULL);
	g_list_free(refs);
	g_list_foreach(rows, policy_components_gtk_tree_path_free, NULL);
	g_list_free(rows);
	gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(pv->inc_store));
	gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(pv->exc_store));
}

static void policy_components_view_on_select_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	GtkTreeView *tv = GTK_TREE_VIEW(user_data);
	GtkTreeSelection *selection = gtk_tree_view_get_selection(tv);
	gtk_tree_selection_select_all(selection);
}

static void policy_components_view_on_unselect_click(GtkButton * widget __attribute__ ((unused)), gpointer user_data)
{
	GtkTreeView *tv = GTK_TREE_VIEW(user_data);
	GtkTreeSelection *selection = gtk_tree_view_get_selection(tv);
	gtk_tree_selection_unselect_all(selection);
}

static void policy_components_view_init_signals(struct polcomp_view *pv)
{
	g_signal_connect(pv->log_radio, "toggled", G_CALLBACK(policy_components_view_on_source_toggle), pv);
	g_signal_connect(pv->policy_radio, "toggled", G_CALLBACK(policy_components_view_on_source_toggle), pv);
	g_signal_connect(pv->both_radio, "toggled", G_CALLBACK(policy_components_view_on_source_toggle), pv);
	g_signal_connect(pv->to_exc_button, "clicked", G_CALLBACK(policy_components_view_on_to_exc_click), pv);
	g_signal_connect(pv->to_inc_button, "clicked", G_CALLBACK(policy_components_view_on_to_inc_click), pv);
	g_signal_connect(pv->inc_select_button, "clicked", G_CALLBACK(policy_components_view_on_select_click), pv->inc_view);
	g_signal_connect(pv->inc_unselect_button, "clicked", G_CALLBACK(policy_components_view_on_unselect_click), pv->inc_view);
	g_signal_connect(pv->exc_select_button, "clicked", G_CALLBACK(policy_components_view_on_select_click), pv->exc_view);
	g_signal_connect(pv->exc_unselect_button, "clicked", G_CALLBACK(policy_components_view_on_unselect_click), pv->exc_view);
}

apol_vector_t *policy_components_view_run(toplevel_t * top, GtkWindow * parent, const char *title,
					  apol_vector_t * log_items, apol_vector_t * policy_items, apol_vector_t * included)
{
	struct polcomp_view pv;
	gint response;

	memset(&pv, 0, sizeof(pv));
	pv.top = top;
	pv.xml = glade_xml_new(toplevel_get_glade_xml(top), "PolicyComponentListsWindow", NULL);
	pv.log_items = log_items;
	pv.policy_items = policy_items;
	if (included == NULL) {
		pv.included_items = apol_vector_create();
	} else {
		pv.included_items = apol_vector_create_from_vector(included, apol_str_strdup, NULL);
	}
	apol_vector_destroy(&included, free);
	if (pv.included_items == NULL) {
		toplevel_ERR(pv.top, "Error creating dialog: %s", strerror(errno));
		return NULL;
	}

	policy_components_view_init_widgets(&pv);
	policy_components_view_init_lists(&pv);
	policy_components_view_init_signals(&pv);
	gtk_window_set_title(GTK_WINDOW(pv.dialog), title);
	do {
		response = gtk_dialog_run(pv.dialog);
	} while (response != GTK_RESPONSE_CLOSE);

	gtk_widget_destroy(GTK_WIDGET(pv.dialog));
	g_object_unref(pv.master_store);
	g_object_unref(pv.inc_store);
	g_object_unref(pv.exc_store);
	apol_vector_destroy(&pv.both_items, NULL);
	if (apol_vector_get_size(pv.included_items) == 0) {
		apol_vector_destroy(&pv.included_items, NULL);
		return NULL;
	}
	return pv.included_items;
}
