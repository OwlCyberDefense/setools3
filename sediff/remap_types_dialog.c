/**
 *  @file
 *  Displays a dialog that allows users to explicitly remap/remap
 *  types from one policy to the other.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
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

#include "remap_types_dialog.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <apol/type-query.h>
#include <apol/util.h>
#include <glade/glade.h>
#include <poldiff/type_map.h>

struct remap_types
{
	toplevel_t *top;
	GladeXML *xml;
	poldiff_t *diff;
	/** main dialog widget for type remapps*/
	GtkDialog *dialog;
	GtkTreeView *view;
	/** drop-down combo boxes that allow user to add new remap */
	GtkComboBoxEntry *combo[SEDIFFX_POLICY_NUM];
	GtkButton *add, *remove;
	GtkListStore *remaps;
	/** non-zero if a type map was added or removed */
	int changed;
};

static GtkListStore *types[SEDIFFX_POLICY_NUM] = { NULL, NULL };

/**
 * Populate the main text view with all type remaps currently within
 * the poldiff object.
 */
static void remap_types_update_view(struct remap_types *rt)
{
	apol_vector_t *entries = poldiff_type_remap_get_entries(rt->diff);
	apol_vector_t *origs = NULL, *mods = NULL;
	char *orig_string = NULL, *mod_string = NULL;
	size_t i;
	GtkTreeIter iter;
	gtk_list_store_clear(rt->remaps);
	for (i = 0; i < apol_vector_get_size(entries); i++) {
		poldiff_type_remap_entry_t *e = apol_vector_get_element(entries, i);
		if ((origs = poldiff_type_remap_entry_get_original_types(rt->diff, e)) == NULL ||
		    (mods = poldiff_type_remap_entry_get_modified_types(rt->diff, e)) == NULL ||
		    (orig_string = apol_str_join(origs, ", ")) == NULL || (mod_string = apol_str_join(mods, ", ")) == NULL) {
			toplevel_ERR(rt->top, "%s", strerror(errno));
			apol_vector_destroy(&origs, NULL);
			apol_vector_destroy(&mods, NULL);
			free(orig_string);
			free(mod_string);
			return;
		}
		/* don't display implicit remaps */
		if (!poldiff_type_remap_entry_get_is_inferred(e)) {
			gtk_list_store_append(rt->remaps, &iter);
			gtk_list_store_set(rt->remaps, &iter, 0, orig_string, 1, mod_string, 2, e, -1);
		}
		apol_vector_destroy(&origs, NULL);
		apol_vector_destroy(&mods, NULL);
		free(orig_string);
		free(mod_string);
	}
}

static void remap_types_on_selection_change(GtkTreeSelection * selection, gpointer user_data)
{
	struct remap_types *rt = (struct remap_types *)user_data;
	gboolean sens = gtk_tree_selection_get_selected(selection, NULL, NULL);
	gtk_widget_set_sensitive(GTK_WIDGET(rt->remove), sens);
}

static void remap_types_on_combo_change(GtkComboBox * widget __attribute__ ((unused)), gpointer user_data)
{
	struct remap_types *rt = (struct remap_types *)user_data;
	gchar *orig_text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(rt->combo[SEDIFFX_POLICY_ORIG]));
	gchar *mod_text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(rt->combo[SEDIFFX_POLICY_MOD]));
	if (orig_text != NULL && strcmp(orig_text, "") != 0 && mod_text != NULL && strcmp(mod_text, "") != 0) {
		gtk_widget_set_sensitive(GTK_WIDGET(rt->add), TRUE);
	} else {
		gtk_widget_set_sensitive(GTK_WIDGET(rt->add), FALSE);
	}
}

static void remap_types_on_add_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct remap_types *rt = (struct remap_types *)user_data;
	apol_vector_t *orig = NULL, *mod = NULL;
	gchar *orig_type = gtk_combo_box_get_active_text(GTK_COMBO_BOX(rt->combo[SEDIFFX_POLICY_ORIG]));
	gchar *mod_type = gtk_combo_box_get_active_text(GTK_COMBO_BOX(rt->combo[SEDIFFX_POLICY_MOD]));

	if ((orig = apol_str_split(orig_type, " ")) == NULL || (mod = apol_str_split(mod_type, " ")) == NULL) {
		toplevel_ERR(rt->top, "%s", strerror(errno));
	} else if (poldiff_type_remap_create(rt->diff, orig, mod) < 0) {
		toplevel_ERR(rt->top, "%s", "This was not a valid type remap.");
	} else {
		remap_types_update_view(rt);
		rt->changed = 1;
	}
	apol_vector_destroy(&orig, free);
	apol_vector_destroy(&mod, free);
}

static void remap_types_on_remove_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct remap_types *rt = (struct remap_types *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(rt->view);
	GtkTreeIter iter;
	if (gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		poldiff_type_remap_entry_t *entry;
		gtk_tree_model_get(GTK_TREE_MODEL(rt->remaps), &iter, SEDIFFX_POLICY_NUM, &entry, -1);
		poldiff_type_remap_entry_remove(rt->diff, entry);
		gtk_list_store_remove(rt->remaps, &iter);
		rt->changed = 1;
	}
}

static void remap_types_init_widgets(struct remap_types *rt)
{
	GtkTreeSelection *selection;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;

	rt->dialog = GTK_DIALOG(glade_xml_get_widget(rt->xml, "remap_types"));
	assert(rt->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(rt->dialog), toplevel_get_window(rt->top));
	rt->view = GTK_TREE_VIEW(glade_xml_get_widget(rt->xml, "remap_types treeview"));
	rt->combo[SEDIFFX_POLICY_ORIG] = GTK_COMBO_BOX_ENTRY(glade_xml_get_widget(rt->xml, "remap_types orig combo"));
	rt->combo[SEDIFFX_POLICY_MOD] = GTK_COMBO_BOX_ENTRY(glade_xml_get_widget(rt->xml, "remap_types mod combo"));
	assert(rt->view != NULL && rt->combo[SEDIFFX_POLICY_ORIG] != NULL && rt->combo[SEDIFFX_POLICY_MOD] != NULL);

	rt->add = GTK_BUTTON(glade_xml_get_widget(rt->xml, "remap_types add button"));
	rt->remove = GTK_BUTTON(glade_xml_get_widget(rt->xml, "remap_types remove button"));
	assert(rt->add != NULL && rt->remove != NULL);
	g_signal_connect(rt->add, "clicked", G_CALLBACK(remap_types_on_add_click), rt);
	g_signal_connect(rt->remove, "clicked", G_CALLBACK(remap_types_on_remove_click), rt);

	rt->remaps = gtk_list_store_new(SEDIFFX_POLICY_NUM + 1, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
	gtk_tree_view_set_model(rt->view, GTK_TREE_MODEL(rt->remaps));

	selection = gtk_tree_view_get_selection(rt->view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);
	g_signal_connect(selection, "changed", G_CALLBACK(remap_types_on_selection_change), rt);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Original Policy", renderer, "text", SEDIFFX_POLICY_ORIG, NULL);
	gtk_tree_view_column_set_expand(column, TRUE);
	gtk_tree_view_append_column(GTK_TREE_VIEW(rt->view), column);

	column = gtk_tree_view_column_new_with_attributes("Modified Policy", renderer, "text", SEDIFFX_POLICY_MOD, NULL);
	gtk_tree_view_column_set_expand(column, TRUE);
	gtk_tree_view_append_column(GTK_TREE_VIEW(rt->view), column);
}

/**
 * Set up the combo boxes to show only types unique to that policy.
 * (The lists of types were calculated by remap_types_update().)
 */
static void remap_types_init_combos(struct remap_types *rt)
{
	sediffx_policy_e i;
	for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
		gtk_combo_box_set_model(GTK_COMBO_BOX(rt->combo[i]), GTK_TREE_MODEL(types[i]));
		gtk_combo_box_entry_set_text_column(rt->combo[i], 0);
		g_signal_connect(rt->combo[i], "changed", G_CALLBACK(remap_types_on_combo_change), rt);
	}
}

int remap_types_run(toplevel_t * top)
{
	struct remap_types rt;
	gint response;

	memset(&rt, 0, sizeof(rt));
	rt.top = top;
	rt.xml = glade_xml_new(toplevel_get_glade_xml(rt.top), "remap_types", NULL);
	rt.diff = toplevel_get_poldiff(rt.top);

	remap_types_init_widgets(&rt);
	remap_types_init_combos(&rt);
	remap_types_update_view(&rt);

	response = gtk_dialog_run(rt.dialog);

	gtk_widget_destroy(GTK_WIDGET(rt.dialog));
	g_object_unref(rt.remaps);
	return rt.changed;
}

int remap_types_update(apol_policy_t * orig_policy, apol_policy_t * mod_policy)
{
	/* N.b.: The reason why this does not use libpoldiff for the
	 * calculations is because libpoldiff would invoke the already
	 * stored type maps when finding the types.  So rather than
	 * disabling all maps and then getting the diffs, this finds the
	 * differences directly. */
	qpol_policy_t *oq = apol_policy_get_qpol(orig_policy);
	qpol_policy_t *mq = apol_policy_get_qpol(mod_policy);
	apol_vector_t *type_vector = NULL, *v = NULL;
	size_t i;
	qpol_type_t *t;
	char *type_name;
	GtkTreeIter iter;
	int error = 0, retval = -1;

	if (types[SEDIFFX_POLICY_ORIG] == NULL) {
		types[SEDIFFX_POLICY_ORIG] = gtk_list_store_new(1, G_TYPE_STRING);
	} else {
		gtk_list_store_clear(types[SEDIFFX_POLICY_ORIG]);
	}
	if (types[SEDIFFX_POLICY_MOD] == NULL) {
		types[SEDIFFX_POLICY_MOD] = gtk_list_store_new(1, G_TYPE_STRING);
	} else {
		gtk_list_store_clear(types[SEDIFFX_POLICY_MOD]);
	}

	if (apol_type_get_by_query(orig_policy, NULL, &type_vector) < 0 || (v = apol_vector_create()) == NULL) {
		error = errno;
		goto cleanup;
	}
	/* only add original types that are not in modified policy */
	for (i = 0; i < apol_vector_get_size(type_vector); i++) {
		t = apol_vector_get_element(type_vector, i);
		qpol_type_get_name(oq, t, &type_name);
		if (qpol_policy_get_type_by_name(mq, type_name, &t) != 0 && apol_vector_append(v, type_name) < 0) {
			error = errno;
			goto cleanup;
		}
	}
	apol_vector_sort(v, apol_str_strcmp, NULL);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		type_name = apol_vector_get_element(v, i);
		gtk_list_store_append(types[SEDIFFX_POLICY_ORIG], &iter);
		gtk_list_store_set(types[SEDIFFX_POLICY_ORIG], &iter, 0, type_name, -1);
	}
	apol_vector_destroy(&type_vector, NULL);
	apol_vector_destroy(&v, NULL);

	if (apol_type_get_by_query(mod_policy, NULL, &type_vector) < 0 || (v = apol_vector_create()) == NULL) {
		error = errno;
		goto cleanup;
	}
	/* only add modified types that are not in original policy */
	for (i = 0; i < apol_vector_get_size(type_vector); i++) {
		t = apol_vector_get_element(type_vector, i);
		qpol_type_get_name(mq, t, &type_name);
		if (qpol_policy_get_type_by_name(oq, type_name, &t) != 0 && apol_vector_append(v, type_name) < 0) {
			error = errno;
			goto cleanup;
		}
	}
	apol_vector_sort(v, apol_str_strcmp, NULL);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		type_name = apol_vector_get_element(v, i);
		gtk_list_store_append(types[SEDIFFX_POLICY_MOD], &iter);
		gtk_list_store_set(types[SEDIFFX_POLICY_MOD], &iter, 0, type_name, -1);
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&type_vector, NULL);
	apol_vector_destroy(&v, NULL);
	if (retval != 0) {
		errno = error;
		return retval;
	}
	return retval;
}
