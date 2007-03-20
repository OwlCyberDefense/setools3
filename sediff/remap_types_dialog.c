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
	GtkCheckButton *show_inferred;
	/** drop-down combo boxes that allow user to add new remap */
	GtkComboBoxEntry *combo[SEDIFFX_POLICY_NUM];
	GtkButton *add, *remove;
	GtkListStore *remaps;
	GtkTreeModelSort *sort;
	GtkTreeModelFilter *filter;
	/** non-zero if a type map was added or removed */
	int changed;
};

enum
{
	ORIG_NAME_COL = 0, MOD_NAME_COL, ORIG_HIGHLIGHT_VALUE_COL, MOD_HIGHLIGHT_VALUE_COL, ENTRY_COL, NUM_COLUMNS
};

static GtkListStore *types[SEDIFFX_POLICY_NUM] = { NULL, NULL };

/**
 * Go through all entries in the list store; for those that map the
 * current entries for the combo boxes, highlight them.
 */
static void remap_types_highlight_entries(struct remap_types *rt)
{
	gchar *orig_text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(rt->combo[SEDIFFX_POLICY_ORIG]));
	gchar *mod_text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(rt->combo[SEDIFFX_POLICY_MOD]));
	int num_orig_matches = 0, num_mod_matches = 0;
	gboolean iter_valid;
	GtkTreeIter iter;
	poldiff_type_remap_entry_t *entry;
	apol_vector_t *v;
	size_t idx;
	iter_valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(rt->remaps), &iter);
	while (iter_valid) {
		gtk_tree_model_get(GTK_TREE_MODEL(rt->remaps), &iter, ENTRY_COL, &entry, -1);
		if (orig_text != NULL && strcmp(orig_text, "") != 0) {
			v = poldiff_type_remap_entry_get_original_types(rt->diff, entry);
			if (apol_vector_get_index(v, orig_text, apol_str_strcmp, NULL, &idx) == 0) {
				gtk_list_store_set(rt->remaps, &iter, ORIG_HIGHLIGHT_VALUE_COL, PANGO_WEIGHT_BOLD, -1);
				num_orig_matches++;
			} else {
				gtk_list_store_set(rt->remaps, &iter, ORIG_HIGHLIGHT_VALUE_COL, PANGO_WEIGHT_NORMAL, -1);
			}
			apol_vector_destroy(&v, NULL);
		}
		if (mod_text != NULL && strcmp(mod_text, "") != 0) {
			v = poldiff_type_remap_entry_get_modified_types(rt->diff, entry);
			if (apol_vector_get_index(v, mod_text, apol_str_strcmp, NULL, &idx) == 0) {
				gtk_list_store_set(rt->remaps, &iter, MOD_HIGHLIGHT_VALUE_COL, PANGO_WEIGHT_BOLD, -1);
				num_mod_matches++;
			} else {
				gtk_list_store_set(rt->remaps, &iter, MOD_HIGHLIGHT_VALUE_COL, PANGO_WEIGHT_NORMAL, -1);
			}
			apol_vector_destroy(&v, NULL);
		}
		iter_valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(rt->remaps), &iter);
	}
	gtk_widget_set_sensitive(GTK_WIDGET(rt->add), FALSE);
	if (orig_text != NULL && strcmp(orig_text, "") != 0 && mod_text != NULL && strcmp(mod_text, "") != 0) {
		/* enable the add button if and only if:  number of
		 * orig and mod matches are both 0, or one side is 1
		 * and the other is 0 */
		if ((num_orig_matches == 0 && num_mod_matches == 0) ||
		    (num_orig_matches == 1 && num_mod_matches == 0) || (num_orig_matches == 0 && num_mod_matches == 1)) {
			gtk_widget_set_sensitive(GTK_WIDGET(rt->add), TRUE);
		}
	}
}

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
		gtk_list_store_append(rt->remaps, &iter);
		gtk_list_store_set(rt->remaps, &iter, ORIG_NAME_COL, orig_string, MOD_NAME_COL, mod_string, ENTRY_COL, e, -1);
		apol_vector_destroy(&origs, NULL);
		apol_vector_destroy(&mods, NULL);
		free(orig_string);
		free(mod_string);
	}
	remap_types_highlight_entries(rt);
}

static void remap_types_on_show_inferred_toggle(GtkToggleButton * toggle __attribute__ ((unused)), gpointer user_data)
{
	struct remap_types *rt = (struct remap_types *)user_data;
	gtk_tree_model_filter_refilter(rt->filter);
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
	remap_types_highlight_entries(rt);
}

static void remap_types_on_add_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct remap_types *rt = (struct remap_types *)user_data;
	apol_vector_t *orig = NULL, *mod = NULL;
	apol_vector_t *old_orig = NULL, *old_mod = NULL;
	gchar *orig_type = gtk_combo_box_get_active_text(GTK_COMBO_BOX(rt->combo[SEDIFFX_POLICY_ORIG]));
	gchar *mod_type = gtk_combo_box_get_active_text(GTK_COMBO_BOX(rt->combo[SEDIFFX_POLICY_MOD]));

	if ((orig = apol_str_split(orig_type, " ")) == NULL || (mod = apol_str_split(mod_type, " ")) == NULL) {
		toplevel_ERR(rt->top, "%s", strerror(errno));
	}
	if (apol_vector_get_size(orig) > 1 && apol_vector_get_size(mod) > 1) {
		toplevel_ERR(rt->top, "%s", "Remappings may be 1 to many or many to 1, but not many to many.");
		goto cleanup;
	}

	/* check all existing remap entries, to see if the user's
	 * entries should be appended to an existing entry */
	GtkTreeIter iter;
	gboolean iter_valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(rt->remaps), &iter);
	poldiff_type_remap_entry_t *entry = NULL, *e;
	/* remap_types_highlight_entries() should have already marked
	 * which of the existing entries match the user's inputs */
	while (iter_valid) {
		gint orig_marked, mod_marked;
		gtk_tree_model_get(GTK_TREE_MODEL(rt->remaps), &iter, ORIG_HIGHLIGHT_VALUE_COL, &orig_marked,
				   MOD_HIGHLIGHT_VALUE_COL, &mod_marked, ENTRY_COL, &e, -1);
		assert(orig_marked != PANGO_WEIGHT_BOLD || mod_marked != PANGO_WEIGHT_BOLD);
		if (orig_marked == PANGO_WEIGHT_BOLD) {
			assert(entry == NULL);
			entry = e;
		} else if (mod_marked == PANGO_WEIGHT_BOLD) {
			assert(entry == NULL);
			entry = e;
		}
		iter_valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(rt->remaps), &iter);
	}
	if (entry != NULL) {
		size_t i;
		char *s;
		old_orig = poldiff_type_remap_entry_get_original_types(rt->diff, entry);
		old_mod = poldiff_type_remap_entry_get_modified_types(rt->diff, entry);
		assert(old_orig != NULL && old_mod != NULL);
		for (i = 0; i < apol_vector_get_size(old_orig); i++) {
			s = strdup(apol_vector_get_element(old_orig, i));
			if (apol_vector_append_unique(orig, s, apol_str_strcmp, NULL) > 0) {
				free(s);
			}
		}
		for (i = 0; i < apol_vector_get_size(old_mod); i++) {
			s = strdup(apol_vector_get_element(old_mod, i));
			if (apol_vector_append_unique(mod, s, apol_str_strcmp, NULL) > 0) {
				free(s);
			}
		}
		poldiff_type_remap_entry_remove(rt->diff, entry);
	}

	if (poldiff_type_remap_create(rt->diff, orig, mod) < 0) {
		toplevel_ERR(rt->top, "%s", "This was not a valid type remap.");
		goto cleanup;
	} else {
		remap_types_update_view(rt);
		rt->changed = 1;
	}
      cleanup:
	apol_vector_destroy(&orig, free);
	apol_vector_destroy(&mod, free);
	apol_vector_destroy(&old_orig, NULL);
	apol_vector_destroy(&old_mod, NULL);
}

static void remap_types_on_remove_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	struct remap_types *rt = (struct remap_types *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(rt->view);
	GtkTreeIter iter;
	if (gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		poldiff_type_remap_entry_t *entry;
		gtk_tree_model_get(GTK_TREE_MODEL(rt->sort), &iter, ENTRY_COL, &entry, -1);
		poldiff_type_remap_entry_remove(rt->diff, entry);
		GtkTreeIter filteriter, listiter;
		gtk_tree_model_sort_convert_iter_to_child_iter(rt->sort, &filteriter, &iter);
		gtk_tree_model_filter_convert_iter_to_child_iter(rt->filter, &listiter, &filteriter);
		gtk_list_store_remove(rt->remaps, &listiter);
		rt->changed = 1;
	}
}

static gint remap_types_sort_compare(GtkTreeModel * model, GtkTreeIter * a, GtkTreeIter * b, gpointer user_data)
{
	gint column = GPOINTER_TO_INT(user_data);
	char *s, *t;
	gtk_tree_model_get(model, a, column, &s, -1);
	gtk_tree_model_get(model, b, column, &t, -1);
	/* these next two conditionals are needed because while the remap
	 * list store is being built, a row will temporarily have empty
	 * strings */
	if (s == NULL) {
		s = "";
	}
	if (t == NULL) {
		t = "";
	}
	return strcmp(s, t);
}

static gboolean remap_types_filter_visible(GtkTreeModel * model, GtkTreeIter * iter, gpointer user_data)
{
	struct remap_types *rt = (struct remap_types *)user_data;
	poldiff_type_remap_entry_t *entry;
	gtk_tree_model_get(GTK_TREE_MODEL(model), iter, ENTRY_COL, &entry, -1);
	if (poldiff_type_remap_entry_get_is_inferred(entry)) {
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rt->show_inferred))) {
			return TRUE;
		}
		return FALSE;
	} else {
		/* explicit maps are always shown */
		return TRUE;
	}
}

static void remap_types_init_widgets(struct remap_types *rt)
{
	GtkTreeSelection *selection;
	GtkCellRenderer *orig_renderer, *mod_renderer;
	GtkTreeViewColumn *column;

	rt->dialog = GTK_DIALOG(glade_xml_get_widget(rt->xml, "remap_types"));
	assert(rt->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(rt->dialog), toplevel_get_window(rt->top));
	rt->view = GTK_TREE_VIEW(glade_xml_get_widget(rt->xml, "remap_types treeview"));
	rt->show_inferred = GTK_CHECK_BUTTON(glade_xml_get_widget(rt->xml, "remap_types inferred checkbutton"));
	rt->combo[SEDIFFX_POLICY_ORIG] = GTK_COMBO_BOX_ENTRY(glade_xml_get_widget(rt->xml, "remap_types orig combo"));
	rt->combo[SEDIFFX_POLICY_MOD] = GTK_COMBO_BOX_ENTRY(glade_xml_get_widget(rt->xml, "remap_types mod combo"));
	assert(rt->view != NULL && rt->show_inferred && rt->combo[SEDIFFX_POLICY_ORIG] != NULL
	       && rt->combo[SEDIFFX_POLICY_MOD] != NULL);
	g_signal_connect(rt->show_inferred, "toggled", G_CALLBACK(remap_types_on_show_inferred_toggle), rt);

	rt->add = GTK_BUTTON(glade_xml_get_widget(rt->xml, "remap_types add button"));
	rt->remove = GTK_BUTTON(glade_xml_get_widget(rt->xml, "remap_types remove button"));
	assert(rt->add != NULL && rt->remove != NULL);
	g_signal_connect(rt->add, "clicked", G_CALLBACK(remap_types_on_add_click), rt);
	g_signal_connect(rt->remove, "clicked", G_CALLBACK(remap_types_on_remove_click), rt);

	rt->remaps = gtk_list_store_new(NUM_COLUMNS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT, G_TYPE_POINTER);
	rt->filter = GTK_TREE_MODEL_FILTER(gtk_tree_model_filter_new(GTK_TREE_MODEL(rt->remaps), NULL));
	gtk_tree_model_filter_set_visible_func(rt->filter, remap_types_filter_visible, rt, NULL);
	rt->sort = GTK_TREE_MODEL_SORT(gtk_tree_model_sort_new_with_model(GTK_TREE_MODEL(rt->filter)));
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(rt->sort), ORIG_NAME_COL, remap_types_sort_compare,
					GINT_TO_POINTER(ORIG_NAME_COL), NULL);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(rt->sort), MOD_NAME_COL, remap_types_sort_compare,
					GINT_TO_POINTER(MOD_NAME_COL), NULL);
	gtk_tree_sortable_set_default_sort_func(GTK_TREE_SORTABLE(rt->sort), remap_types_sort_compare,
						GINT_TO_POINTER(ORIG_NAME_COL), NULL);
	gtk_tree_view_set_model(rt->view, GTK_TREE_MODEL(rt->sort));

	selection = gtk_tree_view_get_selection(rt->view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);
	g_signal_connect(selection, "changed", G_CALLBACK(remap_types_on_selection_change), rt);

	orig_renderer = gtk_cell_renderer_text_new();
	mod_renderer = gtk_cell_renderer_text_new();
	g_object_set(orig_renderer, "weight", PANGO_WEIGHT_BOLD, NULL);
	g_object_set(mod_renderer, "weight", PANGO_WEIGHT_BOLD, NULL);
	column = gtk_tree_view_column_new_with_attributes("Original Policy", orig_renderer, "text", ORIG_NAME_COL, "weight",
							  ORIG_HIGHLIGHT_VALUE_COL, NULL);
	gtk_tree_view_column_set_expand(column, TRUE);
	gtk_tree_view_column_set_sort_column_id(column, ORIG_NAME_COL);
	gtk_tree_view_column_set_sort_indicator(column, TRUE);
	gtk_tree_view_append_column(GTK_TREE_VIEW(rt->view), column);
	gtk_tree_view_column_clicked(column);

	column = gtk_tree_view_column_new_with_attributes("Modified Policy", mod_renderer, "text", MOD_NAME_COL, "weight",
							  MOD_HIGHLIGHT_VALUE_COL, NULL);
	gtk_tree_view_column_set_expand(column, TRUE);
	gtk_tree_view_column_set_sort_column_id(column, MOD_NAME_COL);
	gtk_tree_view_column_set_sort_indicator(column, TRUE);
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

/**
 * Alphabetize a list of qpol_type_t, base upon their names.
 */
static int remap_types_qpol_type_cmp(const void *a, const void *b, void *data)
{
	qpol_type_t *x = (qpol_type_t *) a;
	qpol_type_t *y = (qpol_type_t *) b;
	qpol_policy_t *q = (qpol_policy_t *) data;
	char *s, *t;
	qpol_type_get_name(q, x, &s);
	qpol_type_get_name(q, y, &t);
	return strcmp(s, t);
}

int remap_types_update(apol_policy_t * orig_policy, apol_policy_t * mod_policy)
{
	qpol_policy_t *oq = apol_policy_get_qpol(orig_policy);
	qpol_policy_t *mq = apol_policy_get_qpol(mod_policy);
	apol_vector_t *v = NULL;
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
	if (apol_type_get_by_query(orig_policy, NULL, &v) < 0) {
		error = errno;
		goto cleanup;
	}
	apol_vector_sort(v, remap_types_qpol_type_cmp, oq);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		t = apol_vector_get_element(v, i);
		qpol_type_get_name(oq, t, &type_name);
		gtk_list_store_append(types[SEDIFFX_POLICY_ORIG], &iter);
		gtk_list_store_set(types[SEDIFFX_POLICY_ORIG], &iter, 0, type_name, -1);
	}
	apol_vector_destroy(&v, NULL);

	if (types[SEDIFFX_POLICY_MOD] == NULL) {
		types[SEDIFFX_POLICY_MOD] = gtk_list_store_new(1, G_TYPE_STRING);
	} else {
		gtk_list_store_clear(types[SEDIFFX_POLICY_MOD]);
	}
	if (apol_type_get_by_query(mod_policy, NULL, &v) < 0) {
		error = errno;
		goto cleanup;
	}
	apol_vector_sort(v, remap_types_qpol_type_cmp, mq);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		t = apol_vector_get_element(v, i);
		qpol_type_get_name(mq, t, &type_name);
		gtk_list_store_append(types[SEDIFFX_POLICY_MOD], &iter);
		gtk_list_store_set(types[SEDIFFX_POLICY_MOD], &iter, 0, type_name, -1);
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v, NULL);
	if (retval != 0) {
		errno = error;
		return retval;
	}
	return retval;
}
