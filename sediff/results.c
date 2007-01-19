/**
 *  @file
 *  Routines for displaying the results after running poldiff.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
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

#include <config.h>

#include "results.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <glade/glade.h>
#include <qpol/cond_query.h>

enum
{
	RESULTS_SUMMARY_COLUMN_LABEL = 0,
	RESULTS_SUMMARY_COLUMN_DIFFBIT,
	RESULTS_SUMMARY_COLUMN_FORM,
	RESULTS_SUMMARY_COLUMN_RECORD,
	RESULTS_SUMMARY_COLUMN_NUM
};

enum
{
	RESULTS_BUFFER_MAIN = 0,
	RESULTS_BUFFER_TE_ADD, RESULTS_BUFFER_TE_ADDTYPE,
	RESULTS_BUFFER_TE_REMOVED, RESULTS_BUFFER_TE_REMOVE_TYPE,
	RESULTS_BUFFER_MODIFIED,
	RESULTS_BUFFER_NUM
};

struct results
{
	toplevel_t *top;
	GladeXML *xml;
	GtkTreeStore *summary_tree;
	GtkTreeView *summary_view;
	GtkTextBuffer *buffers[RESULTS_BUFFER_NUM];
	GtkTextBuffer *key_buffer;
	GtkTextView *view;
	GtkTextTag *policy_orig_tag, *policy_mod_tag;
	GtkLabel *stats;
	/** flags to indicate if a TE buffer needs to be redrawn or not */
	int te_buffered[RESULTS_BUFFER_NUM];
	/** current sort field for a given TE buffer */
	results_sort_e te_sort_field[RESULTS_BUFFER_NUM];
	/** current sort direction for a given TE buffer */
	int te_sort_direction[RESULTS_BUFFER_NUM];
	/** array of line numbers, giving where the cursor is for that
	 * particular results display */
	gint *saved_offsets;
	size_t current_buffer;
};

struct poldiff_item_record
{
	const char *label;
	int record_id;
	uint32_t bit_pos;
	int has_add_type;
	apol_vector_t *(*get_vector) (poldiff_t *);
	 poldiff_form_e(*get_form) (const void *);
	char *(*get_string) (poldiff_t *, const void *);
};

static const struct poldiff_item_record poldiff_items[] = {
	{"Classes", 1, POLDIFF_DIFF_CLASSES, 0,
	 poldiff_get_class_vector, poldiff_class_get_form, poldiff_class_to_string},
	{"Commons", 2, POLDIFF_DIFF_COMMONS, 0,
	 poldiff_get_common_vector, poldiff_common_get_form, poldiff_common_to_string},
	{"Types", 3, POLDIFF_DIFF_TYPES, 0,
	 poldiff_get_type_vector, poldiff_type_get_form, poldiff_type_to_string},
	{"Attributes", 4, POLDIFF_DIFF_ATTRIBS, 0,
	 poldiff_get_attrib_vector, poldiff_attrib_get_form, poldiff_attrib_to_string},
	{"Roles", 5, POLDIFF_DIFF_ROLES, 0,
	 poldiff_get_role_vector, poldiff_role_get_form, poldiff_role_to_string},
	{"Users", 6, POLDIFF_DIFF_USERS, 0,
	 poldiff_get_user_vector, poldiff_user_get_form, poldiff_user_to_string},
	{"Booleans", 7, POLDIFF_DIFF_BOOLS, 0,
	 poldiff_get_bool_vector, poldiff_bool_get_form, poldiff_bool_to_string},
	{"Role Allows", 8, POLDIFF_DIFF_ROLE_ALLOWS, 0,
	 poldiff_get_role_allow_vector, poldiff_role_allow_get_form, poldiff_role_allow_to_string},
	{"Role Transitions", 9, POLDIFF_DIFF_ROLE_TRANS, 1,
	 poldiff_get_role_trans_vector, poldiff_role_trans_get_form, poldiff_role_trans_to_string},
	{"TE Rules", 10, POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES, 1,
	 NULL, NULL, NULL /* special case because this is from two data */ },
	{NULL, 11, 0, 0, NULL, NULL, NULL}
};

static void results_summary_on_change(GtkTreeSelection * selection, gpointer user_data);

static gboolean results_on_line_event(GtkTextTag * tag, GObject * event_object,
				      GdkEvent * event, const GtkTextIter * iter, gpointer user_data);
static gboolean results_on_text_view_motion(GtkWidget * widget, GdkEventMotion * event, gpointer user_data);

/**
 * Build a GTK tree store to hold the summary table of contents; then
 * add that (empty) tree to the tree view.
 */
static void results_create_summary(results_t * r)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkTreeSelection *selection;

	r->summary_tree = gtk_tree_store_new(RESULTS_SUMMARY_COLUMN_NUM, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT, G_TYPE_POINTER);
	r->summary_view = GTK_TREE_VIEW(glade_xml_get_widget(r->xml, "toplevel summary view"));
	assert(r->summary_view != NULL);
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_GROW_ONLY);
	gtk_tree_view_column_set_title(col, "Differences");
	gtk_tree_view_append_column(r->summary_view, col);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", RESULTS_SUMMARY_COLUMN_LABEL);
	gtk_tree_view_set_model(r->summary_view, GTK_TREE_MODEL(r->summary_tree));

	selection = gtk_tree_view_get_selection(r->summary_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);
	g_signal_connect(G_OBJECT(selection), "changed", G_CALLBACK(results_summary_on_change), r);
}

results_t *results_create(toplevel_t * top)
{
	results_t *r;
	int i;
	GtkTextTagTable *tag_table;
	GtkTextAttributes *attr;
	GtkTextView *text_view;
	gint size;
	PangoTabArray *tabs;

	if ((r = calloc(1, sizeof(*r))) == NULL) {
		return NULL;
	}
	r->top = top;
	r->xml = glade_get_widget_tree(GTK_WIDGET(toplevel_get_window(r->top)));
	results_create_summary(r);

	for (i = 0; i < RESULTS_BUFFER_NUM; i++) {
		r->te_sort_field[i] = RESULTS_SORT_DEFAULT;
		r->te_sort_direction[i] = RESULTS_SORT_ASCEND;
	}
	/* allocate an array to keep track of the scrollbar position; that
	 * way when a user switches to a particular result item the view
	 * will retain its position */
	for (i = 0; poldiff_items[i].label != NULL; i++) ;
	/* add 1 for the summary buffer; multiply by 6 for the 5 different
	 * difference forms + summary display */
	r->saved_offsets = g_malloc0((i + 1) * 6 * sizeof(gint));

	r->buffers[0] = gtk_text_buffer_new(NULL);
	tag_table = gtk_text_buffer_get_tag_table(r->buffers[0]);
	for (i = 1; i < RESULTS_BUFFER_NUM; i++) {
		r->buffers[i] = gtk_text_buffer_new(tag_table);
	}
	gtk_text_buffer_create_tag(r->buffers[0], "header", "style", PANGO_STYLE_ITALIC, "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(r->buffers[0], "subheader",
				   "family", "monospace", "weight", PANGO_WEIGHT_BOLD, "underline", PANGO_UNDERLINE_SINGLE, NULL);
	gtk_text_buffer_create_tag(r->buffers[0], "removed-header",
				   "family", "monospace", "foreground", "red", "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(r->buffers[0], "added-header",
				   "family", "monospace", "foreground", "dark green", "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(r->buffers[0], "modified-header",
				   "family", "monospace", "foreground", "dark blue", "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(r->buffers[0], "removed", "family", "monospace", "foreground", "red", NULL);
	gtk_text_buffer_create_tag(r->buffers[0], "added", "family", "monospace", "foreground", "dark green", NULL);
	gtk_text_buffer_create_tag(r->buffers[0], "modified", "family", "monospace", "foreground", "dark blue", NULL);
	r->policy_orig_tag = gtk_text_buffer_create_tag(r->buffers[0], "line-pol_orig",
							"family", "monospace",
							"foreground", "blue", "underline", PANGO_UNDERLINE_SINGLE, NULL);
	g_signal_connect_after(G_OBJECT(r->policy_orig_tag), "event", G_CALLBACK(results_on_line_event), r);
	r->policy_mod_tag = gtk_text_buffer_create_tag(r->buffers[0], "line-pol_mod",
						       "family", "monospace",
						       "foreground", "blue", "underline", PANGO_UNDERLINE_SINGLE, NULL);
	g_signal_connect_after(G_OBJECT(r->policy_mod_tag), "event", G_CALLBACK(results_on_line_event), r);

	r->view = GTK_TEXT_VIEW(glade_xml_get_widget(r->xml, "toplevel results view"));
	assert(r->view != NULL);
	g_signal_connect(G_OBJECT(r->view), "motion-notify-event", G_CALLBACK(results_on_text_view_motion), r);
	attr = gtk_text_view_get_default_attributes(r->view);
	size = pango_font_description_get_size(attr->font);
	tabs = pango_tab_array_new_with_positions(4,
						  FALSE,
						  PANGO_TAB_LEFT, 3 * size,
						  PANGO_TAB_LEFT, 6 * size, PANGO_TAB_LEFT, 9 * size, PANGO_TAB_LEFT, 12 * size);
	gtk_text_view_set_tabs(r->view, tabs);
	gtk_text_view_set_buffer(r->view, r->buffers[RESULTS_BUFFER_MAIN]);
	r->current_buffer = 0;

	r->key_buffer = gtk_text_buffer_new(tag_table);
	text_view = GTK_TEXT_VIEW(glade_xml_get_widget(r->xml, "toplevel key view"));
	assert(text_view != NULL);
	gtk_text_view_set_buffer(text_view, r->key_buffer);

	r->stats = GTK_LABEL((glade_xml_get_widget(r->xml, "toplevel stats label")));
	assert(r->stats != NULL);
	gtk_label_set_text(r->stats, "");

	return r;
}

void results_destroy(results_t ** r)
{
	if (r != NULL && *r != NULL) {
		free((*r)->saved_offsets);
		free(*r);
		*r = NULL;
	}
}

void results_clear(results_t * r)
{
	size_t i;
	gtk_tree_store_clear(r->summary_tree);
	for (i = 0; i < RESULTS_BUFFER_NUM; i++) {
		util_text_buffer_clear(r->buffers[i]);
		r->te_buffered[i] = 0;
	}
	gtk_text_view_set_buffer(r->view, r->buffers[RESULTS_BUFFER_MAIN]);
	r->current_buffer = 0;
	util_text_buffer_clear(r->key_buffer);
}

/**
 * Update the summary tree to reflect the number of items
 * added/removed/modified.
 */
static void results_update_summary(results_t * r)
{
	GtkTreeIter topiter, childiter;
	size_t stats[5] = { 0, 0, 0, 0, 0 }, i;
	GString *s = g_string_new("");
	poldiff_t *diff = toplevel_get_poldiff(r->top);
	uint32_t flags = toplevel_get_poldiff_run_flags(r->top);
	assert(diff != NULL);

	gtk_tree_store_append(r->summary_tree, &topiter, NULL);
	gtk_tree_store_set(r->summary_tree, &topiter,
			   RESULTS_SUMMARY_COLUMN_LABEL, "Summary",
			   RESULTS_SUMMARY_COLUMN_DIFFBIT, 0,
			   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_NONE, RESULTS_SUMMARY_COLUMN_RECORD, NULL, -1);

	for (i = 0; poldiff_items[i].label != NULL; i++) {
		if (!poldiff_is_run(diff, poldiff_items[i].bit_pos)) {
			continue;
		}
		poldiff_get_stats(diff, poldiff_items[i].bit_pos, stats);

		gtk_tree_store_append(r->summary_tree, &topiter, NULL);
		g_string_printf(s, "%s %zd", poldiff_items[i].label, stats[0] + stats[1] + stats[2] + stats[3] + stats[4]);
		gtk_tree_store_set(r->summary_tree, &topiter,
				   RESULTS_SUMMARY_COLUMN_LABEL, s->str,
				   RESULTS_SUMMARY_COLUMN_DIFFBIT, poldiff_items[i].bit_pos,
				   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_NONE,
				   RESULTS_SUMMARY_COLUMN_RECORD, poldiff_items + i, -1);

		gtk_tree_store_append(r->summary_tree, &childiter, &topiter);
		g_string_printf(s, "Added %zd", stats[0]);
		gtk_tree_store_set(r->summary_tree, &childiter,
				   RESULTS_SUMMARY_COLUMN_LABEL, s->str,
				   RESULTS_SUMMARY_COLUMN_DIFFBIT, poldiff_items[i].bit_pos,
				   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_ADDED,
				   RESULTS_SUMMARY_COLUMN_RECORD, poldiff_items + i, -1);

		if (poldiff_items[i].has_add_type) {
			gtk_tree_store_append(r->summary_tree, &childiter, &topiter);
			g_string_printf(s, "Added Type %zd", stats[3]);
			gtk_tree_store_set(r->summary_tree, &childiter,
					   RESULTS_SUMMARY_COLUMN_LABEL, s->str,
					   RESULTS_SUMMARY_COLUMN_DIFFBIT, poldiff_items[i].bit_pos,
					   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_ADD_TYPE,
					   RESULTS_SUMMARY_COLUMN_RECORD, poldiff_items + i, -1);
		}

		gtk_tree_store_append(r->summary_tree, &childiter, &topiter);
		g_string_printf(s, "Removed %zd", stats[1]);
		gtk_tree_store_set(r->summary_tree, &childiter,
				   RESULTS_SUMMARY_COLUMN_LABEL, s->str,
				   RESULTS_SUMMARY_COLUMN_DIFFBIT, poldiff_items[i].bit_pos,
				   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_REMOVED,
				   RESULTS_SUMMARY_COLUMN_RECORD, poldiff_items + i, -1);

		if (poldiff_items[i].has_add_type) {
			gtk_tree_store_append(r->summary_tree, &childiter, &topiter);
			g_string_printf(s, "Removed Type %zd", stats[4]);
			gtk_tree_store_set(r->summary_tree, &childiter,
					   RESULTS_SUMMARY_COLUMN_LABEL, s->str,
					   RESULTS_SUMMARY_COLUMN_DIFFBIT, poldiff_items[i].bit_pos,
					   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_REMOVE_TYPE,
					   RESULTS_SUMMARY_COLUMN_RECORD, poldiff_items + i, -1);
		}
		if (poldiff_items[i].bit_pos != POLDIFF_DIFF_TYPES || (flags & POLDIFF_DIFF_ATTRIBS)) {
			gtk_tree_store_append(r->summary_tree, &childiter, &topiter);
			g_string_printf(s, "Modified %zd", stats[2]);
			gtk_tree_store_set(r->summary_tree, &childiter,
					   RESULTS_SUMMARY_COLUMN_LABEL, s->str,
					   RESULTS_SUMMARY_COLUMN_DIFFBIT, poldiff_items[i].bit_pos,
					   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_MODIFIED,
					   RESULTS_SUMMARY_COLUMN_RECORD, poldiff_items + i, -1);
		}
	}

	g_string_free(s, TRUE);
}

/**
 * Show the legend of the symbols used in results displays.
 */
static void results_populate_key_buffer(results_t * r)
{
	GString *string = g_string_new("");
	GtkTextIter iter;

	gtk_text_buffer_get_end_iter(r->key_buffer, &iter);

	g_string_printf(string, " Added(+):\n  Items added in\n  modified policy.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(r->key_buffer, &iter, string->str, -1, "added", NULL);
	g_string_printf(string, " Removed(-):\n  Items removed\n  from original\n   policy.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(r->key_buffer, &iter, string->str, -1, "removed", NULL);
	g_string_printf(string, " Modified(*):\n  Items modified\n  from original\n  policy to\n  modified policy.");
	gtk_text_buffer_insert_with_tags_by_name(r->key_buffer, &iter, string->str, -1, "modified", NULL);
	g_string_free(string, TRUE);
}

/**
 * Populate the status bar with summary info of our diff.
 */
static void results_update_stats(results_t * r)
{
	GString *string = g_string_new("");
	size_t class_stats[5] = { 0, 0, 0, 0, 0 };
	size_t common_stats[5] = { 0, 0, 0, 0, 0 };
	size_t type_stats[5] = { 0, 0, 0, 0, 0 };
	size_t attrib_stats[5] = { 0, 0, 0, 0, 0 };
	size_t role_stats[5] = { 0, 0, 0, 0, 0 };
	size_t user_stats[5] = { 0, 0, 0, 0, 0 };
	size_t bool_stats[5] = { 0, 0, 0, 0, 0 };
	size_t terule_stats[5] = { 0, 0, 0, 0, 0 };
	size_t avrule_stats[5] = { 0, 0, 0, 0, 0 };
	size_t rallow_stats[5] = { 0, 0, 0, 0, 0 };
	size_t rtrans_stats[5] = { 0, 0, 0, 0, 0 };
	poldiff_t *diff = toplevel_get_poldiff(r->top);
	assert(diff != NULL);

	poldiff_get_stats(diff, POLDIFF_DIFF_CLASSES, class_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_COMMONS, common_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_TYPES, type_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_ATTRIBS, attrib_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_ROLES, role_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_USERS, user_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_BOOLS, bool_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_TERULES, terule_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_AVRULES, avrule_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_ROLE_ALLOWS, rallow_stats);
	poldiff_get_stats(diff, POLDIFF_DIFF_ROLE_TRANS, rtrans_stats);

	g_string_printf(string, "Classes %d "
			"Commons %d Types: %d Attribs: %d Roles: %d Users: %d Bools: %d "
			"TE Rules: %d Role Allows: %d Role Trans: %d",
			class_stats[0] + class_stats[1] + class_stats[2],
			common_stats[0] + common_stats[1] + common_stats[2],
			type_stats[0] + type_stats[1] + type_stats[2],
			attrib_stats[0] + attrib_stats[1] + attrib_stats[2],
			role_stats[0] + role_stats[1] + role_stats[2],
			user_stats[0] + user_stats[1] + user_stats[2],
			bool_stats[0] + bool_stats[1] + bool_stats[2],
			terule_stats[0] + terule_stats[1] + terule_stats[2] + terule_stats[3] + terule_stats[4] +
			avrule_stats[0] + avrule_stats[1] + avrule_stats[2] + avrule_stats[3] + avrule_stats[4],
			rallow_stats[0] + rallow_stats[1] + rallow_stats[2],
			rtrans_stats[0] + rtrans_stats[1] + rtrans_stats[2] + rtrans_stats[3] + rtrans_stats[4]);
	gtk_label_set_text(r->stats, string->str);
	g_string_free(string, TRUE);
}

void results_update(results_t * r)
{
	size_t i, was_diff_run = 0;
	poldiff_t *diff = toplevel_get_poldiff(r->top);

	/* first clear away old stuff */
	gtk_tree_store_clear(r->summary_tree);
	util_text_buffer_clear(r->key_buffer);
	gtk_label_set_text(r->stats, "");
	gtk_text_view_set_buffer(r->view, r->buffers[RESULTS_BUFFER_MAIN]);
	util_text_buffer_clear(r->buffers[RESULTS_BUFFER_MAIN]);
	r->current_buffer = 0;

	/* only show diff-relevant buffers if a diff was actually run */
	for (i = 0; diff != NULL && poldiff_items[i].label != NULL; i++) {
		if (poldiff_is_run(diff, poldiff_items[i].bit_pos)) {
			was_diff_run = 1;
			break;
		}
	}
	if (was_diff_run) {
		results_update_summary(r);
		results_populate_key_buffer(r);
		results_update_stats(r);

		/* select the summary item */
		GtkTreeSelection *selection = gtk_tree_view_get_selection(r->summary_view);
		GtkTreeIter iter;
		gtk_tree_model_get_iter_first(GTK_TREE_MODEL(r->summary_tree), &iter);
		gtk_tree_selection_select_iter(selection, &iter);
	}
}

void results_switch_to_page(results_t * r)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(r->summary_view);
	GtkTreeIter iter;
	toplevel_set_sort_menu_sensitivity(r->top, FALSE);
	if (gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		int form;
		const struct poldiff_item_record *item_record;
		gtk_tree_model_get(GTK_TREE_MODEL(r->summary_tree), &iter, RESULTS_SUMMARY_COLUMN_FORM, &form,
				   RESULTS_SUMMARY_COLUMN_RECORD, &item_record, -1);
		if (item_record != NULL &&
		    item_record->bit_pos == (POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES) && form != POLDIFF_FORM_NONE) {
			toplevel_set_sort_menu_sensitivity(r->top, TRUE);
		}
	}
}

/**
 * Show a common header when printing a policy component diff.
 */
static void results_print_item_header(results_t * r, GtkTextBuffer * tb, const struct poldiff_item_record *record,
				      poldiff_form_e form)
{
	GtkTextIter iter;
	poldiff_t *diff = toplevel_get_poldiff(r->top);
	size_t stats[5] = { 0, 0, 0, 0, 0 };
	GString *string = g_string_new("");
	char *s;

	gtk_text_buffer_get_end_iter(tb, &iter);
	poldiff_get_stats(diff, record->bit_pos, stats);
	if (record->has_add_type) {
		g_string_printf(string,
				"%s (%zd Added, %zd Added New Type, %zd Removed, %zd Removed Missing Type, %zd Modified)\n\n",
				record->label, stats[0], stats[3], stats[1], stats[4], stats[2]);
	} else {
		g_string_printf(string, "%s (%zd Added, %zd Removed, %zd Modified)\n\n",
				record->label, stats[0], stats[1], stats[2]);
	}
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "header", NULL);

	switch (form) {
	case POLDIFF_FORM_ADDED:{
			g_string_printf(string, "Added %s: %zd\n", record->label, stats[0]);
			s = "added-header";
			break;
		}
	case POLDIFF_FORM_ADD_TYPE:{
			g_string_printf(string, "Added %s because of new type: %zd\n", record->label, stats[3]);
			s = "added-header";
			break;
		}
	case POLDIFF_FORM_REMOVED:{
			g_string_printf(string, "Removed %s: %zd\n", record->label, stats[1]);
			s = "removed-header";
			break;
		}
	case POLDIFF_FORM_REMOVE_TYPE:{
			g_string_printf(string, "Removed %s because of missing type: %zd\n", record->label, stats[4]);
			s = "removed-header";
			break;
		}
	case POLDIFF_FORM_MODIFIED:{
			g_string_printf(string, "Modified %s: %zd\n", record->label, stats[2]);
			s = "modified-header";
			break;
		}
	default:{
			assert(0);
			s = NULL;
		}
	}
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, s, NULL);
	g_string_free(string, TRUE);
}

/**
 * Show a single diff item string.  This will add the appropriate
 * color tags based upon the item's first character.
 */
static void results_print_string(GtkTextBuffer * tb, GtkTextIter * iter, const char *s, unsigned int indent_level)
{
	const char *c = s;
	unsigned int i;
	size_t start = 0, end = 0;
	static const char *indent = "\t";
	const gchar *current_tag = NULL;
	for (i = 0; i < indent_level; i++) {
		gtk_text_buffer_insert(tb, iter, indent, -1);
	}
	for (; *c; c++, end++) {
		switch (*c) {
		case '+':{
				if (*(c + 1) == ' ') {
					if (end > 0) {
						gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start,
											 current_tag, NULL);
					}
					start = end;
					current_tag = "added";
					break;
				}
			}
		case '-':{
				if (*(c + 1) == ' ') {
					if (end > 0) {
						gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start,
											 current_tag, NULL);
					}
					start = end;
					current_tag = "removed";
				}
				break;
			}
		case '*':{
				if (*(c + 1) == ' ') {
					if (end > 0) {
						gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start,
											 current_tag, NULL);
					}
					start = end;
					current_tag = "modified";
				}
				break;
			}
		case '\n':{
				if (*(c + 1) != '\0') {
					gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start + 1, current_tag,
										 NULL);
					for (i = 0; i < indent_level; i++) {
						gtk_text_buffer_insert(tb, iter, indent, -1);
					}
					start = end + 1;
				}
				break;
			}
		}
	}
	if (start < end) {
		gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag, NULL);
	}
}

/**
 * Show a summary of the diff for a particular policy component.
 */
static void results_print_summary(results_t * r, GtkTextBuffer * tb, const struct poldiff_item_record *record)
{
	GtkTextIter iter;
	poldiff_t *diff = toplevel_get_poldiff(r->top);
	size_t stats[5] = { 0, 0, 0, 0, 0 };
	GString *string = g_string_new("");

	gtk_text_buffer_get_end_iter(tb, &iter);
	poldiff_get_stats(diff, record->bit_pos, stats);

	g_string_printf(string, "%s:\n", record->label);
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "subheader", NULL);

	g_string_printf(string, "\tAdded: %zd\n", stats[0]);
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "added-header", NULL);

	if (record->has_add_type) {
		g_string_printf(string, "\tAdded because of new type: %zd\n", stats[3]);
		gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "added-header", NULL);
	}

	g_string_printf(string, "\tRemoved: %zd\n", stats[1]);
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "removed-header", NULL);

	if (record->has_add_type) {
		g_string_printf(string, "\tRemoved because of missing type: %zd\n", stats[4]);
		gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "removed-header", NULL);
	}

	g_string_printf(string, "\tModified: %zd\n", stats[2]);
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "modified-header", NULL);

	g_string_free(string, TRUE);
}

/**
 * Show a summary of the diff for all policy components.
 */
static void results_select_summary(results_t * r)
{
	GtkTextBuffer *tb = r->buffers[RESULTS_BUFFER_MAIN];
	GtkTextIter iter;
	GString *string = g_string_new("");
	size_t i;
	poldiff_t *diff = toplevel_get_poldiff(r->top);

	gtk_text_view_set_buffer(r->view, tb);
	util_text_buffer_clear(tb);

	gtk_text_buffer_get_start_iter(tb, &iter);
	g_string_printf(string, "Policy Difference Statistics\n\n");
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "header", NULL);

	for (i = 0; poldiff_items[i].label != NULL; i++) {
		if (!poldiff_is_run(diff, poldiff_items[i].bit_pos)) {
			continue;
		}
		gtk_text_buffer_insert(tb, &iter, "\n", -1);
		results_print_summary(r, tb, poldiff_items + i);
		gtk_text_buffer_get_end_iter(tb, &iter);
	}
	g_string_free(string, TRUE);
}

/**
 * Show the results for non-rules diff components.
 */
static void results_select_simple(results_t * r, const struct poldiff_item_record *item_record, poldiff_form_e form)
{
	GtkTextBuffer *tb = r->buffers[RESULTS_BUFFER_MAIN];
	poldiff_t *diff = toplevel_get_poldiff(r->top);

	gtk_text_view_set_buffer(r->view, tb);
	util_text_buffer_clear(tb);

	if (form == POLDIFF_FORM_NONE) {
		results_print_summary(r, tb, item_record);
	} else {
		GtkTextIter iter;
		apol_vector_t *v;
		size_t i;
		void *elem;
		char *s = NULL;

		results_print_item_header(r, tb, item_record, form);
		gtk_text_buffer_get_end_iter(tb, &iter);

		v = item_record->get_vector(diff);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			elem = apol_vector_get_element(v, i);
			if (item_record->get_form(elem) == form) {
				s = item_record->get_string(diff, elem);
				results_print_string(tb, &iter, s, 1);
				free(s);
				gtk_text_buffer_insert(tb, &iter, "\n", -1);
			}
		}
	}

}

struct sort_opts
{
	poldiff_t *diff;
	int field;
	int direction;
};

static int results_avsort_comp(const void *a, const void *b, void *data)
{
	const poldiff_avrule_t *a1 = a;
	const poldiff_avrule_t *a2 = b;
	struct sort_opts *opts = data;
	const char *s1, *s2;
	switch (opts->field) {
	case RESULTS_SORT_SOURCE:{
			s1 = poldiff_avrule_get_source_type(a1);
			s2 = poldiff_avrule_get_source_type(a2);
			break;
		}
	case RESULTS_SORT_TARGET:{
			s1 = poldiff_avrule_get_target_type(a1);
			s2 = poldiff_avrule_get_target_type(a2);
			break;
		}
	case RESULTS_SORT_CLASS:{
			s1 = poldiff_avrule_get_object_class(a1);
			s2 = poldiff_avrule_get_object_class(a2);
			break;
		}
	case RESULTS_SORT_COND:{
			qpol_cond_t *q1, *q2;
			apol_policy_t *p1, *p2;
			uint32_t w1, w2;
			poldiff_avrule_get_cond(opts->diff, a1, &q1, &w1, &p1);
			poldiff_avrule_get_cond(opts->diff, a2, &q2, &w2, &p2);
			if (q1 != q2) {
				return opts->direction * ((int)q1 - (int)q2);
			}
			return opts->direction * (w1 - w2);
			break;
		}
	default:{
			/* shouldn't get here */
			assert(0);
			return 0;
		}
	}
	return opts->direction * strcmp(s1, s2);
}

static apol_vector_t *results_avsort(poldiff_t * diff, poldiff_form_e form, int field, int direction)
{
	apol_vector_t *orig_v, *v;
	size_t i;
	void *elem;
	struct sort_opts opts = { diff, field, direction };
	orig_v = poldiff_get_avrule_vector(diff);
	if ((v = apol_vector_create()) == NULL) {
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(orig_v); i++) {
		elem = apol_vector_get_element(orig_v, i);
		if (poldiff_avrule_get_form(elem) == form && apol_vector_append(v, elem) < 0) {
			apol_vector_destroy(&v, NULL);
			return NULL;
		}
	}
	if (field != RESULTS_SORT_DEFAULT) {
		apol_vector_sort(v, results_avsort_comp, &opts);
	}
	return v;
}

static int results_tesort_comp(const void *a, const void *b, void *data)
{
	const poldiff_terule_t *a1 = a;
	const poldiff_terule_t *a2 = b;
	struct sort_opts *opts = data;
	const char *s1, *s2;
	switch (opts->field) {
	case RESULTS_SORT_SOURCE:{
			s1 = poldiff_terule_get_source_type(a1);
			s2 = poldiff_terule_get_source_type(a2);
			break;
		}
	case RESULTS_SORT_TARGET:{
			s1 = poldiff_terule_get_target_type(a1);
			s2 = poldiff_terule_get_target_type(a2);
			break;
		}
	case RESULTS_SORT_CLASS:{
			s1 = poldiff_terule_get_object_class(a1);
			s2 = poldiff_terule_get_object_class(a2);
			break;
		}
	case RESULTS_SORT_COND:{
			qpol_cond_t *q1, *q2;
			apol_policy_t *p1, *p2;
			uint32_t w1, w2;
			poldiff_terule_get_cond(opts->diff, a1, &q1, &w1, &p1);
			poldiff_terule_get_cond(opts->diff, a2, &q2, &w2, &p2);
			if (q1 != q2) {
				return opts->direction * ((int)q1 - (int)q2);
			}
			return opts->direction * (w1 - w2);
			break;
		}
	default:{
			/* shouldn't get here */
			assert(0);
			return 0;
		}
	}
	return opts->direction * strcmp(s1, s2);
}

static apol_vector_t *results_tesort(poldiff_t * diff, poldiff_form_e form, int field, int direction)
{
	apol_vector_t *orig_v, *v;
	size_t i;
	void *elem;
	struct sort_opts opts = { diff, field, direction };
	orig_v = poldiff_get_terule_vector(diff);
	if ((v = apol_vector_create()) == NULL) {
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(orig_v); i++) {
		elem = apol_vector_get_element(orig_v, i);
		if (poldiff_terule_get_form(elem) == form && apol_vector_append(v, elem) < 0) {
			apol_vector_destroy(&v, NULL);
			return NULL;
		}
	}
	if (field != RESULTS_SORT_DEFAULT) {
		apol_vector_sort(v, results_tesort_comp, &opts);
	}
	return v;
}

/**
 * Print a modified rule.  Note that this differs from the more
 * general results_print_string() because:
 *
 * <ul>
 *   <li>there are inline '+' and '-' markers
 *   <li>for source policies, hyperlink permission names to their
 *       line(s) within the policy
 * </ul>
 */
static void results_print_rule_modified(GtkTextBuffer * tb, GtkTextIter * iter, const char *s, unsigned int indent_level)
{
	const char *c = s;
	unsigned int i;
	size_t start = 0, end = 0;
	static const char *indent = "\t";
	const gchar *current_tag = "modified";
	for (i = 0; i < indent_level; i++) {
		gtk_text_buffer_insert(tb, iter, indent, -1);
	}
	for (; *c; c++, end++) {
		switch (*c) {
		case '+':{
				if (end > 0) {
					gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag,
										 NULL);
				}
				start = end;
				current_tag = "added";
				break;
			}
		case '-':{
				if (end > 0) {
					gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag,
										 NULL);
				}
				start = end;
				current_tag = "removed";
				break;
			}
		case '\n':{
				if (*(c + 1) != '\0') {
					gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start + 1, current_tag,
										 NULL);
					for (i = 0; i < indent_level; i++) {
						gtk_text_buffer_insert(tb, iter, indent, -1);
					}
					start = end + 1;
				}
				break;
			}
		case ' ':{
				if (current_tag != "modified") {
					gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start + 1, current_tag,
										 NULL);
					start = end + 1;
					current_tag = "modified";
				}
				break;
			}
		}
	}
	if (start < end) {
		gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag, NULL);
	}
}

/**
 * Given a vector of unsigned long integers, write to the text buffer
 * those line numbers using the given tag.
 */
static void results_print_linenos(GtkTextBuffer * tb, GtkTextIter * iter,
				  const gchar * prefix, apol_vector_t * linenos, const gchar * tag, GString * string)
{
	size_t i;
	unsigned long lineno;
	gtk_text_buffer_insert(tb, iter, "  [", -1);
	if (prefix != NULL) {
		gtk_text_buffer_insert(tb, iter, prefix, -1);
	}
	for (i = 0; i < apol_vector_get_size(linenos); i++) {
		lineno = (unsigned long)apol_vector_get_element(linenos, i);
		if (i > 0) {
			gtk_text_buffer_insert(tb, iter, ", ", -1);
		}
		g_string_printf(string, "%lu", lineno);
		gtk_text_buffer_insert_with_tags_by_name(tb, iter, string->str, -1, tag, NULL);
	}
	gtk_text_buffer_insert(tb, iter, "]", -1);
}

static void results_print_rules(results_t * r, GtkTextBuffer * tb,
				const struct poldiff_item_record *item_record,
				poldiff_form_e form, apol_vector_t * av, apol_vector_t * te)
{
	poldiff_t *diff = toplevel_get_poldiff(r->top);
	GtkTextIter iter;
	size_t i;
	void *elem;
	char *s;
	apol_vector_t *syn_linenos;
	GString *string = g_string_new("");

	results_print_item_header(r, tb, item_record, form);
	gtk_text_buffer_get_end_iter(tb, &iter);

	if (apol_vector_get_size(av) > 0 || apol_vector_get_size(te) > 0) {
		poldiff_enable_line_numbers(diff);
	}
	for (i = 0; i < apol_vector_get_size(av); i++) {
		elem = apol_vector_get_element(av, i);
		if ((s = poldiff_avrule_to_string(diff, elem)) == NULL) {
			util_message(toplevel_get_window(r->top), GTK_MESSAGE_ERROR, "Out of memory.");
			g_string_free(string, TRUE);
			return;
		}
		if (form != POLDIFF_FORM_MODIFIED) {
			results_print_string(tb, &iter, s, 1);
			if (toplevel_is_policy_capable_line_numbers(r->top, SEDIFFX_POLICY_ORIG) &&
			    (syn_linenos = poldiff_avrule_get_orig_line_numbers((poldiff_avrule_t *) elem)) != NULL) {
				results_print_linenos(tb, &iter, NULL, syn_linenos, "line-pol_orig", string);
			}
			if (toplevel_is_policy_capable_line_numbers(r->top, SEDIFFX_POLICY_MOD) &&
			    (syn_linenos = poldiff_avrule_get_mod_line_numbers((poldiff_avrule_t *) elem)) != NULL) {
				results_print_linenos(tb, &iter, NULL, syn_linenos, "line-pol_mod", string);
			}
		} else {
			results_print_rule_modified(tb, &iter, s, 1);
			if (toplevel_is_policy_capable_line_numbers(r->top, SEDIFFX_POLICY_ORIG) &&
			    (syn_linenos = poldiff_avrule_get_orig_line_numbers((poldiff_avrule_t *) elem)) != NULL) {
				results_print_linenos(tb, &iter, "p1: ", syn_linenos, "line-pol_orig", string);
			}
			if (toplevel_is_policy_capable_line_numbers(r->top, SEDIFFX_POLICY_MOD) &&
			    (syn_linenos = poldiff_avrule_get_mod_line_numbers((poldiff_avrule_t *) elem)) != NULL) {
				results_print_linenos(tb, &iter, "p2: ", syn_linenos, "line-pol_mod", string);
			}
		}
		free(s);
		gtk_text_buffer_insert(tb, &iter, "\n", -1);
	}

	for (i = 0; i < apol_vector_get_size(te); i++) {
		elem = apol_vector_get_element(te, i);
		if ((s = poldiff_terule_to_string(diff, elem)) == NULL) {
			util_message(toplevel_get_window(r->top), GTK_MESSAGE_ERROR, "Out of memory.");
			g_string_free(string, TRUE);
			return;
		}
		if (form != POLDIFF_FORM_MODIFIED) {
			results_print_string(tb, &iter, s, 1);
			if (toplevel_is_policy_capable_line_numbers(r->top, SEDIFFX_POLICY_ORIG) &&
			    (syn_linenos = poldiff_terule_get_orig_line_numbers((poldiff_terule_t *) elem)) != NULL) {
				results_print_linenos(tb, &iter, NULL, syn_linenos, "line-pol_orig", string);
			}
			if (toplevel_is_policy_capable_line_numbers(r->top, SEDIFFX_POLICY_MOD) &&
			    (syn_linenos = poldiff_terule_get_mod_line_numbers((poldiff_terule_t *) elem)) != NULL) {
				results_print_linenos(tb, &iter, NULL, syn_linenos, "line-pol_mod", string);
			}
		} else {
			results_print_rule_modified(tb, &iter, s, 1);
			if (toplevel_is_policy_capable_line_numbers(r->top, SEDIFFX_POLICY_ORIG) &&
			    (syn_linenos = poldiff_terule_get_orig_line_numbers((poldiff_terule_t *) elem)) != NULL) {
				results_print_linenos(tb, &iter, "p1: ", syn_linenos, "line-pol_orig", string);
			}
			if (toplevel_is_policy_capable_line_numbers(r->top, SEDIFFX_POLICY_MOD) &&
			    (syn_linenos = poldiff_terule_get_mod_line_numbers((poldiff_terule_t *) elem)) != NULL) {
				results_print_linenos(tb, &iter, "p2: ", syn_linenos, "line-pol_mod", string);
			}
		}
		free(s);
		gtk_text_buffer_insert(tb, &iter, "\n", -1);
	}

	g_string_free(string, TRUE);
}

struct run_datum
{
	results_t *r;
	poldiff_form_e form;
	progress_t *progress;
	apol_vector_t *av, *te;
	int result;
};

static gpointer results_sort_rule_runner(gpointer data)
{
	struct run_datum *run = (struct run_datum *)data;
	progress_update(run->progress, "sorting rules");
	poldiff_t *diff = toplevel_get_poldiff(run->r->top);
	if ((run->av =
	     results_avsort(diff, run->form, run->r->te_sort_field[run->form], run->r->te_sort_direction[run->form])) == NULL
	    || (run->te =
		results_tesort(diff, run->form, run->r->te_sort_field[run->form], run->r->te_sort_direction[run->form])) == NULL) {
		apol_vector_destroy(&run->av, NULL);
		apol_vector_destroy(&run->te, NULL);
		progress_abort(run->progress, "%s", strerror(errno));
		run->result = -1;
	} else {
		progress_update(run->progress, "printing rules");
		run->result = 0;
		progress_done(run->progress);
	}
	return NULL;
}

/**
 * Show the results for AV and TE rules diff.
 */
static void results_select_rules(results_t * r, const struct poldiff_item_record *item_record, poldiff_form_e form)
{
	GtkTextBuffer *tb;
	if (form == POLDIFF_FORM_NONE) {
		tb = r->buffers[RESULTS_BUFFER_MAIN];
		gtk_text_view_set_buffer(r->view, tb);
		util_text_buffer_clear(tb);
		results_print_summary(r, tb, item_record);
		return;
	}
	tb = r->buffers[form];
	gtk_text_view_set_buffer(r->view, tb);
	toplevel_set_sort_menu_sensitivity(r->top, TRUE);
	if (!r->te_buffered[form]) {
		struct run_datum run;
		run.r = r;
		run.form = form;
		run.progress = toplevel_get_progress(r->top);
		run.av = run.te = NULL;
		run.result = 0;

		util_text_buffer_clear(tb);
		util_cursor_wait(GTK_WIDGET(toplevel_get_window(r->top)));
		progress_show(run.progress, "Rendering Rules");
		g_thread_create(results_sort_rule_runner, &run, FALSE, NULL);
		progress_wait(run.progress);
		util_cursor_clear(GTK_WIDGET(toplevel_get_window(r->top)));
		if (run.result == 0) {
			results_print_rules(r, tb, item_record, form, run.av, run.te);
			apol_vector_destroy(&run.av, NULL);
			apol_vector_destroy(&run.te, NULL);
		}
		progress_hide(run.progress);
		r->te_buffered[form] = 1;
	}
}

/**
 * Display in the main view the diff results for a particular component.
 *
 * @param r Results object whose view to update.
 * @param record Item record for the component to show.
 * @param form Particular form of the diff result to show.
 */
static void results_record_select(results_t * r, const struct poldiff_item_record *record, poldiff_form_e form)
{
	GtkTextMark *mark;
	GdkRectangle rect;
	GtkTextIter iter;
	size_t new_buffer;
	GtkTextBuffer *tb;

	/* save current view position */
	gtk_text_view_get_visible_rect(r->view, &rect);
	gtk_text_view_get_iter_at_location(r->view, &iter, rect.x, rect.y);
	r->saved_offsets[r->current_buffer] = gtk_text_iter_get_offset(&iter);

	toplevel_set_sort_menu_sensitivity(r->top, FALSE);

	if (record == NULL) {
		results_select_summary(r);
		new_buffer = 0;
	} else {
		switch (record->bit_pos) {
		case POLDIFF_DIFF_CLASSES:
		case POLDIFF_DIFF_COMMONS:
		case POLDIFF_DIFF_TYPES:
		case POLDIFF_DIFF_ATTRIBS:
		case POLDIFF_DIFF_ROLES:
		case POLDIFF_DIFF_USERS:
		case POLDIFF_DIFF_BOOLS:
		case POLDIFF_DIFF_ROLE_ALLOWS:
		case POLDIFF_DIFF_ROLE_TRANS:{
				results_select_simple(r, record, form);
				break;
			}
		case (POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES):{
				results_select_rules(r, record, form);
				toplevel_set_sort_menu_selection(r->top, r->te_sort_field[form], r->te_sort_direction[form]);
				break;
			}
		}

		new_buffer = record->record_id * 6 + form;
	}

	/* restore saved location.  use marks to ensure that we go to
	 * this position even if it hasn't been drawn. */
	tb = gtk_text_view_get_buffer(r->view);
	gtk_text_buffer_get_start_iter(tb, &iter);
	gtk_text_iter_set_offset(&iter, r->saved_offsets[new_buffer]);
	mark = gtk_text_buffer_create_mark(tb, "location-mark", &iter, FALSE);
	gtk_text_view_scroll_to_mark(r->view, mark, 0.0, TRUE, 0.0, 0.0);
	gtk_text_buffer_delete_mark(tb, mark);
	r->current_buffer = new_buffer;
}

/**
 * Callback invoked when the user selects an entry from the summary
 * tree.
 */
static void results_summary_on_change(GtkTreeSelection * selection, gpointer user_data)
{
	results_t *r = (results_t *) user_data;
	GtkTreeIter iter;
	if (gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		int form;
		const struct poldiff_item_record *item_record;
		gtk_tree_model_get(GTK_TREE_MODEL(r->summary_tree), &iter, RESULTS_SUMMARY_COLUMN_FORM, &form,
				   RESULTS_SUMMARY_COLUMN_RECORD, &item_record, -1);
		results_record_select(r, item_record, form);
	}
}

/**
 * Callback invoked when the user clicks on a line number tag.  This
 * will flip to the appropriate policy's source page and jump to that
 * line.
 */
static gboolean results_on_line_event(GtkTextTag * tag, GObject * event_object __attribute__ ((unused)),
				      GdkEvent * event, const GtkTextIter * iter, gpointer user_data)
{
	results_t *r = (results_t *) user_data;
	int offset;
	sediffx_policy_e which_pol = -1;
	unsigned long line;
	GtkTextIter *start, *end;
	if (event->type == GDK_BUTTON_PRESS) {
		start = gtk_text_iter_copy(iter);
		offset = gtk_text_iter_get_line_offset(start);

		while (!gtk_text_iter_starts_word(start))
			gtk_text_iter_backward_char(start);
		end = gtk_text_iter_copy(start);
		while (!gtk_text_iter_ends_word(end))
			gtk_text_iter_forward_char(end);

		/* the line # in policy starts with 1, in the buffer it
		 * starts at 0 */
		line = atoi(gtk_text_iter_get_slice(start, end)) - 1;
		if (tag == r->policy_orig_tag) {
			which_pol = SEDIFFX_POLICY_ORIG;
		} else if (tag == r->policy_mod_tag) {
			which_pol = SEDIFFX_POLICY_MOD;
		} else {
			/* should never get here */
			assert(0);
		}
		toplevel_show_policy_line(r->top, which_pol, line);
		return TRUE;
	}
	return FALSE;
}

/**
 * Set the cursor to a hand when user scrolls over a line number in
 * when displaying te diff.
 */
static gboolean results_on_text_view_motion(GtkWidget * widget, GdkEventMotion * event, gpointer user_data __attribute__ ((unused)))
{
	GtkTextBuffer *buffer;
	GtkTextView *textview;
	GdkCursor *cursor;
	GtkTextIter iter;
	GSList *tags, *tagp;
	gint x, ex, ey, y;
	int hovering = 0;

	textview = GTK_TEXT_VIEW(widget);

	if (event->is_hint) {
		gdk_window_get_pointer(event->window, &ex, &ey, NULL);
	} else {
		ex = event->x;
		ey = event->y;
	}

	gtk_text_view_window_to_buffer_coords(textview, GTK_TEXT_WINDOW_WIDGET, ex, ey, &x, &y);
	buffer = gtk_text_view_get_buffer(textview);
	gtk_text_view_get_iter_at_location(textview, &iter, x, y);
	tags = gtk_text_iter_get_tags(&iter);
	for (tagp = tags; tagp != NULL; tagp = tagp->next) {
		if (strncmp(GTK_TEXT_TAG(tagp->data)->name, "line", 4) == 0) {
			hovering = TRUE;
			break;
		}
	}

	if (hovering) {
		cursor = gdk_cursor_new(GDK_HAND2);
		gdk_window_set_cursor(event->window, cursor);
		gdk_cursor_unref(cursor);
		gdk_flush();
	} else {
		gdk_window_set_cursor(event->window, NULL);
	}
	g_slist_free(tags);
	return FALSE;
}

void results_sort(results_t * r, results_sort_e field, int direction)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(r->summary_view);
	GtkTreeIter iter;
	int form;
	const struct poldiff_item_record *item_record;
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		return;
	}
	gtk_tree_model_get(GTK_TREE_MODEL(r->summary_tree), &iter, RESULTS_SUMMARY_COLUMN_FORM, &form,
			   RESULTS_SUMMARY_COLUMN_RECORD, &item_record, -1);
	assert(item_record->bit_pos == (POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES));
	if (r->te_sort_field[form] != field || r->te_sort_direction[form] != direction || !r->te_buffered[form]) {
		r->te_sort_field[form] = field;
		r->te_sort_direction[form] = direction;
		r->te_buffered[form] = 0;
		results_select_rules(r, item_record, form);
	}
}

GtkTextView *results_get_text_view(results_t * r)
{
	return r->view;
}
