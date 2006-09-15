/**
 *  @file sediff_results.c
 *  Routines for displaying the results of a difference run, as well
 *  as maintaining the status bar.
 *
 *  @author Don Patterson don.patterson@tresys.com
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

#include <config.h>

#include "sediff_gui.h"
#include "sediff_progress.h"
#include "sediff_results.h"

#include <assert.h>

struct sediff_results {
	GtkTextBuffer *main_buffer;       /* generic buffer used for everything but te rules and conditionals(because they take so long to draw) */
	GtkTextBuffer *te_buffers[5];
	GtkTextBuffer *cond_buffers[3];
};

extern sediff_item_record_t sediff_items[];

void sediff_results_create(sediff_app_t *app)
{
	sediff_results_t *r;
	GtkTextView *textview;
	GtkTextAttributes *attr;
	gint size;
	PangoTabArray *tabs;
	GtkLabel *label;
	size_t i;

	if ((r = app->results) == NULL) {
		app->results = g_malloc0(sizeof(*r));
		r = app->results;
        }
	if (r->main_buffer == NULL) {
		/* recreate the results buffer -- it could have been
		 * destroyed by sediff_results_clear() */
		GtkTextTagTable *tag_table;
		r->main_buffer = gtk_text_buffer_new(NULL);
		tag_table = gtk_text_buffer_get_tag_table(r->main_buffer);
		for (i = 0; i < 5; i++) {
			r->te_buffers[i] = gtk_text_buffer_new(tag_table);
		}
		for (i = 0; i < 3; i++) {
			r->cond_buffers[i] = gtk_text_buffer_new(tag_table);
		}
		gtk_text_buffer_create_tag(r->main_buffer, "header",
					   "style", PANGO_STYLE_ITALIC,
					   "weight", PANGO_WEIGHT_BOLD,
					   NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "subheader",
					   "family", "monospace",
					   "weight", PANGO_WEIGHT_BOLD,
					   "underline", PANGO_UNDERLINE_SINGLE,
					   NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "removed",
					   "family", "monospace",
					   "foreground", "red",
					   "weight", PANGO_WEIGHT_BOLD, NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "added",
					   "family", "monospace",
					   "foreground", "dark green",
					   "weight", PANGO_WEIGHT_BOLD, NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "modified",
					   "family", "monospace",
					   "foreground", "dark blue",
					   "weight", PANGO_WEIGHT_BOLD, NULL);
	}

	textview = GTK_TEXT_VIEW((glade_xml_get_widget(app->window_xml, "sediff_results_txt_view")));
	attr = gtk_text_view_get_default_attributes(textview);
	size = pango_font_description_get_size(attr->font);
	tabs = pango_tab_array_new_with_positions (4,
						   FALSE,
						   PANGO_TAB_LEFT, 3*size,
						   PANGO_TAB_LEFT, 6*size,
						   PANGO_TAB_LEFT, 9*size,
						   PANGO_TAB_LEFT, 12*size);
	gtk_text_view_set_tabs(textview, tabs);

	/* switch to our newly blank main buffer */
	gtk_text_view_set_buffer(textview, r->main_buffer);

	label = (GtkLabel *)(glade_xml_get_widget(app->window_xml, "label_stats"));
	gtk_label_set_text(label, "");
}

void sediff_results_clear(sediff_app_t *app)
{
	sediff_results_t *r = app->results;
	if (r != NULL) {
		size_t i;

		if (r->main_buffer) {
			g_object_unref (G_OBJECT(r->main_buffer));
			r->main_buffer = NULL;
		}
		for (i = 0; i < 5; i++) {
			if (r->te_buffers[i]) {
				g_object_unref (G_OBJECT(r->te_buffers[i]));
				r->te_buffers[i] = NULL;
			}
		}
		for (i = 0; i < 3; i++) {
			if (r->cond_buffers[i]) {
				g_object_unref (G_OBJECT(r->cond_buffers[i]));
				r->cond_buffers[i] = NULL;
			}
		}
	}
}

static void sediff_results_print_summary(sediff_app_t *app, GtkTextBuffer *tb, sediff_item_record_t *record) {
	GtkTextIter iter;
	size_t stats[5] = {0, 0, 0, 0, 0};
	GString *string = g_string_new("");

	gtk_text_buffer_get_end_iter(tb, &iter);
	poldiff_get_stats(app->diff, record->bit_pos, stats);

	g_string_printf(string, "%s:\n", record->label);
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "subheader", NULL);

	g_string_printf(string, "\tAdded: %zd\n", stats[0]);
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "added", NULL);

	if (record->has_add_type) {
		g_string_printf(string, "\tAdded because of new type: %zd\n", stats[3]);
		gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "added", NULL);
	}

	g_string_printf(string, "\tRemoved: %zd\n", stats[1]);
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "removed", NULL);

	if (record->has_add_type) {
		g_string_printf(string, "\tRemoved because of missing type: %zd\n", stats[4]);
		gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "removed", NULL);
	}

	g_string_printf(string, "\tModified: %zd\n", stats[2]);
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "modified", NULL);

	g_string_free(string, TRUE);
}

static void sediff_results_print_string(sediff_app_t *app, GtkTextBuffer *tb, GtkTextIter *iter, const char *s) {
        gtk_text_buffer_insert(tb, iter, "\t\t", -1);
        gtk_text_buffer_insert(tb, iter, s, -1);
        gtk_text_buffer_insert(tb, iter, "\n", -1);
}

static void sediff_results_print_item(sediff_app_t *app, GtkTextBuffer *tb, sediff_item_record_t *record, poldiff_form_e form) {
	GtkTextIter iter;
	size_t stats[5] = {0, 0, 0, 0, 0};
	GString *string = g_string_new("");
	if (form == POLDIFF_FORM_NONE) {
		sediff_results_print_summary(app, tb, record);
	}
	else {
		apol_vector_t *v;
		size_t i;
		void *elem;
		char *s = NULL;

		gtk_text_buffer_get_end_iter(tb, &iter);
		poldiff_get_stats(app->diff, record->bit_pos, stats);
		g_string_printf(string, "%s (%zd Added, %zd Removed, %zd Changed)\n", record->label, stats[0], stats[1], stats[2]);
		gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "header", NULL);

		switch (form) {
		case POLDIFF_FORM_ADDED: {
			g_string_printf(string, "\tAdded %s: %zd\n", record->label, stats[0]);
			s = "added";
			break;
		}
		case POLDIFF_FORM_ADD_TYPE: {
			g_string_printf(string, "\tAdded %s because of new type: %zd\n", record->label, stats[3]);
			s = "added";
			break;
		}
		case POLDIFF_FORM_REMOVED: {
			g_string_printf(string, "\tRemoved %s: %zd\n", record->label, stats[1]);
			s = "removed";
			break;
		}
		case POLDIFF_FORM_REMOVE_TYPE: {
			g_string_printf(string, "\tRemoved %s because of missing type: %zd\n", record->label, stats[4]);
			s = "removed";
			break;
		}
		case POLDIFF_FORM_MODIFIED: {
			g_string_printf(string, "\tModified %s: %zd\n", record->label, stats[2]);
			s = "removed";
			break;
		}
		default: {
			assert(0);
		}
		}
		gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, s, NULL);

		v = record->get_vector(app->diff);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			elem = apol_vector_get_element(v, i);
			if (record->get_form(elem) == form) {
				s = record->get_string(app->diff, elem);
				sediff_results_print_string(app, tb, &iter, s);
				free(s);
			}
		}
	}
	g_string_free(string, TRUE);
}

static void sediff_results_select_summary(sediff_app_t *app, GtkTextView *view)
{
	sediff_results_t *r = app->results;
	GtkTextBuffer *tb = r->main_buffer;
	GtkTextIter iter;
	GString *string = g_string_new("");
	size_t i;

	gtk_text_view_set_buffer(view, tb);
	sediff_clear_text_buffer(tb);
	if (app->diff == NULL) {
		/* diff not run yet, so don't display anything */
		return;
	}

	gtk_text_buffer_get_start_iter(tb, &iter);
	g_string_printf(string, "Policy Difference Statistics\n\n");
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "header", NULL);

	g_string_printf(string, "Policy Filenames:\n");
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "subheader", NULL);
	g_string_printf(string, "\tPolicy 1: %s\n", app->p1_sfd.name->str);
	gtk_text_buffer_insert(tb, &iter, string->str, -1);
	g_string_printf(string, "\tPolicy 2: %s\n", app->p2_sfd.name->str);
	gtk_text_buffer_insert(tb, &iter, string->str, -1);

	for (i = 0; sediff_items[i].label != NULL; i++) {
		gtk_text_buffer_insert(tb, &iter, "\n", -1);
                sediff_results_print_summary(app, tb, sediff_items + i);
                gtk_text_buffer_get_end_iter(tb, &iter);
	}
	g_string_free(string, TRUE);
}

static void sediff_results_select_simple(sediff_app_t *app, GtkTextView *view,
					 uint32_t diffbit, poldiff_form_e form)
{
	sediff_results_t *r = app->results;
        GtkTextBuffer *tb = r->main_buffer;
        sediff_item_record_t *item_record = NULL;
        size_t i;

	gtk_text_view_set_buffer(view, tb);
	sediff_clear_text_buffer(tb);
	if (app->diff == NULL) {
		/* diff not run yet, so don't display anything */
		return;
	}

	/* find associated item record */
	for (i = 0; sediff_items[i].label != NULL; i++) {
		if (sediff_items[i].bit_pos == diffbit) {
			item_record = sediff_items + i;
			break;
		}
	}
	assert(item_record != NULL);
	sediff_results_print_item(app, tb, item_record, form);
}

void sediff_results_select(sediff_app_t *app, uint32_t diffbit, poldiff_form_e form)
{
	GtkTextView *textview1;
	/* grab the text buffers for our text views */
	textview1 = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_results_txt_view"));
	g_assert(textview1);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(textview1), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(textview1), FALSE);

	switch (diffbit) {
	case POLDIFF_DIFF_SUMMARY: {
		sediff_results_select_summary(app, textview1);
		break;
	}
	case POLDIFF_DIFF_CLASSES:
	case POLDIFF_DIFF_COMMONS:
	case POLDIFF_DIFF_TYPES:
	case POLDIFF_DIFF_ATTRIBS:
	case POLDIFF_DIFF_ROLES:
	case POLDIFF_DIFF_USERS:
	case POLDIFF_DIFF_BOOLS:
	case POLDIFF_DIFF_ROLE_ALLOWS: {
		sediff_results_select_simple(app, textview1, diffbit, form);
		break;
	}
	}
}

void sediff_results_sort_current(sediff_app_t *app, int field, int direction)
{
        printf("sorting field %d towards %d\n", field, direction);
#if 0
	int treeview_row;
	GtkTextIter iter;
	int draw_opt;
	GtkTextBuffer *buffer;

	sediff_progress_message(sediff_app, "Sorting", "Sorting - this may take a while");
	/* get the current row so we know what to sort */
	treeview_row = sediff_get_current_treeview_selected_row(GTK_TREE_VIEW(sediff_app->tree_view));

	/* set up the buffers and the drawing options */
	if (treeview_row == OPT_TE_RULES_ADD) {
		draw_opt = POLDIFF_FORM_ADDED;
		buffer = sediff_app->te_add_buffer;
	} else if (treeview_row == OPT_TE_RULES_ADD_TYPE) {
		draw_opt = POLDIFF_FORM_ADD_TYPE;
		buffer = sediff_app->te_add_type_buffer;
	} else if (treeview_row == OPT_TE_RULES_REM) {
		draw_opt = POLDIFF_FORM_REMOVED;
		buffer = sediff_app->te_rem_buffer;
	} else if (treeview_row == OPT_TE_RULES_REM_TYPE) {
		draw_opt = POLDIFF_FORM_REMOVE_TYPE;
		buffer = sediff_app->te_rem_type_buffer;
	} else if (treeview_row == OPT_TE_RULES_MOD) {
		draw_opt = POLDIFF_FORM_MODIFIED;
		buffer = sediff_app->te_mod_buffer;
	} else {
		assert(FALSE);
		return;
	}

	/* sort the rules */
/*
	ap_single_view_diff_sort_te_rules(sediff_app->diff, sort_opt, draw_opt, direction);
*/
	sediff_clear_text_buffer(buffer);
	gtk_text_buffer_get_start_iter(buffer, &iter);

	/* put the sorted rules into the buffer */
	sediff_txt_buffer_insert_te_results(buffer, sediff_app->diff, draw_opt, TRUE);

	sediff_progress_hide(sediff_app);

#endif
}

/* populate the status bar with summary info of our diff */
void sediff_results_update_stats(sediff_app_t *app)
{
	GtkLabel *statusbar;
	GString *string = g_string_new("");
	size_t class_stats[5]  = {0,0,0,0,0};
	size_t common_stats[5] = {0,0,0,0,0};
	size_t type_stats[5]   = {0,0,0,0,0};
	size_t attrib_stats[5] = {0,0,0,0,0};
	size_t role_stats[5]   = {0,0,0,0,0};
	size_t user_stats[5]   = {0,0,0,0,0};
	size_t bool_stats[5]   = {0,0,0,0,0};
	size_t terule_stats[5] = {0,0,0,0,0};
	size_t avrule_stats[5] = {0,0,0,0,0};
	size_t rallow_stats[5] = {0,0,0,0,0};
	size_t rtrans_stats[5] = {0,0,0,0,0};
	size_t cond_stats[5]   = {0,0,0,0,0};

	poldiff_get_stats(app->diff, POLDIFF_DIFF_CLASSES, class_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_COMMONS, common_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_TYPES, type_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_ATTRIBS, attrib_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_ROLES, role_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_USERS, user_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_BOOLS, bool_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_TERULES, terule_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_AVRULES, avrule_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_ROLE_ALLOWS, rallow_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_ROLE_TRANS, rtrans_stats);
	poldiff_get_stats(app->diff, POLDIFF_DIFF_CONDS, cond_stats);

	g_string_printf(string,"Classes %d "
			"Commons %d Types: %d Attribs: %d Roles: %d Users: %d Bools: %d "
			"TE Rules: %d Role Allows: %d Role Trans: %d",
			class_stats[0]+class_stats[1]+class_stats[2],
			common_stats[0]+common_stats[1]+common_stats[2],
			type_stats[0]+type_stats[1]+type_stats[2],
			attrib_stats[0]+attrib_stats[1]+attrib_stats[2],
			role_stats[0]+role_stats[1]+role_stats[2],
			user_stats[0]+user_stats[1]+user_stats[2],
			bool_stats[0]+bool_stats[1]+bool_stats[2],
			terule_stats[0]+terule_stats[1]+terule_stats[2]+terule_stats[3]+terule_stats[4] +
			avrule_stats[0]+avrule_stats[1]+avrule_stats[2]+avrule_stats[3]+avrule_stats[4],
			rallow_stats[0]+rallow_stats[1]+rallow_stats[2],
			rtrans_stats[0]+rtrans_stats[1]+rtrans_stats[2]+rtrans_stats[3]+rtrans_stats[4]);
	statusbar = (GtkLabel *)(glade_xml_get_widget(app->window_xml, "label_stats"));
	g_assert(statusbar);
	gtk_label_set_text(statusbar, string->str);
	g_string_free(string, TRUE);
}


#if 0
static int sediff_txt_buffer_insert_te_results(GtkTextBuffer *txt, poldiff_t *diff, int opts, bool_t showheader)
{
        return 0;  /* FIX ME! */
}

static int sediff_txt_buffer_insert_cond_results(GtkTextBuffer *txt, poldiff_t *diff, int opts, bool_t showheader)
{
        return 0;  /* FIX ME! */
}


static void sediff_lazy_load_large_buffer(unsigned int buff_idx, gboolean show_dialog)
{
	if (show_dialog)
		sediff_progress_message(sediff_app, "Loading Buffers", "Loading text - this may take a while.");

	switch (buff_idx) {
	case OPT_TE_RULES_ADD:
		if (sediff_app->te_add_buffer == NULL) {
			sediff_app->te_add_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_add_buffer, sediff_app->diff, POLDIFF_FORM_ADDED, TRUE);
		}
		break;
	case OPT_TE_RULES_ADD_TYPE:
		if (sediff_app->te_add_type_buffer == NULL) {
			sediff_app->te_add_type_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_add_type_buffer, sediff_app->diff, POLDIFF_FORM_ADD_TYPE, TRUE);
		}
		break;
	case OPT_TE_RULES_REM:
		if (sediff_app->te_rem_buffer == NULL) {
			sediff_app->te_rem_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_rem_buffer, sediff_app->diff, POLDIFF_FORM_REMOVED, TRUE);
		}
		break;
	case OPT_TE_RULES_REM_TYPE:
		if (sediff_app->te_rem_type_buffer == NULL) {
			sediff_app->te_rem_type_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_rem_type_buffer, sediff_app->diff, POLDIFF_FORM_REMOVE_TYPE, TRUE);
		}
		break;
	case OPT_TE_RULES_MOD:
		if (sediff_app->te_mod_buffer == NULL) {
			sediff_app->te_mod_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_mod_buffer, sediff_app->diff, POLDIFF_FORM_MODIFIED, TRUE);
		}
		break;
	case OPT_CONDITIONALS_ADD:
		if (sediff_app->cond_add_buffer == NULL) {
			sediff_app->cond_add_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_cond_results(sediff_app->cond_add_buffer, sediff_app->diff, POLDIFF_FORM_ADDED, TRUE);
		}
		break;
	case OPT_CONDITIONALS_REM:
		if (sediff_app->cond_rem_buffer == NULL) {
			sediff_app->cond_rem_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_cond_results(sediff_app->cond_rem_buffer, sediff_app->diff, POLDIFF_FORM_REMOVED, TRUE);
		}
		break;
	case OPT_CONDITIONALS_MOD:
		if (sediff_app->cond_mod_buffer == NULL) {
			sediff_app->cond_mod_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_cond_results(sediff_app->cond_mod_buffer, sediff_app->diff, POLDIFF_FORM_MODIFIED, TRUE);
		}

		break;
	default:
		assert(FALSE);
		break;
	}

	if (show_dialog)
		sediff_progress_hide(sediff_app);
}

static void sediff_callback_signal_emit_1(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *)data;
	unsigned int type = *(unsigned int*)user_data;
	if (callback->type == type) {
		gpointer data = &callback->user_data;
		g_idle_add_full(G_PRIORITY_HIGH_IDLE+10, callback->function, &data, NULL);
	}
	return;
}

/* the signal emit function executes each function registered with
 * sediff_callback_register() */
static void sediff_callback_signal_emit(unsigned int type)
{
	g_list_foreach(sediff_app->callbacks, &sediff_callback_signal_emit_1, &type);
	return;
}

static int sediff_txt_buffer_insert_results(GtkTextBuffer *txt, GString *string, poldiff_t *diff, uint32_t flag, int opts)
{
	char* (*get_name)(poldiff_t *diff, const void *cls);
	apol_vector_t *diff_vector;
	char *name, *descrp = NULL, *adescrp = NULL;
	int i;
	GtkTextTag *added_tag, *removed_tag, *changed_tag;
	GtkTextTag *header_added_tag,*header_removed_tag,*header_changed_tag,*header_tag;
	GtkTextTagTable *table;
	GtkTextMark *mark;
	GtkTextIter iter;
	size_t stats[5] = {0,0,0,0,0};

	if (string == NULL || diff == NULL) {
		g_assert(FALSE);
		return -1;
	}

	gtk_text_buffer_get_start_iter(txt, &iter);

	mark = gtk_text_buffer_get_mark(txt,"added-mark");
	if (!mark)
		mark = gtk_text_buffer_create_mark (txt,"added-mark",&iter,TRUE);
	gtk_text_buffer_get_iter_at_mark(txt,&iter,mark);

	table = gtk_text_buffer_get_tag_table(txt);
	added_tag = gtk_text_tag_table_lookup(table, "added-tag");
	if (!added_tag) {
		added_tag = gtk_text_buffer_create_tag(txt, "added-tag",
						      "family", "monospace",
						      "foreground", "dark green",
						      NULL);
	}
	removed_tag = gtk_text_tag_table_lookup(table, "removed-tag");
	if (!removed_tag) {
		removed_tag = gtk_text_buffer_create_tag(txt, "removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 NULL);
	}
	changed_tag = gtk_text_tag_table_lookup(table, "changed-tag");
	if (!changed_tag) {
		changed_tag = gtk_text_buffer_create_tag(txt, "changed-tag",
						       "family", "monospace",
						       "foreground", "dark blue",
						       NULL);
	}
	header_removed_tag = gtk_text_tag_table_lookup(table, "header-removed-tag");
	if(!header_removed_tag) {
		header_removed_tag = gtk_text_buffer_create_tag (txt, "header-removed-tag",
						      "family", "monospace",
								 "foreground", "red",
								 "weight", PANGO_WEIGHT_BOLD, NULL);
	}
	header_added_tag = gtk_text_tag_table_lookup(table, "header-added-tag");
	if(!header_added_tag) {
		header_added_tag = gtk_text_buffer_create_tag (txt, "header-added-tag",
						      "family", "monospace",
							       "foreground", "dark green",
							       "weight", PANGO_WEIGHT_BOLD, NULL);
	}
	header_changed_tag = gtk_text_tag_table_lookup(table, "header-changed-tag");
	if(!header_changed_tag) {
		header_changed_tag = gtk_text_buffer_create_tag (txt, "header-changed-tag",
						      "family", "monospace",
								 "foreground", "dark blue",
								 "weight", PANGO_WEIGHT_BOLD, NULL);
	}
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
						      "family", "monospace",
							 "weight", PANGO_WEIGHT_BOLD,
							 "underline", PANGO_UNDERLINE_SINGLE,
							 NULL);
	}

	switch(flag) {
/*
	case POLDIFF_DIFF_ROLE_ALLOWS:
                diff_vector = poldiff_get_class_vector(diff);
                get_name = poldiff_class_to_string;
		descrp = "Role Allows";
		adescrp = "Role Allows";
		break;
	case POLDIFF_DIFF_TYPES:
                diff_vector = poldiff_get_class_vector(diff);
                get_name = poldiff_class_to_string;
		descrp = "Types";
		adescrp = "Attributes";
		break;
	case POLDIFF_DIFF_ATTRIBS:
                diff_vector = poldiff_get_class_vector(diff);
                get_name = poldiff_class_to_string;
		descrp = "Attributes";
		adescrp = "Types";
		break;
*/
	case POLDIFF_DIFF_ROLES:
                diff_vector = poldiff_get_role_vector(diff);
                get_name = poldiff_role_to_string;
		descrp = "Roles";
		adescrp = "Types";
		break;
	case POLDIFF_DIFF_USERS:
                diff_vector = poldiff_get_user_vector(diff);
                get_name = poldiff_user_to_string;
		descrp = "Users";
		adescrp = "Roles";
		break;
	case POLDIFF_DIFF_CLASSES:
		diff_vector = poldiff_get_class_vector(diff);
		get_name = poldiff_class_to_string;
		descrp = "Classes";
		adescrp = "Permissions";
		break;
	case POLDIFF_DIFF_BOOLS:
		diff_vector = poldiff_get_bool_vector(diff);
		get_name = poldiff_bool_to_string;
		descrp = "Booleans";
		adescrp = "Booleans";
/*
	case POLDIFF_DIFF_COMMONS:
                diff_vector = poldiff_get_class_vector(diff);
                get_name = poldiff_class_to_string;
		descrp = "Commons";
		adescrp = "Permissions";
		break;
*/
	default:
		g_assert(FALSE);
		return -1;
	}

	poldiff_get_stats(diff, flag, stats);
	g_string_printf(string, "%s (%d Added, %d Removed, %d Changed)\n", descrp, stats[0], stats[1], stats[2]);
	sediff_add_hdr(txt, string);

	if (opts & POLDIFF_FORM_ADDED) {
		g_string_printf(string, "\tAdded %s: %d\n", descrp, stats[0]);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,
						 -1, "header-added-tag", NULL);
		for (i=0; i<apol_vector_get_size(diff_vector); i++) {
			void *obj;
			obj = apol_vector_get_element(diff_vector, i);
			name = get_name(diff,obj);
			if (!name) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, i);
				return -1;
			}
			if (name[0]!='+') continue;
			g_string_printf(string, "\t\t%s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,
								 -1, "added-tag", NULL);
			free(name);
		}
	}
	if (opts & POLDIFF_FORM_REMOVED) {
		g_string_printf(string, "\tRemoved %s: %d\n",descrp, stats[1]);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,
						 -1, "header-removed-tag", NULL);
		for (i=0; i<apol_vector_get_size(diff_vector); i++) {
                        void *obj;
                        obj = apol_vector_get_element(diff_vector, i);
                        name = get_name(diff,obj);
                        if (!name) {
                                fprintf(stderr, "Problem getting name for %s %d\n", descrp, i);
                                return -1;
                        }
                        if (name[0]!='-') continue;
			g_string_printf(string, "\t\t%s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,
								 -1, "removed-tag", NULL);
			free(name);
		}
	}

	if (opts & POLDIFF_FORM_MODIFIED) {
		g_string_printf(string, "\tChanged %s: %d\n", descrp, stats[2]);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,
						 -1, "header-changed-tag", NULL);
		for (i=0; i<apol_vector_get_size(diff_vector); i++) {
	                void *obj;
	                obj = apol_vector_get_element(diff_vector, i);
	        name = get_name(diff,obj);
                        if (!name) {
                                fprintf(stderr, "Problem getting name for %s %d\n", descrp, i);
                                return -1;
                        }
                        if (name[0]!='*') continue;
			g_string_printf(string, "\t\t%s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			free(name);
		}
	}

	gtk_text_buffer_delete_mark(txt,mark);
	return 0;
}


static void sediff_txt_buffer_insert_summary(GtkTextBuffer *txt, int opt)
{
	GtkTextTagTable *table;
	GtkTextTag *header_tag, *header_removed_tag = NULL, *header_changed_tag = NULL;
	GtkTextTag *header_added_tag = NULL, *main_header_tag;
	GString *string;
	GtkTextIter iter;
	size_t stats[5] = {0,0,0,0,0};

	string = g_string_new("");
	table = gtk_text_buffer_get_tag_table(txt);
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
						      "family", "monospace",
							 "weight", PANGO_WEIGHT_BOLD,
							 "underline", PANGO_UNDERLINE_SINGLE,
							 NULL);
	}
	main_header_tag = gtk_text_tag_table_lookup(table, "main-header-tag");
	if (!main_header_tag) {
	        main_header_tag = gtk_text_buffer_create_tag(txt, "main-header-tag",
							 "style", PANGO_STYLE_ITALIC,
							 "weight", PANGO_WEIGHT_BOLD,
							NULL);
	}
	header_removed_tag = gtk_text_tag_table_lookup(table, "header-removed-tag");
	if(!header_removed_tag) {
		header_removed_tag = gtk_text_buffer_create_tag (txt, "header-removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 "weight", PANGO_WEIGHT_BOLD, NULL);
	}
	header_added_tag = gtk_text_tag_table_lookup(table, "header-added-tag");
	if(!header_added_tag) {
		header_added_tag = gtk_text_buffer_create_tag (txt, "header-added-tag",
							 "family", "monospace",
							 "foreground", "dark green",
							 "weight", PANGO_WEIGHT_BOLD, NULL);
	}
	header_changed_tag = gtk_text_tag_table_lookup(table, "header-changed-tag");
	if(!header_changed_tag) {
		header_changed_tag = gtk_text_buffer_create_tag (txt, "header-changed-tag",
							 "family", "monospace",
							 "foreground", "dark blue",
							 "weight", PANGO_WEIGHT_BOLD, NULL);
	}

	gtk_text_buffer_get_end_iter(txt, &iter);
	switch(opt) {
	case OPT_CLASSES:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_CLASSES, stats);
		g_string_printf(string,"Classes:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, header_tag, NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_COMMON_PERMS:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_COMMONS, stats);
		g_string_printf(string,"Commons:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_TYPES:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_TYPES, stats);
		g_string_printf(string,"Types:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_ATTRIBUTES:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_ATTRIBS, stats);
		g_string_printf(string,"Attributes:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_ROLES:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_ROLES, stats);
		g_string_printf(string,"Roles:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_USERS:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_USERS, stats);
		g_string_printf(string,"Users:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_BOOLEANS:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_BOOLS, stats);
		g_string_printf(string,"Booleans:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_AV_RULES:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_AVRULES, stats);
		g_string_printf(string,"AV Rules:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_TE_RULES:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_TERULES, stats);
		g_string_printf(string,"TE Rules:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_ROLE_ALLOWS:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_ROLE_ALLOWS, stats);
		g_string_printf(string,"Role Allows:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_ROLE_TRANS:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_ROLE_TRANS, stats);
		g_string_printf(string,"Role Transitions:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_CONDITIONALS:
		poldiff_get_stats(sediff_app->diff, POLDIFF_DIFF_CONDS, stats);
		g_string_printf(string,"Conditionals:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n", stats[0]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n", stats[1]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n", stats[2]);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	default:
		break;
	}
	g_string_free(string,TRUE);
}


/*
 * switches the currently displayed text buffer
 */
static void sediff_results_txt_view_switch_buffer(GtkTextView *textview,gint option,gint policy_option)
{
	GtkTextAttributes *attr;
	gint size;
	PangoTabArray *tabs;
/*
	GtkTextIter end;
	GtkTextTag *link1_tag;
	GtkTextTag *link2_tag;
	GtkTextTagTable *table;
*/
	GString *string = g_string_new("");
	int rt;
	GtkWidget *widget = NULL;
	GtkTextIter iter;
	GtkTextMark *mark;
	GtkTextBuffer *txt;
	GdkRectangle rect;

	/* Save position in this buffer
	   you must use an offset because an x/y coord is does not stay true
	   across clears and redraws */
	gtk_text_view_get_visible_rect(textview, &rect);
	gtk_text_view_get_iter_at_location(textview, &iter, rect.x,
					   rect.y);
	sediff_app->tv_buf_offsets[sediff_app->tv_curr_buf] = gtk_text_iter_get_offset(&iter);


	attr = gtk_text_view_get_default_attributes(textview);
	if (attr->font != NULL) {
		size = pango_font_description_get_size(attr->font);
		tabs = pango_tab_array_new_with_positions (4,
					    FALSE,
					    PANGO_TAB_LEFT, 3*size,
					    PANGO_TAB_LEFT, 6*size,
					    PANGO_TAB_LEFT, 9*size,
					    PANGO_TAB_LEFT, 12*size);
		if (gtk_text_view_get_tabs(textview) == NULL)
			gtk_text_view_set_tabs(textview,tabs);
	}
	if (policy_option == 1) {
		sediff_find_window_reset_idx(sediff_app->find_window);
		widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_sort_menu");
		g_assert(widget);
		gtk_widget_set_sensitive(widget, FALSE);

		switch (option) {
		case OPT_SUMMARY:
			if (sediff_app->diff != NULL)
				sediff_txt_buffer_insert_summary_results(sediff_app->main_buffer);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_CLASSES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_CLASSES);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_CLASSES_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->diff, POLDIFF_DIFF_CLASSES, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_CLASSES_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->diff, POLDIFF_DIFF_CLASSES, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_CLASSES_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->diff, POLDIFF_DIFF_CLASSES, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
/*
		case OPT_PERMISSIONS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_PERMISSIONS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_PERMISSIONS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_perms_results(sediff_app->main_buffer,
					    string, sediff_app->svd->perms,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_PERMISSIONS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_perms_results(sediff_app->main_buffer,
					    string, sediff_app->svd->perms,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);
			break;
		case OPT_COMMON_PERMS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_COMMON_PERMS);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);
			break;
		case OPT_COMMON_PERMS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
							    string, sediff_app->svd->common_perms,
							    sediff_app->svd->diff->p1,
							    sediff_app->svd->diff->p2, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_COMMON_PERMS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
							    string, sediff_app->svd->common_perms,
							    sediff_app->svd->diff->p1,
							    sediff_app->svd->diff->p2, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_COMMON_PERMS_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
							    string, sediff_app->svd->common_perms,
							    sediff_app->svd->diff->p1,
							    sediff_app->svd->diff->p2, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_TYPES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_TYPES);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);
			break;
		case OPT_TYPES_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->types,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_TYPES_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->types,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_TYPES_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->types,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
*/
		case OPT_ROLES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_ROLES);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);
			break;
		case OPT_ROLES_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_ROLES, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLES_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_ROLES, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLES_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_ROLES, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
/*
		case OPT_ROLES_MOD_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->roles,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_ADD_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLES_MOD_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->roles,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_REMOVE_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
*/
		case OPT_USERS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_USERS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_USERS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_USERS, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_USERS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_USERS, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_USERS_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_USERS, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
/*
		case OPT_ATTRIBUTES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			gtk_text_buffer_get_start_iter(sediff_app->main_buffer,&end);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_ATTRIBUTES);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ATTRIBUTES_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ATTRIBUTES_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ATTRIBUTES_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ATTRIBUTES_MOD_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_ADD_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ATTRIBUTES_MOD_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_REMOVE_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
*/
		case OPT_BOOLEANS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_BOOLEANS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_BOOLEANS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_BOOLS, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_BOOLEANS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_BOOLS, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_BOOLEANS_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
                        rt = sediff_txt_buffer_insert_results(sediff_app->main_buffer,
                                            string, sediff_app->diff, POLDIFF_DIFF_BOOLS, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
/*
		case OPT_ROLE_ALLOWS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_ROLE_ALLOWS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_ALLOWS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_rallow_results(sediff_app->main_buffer,
					    string, sediff_app->svd->rallows,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_ALLOWS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_rallow_results(sediff_app->main_buffer,
					    string, sediff_app->svd->rallows,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_ALLOWS_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_rallow_results(sediff_app->main_buffer,
					    string, sediff_app->svd->rallows,
					    sediff_app->svd->diff->p1,
					    sediff_app->svd->diff->p2, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_TRANS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_ROLE_TRANS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_TRANS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans,
							 sediff_app->svd->diff->p1,
							 sediff_app->svd->diff->p2, POLDIFF_FORM_ADDED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_TRANS_ADD_TYPE:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans,
							 sediff_app->svd->diff->p1,
							 sediff_app->svd->diff->p2, POLDIFF_FORM_ADD_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_TRANS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans,
							 sediff_app->svd->diff->p1,
							 sediff_app->svd->diff->p2, POLDIFF_FORM_REMOVED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_TRANS_REM_TYPE:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans,
							 sediff_app->svd->diff->p1,
							 sediff_app->svd->diff->p2, POLDIFF_FORM_REOVE_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_ROLE_TRANS_MOD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans,
							 sediff_app->svd->diff->p1,
							 sediff_app->svd->diff->p2, POLDIFF_FORM_MODIFIED);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_CONDITIONALS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_CONDITIONALS);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);
			break;
		case OPT_CONDITIONALS_ADD:
			if (sediff_app->cond_add_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_CONDITIONALS_ADD, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->cond_add_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->cond_add_buffer);
			break;
		case OPT_CONDITIONALS_REM:
			if (sediff_app->cond_rem_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_CONDITIONALS_REM, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->cond_rem_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->cond_rem_buffer);
			break;
		case OPT_CONDITIONALS_MOD:
			if (sediff_app->cond_mod_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_CONDITIONALS_MOD, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->cond_mod_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->cond_mod_buffer);
			break;
		case OPT_TE_RULES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_TE_RULES);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);
			break;
		case OPT_TE_RULES_ADD:
			if (sediff_app->te_add_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_ADD, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_add_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_add_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		case OPT_TE_RULES_REM:
			if (sediff_app->te_rem_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_REM, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_rem_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_rem_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		case OPT_TE_RULES_MOD:
			if (sediff_app->te_mod_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_MOD, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_mod_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_mod_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		case OPT_TE_RULES_ADD_TYPE:
			if (sediff_app->te_add_type_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_ADD_TYPE, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_add_type_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_add_type_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		case OPT_TE_RULES_REM_TYPE:
			if (sediff_app->te_rem_type_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_REM_TYPE, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_rem_type_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event),
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion",
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_rem_type_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
*/
		default:
			fprintf(stderr, "Invalid list item %d!", option);
			break;
		};

		/** go back to our previous location if we had one
		   must use marks to ensure that we go to this position even if
		   it hasn't been drawn
		 **/
		txt = gtk_text_view_get_buffer(textview);
		gtk_text_buffer_get_start_iter(txt, &iter);
		gtk_text_iter_set_offset(&iter, sediff_app->tv_buf_offsets[option]);
		mark = gtk_text_buffer_create_mark(txt, "location-mark", &iter, FALSE);
		gtk_text_view_scroll_to_mark(textview, mark, 0.0, TRUE, 0.0, 0.0);
		gtk_text_buffer_delete_mark(txt, mark);
		sediff_app->tv_curr_buf = option;
	}
}

#endif
