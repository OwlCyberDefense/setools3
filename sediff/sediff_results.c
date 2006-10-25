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
#include "utilgui.h"

#include <qpol/cond_query.h>

#include <assert.h>
#include <string.h>

struct sediff_results {
	GtkTextBuffer *main_buffer;       /* generic buffer used for everything but te rules and conditionals(because they take so long to draw) */
	GtkTextBuffer *te_buffers[5];
	int te_buffered[5];
	gint *saved_offsets;
	size_t current_buffer;
};

extern sediff_item_record_t sediff_items[];

static gboolean sediff_results_line_event(GtkTextTag *tag, GObject *event_object,
					  GdkEvent *event, const GtkTextIter *iter,
					  gpointer user_data);

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
		/* allocate an array to keep track of the scrollbar
		 * position; that way when a user switches to a
		 * particular result item the view will retain its
		 * position */
                for (i = 0; sediff_items[i].label != NULL; i++)
                        ;
		/* add 1 for the summary buffer; multiply by 6 for the
		 * 5 different difference forms + summary display */
		r->saved_offsets = g_malloc0((i + 1) * 6 * sizeof(gint));
		r->current_buffer = 0;
        }
	if (r->main_buffer == NULL) {
		/* recreate the results buffer -- it could have been
		 * destroyed by sediff_results_clear() */
		GtkTextTagTable *tag_table;
		GtkTextTag *tag;
		r->main_buffer = gtk_text_buffer_new(NULL);
		tag_table = gtk_text_buffer_get_tag_table(r->main_buffer);
		for (i = 0; i < 5; i++) {
			r->te_buffers[i] = gtk_text_buffer_new(tag_table);
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
		gtk_text_buffer_create_tag(r->main_buffer, "removed-header",
					   "family", "monospace",
					   "foreground", "red",
					   "weight", PANGO_WEIGHT_BOLD, NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "added-header",
					   "family", "monospace",
					   "foreground", "dark green",
					   "weight", PANGO_WEIGHT_BOLD, NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "modified-header",
					   "family", "monospace",
					   "foreground", "dark blue",
					   "weight", PANGO_WEIGHT_BOLD, NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "removed",
					   "family", "monospace",
					   "foreground", "red",
					   NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "added",
					   "family", "monospace",
					   "foreground", "dark green",
					   NULL);
		gtk_text_buffer_create_tag(r->main_buffer, "modified",
					   "family", "monospace",
					   "foreground", "dark blue",
					   NULL);
		tag = gtk_text_buffer_create_tag(r->main_buffer, "line-p1",
						 "family", "monospace",
						 "foreground", "blue",
						 "underline", PANGO_UNDERLINE_SINGLE,
						 NULL);
		g_signal_connect_after(G_OBJECT(tag), "event",
				       GTK_SIGNAL_FUNC(sediff_results_line_event), "orig");
		tag = gtk_text_buffer_create_tag(r->main_buffer, "line-p2",
						 "family", "monospace",
						 "foreground", "blue",
						 "underline", PANGO_UNDERLINE_SINGLE,
						 NULL);
		g_signal_connect_after(G_OBJECT(tag), "event",
				       GTK_SIGNAL_FUNC(sediff_results_line_event), "mod");
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
				r->te_buffered[i] = 0;
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

static void sediff_results_select_summary(sediff_app_t *app, GtkTextView *view)
{
	sediff_results_t *r = app->results;
	GtkTextBuffer *tb = r->main_buffer;
	GtkTextIter iter;
	GString *string = g_string_new("");
	size_t i;

	gtk_text_view_set_buffer(view, tb);
	sediff_clear_text_buffer(tb);

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
		if (!poldiff_is_run(app->diff, sediff_items[i].bit_pos)) {
			continue;
		}
		gtk_text_buffer_insert(tb, &iter, "\n", -1);
                sediff_results_print_summary(app, tb, sediff_items + i);
                gtk_text_buffer_get_end_iter(tb, &iter);
	}
	g_string_free(string, TRUE);
}

static void sediff_results_print_item_header(sediff_app_t *app, GtkTextBuffer *tb, sediff_item_record_t *record, poldiff_form_e form) {
	GtkTextIter iter;
	size_t stats[5] = {0, 0, 0, 0, 0};
	GString *string = g_string_new("");
	char *s;

	gtk_text_buffer_get_end_iter(tb, &iter);
	poldiff_get_stats(app->diff, record->bit_pos, stats);
	if (record->has_add_type) {
		g_string_printf(string, "%s (%zd Added, %zd Added New Type, %zd Removed, %zd Removed Missing Type, %zd Changed)\n\n",
				record->label,
				stats[0], stats[3],
				stats[1], stats[4],
				stats[2]);
	}
	else {
		g_string_printf(string, "%s (%zd Added, %zd Removed, %zd Changed)\n\n",
				record->label,
				stats[0],
				stats[1],
				stats[2]);
	}
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "header", NULL);

	switch (form) {
	case POLDIFF_FORM_ADDED: {
		g_string_printf(string, "Added %s: %zd\n", record->label, stats[0]);
		s = "added-header";
		break;
	}
	case POLDIFF_FORM_ADD_TYPE: {
		g_string_printf(string, "Added %s because of new type: %zd\n", record->label, stats[3]);
		s = "added-header";
		break;
	}
	case POLDIFF_FORM_REMOVED: {
		g_string_printf(string, "Removed %s: %zd\n", record->label, stats[1]);
		s = "removed-header";
		break;
	}
	case POLDIFF_FORM_REMOVE_TYPE: {
		g_string_printf(string, "Removed %s because of missing type: %zd\n", record->label, stats[4]);
		s = "removed-header";
		break;
	}
	case POLDIFF_FORM_MODIFIED: {
		g_string_printf(string, "Modified %s: %zd\n", record->label, stats[2]);
		s = "modified-header";
		break;
	}
	default: {
		assert(0);
		s = NULL;
	}
	}
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, s, NULL);
	g_string_free(string, TRUE);
}

static void sediff_results_print_string(GtkTextBuffer *tb, GtkTextIter *iter,
					const char *s, unsigned int indent_level) {
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
		case '+': {
			if (*(c + 1) == ' ') {
				if (end > 0) {
					gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag, NULL);
				}
				start = end;
				current_tag = "added";
				break;
			}
		}
		case '-': {
			if (*(c + 1) == ' ') {
				if (end > 0) {
					gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag, NULL);
				}
				start = end;
				current_tag = "removed";
			}
			break;
		}
		case '*': {
			if (*(c + 1) == ' ') {
				if (end > 0) {
					gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag, NULL);
				}
				start = end;
				current_tag = "modified";
			}
			break;
		}
		case '\n': {
			if (*(c + 1) != '\0') {
				gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start + 1, current_tag, NULL);
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

static void sediff_results_select_simple(sediff_app_t *app, GtkTextView *view,
					 sediff_item_record_t *item_record, poldiff_form_e form)
{
	sediff_results_t *r = app->results;
        GtkTextBuffer *tb = r->main_buffer;

	gtk_text_view_set_buffer(view, tb);
	sediff_clear_text_buffer(tb);

	if (form == POLDIFF_FORM_NONE) {
		sediff_results_print_summary(app, tb, item_record);
	}
	else {
		GtkTextIter iter;
		apol_vector_t *v;
		size_t i;
		void *elem;
		char *s = NULL;

		sediff_results_print_item_header(app, tb, item_record, form);
		gtk_text_buffer_get_end_iter(tb, &iter);

		v = item_record->get_vector(app->diff);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			elem = apol_vector_get_element(v, i);
			if (item_record->get_form(elem) == form) {
				s = item_record->get_string(app->diff, elem);
				sediff_results_print_string(tb, &iter, s, 1);
				free(s);
				gtk_text_buffer_insert(tb, &iter, "\n", -1);
			}
		}
	}

}

struct sort_opts {
        poldiff_t *diff;
        int field;
        int direction;
};

static int sediff_results_avsort_comp(const void *a, const void *b, void *data)
{
	const poldiff_avrule_t *a1 = a;
	const poldiff_avrule_t *a2 = b;
	struct sort_opts *opts = data;
	const char *s1, *s2;
	switch (opts->field) {
	case SORT_SOURCE: {
		s1 = poldiff_avrule_get_source_type(a1);
		s2 = poldiff_avrule_get_source_type(a2);
		break;
	}
	case SORT_TARGET: {
		s1 = poldiff_avrule_get_target_type(a1);
		s2 = poldiff_avrule_get_target_type(a2);
		break;
	}
	case SORT_CLASS: {
		s1 = poldiff_avrule_get_object_class(a1);
		s2 = poldiff_avrule_get_object_class(a2);
		break;
	}
	case SORT_COND: {
		qpol_cond_t *q1, *q2;
		apol_policy_t *p1, *p2;
		uint32_t w1, w2;
		poldiff_avrule_get_cond(opts->diff, a1, &q1, &w1, &p1);
		poldiff_avrule_get_cond(opts->diff, a2, &q2, &w2, &p2);
		if (q1 != q2) {
			return opts->direction * ((int) q1 - (int) q2);
		}
		return opts->direction * (w1 - w2);
		break;
	}
	default: {
		/* shouldn't get here */
		assert(0);
		return 0;
	}
	}
	return opts->direction * strcmp(s1, s2);
}

static apol_vector_t *sediff_results_avsort(poldiff_t *diff, poldiff_form_e form, int field, int direction)
{
	apol_vector_t *orig_v, *v;
	size_t i;
	void *elem;
	struct sort_opts opts = {diff, field, direction};
	orig_v = poldiff_get_avrule_vector(diff);
	if ((v = apol_vector_create()) == NULL) {
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(orig_v); i++) {
		elem = apol_vector_get_element(orig_v, i);
		if (poldiff_avrule_get_form(elem) == form &&
		    apol_vector_append(v, elem) < 0) {
			apol_vector_destroy(&v, NULL);
			return NULL;
		}
	}
	if (field != SORT_DEFAULT) {
		apol_vector_sort(v, sediff_results_avsort_comp, &opts);
	}
	return v;
}

static int sediff_results_tesort_comp(const void *a, const void *b, void *data)
{
	const poldiff_terule_t *a1 = a;
	const poldiff_terule_t *a2 = b;
	struct sort_opts *opts = data;
	const char *s1, *s2;
	switch (opts->field) {
	case SORT_SOURCE: {
		s1 = poldiff_terule_get_source_type(a1);
		s2 = poldiff_terule_get_source_type(a2);
		break;
	}
	case SORT_TARGET: {
		s1 = poldiff_terule_get_target_type(a1);
		s2 = poldiff_terule_get_target_type(a2);
		break;
	}
	case SORT_CLASS: {
		s1 = poldiff_terule_get_object_class(a1);
		s2 = poldiff_terule_get_object_class(a2);
		break;
	}
	case SORT_COND: {
		qpol_cond_t *q1, *q2;
		apol_policy_t *p1, *p2;
		uint32_t w1, w2;
		poldiff_terule_get_cond(opts->diff, a1, &q1, &w1, &p1);
		poldiff_terule_get_cond(opts->diff, a2, &q2, &w2, &p2);
		if (q1 != q2) {
			return opts->direction * ((int) q1 - (int) q2);
		}
		return opts->direction * (w1 - w2);
		break;
	}
	default: {
		/* shouldn't get here */
		assert(0);
		return 0;
	}
	}
	return opts->direction * strcmp(s1, s2);
}

static apol_vector_t *sediff_results_tesort(poldiff_t *diff, poldiff_form_e form, int field, int direction)
{
	apol_vector_t *orig_v, *v;
	size_t i;
	void *elem;
	struct sort_opts opts = {diff, field, direction};
	orig_v = poldiff_get_terule_vector(diff);
	if ((v = apol_vector_create()) == NULL) {
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(orig_v); i++) {
		elem = apol_vector_get_element(orig_v, i);
		if (poldiff_terule_get_form(elem) == form &&
		    apol_vector_append(v, elem) < 0) {
			apol_vector_destroy(&v, NULL);
			return NULL;
		}
	}
	if (field != SORT_DEFAULT) {
		apol_vector_sort(v, sediff_results_tesort_comp, &opts);
	}
	return v;
}

/**
 * Print a modified rule.  Note that this differs from the more
 * general sediff_results_print_string() because:
 *
 * <ul>
 *   <li>there are inline '+' and '-' markers
 *   <li>for source policies, hyperlink permission names to their
 *       line(s) within the policy
 * </ul>
 */
static void sediff_results_print_rule_modified(GtkTextBuffer *tb, GtkTextIter *iter,
					       const char *s, unsigned int indent_level) {
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
		case '+': {
			if (end > 0) {
				gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag, NULL);
			}
			start = end;
			current_tag = "added";
			break;
		}
		case '-': {
			if (end > 0) {
				gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, current_tag, NULL);
			}
			start = end;
			current_tag = "removed";
			break;
		}
		case '\n': {
			if (*(c + 1) != '\0') {
				gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start + 1, current_tag, NULL);
				for (i = 0; i < indent_level; i++) {
					gtk_text_buffer_insert(tb, iter, indent, -1);
				}
				start = end + 1;
			}
			break;
		}
		case ' ': {
			if (current_tag != "modified") {
				gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start + 1, current_tag, NULL);
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

static void sediff_results_print_linenos(GtkTextBuffer *tb, GtkTextIter *iter,
					 const gchar *prefix,
					 apol_vector_t *linenos, const gchar *tag, GString *string)
{
	size_t i;
	unsigned long lineno;
	gtk_text_buffer_insert(tb, iter, "  [", -1);
	if (prefix != NULL) {
		gtk_text_buffer_insert(tb, iter, prefix, -1);
	}
	for (i = 0; i < apol_vector_get_size(linenos); i++) {
		lineno = (unsigned long) apol_vector_get_element(linenos, i);
		if (i > 0) {
			gtk_text_buffer_insert(tb, iter, ", ", -1);
		}
                g_string_printf(string, "%lu", lineno);
		gtk_text_buffer_insert_with_tags_by_name(tb, iter, string->str, -1, tag, NULL);
	}
	gtk_text_buffer_insert(tb, iter, "]", -1);
}

static void sediff_results_print_rules(sediff_app_t *app, GtkTextBuffer *tb,
				       sediff_item_record_t *item_record,
				       poldiff_form_e form,
				       apol_vector_t *av, apol_vector_t *te)
{
	GtkTextIter iter;
	size_t i;
	void *elem;
	char *s;
	apol_vector_t *syn_linenos;
	GString *string = g_string_new("");

	sediff_results_print_item_header(app, tb, item_record, form);
	gtk_text_buffer_get_end_iter(tb, &iter);

	if (apol_vector_get_size(av) + apol_vector_get_size(te) > 0) {
		poldiff_enable_line_numbers(app->diff);
	}
	for (i = 0; i < apol_vector_get_size(av); i++) {
		elem = apol_vector_get_element(av, i);
		if ((s = poldiff_avrule_to_string(app->diff, elem)) == NULL) {
			message_display(app->window, GTK_MESSAGE_ERROR, "Out of memory!");
			g_string_free(string, TRUE);
			return;
		}
		if (form != POLDIFF_FORM_MODIFIED) {
			sediff_results_print_string(tb, &iter, s, 1);
			if ((syn_linenos = poldiff_avrule_get_orig_line_numbers((poldiff_avrule_t *) elem)) != NULL) {
				sediff_results_print_linenos(tb, &iter, NULL, syn_linenos, "line-p1", string);
			}
			if ((syn_linenos = poldiff_avrule_get_mod_line_numbers((poldiff_avrule_t *) elem)) != NULL) {
				sediff_results_print_linenos(tb, &iter, NULL, syn_linenos, "line-p2", string);
			}
		}
		else {
			sediff_results_print_rule_modified(tb, &iter, s, 1);
			if ((syn_linenos = poldiff_avrule_get_orig_line_numbers((poldiff_avrule_t *) elem)) != NULL) {
				sediff_results_print_linenos(tb, &iter, "p1: ", syn_linenos, "line-p1", string);
			}
			if ((syn_linenos = poldiff_avrule_get_mod_line_numbers((poldiff_avrule_t *) elem)) != NULL) {
				sediff_results_print_linenos(tb, &iter, "p2: ", syn_linenos, "line-p2", string);
			}
		}
		free(s);
		gtk_text_buffer_insert(tb, &iter, "\n", -1);
	}

	for (i = 0; i < apol_vector_get_size(te); i++) {
		elem = apol_vector_get_element(te, i);
		if ((s = poldiff_terule_to_string(app->diff, elem)) == NULL) {
			message_display(app->window, GTK_MESSAGE_ERROR, "Out of memory!");
			g_string_free(string, TRUE);
			return;
		}
		if (form != POLDIFF_FORM_MODIFIED) {
			sediff_results_print_string(tb, &iter, s, 1);
			if ((syn_linenos = poldiff_terule_get_orig_line_numbers((poldiff_terule_t *) elem)) != NULL) {
				sediff_results_print_linenos(tb, &iter, NULL, syn_linenos, "line-p1", string);
			}
			if ((syn_linenos = poldiff_terule_get_mod_line_numbers((poldiff_terule_t *) elem)) != NULL) {
				sediff_results_print_linenos(tb, &iter, NULL, syn_linenos, "line-p2", string);
			}
		}
		else {
			sediff_results_print_rule_modified(tb, &iter, s, 1);
			if ((syn_linenos = poldiff_terule_get_orig_line_numbers((poldiff_terule_t *) elem)) != NULL) {
				sediff_results_print_linenos(tb, &iter, "p1: ", syn_linenos, "line-p1", string);
			}
			if ((syn_linenos = poldiff_terule_get_mod_line_numbers((poldiff_terule_t *) elem)) != NULL) {
				sediff_results_print_linenos(tb, &iter, "p2: ", syn_linenos, "line-p2", string);
			}
		}
		free(s);
		gtk_text_buffer_insert(tb, &iter, "\n", -1);
	}

	app->results->te_buffered[form - 1] = 1;
	g_string_free(string, TRUE);
}


static void sediff_results_select_rules(sediff_app_t *app, GtkTextView *view,
					sediff_item_record_t *item_record, poldiff_form_e form)
{
	sediff_results_t *r = app->results;
	GtkTextBuffer *tb;

	if (form == POLDIFF_FORM_NONE) {
		tb = r->main_buffer;
		gtk_text_view_set_buffer(view, tb);
		sediff_clear_text_buffer(tb);
		sediff_results_print_summary(app, tb, item_record);
	}
	else {
		GtkWidget *w;
		apol_vector_t *av = NULL, *te = NULL;

		/* enable sort TE rules menu */
		w = glade_xml_get_widget(app->window_xml, "sediff_sort_menu");
		g_assert(w);

		gtk_widget_set_sensitive(w, TRUE);
		tb = r->te_buffers[form - 1];
		gtk_text_view_set_buffer(view, tb);
		if (r->te_buffered[form - 1]) {
			return;
		}

		sediff_progress_message(app, "Rendering Rules", "Rendering Rules - this may take a while.");

		if ((av = sediff_results_avsort(app->diff, form, SORT_DEFAULT, 0)) == NULL ||
		    (te = sediff_results_tesort(app->diff, form, SORT_DEFAULT, 0)) == NULL) {
			message_display(app->window, GTK_MESSAGE_ERROR, "Out of memory!");
			apol_vector_destroy(&av, NULL);
			apol_vector_destroy(&te, NULL);
			sediff_progress_hide(app);
			return;
		}
		sediff_results_print_rules(app, tb, item_record, form, av, te);
		apol_vector_destroy(&av, NULL);
		apol_vector_destroy(&te, NULL);
		sediff_progress_hide(app);
	}
}

void sediff_results_select(sediff_app_t *app, uint32_t diffbit, poldiff_form_e form)
{
	sediff_results_t *r = app->results;
	GtkTextView *textview1;
	GtkTextBuffer *tb;
	GtkTextMark *mark;
	GdkRectangle rect;
	GtkTextIter iter;
	GtkWidget *w;
	size_t i, new_buffer;
	sediff_item_record_t *item_record = NULL;

	if (app->diff == NULL) {
		/* diff not run yet, so don't display anything */
		return;
	}

	/* grab the text buffers for our text views */
	textview1 = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_results_txt_view"));
	g_assert(textview1);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(textview1), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(textview1), FALSE);

	/* save view position */
	gtk_text_view_get_visible_rect(textview1, &rect);
	gtk_text_view_get_iter_at_location(textview1, &iter, rect.x, rect.y);
	r->saved_offsets[r->current_buffer] = gtk_text_iter_get_offset(&iter);

	/* disable sort TE rules menu */
	w = glade_xml_get_widget(app->window_xml, "sediff_sort_menu");
	g_assert(w);
	gtk_widget_set_sensitive(w, FALSE);

	if (diffbit == POLDIFF_DIFF_SUMMARY) {
		sediff_results_select_summary(app, textview1);
		new_buffer = 0;
	}
	else {
		/* find associated item record */
		for (i = 0; sediff_items[i].label != NULL; i++) {
			if (sediff_items[i].bit_pos == diffbit) {
				item_record = sediff_items + i;
				break;
			}
		}
		assert(item_record != NULL);

		switch (diffbit) {
		case POLDIFF_DIFF_CLASSES:
		case POLDIFF_DIFF_COMMONS:
		case POLDIFF_DIFF_TYPES:
		case POLDIFF_DIFF_ATTRIBS:
		case POLDIFF_DIFF_ROLES:
		case POLDIFF_DIFF_USERS:
		case POLDIFF_DIFF_BOOLS:
		case POLDIFF_DIFF_ROLE_ALLOWS:
		case POLDIFF_DIFF_ROLE_TRANS: {
			sediff_results_select_simple(app, textview1, item_record, form);
			break;
		}
		case (POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES): {
			sediff_results_select_rules(app, textview1, item_record, form);
			break;
		}
		}

		/* add 1 to i because the first 6 slots are taken by
		 * the overall diff summary */
		new_buffer = (i + 1) * 6 + form;
	}

	/* restore saved location.  use marks to ensure that we go to
	 * this position even if it hasn't been drawn. */
	tb = gtk_text_view_get_buffer(textview1);
	gtk_text_buffer_get_start_iter(tb, &iter);
	gtk_text_iter_set_offset(&iter, r->saved_offsets[new_buffer]);
	mark = gtk_text_buffer_create_mark(tb, "location-mark", &iter, FALSE);
	gtk_text_view_scroll_to_mark(textview1, mark, 0.0, TRUE, 0.0, 0.0);
	gtk_text_buffer_delete_mark(tb, mark);
	r->current_buffer = new_buffer;
}

void sediff_results_sort_current(sediff_app_t *app, int field, int direction)
{
        uint32_t diffbit;
        poldiff_form_e form;
        sediff_item_record_t *item_record = NULL;
        size_t i;
        GtkTextBuffer *tb;
        apol_vector_t *av = NULL, *te = NULL;

	/* get the current row so we know what to sort */
	if (sediff_get_current_treeview_selected_row(GTK_TREE_VIEW(app->tree_view), &diffbit, &form) == 0) {
		return;
	}

	sediff_progress_message(app, "Sorting", "Sorting - this may take a while.");

	/* find associated item record */
	for (i = 0; sediff_items[i].label != NULL; i++) {
		if (sediff_items[i].bit_pos == diffbit) {
			item_record = sediff_items + i;
			break;
		}
	}
	assert(item_record != NULL);

	if ((av = sediff_results_avsort(app->diff, form, field, direction)) == NULL ||
	    (te = sediff_results_tesort(app->diff, form, field, direction)) == NULL) {
		message_display(app->window, GTK_MESSAGE_ERROR, "Out of memory!");
		apol_vector_destroy(&av, NULL);
		apol_vector_destroy(&te, NULL);
		sediff_progress_hide(app);
		return;
	}

	tb = app->results->te_buffers[form - 1];
	sediff_clear_text_buffer(tb);
	sediff_results_print_rules(app, tb, item_record, form, av, te);
	apol_vector_destroy(&av, NULL);
	apol_vector_destroy(&te, NULL);
	sediff_progress_hide(app);
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


/* Set the cursor to a hand when user scrolls over a line number in
 * when displaying te diff.
 */
gboolean sediff_results_on_text_view_motion(GtkWidget *widget,
					    GdkEventMotion *event,
					    gpointer user_data)
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
	}
	else {
		ex = event->x;
		ey = event->y;
	}

	gtk_text_view_window_to_buffer_coords(textview, GTK_TEXT_WINDOW_WIDGET,
					       ex, ey, &x, &y);
	buffer = gtk_text_view_get_buffer(textview);
	gtk_text_view_get_iter_at_location(textview, &iter, x, y);
	tags = gtk_text_iter_get_tags(&iter);
	for (tagp = tags;  tagp != NULL; tagp = tagp->next) {
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
	}
	else {
		gdk_window_set_cursor(event->window, NULL);
	}
	g_slist_free(tags);
	return FALSE;
}

static gboolean sediff_results_line_event(GtkTextTag *tag, GObject *event_object,
					  GdkEvent *event, const GtkTextIter *iter,
					  gpointer user_data)
{
	int offset, which_pol;
	unsigned long line;
	GtkTextIter *start, *end;
	if (event->type == GDK_BUTTON_PRESS) {
		start = gtk_text_iter_copy(iter);
		offset = gtk_text_iter_get_line_offset(start);

		/* testing a new way */
		while (!gtk_text_iter_starts_word(start))
			gtk_text_iter_backward_char(start);
		end = gtk_text_iter_copy(start);
		while (!gtk_text_iter_ends_word(end))
			gtk_text_iter_forward_char(end);

		/* the line # in policy starts with 1, in the buffer it
		   starts at 0 */
		line = atoi(gtk_text_iter_get_slice(start, end)) - 1;
                if (strcmp((char *) user_data, "orig") == 0) {
                        which_pol = 0;
                }
                else {
                        which_pol = 1;
                }

		sediff_main_notebook_raise_policy_tab_goto_line(line, which_pol);
		return TRUE;
	}
	return FALSE;
}
