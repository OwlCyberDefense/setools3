/**
 *  @file
 *  Common rendering routines for result items.
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

#include "result_item_render.h"

#include <assert.h>

static const char *form_name_map[] = {
	"Added", "Added New Type", "Removed", "Removed Missing Type", "Modified"
};
static const char *form_name_long_map[] = {
	"Added", "Added because of new type", "Removed", "Removed because of missing type", "Modified"
};
static const char *tag_map[] = {
	"added-header", "added-header", "removed-header", "removed-header", "modified-header"
};
static const poldiff_form_e form_map[] = {
	POLDIFF_FORM_ADDED, POLDIFF_FORM_ADD_TYPE,
	POLDIFF_FORM_REMOVED, POLDIFF_FORM_REMOVE_TYPE,
	POLDIFF_FORM_MODIFIED
};

/**
 * Show a single diff item string.  This will add the appropriate
 * color tags based upon the item's first non-space character.
 */
void result_item_print_string(GtkTextBuffer * tb, GtkTextIter * iter, const char *s, unsigned int indent_level)
{
	const char *c;
	unsigned int i;
	size_t start = 0, end = 0;
	static const char *indent = "\t";
	const gchar *tag = NULL;
	for (i = 0; i < indent_level; i++) {
		gtk_text_buffer_insert(tb, iter, indent, -1);
	}
	for (c = s; *c && tag == NULL; c++) {
		switch (*c) {
		case '+':{
				tag = "added";
				break;
			}
		case '-':{
				tag = "removed";
				break;
			}
		case ' ':
		case '\t':
		case '\n':{
				break;
			}
		default:{
				tag = "modified";
				break;
			}
		}
	}
	for (c = s; *c; c++, end++) {
		if (*c == '\n' && *(c + 1) != '\0') {
			gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start + 1, tag, NULL);
			for (i = 0; i < indent_level; i++) {
				gtk_text_buffer_insert(tb, iter, indent, -1);
			}
			start = end + 1;
		}
	}
	if (start < end) {
		gtk_text_buffer_insert_with_tags_by_name(tb, iter, s + start, end - start, tag, NULL);
	}
}

void result_item_print_string_inline(GtkTextBuffer * tb, GtkTextIter * iter, const char *s, unsigned int indent_level)
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

void result_item_print_diff(result_item_t * item, GtkTextBuffer * tb, poldiff_form_e form)
{
	GtkTextIter iter;
	apol_vector_t *v;
	size_t i;
	void *elem;
	char *s = NULL;

	gtk_text_buffer_get_end_iter(tb, &iter);
	v = result_item_get_vector(item);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		elem = apol_vector_get_element(v, i);
		if (result_item_get_form(item, elem) == form) {
			s = result_item_get_string(item, elem);
			result_item_print_string(tb, &iter, s, 1);
			free(s);
			gtk_text_buffer_insert(tb, &iter, "\n", -1);
		}
	}
}

void result_item_print_rule_diff(result_item_t * item, GtkTextBuffer * tb, poldiff_form_e form)
{
	GtkTextIter iter;
	apol_vector_t *v;
	size_t i;
	void *elem;
	char *s = NULL;

	gtk_text_buffer_get_end_iter(tb, &iter);
	v = result_item_get_vector(item);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		elem = apol_vector_get_element(v, i);
		if (result_item_get_form(item, elem) == form) {
			s = result_item_get_string(item, elem);
			if (form != POLDIFF_FORM_MODIFIED) {
				result_item_print_string(tb, &iter, s, 1);
			} else {
				result_item_print_string_inline(tb, &iter, s, 1);
			}
			free(s);
			gtk_text_buffer_insert(tb, &iter, "\n", -1);
		}
	}
}

void result_item_print_summary(result_item_t * item, GtkTextBuffer * tb)
{
	GtkTextIter iter;
	int i, forms[5];
	GString *string = g_string_new("");

	gtk_text_buffer_get_end_iter(tb, &iter);
	g_string_printf(string, "%s:\n", result_item_get_label(item));
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "subheader", NULL);

	result_item_get_forms(item, forms);
	for (i = 0; i < 5; i++) {
		if (forms[i] > 0) {
			g_string_printf(string, "\t%s: %zd\n",
					form_name_long_map[i], result_item_get_num_differences(item, form_map[i]));
			gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, tag_map[i], NULL);
		}
	}
	g_string_free(string, TRUE);
}

/**
 * Show a common header when printing a policy component diff.
 */
void result_item_print_header(result_item_t * item, GtkTextBuffer * tb, poldiff_form_e form)
{
	GtkTextIter iter;
	int i, forms[5];
	GString *string = g_string_new("");
	char *tag = NULL;
	const char *label = result_item_get_label(item);
	int add_separator = 0;

	gtk_text_buffer_get_end_iter(tb, &iter);
	result_item_get_forms(item, forms);
	g_string_printf(string, "%s (", label);
	for (i = 0; i < 5; i++) {
		if (forms[i] > 0) {
			g_string_append_printf(string, "%s%zd %s",
					       (add_separator ? ", " : ""),
					       result_item_get_num_differences(item, form_map[i]), form_name_map[i]);
			add_separator = 1;
		}
	}
	g_string_append_printf(string, ")\n\n");
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, "header", NULL);

	switch (form) {
	case POLDIFF_FORM_ADDED:{
			g_string_printf(string, "Added %s:", label);
			tag = "added-header";
			break;
		}
	case POLDIFF_FORM_ADD_TYPE:{
			g_string_printf(string, "Added %s because of new type:", label);
			tag = "added-header";
			break;
		}
	case POLDIFF_FORM_REMOVED:{
			g_string_printf(string, "Removed %s:", label);
			tag = "removed-header";
			break;
		}
	case POLDIFF_FORM_REMOVE_TYPE:{
			g_string_printf(string, "Removed %s because of missing type:", label);
			tag = "removed-header";
			break;
		}
	case POLDIFF_FORM_MODIFIED:{
			g_string_printf(string, "Modified %s:", label);
			tag = "modified-header";
			break;
		}
	default:{
			assert(0);
			tag = NULL;
		}
	}
	g_string_append_printf(string, " %zd\n", result_item_get_num_differences(item, form));
	gtk_text_buffer_insert_with_tags_by_name(tb, &iter, string->str, -1, tag, NULL);
	g_string_free(string, TRUE);
}

void result_item_print_linenos(GtkTextBuffer * tb, GtkTextIter * iter,
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

void result_item_print_modified_range(result_item_t * item, const poldiff_range_t * range, GtkTextBuffer * tb, GtkTextIter * iter)
{
	poldiff_t *diff = result_item_get_diff(item);
	char *orig_s = poldiff_range_to_string_brief(diff, range);
	char *next_s = orig_s;
	GString *string = g_string_new("");

	/* first line should always be printed with normal font */
	char *s = strsep(&next_s, "\n");
	result_item_print_string(tb, iter, s, 1);
	gtk_text_buffer_insert(tb, iter, "\n", -1);

	/* if the next line is minimum category set differences then
	 * display it */
	if (strncmp(next_s, "     minimum categories:", strlen("     minimum categories:")) == 0) {
		s = strsep(&next_s, "\n");
		result_item_print_string_inline(tb, iter, s, 1);
	}
	/* all subsequent lines are printed as normal (yes, this
	 * discards lines from poldiff_range_to_string_brief() */
	free(orig_s);
	apol_vector_t *levels = poldiff_range_get_levels(range);
	size_t i;
	for (i = 0; i < apol_vector_get_size(levels); i++) {
		poldiff_level_t *l = apol_vector_get_element(levels, i);
		s = poldiff_level_to_string_brief(diff, l);
		g_string_printf(string, "     %s", s);
		if (poldiff_level_get_form(l) != POLDIFF_FORM_MODIFIED) {
			result_item_print_string(tb, iter, string->str, 1);
		} else {
			result_item_print_string_inline(tb, iter, string->str, 1);
		}
		free(s);
	}
	g_string_free(string, TRUE);
}
