/**
 *  @file
 *  Header for rendering a result item.
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
#ifndef RESULT_ITEM_RENDER_H
#define RESULT_ITEM_RENDER_H

#include "result_item.h"

/**
 * Show a single diff item string.  This will add the appropriate
 * color tags based upon the item's first non-space character.
 */
void result_item_print_string(GtkTextBuffer * tb, GtkTextIter * iter, const char *s, unsigned int indent_level);

/**
 * Print a string to a text buffer.  Note that this differs from the
 * more general results_print_string() because there are inline '+'
 * and '-' markers.
 */
void result_item_print_string_inline(GtkTextBuffer * tb, GtkTextIter * iter, const char *s, unsigned int indent_level);

/**
 * Show the results for a single AV rule diff string.
 */
void result_item_print_string_avrule(GtkTextBuffer * tb, GtkTextIter * iter, const char *s, unsigned int indent_level);

/**
 * Show the results for non-rules diff components.
 */
void result_item_print_diff(result_item_t * item, GtkTextBuffer * tb, poldiff_form_e form);

/**
 * Show the results for rules diff components.
 */
void result_item_print_rule_diff(result_item_t * item, GtkTextBuffer * tb, poldiff_form_e form);

/**
 * Show a summary of the diff for a particular policy component.
 */
void result_item_print_summary(result_item_t * item, GtkTextBuffer * tb);

/**
 * Show a common header when printing a policy component diff.
 */
void result_item_print_header(result_item_t * item, GtkTextBuffer * tb, poldiff_form_e form);

/**
 * Given a vector of unsigned long integers, write to the text buffer
 * those line numbers using the given tag.
 */
void result_item_print_linenos(GtkTextBuffer * tb, GtkTextIter * iter,
			       const gchar * prefix, const apol_vector_t * linenos, const gchar * tag, GString * string);

/**
 * Show the results for a modified range.
 */
void result_item_print_modified_range(result_item_t * item, const poldiff_range_t * range, GtkTextBuffer * tb, GtkTextIter * iter);

#endif
