/**
 *  @file
 *  Header for showing a diff result for a single component.
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
#ifndef RESULT_ITEM_H
#define RESULT_ITEM_H

typedef struct result_item result_item_t;

#include "results.h"

#include <gtk/gtk.h>
#include <poldiff/poldiff.h>
#include <poldiff/item_record.h>

/* constructors for various result items */

result_item_t *result_item_create_classes(GtkTextTagTable * table);
result_item_t *result_item_create_commons(GtkTextTagTable * table);
result_item_t *result_item_create_levels(GtkTextTagTable * table);
result_item_t *result_item_create_categories(GtkTextTagTable * table);
result_item_t *result_item_create_types(GtkTextTagTable * table);
result_item_t *result_item_create_attributes(GtkTextTagTable * table);
result_item_t *result_item_create_roles(GtkTextTagTable * table);
result_item_t *result_item_create_users(GtkTextTagTable * table);
result_item_t *result_item_create_booleans(GtkTextTagTable * table);

result_item_t *result_item_create_avrules_allow(GtkTextTagTable * table);
result_item_t *result_item_create_avrules_neverallow(GtkTextTagTable * table);
result_item_t *result_item_create_avrules_dontaudit(GtkTextTagTable * table);
result_item_t *result_item_create_avrules_auditallow(GtkTextTagTable * table);

result_item_t *result_item_create_terules_member(GtkTextTagTable * table);
result_item_t *result_item_create_terules_change(GtkTextTagTable * table);
result_item_t *result_item_create_terules_trans(GtkTextTagTable * table);

result_item_t *result_item_create_role_allows(GtkTextTagTable * table);
result_item_t *result_item_create_role_trans(GtkTextTagTable * table);
result_item_t *result_item_create_range_trans(GtkTextTagTable * table);

/**
 * Deallocate all space associated with a result item, including the
 * pointer itself.  Does nothing if the pointer is already set to NULL.
 *
 * @param item Reference to the item to destroy.  Afterwards it will
 * be set to NULL.
 */
void result_item_destroy(result_item_t ** item);

/**
 * Get the title case label for this result item.  The string will be
 * used for printing.
 *
 * @param item Result item to query.
 *
 * @return Name of this result item.
 */
const char *result_item_get_label(const result_item_t * item);

/**
 * Function to update a result item whenever the policies are changed.
 * The result item can then configure its own rendering routine.
 *
 * @param item Result item to modify based upon the policies.
 * @param orig_pol Original policy to diff.
 * @param mod_pol Modified policy to diff.
 */
void result_item_policy_changed(result_item_t * item, apol_policy_t * orig_pol, apol_policy_t * mod_pol);

/**
 * Function to update a result item whenever the user (re)runs the
 * diff.  This will clear the result item's cache as necessary.
 *
 * @param item Result item to update based upon the poldiff object.
 * @param diff Poldiff item that was (re)run.
 * @param incremental If non-zero, the diff was incrementally run;
 * existing results should not be destroyed.
 */
void result_item_poldiff_run(result_item_t * item, poldiff_t * diff, int incremental);

/**
 * Return a text buffer that contains the rendered results for a
 * particular policy component's form.  This will re-render the buffer
 * as necessary.
 *
 * @param item Result item whose display to obtain.
 * @param form Form to display, or POLDIFF_FORM_NONE if just the
 * summary is requested.
 *
 * @return A text buffer containing the results.
 */
GtkTextBuffer *result_item_get_buffer(result_item_t * item, poldiff_form_e form);

/**
 * If it will take a "significant" amount of time (where "significant"
 * is some arbitrary amount) to render a buffer then sediffx will
 * display a progress dialog while working.  This function returns
 * non-zero if it will be significantly long, 0 or not.  This function
 * will be called prior to result_item_get_buffer().
 *
 * @param item Result item to query.
 * @param form Form that will be displayed, or POLDIFF_FORM_NONE if
 * just the summary is requested.
 *
 * @return Non-zero if a progress dialog should be displayed, zero if
 * not.
 */
int result_item_is_render_slow(result_item_t * item, poldiff_form_e form);

/**
 * Determine if a result item is capable of being run according to the
 * given policies.  For example, for binary policies prior to version
 * 20, it is not possible to have modified types.  Note that this does
 * not necessarily mean the item has been run yet, for libpoldiff
 * supports incremental diffing.
 *
 * @param item Result item to query.
 * @param form Particular form to check if it is capable of being run
 * or not.
 *
 * @return Non-zero if the result item could be run, zero if not.
 */
int result_item_is_supported(const result_item_t * item);

/**
 * Get a list of forms that were actually run.  The result is an array
 * of 5 integers, each corresponding to the five poldiff forms (added,
 * add by type, removed, remove by type, modified).  For each form,
 * the possible values are:
 *
 * <dl>
 * <dt>less than zero
 *   <dd>form is not supported
 * <dt>zero
 *   <dd>form was not run
 * <dt>greater than zero
 *   <dd>form was run
 * </dl>
 *
 * @param item Result item to query.
 * @param diff Diff structure that was run.
 * @param forms Array into which write results.
 */
void result_item_get_forms(result_item_t * item, int forms[5]);

/**
 * Get the number of differences for a particular form.
 *
 * @param item Result item to query.
 * @param form Difference form to query.
 *
 * @return Number of differences, or zero if the result item is not
 * support or was not run.
 */
size_t result_item_get_num_differences(result_item_t * item, poldiff_form_e form);

/**
 * Get the current sorting algorithm and sort direction for the given
 * result item.
 *
 * @param item Result item to query.
 * @param form Form whose sort algorithm and direction to get.
 * @param sort Reference to where to write the current sorting algorithm.
 * @param dir Reference to where to write the current sorting direction.
 *
 * @return Non-zero if the result item supports sorting, zero if it
 * does not.
 */
int result_item_get_current_sort(result_item_t * item, poldiff_form_e form, results_sort_e * sort, results_sort_dir_e * dir);

/**
 * Set the current sorting algorithm and sort direction for the given
 * result item.  The next time result_item_get_buffer() is called the
 * contents of the buffer will be updated as necessary.  (This
 * function does not update the buffer.)
 *
 * @param item Result item to modify.
 * @param form Form whose sort algorithm and direction to set.
 * @param sort New sorting algorithm.
 * @param dir New sorting direction.
 */
void result_item_set_current_sort(result_item_t * item, poldiff_form_e form, results_sort_e sort, results_sort_dir_e dir);

/**
 * Tell the result item to store a particular line offset for the
 * given form.
 *
 * @param item Result item to modify.
 * @param form Particular form's line number to store.
 * @param offset Line number to store.
 */
void result_item_save_current_line(result_item_t * item, poldiff_form_e form, gint offset);

/**
 * Return the saved line number for a result item's particular form.
 * If a line number has not yet been saved then return 0.
 *
 * @param item Result item to query.
 * @param form Form whose line number to retrieve.
 *
 * @return The stored line number.
 */
gint result_item_get_current_line(result_item_t * item, poldiff_form_e form);

/**
 * Callback invoked by results_t whenever a inlink-link tag was
 * clicked.  This will pop a menu that will let the user jump to the
 * exact line in the policy that contains that string.
 *
 * @param item Result item upon which the event occurred.
 * @param top Toplevel containing policy sources.
 * @param container Containing GTK widget within which the result item
 * is being displayed.
 * @param event GdkEvent that gives the button used to click on the
 * inlink link, or NULL if the event was generated by hitting the Menu
 * button.
 * @param form Form upon which the event occurred.
 * @param line_num Line number of the text buffer where the clicked occurred.
 * @param s The string that was clicked.
 */
void result_item_inline_link_event(result_item_t * item, toplevel_t * top, GtkWidget * container, GdkEventButton * event,
				   poldiff_form_e form, int line_num, const char *s);

/* these next three functions exist because C has no concept of
 * 'friend' like in C++; result_item_render needs access to three
 * fields within the result_item. */
poldiff_t *result_item_get_diff(result_item_t * item);
const apol_vector_t *result_item_get_vector(result_item_t * item);
poldiff_form_e result_item_get_form(result_item_t * item, void *elem);
char *result_item_get_string(result_item_t * item, void *elem);

#endif
