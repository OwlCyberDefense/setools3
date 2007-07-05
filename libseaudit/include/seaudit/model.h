/**
 *  @file
 *
 *  Public interface to a seaudit_model.  This represents a subset of
 *  log messages from one or more seaudit_log, where the subset is
 *  defined by a finite set of seaudit_filter and sorted by some
 *  criterion or criteria.
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

#ifndef SEAUDIT_MODEL_H
#define SEAUDIT_MODEL_H

#ifdef  __cplusplus
extern "C"
{
#endif

#include "filter.h"
#include "log.h"
#include "message.h"
#include "sort.h"

#include <stdlib.h>

	typedef struct seaudit_model seaudit_model_t;

/**
 * Create a seaudit_model based upon the messages from some particular
 * seaudit_log.  The model will be initialized with the default filter
 * (i.e., accept all of the messages from the log).
 *
 * @param name Name for the model; the string will be duplicated.  If
 * NULL then the model will be assigned a non-unique default name.
 * @param log Initial log for this model to watch.  If NULL then do
 * not watch any log files.
 *
 * @return An initialized model, or NULL upon error.  The caller must
 * call seaudit_model_destroy() afterwards.
 */
	extern seaudit_model_t *seaudit_model_create(const char *name, seaudit_log_t * log);

/**
 * Create a new seaudit_model object, initialized with the data from
 * an existing model.  This will do a deep copy of the original model.
 * The new model will be watch the same logs that the original model
 * was watching.
 *
 * @param model Model to clone.
 *
 * @return A cloned model, or NULL upon error.  The caller must call
 * seaudit_model_destroy() afterwards.
 */
	extern seaudit_model_t *seaudit_model_create_from_model(const seaudit_model_t * model);

/**
 * Create and return a model initialized from the contents of a XML
 * configuration file.  This will also load filters into the model.
 * The model will not be associated with any logs; for that call
 * seaudit_model_append_log().
 *
 * @param filename File containing model data.
 *
 * @return An initialized model, or NULL upon error.  The caller must
 * call seaudit_model_destroy() afterwards.
 *
 * @see seaudit_model_save_to_file()
 */
	extern seaudit_model_t *seaudit_model_create_from_file(const char *filename);

/**
 * Destroy the referenced seadit_model object.
 *
 * @param model Model to destroy.  The pointer will be set to NULL
 * afterwards.  (If pointer is already NULL then do nothing.)
 */
	extern void seaudit_model_destroy(seaudit_model_t ** model);

/**
 * Save to disk, in XML format, the given model's values.  This
 * includes the filters contained within the model as well.  Note that
 * this does not save the messages within the model nor the associated
 * logs.
 *
 * @param model Model to save.
 * @param filename Name of the file to write.  If the file already
 * exists it will be overwritten.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see seaudit_model_create_from_file()
 */
	extern int seaudit_model_save_to_file(const seaudit_model_t * model, const char *filename);

/**
 * Get the name of this model.
 *
 * @param model Model whose name to get.
 *
 * @return Name of the model, or NULL upon error.  Do not modify this
 * string.
 */
	extern const char *seaudit_model_get_name(const seaudit_model_t * model);

/**
 * Set the name of this model, overwriting any previous name.
 *
 * @param model Model whose name to set.
 * @param name New name for the model; the string will be duplicated.
 * If NULL then the model will be assigned a non-unique default name.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_model_set_name(seaudit_model_t * model, const char *name);

/**
 * Have the given model start watching the given log file, in addition
 * to any other log files the model was watching.
 *
 * @param model Model to modify.
 * @param log Additional log file to watch.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_model_append_log(seaudit_model_t * model, seaudit_log_t * log);

/**
 * Append a filter to a model.  The next time the model's messages are
 * retrieved only those messages that match this filter will be
 * returned.  Multiple filters may be applied to a model.  Upon
 * success, the model takes ownership of the filter.
 *
 * @param model Model to modify.
 * @param filter Additional filter to be applied.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_model_append_filter(seaudit_model_t * model, seaudit_filter_t * filter);

/**
 * Get the list of filters for a model.  Whenever a filter is modified
 * the model will be recomputed.  Note: to remove a filter from the
 * model use seaudit_model_remove_filter().
 *
 * @param model Model containing filters.
 *
 * @return Vector of seaudit_filter objects, or NULL upon error.  Note
 * that the vector my be empty.  Do not destroy or otherwise modify
 * this vector.  (It is safe to manipulate the elements within the
 * vector.)
 */
	extern const apol_vector_t *seaudit_model_get_filters(const seaudit_model_t * model);

/**
 * Remove a filter from a model.  The given parameter must match one
 * of the filters stored within the model; call
 * seaudit_model_get_filters() to get a list of the model's filters.
 *
 * @param model Model to modify.
 * @param filter Filter to remove.  Upon success the pointer becomes
 * invalid.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_model_remove_filter(seaudit_model_t * model, seaudit_filter_t * filter);

/**
 * Set a model to accept a message if all filters are met (default
 * behavior) or if any filter is met.  Note that is independent from
 * the setting given to seaudit_model_set_filter_visible().
 *
 * @param model Model to modify.
 * @param match Matching behavior if model has multiple filters.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_model_set_filter_match(seaudit_model_t * model, seaudit_filter_match_e match);

/**
 * Get the current filter match value for a model.
 *
 * @param model Model containing filter match value.
 *
 * @return One of SEAUDIT_FILTER_MATCH_ALL or SEAUDIT_FILTER_MATCH_ANY.
 */
	extern seaudit_filter_match_e seaudit_model_get_filter_match(const seaudit_model_t * model);

/**
 * Set a model to either show (default behavior) or hide messages
 * accepted by the filters.  Note that is independent from the setting
 * given to seaudit_model_set_filter_match().
 *
 * @param model Model to modify.
 * @param visible Messages to show if model has any filters.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_model_set_filter_visible(seaudit_model_t * model, seaudit_filter_visible_e visible);

/**
 * Get the current filter visibility value for a model.
 *
 * @param model Model containing filter visibility value.
 *
 * @return One of SEAUDIT_FILTER_VISIBLE_SHOW or
 * SEAUDIT_FILTER_VISIBLE_HIDE.
 */
	extern seaudit_filter_visible_e seaudit_model_get_filter_visible(const seaudit_model_t * model);

/**
 * Append a sort criterion to a model.  The next time the model's
 * messages are retrieved they will be sorted by this criterion.  If
 * the model already has sort criteria, they will have a higher
 * priority than this new criterion.  Upon success, the model takes
 * ownership of the sort object
 *
 * @param model Model to modify.
 * @param sort Additional sort criterion.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_model_append_sort(seaudit_model_t * model, seaudit_sort_t * sort);

/**
 * Remove all sort criteria from this model.  The next time the
 * model's messages are retrieved they will be in the same order as
 * provided by the model's log(s).
 *
 * @param model Model to modify.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_model_clear_sorts(seaudit_model_t * model);

/**
 * Return a value indicating if this model has changed since the last
 * time seaudit_model_get_messages() was called.  Note that upon a
 * non-zero return value, the vector returned by
 * seaudit_model_get_messages() might contain the same messages.  For
 * example, the user could have removed all sorts but then re-inserted
 * them in the same order.
 *
 * @param model Model to check.
 *
 * @return 0 if the model is unchanged, non-zero if it may have
 * changed.
 */
	extern int seaudit_model_is_changed(const seaudit_model_t * model);

/**
 * Return a sorted list of messages associated with this model.  This
 * will cause the model to recalculate, as necessary, all messages
 * according to its filters and then sort them.
 *
 * @param log Log to which report error messages.
 * @param model Model containing messages.
 *
 * @return A newly allocated vector of seaudit_message_t, pre-filtered
 * and pre-sorted, or NULL upon error.  The caller is responsible for
 * calling apol_vector_destroy() upon this value.
 */
	extern apol_vector_t *seaudit_model_get_messages(const seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return a sorted list of malformed messages associated with this
 * model.  This is the union of all malformed messages from the
 * model's logs.  This will cause the model to recalculate, as
 * necessary, all messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model containing malformed messages.
 *
 * @return A newly allocated vector of strings, or NULL upon error.
 * Treat the contents of the vector as const char *.  The caller is
 * responsible for calling apol_vector_destroy() upon this value.
 */
	extern apol_vector_t *seaudit_model_get_malformed_messages(const seaudit_log_t * log, seaudit_model_t * model);

/**
 * Hide a message from a model such that the next time
 * seaudit_model_get_messages() is called, the given message will not
 * be returned within the vector.
 *
 * @param model Model containing message to hide.
 * @param message Message to be marked hidden.  If NULL, then do
 * nothing.  It is safe to make duplicate calls to this function with
 * the same message.
 */
	extern void seaudit_model_hide_message(seaudit_model_t * model, const seaudit_message_t * message);

/**
 * Return the number of avc allow messages currently within the model.
 * This will cause the model to recalculate, as necessary, all
 * messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model to get statistics.
 *
 * @return Number of allow messages in the model.  This could be zero.
 */
	extern size_t seaudit_model_get_num_allows(const seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return the number of avc deny messages currently within the model.
 * This will cause the model to recalculate, as necessary, all
 * messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model to get statistics.
 *
 * @return Number of deny messages in the model.  This could be zero.
 */
	extern size_t seaudit_model_get_num_denies(const seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return the number of boolean change messages currently within the
 * model.  This will cause the model to recalculate, as necessary, all
 * messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model to get statistics.
 *
 * @return Number of boolean messages in the model.  This could be
 * zero.
 */
	extern size_t seaudit_model_get_num_bools(const seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return the number of load messages currently within the model.
 * This will cause the model to recalculate, as necessary, all
 * messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model to get statistics.
 *
 * @return Number of load messages in the model.  This could be zero.
 */
	extern size_t seaudit_model_get_num_loads(const seaudit_log_t * log, seaudit_model_t * model);

#ifdef  __cplusplus
}
#endif

#endif
