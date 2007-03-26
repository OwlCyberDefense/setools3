/**
 *  @file
 *  Implementation of seaudit_model_t.
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

#include "seaudit_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/uri.h>

#define DEFAULT_MODEL_NAME "Untitled"

struct seaudit_model
{
	char *name;
	/** vector of seaudit_log_t pointers; this model will get
	 * messages from these logs */
	apol_vector_t *logs;
	/** vector of seaudit_message_t pointers; these point into
	 * messages from the watched logs (only valid if dirty == 0) */
	apol_vector_t *messages;
	/** vector of char * pointers; these point into malformed
	 * messages from the watched logs (only valid if dirty == 0) */
	apol_vector_t *malformed_messages;
	/** vector of seaudit_filter_t */
	apol_vector_t *filters;
	/** if more than one filter is being applied, then accept
         * messages if any match or if all match */
	seaudit_filter_match_e match;
	/** if a filter is being applied, then either show/hide
         * messages selected by filter */
	seaudit_filter_visible_e visible;
	/** vector of seaudit_sort_t, order from highest priority to lowest */
	apol_vector_t *sorts;
	/** number of allow messages in the model (only valid if dirty == 0) */
	size_t num_allows;
	/** number of deny messages in the model (only valid if dirty == 0) */
	size_t num_denies;
	/** number of boolean changes in the model (only valid if dirty == 0) */
	size_t num_bools;
	/** number of policy loads in the model (only valid if dirty == 0) */
	size_t num_loads;
	/** non-zero whenever this model needs to be recalculated */
	int dirty;
};

/**
 * Apply all of the model's filters to the message.
 *
 * @param model Model containing filters to apply.
 * @param m Message to check.
 *
 * @return Non-zero if the message is accepted by the filters, 0 if not.
 */
static int model_filter_message(seaudit_model_t * model, const seaudit_message_t * m)
{
	size_t i;
	int compval, filters_passed = 0;
	if (apol_vector_get_size(model->filters) == 0) {
		return 1;
	}
	for (i = 0; i < apol_vector_get_size(model->filters); i++) {
		seaudit_filter_t *f = apol_vector_get_element(model->filters, i);
		compval = filter_is_accepted(f, m);
		if (compval) {
			if (model->match == SEAUDIT_FILTER_MATCH_ANY) {
				return 1;
			}
			filters_passed++;
		} else {
			if (model->match == SEAUDIT_FILTER_MATCH_ALL) {
				return 0;
			}
		}
	}
	if (model->match == SEAUDIT_FILTER_MATCH_ANY) {
		/* if got here, then no filters were met */
		return 0;
	}
	/* if got here, then all criteria were met */
	if (filters_passed) {
		return 1;
	}
	return 0;
}

/**
 * Callback for sorting the model's messages vector.
 *
 * @param a First message to compare.
 * @param b Second message to compare.
 * @param data Pointer to the model being sorted.
 *
 * @return 0 if the messages are equivalent, < 0 if a is first, > 0 if
 * b is first.
 */
static int message_comp(const void *a, const void *b, void *data)
{
	const seaudit_message_t *m1 = a;
	const seaudit_message_t *m2 = b;
	seaudit_model_t *model = data;
	size_t i;
	seaudit_sort_t *s;
	int compval, s1, s2;
	for (i = 0; i < apol_vector_get_size(model->sorts); i++) {
		s = apol_vector_get_element(model->sorts, i);
		s1 = sort_is_supported(s, m1);
		s2 = sort_is_supported(s, m2);
		if (!s1 && !s2) {
			continue;
		}
		if (!s2) {
			return -1;
		}
		if (!s1) {
			return 1;
		}
		if ((compval = sort_comp(s, m1, m2)) != 0) {
			return compval;
		}
	}
	return 0;
}

/**
 * Sort the model's messages.  Create two temporary vectors.  The
 * first holds messages that are sortable, according to the list of
 * sort objects.  Sort them in their priority order.  The second
 * vector holds messages that are not sortable; append those messages
 * to the end of the first (now sorted) vector.
 *
 * @param log Error handling log.
 * @param model Model to sort.
 *
 * @return 0 on successful sort, < 0 on error.
 */
static int model_sort(seaudit_log_t * log, seaudit_model_t * model)
{
	size_t i, j, num_messages = apol_vector_get_size(model->messages);
	apol_vector_t *sup = NULL, *unsup = NULL;
	seaudit_message_t *m;
	seaudit_sort_t *s;
	int supported = 0, retval = -1, error = 0;
	if (apol_vector_get_size(model->sorts) == 0) {
		retval = 0;
		goto cleanup;
	}

	if ((sup = apol_vector_create_with_capacity(num_messages, NULL)) == NULL ||
	    (unsup = apol_vector_create_with_capacity(num_messages, NULL)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < num_messages; i++) {
		m = apol_vector_get_element(model->messages, i);
		supported = 0;
		for (j = 0; j < apol_vector_get_size(model->sorts); j++) {
			s = apol_vector_get_element(model->sorts, j);
			if ((supported = sort_is_supported(s, m)) != 0) {
				break;
			}
		}
		if ((supported && apol_vector_append(sup, m) < 0) || (!supported && apol_vector_append(unsup, m) < 0)) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
	}
	apol_vector_sort(sup, message_comp, model);
	if (apol_vector_cat(sup, unsup) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	apol_vector_destroy(&model->messages);
	model->messages = sup;
	sup = NULL;
	retval = 0;
      cleanup:
	apol_vector_destroy(&sup);
	apol_vector_destroy(&unsup);
	if (retval != 0) {
		errno = error;
	}
	return retval;
}

/**
 * Iterate through the model's messages and recalculate the number of
 * each type of message is stored within.
 *
 * @param model Model to recalculate.
 */
static void model_recalc_stats(seaudit_model_t * model)
{
	size_t i;
	seaudit_message_t *msg;
	seaudit_message_type_e type;
	void *v;
	seaudit_avc_message_t *avc;
	model->num_allows = model->num_denies = model->num_bools = model->num_loads = 0;
	for (i = 0; i < apol_vector_get_size(model->messages); i++) {
		msg = apol_vector_get_element(model->messages, i);
		v = seaudit_message_get_data(msg, &type);
		if (type == SEAUDIT_MESSAGE_TYPE_AVC) {
			avc = (seaudit_avc_message_t *) v;
			if (avc->msg == SEAUDIT_AVC_DENIED) {
				model->num_denies++;
			} else if (avc->msg == SEAUDIT_AVC_GRANTED) {
				model->num_allows++;
			}
		} else if (type == SEAUDIT_MESSAGE_TYPE_BOOL) {
			model->num_bools++;
		} else if (type == SEAUDIT_MESSAGE_TYPE_LOAD) {
			model->num_loads++;
		}
	}
}

/**
 * Recalculate all of the messages associated with a particular model,
 * based upon that model's criteria.  If the model is marked as not
 * dirty then do nothing and return success.
 *
 * @param log Log to which report error messages.
 * @param model Model whose messages list to refresh.
 *
 * @return 0 on success, < 0 on error.
 */
static int model_refresh(seaudit_log_t * log, seaudit_model_t * model)
{
	size_t i, j;
	seaudit_log_t *l;
	apol_vector_t *v;
	seaudit_message_t *message;
	int error, filter_match;

	if (!model->dirty) {
		return 0;
	}
	apol_vector_destroy(&model->messages);
	apol_vector_destroy(&model->malformed_messages);
	if ((model->messages = apol_vector_create(NULL)) == NULL || (model->malformed_messages = apol_vector_create(NULL)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(model->logs); i++) {
		l = apol_vector_get_element(model->logs, i);
		v = log_get_messages(l);
		for (j = 0; j < apol_vector_get_size(v); j++) {
			message = apol_vector_get_element(v, j);
			filter_match = model_filter_message(model, message);
			if (((filter_match && model->visible == SEAUDIT_FILTER_VISIBLE_SHOW) ||
			     (!filter_match && model->visible == SEAUDIT_FILTER_VISIBLE_HIDE)) &&
			    apol_vector_append(model->messages, message) < 0) {
				error = errno;
				ERR(log, "%s", strerror(error));
				errno = error;
				return -1;
			}
		}
		v = log_get_malformed_messages(l);
		if (apol_vector_cat(model->malformed_messages, v) < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}
	if (model_sort(log, model) < 0) {
		return -1;
	}
	model_recalc_stats(model);
	model->dirty = 0;
	return 0;
}

/**
 * Callback invoked when free()ing a vector of filters.
 *
 * @param v Filter object to free.
 */
static void filter_free(void *v)
{
	seaudit_filter_t *f = v;
	seaudit_filter_destroy(&f);
}

/**
 * Callback invoked when free()ing a vector of sort objects.
 *
 * @param v Sort object to free.
 */
static void sort_free(void *v)
{
	seaudit_sort_t *sort = v;
	seaudit_sort_destroy(&sort);
}

seaudit_model_t *seaudit_model_create(const char *name, seaudit_log_t * log)
{
	seaudit_model_t *m = NULL;
	int error;
	if ((m = calloc(1, sizeof(*m))) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	if (name == NULL) {
		name = DEFAULT_MODEL_NAME;
	}
	if ((m->name = strdup(name)) == NULL ||
	    (m->logs = apol_vector_create_with_capacity(1, NULL)) == NULL ||
	    (m->filters = apol_vector_create_with_capacity(1, filter_free)) == NULL ||
	    (m->sorts = apol_vector_create_with_capacity(1, sort_free)) == NULL) {
		error = errno;
		seaudit_model_destroy(&m);
		ERR(log, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	if (log != NULL) {
		if (apol_vector_append(m->logs, log) < 0 || log_append_model(log, m)) {
			error = errno;
			seaudit_model_destroy(&m);
			ERR(log, "%s", strerror(error));
			errno = error;
			return NULL;
		}
	}
	m->dirty = 1;
	return m;
}

static void *model_filter_dup(const void *elem, void *data)
{
	const seaudit_filter_t *filter = elem;
	seaudit_model_t *model = data;
	seaudit_filter_t *f;
	if ((f = seaudit_filter_create_from_filter(filter)) == NULL) {
		return NULL;
	}
	filter_set_model(f, model);
	return f;
}

static void *model_sort_dup(const void *elem, void *data __attribute__ ((unused)))
{
	const seaudit_sort_t *sort = elem;
	seaudit_model_t *model = data;
	seaudit_sort_t *s;
	if ((s = sort_create_from_sort(sort)) == NULL) {
		return NULL;
	}
	if (seaudit_model_append_sort(model, s) < 0) {
		seaudit_sort_destroy(&s);
		return NULL;
	}
	return s;
}

seaudit_model_t *seaudit_model_create_from_model(const seaudit_model_t * model)
{
	seaudit_model_t *m = NULL;
	int error = 0;
	size_t i;
	const char *name;

	if (model == NULL) {
		error = EINVAL;
		goto cleanup;
	}
	if ((m = calloc(1, sizeof(*m))) == NULL) {
		error = errno;
		goto cleanup;
	}
	if ((name = model->name) == NULL) {
		name = "Untitled";
	}
	if ((m->name = strdup(name)) == NULL) {
		error = errno;
		goto cleanup;
	}
	m->dirty = 1;
	if ((m->logs = apol_vector_create_from_vector(model->logs, NULL, NULL)) == NULL) {
		error = errno;
		goto cleanup;
	}
	if ((m->filters = apol_vector_create_from_vector(model->filters, model_filter_dup, (void *)m)) == NULL) {
		error = errno;
		goto cleanup;
	}
	if ((m->sorts = apol_vector_create_from_vector(model->sorts, model_sort_dup, (void *)m)) == NULL) {
		error = errno;
		goto cleanup;
	}
	m->match = model->match;
	m->visible = model->visible;
	/* link this new model to the old model's logs */
	for (i = 0; i < apol_vector_get_size(m->logs); i++) {
		seaudit_log_t *log = apol_vector_get_element(m->logs, i);
		if (log_append_model(log, m) < 0) {
			error = errno;
			goto cleanup;
		}
	}
      cleanup:
	if (error != 0) {
		seaudit_model_destroy(&m);
		errno = error;
		return NULL;
	}
	return m;
}

seaudit_model_t *seaudit_model_create_from_file(const char *filename)
{
	struct filter_parse_state state;
	int retval, error;
	seaudit_model_t *m;
	memset(&state, 0, sizeof(state));
	if ((state.filters = apol_vector_create(filter_free)) == NULL) {
		return NULL;
	}
	retval = filter_parse_xml(&state, filename);
	if (retval < 0) {
		error = errno;
		free(state.view_name);
		apol_vector_destroy(&state.filters);
		errno = errno;
		return NULL;
	}
	if ((m = seaudit_model_create(state.view_name, NULL)) == NULL) {
		error = errno;
		free(state.view_name);
		apol_vector_destroy(&state.filters);
		errno = error;
		return NULL;
	}
	free(state.view_name);
	apol_vector_destroy(&m->filters);
	m->filters = state.filters;
	state.filters = NULL;
	seaudit_model_set_filter_match(m, state.view_match);
	seaudit_model_set_filter_visible(m, state.view_visible);
	return m;
}

void seaudit_model_destroy(seaudit_model_t ** model)
{
	size_t i;
	if (model == NULL || *model == NULL) {
		return;
	}
	for (i = 0; i < apol_vector_get_size((*model)->logs); i++) {
		seaudit_log_t *l = apol_vector_get_element((*model)->logs, i);
		log_remove_model(l, *model);
	}
	free((*model)->name);
	apol_vector_destroy(&(*model)->logs);
	apol_vector_destroy(&(*model)->filters);
	apol_vector_destroy(&(*model)->sorts);
	apol_vector_destroy(&(*model)->messages);
	apol_vector_destroy(&(*model)->malformed_messages);
	free(*model);
	*model = NULL;
}

int seaudit_model_save_to_file(seaudit_model_t * model, const char *filename)
{
	FILE *file;
	const char *XML_VER = "<?xml version=\"1.0\"?>\n";
	seaudit_filter_t *filter;
	size_t i;

	if (model == NULL || filename == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((file = fopen(filename, "w")) == NULL) {
		return -1;
	}
	fprintf(file, XML_VER);
	fprintf(file, "<view xmlns=\"http://oss.tresys.com/projects/setools/seaudit-%s/\" name=\"%s\" match=\"%s\" show=\"%s\">\n",
		FILTER_FILE_FORMAT_VERSION, model->name,
		model->match == SEAUDIT_FILTER_MATCH_ALL ? "all" : "any",
		model->visible == SEAUDIT_FILTER_VISIBLE_SHOW ? "true" : "false");
	for (i = 0; i < apol_vector_get_size(model->filters); i++) {
		filter = apol_vector_get_element(model->filters, i);
		filter_append_to_file(filter, file, 1);
	}
	fprintf(file, "</view>\n");
	fclose(file);
	return 0;
}

char *seaudit_model_get_name(seaudit_model_t * model)
{
	if (model == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return model->name;
}

int seaudit_model_set_name(seaudit_model_t * model, const char *name)
{
	char *s;
	if (model == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (name == NULL) {
		name = DEFAULT_MODEL_NAME;
	}
	if ((s = strdup(name)) == NULL) {
		return -1;
	}
	free(model->name);
	model->name = s;
	return 0;
}

int seaudit_model_append_log(seaudit_model_t * model, seaudit_log_t * log)
{
	if (model == NULL || log == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (apol_vector_append(model->logs, log) < 0 || log_append_model(log, model) < 0) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	model->dirty = 1;
	return 0;
}

int seaudit_model_append_filter(seaudit_model_t * model, seaudit_filter_t * filter)
{
	if (model == NULL || filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (apol_vector_append(model->filters, filter) < 0) {
		return -1;
	}
	filter_set_model(filter, model);
	model->dirty = 1;
	return 0;
}

apol_vector_t *seaudit_model_get_filters(seaudit_model_t * model)
{
	if (model == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return model->filters;
}

int seaudit_model_remove_filter(seaudit_model_t * model, seaudit_filter_t * filter)
{
	size_t i;
	if (model == NULL || filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (apol_vector_get_index(model->filters, filter, NULL, NULL, &i) < 0) {
		errno = EINVAL;
		return -1;
	}
	seaudit_filter_destroy(&filter);
	apol_vector_remove(model->filters, i);
	model->dirty = 1;
	return 0;
}

int seaudit_model_set_filter_match(seaudit_model_t * model, seaudit_filter_match_e match)
{
	if (model == NULL) {
		errno = EINVAL;
		return -1;
	}
	model->match = match;
	model->dirty = 1;
	return 0;
}

seaudit_filter_match_e seaudit_model_get_filter_match(seaudit_model_t * model)
{
	if (model == NULL) {
		errno = EINVAL;
		return SEAUDIT_FILTER_MATCH_ALL;
	}
	return model->match;
}

int seaudit_model_set_filter_visible(seaudit_model_t * model, seaudit_filter_visible_e visible)
{
	if (model == NULL) {
		errno = EINVAL;
		return -1;
	}
	model->visible = visible;
	model->dirty = 1;
	return 0;
}

seaudit_filter_visible_e seaudit_model_get_filter_visible(seaudit_model_t * model)
{
	if (model == NULL) {
		errno = EINVAL;
		return SEAUDIT_FILTER_VISIBLE_SHOW;
	}
	return model->visible;
}

int seaudit_model_append_sort(seaudit_model_t * model, seaudit_sort_t * sort)
{
	if (model == NULL || sort == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (apol_vector_append(model->sorts, sort) < 0) {
		return -1;
	}
	model->dirty = 1;
	return 0;
}

int seaudit_model_clear_sorts(seaudit_model_t * model)
{
	if (model == NULL) {
		errno = EINVAL;
		return -1;
	}
	apol_vector_destroy(&model->sorts);
	if ((model->sorts = apol_vector_create_with_capacity(1, sort_free)) == NULL) {
		return -1;
	}
	model->dirty = 1;
	return 0;
}

int seaudit_model_is_changed(seaudit_model_t * model)
{
	if (model == NULL) {
		errno = EINVAL;
		return -1;
	}
	return model->dirty;
}

apol_vector_t *seaudit_model_get_messages(seaudit_log_t * log, seaudit_model_t * model)
{
	if (log == NULL || model == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (model_refresh(log, model) < 0) {
		return NULL;
	}
	return apol_vector_create_from_vector(model->messages, NULL, NULL);
}

apol_vector_t *seaudit_model_get_malformed_messages(seaudit_log_t * log, seaudit_model_t * model)
{
	if (log == NULL || model == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (model_refresh(log, model) < 0) {
		return NULL;
	}
	return apol_vector_create_from_vector(model->malformed_messages, NULL, NULL);
}

size_t seaudit_model_get_num_allows(seaudit_log_t * log, seaudit_model_t * model)
{
	if (log == NULL || model == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return 0;
	}
	if (model_refresh(log, model) < 0) {
		return 0;
	}
	return model->num_allows;
}

size_t seaudit_model_get_num_denies(seaudit_log_t * log, seaudit_model_t * model)
{
	if (log == NULL || model == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return 0;
	}
	if (model_refresh(log, model) < 0) {
		return 0;
	}
	return model->num_denies;
}

size_t seaudit_model_get_num_bools(seaudit_log_t * log, seaudit_model_t * model)
{
	if (log == NULL || model == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return 0;
	}
	if (model_refresh(log, model) < 0) {
		return 0;
	}
	return model->num_bools;
}

size_t seaudit_model_get_num_loads(seaudit_log_t * log, seaudit_model_t * model)
{
	if (log == NULL || model == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return 0;
	}
	if (model_refresh(log, model) < 0) {
		return 0;
	}
	return model->num_loads;
}

/******************** protected functions below ********************/

void model_remove_log(seaudit_model_t * model, seaudit_log_t * log)
{
	size_t i;
	if (apol_vector_get_index(model->logs, log, NULL, NULL, &i) == 0) {
		apol_vector_remove(model->logs, i);
		model->dirty = 1;
	}
}

void model_notify_log_changed(seaudit_model_t * model, seaudit_log_t * log)
{
	size_t i;
	if (apol_vector_get_index(model->logs, log, NULL, NULL, &i) == 0) {
		model->dirty = 1;
	}
}

void model_notify_filter_changed(seaudit_model_t * model, seaudit_filter_t * filter)
{
	size_t i;
	if (apol_vector_get_index(model->filters, filter, NULL, NULL, &i) == 0) {
		model->dirty = 1;
	}
}
