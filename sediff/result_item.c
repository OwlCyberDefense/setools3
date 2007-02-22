/**
 *  @file
 *  Implementation of the result item class.
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

#include "result_item.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>

typedef void (*policy_changed_fn_t) (result_item_t * item, apol_policy_t * orig_pol, apol_policy_t * mod_pol);
typedef void (*poldiff_run_fn_t) (result_item_t * item, poldiff_t * diff, int incremental);
typedef GtkTextBuffer *(*get_buffer_fn_t) (result_item_t * item, poldiff_form_e form);
typedef void (*get_forms_fn_t) (result_item_t * item, int forms[5]);
typedef size_t(*get_num_differences_fn_t) (result_item_t * item, poldiff_form_e form);
typedef void (*set_current_sort_fn_t) (result_item_t * item, results_sort_e sort, results_sort_dir_e dir);

struct result_item
{
	const char *label;
	results_sort_e current_sort;
	results_sort_dir_e current_sort_dir;
	/** bit value corresponding to polidiff/poldiff.h defines */
	uint32_t bit_pos;
	/** if either policy does not support a particular policy
	    component then this will be zero */
	int supported;
	/* protected members below */
	poldiff_t *diff;
	size_t stats[5];
	/* below are required functions to get poldiff results */
	apol_vector_t *(*get_vector) (poldiff_t *);
	 poldiff_form_e(*get_form) (const void *);
	char *(*get_string) (poldiff_t *, const void *);
	/* below is a virtual function table */
	/** if the result item does not care about the type of
	    policies are loaded then this can be NULL */
	policy_changed_fn_t policy_changed;
	poldiff_run_fn_t poldiff_run;
	get_buffer_fn_t get_buffer;
	get_forms_fn_t get_forms;
	get_num_differences_fn_t get_num_differences;
	/** if the result item cannot be sorted then this will be
	    NULL */
	set_current_sort_fn_t set_current_sort;
	union
	{
		int type_can_modify;
	} data;
};

/******************** common rendering functions ********************/

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
 * color tags based upon the item's first character.
 */
static void result_item_print_string(GtkTextBuffer * tb, GtkTextIter * iter, const char *s, unsigned int indent_level)
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
static void result_item_print_summary(result_item_t * item, GtkTextBuffer * tb)
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
static void result_item_print_header(result_item_t * item, GtkTextBuffer * tb, poldiff_form_e form)
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

/**
 * Show the results for non-rules diff components.
 */
static void result_item_print_diff(result_item_t * item, GtkTextBuffer * tb, poldiff_form_e form)
{
	GtkTextIter iter;
	apol_vector_t *v;
	size_t i;
	void *elem;
	char *s = NULL;

	gtk_text_buffer_get_end_iter(tb, &iter);
	v = item->get_vector(item->diff);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		elem = apol_vector_get_element(v, i);
		if (item->get_form(elem) == form) {
			s = item->get_string(item->diff, elem);
			result_item_print_string(tb, &iter, s, 1);
			free(s);
			gtk_text_buffer_insert(tb, &iter, "\n", -1);
		}
	}
}

/******************** single buffer functions ********************/

/* below is the implementation of the 'single buffer result item'
   class.  most policy components are instances of this class.*/

static GtkTextBuffer *single_buffer = NULL;

/**
 * For single items, results are always destroyed.  (Recalculating
 * results is very fast.)
 */
static void result_item_single_poldiff_run(result_item_t * item, poldiff_t * diff, int incremental __attribute__ ((unused)))
{
	item->diff = diff;
	memset(item->stats, 0, sizeof(item->stats));
}

/**
 * For single items, re-use the same buffer each time.
 */
static GtkTextBuffer *result_item_single_get_buffer(result_item_t * item, poldiff_form_e form)
{
	util_text_buffer_clear(single_buffer);
	if (form == POLDIFF_FORM_NONE) {
		result_item_print_summary(item, single_buffer);
	} else {
		result_item_print_header(item, single_buffer, form);
		result_item_print_diff(item, single_buffer, form);
	}
	return single_buffer;
}

static void result_item_single_get_forms(result_item_t * item, int forms[5])
{
	int i, was_run = poldiff_is_run(item->diff, item->bit_pos);
	if (was_run) {
		poldiff_get_stats(item->diff, item->bit_pos, item->stats);
	}
	for (i = 0; i < 5; i++) {
		if (!result_item_is_supported(item) || i == 1 || i == 3) {
			/* single items do not have add-by-type and
			 * remove-by-type forms */
			forms[i] = -1;
		} else {
			forms[i] = was_run;
		}
	}
}

static size_t result_item_single_get_num_differences(result_item_t * item, poldiff_form_e form)
{
	switch (form) {
	case POLDIFF_FORM_ADDED:
		return item->stats[0];
	case POLDIFF_FORM_REMOVED:
		return item->stats[1];
	case POLDIFF_FORM_MODIFIED:
		return item->stats[2];
	case POLDIFF_FORM_ADD_TYPE:
		return item->stats[3];
	case POLDIFF_FORM_REMOVE_TYPE:
		return item->stats[4];
	default:		       /* should never get here */
		assert(0);
		return 0;
	}
}

/**
 * Constructor for the abstract single buffer item class.
 */
static result_item_t *result_item_single_create(GtkTextTagTable * table)
{
	result_item_t *item = calloc(1, sizeof(*item));
	if (item == NULL) {
		return item;
	}
	if (single_buffer == NULL) {
		single_buffer = gtk_text_buffer_new(table);
	}
	item->supported = 1;
	item->policy_changed = NULL;
	item->poldiff_run = result_item_single_poldiff_run;
	item->get_buffer = result_item_single_get_buffer;
	item->get_forms = result_item_single_get_forms;
	item->get_num_differences = result_item_single_get_num_differences;
	return item;
}

/******************** constructors below ********************/

result_item_t *result_item_create_classes(GtkTextTagTable * table)
{
	result_item_t *item = result_item_single_create(table);
	if (item == NULL) {
		return item;
	}
	item->label = "Classes";
	item->bit_pos = POLDIFF_DIFF_CLASSES;
	item->get_vector = poldiff_get_class_vector;
	item->get_form = poldiff_class_get_form;
	item->get_string = poldiff_class_to_string;
	return item;
}

result_item_t *result_item_create_commons(GtkTextTagTable * table)
{
	result_item_t *item = result_item_single_create(table);
	if (item == NULL) {
		return item;
	}
	item->label = "Commons";
	item->bit_pos = POLDIFF_DIFF_COMMONS;
	item->get_vector = poldiff_get_common_vector;
	item->get_form = poldiff_common_get_form;
	item->get_string = poldiff_common_to_string;
	return item;
}

/**
 * Only show modified types if it makes sense -- i.e, when both
 * policies have meaningful attribute names.
 */
static void result_item_type_policy_changed(result_item_t * item, apol_policy_t * orig_pol, apol_policy_t * mod_pol)
{
	qpol_policy_t *oq = apol_policy_get_qpol(orig_pol);
	qpol_policy_t *mq = apol_policy_get_qpol(mod_pol);
	if (!qpol_policy_has_capability(oq, QPOL_CAP_ATTRIB_NAMES) || !qpol_policy_has_capability(mq, QPOL_CAP_ATTRIB_NAMES)) {
		item->data.type_can_modify = 0;
	} else {
		item->data.type_can_modify = 1;
	}
}

static void result_item_type_get_forms(result_item_t * item, int forms[5])
{
	result_item_single_get_forms(item, forms);
	if (!item->data.type_can_modify) {
		forms[4] = -1;
	}
}

/* the type result item is a subclass of single item.  it differs in
   that it might not have a modified form */
result_item_t *result_item_create_types(GtkTextTagTable * table)
{
	result_item_t *item = result_item_single_create(table);
	if (item == NULL) {
		return item;
	}
	item->label = "Types";
	item->bit_pos = POLDIFF_DIFF_TYPES;
	item->get_vector = poldiff_get_type_vector;
	item->get_form = poldiff_type_get_form;
	item->get_string = poldiff_type_to_string;
	item->policy_changed = result_item_type_policy_changed;
	item->get_forms = result_item_type_get_forms;
	return item;
}

/**
 * Only support attributes when both policies (can) have them.
 */
static void result_item_attribute_policy_changed(result_item_t * item, apol_policy_t * orig_pol, apol_policy_t * mod_pol)
{
	qpol_policy_t *oq = apol_policy_get_qpol(orig_pol);
	qpol_policy_t *mq = apol_policy_get_qpol(mod_pol);
	if (!qpol_policy_has_capability(oq, QPOL_CAP_ATTRIB_NAMES) || !qpol_policy_has_capability(mq, QPOL_CAP_ATTRIB_NAMES)) {
		item->supported = 0;
	}
}

/* the attribute result item is a subclass of single item.  it differs
   in that it might not exist if attributes are not supported in
   either policy */
result_item_t *result_item_create_attributes(GtkTextTagTable * table)
{
	result_item_t *item = result_item_single_create(table);
	if (item == NULL) {
		return item;
	}
	item->label = "Attributes";
	item->bit_pos = POLDIFF_DIFF_ATTRIBS;
	item->get_vector = poldiff_get_attrib_vector;
	item->get_form = poldiff_attrib_get_form;
	item->get_string = poldiff_attrib_to_string;
	item->policy_changed = result_item_attribute_policy_changed;
	return item;
}

result_item_t *result_item_create_roles(GtkTextTagTable * table)
{
	result_item_t *item = result_item_single_create(table);
	if (item == NULL) {
		return item;
	}
	item->label = "Roles";
	item->bit_pos = POLDIFF_DIFF_ROLES;
	item->get_vector = poldiff_get_role_vector;
	item->get_form = poldiff_role_get_form;
	item->get_string = poldiff_role_to_string;
	return item;
}

/**
 * Printing a modified user is special; the result depends upon if a
 * MLS policy is loaded or not.
 */
static GtkTextBuffer *result_item_user_get_buffer(result_item_t * item, poldiff_form_e form)
{
	/* FIX ME */
	return result_item_single_get_buffer(item, form);
}

/* the user result item is a subclass of a single item. */
result_item_t *result_item_create_users(GtkTextTagTable * table)
{
	result_item_t *item = result_item_single_create(table);
	if (item == NULL) {
		return item;
	}
	item->label = "Users";
	item->bit_pos = POLDIFF_DIFF_USERS;
	item->get_vector = poldiff_get_user_vector;
	item->get_form = poldiff_user_get_form;
	item->get_string = poldiff_user_to_string;
	item->get_buffer = result_item_user_get_buffer;
	return item;
}

/**
 * Only support booleans when both policies (can) have them.
 */
static void result_item_boolean_policy_changed(result_item_t * item, apol_policy_t * orig_pol, apol_policy_t * mod_pol)
{
	qpol_policy_t *oq = apol_policy_get_qpol(orig_pol);
	qpol_policy_t *mq = apol_policy_get_qpol(mod_pol);
	if (!qpol_policy_has_capability(oq, QPOL_CAP_CONDITIONALS) || !qpol_policy_has_capability(mq, QPOL_CAP_CONDITIONALS)) {
		item->supported = 0;
	}
}

/* booleans are not supported for policy versions less than 16 */
result_item_t *result_item_create_booleans(GtkTextTagTable * table)
{
	result_item_t *item = result_item_single_create(table);
	if (item == NULL) {
		return item;
	}
	item->label = "Booleans";
	item->bit_pos = POLDIFF_DIFF_BOOLS;
	item->get_vector = poldiff_get_bool_vector;
	item->get_form = poldiff_bool_get_form;
	item->get_string = poldiff_bool_to_string;
	item->policy_changed = result_item_boolean_policy_changed;
	return item;
}

/******************** public methods below ********************/

void result_item_destroy(result_item_t ** item)
{
	if (item != NULL && *item != NULL) {
		free(*item);
		*item = NULL;
	}
}

const char *result_item_get_label(const result_item_t * item)
{
	return item->label;
}

void result_item_policy_changed(result_item_t * item, apol_policy_t * orig_pol, apol_policy_t * mod_pol)
{
	if (item->policy_changed != NULL) {
		item->policy_changed(item, orig_pol, mod_pol);
	}
}

GtkTextBuffer *result_item_get_buffer(result_item_t * item, poldiff_form_e form)
{
	return item->get_buffer(item, form);
}

void result_item_poldiff_run(result_item_t * item, poldiff_t * diff, int incremental)
{
	item->poldiff_run(item, diff, incremental);
}

int result_item_is_supported(const result_item_t * item)
{
	return item->supported;
}

void result_item_get_forms(result_item_t * item, int forms[5])
{
	item->get_forms(item, forms);
}

size_t result_item_get_num_differences(result_item_t * item, poldiff_form_e form)
{
	return item->get_num_differences(item, form);
}

int result_item_get_current_sort(result_item_t * item, results_sort_e * sort, results_sort_dir_e * dir)
{
	if (item->set_current_sort == NULL) {
		return 0;
	}
	*sort = item->current_sort;
	*dir = item->current_sort_dir;
	return 1;
}

void result_item_set_current_sort(result_item_t * item, results_sort_e sort, results_sort_dir_e dir)
{
	if (item->set_current_sort != NULL) {
		item->set_current_sort(item, sort, dir);
	}
}

#if 0
static const struct poldiff_item_record poldiff_items[] = {
	{"Levels", 11, POLDIFF_DIFF_LEVELS, 0,
	 poldiff_get_level_vector, poldiff_level_get_form, poldiff_level_to_string},
	{"Categories", 12, POLDIFF_DIFF_CATS, 0,
	 poldiff_get_cat_vector, poldiff_cat_get_form, poldiff_cat_to_string},
	{"Role Allows", 8, POLDIFF_DIFF_ROLE_ALLOWS, 0,
	 poldiff_get_role_allow_vector, poldiff_role_allow_get_form, poldiff_role_allow_to_string},
	{"Role Transitions", 9, POLDIFF_DIFF_ROLE_TRANS, 1,
	 poldiff_get_role_trans_vector, poldiff_role_trans_get_form, poldiff_role_trans_to_string},
	{"TE Rules", 10, POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES, 1,
	 NULL, NULL, NULL /* special case because this is from two data */ },
	{NULL, 13, 0, 0, NULL, NULL, NULL}	/* must have highest id value */
};

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
				return opts->direction * ((char *)q1 - (char *)q2);
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
				return opts->direction * ((char *)q1 - (char *)q2);
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
		case POLDIFF_DIFF_LEVELS:
		case POLDIFF_DIFF_CATS:
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

#endif
