/**
 *  @file
 *  Typedefs to aid declaring function pointers for callbacks
 *  extracted from component records.
 *
 *  This file also declares functions to extract the callbacks for
 *  component records.  This implements a form of polymorphism so that
 *  one can operate on component records and not care about the
 *  library dependent implementation.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Mark Goldman mgoldman@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#ifndef POLDIFF_COMPONENT_RECORD_H
#define POLDIFF_COMPONENT_RECORD_H

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 *  Callback function signature for getting an array of statistics for the
 *  number of differences of each form for a given item.
 *  @param diff The policy difference structure from which to get the stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated). The order of the values written to the array is as follows:
 *  number of items of form POLDIFF_FORM_ADDED, number of POLDIFF_FORM_REMOVED,
 *  number of POLDIFF_FORM_MODIFIED, number of form POLDIFF_FORM_ADD_TYPE, and
 *  number of POLDIFF_FORM_REMOVE_TYPE.
 */
	typedef void (*poldiff_get_item_stats_fn_t) (const poldiff_t * diff, size_t stats[5]);

/**
 *  Callback function signature for getting a vector of all result
 *  items that were created during a call to poldiff_do_item_diff().
 *  @param diff Policy diff structure containing results.
 *  @return A vector of result items, which the caller may not modify
 *  or destroy.  Upon error, return null and set errno.
 */
	typedef const apol_vector_t *(*poldiff_get_result_items_fn_t) (const poldiff_t * diff);

/**
 *  Callback function signature for getting the form of difference for
 *  a result item.
 *  @param diff The policy difference structure associated with the item.
 *  @param item The item from which to get the form.
 *  @return One of the POLDIFF_FORM_* enumeration.
 */
	typedef poldiff_form_e(*poldiff_item_get_form_fn_t) (const void *item);

/**
 *  Callback function signature for obtaining a newly allocated string
 *  representation of a difference item.
 *  @param diff The policy difference structure associated with the item.
 *  @param item The item from which to generate the string.
 *  @return Expected return value from this function is a newly allocated
 *  string representation of the item or null on error; if the call fails,
 *  it is expected to set errno.
 */
	typedef char *(*poldiff_item_to_string_fn_t) (const poldiff_t * diff, const void *item);

	typedef struct poldiff_component_record poldiff_component_record_t;

/**
 * Get the poldiff_component_record_t for a particular policy
 * component.  Consult this record for function pointers, so as to
 * achieve a limited form of polymorphism.
 *
 * @param which Flag (as defined in <poldiff/poldiff.h>) indicating
 * which component to look up.
 * @return A poldiff_component_record_t associated with the component
 * or NULL if not found.
 */
	extern const poldiff_component_record_t *poldiff_get_component_record(uint32_t which);

/**
 * Get the function that will return the form from a
 * poldiff_component_record_t.
 *
 * @param comp Pointer to the component to extract the named virtual
 * function.
 *
 * @return Function pointer relating to the passed in record key, or
 * NULL upon error.
 */
	extern poldiff_item_get_form_fn_t poldiff_component_record_get_form_fn(const poldiff_component_record_t * comp);

/**
 * Get the function that will return the to_string from a
 * poldiff_component_record_t.
 *
 * @param diff Pointer to the component to extract the named virtual
 * function.
 *
 * @return Function pointer relating to the passed in record key, or
 * NULL upon error.
 */
	extern poldiff_item_to_string_fn_t poldiff_component_record_get_to_string_fn(const poldiff_component_record_t * diff);

/**
 * Get the function that will return the item_stats from a
 * poldiff_component_record_t.
 *
 * @param diff Pointer to the component to extract the named virtual
 * function.
 *
 * @return Function pointer relating to the passed in record key, or
 * NULL upon error.
 */
	extern poldiff_get_item_stats_fn_t poldiff_component_record_get_stats_fn(const poldiff_component_record_t * diff);

/**
 * Get the function that will return the results from a
 * poldiff_component_record_t.
 *
 * @param diff Pointer to the component to extract the named virtual
 * function.
 *
 * @return Function pointer relating to the passed in record key, or
 * NULL upon error.
 */
	extern poldiff_get_result_items_fn_t poldiff_component_record_get_results_fn(const poldiff_component_record_t * diff);

/**
 * Get the function that will return the label from a
 * poldiff_component_record_t.  This label describes the policy
 * component (e.g., "attribute" or "AVrule dontaudit").
 *
 * @param diff Pointer to the component to extract named the label.
 *
 * @return Label describing the policy component record.  Do not
 * modify this string.
 */
	extern const char *poldiff_component_record_get_label(const poldiff_component_record_t * diff);

#ifdef	__cplusplus
}
#endif

#endif
