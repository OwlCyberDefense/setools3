/**
 * @file
 *
 * Miscellaneous, uncategorized functions for libpolsearch.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2007 Tresys Technology, LLC
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

#ifndef POLSEARCH_UTIL_H
#define POLSEARCH_UTIL_H

#include "polsearch.hh"
#include <sefs/fclist.hh>

#ifdef	__cplusplus
extern "C"
{
#endif

#include <apol/policy.h>

	/**
	 * Return an immutable string describing this library's version.
	 *
	 * @return String describing this library.
	 */
	extern const char *libpolsearch_get_version(void);

	/**
	 * Get the name of a policy symbol.
	 * @param symbol The symbol for which to get the name.
	 * @param sym_type The type of symbol.
	 * @param p The policy conaining \a symbol.
	 * @return The name of the symbol, or NULL on error.
	 */
	extern const char *libpolsearch_symbol_get_name(const void *symbol, polsearch_symbol_e sym_type, const apol_policy_t * p);

	/**
	 * Get a string representing a symbol type.
	 * @param sym_type The symbol type for which to get a string representation.
	 * @return A string representing the symbol type, or NULL on error.
	 */
	extern const char *polsearch_symbol_type_to_string(polsearch_symbol_e sym_type);

	/**
	 * Given a string representing a symbol type get the value for that type.
	 * @param str A string representing a policy symbol type.
	 * @return The corresponding symbol value, or POLSEARCH_SYMBOL_NONE on error.
	 */
	extern polsearch_symbol_e polsearch_sting_to_symbol_type(const char *str);

	/**
	 * Get a string representing a element type.
	 * @param elem_type The element type for which to get a string representation.
	 * @return A string representing the element type, or NULL on error.
	 */
	extern const char *polsearch_element_type_to_string(polsearch_element_e elem_type);

	/**
	 * Given a string representing a element type get the value for that type.
	 * @param str A string representing a policy element type.
	 * @return The corresponding element value, or POLSEARCH_ELEMENT_NONE on error.
	 */
	extern polsearch_element_e polsearch_sting_to_element_type(const char *str);

	/**
	 * Given an element and its type, return a string representation of
	 * that element.
	 * @param elem The element for which to get a string representation.
	 * @param elem_type The type of element represented by \a elem.
	 * @param p The policy from which any symbol(s) referenced by \a elem come.
	 * @param fclist The file_contexts list from which any file_context entries come.
	 * @return The string representation of \a elem; the caller is responsible for
	 * calling free() on the returned string.
	 */
	extern char *polsearch_element_to_string(const void *elem, polsearch_element_e elem_type, const apol_policy_t * p,
						 const sefs_fclist_t * fclist);

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_UTIL_H */
