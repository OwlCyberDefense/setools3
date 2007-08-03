/**
 * @file
 *
 * Routines to create and manipulate logically related lists of strings.
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

#ifndef POLSEARCH_STRING_LIST_HH
#define POLSEARCH_STRING_LIST_HH

#include <polsearch/polsearch.hh>

#ifdef __cplusplus
extern "C"
{
#endif

#include <apol/vector.h>

#ifdef __cplusplus
}

#include <stdexcept>

/**
 * An expression for the list of possible string values in a particular field
 * or element in a policy or file_context entry.
 */
class polsearch_string_list
{
      public:
	/**
	 * Create a string list from a string.
	 * @param str String representing the identifiers and logic operators.
	 * @param Xvalid If \a true, The special identifier \a X may be used to
	 * represent that the current query candidates should be considered for
	 * the field for which the identifiers are used.
	 * @exception std::bad_alloc Could not allocate space for internal data.
	 * @exception std::runtime_error Could not parse \a str or
	 * invalid use of the special identifier \a X.
	 * @see polsearch_is_X_valid()
	 */
	polsearch_string_list(const char *str = NULL, bool Xvalid = true) throw(std::runtime_error, std::bad_alloc);
	/**
	 * Copy a string list.
	 * @param sl The string list to copy.
	 * @exception std::bad_alloc Could not copy internal vectors.
	 */
	 polsearch_string_list(const polsearch_string_list & sl) throw(std::bad_alloc);
	//! Destructor.
	~polsearch_string_list();

	/**
	 * Get a sorted list of all unique identifiers in the list.
	 * @return A vector of identifiers (char*) in the list.
	 */
	const apol_vector_t *ids() const;
	/**
	 * Determine if there are matching identifiers in a list that match
	 * the string list.
	 * @param test_ids A vector of identifiers (char *) to match literally.
	 * @param Xcandidates A vector of identifiers (char *) to consider matches
	 * to the special identifier "X".
	 * @return If at least one of the elments of \a test_ids matches the list
	 * expression, return \a true; reurn \a false otherwise.
	 */
	bool match(const apol_vector_t * test_ids, const apol_vector_t * Xcandidates) const;
	/**
	 * Return a string representing the list.
	 * @return A string representing the list.
	 */
	char *toString() const;

      private:
	 apol_vector_t * _tokens;      /*!< RPN list of string list tokens. TODO: What is a token? */
	apol_vector_t *_ids;	       /*!< A sorted unique list of the identifiers (char*) in the list. */
};

extern "C"
{
#else
#include <stdbool.h>
#endif

//we do not want to wrap two copies of everything so have SWIG ignore the compatibility section.
#ifndef SWIG

	typedef struct polsearch_string_list polsearch_string_list_t;

	extern polsearch_string_list_t *polsearch_string_list_create(const char *str, bool Xvalid);
	extern polsearch_string_list_t *polsearch_string_list_create_from_string_list(const polsearch_string_list_t * psl);
	extern const apol_vector_t *polsearch_string_list_get_ids(const polsearch_string_list_t * psl);
	extern apol_vector_t *polsearch_string_list_match(const polsearch_string_list_t * psl, const apol_vector_t * test_ids,
							  const apol_vector_t * Xcandidates);
	extern char *polsearch_string_list_to_string(const polsearch_string_list_t * psl);

#endif				       /* SWIG */

//do wrap the following top level functions

	/**
	 * Determine if the special identifier \a X is valid for a given element
	 * and comparison operator.
	 * @param elem_type The type of element queried.
	 * @param opr The comparison operator used by the criterion.
	 * @return If \a X is valid, return \a true, otherwise, return \a false.
	 */
	extern bool polsearch_is_X_valid(polsearch_element_e elem_type, polsearch_op_e opr);

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_STRING_LIST_HH */
