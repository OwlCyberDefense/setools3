/**
 * @file
 *
 * Top level internal library routines.
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

#ifndef POLSEARCH_INTERNAL_HH
#define POLSEARCH_INTERNAL_HH

#include <polsearch/polsearch.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <vector>
#include <string>
#include <typeinfo>

/**
 * Determine the type of element for test candidates when running
 * \a test_cond.
 * @param test_cond The test condition.
 * @return The type of element examined to check if the test's
 * criteria are met.
 * @exception std::invalid_argument The given test is not valid.
 */
polsearch_element_e determine_candidate_type(polsearch_test_cond_e test_cond) throw(std::invalid_argument);

/**
 * Determine if a test condition is valid for a particular element type.
 * @param elem_type The element type.
 * @param test_cond The test condition.
 * @return If test condition \a test_cond is valid for \a elem_type,
 * return \a true, otherwise, return \a false.
 */
bool validate_test_condition(polsearch_element_e elem_type, polsearch_test_cond_e cond);

/**
 * Determine if a comparison operator is valid for a particular test condition and
 * type of element.
 * @param elem_type The type of element.
 * @param cond The test condition.
 * @param opr The comparison operator.
 * @return If operator \a opr is valid for \a cond and \a elem_type, return \a true,
 * otherwise, return \a false.
 */
bool validate_operator(polsearch_element_e elem_type, polsearch_test_cond_e cond, polsearch_op_e opr);

/**
 * Determine if a parameter type is valid for a particular comparison operator,
 * test condition, and type of element.
 * @param elem_type The type of element queried.
 * @param cond The test condition.
 * @param opr The comparison operator.
 * @param param_type The parameter type.
 * @return If parameter type \a param_type is valid for \a cond,
 * \a elem_type, and \a opr, return \a true, otherwise, return \a false.
 */
bool validate_parameter_type(polsearch_element_e elem_type, polsearch_test_cond_e cond, polsearch_op_e opr,
			     const std::type_info & param_type);

/**
 * Determine if a parameter type is valid for a particular comparison operator,
 * test condition, and type of element.
 * @param elem_type The type of element queried.
 * @param cond The test condition.
 * @param opr The comparison operator.
 * @param param_type The parameter type.
 * @return If parameter type \a param_type is valid for \a cond,
 * \a elem_type, and \a opr, return \a true, otherwise, return \a false.
 */
bool validate_parameter_type(polsearch_element_e elem_type, polsearch_test_cond_e cond, polsearch_op_e opr,
			     polsearch_param_type_e param_type);

/**
 * Get the name of a policy symbol.
 * @param symbol The symbol.
 * @param sym_type The type of symbol.
 * @param policy The policy from which \a symbol comes.
 * @return The name of the symbol or NULL on error.
 */
const char *symbol_get_name(const void *symbol, polsearch_element_e sym_type, const apol_policy_t * policy);

/**
 * Get all valid names for a policy element.
 * @param element The element.
 * @param elem_type The type of element.
 * @param policy The policy from which \a element comes.
 * @return A vector of all valid names for the element. This vector may be
 * empty if \a element is of a type which cannot be identified by a name.
 * @exception std::bad_alloc Out of memory.
 */
std::vector < std::string > get_all_names(const void *element, polsearch_element_e elem_type,
					  const apol_policy_t * policy) throw(std::bad_alloc);

/**
 * Make a vector of strings from an apol vector.
 * @param rhs The apol vector to convert.
 * @return A new vector initialized to the values is \a rhs.
 * @pre The apol vector contains items of type (char*).
 * @post There are no memory ownership constraints on the strings in the created vector.
 */
std::vector < std::string > mkvector(const apol_vector_t * rhs);

/**
 * Copy an arbirtary element.
 * @param elem_type The type of element.
 * @param elem The element to copy.
 * @return A newly allocated copy of \a elem.
 */
void *element_copy(polsearch_element_e elem_type, const void *elem) throw(std::bad_alloc);

/**
 * Get the function to free an element for use when adding proof entries or
 * dealing with qpol objects.
 * @param elem_type The type of element for which to get the free function.
 * @return Function pointer to the free function to call to free an element
 * of type \a elem_type or NULL if no function needs to be called.
 */
polsearch_proof_element_free_fn get_element_free_fn(polsearch_element_e elem_type);

#endif				       /* POLSEARCH_INTERNAL_HH */
