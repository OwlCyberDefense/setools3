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

#include <stdexcept>

/**
 * Determine the type of element for test candidates when running
 * \a test_cond for elements of type \a elem_type.
 * @param elem_type The type of element queried.
 * @param test_cond The test condition.
 * @return The type of element examined to check if the test's
 * criteria are met.
 * @exception std::invalid_argument The given test is not valid for
 * the given element.
 */
polsearch_element_e determine_candidate_type(polsearch_element_e elem_type,
					     polsearch_test_cond_e test_cond) throw(std::invalid_argument);

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
			     polsearch_param_type_e param_type);

#endif				       /* POLSEARCH_INTERNAL_HH */
