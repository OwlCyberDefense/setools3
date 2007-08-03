/**
 * @file
 *
 * Top level library routines.
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

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * Compare two elements to determine the correct order for the report.
	 * @param elem_type The type of elements being compared.
	 * @param left An element.
	 * @param right An element.
	 * @param policy The policy from which to retrieve any needed symbols.
	 * @return Less than, equal to, or greater than 0 if \a left should appear
	 * before, with, or after \a right respectively.
	 */
	int element_compare(polsearch_element_e elem_type, const void *left, const void *right, const apol_policy_t * policy);

#ifdef __cplusplus
}

#include <stdexcept>

	/**
	 * Copy an arbirtary element.
	 * @param elem_type The type of element.
	 * @param elem The element to copy.
	 * @return A newly allocated copy of \a elem.
	 */
void *element_copy(polsearch_element_e elem_type, void *elem) throw(std::bad_alloc);

#endif

#endif				       /* POLSEARCH_INTERNAL_HH */
