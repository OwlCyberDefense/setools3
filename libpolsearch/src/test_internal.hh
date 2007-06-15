/**
 * @file
 *
 * Internal routines related to logic tests.
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

#ifndef POLSEARCH_TEST_INTERNAL_H
#define POLSEARCH_TEST_INTERNAL_H

#include <polsearch/test.hh>

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * Free callback for polsearch_test objects in apol vectors.
	 * @param pt Pointer to a polsearch_test object to destroy.
	 */
	void free_test(void *pt);

	/**
	 * Duplicate callback for polsearch_test objects in apol vectors.
	 * @param pt Pointer to a polsearch_test object to copy.
	 * @param x Unused parameter
	 */
	void *dup_test(const void *pt, void *x __attribute__ ((unused)));

	/**
	 * Free callback for polsearch_result objects in apol vectors.
	 * @param pr Pointer to a polsearch_result object to destroy.
	 */
	void free_result(void *pr);

	/**
	 * Duplicate callback for polsearch_result objects in apol vectors.
	 * @param pr Pointer to a polsearch_result object to copy.
	 * @param x Unused parameter
	 */
	void *dup_result(const void *pr, void *x __attribute__ ((unused)));

	/**
	 * Free callback for polsearch_proof objects in apol vectors.
	 * @param pp Pointer to a polsearch_proof object to destroy.
	 */
	void free_proof(void *pp);

	/**
	 * Duplicate callback for polsearch_proof objects in apol vectors.
	 * @param pp Pointer to a polsearch_proof object to copy.
	 * @param x Unused parameter.
	 */
	void *dup_proof(const void *pp, void *x __attribute__ ((unused)));

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_TEST_INTERNAL_H */
