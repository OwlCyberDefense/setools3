/**
 * @file
 *
 * Internal routines to handle tests' criteria for logic queries.
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

#ifndef POLSEARCH_CRITERION_INTERNAL_H
#define POLSEARCH_CRITERION_INTERNAL_H

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * Free callback for polsearch_criterion objects in apol vectors.
	 * @param pc Pointer to a polsearch_criterion object to destroy.
	 */
	void free_criterion(void *pc);

	/**
	 * Duplicate callback for polsearch_criterion objects in apol vectors.
	 * @param pc Pointer to a polsearch_criterion object to copy.
	 * @param x Unused parameter
	 */
	void *dup_criterion(const void *pc, void *x __attribute__ ((unused)));

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_CRITERION_INTERNAL_H */
