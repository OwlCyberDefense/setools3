/**
 * @file
 *
 * Routines to handle tests' criteria for logic queries.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2007 Tresys Technology, LLC
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

#include <polsearch/criterion.hh>
#include "criterion_internal.hh"

// base criterion

// derived variants

// internal functions

void free_criterion(void *pc)
{
	//TODO CHECKME
	delete pc;
}

void *dup_criterion(const void *pc, void *x __attribute__ ((unused)))
{
	//TODO check which kind and return it.
	return NULL;
}

// C compatibility
