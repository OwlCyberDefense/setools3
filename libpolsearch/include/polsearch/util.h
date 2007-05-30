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

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_UTIL_H */
