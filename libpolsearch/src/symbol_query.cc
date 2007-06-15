/**
 * @file
 *
 * Routines to perform complex queries for symbols in a selinux policy.
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

#include <config.h>

#include <polsearch/symbol_query.hh>
#include <polsearch/query.hh>
#include <polsearch/polsearch.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>
#include <apol/vector.h>

#include <stdexcept>
#include <string>

using std::bad_alloc;
using std::invalid_argument;
using std::string;

polsearch_symbol_query::polsearch_symbol_query(polsearch_symbol_e sym_type, polsearch_match_e m) throw(std::bad_alloc, std::invalid_argument):polsearch_query
	(m)
{
	if (sym_type == POLSEARCH_SYMBOL_NONE || sym_type > POLSEARCH_SYMBOL_BOOL)
		throw invalid_argument("Invalid symbol type specified");

	_symbol_type = sym_type;
}

polsearch_symbol_query::polsearch_symbol_query(const polsearch_symbol_query & sq) throw(std::bad_alloc):polsearch_query(sq.match())
{
	_symbol_type = sq._symbol_type;
}

polsearch_symbol_query::~polsearch_symbol_query()
{
	// nothing to do
}

polsearch_symbol_e polsearch_symbol_query::symbolType() const
{
	return _symbol_type;
}

	/**
	 * Get a list of the valid types of tests to perform for the symbol
	 * type specified by the query.
	 * @return A vector (of type polsearch_test_cond_e) containing all valid
	 * tests for the specified symbol type. The caller is responsible for
	 * calling apol_vector_destroy() on the returned vector.
	 * @exception std::bad_alloc Could not allocate the vector.
	 */
apol_vector_t *polsearch_symbol_query::getValidTests() const throw(std::bad_alloc)
{
	//TODO
	return NULL;
}

	/**
	 * Run the query.
	 * @param policy The policy containing the elements to match.
	 * @param fclist A file_contexts list to optionally use for tests that
	 * match file_context entries. It is an error to not provide \a fclist
	 * if a test matches file_context entries.
	 * @return A vector of results (polsearch_result), or NULL on
	 * error. The caller is responsible for calling apol_vector_destroy()
	 * on the returned vector.
	 * @exception std::bad_alloc Could not allocate the vector.
	 */
apol_vector_t *polsearch_symbol_query::run(const apol_policy_t * policy,
					   const sefs_fclist_t * fclist) const throw(std::bad_alloc)
{
	//TODO
	return NULL;
}
