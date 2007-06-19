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
#include <polsearch/test.hh>
#include <polsearch/polsearch.hh>
#include "test_internal.hh"

#include <sefs/fclist.hh>

#include <apol/policy.h>
#include <apol/vector.h>

#include <stdexcept>
#include <string>
#include <errno.h>
#include <cstdlib>

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

apol_vector_t *polsearch_symbol_query::getValidTests() const throw(std::bad_alloc)
{
	apol_vector_t *v = apol_vector_create(NULL);
	if (!v)
	{
		throw bad_alloc();
		return NULL;
	}

	for (int i = POLSEARCH_TEST_NAME; i <= POLSEARCH_TEST_STATE; i++)
	{
		if (polsearch_validate_test_condition
		    (static_cast < polsearch_element_e > (_symbol_type), static_cast < polsearch_test_cond_e > (i)) &&
		    apol_vector_append(v, reinterpret_cast < void *>(i)))
			throw bad_alloc();
	}
}

/**
 * Given a policy and a symbol type get all symbols of that type.
 * @param p The policy from which to get the symbols.
 * @param sym_type The type of symbols to get.
 * @return A newly allocated vector of the symbols. The caller is responsible
 * for calling apol_vector_destroy() on the returned vector.
 * @exception std::bad_alloc Could not allocate enough space to get the symbols.
 */
static apol_vector_t *get_all_symbols(const apol_policy_t * p, polsearch_symbol_e sym_type) throw(std::bad_alloc)
{
	switch (sym_type)
	{
		//TODO
	default:
	{
		return NULL;
	}
	}
}

/**
 * Merge the results from a single test into the master list of results.
 * Result and proof entries will be duplicated as needed such that it is
 * save to call apol_vector_destroy() on \a cur_results after calling this
 * function.
 * @param master_results The master list of results from all tests run.
 * @param cur_results The list of results from the most recent test run.
 * @exception std::bad_alloc Could not allocate space to duplicate entries.
 */
static void merge_results(apol_vector_t * master_results, apol_vector_t * cur_results) throw(std::bad_alloc)
{
	//TODO
	return;
}

apol_vector_t *polsearch_symbol_query::run(const apol_policy_t * policy,
					   const sefs_fclist_t * fclist) const throw(std::bad_alloc)
{
	apol_vector_t *master_results = apol_vector_create(free_result);
	if (!master_results)
		throw bad_alloc();

	apol_vector_t *Xcandidates = get_all_symbols(policy, _symbol_type);
	if (!Xcandidates)
		throw bad_alloc();

	apol_vector_t *cur_results = NULL;
	for (size_t i; i < apol_vector_get_size(_tests) && apol_vector_get_size(Xcandidates); i++)
	{
		polsearch_test *cur = static_cast < polsearch_test * >(apol_vector_get_element(_tests, i));
		cur_results = cur->run(policy, fclist, Xcandidates);
		merge_results(master_results, cur_results);
		apol_vector_destroy(&cur_results);
	}

	//sort results ? TODO
	return master_results;
}

// C compatibility functions

polsearch_symbol_query_t *polsearch_symbol_query_create(polsearch_symbol_e sym_type, polsearch_match_e m)
{
	if (sym_type == POLSEARCH_SYMBOL_NONE || sym_type > POLSEARCH_SYMBOL_BOOL ||
	    m == POLSEARCH_MATCH_ERROR || m > POLSEARCH_MATCH_ANY)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return new polsearch_symbol_query(sym_type, m);
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
	catch(invalid_argument)
	{
		errno = EINVAL;
		return NULL;
	}
}

polsearch_symbol_query_t *polsearch_symbol_query_create_from_symbol_query(const polsearch_symbol_query_t * sq)
{
	if (!sq)
	{
		errno = EINVAL;
		return NULL;
	}
	try
	{
		return new polsearch_symbol_query(*sq);
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

void polsearch_symbol_query_destroy(polsearch_symbol_query_t ** sq)
{
	if (!sq)
		return;

	delete *sq;
	*sq = NULL;
}

polsearch_symbol_e polsearch_symbol_query_get_symbol_type(const polsearch_symbol_query_t * sq)
{
	if (!sq)
	{
		errno = EINVAL;
		return POLSEARCH_SYMBOL_NONE;
	}

	return sq->symbolType();
}

apol_vector_t *polsearch_symbol_query_run(const polsearch_symbol_query_t * sq, const apol_policy_t * p,
					  const sefs_fclist_t * fclist)
{
	if (!sq)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return sq->run(p, fclist);
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

apol_vector_t *polsearch_symbol_query_get_valid_tests(const polsearch_symbol_query_t * sq)
{
	if (!sq)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return sq->getValidTests();
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}
