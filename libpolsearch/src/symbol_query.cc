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
using std::runtime_error;
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
	apol_vector_t *v = NULL;
	int retv = 0;
	switch (sym_type)
	{
	case POLSEARCH_SYMBOL_TYPE:
	{
		apol_type_query_t *q = apol_type_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_type_get_by_query(p, q, &v);
		apol_type_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_ATTRIBUTE:
	{
		apol_attr_query_t *q = apol_attr_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_attr_get_by_query(p, q, &v);
		apol_attr_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_ROLE:
	{
		apol_role_query_t *q = apol_role_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_role_get_by_query(p, q, &v);
		apol_role_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_USER:
	{
		apol_user_query_t *q = apol_user_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_user_get_by_query(p, q, &v);
		apol_user_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_CLASS:
	{
		apol_class_query_t *q = apol_class_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_class_get_by_query(p, q, &v);
		apol_class_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_COMMON:
	{
		apol_common_query_t *q = apol_common_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_common_get_by_query(p, q, &v);
		apol_common_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_CATEGORY:
	{
		apol_cat_query_t *q = apol_cat_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_cat_get_by_query(p, q, &v);
		apol_cat_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_LEVEL:
	{
		apol_level_query_t *q = apol_level_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_level_get_by_query(p, q, &v);
		apol_level_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_BOOL:
	{
		apol_bool_query_t *q = apol_bool_query_create();
		if (!q)
			throw bad_alloc();
		retv = apol_bool_get_by_query(p, q, &v);
		apol_bool_query_destroy(&q);
		if (retv)
			throw bad_alloc();
		return v;
	}
	case POLSEARCH_SYMBOL_NONE:
	default:
	{
		return NULL;
	}
	}
}

apol_vector_t *polsearch_symbol_query::run(const apol_policy_t * policy,
					   sefs_fclist_t * fclist) const throw(std::bad_alloc, std::runtime_error)
{
	apol_vector_t *master_results = apol_vector_create(free_result);
	if (!master_results)
		throw bad_alloc();

	apol_vector_t *Xcandidates = get_all_symbols(policy, _symbol_type);
	if (!Xcandidates)
		throw bad_alloc();

	for (size_t i = 0; i < apol_vector_get_size(_tests); i++)
	{
		polsearch_test *cur = static_cast < polsearch_test * >(apol_vector_get_element(_tests, i));
		if (!polsearch_validate_test_condition(static_cast < polsearch_element_e > (_symbol_type), cur->testCond()) ||
		    static_cast < polsearch_element_e > (_symbol_type) != cur->elementType())
			throw runtime_error("Invalid test provided");
	}

	apol_vector_t *cur_results = NULL;
	for (size_t i = 0; i < apol_vector_get_size(_tests) && apol_vector_get_size(Xcandidates); i++)
	{
		polsearch_test *cur = static_cast < polsearch_test * >(apol_vector_get_element(_tests, i));
		cur_results = cur->run(policy, fclist, Xcandidates, (_match == POLSEARCH_MATCH_ALL));
		merge_results(policy, master_results, cur_results, _match);
		apol_vector_destroy(&cur_results);
		// matching all tests but no results remain; stop checking and return empty vector
		if (!apol_vector_get_size(master_results) && _match == POLSEARCH_MATCH_ALL)
		{
			return master_results;
		}
	}

	//sort results
	apol_vector_sort(master_results, result_cmp, const_cast < void *>(static_cast < const void *>(policy)));
	for (size_t i = 0; i < apol_vector_get_size(master_results); i++)
	{
		polsearch_result *tmp = static_cast < polsearch_result * >(apol_vector_get_element(master_results, i));
		apol_vector_sort(tmp->proof(), proof_cmp, const_cast < void *>(static_cast < const void *>(policy)));
	}
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

apol_vector_t *polsearch_symbol_query_run(const polsearch_symbol_query_t * sq, const apol_policy_t * p, sefs_fclist_t * fclist)
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
