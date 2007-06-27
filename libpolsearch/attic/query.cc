/**
 * @file
 *
 * Routines to perform complex queries on a selinux policy.
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

#include <polsearch/polsearch.hh>
#include <polsearch/test.hh>
#include <polsearch/query.hh>

#include "test_internal.hh"

#include <apol/policy.h>
#include <apol/vector.h>

#include <sefs/fclist.hh>

#include <errno.h>
#include <stdexcept>

polsearch_query::polsearch_query(polsearch_match_e m) throw(std::bad_alloc, std::invalid_argument)
{
	_match = m;
	_tests = apol_vector_create(free_test);
	if (!_tests)
		throw std::bad_alloc();
}

polsearch_query::polsearch_query(const polsearch_query & pq) throw(std::bad_alloc)
{
	_match = pq._match;
	_tests = apol_vector_create_from_vector(pq._tests, dup_test, NULL, free_test);
	if (!_tests)
		throw std::bad_alloc();
}

polsearch_query::~polsearch_query()
{
	apol_vector_destroy(&_tests);
}

polsearch_match_e polsearch_query::match() const
{
	return this->_match;
}

polsearch_match_e polsearch_query::match(polsearch_match_e m) throw(std::invalid_argument)
{
	if (m != POLSEARCH_MATCH_ALL && m != POLSEARCH_MATCH_ANY)
		throw std::invalid_argument("Invalid matching method requested.");

	return (this->_match = m);
}

apol_vector_t *polsearch_query::tests()
{
	return _tests;
}

// C compatibility functions

polsearch_match_e polsearch_query_get_match(const polsearch_query_t * sq)
{
	if (!sq)
	{
		errno = EINVAL;
		return POLSEARCH_MATCH_ERROR;
	}
	return sq->match();
}

polsearch_match_e polsearch_query_set_match(polsearch_query_t * sq, polsearch_match_e m)
{
	if (!sq)
	{
		errno = EINVAL;
		return POLSEARCH_MATCH_ERROR;
	}
	try
	{
		return sq->match(m);
	}
	catch(std::invalid_argument)
	{
		errno = EINVAL;
		return POLSEARCH_MATCH_ERROR;
	}
}

apol_vector_t *polsearch_query_get_tests(polsearch_query_t * sq)
{
	if (!sq)
	{
		errno = EINVAL;
		return NULL;
	}

	return sq->tests();
}
