/**
 * @file
 *
 * Routines to perform complex queries on booleans in a selinux policy.
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

#include <polsearch/polsearch.hh>
#include <polsearch/query.hh>
#include <polsearch/bool_query.hh>
#include <polsearch/test.hh>
#include <polsearch/criterion.hh>
#include <polsearch/result.hh>
#include <polsearch/proof.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>
#include <apol/bool-query.h>

#include <stdexcept>
#include <vector>
#include <string>

using std::vector;
using std::string;
using std::runtime_error;
using std::bad_alloc;

polsearch_bool_query::polsearch_bool_query(polsearch_match_e m) throw(std::invalid_argument):polsearch_query(m)
{
	//nothing more to do
}

polsearch_bool_query::polsearch_bool_query(const polsearch_bool_query & rhs):polsearch_query(rhs)
{
	//nothing more to do
}

polsearch_bool_query::~polsearch_bool_query()
{
	//nothing to do
}

std::vector < const void *>polsearch_bool_query::getCandidates(const apol_policy_t * policy) const throw(std::bad_alloc,
													       std::runtime_error)
{
	apol_bool_query_t *bq = apol_bool_query_create();
	if (!bq)
		throw bad_alloc();
	apol_vector_t *v = NULL;
	if (apol_bool_get_by_query(policy, bq, &v))
	{
		if (!v)
			throw bad_alloc();
		else
		throw runtime_error("Unable to get all booleans");
	}
	vector < const void *>bv;
	for (size_t i = 0; i < apol_vector_get_size(v); i++)
	{
		bv.push_back(apol_vector_get_element(v, i));
	}

	return bv;
}

std::string polsearch_bool_query::toString() const
{
	//TODO polsearch_bool_query.toString()
	return "";
}

polsearch_element_e polsearch_bool_query::elementType() const
{
	return POLSEARCH_ELEMENT_BOOL;
}
