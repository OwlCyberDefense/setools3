/**
 * @file
 *
 * Routines to perform complex queries on roles in a selinux policy.
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
#include <polsearch/role_query.hh>
#include <polsearch/test.hh>
#include <polsearch/criterion.hh>
#include <polsearch/result.hh>
#include <polsearch/proof.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>
#include <apol/role-query.h>

#include <stdexcept>
#include <vector>
#include <string>

using std::vector;
using std::string;
using std::runtime_error;
using std::bad_alloc;

polsearch_role_query::polsearch_role_query(polsearch_match_e m) throw(std::invalid_argument):polsearch_query(m)
{
	//nothing more to do
}

polsearch_role_query::polsearch_role_query(const polsearch_role_query & rhs):polsearch_query(rhs)
{
	//nothing more to do
}

polsearch_role_query::~polsearch_role_query()
{
	//nothing to do
}

std::vector < const void *>polsearch_role_query::getCandidates(const apol_policy_t * policy) const throw(std::bad_alloc,
													       std::runtime_error)
{
	apol_role_query_t *rq = apol_role_query_create();
	if (!rq)
		throw bad_alloc();
	apol_vector_t *v = NULL;
	if (apol_role_get_by_query(policy, rq, &v))
	{
		if (!v)
		{
			throw bad_alloc();
		}
		else
		{
			throw runtime_error("Unable to get all roles");
		}
	}
	vector < const void *>rv;
	for (size_t i = 0; i < apol_vector_get_size(v); i++)
	{
		rv.push_back(apol_vector_get_element(v, i));
	}
	apol_vector_destroy(&v);
	apol_role_query_destroy(&rq);

	return rv;
}

std::string polsearch_role_query::toString() const
{
	//TODO polsearch_role_query.toString()
	return "";
}

polsearch_element_e polsearch_role_query::elementType() const
{
	return POLSEARCH_ELEMENT_ROLE;
}
