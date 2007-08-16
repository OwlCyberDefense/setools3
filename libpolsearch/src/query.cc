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

#include <polsearch/query.hh>
#include <polsearch/polsearch.hh>
#include <polsearch/criterion.hh>
#include <polsearch/test.hh>
#include <polsearch/result.hh>
#include <polsearch/proof.hh>
#include "polsearch_internal.hh"

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <vector>
#include <string>

using std::invalid_argument;
using std::vector;

polsearch_query::polsearch_query(polsearch_match_e m) throw(std::invalid_argument)
{
	if (m != POLSEARCH_MATCH_ALL && m != POLSEARCH_MATCH_ANY)
		throw invalid_argument("Invalid matching behavior requested.");

	_match = m;
}

polsearch_query::polsearch_query(const polsearch_query & rhs)
{
	_match = rhs._match;
	_tests = rhs._tests;
}

polsearch_query::~polsearch_query()
{
	// no-op
}

polsearch_match_e polsearch_query::match() const
{
	return _match;
}

polsearch_match_e polsearch_query::match(polsearch_match_e m) throw(std::invalid_argument)
{
	if (m != POLSEARCH_MATCH_ALL && m != POLSEARCH_MATCH_ANY)
		throw invalid_argument("Invalid matching behavior requested.");

	return _match = m;
}

std::vector < polsearch_test_cond_e > polsearch_query::getValidTests()
{
	vector < polsearch_test_cond_e > v;
	for (int i = POLSEARCH_TEST_NONE; i <= POLSEARCH_TEST_STATE; i++)
		if (validate_test_condition(elementType(), static_cast < polsearch_test_cond_e > (i)))
			v.push_back(static_cast < polsearch_test_cond_e > (i));

	return v;
}

polsearch_test & polsearch_query::addTest(polsearch_test_cond_e test_cond) throw(std::invalid_argument)
{
	_tests.push_back(polsearch_test(this, test_cond));
	return _tests.back();
}

std::vector < polsearch_result > polsearch_query::run(const apol_policy_t * policy,
						      sefs_fclist * fclist) const throw(std::bad_alloc, std::runtime_error)
{
	vector < polsearch_result > master_results;
	vector < const void *>Xcandidates = getCandidates(policy);
	for (vector < polsearch_test >::const_iterator i = _tests.begin(); i != _tests.end(); i++)
	{
		vector < polsearch_result > cur_test_results = i->run(policy, fclist, Xcandidates);
		for (vector < polsearch_result >::iterator j = cur_test_results.begin(); j != cur_test_results.end(); j++)
		{
			polsearch_result *master_entry = NULL;
			for (vector < polsearch_result >::iterator k = master_results.begin(); k != master_results.end(); k++)
			{
				if (k->element() == j->element())
				{
					master_entry = &(*k);
					break;
				}
			}
			if (master_entry)
			{
				master_entry->merge(*j);
			}
			else
			{
				master_results.push_back(polsearch_result(*j));
			}
		}
	}

	return master_results;
}

void polsearch_query::update()
{
	for (vector < polsearch_test >::iterator i = _tests.begin(); i != _tests.end(); i++)
	{
		i->_query = this;
		i->update();
	}
}
