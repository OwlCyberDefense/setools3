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

#include <stdexcept>
#include <vector>
#include <string>

using std::vector;
using std::string;
using std::runtime_error;

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

polsearch_test & polsearch_bool_query::addTest(polsearch_test_cond_e test_cond) throw(std::invalid_argument)
{
	_tests.push_back(polsearch_test(this, test_cond));
	return *_tests.end();
}

/*
 * Run the query.
 * @param policy The policy containing the booleans to match.
 * @param fclist A file_contexts list to optionally use for tests that
 * match file_context entries. It is an error to not provide \a fclist
 * if a test matches file_context entries.
 * @return A vector of results containing one entry per boolean that matches the query.
 * @exception std::runtime_error Error running tests.
 */
std::vector < polsearch_result > polsearch_bool_query::run(const apol_policy_t * policy,
							   sefs_fclist * fclist) const throw(std::runtime_error)
{
	vector<polsearch_result> master_results;
	//TODO polsearch_bool_query.run()

	return master_results;
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
