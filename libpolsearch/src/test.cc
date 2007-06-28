/**
 * @file
 *
 * Routines to create policy element tests.
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
#include <polsearch/criterion.hh>
#include <polsearch/test.hh>
#include <polsearch/query.hh>
#include "polsearch_internal.hh"

#include <stdexcept>
#include <string>
#include <vector>

using std::invalid_argument;
using std::vector;
using std::string;

polsearch_test::polsearch_test(polsearch_query * query, polsearch_test_cond_e test_cond) throw(std::invalid_argument)
{
	if (!validate_test_condition(query->elementType(), test_cond))
		throw invalid_argument("The given test condition is not valid for the given element.");

	_query = query;
	_test_cond = test_cond;
}

polsearch_test::polsearch_test(const polsearch_test & rhs)
{
	_criteria = rhs._criteria;
	_query = rhs._query;
	_test_cond = rhs._test_cond;
}

polsearch_test::~polsearch_test()
{
	// no-op
}

polsearch_element_e polsearch_test::elementType() const
{
	return _query->elementType();
}

polsearch_test_cond_e polsearch_test::testCond() const
{
	return _test_cond;
}

/**
	* Set the condition tested.
	* @param test_cond The condition to set.
	* @return The condition set.
	* @exception std::invalid_argument The given condition is not valid
	* for the element type tested.
	*/
polsearch_test_cond_e polsearch_test::testCond(polsearch_test_cond_e test_cond) throw(std::invalid_argument)
{
	if (!validate_test_condition(_query->elementType(), test_cond))
		throw invalid_argument("Invalid test for this element.");

	return _test_cond = test_cond;
}

polsearch_criterion & polsearch_test::addCriterion(polsearch_op_e opr, bool neg) throw(std::invalid_argument)
{
	polsearch_criterion crit(this, opr, neg);
	_criteria.insert(_criteria.end(), crit);
	return _criteria.back();
}
