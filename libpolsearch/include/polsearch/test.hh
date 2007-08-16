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

#ifndef POLSEARCH_TEST_HH
#define POLSEARCH_TEST_HH

#include <polsearch/polsearch.hh>
#include <polsearch/query.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <string>
#include <vector>

/**
 * Individual test to be run by a query. This test will check for a single
 * condition (such as a type having an attribute or a role being used in a
 * role_transition rule).
 */
class polsearch_test
{
      public:
	/**
	 * Copy a test.
	 * @param rhs The test to copy.
	 */
	polsearch_test(const polsearch_test & rhs);
	//! Destructor.
	~polsearch_test();

	/**
	 * Get the element type tested by the test.
	 * @return The element type tested.
	 */
	polsearch_element_e elementType() const;
	/**
	 * Get the condition tested.
	 * @return The condition tested.
	 */
	polsearch_test_cond_e testCond() const;
	/**
	 * Set the condition tested.
	 * @param test_cond The condition to set.
	 * @return The condition set.
	 * @exception std::invalid_argument The given condition is not valid
	 * for the element type tested.
	 */
	polsearch_test_cond_e testCond(polsearch_test_cond_e test_cond) throw(std::invalid_argument);

	/**
	 * Add a criterion to check for the given condition.
	 * @param opr The comparison operator to use.
	 * @param neg If \a true, invert the logic result of \a opr.
	 * @exception std::invalid_argument The given criterion is not valid for
	 * the element tested and/or the current condition. The criterion will not
	 * be changed if it cannot successfully be added to the test.
	 */
	 polsearch_criterion & addCriterion(polsearch_op_e opr, bool neg = false) throw(std::invalid_argument);

	 /**
	  * Determine if the condition tested can have more than one criterion.
	  * @return If multiple criteria are valid, return \a true; otherwise
	  * return \a false.
	  */
	bool isContinueable();

	 /**
	  * Get a list of valid comparison operators for this test.
	  * @return A vector of all valid operators for the current test condition
	  * and the element type of the associated query.
	  */
	 std::vector < polsearch_op_e > getValidOperators();

	friend class polsearch_query;

	/**
	 * DO NOT CALL. This default constructor is defined for SWIG.
	 * Tests should be created via polsearch_query::addTest().
	 */
	 polsearch_test();

      protected:
	 /**
	 * Run the test. Get all candidates for each criterion specified and check for any
	 * that are satisfied. For each element of \a Xcandidates that satisfies the criteria,
	 * there will be one result entry in the returned result vector.
	 * @param policy The policy from which the elements of \a Xcandidates come.
	 * @param fclist The file_context list to use.
	 * @param Xcandidates The vector of potential candidates for this test. If the
	 * query containing this test is set to match all, this vector will be pruned to
	 * only those candidates satisfying all criteria for this test.
	 * @return A vector containing one result entry for each element in \a Xcandidates
	 * that satisfies all criteria for the test.
	 * @exception std::runtime_error Unable to complete the test.
	 */
	const std::vector < polsearch_result > run(const apol_policy_t * policy, sefs_fclist * fclist,
						   std::vector < const void *>&Xcandidates) const throw(std::runtime_error);

	/**
	 * Create a test.
	 * @param query The query with which the test should be associated.
	 * @param test_cond The condition to test.
	 * @exception std::invalid_argument Test condition is not valid for
	 * the given element type.
	 */
	 polsearch_test(polsearch_query * query, polsearch_test_cond_e test_cond) throw(std::invalid_argument);

      private:

	/**
	 * Update internal state data. Called when adding tests to the parent query or copying the test.
	 */
	void update();

	polsearch_query *_query;       /*!< The query with which this test is associated. */
	polsearch_test_cond_e _test_cond;	/*!< The condition tested. */
	 std::vector < polsearch_criterion > _criteria;	/*!< The criteria to check. */
};

#endif				       /* POLSEARCH_TEST_HH */
