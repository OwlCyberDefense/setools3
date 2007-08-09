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

#ifndef POLSEARCH_BOOL_QUERY_HH
#define POLSEARCH_BOOL_QUERY_HH

#include <polsearch/polsearch.hh>
#include <polsearch/query.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <vector>
#include <string>

class polsearch_bool_query:public polsearch_query
{
      public:
	/**
	 * Create a query for conditional booleans.
	 * @param m Set the matching behavior of the query, must be
	 * either POLSEARCH_MATCH_ALL or POLSEARCH_MATCH_ANY.
	 * @exception std::invalid_argument Invalid matching behavior requested.
	 */
	polsearch_bool_query(polsearch_match_e m = POLSEARCH_MATCH_ALL) throw(std::invalid_argument);
	/**
	 * Copy constructor
	 * @param rhs The query to copy.
	 */
	polsearch_bool_query(const polsearch_bool_query & rhs);
	//! Destructor.
	~polsearch_bool_query();

	/**
	 * Add a test to the query.
	 * @param test_cond The condition to be tested.
	 * @return A reference to the newly created and added test.
	 * @exception std::invalid_argument Given condition is not valid for booleans.
	 */
	virtual polsearch_test & addTest(polsearch_test_cond_e test_cond) throw(std::invalid_argument);

	/**
	 * Run the query.
	 * @param policy The policy containing the booleans to match.
	 * @param fclist A file_contexts list to optionally use for tests that
	 * match file_context entries. It is an error to not provide \a fclist
	 * if a test matches file_context entries.
	 * @return A vector of results containing one entry per boolean that matches
	 * the query.
	 * @exception std::runtime_error Error running tests.
	 */
	virtual std::vector < polsearch_result > run(const apol_policy_t * policy, sefs_fclist * fclist =
						     NULL) const throw(std::runtime_error);

	/**
	 * Get a string repersenting the query.
	 * @return A string representing the query.
	 */
	virtual std::string toString() const;

	/**
	 * Get the type of element queried.
	 * @return Always returns POLSEARCH_ELEMENT_BOOL.
	 */
	virtual polsearch_element_e elementType() const;
};

#endif				       /* POLSEARCH_BOOL_QUERY_HH */
