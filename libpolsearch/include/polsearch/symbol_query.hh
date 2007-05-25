/**
 * @file
 *
 * Routines to perform complex queries on a selinux policy.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2007 Tresys Technology, LLC
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

#ifndef POLSEARCH_SYMBOL_QUERY_H
#define POLSEARCH_SYMBOL_QUERY_H

#include <apol/policy.h>
#include <apol/vector.h>

#include <sefs/fclist.h>

#include "polsearch.hh"
#include "test.hh"

#ifdef __cplusplus
extern "C"
{
#endif

/** Value to indicate the overall matching behavior of the query */
	typedef enum polsearch_match
	{
		POLSEARCH_MATCH_ALL = 0,	/*!< Returned symbols must match all tests. */
		POLSEARCH_MATCH_ANY    /*!< Returned symbols must match at least one test. */
	} polsearch_match_e;

#ifdef __cplusplus
}

/**
 * Query containing multiple tests. Running this query will find all symbols X
 * of a given symbol type that match the specified tests.  The symbol type may
 * only be set at creation of the query; however, the user is free to change
 * the matching behavior to either match all or any of the specified tests.
 * Tests are handled as semantic tests except in the case where \a symbol_type
 * is POLSEARCH_SYMBOL_ATTRIBUTE in which case the tests are considered syntactic.
 */
class polsearch_symbol_query
{
      public:
		/**
		 * Create a new symbol query.
		 * @param symbol_type The type of symbol to match; must be one of
		 * POLSEARCH_SYMBOL_* from above.
		 * @param match Set the matching behavior of the query, must be
		 * either POLSEARCH_MATCH_ALL or POLSEARCH_MATCH_ANY.
		 */
	polsearch_symbol_query(polsearch_symbol_e sym_type, polsearch_match_e match = POLSEARCH_MATCH_ALL);
		/**
		 * Copy a symbol query.
		 * @param sq The query to copy.
		 */
	polsearch_symbol_query(const polsearch_symbol_query & sq);
	//! Destructor.
	~polsearch_symbol_query();

		/**
		 * Get the symbol type matched by the query.
		 * @return The type of symbol matched.
		 */
	polsearch_symbol_e symbol_type() const;
		/**
		 * Get the matching behavior of the query.
		 * @return The current matching behavior of the query.
		 */
	polsearch_match_e match() const;
		/**
		 * Set the matching behavior of the query.
		 * @param m One of POLSEARCH_MATCH_ALL or POLSEARCH_MATCH_ANY to set.
		 * @return The behavior set.
		 */
	polsearch_match_e match(polsearch_match_e m);
		/**
		 * Get the vector of tests performed by the query.
		 * @return The vector of tests. The caller is free to modify this vector,
		 * but should not destroy it.
		 */
	apol_vector_t *tests();
		/**
		 * Run the query.
		 * @param policy The policy containing the symbols to match.
		 * @param fclist A file_contexts list to optionally use for tests that
		 * match file_context entries. It is an error to not provide \a fclist
		 * if a test matches file_context entries.
		 * @return A vector of symbols matching the query (see polsearch_symbol_e
		 * values for appropriate type of the vector's elements), or NULL on
		 * error. The caller is responsible for calling apol_vector_destroy()
		 * on the returned vector.
		 */
	apol_vector_t *run(const apol_policy_t * policy, const sefs_fclist_t * fclist = NULL) const;
		/**
		 * Get a list of the valid types of tests to perform for the symbol
		 * type specified by the query.
		 * @return A vector (of type polsearch_test_cond_e) containing all valid
		 * tests for the specified symbol type. The caller is responsible for
		 * calling apol_vector_destroy() on the returned vector.
		 */
	apol_vector_t *getValidTests() const;

      private:
	 polsearch_symbol_e _symbol_type;	/*!< The type of symbol matched by the query. */
	polsearch_match_e _match:      /*!< The matching behavior used for determining if a symbol matches with multiple tests. */
	 apol_vector_t * _tests;       /*!< The set of tests used by the query to determine which symbols match. */
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore the compatibility section.
#ifndef SWIG

	/** This typedef may safely be used in C to represent the class polsearch_symbol_query */
	typedef struct polsearch_symbol_query polsearch_symbol_query_t;

	/**
	 * Create a symbol query.
	 * @see polsearch_symbol_query::polsearch_symbol_query(polsearch_symbol_e, polsearch_match_e)
	 */
	polsearch_symbol_query_t *polsearch_symbol_query_create(polsearch_symbol_e symbol_type, polsearch_match_e match);
	/**
	 * Copy a symbol query.
	 * @see polsearch_symbol_query::polsearch_symbol_query(const polsearch_symbol_query&)
	 */
	polsearch_symbol_query_t *polsearch_symbol_query_create_from_symbol_query(const polsearch_symbol_query_t * sq);
	/**
	 * Deallocate all memory associated with a symbol query and set it to NULL.
	 * @param sq Reference pointer to the symbol query to destroy.
	 * @see polsearch_symbol_query::~polsearch_symbol_query()
	 */
	void polsearch_symbol_query_destroy(polsearch_symbol_query_t ** sq);

	/**
	 * Get the symbol type matched by a symbol query.
	 * @see polsearch_symbol_query::symbol_type()
	 */
	polsearch_symbol_e polsearch_symbol_query_get_symbol_type(const polsearch_symbol_query_t * sq);
	/**
	 * Get the symbol matching behavior from a symbol query.
	 * @see polsearch_symbol_query::match()
	 */
	polsearch_match_e polsearch_symbol_query_get_match(const polsearch_symbol_query_t * sq);
	/**
	 * Set the symbol matching behavior from a symbol query.
	 * @see polsearch_symbol_query::match(polsearch_match_e)
	 */
	polsearch_match_e polsearch_symbol_query_set_match(polsearch_symbol_query_t * sq, polsearch_match_e m);
	/**
	 * Get the vector of tests run by a symbol query.
	 * @see polsearch_symbol_query::tests()
	 */
	apol_vector_t *polsearch_symbol_query_get_tests(polsearch_symbol_query_t * sq);
	/**
	 * Run a symbol query.
	 * @param sq The query to run.
	 * @param p The policy containing the symbols to match.
	 * @param fclist A file_contexts list to optionally use for the tests that
	 * match file_context entries. It is an error to pass \a fclist as NULL if
	 * a test matches file_context entries.
	 * @return A vector of symbols matching the query (see polsearch_symbol_e
	 * values for appropriate type of the vector's elements), or NULL on
	 * error. The caller is responsible for calling apol_vector_destroy()
	 * on the returned vector.
	 * @see polsearch_symbol_query::run(apol_policy_t*, sefs_fclist_t*)
	 */
	apol_vector_t *polsearch_symbol_query_run(const polsearch_symbol_query_t * sq, const apol_policy_t * p, const sefs_fclist_t * fclist);
	/**
	 * Get a list of the valid types of tests to perform for the symol
	 * type specified by the query.
	 * @see polsearch_symbol_query::getValidTests()
	 */
	apol_vector_t *polsearch_symbol_query_get_valid_tests(const polsearch_symbol_query_t * sq);

#endif /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_SYMBOL_QUERY_H */
