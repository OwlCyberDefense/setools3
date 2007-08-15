/**
 * @file
 *
 * Routines to handle tests' criteria.
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

#ifndef POLSEARCH_CRITERION_HH
#define POLSEARCH_CRITERION_HH

#include <string>
#include <vector>
#include <stdexcept>

#include <stdint.h>
#include <assert.h>

#include <polsearch/polsearch.hh>
#include <polsearch/test.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>

// forward declaration
class polsearch_test;

class polsearch_criterion
{
      public:
	/**
	 * Copy a criterion.
	 * @param rhs The criterion to copy.
	 */
	polsearch_criterion(const polsearch_criterion & rhs);
	//! Destructor.
	~polsearch_criterion();

	/**
	 * Get the operator used.
	 * @return The operator used.
	 */
	polsearch_op_e op() const;
	/**
	 * Set the operator to use.
	 * @param opr The operator to set.
	 * @return The operator set.
	 */
	polsearch_op_e op(polsearch_op_e opr);

	/**
	 * Get the negated flag.
	 * @return The negated flag.
	 */
	bool negated() const;
	/**
	 * Set the negated flag.
	 * @param neg If \a true, the logic result of the comparison operator
	 * will be negated.
	 * @return The value set.
	 */
	bool negated(bool neg);

	/**
	 * Get the test with which the criterion is associated.
	 * @return A pointer to the test with which the criterion is associated,
	 * or NULL if it has not yet been associated with any test.
	 */
	const polsearch_test *test() const;

	/**
	 * Get the parameter checked by the criterion.
	 * @return The parameter checked by the criterion.
	 */
	const polsearch_parameter *param() const;
	/**
	 * Get the parameter checked by the criterion.
	 * @return The parameter checked by the criterion.
	 */
	polsearch_parameter *param();
	/**
	 * Set the parameter to be checked by the criterion. If any previous
	 * parameter was set it will be deleted.
	 * @param p The parameter to set. The caller should not delete this
	 * parameter once it is associated with the criterion.
	 * @return The parameter set.
	 * @exception std::invalid_argument Parameter \a p is NULL or of the
	 * wrong type for the current operator.
	 */
	polsearch_parameter *param(polsearch_parameter * p) throw(std::invalid_argument);
	/**
	 * Get a list of valid parameter types for the criterion.
	 * @return A vector of all valid types of parameter the criterion can check.
	 */
	 std::vector < polsearch_param_type_e > getValidParamTypes() const;

	/**
	 * Get a string representing the criterion.
	 * @return A string representing the criterion.
	 */
	 std::string toString() const;

	friend class polsearch_test;
	friend int fcentry_callback(sefs_fclist * fclist, const sefs_entry * entry, void *data);

	/**
	 * DO NOT CALL. This default constructor is defined for SWIG.
	 * Criteria should be created via polsearch_test::addCriterion().
	 */
	 polsearch_criterion();
      protected:
	/**
		 * Check a list test candidates to see which of them match this criterion.
		 * @param policy The policy from which all relevant elements come.
		 * @param test_candidates The list of possible candidates to match.
		 * This vector will be pruned to only those candidates that match the criterion.
		 * @param Xnames A list of names valid for the symbol X.
		 * If empty, this list is ignored.
		 * @exception std::runtime_error Could not perform check.
		 * @exception std::bad_alloc Out of memory.
	 */
	void check(const apol_policy_t * policy, std::vector < const void *>&test_candidates,
		   const std::vector < std::string > &Xnames) const throw(std::runtime_error, std::bad_alloc);

		/**
		 * Create a criterion.
		 * @param Test The test with which the criterion is associated.
		 * @param opr The comparison operator to use.
		 * @param neg If \a true, invert the logic result of \a opr.
		 */
	 polsearch_criterion(const polsearch_test * Test, polsearch_op_e opr, bool neg = false) throw(std::invalid_argument);

      private:
	 polsearch_op_e _op;	       /*!< The comparison operator. */
	bool _negated;		       /*!< The negated flag. */
	const polsearch_test *_test;   /*!< The test with which the criterion is associated. */
	polsearch_parameter *_param;   /*!< The parameter used as the second argument or \a _op. */
};

#endif				       /* POLSEARCH_CRITERION_HH */
