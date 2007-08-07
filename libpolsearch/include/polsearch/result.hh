/**
 * @file
 *
 * Routines to create policy element test results.
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

#ifndef POLSEARCH_RESULT_HH
#define POLSEARCH_RESULT_HH

#include <polsearch/polsearch.hh>
#include <polsearch/test.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <string>
#include <vector>

/**
 * The results of a query including all proof for each criterion matched.
 */
class polsearch_result
{
      public:
	/**
	 * Copy a result entry.
	 * @param rhs The result to copy.
	 */
	polsearch_result(const polsearch_result & rhs);
	//! Destructor.
	~polsearch_result();

	/**
	 * Get the element type for this result entry.
	 * @return The element type.
	 */
	polsearch_element_e elementType() const;
	/**
	 * Get the element for this result entry.
	 * @return The element matched. The caller is responsible for casting the
	 * returned object to the correct type.
	 * @see See polsearch_result::elementType() to get the type of element
	 * and polsearch_element_e for the correct type to which to cast the
	 * returned object.
	 */
	const void *element() const;
	/**
	 * Get the proof that this element matches the query.
	 * @return Vector of proof (polsearch_proof).
	 */
	const std::vector < polsearch_proof > &proof() const;
	/**
	 * Return a string representing the result (but not all of its proof entries).
	 * @return A string representing the result.
	 * @see polsearch_proof::toString() to get the string representation of each
	 * proof entry.
	 */
	 std::string toString() const;

	friend const std::vector < polsearch_result > polsearch_test::run(apol_policy_t * policy, sefs_fclist * fclist,
									  std::vector <
									  const void *>&Xcandidates) const throw(std::
														 runtime_error);

	/**
	 * Add a new proof entry for this result.
	 * @param test The test condition satisfied by \a elem.
	 * @param elem_type The type of policy element for \a elem.
	 * @param elem The policy element representing the proof that \a test is satisfied.
	 * @param free_fn If non-null, function to call to free all memory used by \a elem.
	 * @return A reference to the newly added proof entry.
	 */
	 polsearch_proof & addProof(polsearch_test_cond_e test, polsearch_element_e elem_type, void *elem,
				    polsearch_proof_element_free_fn free_fn);

	/**
	 * Merge the proof entries from another result for the same element.
	 * @pre The element in result \a rhs is exactly the same object as \a _element.
	 * @param rhs The result containing the proof entries to merge. Its proof entries
	 * will be duplicated by this function.
	 * @post All proof entries from \a rhs are appended to current list of proof entries.
	 * @exception std::invalid_argument Attempt to merge results for different elements.
	 */
	void merge(const polsearch_result & rhs) throw(std::invalid_argument);

      protected:
	/**
	 * Create a result entry.
	 * @param elem_type Type of element found.
	 * @param elem Pointer to the element; the element is not owned by the result entry.
	 * @param p The policy associated with \a elem.
	 * @param fclist The file_contexts list associated with \a elem.
	 */
	 polsearch_result(polsearch_element_e elem_type, const void *elem, const apol_policy_t * p, sefs_fclist * fclist = NULL);

	/**
	 * Add a copy of a proof entry to this result.
	 * @param proof_entry The entry to copy and append.
	 * @return A reference to the proof entry appended.
	 */
	 polsearch_proof & addProof(const polsearch_proof & proof_entry);

      private:
	 polsearch_element_e _element_type;	/*!< The type of element. */
	const void *_element;	       /*!< The element matched. This object is not owned by the result. */
	 std::vector < polsearch_proof > _proof;	/*!< List of proof that \a _element matched the query. */
	const apol_policy_t *_policy;  /*!< The policy associated with \a _element. */
	sefs_fclist *_fclist;	       /*!< The fclist associated with \a _element. */
};

#endif				       /* POLSEARCH_RESULT_HH */
