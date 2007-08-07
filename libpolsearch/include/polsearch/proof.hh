/**
 * @file
 *
 * Routines to create policy element test result proof entries.
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

#ifndef POLSEARCH_PROOF_HH
#define POLSEARCH_PROOF_HH

#include <polsearch/polsearch.hh>
#include <polsearch/result.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <string>
#include <vector>

/**
 * Individual proof entry created when a policy element matches a test
 * condition. The proof element is another policy element which proves that
 * the tested element (as stored by the query result) matches the test.
 * (Examples include the specific attribute a type has and the rule using a
 * specific role.)
 */
class polsearch_proof
{
	public:
	/**
	 * Copy a proof.
	 * @param pp The proof to copy.
	 */
	polsearch_proof(const polsearch_proof & pp);
	//! Destructor.
	~polsearch_proof();

	/**
	 * Return a string representing the proof.
	 * @return A string representing the proof.
	 */
	std::string toString() const;
	/**
	 * Get the type of element stored in the proof.
	 * @return The type of element stored in the proof.
	 */
	polsearch_element_e elementType() const;
	/**
	 * Get the element stored in the proof.
	 * @return The element stored in the proof.
	 */
	const void *element() const;
	/**
	 * Get the test condition the element statisfied.
	 * @return The test condition.
	 */
	polsearch_test_cond_e testCond() const;

	friend polsearch_proof & polsearch_result::addProof(polsearch_test_cond_e test, polsearch_element_e elem_type, void *elem, polsearch_proof_element_free_fn free_fn);
	friend int fcentry_callback(sefs_fclist * fclist, const sefs_entry * entry, void *data);

	protected:
	/**
	 * Create a new poof entry.
	 * @param test The test condition proved by this entry.
	 * @param elem_type The type of element used as proof.
	 * @param elem The element that proves the test.
	 * @param p The policy associated with \a elem.
	 * @param fclist The file_contexts list associated with \a elem.
	 * @param free_fn Callback to be envoked if \a elem should be freed.
	 * If NULL, do not free \a elem when this proof is destroyed.
	 */
	polsearch_proof(polsearch_test_cond_e test, polsearch_element_e elem_type, void *elem, const apol_policy_t * p, sefs_fclist * fclist, polsearch_proof_element_free_fn free_fn = NULL);

	private:
	polsearch_test_cond_e _test_cond;	/*!< Test condition matched by the element */
	polsearch_element_e _element_type;	/*!< The type of element to display as proof (may not be same type as tested element). */
	void *_element;		       /*!< The element to display as proof. */
	const apol_policy_t *_policy;  /*!< The policy associated with \a _element. */
	sefs_fclist_t *_fclist;	       /*!< The fclist associated with \a _element. */
	polsearch_proof_element_free_fn _free_fn;	/*!< Function to be called to free \a _element if needed. */
};

#endif /* POLSEARCH_PROOF_HH */
