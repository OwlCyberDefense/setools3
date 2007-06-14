/**
 * @file
 *
 * Routines to handle tests' criteria for logic queries.
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

#ifndef POLSEARCH_CRITERION_HH
#define POLSEARCH_CRITERION_HH

#include "string_list.hh"

#include <sefs/fclist.hh>

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include <apol/mls-query.h>
#include <apol/vector.h>
#include <apol/policy.h>

#ifdef __cplusplus
}

#include <stdexcept>

/**
 * A single criterion to be checked when running a test. This is the base
 * criterion with no parameter and by itself is not valid for use in a test;
 * use one of the specific criteria instead. This class also serves as a
 * uniform base type for vectors of criteria with different parameter types.
 */
class polsearch_base_criterion
{
      public:
	/**
	 * Create a generic criterion.
	 * @param opr Comparison operator to use.
	 * @param neg If \a true, invert the logic result of the operator.
	 * @exception std::invalid_argument Invalid operator requested.
	 */
	polsearch_base_criterion(polsearch_op_e opr, bool neg = false) throw(std::invalid_argument);
	/**
	 * Copy a generic criterion.
	 * @param pc The criterion to copy.
	 */
	polsearch_base_criterion(const polsearch_base_criterion & pc);
	//! Destructor.
	 virtual ~polsearch_base_criterion();

	/**
	 * Get the comparison operator used to check this criterion.
	 * @return The operator used.
	 */
	polsearch_op_e op() const;
	/**
	 * Determine if the comparison operator for this criterion is negated.
	 * @return \a true if negated, \a false otherwise
	 */
	bool negated() const;
	/**
	 * Set the flag to negate the comparison operator.
	 * @param neg If \a true, invert the logic result of the operator;
	 * if \a false do not invert.
	 * @return The state set.
	 */
	bool negated(bool neg);
	/**
	 * Get the type of parameter used by this criterion.
	 * @return The type of parameter (see polsearch_param_type_e).
	 */
	polsearch_param_type_e paramType() const;

	/**
	 * Check all candidates to find those meet this criterion.
	 * @param p The policy containing the elements to check.
	 * @param fclist The file_contexts list to use.
	 * @param test_candidates Vector of items to check. This vector will be
	 * pruned to only those candidates satisfying this criterion.
	 * <b>Must be non-null.</b>
	 * @param Xcandidtates Current list of possible candidates for the symbol X.
	 * <b>Must be non-null. Must not be the same vector as \a test_candidates. </b>
	 * @return A vector of result entries.
	 */
	virtual apol_vector_t *check(const apol_policy_t * p, const sefs_fclist_t * fclist,
				     apol_vector_t * test_candidates, const apol_vector_t * Xcandidtates) const = 0;

      protected:
	 polsearch_op_e _op;	       /*!< The comparison operator. */
	bool _negated;		       /*!< Negate operator flag. */
	polsearch_param_type_e _param_type;	/*!< Type of parameter. */
};

/**
 * Derived criterion class with arbitrary parameter.
 * @param T Type of parameter used when checking this criterion. This item will
 * be the second argument to the comparision operator \a _op.
 */
template<class T> class polsearch_criterion: public polsearch_base_criterion
{
	public:
		/**
		 * Create a new criterion.
		 * @param opr The comparison operator to use.
		 * @param neg If \a true, invert the logic result of the operator.
		 * @param parameter The second parameter to \a opr. This object will
		 * be duplicated by this call.
		 * @exception std::bad_alloc Could not copy \a parameter.
		 * @exception std::invalid_argument The type of \a parameter is not
		 * compatible with \a opr, or invalid operator requested.
		 */
		polsearch_criterion(polsearch_op_e opr = POLSEARCH_OP_NONE, bool neg = false, const T& parameter = 0) throw(std::bad_alloc, std::invalid_argument);
		/**
		 * Copy a criterion.
		 * @param pc Criterion to copy.
		 * @exception std::bad_alloc Could not copy parameter.
		 */
		polsearch_criterion(const polsearch_criterion<T>& pc) throw(std::bad_alloc);
		//! Destructor.
		~polsearch_criterion();
		/**
		 * Get the parameter of the criterion's comparison operator.
		 * @return The parameter used as the second argument of the comparison.
		 */
		const T& param() const;
		/**
		 * Set the parameter of the criterion's comparison operator.
		 * @param parameter The parameter to set.
		 * @return The parameter set.
		 */
		const T& parm(const T& parameter);
	/**
	 * Check all candidates to find those meet this criterion.
	 * @param p The policy containing the elements to check.
	 * @param fclist The file_contexts list to use.
	 * @param test_candidates Vector of items to check. This vector will be
	 * pruned to only those candidates satisfying this criterion.
	 * <b>Must be non-null.</b>
	 * @param Xcandidtates Current list of possible candidates for the symbol X.
	 * <b>Must be non-null. Must not be the same vector as \a test_candidates. </b>
	 * @return A vector of result entries.
	 */
		apol_vector_t *check(const apol_policy_t * p, const sefs_fclist_t * fclist,
				     apol_vector_t * test_candidates, const apol_vector_t * Xcandidtates) const;
	private:
		T _param; /*!< Parameter to check for this criterion. */
		/**
		 * Detect the type of parameter and verify that it is valid for
		 * the specified operator.
		 * @exception std::invalid_argument The type of \a parameter is not
		 * compatible with \a opr.
		 */
		void _detect_param_type() throw(std::invalid_argument);
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore the compatibility section.
#ifndef SWIG

	/** This typedef may be safely used in C to repesent any type of criterion;
	 * the template code and casting is handled within the compatibility code. */
	typedef struct polsearch_base_criterion polsearch_criterion_t;

	extern polsearch_criterion_t * polsearch_criterion_crate(polsearch_op_e opr, bool neg, polsearch_param_type_e param_type, const void * parameter);
	extern polsearch_criterion_t * polsearch_criterion_crete_from_criterion(const polsearch_criterion_t *pc);
	extern void polsearch_criterion_destroy(polsearch_criterion_t ** pc);
	extern polsearch_op_e polsearch_criterion_get_op(const polsearch_criterion_t * pc);
	extern bool polsearch_criterion_get_negated(const polsearch_criterion_t * pc);
	extern bool polsearch_criterion_set_negated(polsearch_criterion_t * pc);
	extern polsearch_param_type_e polsearch_criterion_get_param_type(const polsearch_criterion_t * pc);
	extern apol_vector_t *polsearch_criterion_check(const polsearch_criterion_t * pc, const apol_policy_t * p,
							const sefs_fclist_t * fclist, const apol_vector_t * test_candidates,
							apol_vector_t * Xcandidtates);
	extern const void * polsearch_criterion_get_param(const polsearch_criterion_t * pc);


#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_CRITERION_HH */
