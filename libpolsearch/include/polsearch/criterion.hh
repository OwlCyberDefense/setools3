/**
 * @file
 *
 * Routines to handle tests' criteria for logic queries.
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
	 */
	virtual void check(const apol_policy_t * p, const sefs_fclist_t * fclist,
			   apol_vector_t * test_candidates, const apol_vector_t * Xcandidtates) const = 0;

      protected:
	 polsearch_op_e _op;	       /*!< The comparison operator. */
	bool _negated;		       /*!< Negate operator flag. */
	polsearch_param_type_e _param_type;	/*!< Type of parameter. */
};

/**
 * Derived criterion class with arbitrary parameter.
 * @param T Type of parameter used when checking this criterion. This item will
 * be the second argument to the comparison operator \a _op.
 */
template < class T > class polsearch_criterion:public polsearch_base_criterion
{
      public:
	/**
	 * Create a new criterion.
	 * @param parameter The second parameter to \a opr. This object will
	 * be duplicated by this call.
	 * @param opr The comparison operator to use.
	 * @param neg If \a true, invert the logic result of the operator.
	 * @exception std::bad_alloc Could not copy \a parameter.
	 * @exception std::invalid_argument The type of \a parameter is not
	 * compatible with \a opr, or invalid operator requested.
	 */
	polsearch_criterion(const T & parameter, polsearch_op_e opr, bool neg = false) throw(std::bad_alloc, std::invalid_argument);
	/**
	 * Copy a criterion.
	 * @param pc Criterion to copy.
	 * @exception std::bad_alloc Could not copy parameter.
	 */
	polsearch_criterion(const polsearch_criterion < T > &pc) throw(std::bad_alloc);
	//! Destructor.
	~polsearch_criterion();
	/**
	 * Get the parameter of the criterion's comparison operator.
	 * @return The parameter used as the second argument of the comparison.
	 */
	const T & param() const;
	/**
	 * Set the parameter of the criterion's comparison operator.
	 * @param parameter The parameter to set.
	 * @return The parameter set.
	 * @exception std::bad_alloc Could not copy \a parameter.
	 */
	const T & param(const T & parameter) throw(std::bad_alloc);
	/**
	 * Check all candidates to find those meet this criterion.
	 * @param p The policy containing the elements to check.
	 * @param fclist The file_contexts list to use.
	 * @param test_candidates Vector of items to check. This vector will be
	 * pruned to only those candidates satisfying this criterion.
	 * <b>Must be non-null.</b>
	 * @param Xcandidtates Current list of possible candidates for the symbol X.
	 * <b>Must be non-null. Must not be the same vector as \a test_candidates. </b>
	 */
	void check(const apol_policy_t * p, const sefs_fclist_t * fclist,
		   apol_vector_t * test_candidates, const apol_vector_t * Xcandidtates) const;
      private:
	T _param;		       /*!< Parameter to check for this criterion. */
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

	/**
	 * Allocate and initialize a new polsearch criterion.
	 * @param opr The comparison operator to use.
	 * @param neg If \a true, inver the logic result of the operator.
	 * @param param_type Type of parameter to use.
	 * @param parameter The parameter to set as the second argument to \a opr.
	 * @return A newly allocated criterion, or NULL on error; the caller is
	 * responsible for calling polsearch_criterion_destroy() on the returned
	 * object.
	 * @see polsearch_criterion<T>::polsearch_criterion(polsearch_op_e, bool, const T&)
	 */
	extern polsearch_criterion_t *polsearch_criterion_create(polsearch_op_e opr, bool neg, polsearch_param_type_e param_type,
								 const void *parameter);
	/**
	 * Copy a criterion.
	 * @param pc The criterion to copy.
	 * @return A newly allocated criterion that is a deep copy of \a pc; the
	 * caller is responsible for calling polsearch_criterion_destroy() on
	 * the returned object.
	 * @see polsearch_criterion<T>::polsearch_criterion(const polsearch_criterion<T>&)
	 */
	extern polsearch_criterion_t *polsearch_criterion_create_from_criterion(const polsearch_criterion_t * pc);
	/**
	 * Deallocate all memory associated with a criterion and set it to NULL.
	 * This function does nothing if \a pc is already NULL.
	 * @param pc The criterion to destroy.
	 * @see polsearch_criterion<T>::~polsearch_criterion()
	 */
	extern void polsearch_criterion_destroy(polsearch_criterion_t ** pc);
	/**
	 * Get the comparison operator used by a criterion.
	 * @param pc The criterion from which to get the operator.
	 * @return The operator used, or POLSEARCH_OP_NONE on error.
	 * @see polsearch_base_criterion::op()
	 */
	extern polsearch_op_e polsearch_criterion_get_op(const polsearch_criterion_t * pc);
	/**
	 * Get the value of the negated flag for a criterion.
	 * @param pc The criterion from which to get the flag.
	 * @return \a true if set, or \a false if not set or on error.
	 * @see polsearch_base_criterion::negated()
	 */
	extern bool polsearch_criterion_get_negated(const polsearch_criterion_t * pc);
	/**
	 * Set the negated flag for a criterion.
	 * @param pc The criterion for which to set the flag.
	 * @param neg The value to set. If \a true, invert the logic result
	 * of this criterion's comparison operator; if \a false, do not
	 * alter the result of comparison.
	 * @return The value set.
	 * @see polsearch_base_criterion::negated(bool)
	 */
	extern bool polsearch_criterion_set_negated(polsearch_criterion_t * pc, bool neg);
	/**
	 * Get the type of the parameter used by this criterion.
	 * @param pc The criterion from which to get the parameter type.
	 * @return The type of parameter or POLSEARCH_PARAM_TYPE_NONE on error.
	 * @see polsearch_base_criterion::paramType()
	 */
	extern polsearch_param_type_e polsearch_criterion_get_param_type(const polsearch_criterion_t * pc);
	/**
	 * Check all candidates to find those meet a criterion.
	 * @param pc The criterion to check.
	 * @param p The policy containing the elements to check.
	 * @param fclist The file_contexts list to use.
	 * @param test_candidates Vector of items to check. This vector will be
	 * pruned to only those candidates satisfying this criterion.
	 * <b>Must be non-null.</b>
	 * @param Xcandidtates Current list of possible candidates for the symbol X.
	 * <b>Must be non-null. Must not be the same vector as \a test_candidates. </b>
	 * @see polsearch_criterion<T>::check(const apol_policy_t*, const sefs_fclist_t*, apol_vector_t*, const apol_vector_t*)
	 */
	extern void polsearch_criterion_check(const polsearch_criterion_t * pc, const apol_policy_t * p,
					      const sefs_fclist_t * fclist, apol_vector_t * test_candidates,
					      const apol_vector_t * Xcandidtates);
	/**
	 * Get the parameter used by a criterion's comparison operator.
	 * <b>This function resets errno.</b>
	 * @param pc The criterion from which to get the parameter.
	 * @return The parameter used, or NULL on error. If the call fails,
	 * errno will be set; if it succeeds errno will be explicitly set
	 * to 0. The caller is responsible for casting the returned object
	 * to the type specified by polsearch_criterion_get_param_type().
	 * The types to use are as follows:
	 * <ul>
	 * <li>POLSEARCH_PARAM_TYPE_REGEX: Cast to (const char *). <b>Note: this is
	 * different than the typical use as C does not know anything about
	 * std::string and therefore cannot use it.</b></li>
	 * <li>POLSEARCH_PARAM_TYPE_STR_LIST: Cast to (const polsearch_string_list_t*).</li>
	 * <li>POLSEARCH_PARAM_TYPE_RULE_TYPE: Cast to (uint32_t).</li>
	 * <li>POLSEARCH_PARAM_TYPE_BOOL: Cast to (bool).</li>
	 * <li>POLSEARCH_PARAM_TYPE_LEVEL: Cast to (const apol_mls_level_t*).</li>
	 * <li>POLSEARCH_PARAM_TYPE_RANGE: Cast to (const apol_mls_range_t*).</li>
	 * <li>POLSEARCH_PARAM_TYPE_NONE: This is an error; do not use the criterion.</li>
	 * </ul>
	 * @see polsearch_criterion<T>::param()
	 */
	extern const void *polsearch_criterion_get_param(const polsearch_criterion_t * pc);
	/**
	 * Set the parameter to be used by a criterion as the second argument
	 * to the comparison operator. <b>This function resets errno.</b>
	 * @param pc The criterion for which to set the parameter.
	 * @param param_type The type of parameter to set. <b>Must match the type
	 * expected by the criterion.</b>
	 * @param parameter The parameter to set. If \a parameter is of a type
	 * that requires memory to be allocated, then it will be duplicated
	 * by this call.
	 * @return The parameter set or NULL on error. If the call fails, errno
	 * will be set; if it succeeds errno will be explicitly set to 0.
	 * @see polsearch_criterion<T>::param(const T&)
	 */
	extern const void *polsearch_criterion_set_param(polsearch_criterion_t * pc, polsearch_param_type_e param_type,
							 const void *parameter);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_CRITERION_HH */
