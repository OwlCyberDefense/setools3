/**
 * @file
 *
 * Routines to create logic tests.
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

#ifndef POLSEARCH_TEST_H
#define POLSEARCH_TEST_H

#include <apol/vector.h>

#include "polsearch.hh"
#include "criterion.hh"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct polsearch_test polsearch_test_t;

/** Value to indicate the test condition */
	typedef enum polsearch_test_cond
	{
		POLSEARCH_TEST_NONE = 0,	/*!< only used for error conditions */
		POLSEARCH_TEST_NAME,   /*!< primary name of the symbol */
		POLSEARCH_TEST_ALIAS,  /*!< alias(es) of the symbol */
		POLSEARCH_TEST_ATTRIBUTES,	/*!< assigned attributes */
		POLSEARCH_TEST_ROLES,  /*!< assigned roles (or assigned to roles) */
		POLSEARCH_TEST_AVRULE, /*!< there is an av rule */
		POLSEARCH_TEST_TERULE, /*!< there is a type rule */
		POLSEARCH_TEST_ROLEALLOW,	/*!< there is a role allow rule */
		POLSEARCH_TEST_ROLETRANS,	/*!< there is a role_transition rule */
		POLSEARCH_TEST_RANGETRANS,	/*!< there is a range_transition rule */
		POLSEARCH_TEST_FCENTRY,	/*!< there is a file_contexts entry */
		POLSEARCH_TEST_TYPES,  /*!< assigned types */
		POLSEARCH_TEST_USERS,  /*!< assigned to users */
		POLSEARCH_TEST_DEFAULT_LEVEL,	/*!< its default level */
		POLSEARCH_TEST_RANGE,  /*!< assigned range */
		POLSEARCH_TEST_COMMON, /*!< inherited common */
		POLSEARCH_TEST_PERMISSIONS,	/*!< assigned permissions */
		POLSEARCH_TEST_CATEGORIES,	/*!< assigned categories */
		POLSEARCH_TEST_STATE,  /*!< boolean default state */
	} polsearch_test_cond_e;

#ifdef __cplusplus
}

/**
 * Individual test to be run by a query. This test will check for a single
 * condition (such as a type having an attribute or a role being used in a
 * role_transition rule).
 */
class polsearch_test
{
      public:
	/**
	 * Create a new test.
	 * @param sym_type Type of symbol to test.
	 * @param cond Condition for which to test.
	 */
	polsearch_test(polsearch_symbol_e sym_type, polsearch_test_cond_e cond);
	/**
	 * Copy a test.
	 * @param pt Test to copy.
	 */
	polsearch_test(const polsearch_test & pt);
	//! Destructor.
	~polsearch_test();

	/**
	 * Get a list of the valid comparison operators for the symbol and
	 * condition of a test.
	 * @return Vector of valid operators (polsearch_op_e) or NULL on error.
	 * The caller is responsible for calling apol_vector_destroy() on the
	 * returned vector.
	 */
	apol_vector_t *getValidOps() const;
	/**
	 * Get the type of parameter to use for the test criterion for the
	 * given comparison operator.
	 * @param opr The comparison operator for which to get the parameter type.
	 * @return The type of parameter or POLSEARCH_PARAM_TYPE_NONE on error.
	 */
	polsearch_param_type_e getParamType(polsearch_op_e opr) const;
	/**
	 * Get the vector of criteria checked by this test.
	 * @return The vector of criteria. The caller is free to modify this
	 * vector but should not destroy it.
	 */
	apol_vector_t *criteria();
	/**
	 * Get the symbol type tested by a test.
	 * @return The type of symbol tested.
	 */
	polsearch_symbol_e symbol_type() const;
	/**
	 * Get the condition for which a test checks.
	 * @return The condition tested.
	 */
	polsearch_test_cond_e test_cond() const;
	/**
	 * Run the test. This finds all symbols of the specified type that
	 * meet all criteria for the test.
	 * @param p The policy containing the symbols to test.
	 * @param fclist The file_contexts list to use for conditions that
	 * check for file_context entries. (Optional)
	 * @param Xcandidates The list of currenly valid candidates for the test.
	 * If null, all symbols of the specified type are considered candidates.
	 * @return A vector of all symbols of the appropriate type (see
	 * polsearch_symbol_e) or NULL on error. The caller is responsible for
	 * calling apol_vector_destroy() on the returned vector. The size of the
	 * returned vector may be zero, indicating that none of the candidates
	 * satisfied all criteria for the test.
	 */
	apol_vector_t *run(const apol_policy_t * p, const sefs_fclist * fclist, apol_vector_t * Xcandidates) const;

      private:
	apol_vector_t * _criteria; /*!< The list of criteria. */
	polsearch_symbol_e _symbol_type; /*!< The type of symbol tested. */
	polsearch_test_cond_e _test_cond; /*!< The condition for which the test checks. */
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore the compatibility section.
#ifndef SWIG

	/** This typedef may safely be used in C to represent the class polsearch_test */
	typedef struct polsearch_test polsearch_test_t;

	/**
	 * Create a test.
	 * @see polsearch_test::polsearch_test(polsearch_symbol_e, polsearch_test_cond_e)
	 */
	polsearch_test_t * polsearch_test_create(polsearch_symbol_e sym_type, polsearch_test_cond_e cond);
	/**
	 * Copy a test.
	 * @see polsearch_test::polsearch_test(const polsearch_test&)
	 */
	polsearch_test_t * polsearch_test_create_from_test(const polsearch_test_t * pt);
	/**
	 * Deallocate all memory associated with a test and set it to NULL.
	 * @param pt Reference pointer to the test to destroy.
	 * @see polsearch_test::~polsearch_test()
	 */
	void polsearch_test_destroy(polsearch_test_t ** pt);
	/**
	 * Get a list of valid comparison operators for a test.
	 * @see polsearch_test::getValidOps()
	 */
	apol_vector_t * polsearch_test_get_valid_ops(const polsearch_test_t * pt);
	/**
	 * Get the list of criteria checked.
	 * @see polsearch_test::criteria()
	 */
	apol_vector_t * polsearch_test_get_criteria(polsearch_test_t * pt);
	/**
	 * Get the type of symbol used by a test.
	 * @see polsearch_test::symbol_type()
	 */
	polsearch_symbol_e polsearch_test_get_symbol_type(const polsearch_test_t *pt);
	/**
	 * Get the condition for which a test checks.
	 * @see polsearch_test::test_cond()
	 */
	polsearch_test_cond_e polsearch_test_get_test_cond(const polsearch_test_t *pt);
	/**
	 * Run the test.
	 * @see polsearch_test::run()
	 */
	apol_vector_t * polsearch_test_run(const polsearch_test_t *pt, const apol_policy_t * p, const sefs_fclist * fclist, apol_vector_t * Xcandidates);
	/**
	 * Get the correct type of parameter to use for a criterion of a
	 * given comparison operator.
	 * @see polsearch_test::getParamType()
	 */
	polsearch_param_type_e polsearch_test_get_param_type(const polsearch_test_t *pt, polsearch_op_e opr);

#endif /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_TEST_H */
