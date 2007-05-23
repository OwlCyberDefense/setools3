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
		POLSEARCH_TEST_NONE = 0, /*!< only used for error conditions */
		POLSEARCH_TEST_NAME,     /*!< primary name of the symbol */
		POLSEARCH_TEST_ALIAS,    /*!< alias(es) of the symbol */
		POLSEARCH_TEST_ATTRIBUTES,	/*!< assigned attributes */
		POLSEARCH_TEST_ROLES,    /*!< assigned roles (or assigned to roles) */
		POLSEARCH_TEST_AVRULE,   /*!< there is an av rule */
		POLSEARCH_TEST_TERULE,   /*!< there is a type rule */
		POLSEARCH_TEST_ROLEALLOW,	/*!< there is a role allow rule */
		POLSEARCH_TEST_ROLETRANS,	/*!< there is a role_transition rule */
		POLSEARCH_TEST_RANGETRANS,	/*!< there is a range_transition rule */
		POLSEARCH_TEST_FCENTRY,  /*!< there is a file_contexts entry */
		POLSEARCH_TEST_TYPES,    /*!< assigned types */
		POLSEARCH_TEST_USERS,    /*!< assigned to users */
		POLSEARCH_TEST_DEFAULT_LEVEL,	/*!< its default level */
		POLSEARCH_TEST_RANGE,    /*!< assigned range */
		POLSEARCH_TEST_COMMON,   /*!< inherited common */
		POLSEARCH_TEST_PERMISSIONS,	/*!< assigned permissions */
		POLSEARCH_TEST_CATEGORIES,	/*!< assigned categories */
		POLSEARCH_TEST_STATE,    /*!< boolean default state */
	} polsearch_test_cond_e;

#ifdef __cplusplus
}

class polsearch_test
{
      public:
	polsearch_test(polsearch_symbol_e sym_type, polsearch_test_cond_e cond);
	polsearch_test(const polsearch_test & st);
	~polsearch_test();

	apol_vector_t *getValidOps() const;
	apol_vector_t *criteria();
	polsearch_symbol_e symbol_type() const;
	apol_vector_t *run(apol_policy_t * p, sefs_fclist * fclist, apol_vector_t * Xcandidates) const;
	polsearch_param_type_e getParamType(polsearch_op_e op) const;

      protected:
	apol_vector_t * _criteria;

      private:
	polsearch_symbol_e _symbol_type;
};

extern "C"
{
#endif

	//TODO extern C bindings

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_TEST_H */
