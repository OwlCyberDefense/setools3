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

#ifndef SERECON_TEST_H
#define SERECON_TEST_H

#include <apol/vector.h>

#include "serecon.hh"
#include "criterion.hh"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct serecon_test serecon_test_t;

/** Value to indicate the test condition */
	typedef enum serecon_test_cond
	{
		SERECON_TEST_NONE = 0, /*!< only used for error conditions */
		SERECON_TEST_NAME,     /*!< primary name of the symbol */
		SERECON_TEST_ALIAS,    /*!< alias(es) of the symbol */
		SERECON_TEST_ATTRIBUTES,	/*!< assigned attributes */
		SERECON_TEST_ROLES,    /*!< assigned roles (or assigned to roles) */
		SERECON_TEST_AVRULE,   /*!< there is an av rule */
		SERECON_TEST_TERULE,   /*!< there is a type rule */
		SERECON_TEST_ROLEALLOW,	/*!< there is a role allow rule */
		SERECON_TEST_ROLETRANS,	/*!< there is a role_transition rule */
		SERECON_TEST_RANGETRANS,	/*!< there is a range_transition rule */
		SERECON_TEST_FCENTRY,  /*!< there is a file_contexts entry */
		SERECON_TEST_TYPES,    /*!< assigned types */
		SERECON_TEST_USERS,    /*!< assigned to users */
		SERECON_TEST_DEFAULT_LEVEL,	/*!< its default level */
		SERECON_TEST_RANGE,    /*!< assigned range */
		SERECON_TEST_COMMON,   /*!< inherited common */
		SERECON_TEST_PERMISSIONS,	/*!< assigned permissions */
		SERECON_TEST_CATEGORIES,	/*!< assigned categories */
		SERECON_TEST_STATE,    /*!< boolean default state */
	} serecon_test_cond_e;

#ifdef __cplusplus
}

class serecon_test
{
      public:
	serecon_test(serecon_symbol_e sym_type, serecon_test_cond_e cond);
	serecon_test(const serecon_test & st);
	~serecon_test();

	apol_vector_t *getValidOps() const;
	apol_vector_t *criteria();
	serecon_symbol_e symbol_type() const;
	apol_vector_t *run(apol_policy_t * p, sefs_fclist * fclist, apol_vector_t * Xcandidates) const;
	serecon_param_type_e getParamType(serecon_op_e op) const;

      protected:
	apol_vector_t * _criteria;

      private:
	serecon_symbol_e _symbol_type;
};

extern "C"
{
#endif

	//TODO extern C bindings

#ifdef __cplusplus
}
#endif

#endif				       /* SERECON_TEST_H */
