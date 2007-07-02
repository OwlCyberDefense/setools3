/**
 * @file
 *
 * Top level library routines.
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

#ifndef POLSEARCH_HH
#define POLSEARCH_HH

/** Value to indicate the overall matching behavior of the query */
typedef enum polsearch_match
{
	POLSEARCH_MATCH_ERROR = -1,    /*!< Error condition. */
	POLSEARCH_MATCH_ALL = 0,       /*!< Returned symbols must match all tests. */
	POLSEARCH_MATCH_ANY	       /*!< Returned symbols must match at least one test. */
} polsearch_match_e;

/** Values to indicate the type of policy element. This is a superset of polsearch_symbol_e */
typedef enum polsearch_element
{
	POLSEARCH_ELEMENT_NONE = 0,    /*!< only used for error conditions */
	POLSEARCH_ELEMENT_TYPE,	       /*!< qpol_type_t */
	POLSEARCH_ELEMENT_ATTRIBUTE,   /*!< qpol_type_t */
	POLSEARCH_ELEMENT_ROLE,	       /*!< qpol_role_t */
	POLSEARCH_ELEMENT_USER,	       /*!< qpol_user_t */
	POLSEARCH_ELEMENT_CLASS,       /*!< qpol_class_t */
	POLSEARCH_ELEMENT_COMMON,      /*!< qpol_common_t */
	POLSEARCH_ELEMENT_CATEGORY,    /*!< qpol_cat_t */
	POLSEARCH_ELEMENT_LEVEL,       /*!< qpol_level_t */
	POLSEARCH_ELEMENT_BOOL,	       /*!< qpol_bool_t */
	POLSEARCH_ELEMENT_STRING,      /*!< char * */
	POLSEARCH_ELEMENT_AVRULE,      /*!< qpol_avrule_t */
	POLSEARCH_ELEMENT_TERULE,      /*!< qpol_terule_t */
	POLSEARCH_ELEMENT_ROLE_ALLOW,  /*!< qpol_role_allow_t */
	POLSEARCH_ELEMENT_ROLE_TRANS,  /*!< qpol_role_trans_t */
	POLSEARCH_ELEMENT_RANGE_TRANS, /*!< qpol_range_trans_t */
	POLSEARCH_ELEMENT_FC_ENTRY,    /*!< sefs_entry_t */
	POLSEARCH_ELEMENT_MLS_LEVEL,   /*!< apol_mls_level_t */
	POLSEARCH_ELEMENT_MLS_RANGE,   /*!< apol_mls_range_t */
	POLSEARCH_ELEMENT_PERMISSION,  /*!< char * */
	POLSEARCH_ELEMENT_BOOL_STATE   /*!< bool */
} polsearch_element_e;

/** Value to indicate the test condition */
typedef enum polsearch_test_cond
{
	POLSEARCH_TEST_NONE = 0,       /*!< only used for error conditions */
	POLSEARCH_TEST_NAME,	       /*!< primary name of the symbol */
	POLSEARCH_TEST_ALIAS,	       /*!< alias(es) of the symbol */
	POLSEARCH_TEST_ATTRIBUTES,     /*!< assigned attributes */
	POLSEARCH_TEST_ROLES,	       /*!< assigned roles (or assigned to roles) */
	POLSEARCH_TEST_AVRULE,	       /*!< there is an av rule */
	POLSEARCH_TEST_TERULE,	       /*!< there is a type rule */
	POLSEARCH_TEST_ROLEALLOW,      /*!< there is a role allow rule */
	POLSEARCH_TEST_ROLETRANS,      /*!< there is a role_transition rule */
	POLSEARCH_TEST_RANGETRANS,     /*!< there is a range_transition rule */
	POLSEARCH_TEST_FCENTRY,	       /*!< there is a file_contexts entry */
	POLSEARCH_TEST_TYPES,	       /*!< assigned types */
	POLSEARCH_TEST_USERS,	       /*!< assigned to users */
	POLSEARCH_TEST_DEFAULT_LEVEL,  /*!< its default level */
	POLSEARCH_TEST_RANGE,	       /*!< assigned range */
	POLSEARCH_TEST_COMMON,	       /*!< inherited common */
	POLSEARCH_TEST_PERMISSIONS,    /*!< assigned permissions */
	POLSEARCH_TEST_CATEGORIES,     /*!< assigned categories */
	POLSEARCH_TEST_STATE	       /*!< boolean default state */
} polsearch_test_cond_e;

/** Value to indicate the comparison operator for a parameter */
typedef enum polsearch_op
{
	POLSEARCH_OP_NONE = 0,	       /*!< only used for error conditions */
	POLSEARCH_OP_IS,	       /*!< symbol (or state) is */
	POLSEARCH_OP_MATCH_REGEX,      /*!< symbol name (or alias name) matches regular expression */
	POLSEARCH_OP_RULE_TYPE,	       /*!< is rule type */
	POLSEARCH_OP_INCLUDE,	       /*!< set includes */
	POLSEARCH_OP_AS_SOURCE,	       /*!< has as rule source */
	POLSEARCH_OP_AS_TARGET,	       /*!< has as rule target */
	POLSEARCH_OP_AS_CLASS,	       /*!< has as rule class */
	POLSEARCH_OP_AS_PERM,	       /*!< has as rule permission */
	POLSEARCH_OP_AS_DEFAULT,       /*!< has as rule default */
	POLSEARCH_OP_AS_SRC_TGT,       /*!< has as rule source or target */
	POLSEARCH_OP_AS_SRC_TGT_DFLT,  /*!< has as rule source, target, or default */
	POLSEARCH_OP_AS_SRC_DFLT,      /*!< has as rule source or default */
	POLSEARCH_OP_IN_COND,	       /*!< is in a conditional with boolean */
	POLSEARCH_OP_AS_LEVEL_EXACT,   /*!< user level exact comparison */
	POLSEARCH_OP_AS_LEVEL_DOM,     /*!< user level dominates parameter */
	POLSEARCH_OP_AS_LEVEL_DOMBY,   /*!< user level dominated by parameter */
	POLSEARCH_OP_AS_RANGE_EXACT,   /*!< has exactly range */
	POLSEARCH_OP_AS_RANGE_SUPER,   /*!< has range that is a superset of parameter */
	POLSEARCH_OP_AS_RANGE_SUB,     /*!< has that is a subset of parameter range */
	POLSEARCH_OP_AS_USER,	       /*!< has as user */
	POLSEARCH_OP_AS_ROLE,	       /*!< has as role */
	POLSEARCH_OP_AS_TYPE	       /*!< has as type */
} polsearch_op_e;

/** Value to indicate the type of the parameter value of a criterion */
typedef enum polsearch_param_type
{
	POLSEARCH_PARAM_TYPE_NONE = 0, /*!< only used for error conditions */
	POLSEARCH_PARAM_TYPE_REGEX,    /*!< parameter is a string (std::string) representing a regular expression */
	POLSEARCH_PARAM_TYPE_STR_EXPR, /*!< parameter is a string expression (polsearch_string_expression) */
	POLSEARCH_PARAM_TYPE_RULE_TYPE,	/*!< parameter is a rule type code (uint32_t) */
	POLSEARCH_PARAM_TYPE_BOOL,     /*!< parameter is a boolean value (bool) */
	POLSEARCH_PARAM_TYPE_LEVEL,    /*!< parameter is an apol_mls_level_t * */
	POLSEARCH_PARAM_TYPE_RANGE     /*!< parameter is an apol_mls_range_t * */
} polsearch_param_type_e;

//forward declaration of classes
class polsearch_query;
class polsearch_symbol_query;
class polsearch_test;
class polsearch_criterion;
class polsearch_parameter;
class polsearch_result;
class polsearch_proof;

#endif				       /* POLSEARCH_HH */
