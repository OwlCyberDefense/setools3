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

#include <polsearch/polsearch.hh>
#include "polsearch_internal.hh"

#include <apol/policy-query.h>

#include <stdexcept>
#include <vector>
#include <string>
#include <cerrno>
#include <cassert>

using std::invalid_argument;
using std::bad_alloc;
using std::vector;
using std::string;

// internal functions

polsearch_element_e determine_candidate_type(polsearch_test_cond_e test_cond) throw(std::invalid_argument)
{
	switch (test_cond)
	{
	case POLSEARCH_TEST_NAME:
	case POLSEARCH_TEST_ALIAS:
	{
		return POLSEARCH_ELEMENT_STRING;
	}
	case POLSEARCH_TEST_ATTRIBUTES:
	{
		return POLSEARCH_ELEMENT_ATTRIBUTE;
	}
	case POLSEARCH_TEST_ROLES:
	{
		return POLSEARCH_ELEMENT_ROLE;
	}
	case POLSEARCH_TEST_AVRULE:
	{
		return POLSEARCH_ELEMENT_AVRULE;
	}
	case POLSEARCH_TEST_TERULE:
	{
		return POLSEARCH_ELEMENT_TERULE;
	}
	case POLSEARCH_TEST_ROLEALLOW:
	{
		return POLSEARCH_ELEMENT_ROLE_ALLOW;
	}
	case POLSEARCH_TEST_ROLETRANS:
	{
		return POLSEARCH_ELEMENT_ROLE_TRANS;
	}
	case POLSEARCH_TEST_RANGETRANS:
	{
		return POLSEARCH_ELEMENT_RANGE_TRANS;
	}
	case POLSEARCH_TEST_TYPES:
	{
		return POLSEARCH_ELEMENT_TYPE;
	}
	case POLSEARCH_TEST_USERS:
	{
		return POLSEARCH_ELEMENT_USER;
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	{
		return POLSEARCH_ELEMENT_MLS_LEVEL;
	}
	case POLSEARCH_TEST_RANGE:
	{
		return POLSEARCH_ELEMENT_MLS_RANGE;
	}
	case POLSEARCH_TEST_COMMON:
	{
		return POLSEARCH_ELEMENT_COMMON;
	}
	case POLSEARCH_TEST_PERMISSIONS:
	{
		return POLSEARCH_ELEMENT_PERMISSION;
	}
	case POLSEARCH_TEST_CATEGORIES:
	{
		return POLSEARCH_ELEMENT_CATEGORY;
	}
	case POLSEARCH_TEST_STATE:
	{
		return POLSEARCH_ELEMENT_BOOL_STATE;
	}
	case POLSEARCH_TEST_FCENTRY:
	{
		return POLSEARCH_ELEMENT_FC_ENTRY;
	}
	case POLSEARCH_TEST_NONE:
	default:
	{
		// should not be possible to get here
		assert(0);
		throw invalid_argument("reached impossible state");
		return POLSEARCH_ELEMENT_NONE;
	}
	}
}

bool validate_test_condition(polsearch_element_e elem_type, polsearch_test_cond_e cond)
{
	switch (cond)
	{
	case POLSEARCH_TEST_NAME:
	{
		if (elem_type <= POLSEARCH_ELEMENT_BOOL)
			return true;
		break;
	}
	case POLSEARCH_TEST_ALIAS:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_LEVEL ||
		    elem_type == POLSEARCH_ELEMENT_CATEGORY)
			return true;
		break;
	}
	case POLSEARCH_TEST_ATTRIBUTES:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLES:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_USER)
			return true;
		break;
	}
	case POLSEARCH_TEST_AVRULE:
	case POLSEARCH_TEST_TERULE:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_ATTRIBUTE ||
		    elem_type == POLSEARCH_ELEMENT_CLASS)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLEALLOW:
	case POLSEARCH_TEST_USERS:
	{
		if (elem_type == POLSEARCH_ELEMENT_ROLE)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLETRANS:
	{
		if (elem_type == POLSEARCH_ELEMENT_ROLE || elem_type == POLSEARCH_ELEMENT_TYPE ||
		    elem_type == POLSEARCH_ELEMENT_ATTRIBUTE)
			return true;
		break;
	}
	case POLSEARCH_TEST_RANGETRANS:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_ATTRIBUTE ||
		    elem_type == POLSEARCH_ELEMENT_CLASS || elem_type == POLSEARCH_ELEMENT_LEVEL ||
		    elem_type == POLSEARCH_ELEMENT_CATEGORY)
			return true;
		break;
	}
	case POLSEARCH_TEST_FCENTRY:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_ROLE ||
		    elem_type == POLSEARCH_ELEMENT_CLASS || elem_type == POLSEARCH_ELEMENT_LEVEL ||
		    elem_type == POLSEARCH_ELEMENT_CATEGORY)
			return true;
		break;
	}
	case POLSEARCH_TEST_TYPES:
	{
		if (elem_type == POLSEARCH_ELEMENT_ROLE || elem_type == POLSEARCH_ELEMENT_ATTRIBUTE)
			return true;
		break;
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	case POLSEARCH_TEST_RANGE:
	{
		if (elem_type == POLSEARCH_ELEMENT_USER)
			return true;
		break;
	}
	case POLSEARCH_TEST_COMMON:
	{
		if (elem_type == POLSEARCH_ELEMENT_CLASS)
			return true;
		break;
	}
	case POLSEARCH_TEST_PERMISSIONS:
	{
		if (elem_type == POLSEARCH_ELEMENT_CLASS || elem_type == POLSEARCH_ELEMENT_COMMON)
			return true;
		break;
	}
	case POLSEARCH_TEST_CATEGORIES:
	{
		if (elem_type == POLSEARCH_ELEMENT_LEVEL)
			return true;
		break;
	}
	case POLSEARCH_TEST_STATE:
	{
		if (elem_type == POLSEARCH_ELEMENT_BOOL)
			return true;
		break;
	}
	case POLSEARCH_TEST_NONE:
	default:
	{
		return false;
	}
	}
	return false;
}

bool validate_operator(polsearch_element_e elem_type, polsearch_test_cond_e cond, polsearch_op_e opr)
{
	// First, validate that the condition makes sense for this element.
	if (!validate_test_condition(elem_type, cond))
		return false;

	switch (cond)
	{
	case POLSEARCH_TEST_NAME:
	{
		if (opr == POLSEARCH_OP_IS || opr == POLSEARCH_OP_MATCH_REGEX)
			return true;
		break;
	}
	case POLSEARCH_TEST_ALIAS:
	{
		if (opr == POLSEARCH_OP_MATCH_REGEX)
			return true;
		break;
	}
	case POLSEARCH_TEST_ATTRIBUTES:
	case POLSEARCH_TEST_ROLES:
	case POLSEARCH_TEST_TYPES:
	case POLSEARCH_TEST_USERS:
	case POLSEARCH_TEST_COMMON:
	case POLSEARCH_TEST_PERMISSIONS:
	case POLSEARCH_TEST_CATEGORIES:
	{
		if (opr == POLSEARCH_OP_INCLUDE)
			return true;
		break;
	}
	case POLSEARCH_TEST_AVRULE:
	{
		if (opr == POLSEARCH_OP_RULE_TYPE || opr == POLSEARCH_OP_AS_SOURCE ||
		    opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_CLASS ||
		    opr == POLSEARCH_OP_AS_SRC_TGT || opr == POLSEARCH_OP_IN_COND || opr == POLSEARCH_OP_AS_PERM)
			return true;
		break;
	}
	case POLSEARCH_TEST_TERULE:
	{
		if (opr == POLSEARCH_OP_RULE_TYPE || opr == POLSEARCH_OP_AS_SOURCE ||
		    opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_CLASS ||
		    opr == POLSEARCH_OP_AS_SRC_TGT || opr == POLSEARCH_OP_IN_COND ||
		    opr == POLSEARCH_OP_AS_DEFAULT || opr == POLSEARCH_OP_AS_SRC_DFLT || opr == POLSEARCH_OP_AS_SRC_TGT_DFLT)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLEALLOW:
	{
		if (opr == POLSEARCH_OP_AS_SOURCE || opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_SRC_TGT)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLETRANS:
	{
		if (opr == POLSEARCH_OP_AS_SOURCE || opr == POLSEARCH_OP_AS_TARGET ||
		    opr == POLSEARCH_OP_AS_DEFAULT || opr == POLSEARCH_OP_AS_SRC_DFLT)
			return true;
		break;
	}
	case POLSEARCH_TEST_RANGETRANS:
	{
		if (opr == POLSEARCH_OP_AS_RANGE_EXACT || opr == POLSEARCH_OP_AS_RANGE_SUPER ||
		    opr == POLSEARCH_OP_AS_RANGE_SUB || opr == POLSEARCH_OP_AS_SOURCE ||
		    opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_CLASS || opr == POLSEARCH_OP_AS_SRC_TGT)
			return true;
		break;
	}
	case POLSEARCH_TEST_FCENTRY:
	{
		if (opr == POLSEARCH_OP_AS_USER || opr == POLSEARCH_OP_AS_ROLE ||
		    opr == POLSEARCH_OP_AS_TYPE || opr == POLSEARCH_OP_AS_RANGE_EXACT || opr == POLSEARCH_OP_AS_RANGE_SUPER ||
		    opr == POLSEARCH_OP_AS_RANGE_SUB || opr == POLSEARCH_OP_AS_CLASS)
			return true;
		break;
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	{
		if (opr == POLSEARCH_OP_AS_LEVEL_EXACT || opr == POLSEARCH_OP_AS_LEVEL_DOM || opr == POLSEARCH_OP_AS_LEVEL_DOMBY)
			return true;
		break;
	}
	case POLSEARCH_TEST_RANGE:
	{
		if (opr == POLSEARCH_OP_AS_RANGE_EXACT || opr == POLSEARCH_OP_AS_RANGE_SUPER || opr == POLSEARCH_OP_AS_RANGE_SUB)
			return true;
		break;
	}
	case POLSEARCH_TEST_STATE:
	{
		if (opr == POLSEARCH_OP_IS)
			return true;
		break;
	}
	case POLSEARCH_TEST_NONE:
	default:
	{
		return false;
	}
	}
	return false;
}

bool validate_parameter_type(polsearch_element_e elem_type, polsearch_test_cond_e cond, polsearch_op_e opr,
			     polsearch_param_type_e param_type)
{
	if (!validate_operator(elem_type, cond, opr))
		return false;

	switch (opr)
	{
	case POLSEARCH_OP_IS:
	{
		if (cond == POLSEARCH_TEST_STATE && param_type == POLSEARCH_PARAM_TYPE_BOOL)
			return true;
		else if (param_type == POLSEARCH_PARAM_TYPE_STR_EXPR)
			return true;
		break;
	}
	case POLSEARCH_OP_MATCH_REGEX:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_REGEX)
			return true;
		break;
	}
	case POLSEARCH_OP_RULE_TYPE:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_RULE_TYPE)
			return true;
		break;
	}
	case POLSEARCH_OP_INCLUDE:
	case POLSEARCH_OP_AS_SOURCE:
	case POLSEARCH_OP_AS_TARGET:
	case POLSEARCH_OP_AS_CLASS:
	case POLSEARCH_OP_AS_PERM:
	case POLSEARCH_OP_AS_DEFAULT:
	case POLSEARCH_OP_AS_SRC_TGT:
	case POLSEARCH_OP_AS_SRC_TGT_DFLT:
	case POLSEARCH_OP_AS_SRC_DFLT:
	case POLSEARCH_OP_IN_COND:
	case POLSEARCH_OP_AS_USER:
	case POLSEARCH_OP_AS_ROLE:
	case POLSEARCH_OP_AS_TYPE:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_STR_EXPR)
			return true;
		break;
	}
	case POLSEARCH_OP_AS_LEVEL_EXACT:
	case POLSEARCH_OP_AS_LEVEL_DOM:
	case POLSEARCH_OP_AS_LEVEL_DOMBY:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_LEVEL)
			return true;
		break;
	}
	case POLSEARCH_OP_AS_RANGE_EXACT:
	case POLSEARCH_OP_AS_RANGE_SUPER:
	case POLSEARCH_OP_AS_RANGE_SUB:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_RANGE)
			return true;
		break;
	}
	case POLSEARCH_OP_NONE:
	default:
	{
		return false;
	}
	}

	return false;
}

const char *symbol_get_name(const void *symbol, polsearch_element_e sym_type, const apol_policy_t * policy)
{
	if (!policy)
	{
		errno = EINVAL;
		return NULL;
	}
	qpol_policy_t *qp = apol_policy_get_qpol(policy);
	const char *name = NULL;
	switch (sym_type)
	{
	case POLSEARCH_ELEMENT_TYPE:
	case POLSEARCH_ELEMENT_ATTRIBUTE:
	{
		qpol_type_get_name(qp, static_cast < const qpol_type_t * >(symbol), &name);
		break;
	}
	case POLSEARCH_ELEMENT_ROLE:
	{
		qpol_role_get_name(qp, static_cast < const qpol_role_t * >(symbol), &name);
		break;
	}
	case POLSEARCH_ELEMENT_USER:
	{
		qpol_user_get_name(qp, static_cast < const qpol_user_t * >(symbol), &name);
		break;
	}
	case POLSEARCH_ELEMENT_CLASS:
	{
		qpol_class_get_name(qp, static_cast < const qpol_class_t * >(symbol), &name);
		break;
	}
	case POLSEARCH_ELEMENT_COMMON:
	{
		qpol_common_get_name(qp, static_cast < const qpol_common_t * >(symbol), &name);
		break;
	}
	case POLSEARCH_ELEMENT_CATEGORY:
	{
		qpol_cat_get_name(qp, static_cast < const qpol_cat_t * >(symbol), &name);
		break;
	}
	case POLSEARCH_ELEMENT_LEVEL:
	{
		qpol_level_get_name(qp, static_cast < const qpol_level_t * >(symbol), &name);
		break;
	}
	case POLSEARCH_ELEMENT_BOOL:
	{
		qpol_bool_get_name(qp, static_cast < const qpol_bool_t * >(symbol), &name);
		break;
	}
	case POLSEARCH_ELEMENT_NONE:
	default:
	{
		errno = EINVAL;
		return NULL;
	}
	}
	return name;
}

vector < string > get_all_names(const void *element, polsearch_element_e elem_type,
				const apol_policy_t * policy)throw(std::bad_alloc)
{
	vector < string > ret_v;
	qpol_iterator_t *iter = NULL;
	const qpol_policy_t *qp = apol_policy_get_qpol(policy);

	const char *primary = symbol_get_name(element, elem_type, policy);

	if (primary)
		ret_v.push_back(string(primary));

	if (elem_type == POLSEARCH_ELEMENT_TYPE)
	{
		qpol_type_get_alias_iter(qp, static_cast < const qpol_type_t * >(element), &iter);
		if (!iter)
			throw bad_alloc();
	}
	else if (elem_type == POLSEARCH_ELEMENT_CATEGORY)
	{
		qpol_cat_get_alias_iter(qp, static_cast < const qpol_cat_t * >(element), &iter);
		if (!iter)
			throw bad_alloc();
	}
	else if (elem_type == POLSEARCH_ELEMENT_LEVEL)
	{
		qpol_level_get_alias_iter(qp, static_cast < const qpol_level_t * >(element), &iter);
		if (!iter)
			throw bad_alloc();
	}

	if (iter)
	{
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
		{
			void *name;
			qpol_iterator_get_item(iter, &name);
			ret_v.push_back(string(static_cast < const char *>(name)));
		}
	}
	qpol_iterator_destroy(&iter);

	return ret_v;
}

std::vector < std::string > mkvector(const apol_vector_t * rhs)
{
	vector < string > v;
	for (size_t i = 0; i < apol_vector_get_size(rhs); i++)
	{
		v.push_back(string(static_cast < char *>(apol_vector_get_element(rhs, i))));
	}
	return v;
}
