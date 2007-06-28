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

#include <stdexcept>

using std::invalid_argument;

// internal functions

polsearch_element_e determine_candidate_type(polsearch_element_e elem_type,
					     polsearch_test_cond_e test_cond) throw(std::invalid_argument)
{
	//TODO
	return POLSEARCH_ELEMENT_NONE;
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
