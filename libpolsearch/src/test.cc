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

#include <polsearch/polsearch.hh>
#include <polsearch/criterion.hh>
#include <polsearch/test.hh>
#include "test_internal.hh"
#include "criterion_internal.hh"

#include <apol/vector.h>
#include <apol/policy.h>

#include <sefs/fclist.hh>

#include <errno.h>
#include <stdexcept>
#include <cstring>

using std::string;
using std::bad_alloc;
using std::invalid_argument;

const char *polsearch_test_cond_to_string(polsearch_test_cond_e test)
{
	switch (test)
	{
	case POLSEARCH_TEST_NAME:
	{
		return "its name";
	}
	case POLSEARCH_TEST_ALIAS:
	{
		return "it has an alias";
	}
	case POLSEARCH_TEST_ATTRIBUTES:
	{
		return "its assigned attributes";
	}
	case POLSEARCH_TEST_ROLES:
	{
		return "its assigned roles";
	}
	case POLSEARCH_TEST_AVRULE:
	{
		return "there is an av tule";
	}
	case POLSEARCH_TEST_TERULE:
	{
		return "there is a type rule";
	}
	case POLSEARCH_TEST_ROLEALLOW:
	{
		return "there is a role allow rule";
	}
	case POLSEARCH_TEST_ROLETRANS:
	{
		return "there is a role_transition rule";
	}
	case POLSEARCH_TEST_RANGETRANS:
	{
		return "there is a range_transition rule";
	}
	case POLSEARCH_TEST_FCENTRY:
	{
		return "there is a file_context entry";
	}
	case POLSEARCH_TEST_TYPES:
	{
		return "its assigned types";
	}
	case POLSEARCH_TEST_USERS:
	{
		return "it is assigned to users";
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	{
		return "its default level";
	}
	case POLSEARCH_TEST_RANGE:
	{
		return "its assigned range";
	}
	case POLSEARCH_TEST_COMMON:
	{
		return "its inherited common";
	}
	case POLSEARCH_TEST_PERMISSIONS:
	{
		return "its assigned permissions";
	}
	case POLSEARCH_TEST_CATEGORIES:
	{
		return "its assigned categories";
	}
	case POLSEARCH_TEST_STATE:
	{
		return "its default state";
	}
	case POLSEARCH_TEST_NONE:
	default:
	{
		return "";
	}
	}
}

// polsearch test

/**
 * Test if a test condition is valid for a particular element type.
 * @param elem_type The element type.
 * @param test_cond The test condition.
 * @return If test condition \a test_cond is valid for \a elem_type,
 * return \a true, otherwise, return \a false.
 */
static bool validate_elem_cond_combo(polsearch_element_e elem_type, polsearch_test_cond_e cond)
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

/**
 * Test if a comparison operator is valid for a particular test condition and
 * type of element.
 * @param elem_type The type of element.
 * @param cond The test condition.
 * @param opr The comparison operator.
 * @return If operator \a opr is valid for \a cond and \a elem, return \a true,
 * otherwise, return \a false.
 */
static bool validate_elem_cond_op_combo(polsearch_element_e elem_type, polsearch_test_cond_e cond, polsearch_op_e opr)
{
	// First, validate that the condition makes sense for this element.
	if (!validate_elem_cond_combo(elem_type, cond))
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
		if (opr == POLSEARCH_OP_AS_RANGE || opr == POLSEARCH_OP_AS_SOURCE ||
		    opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_CLASS || opr == POLSEARCH_OP_AS_SRC_TGT)
			return true;
		break;
	}
	case POLSEARCH_TEST_FCENTRY:
	{
		if (opr == POLSEARCH_OP_AS_USER || opr == POLSEARCH_OP_AS_ROLE ||
		    opr == POLSEARCH_OP_AS_TYPE || opr == POLSEARCH_OP_AS_RANGE || opr == POLSEARCH_OP_AS_CLASS)
			return true;
		break;
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	{
		if (opr == POLSEARCH_OP_AS_LEVEL)
			return true;
		break;
	}
	case POLSEARCH_TEST_RANGE:
	{
		if (opr == POLSEARCH_OP_AS_RANGE)
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

polsearch_test::polsearch_test(polsearch_element_e elem_type, polsearch_test_cond_e cond) throw(std::bad_alloc,
												std::invalid_argument)
{
	try
	{
		if (!validate_elem_cond_combo(elem_type, cond))
		{
			string str = "Invalid test: \"";
			str += polsearch_test_cond_to_string(cond);
			str += "\" for element: \"";
			str += polsearch_element_type_to_string(elem_type);
			str += "\".";
			throw invalid_argument(str);
		}
	}
	catch(invalid_argument x)
	{
		throw x;
	}
	_element_type = elem_type;
	_test_cond = cond;
	try
	{
		_criteria = apol_vector_create(free_criterion);
		if (!_criteria)
			throw bad_alloc();
	}
	catch(bad_alloc x)
	{
		throw x;
	}
}

polsearch_test::polsearch_test(const polsearch_test & pt) throw(std::bad_alloc)
{
	_element_type = pt._element_type;
	_test_cond = pt._test_cond;
	try
	{
		_criteria = apol_vector_create_from_vector(pt._criteria, dup_criterion, NULL, free_criterion);
		if (!_criteria)
			throw bad_alloc();
	}
	catch(bad_alloc x)
	{
		throw x;
	}
}

polsearch_test::~polsearch_test()
{
	apol_vector_destroy(&_criteria);
}

apol_vector_t *polsearch_test::getValidOps() const throw(std::bad_alloc)
{
	apol_vector_t *result_v = NULL;
	try
	{
		result_v = apol_vector_create(NULL);
		if (!result_v)
			throw bad_alloc();
		for (int op = POLSEARCH_OP_IS; op <= POLSEARCH_OP_AS_TYPE; op++)
			if (validate_elem_cond_op_combo(this->_element_type, this->_test_cond, static_cast < polsearch_op_e > (op)))
				if (apol_vector_append(result_v, reinterpret_cast < void *>(op)))
					throw bad_alloc();
	}
	catch(bad_alloc x)
	{
		throw x;
	}
	return result_v;
}

polsearch_param_type_e polsearch_test::getParamType(polsearch_op_e opr) const
{
	if (!validate_elem_cond_op_combo(this->_element_type, this->_test_cond, opr))
		return POLSEARCH_PARAM_TYPE_NONE;
	switch (opr)
	{
	case POLSEARCH_OP_IS:
	{
		if (this->_test_cond == POLSEARCH_TEST_STATE)
			return POLSEARCH_PARAM_TYPE_BOOL;
		else
			return POLSEARCH_PARAM_TYPE_STR_LIST;
	}
	case POLSEARCH_OP_MATCH_REGEX:
	{
		return POLSEARCH_PARAM_TYPE_REGEX;
	}
	case POLSEARCH_OP_INCLUDE:
	case POLSEARCH_OP_AS_SOURCE:
	case POLSEARCH_OP_AS_TARGET:
	case POLSEARCH_OP_AS_DEFAULT:
	case POLSEARCH_OP_AS_CLASS:
	case POLSEARCH_OP_AS_PERM:
	case POLSEARCH_OP_AS_SRC_TGT:
	case POLSEARCH_OP_AS_SRC_TGT_DFLT:
	case POLSEARCH_OP_AS_SRC_DFLT:
	case POLSEARCH_OP_IN_COND:
	case POLSEARCH_OP_AS_USER:
	case POLSEARCH_OP_AS_ROLE:
	case POLSEARCH_OP_AS_TYPE:
	{
		return POLSEARCH_PARAM_TYPE_STR_LIST;
	}
	case POLSEARCH_OP_RULE_TYPE:
	{
		return POLSEARCH_PARAM_TYPE_RULE_TYPE;
	}
	case POLSEARCH_OP_AS_LEVEL:
	{
		return POLSEARCH_PARAM_TYPE_LEVEL;
	}
	case POLSEARCH_OP_AS_RANGE:
	{
		return POLSEARCH_PARAM_TYPE_RANGE;
	}
	case POLSEARCH_OP_NONE:
	default:
	{
		return POLSEARCH_PARAM_TYPE_NONE;
	}
	}
}

apol_vector_t *polsearch_test::criteria()
{
	return _criteria;
}

polsearch_element_e polsearch_test::element_type() const
{
	return _element_type;
}

polsearch_test_cond_e polsearch_test::test_cond() const
{
	return _test_cond;
}

apol_vector_t *polsearch_test::run(const apol_policy_t * p, const sefs_fclist * fclist,
				   apol_vector_t * Xcandidates) const throw(std::bad_alloc)
{
	//TODO
	return NULL;
}

// polsearch result

polsearch_result::polsearch_result(polsearch_element_e elem_type, const void *elem)throw(std::bad_alloc)
{
	_element_type = elem_type;
	_element = elem;
	try
	{
		_proof = apol_vector_create(free_proof);
		if (!_proof)
			throw bad_alloc();
	}
	catch(bad_alloc x)
	{
		throw x;
	}
}

polsearch_result::polsearch_result(const polsearch_result & psr) throw(std::bad_alloc)
{
	_element_type = psr._element_type;
	_element = psr._element;
	try
	{
		_proof = apol_vector_create_from_vector(psr._proof, dup_proof, NULL, free_proof);
		if (!_proof)
			throw bad_alloc();
	}
	catch(bad_alloc x)
	{
		throw x;
	}
}

polsearch_result::~polsearch_result()
{
	apol_vector_destroy(&_proof);
}

polsearch_element_e polsearch_result::elementType() const
{
	return _element_type;
}

const void *polsearch_result::element() const
{
	return _element;
}

apol_vector_t *polsearch_result::proof()
{
	return _proof;
}

// polsearch proof

polsearch_proof::polsearch_proof(polsearch_test_cond_e test, polsearch_element_e elem_type, void *elem)
{
	_test_cond = test;
	_element_type = elem_type;
	_element = elem;
}

polsearch_proof::polsearch_proof(const polsearch_proof & pp)
{
	_test_cond = pp._test_cond;
	_element_type = pp._element_type;
	_element = pp._element;
}

polsearch_proof::~polsearch_proof()
{
	//nothing to do.
}

char *polsearch_proof::toString(const apol_policy_t * p, const sefs_fclist_t * fclist) const throw(std::bad_alloc)
{
	string str("");
	str += polsearch_test_cond_to_string(_test_cond);
	str += " ";
	str += polsearch_element_to_string(_element, _element_type, p, fclist);

	char *tmp = strdup(str.c_str());
	try
	{
		if (!tmp)
			throw bad_alloc();
	}
	catch(bad_alloc x)
	{
		throw x;
	}
	return tmp;
}

polsearch_element_e polsearch_proof::elementType() const
{
	return _element_type;
}

const void *polsearch_proof::element() const
{
	return _element;
}

polsearch_test_cond_e polsearch_proof::testCond() const
{
	return _test_cond;
}

// internal functions

void free_test(void *pt)
{
	delete static_cast < polsearch_test * >(pt);
}

void *dup_test(const void *pt, void *x __attribute__ ((unused)))
{
	return static_cast < void *>(new polsearch_test(*(static_cast < const polsearch_test * >(pt))));
}

void free_result(void *pr)
{
	delete static_cast < polsearch_result * >(pr);
}

void *dub_result(const void *pr, void *x __attribute__ ((unused)))
{
	return static_cast < void *>(new polsearch_result(*(static_cast < const polsearch_result * >(pr))));
}

void free_proof(void *pp)
{
	delete static_cast < polsearch_proof * >(pp);
}

void *dup_proof(const void *pp, void *x __attribute__ ((unused)))
{
	return static_cast < void *>(new polsearch_proof(*(static_cast < const polsearch_proof * >(pp))));
}

// C compatibility functions
