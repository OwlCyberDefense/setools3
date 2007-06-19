/**
 * @file
 *
 * Routines to create logic tests.
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
#include <polsearch/criterion.hh>
#include <polsearch/test.hh>
#include "test_internal.hh"
#include "criterion_internal.hh"

#include <apol/vector.h>
#include <apol/policy.h>
#include <apol/mls_range.h>
#include <apol/mls_level.h>

#include <sefs/fclist.hh>
#include <sefs/entry.hh>

#include <errno.h>
#include <stdexcept>
#include <cstring>
#include <stdlib.h>
#include <assert.h>

using std::string;
using std::bad_alloc;
using std::invalid_argument;

// polsearch test

polsearch_test::polsearch_test(polsearch_element_e elem_type, polsearch_test_cond_e cond) throw(std::bad_alloc,
												std::invalid_argument)
{
	if (!polsearch_validate_test_condition(elem_type, cond))
	{
		string str = "Invalid test: \"";
		str += polsearch_test_cond_to_string(cond);
		str += "\" for element: \"";
		str += polsearch_element_type_to_string(elem_type);
		str += "\".";
		throw invalid_argument(str);
	}
	_element_type = elem_type;
	_test_cond = cond;
	_criteria = apol_vector_create(free_criterion);
	if (!_criteria)
		throw bad_alloc();
}

polsearch_test::polsearch_test(const polsearch_test & pt) throw(std::bad_alloc)
{
	_element_type = pt._element_type;
	_test_cond = pt._test_cond;
	_criteria = apol_vector_create_from_vector(pt._criteria, dup_criterion, NULL, free_criterion);
	if (!_criteria)
		throw bad_alloc();
}

polsearch_test::~polsearch_test()
{
	apol_vector_destroy(&_criteria);
}

apol_vector_t *polsearch_test::getValidOps() const throw(std::bad_alloc)
{
	apol_vector_t *result_v = NULL;
	result_v = apol_vector_create(NULL);
	if (!result_v)
		throw bad_alloc();
	for (int op = POLSEARCH_OP_IS; op <= POLSEARCH_OP_AS_TYPE; op++)
		if (polsearch_validate_operator(this->_element_type, this->_test_cond, static_cast < polsearch_op_e > (op)))
			if (apol_vector_append(result_v, reinterpret_cast < void *>(op)))
				throw bad_alloc();
	return result_v;
}

polsearch_param_type_e polsearch_test::getParamType(polsearch_op_e opr) const
{
	if (!polsearch_validate_operator(this->_element_type, this->_test_cond, opr))
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
	case POLSEARCH_OP_AS_LEVEL_EXACT:
	case POLSEARCH_OP_AS_LEVEL_DOM:
	case POLSEARCH_OP_AS_LEVEL_DOMBY:
	{
		return POLSEARCH_PARAM_TYPE_LEVEL;
	}
	case POLSEARCH_OP_AS_RANGE_EXACT:
	case POLSEARCH_OP_AS_RANGE_SUPER:
	case POLSEARCH_OP_AS_RANGE_SUB:
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

polsearch_element_e polsearch_test::elementType() const
{
	return _element_type;
}

polsearch_test_cond_e polsearch_test::testCond() const
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

polsearch_result::polsearch_result(polsearch_element_e elem_type, const void *elem, const apol_policy_t * p,
				   const sefs_fclist * fclist)throw(std::bad_alloc)
{
	_element_type = elem_type;
	_element = elem;
	_policy = p;
	_fclist = fclist;
	_proof = apol_vector_create(free_proof);
	if (!_proof)
		throw bad_alloc();
}

polsearch_result::polsearch_result(const polsearch_result & psr) throw(std::bad_alloc)
{
	_element_type = psr._element_type;
	_element = psr._element;
	_policy = psr._policy;
	_fclist = psr._fclist;
	_proof = apol_vector_create_from_vector(psr._proof, dup_proof, NULL, free_proof);
	if (!_proof)
		throw bad_alloc();
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

char *polsearch_result::toString() const throw(std::bad_alloc)
{
	char *tmp = NULL;
	tmp = polsearch_element_to_string(_element, _element_type, _policy, _fclist);
	if (!tmp)
		throw bad_alloc();
	return tmp;
}

// polsearch proof

polsearch_proof::polsearch_proof(polsearch_test_cond_e test, polsearch_element_e elem_type, void *elem, const apol_policy_t * p,
				 const sefs_fclist * fclist)
{
	_test_cond = test;
	_element_type = elem_type;
	_element = elem;
	_policy = p;
	_fclist = fclist;
}

polsearch_proof::polsearch_proof(const polsearch_proof & pp)
{
	_test_cond = pp._test_cond;
	_element_type = pp._element_type;
	_element = pp._element;
	_policy = pp._policy;
	_fclist = pp._fclist;
}

polsearch_proof::~polsearch_proof()
{
	//nothing to do.
}

char *polsearch_proof::toString() const throw(std::bad_alloc)
{
	char *tmp = NULL;
	string str("");
	str += polsearch_test_cond_to_string(_test_cond);
	str += " ";
	str += (tmp = polsearch_element_to_string(_element, _element_type, _policy, _fclist));
	if (!tmp)
		throw bad_alloc();
	free(tmp);
	tmp = strdup(str.c_str());
	if (!tmp)
		throw bad_alloc();
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
	try
	{
		return static_cast < void *>(new polsearch_test(*(static_cast < const polsearch_test * >(pt))));
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

void free_result(void *pr)
{
	delete static_cast < polsearch_result * >(pr);
}

void *dup_result(const void *pr, void *x __attribute__ ((unused)))
{
	try
	{
		return static_cast < void *>(new polsearch_result(*(static_cast < const polsearch_result * >(pr))));
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

int result_cmp(const void *a, const void *b, void *data)
{
	const polsearch_result *left = static_cast < const polsearch_result * >(a);
	const polsearch_result *right = static_cast < const polsearch_result * >(b);
	apol_policy_t *policy = static_cast < apol_policy_t * >(data);
	const qpol_policy_t *q = apol_policy_get_qpol(policy);

	// comparison makes no sense if results are not same element type
	assert(left->elementType() == right->elementType());
	switch (left->elementType())
	{
	case POLSEARCH_ELEMENT_TYPE:
	case POLSEARCH_ELEMENT_ATTRIBUTE:
	case POLSEARCH_ELEMENT_ROLE:
	case POLSEARCH_ELEMENT_USER:
	case POLSEARCH_ELEMENT_CLASS:
	case POLSEARCH_ELEMENT_COMMON:
	case POLSEARCH_ELEMENT_CATEGORY:
	case POLSEARCH_ELEMENT_LEVEL:
	case POLSEARCH_ELEMENT_BOOL:
	{
		return strcmp(polsearch_symbol_get_name
			      (left->element(), static_cast < polsearch_symbol_e > (left->elementType()), policy),
			      polsearch_symbol_get_name(right->element(), static_cast < polsearch_symbol_e > (right->elementType()),
							policy));
	}
	case POLSEARCH_ELEMENT_STRING:
	case POLSEARCH_ELEMENT_PERMISSION:
	{
		return strcmp(static_cast < const char *>(left->element()), static_cast < const char *>(right->element()));
	}
	case POLSEARCH_ELEMENT_AVRULE:
	{
		const qpol_avrule_t *lrule = static_cast < const qpol_avrule_t * >(left->element());
		const qpol_avrule_t *rrule = static_cast < const qpol_avrule_t * >(right->element());
		int retv = 0;
		// compare rule type
		uint32_t lt;
		qpol_avrule_get_rule_type(q, lrule, &lt);
		uint32_t rt;
		qpol_avrule_get_rule_type(q, rrule, &rt);
		if ((retv = lt - rt))
			return retv;
		// compare source name
		const qpol_type_t *ltype;
		qpol_avrule_get_source_type(q, lrule, &ltype);
		const qpol_type_t *rtype;
		qpol_avrule_get_source_type(q, rrule, &rtype);
		const char *lname;
		qpol_type_get_name(q, ltype, &lname);
		const char *rname;
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare target name
		qpol_avrule_get_target_type(q, lrule, &ltype);
		qpol_avrule_get_target_type(q, rrule, &rtype);
		qpol_type_get_name(q, ltype, &lname);
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare class name
		const qpol_class_t *lclass;
		qpol_avrule_get_object_class(q, lrule, &lclass);
		const qpol_class_t *rclass;
		qpol_avrule_get_object_class(q, rrule, &rclass);
		qpol_class_get_name(q, lclass, &lname);
		qpol_class_get_name(q, rclass, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare conditional (pointer comparison only)
		const qpol_cond_t *lcond;
		qpol_avrule_get_cond(q, lrule, &lcond);
		const qpol_cond_t *rcond;
		qpol_avrule_get_cond(q, rrule, &rcond);
		if ((retv = reinterpret_cast < const ssize_t > (lcond) - reinterpret_cast < const ssize_t > (rcond)))
			return retv;
		// semantic rules with same key; should be the same rule.
		return 0;
	}
	case POLSEARCH_ELEMENT_TERULE:
	{
		const qpol_terule_t *lrule = static_cast < const qpol_terule_t * >(left->element());
		const qpol_terule_t *rrule = static_cast < const qpol_terule_t * >(right->element());
		int retv = 0;
		// compare rule type
		uint32_t lt;
		qpol_terule_get_rule_type(q, lrule, &lt);
		uint32_t rt;
		qpol_terule_get_rule_type(q, rrule, &rt);
		if ((retv = lt - rt))
			return retv;
		// compare source name
		const qpol_type_t *ltype;
		qpol_terule_get_source_type(q, lrule, &ltype);
		const qpol_type_t *rtype;
		qpol_terule_get_source_type(q, rrule, &rtype);
		const char *lname;
		qpol_type_get_name(q, ltype, &lname);
		const char *rname;
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare target name
		qpol_terule_get_target_type(q, lrule, &ltype);
		qpol_terule_get_target_type(q, rrule, &rtype);
		qpol_type_get_name(q, ltype, &lname);
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare class name
		const qpol_class_t *lclass;
		qpol_terule_get_object_class(q, lrule, &lclass);
		const qpol_class_t *rclass;
		qpol_terule_get_object_class(q, rrule, &rclass);
		qpol_class_get_name(q, lclass, &lname);
		qpol_class_get_name(q, rclass, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare conditional (pointer comparison only)
		const qpol_cond_t *lcond;
		qpol_terule_get_cond(q, lrule, &lcond);
		const qpol_cond_t *rcond;
		qpol_terule_get_cond(q, rrule, &rcond);
		if ((retv = reinterpret_cast < const ssize_t > (lcond) - reinterpret_cast < const ssize_t > (rcond)))
			return retv;
		// semantic rules with same key; should be the same rule.
		return 0;
	}
	case POLSEARCH_ELEMENT_ROLE_ALLOW:
	{
		const qpol_role_allow_t *lrule = static_cast < const qpol_role_allow_t * >(left->element());
		const qpol_role_allow_t *rrule = static_cast < const qpol_role_allow_t * >(right->element());
		// compare source role
		const qpol_role_t *lrole;
		qpol_role_allow_get_source_role(q, lrule, &lrole);
		const qpol_role_t *rrole;
		qpol_role_allow_get_source_role(q, rrule, &rrole);
		const char *lname;
		qpol_role_get_name(q, lrole, &lname);
		const char *rname;
		qpol_role_get_name(q, rrole, &rname);
		int retv;
		if ((retv = strcmp(lname, rname)))
			return retv;
		// conpare target
		qpol_role_allow_get_target_role(q, lrule, &lrole);
		qpol_role_allow_get_target_role(q, rrule, &rrole);
		qpol_role_get_name(q, lrole, &lname);
		qpol_role_get_name(q, rrole, &rname);
		return strcmp(lname, rname);
	}
	case POLSEARCH_ELEMENT_ROLE_TRANS:
	{
		const qpol_role_trans_t *lrule = static_cast < const qpol_role_trans_t * >(left->element());
		const qpol_role_trans_t *rrule = static_cast < const qpol_role_trans_t * >(right->element());
		// compare source role
		const qpol_role_t *lrole;
		qpol_role_trans_get_source_role(q, lrule, &lrole);
		const qpol_role_t *rrole;
		qpol_role_trans_get_source_role(q, rrule, &rrole);
		const char *lname;
		qpol_role_get_name(q, lrole, &lname);
		const char *rname;
		qpol_role_get_name(q, rrole, &rname);
		int retv;
		if ((retv = strcmp(lname, rname)))
			return retv;
		// conpare target type
		const qpol_type_t *ltype;
		qpol_role_trans_get_target_type(q, lrule, &ltype);
		const qpol_type_t *rtype;
		qpol_role_trans_get_target_type(q, rrule, &rtype);
		qpol_type_get_name(q, ltype, &lname);
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare default role
		qpol_role_trans_get_default_role(q, lrule, &lrole);
		qpol_role_trans_get_default_role(q, rrule, &rrole);
		qpol_role_get_name(q, lrole, &lname);
		qpol_role_get_name(q, rrole, &rname);
		return strcmp(lname, rname);
	}
	case POLSEARCH_ELEMENT_RANGE_TRANS:
	{
		const qpol_range_trans_t *lrule = static_cast < const qpol_range_trans_t * >(left->element());
		const qpol_range_trans_t *rrule = static_cast < const qpol_range_trans_t * >(right->element());
		// compare source type
		const qpol_type_t *ltype;
		qpol_range_trans_get_source_type(q, lrule, &ltype);
		const qpol_type_t *rtype;
		qpol_range_trans_get_source_type(q, rrule, &rtype);
		const char *lname;
		qpol_type_get_name(q, ltype, &lname);
		const char *rname;
		qpol_type_get_name(q, rtype, &rname);
		int retv;
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare target type
		qpol_range_trans_get_target_type(q, lrule, &ltype);
		qpol_range_trans_get_target_type(q, rrule, &rtype);
		qpol_type_get_name(q, ltype, &lname);
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare object class
		const qpol_class_t *lclass;
		qpol_range_trans_get_target_class(q, lrule, &lclass);
		const qpol_class_t *rclass;
		qpol_range_trans_get_target_class(q, rrule, &rclass);
		qpol_class_get_name(q, lclass, &lname);
		qpol_class_get_name(q, rclass, &rname);
		return strcmp(lname, rname);
	}
	case POLSEARCH_ELEMENT_FC_ENTRY:
	{
		const sefs_entry *le = static_cast < const sefs_entry * >(left->element());
		const sefs_entry *re = static_cast < const sefs_entry * >(right->element());
		char *ls = le->toString();
		char *rs = re->toString();
		int ret = strcmp(ls, rs);
		free(ls);
		free(rs);
		return ret;
	}
	case POLSEARCH_ELEMENT_MLS_RANGE:
	{
		const apol_mls_range_t *lr = static_cast < const apol_mls_range_t * >(left->element());
		const apol_mls_range_t *rr = static_cast < const apol_mls_range_t * >(right->element());

		if (apol_mls_range_compare(policy, lr, rr, APOL_QUERY_EXACT) > 0)
			return 0;
		if (apol_mls_range_compare(policy, lr, rr, APOL_QUERY_SUB) > 0)
			return 1;
		if (apol_mls_range_compare(policy, lr, rr, APOL_QUERY_SUPER) > 0)
			return -1;
		// no clear dominance; fallback on sensitivity name of low level
		return strcmp(apol_mls_level_get_sens(apol_mls_range_get_low(lr)),
			      apol_mls_level_get_sens(apol_mls_range_get_low(rr)));
	}
	case POLSEARCH_ELEMENT_BOOL_STATE:
	{
		if (left->element() == right->element())
			return 0;
		else if (left->element())
			return 1;
		else
			return -1;
	}
	case POLSEARCH_ELEMENT_NONE:
	default:
	{
		return 0;	       // not comparable, don't sort
	}
	}
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

polsearch_test_t *polsearch_test_create(polsearch_element_e elem_type, polsearch_test_cond_e cond)
{
	if (elem_type == POLSEARCH_ELEMENT_NONE || cond == POLSEARCH_TEST_NONE)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return new polsearch_test(elem_type, cond);
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

polsearch_test_t *polsearch_test_create_from_test(const polsearch_test_t * pt)
{
	if (!pt)
	{
		errno = EINVAL;
		return NULL;
	}

	return static_cast < polsearch_test * >(dup_test(static_cast < const void *>(pt), NULL));
}

void polsearch_test_destroy(polsearch_test_t ** pt)
{
	if (!pt)
		return;

	free_test(*pt);
	*pt = NULL;
}

apol_vector_t *polsearch_test_get_valid_ops(const polsearch_test_t * pt)
{
	if (!pt)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return pt->getValidOps();
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

apol_vector_t *polsearch_test_get_criteria(polsearch_test_t * pt)
{
	if (!pt)
	{
		errno = EINVAL;
		return NULL;
	}

	return pt->criteria();
}

polsearch_element_e polsearch_test_get_element_type(const polsearch_test_t * pt)
{
	if (!pt)
	{
		errno = EINVAL;
		return POLSEARCH_ELEMENT_NONE;
	}

	return pt->elementType();
}

polsearch_test_cond_e polsearch_test_get_test_cond(const polsearch_test_t * pt)
{
	if (!pt)
	{
		errno = EINVAL;
		return POLSEARCH_TEST_NONE;
	}

	return pt->testCond();
}

apol_vector_t *polsearch_test_run(const polsearch_test_t * pt, const apol_policy_t * p, const sefs_fclist_t * fclist,
				  apol_vector_t * Xcandidates)
{
	if (!pt)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return pt->run(p, fclist, Xcandidates);
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

polsearch_param_type_e polsearch_test_get_param_type(const polsearch_test_t * pt, polsearch_op_e opr)
{
	if (!pt || opr == POLSEARCH_OP_NONE)
	{
		errno = EINVAL;
		return POLSEARCH_PARAM_TYPE_NONE;
	}

	return pt->getParamType(opr);
}

polsearch_result_t *polsearch_result_create(polsearch_element_e elem_type, const void *elem, const apol_policy_t * p,
					    const sefs_fclist_t * fclist)
{
	if (elem_type == POLSEARCH_ELEMENT_NONE)
	{
		errno = EINVAL;
		return NULL;
	}
	try
	{
		return new polsearch_result(elem_type, elem, p, fclist);
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

polsearch_result_t *polsearch_result_create_from_result(const polsearch_result_t * pr)
{
	if (!pr)
	{
		errno = EINVAL;
		return NULL;
	}

	return static_cast < polsearch_result * >(dup_result(static_cast < const void *>(pr), NULL));
}

void polsearch_result_destroy(polsearch_result_t ** pr)
{
	if (!pr)
		return;

	free_result(*pr);
	*pr = NULL;
}

polsearch_element_e polsearch_result_get_element_type(const polsearch_result_t * pr)
{
	if (!pr)
	{
		errno = EINVAL;
		return POLSEARCH_ELEMENT_NONE;
	}

	return pr->elementType();
}

const void *polsearch_result_get_element(const polsearch_result_t * pr)
{
	if (!pr)
	{
		errno = EINVAL;
		return NULL;
	}

	return pr->element();
}

apol_vector_t *polsearch_result_get_proof(polsearch_result_t * pr)
{
	if (!pr)
	{
		errno = EINVAL;
		return NULL;
	}

	return pr->proof();
}

char *polsearch_result_to_string(polsearch_result_t * pr)
{
	if (!pr)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return pr->toString();
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}

polsearch_proof_t *polsearch_proof_create(polsearch_test_cond_e test, polsearch_element_e elem_type, void *elem,
					  const apol_policy_t * p, const sefs_fclist_t * fclist)
{
	if (test == POLSEARCH_TEST_NONE || elem_type == POLSEARCH_ELEMENT_NONE)
	{
		errno = EINVAL;
		return NULL;
	}

	return new polsearch_proof(test, elem_type, elem, p, fclist);
}

polsearch_proof_t *polsearch_proof_create_from_proof(polsearch_proof_t * pp)
{
	if (!pp)
	{
		errno = EINVAL;
		return NULL;
	}

	return static_cast < polsearch_proof * >(dup_proof(static_cast < const void *>(pp), NULL));
}

void polsearch_proof_destroy(polsearch_proof_t ** pp)
{
	if (!pp)
		return;

	free_proof(*pp);
	*pp = NULL;
}

polsearch_element_e polsearch_proof_get_element_type(const polsearch_proof_t * pp)
{
	if (!pp)
	{
		errno = EINVAL;
		return POLSEARCH_ELEMENT_NONE;
	}

	return pp->elementType();
}

const void *polsearch_proof_get_element(const polsearch_proof_t * pp)
{
	if (!pp)
	{
		errno = EINVAL;
		return NULL;
	}

	return pp->element();
}

polsearch_test_cond_e polsearch_proof_get_test_cond(const polsearch_proof_t * pp)
{
	if (!pp)
	{
		errno = EINVAL;
		return POLSEARCH_TEST_NONE;
	}

	return pp->testCond();
}

char *polsearch_proof_to_string(polsearch_proof_t * pp)
{
	if (!pp)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return pp->toString();
	}
	catch(bad_alloc)
	{
		errno = ENOMEM;
		return NULL;
	}
}
