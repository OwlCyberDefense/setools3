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

#ifndef POLSEARCH_CRITERION_CC
#define POLSEARCH_CRITERION_CC

#ifndef POLSEARCH_CRITERION_HH
#include <polsearch/criterion.hh>
#endif /* POLSEARCH_CRITERION_HH */

#include "criterion_internal.hh"

#include <apol/mls_level.h>
#include <apol/mls_range.h>

#include <assert.h>
#include <stdexcept>
#include <typeinfo>
#include <string>

using std::invalid_argument;
using std::bad_alloc;
using std::type_info;
using std::string;

// base criterion
polsearch_base_criterion::polsearch_base_criterion(polsearch_op_e opr, bool neg) throw(std::invalid_argument)
{
	try
	{
		if (opr == POLSEARCH_OP_NONE || opr > POLSEARCH_OP_AS_TYPE)
			throw invalid_argument("Invalid operator requested");
	}
	catch (invalid_argument x)
	{
		throw x;
	}
	_op = opr;
	_negated = neg;
	_param_type = POLSEARCH_PARAM_TYPE_NONE;
}

polsearch_base_criterion::polsearch_base_criterion(const polsearch_base_criterion & pc)
{
	_op = pc._op;
	_negated = pc._negated;
	_param_type = pc._param_type;
}

polsearch_base_criterion::~polsearch_base_criterion()
{
	// nothing to do
}

polsearch_op_e polsearch_base_criterion::op() const
{
	return _op;
}

bool polsearch_base_criterion::negated() const
{
	return _negated;
}

bool polsearch_base_criterion::negated(bool neg)
{
	return (_negated = neg);
}

polsearch_param_type_e polsearch_base_criterion::paramType() const
{
	return _param_type;
}


// derived variants

/**
 * Validate the operator and parameter type independent of any other information.
 * @param opr The comparison operator.
 * @param param_type The parameter type.
 * @return If \a param_type is valid for at least one use of \a opr, return \a true,
 * otherwise, return \a false.
 */
static bool validate_opr_elem(polsearch_op_e opr, polsearch_param_type_e param_type)
{
	if (param_type == POLSEARCH_PARAM_TYPE_NONE)
		return false;

	switch(opr)
	{
		case POLSEARCH_OP_IS:
		{
			if (param_type == POLSEARCH_PARAM_TYPE_STR_LIST || param_type == POLSEARCH_PARAM_TYPE_BOOL)
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
			if (param_type == POLSEARCH_PARAM_TYPE_STR_LIST)
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

template <class T>
polsearch_criterion<T>::polsearch_criterion(polsearch_op_e opr, bool neg, const T& parameter) throw(std::bad_alloc, std::invalid_argument)
	:polsearch_base_criterion(opr,neg)
{
	try
	{
		_detect_param_type();
	}
	catch (invalid_argument x)
	{
		throw x;
	}
	_param = parameter;
}

template <class T>
polsearch_criterion<T>::polsearch_criterion(const polsearch_criterion<T>& pc) throw(std::bad_alloc)
	:polsearch_base_criterion(pc.op(), pc.negated())
{
	_param = pc._param;
}

template <class T>
polsearch_criterion<T>::~polsearch_criterion()
{
	// nothing to do
}

template <class T>
const T& polsearch_criterion<T>::param() const
{
	return _param;
}

template <class T>
const T& polsearch_criterion<T>::parm(const T& parameter)
{
	return (_param = parameter);
}

template <class T>
apol_vector_t *polsearch_criterion<T>::check(const apol_policy_t * p, const sefs_fclist_t * fclist,
				     apol_vector_t * test_candidates, const apol_vector_t * Xcandidtates) const
{
	//TODO
	return NULL;
}

/**
 * Get the corresponding value for the parameter type.
 * This is so the C compatibility functions do not need to care that
 * polsearch_criterion is a template.
 * @param param_type_info Type information about the parameter stored.
 * @return A valid polsearch_param_type_e value
 * or POLSEARCH_PARAM_TYPE_NONE on error.
 */
static polsearch_param_type_e get_param_type(const type_info& param_type_info)
{
	if (typeid(string) == param_type_info)
		return POLSEARCH_PARAM_TYPE_REGEX;
	if (typeid(polsearch_string_list) == param_type_info)
		return POLSEARCH_PARAM_TYPE_STR_LIST;
	if (typeid(uint32_t) == param_type_info)
		return POLSEARCH_PARAM_TYPE_RULE_TYPE;
	if (typeid(bool) == param_type_info)
		return POLSEARCH_PARAM_TYPE_BOOL;
	if (typeid(apol_mls_level_t*) == param_type_info)
		return POLSEARCH_PARAM_TYPE_LEVEL;
	if (typeid(apol_mls_range_t*) == param_type_info)
		return POLSEARCH_PARAM_TYPE_RANGE;
	return POLSEARCH_PARAM_TYPE_NONE;
}

template <class T>
void polsearch_criterion<T>::_detect_param_type() throw(std::invalid_argument)
{
	polsearch_param_type_e p;
	try
	{
		validate_opr_elem(_op, (p = get_param_type(typeid(T))));
	}
	catch (invalid_argument x)
	{
		throw x;
	}
	_param_type = p;
}


// special handling of apol_mls_level_t and apol_mls_range_t since they are C structs

typedef apol_mls_level_t* apol_mls_level_tp; //makes gcc happy
template<>
polsearch_criterion<apol_mls_level_t*>::polsearch_criterion(polsearch_op_e opr, bool neg, const apol_mls_level_tp& parameter) throw(std::bad_alloc, std::invalid_argument)
	:polsearch_base_criterion(opr, neg)
{
	try
	{
		_detect_param_type();
	}
	catch (invalid_argument x)
	{
		throw x;
	}
	try
	{
		_param = apol_mls_level_create_from_mls_level(parameter);
		if (!_param)
			throw bad_alloc();
	}
	catch(bad_alloc x)
	{
		throw x;
	}
}

template<>
polsearch_criterion<apol_mls_level_t*>::polsearch_criterion(const polsearch_criterion<apol_mls_level_t*>& pc) throw(std::bad_alloc)
	:polsearch_base_criterion(pc.op(), pc.negated())
{
	try
	{
		_param = apol_mls_level_create_from_mls_level(pc._param);
		if (!_param)
			throw bad_alloc();
	}
	catch (bad_alloc x)
	{
		throw x;
	}
}

template<>
polsearch_criterion<apol_mls_level_t*>::~polsearch_criterion()
{
	apol_mls_level_destroy(&_param);
}

typedef apol_mls_range_t* apol_mls_range_tp; //makes gcc happy
template<>
polsearch_criterion<apol_mls_range_t*>::polsearch_criterion(polsearch_op_e opr, bool neg, const apol_mls_range_tp& parameter) throw(std::bad_alloc, std::invalid_argument)
	:polsearch_base_criterion(opr, neg)
{
	try
	{
		_detect_param_type();
	}
	catch (invalid_argument x)
	{
		throw x;
	}
	try
	{
		_param = apol_mls_range_create_from_mls_range(parameter);
		if (!_param)
			throw bad_alloc();
	}
	catch(bad_alloc x)
	{
		throw x;
	}
}

template<>
polsearch_criterion<apol_mls_range_t*>::polsearch_criterion(const polsearch_criterion<apol_mls_range_t*>& pc) throw(std::bad_alloc)
	:polsearch_base_criterion(pc.op(), pc.negated())
{
	try
	{
		_param = apol_mls_range_create_from_mls_range(pc._param);
		if (!_param)
			throw bad_alloc();
	}
	catch (bad_alloc x)
	{
		throw x;
	}
}

template<>
polsearch_criterion<apol_mls_range_t*>::~polsearch_criterion()
{
	apol_mls_range_destroy(&_param);
}

// internal functions

void free_criterion(void *pc)
{
	if (!pc)
		return;

	polsearch_base_criterion *crit = static_cast<polsearch_base_criterion *>(pc);

	polsearch_param_type_e param_type = crit->paramType();
	switch (param_type)
	{
		case POLSEARCH_PARAM_TYPE_REGEX:
		{
			delete dynamic_cast< polsearch_criterion<string>* >(crit);
		}
		case POLSEARCH_PARAM_TYPE_STR_LIST:
		{
			delete dynamic_cast< polsearch_criterion<polsearch_string_list>* >(crit);
		}
		case POLSEARCH_PARAM_TYPE_RULE_TYPE:
		{
			delete dynamic_cast< polsearch_criterion<uint32_t>* >(crit);
		}
		case POLSEARCH_PARAM_TYPE_BOOL:
		{
			delete dynamic_cast< polsearch_criterion<bool>* >(crit);
		}
		case POLSEARCH_PARAM_TYPE_LEVEL:
		{
			delete dynamic_cast< polsearch_criterion<apol_mls_level_t*>* >(crit);
		}
		case POLSEARCH_PARAM_TYPE_RANGE:
		{
			delete dynamic_cast< polsearch_criterion<apol_mls_range_t*>* >(crit);
		}
		case POLSEARCH_PARAM_TYPE_NONE:
		default:
		{
			/* should not get here */
			assert(0);
			return;
		}
	}
}

void *dup_criterion(const void *pc, void *x __attribute__ ((unused)))
{
	//TODO check which kind and return it.
	return NULL;
}

// C compatibility



#endif /* POLSEARCH_CRITERION_CC */
