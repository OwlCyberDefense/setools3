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

#ifndef POLSEARCH_CRITERION_CC
#define POLSEARCH_CRITERION_CC

#ifndef POLSEARCH_CRITERION_HH
#include <polsearch/criterion.hh>
#endif				       /* POLSEARCH_CRITERION_HH */

#include "criterion_internal.hh"

#include <apol/mls_level.h>
#include <apol/mls_range.h>

#include <sefs/entry.hh>

#include <assert.h>
#include <errno.h>
#include <stdexcept>
#include <typeinfo>
#include <string>
#include <regex.h>

using std::invalid_argument;
using std::runtime_error;
using std::bad_alloc;
using std::type_info;
using std::bad_typeid;
using std::string;

// base criterion
polsearch_base_criterion::polsearch_base_criterion(polsearch_op_e opr, bool neg) throw(std::invalid_argument)
{
	if (opr == POLSEARCH_OP_NONE || opr > POLSEARCH_OP_AS_TYPE)
		throw invalid_argument("Invalid operator requested");

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

	switch (opr)
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

template < class T > polsearch_criterion < T >::polsearch_criterion(const T & parameter, polsearch_op_e opr, bool neg)throw(std::bad_alloc, std::invalid_argument):polsearch_base_criterion(opr,
			 neg)
{
	_detect_param_type();

	_param = parameter;
}

template < class T >
	polsearch_criterion < T >::polsearch_criterion(const polsearch_criterion < T >
						       &pc) throw(std::bad_alloc):polsearch_base_criterion(pc.op(), pc.negated())
{
	_param = pc._param;
}

template < class T > polsearch_criterion < T >::~polsearch_criterion()
{
	// nothing to do
}

template < class T > const T & polsearch_criterion < T >::param() const
{
	return _param;
}

template < class T > const T & polsearch_criterion < T >::param(const T & parameter) throw(std::bad_alloc)
{
	return (_param = parameter);
}

/**
 * Compare a policy element to the given parameter with the given operator.
 * @param p The policy associated with all relevant elements.
 * @param candidate A policy element to consider for proving a test
 * criterion is met.
 * @param candidate_type The type of policy element \a candidate is.
 * @param opr The comparison operator to use.
 * @param parameter The second parameter of the operator \a opr.
 * @return The logic value of the comparison \a candidate \a opr \a parameter.
 * @exception std::runtime_error Unable to perform the comparison.
 * @exception std::bad_alloc Could not allocate enough space to perform the comparison.
 */
template < class T > static bool compare(const apol_policy_t * p, const void *candidate, polsearch_element_e candidate_type,
					 polsearch_op_e opr, const T parameter) throw(std::runtime_error, std::bad_alloc);

template < class T >
	void polsearch_criterion < T >::check(const apol_policy_t * p, apol_vector_t * test_candidates,
					      polsearch_element_e candidate_type,
					      const apol_vector_t * Xcandidtates) const throw(std::runtime_error,
												    std::bad_alloc)
{
	for (size_t i = 0; i < apol_vector_get_size(test_candidates); i++)
	{
		bool match = false;
		const void *element = apol_vector_get_element(test_candidates, i);

		match = compare(p, element, candidate_type, _op, _param);

		if (_negated)
			match = !match;

		// prune this candidate
		if (!match)
		{
			apol_vector_remove(test_candidates, i);
			i--;
		}
	}

	return;
}

/**
 * Get the corresponding value for the parameter type.
 * This is so the C compatibility functions do not need to care that
 * polsearch_criterion is a template.
 * @param param_type_info Type information about the parameter stored.
 * @return A valid polsearch_param_type_e value
 * or POLSEARCH_PARAM_TYPE_NONE on error.
 */
static polsearch_param_type_e get_param_type(const type_info & param_type_info)
{
	if (typeid(string) == param_type_info)
		return POLSEARCH_PARAM_TYPE_REGEX;
	if (typeid(polsearch_string_list) == param_type_info)
		return POLSEARCH_PARAM_TYPE_STR_LIST;
	if (typeid(uint32_t) == param_type_info)
		return POLSEARCH_PARAM_TYPE_RULE_TYPE;
	if (typeid(bool) == param_type_info)
		return POLSEARCH_PARAM_TYPE_BOOL;
	if (typeid(apol_mls_level_t *) == param_type_info)
		return POLSEARCH_PARAM_TYPE_LEVEL;
	if (typeid(apol_mls_range_t *) == param_type_info)
		return POLSEARCH_PARAM_TYPE_RANGE;
	return POLSEARCH_PARAM_TYPE_NONE;
}

template < class T > void polsearch_criterion < T >::_detect_param_type() throw(std::invalid_argument)
{
	polsearch_param_type_e p;
	validate_opr_elem(_op, (p = get_param_type(typeid(T))));

	_param_type = p;
}

// special handling of apol_mls_level_t and apol_mls_range_t since they are C structs

typedef apol_mls_level_t *apol_mls_level_tp;	//makes gcc happy
template <>
	polsearch_criterion < apol_mls_level_t * >::polsearch_criterion(const apol_mls_level_tp & parameter, polsearch_op_e opr,
									bool neg) throw(std::bad_alloc,
											std::
											invalid_argument):polsearch_base_criterion
	(opr, neg)
{
	_detect_param_type();
	_param = apol_mls_level_create_from_mls_level(parameter);
	if (!_param)
		throw bad_alloc();

}

template <>
	polsearch_criterion < apol_mls_level_t * >::polsearch_criterion(const polsearch_criterion <
									apol_mls_level_t *
									>&pc) throw(std::bad_alloc):polsearch_base_criterion(pc.
															     op(),
															     pc.
															     negated
															     ())
{
	_param = apol_mls_level_create_from_mls_level(pc._param);
	if (!_param)
		throw bad_alloc();
}

template <> polsearch_criterion < apol_mls_level_t * >::~polsearch_criterion()
{
	apol_mls_level_destroy(&_param);
}

template <>
	const apol_mls_level_tp & polsearch_criterion <
	apol_mls_level_t * >::param(const apol_mls_level_tp & parameter) throw(std::bad_alloc)
{
	_param = apol_mls_level_create_from_mls_level(parameter);
	if (!_param)
		throw bad_alloc();
}

typedef apol_mls_range_t *apol_mls_range_tp;	//makes gcc happy
template <>
	polsearch_criterion < apol_mls_range_t * >::polsearch_criterion(const apol_mls_range_tp & parameter, polsearch_op_e opr,
									bool neg) throw(std::bad_alloc,
											std::
											invalid_argument):polsearch_base_criterion
	(opr, neg)
{
	_detect_param_type();
	_param = apol_mls_range_create_from_mls_range(parameter);
	if (!_param)
		throw bad_alloc();
}

template <>
	polsearch_criterion < apol_mls_range_t * >::polsearch_criterion(const polsearch_criterion <
									apol_mls_range_t *
									>&pc) throw(std::bad_alloc):polsearch_base_criterion(pc.
															     op(),
															     pc.
															     negated
															     ())
{
	_param = apol_mls_range_create_from_mls_range(pc._param);
	if (!_param)
		throw bad_alloc();
}

template <> polsearch_criterion < apol_mls_range_t * >::~polsearch_criterion()
{
	apol_mls_range_destroy(&_param);
}

template <>
	const apol_mls_range_tp & polsearch_criterion <
	apol_mls_range_t * >::param(const apol_mls_range_tp & parameter) throw(std::bad_alloc)
{
	_param = apol_mls_range_create_from_mls_range(parameter);
	if (!_param)
		throw bad_alloc();
}

// internal functions

void free_criterion(void *pc)
{
	if (!pc)
		return;

	polsearch_base_criterion *crit = static_cast < polsearch_base_criterion * >(pc);

	polsearch_param_type_e param_type = crit->paramType();
	switch (param_type)
	{
	case POLSEARCH_PARAM_TYPE_REGEX:
	{
		delete dynamic_cast < polsearch_criterion < string > *>(crit);
	}
	case POLSEARCH_PARAM_TYPE_STR_LIST:
	{
		delete dynamic_cast < polsearch_criterion < polsearch_string_list > *>(crit);
	}
	case POLSEARCH_PARAM_TYPE_RULE_TYPE:
	{
		delete dynamic_cast < polsearch_criterion < uint32_t > *>(crit);
	}
	case POLSEARCH_PARAM_TYPE_BOOL:
	{
		delete dynamic_cast < polsearch_criterion < bool > *>(crit);
	}
	case POLSEARCH_PARAM_TYPE_LEVEL:
	{
		delete dynamic_cast < polsearch_criterion < apol_mls_level_t * >*>(crit);
	}
	case POLSEARCH_PARAM_TYPE_RANGE:
	{
		delete dynamic_cast < polsearch_criterion < apol_mls_range_t * >*>(crit);
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
	if (!pc)
	{
		errno = EINVAL;
		return NULL;
	}

	const polsearch_base_criterion *crit = static_cast < const polsearch_base_criterion * >(pc);
	try
	{
		switch (crit->paramType())
		{
		case POLSEARCH_PARAM_TYPE_REGEX:
		{
			polsearch_criterion < string > *prc =
				new polsearch_criterion < string > (*dynamic_cast < const polsearch_criterion < string > *>(crit));
			if (!prc)
				throw bad_alloc();
			return static_cast < void *>(prc);
		}
		case POLSEARCH_PARAM_TYPE_STR_LIST:
		{
			polsearch_criterion < polsearch_string_list > *pslc =
				new polsearch_criterion < polsearch_string_list > (*dynamic_cast < const polsearch_criterion <
										   polsearch_string_list > *>(crit));
			if (!pslc)
				throw bad_alloc();
			return static_cast < void *>(pslc);
		}
		case POLSEARCH_PARAM_TYPE_RULE_TYPE:
		{
			polsearch_criterion < uint32_t > *prtc =
				new polsearch_criterion < uint32_t > (*dynamic_cast < const polsearch_criterion < uint32_t >
								      *>(crit));
			if (!prtc)
				throw bad_alloc();
			return static_cast < void *>(prtc);
		}
		case POLSEARCH_PARAM_TYPE_BOOL:
		{
			polsearch_criterion < bool > *pbc =
				new polsearch_criterion < bool > (*dynamic_cast < const polsearch_criterion < bool > *>(crit));
			if (!pbc)
				throw bad_alloc();
			return static_cast < void *>(pbc);
		}
		case POLSEARCH_PARAM_TYPE_LEVEL:
		{
			polsearch_criterion < apol_mls_level_t * >*plc =
				new polsearch_criterion < apol_mls_level_t * >(*dynamic_cast < const polsearch_criterion <
									       apol_mls_level_t * >*>(crit));
			if (!plc)
				throw bad_alloc();
			return static_cast < void *>(plc);
		}
		case POLSEARCH_PARAM_TYPE_RANGE:
		{
			polsearch_criterion < apol_mls_range_t * >*prc =
				new polsearch_criterion < apol_mls_range_t * >(*dynamic_cast < const polsearch_criterion <
									       apol_mls_range_t * >*>(crit));
			if (!prc)
				throw bad_alloc();
			return static_cast < void *>(prc);
		}
		case POLSEARCH_PARAM_TYPE_NONE:
		default:
		{
			errno = ENOTSUP;
			return NULL;
		}
		}
	}
	catch(bad_alloc x)
	{
		errno = ENOMEM;
		return NULL;
	}
}

// C compatibility

polsearch_criterion_t *polsearch_criterion_create(const void *parameter, polsearch_param_type_e param_type, polsearch_op_e opr,
						  bool neg)
{
	if (opr == POLSEARCH_OP_NONE || param_type == POLSEARCH_PARAM_TYPE_NONE)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		switch (param_type)
		{
		case POLSEARCH_PARAM_TYPE_REGEX:
		{
			string s(static_cast < const char *>(parameter));
			return dynamic_cast < polsearch_base_criterion * >(new polsearch_criterion < string > (s, opr, neg));
		}
		case POLSEARCH_PARAM_TYPE_STR_LIST:
		{
			return dynamic_cast < polsearch_base_criterion * >(new polsearch_criterion < polsearch_string_list >
									   (*static_cast <
									    const polsearch_string_list * >(parameter), opr, neg));
		}
		case POLSEARCH_PARAM_TYPE_RULE_TYPE:
		{
			return dynamic_cast < polsearch_base_criterion * >(new polsearch_criterion < uint32_t >
									   (static_cast < uint32_t >
									    (reinterpret_cast < size_t > (parameter)), opr, neg));
		}
		case POLSEARCH_PARAM_TYPE_BOOL:
		{
			return dynamic_cast < polsearch_base_criterion * >(new polsearch_criterion < bool >
									   ((parameter != 0), opr, neg));
		}
		case POLSEARCH_PARAM_TYPE_LEVEL:
		{
			//const_cast here because const apol_mls_level_t* cannot be directly converted to const apol_mls_level_t*&
			apol_mls_level_t *lvl = static_cast < apol_mls_level_t * >(const_cast < void *>(parameter));
			return dynamic_cast < polsearch_base_criterion * >(new polsearch_criterion <
									   apol_mls_level_t * >(lvl, opr, neg));
		}
		case POLSEARCH_PARAM_TYPE_RANGE:
		{
			//const_cast here because const apol_mls_level_t* cannot be directly converted to const apol_mls_level_t*&
			apol_mls_range_t *rng = static_cast < apol_mls_range_t * >(const_cast < void *>(parameter));
			return dynamic_cast < polsearch_base_criterion * >(new polsearch_criterion <
									   apol_mls_range_t * >(rng, opr, neg));
		}
		case POLSEARCH_PARAM_TYPE_NONE:
		default:
		{
			errno = ENOTSUP;
			return NULL;
		}
		}
	}
	catch(bad_alloc x)
	{
		errno = ENOMEM;
		return NULL;
	}
	catch(invalid_argument x)
	{
		errno = EINVAL;
		return NULL;
	}
}

polsearch_criterion_t *polsearch_criterion_create_from_criterion(const polsearch_criterion_t * pc)
{
	return static_cast < polsearch_criterion_t * >(dup_criterion(pc, NULL));
}

void polsearch_criterion_destroy(polsearch_criterion_t ** pc)
{
	if (!pc)
		return;

	free_criterion(*pc);
	*pc = NULL;
}

polsearch_op_e polsearch_criterion_get_op(const polsearch_criterion_t * pc)
{
	if (!pc)
	{
		errno = EINVAL;
		return POLSEARCH_OP_NONE;
	}

	return pc->op();
}

bool polsearch_criterion_get_negated(const polsearch_criterion_t * pc)
{
	if (!pc)
	{
		errno = EINVAL;
		return false;
	}

	return pc->negated();
}

bool polsearch_criterion_set_negated(polsearch_criterion_t * pc, bool neg)
{
	if (!pc)
	{
		errno = EINVAL;
		return false;
	}

	return pc->negated(neg);
}

polsearch_param_type_e polsearch_criterion_get_param_type(const polsearch_criterion_t * pc)
{
	if (!pc)
	{
		errno = EINVAL;
		return POLSEARCH_PARAM_TYPE_NONE;
	}

	return pc->paramType();
}

void polsearch_criterion_check(const polsearch_criterion_t * pc, const apol_policy_t * p,
			       apol_vector_t * test_candidates, polsearch_element_e candidate_type,
			       const apol_vector_t * Xcandidtates)
{
	if (!pc)
		return;

	pc->check(p, test_candidates, candidate_type, Xcandidtates);
}

const void *polsearch_criterion_get_param(const polsearch_criterion_t * pc)
{
	//explicitly reset errno here as NULL might be a valid return.
	errno = 0;

	if (!pc)
	{
		errno = EINVAL;
		return NULL;
	}

	switch (pc->paramType())
	{
	case POLSEARCH_PARAM_TYPE_REGEX:
	{
		return (dynamic_cast < const polsearch_criterion < string > *>(pc))->param().c_str();
	}
	case POLSEARCH_PARAM_TYPE_STR_LIST:
	{
		return &((dynamic_cast < const polsearch_criterion < polsearch_string_list > *>(pc))->param());
	}
	case POLSEARCH_PARAM_TYPE_RULE_TYPE:
	{
		//pointer from int here explicitly
		return reinterpret_cast < const void *>((dynamic_cast < const polsearch_criterion < uint32_t > *>(pc))->param());
	}
	case POLSEARCH_PARAM_TYPE_BOOL:
	{
		//poiinter from bool here explicitly
		return reinterpret_cast < const void *>((dynamic_cast < const polsearch_criterion < bool > *>(pc))->param());
	}
	case POLSEARCH_PARAM_TYPE_LEVEL:
	{
		return (dynamic_cast < const polsearch_criterion < apol_mls_level_t * >*>(pc))->param();
	}
	case POLSEARCH_PARAM_TYPE_RANGE:
	{
		return (dynamic_cast < const polsearch_criterion < apol_mls_range_t * >*>(pc))->param();
	}
	case POLSEARCH_PARAM_TYPE_NONE:
	default:
	{
		errno = ENOTSUP;
		return NULL;
	}
	}
}

const void *polsearch_criterion_set_param(polsearch_criterion_t * pc, polsearch_param_type_e param_type, const void *parameter)
{
	//explicitly reset errno here as NULL might be a valid return.
	errno = 0;

	if (!pc || pc->paramType() != param_type)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		switch (pc->paramType())
		{
		case POLSEARCH_PARAM_TYPE_REGEX:
		{
			polsearch_criterion < string > *prc = dynamic_cast < polsearch_criterion < string > *>(pc);
			string str(static_cast < const char *>(parameter));
			return static_cast < const void *>(prc->param(str).c_str());
		}
		case POLSEARCH_PARAM_TYPE_STR_LIST:
		{
			polsearch_criterion < polsearch_string_list > *pslc =
				dynamic_cast < polsearch_criterion < polsearch_string_list > *>(pc);
			const polsearch_string_list sl(*static_cast < const polsearch_string_list * >(parameter));
			return static_cast < const void *>(&(pslc->param(sl)));
		}
		case POLSEARCH_PARAM_TYPE_RULE_TYPE:
		{
			polsearch_criterion < uint32_t > *prtc = dynamic_cast < polsearch_criterion < uint32_t > *>(pc);
			const uint32_t rt = static_cast < const uint32_t > (reinterpret_cast < const size_t > (parameter));
			return reinterpret_cast < const void *>(prtc->param(rt));
		}
		case POLSEARCH_PARAM_TYPE_BOOL:
		{
			polsearch_criterion < bool > *pbc = dynamic_cast < polsearch_criterion < bool > *>(pc);
			//do this in place of casts
			const bool b = (parameter != 0);
			return reinterpret_cast < const void *>(pbc->param(b));
		}
		case POLSEARCH_PARAM_TYPE_LEVEL:
		{
			polsearch_criterion < apol_mls_level_t * >*plc =
				dynamic_cast < polsearch_criterion < apol_mls_level_t * >*>(pc);
			//const_cast here because const apol_mls_level_t* cannot be directly converted to const apol_mls_level_t*&
			apol_mls_level_t *lvl = static_cast < apol_mls_level_t * >(const_cast < void *>(parameter));
			return static_cast < const void *>(plc->param(lvl));
		}
		case POLSEARCH_PARAM_TYPE_RANGE:
		{
			polsearch_criterion < apol_mls_range_t * >*prc =
				dynamic_cast < polsearch_criterion < apol_mls_range_t * >*>(pc);
			//const_cast here because const apol_mls_range_t* cannot be directly converted to const apol_mls_range_t*&
			apol_mls_range_t *rng = static_cast < apol_mls_range_t * >(const_cast < void *>(parameter));
			return static_cast < const void *>(prc->param(rng));
		}
		case POLSEARCH_PARAM_TYPE_NONE:
		default:
		{
			errno = ENOTSUP;
			return NULL;
		}
		}
	}
	catch(bad_alloc x)
	{
		errno = ENOMEM;
		return NULL;
	}
}

// explicit specializations of compare function.

template <> static bool compare(const apol_policy_t * p, const void *candidate, polsearch_element_e candidate_type,
				polsearch_op_e opr, const string parameter) throw(std::runtime_error, std::bad_alloc)
{
	if (opr != POLSEARCH_OP_MATCH_REGEX || candidate_type != POLSEARCH_ELEMENT_STRING)
		throw runtime_error("Incompatiple comparison attempted");

	regex_t *reg = new regex_t;
	bool retv = false;
	if (regcomp(reg, parameter.c_str(), REG_EXTENDED | REG_NOSUB))
	{
		delete reg;
		throw runtime_error("Error compiling regular expression");
	}

	if (regexec(reg, static_cast < const char *>(candidate), 0, NULL, 0) == 0)
		retv = true;

	regfree(reg);
	delete reg;

	return retv;
}

template <> static bool compare(const apol_policy_t * p
				__attribute__ ((unused)), const void *candidate, polsearch_element_e candidate_type,
				polsearch_op_e opr, const bool parameter) throw(std::runtime_error, std::bad_alloc)
{
	if (candidate_type != POLSEARCH_ELEMENT_BOOL_STATE || opr != POLSEARCH_OP_IS)
		throw runtime_error("Incompatiple comparison attempted");

	const bool x = static_cast < const bool > (reinterpret_cast < const size_t > (candidate));

	return (x == parameter);
}

template <> static bool compare(const apol_policy_t * p, const void *candidate, polsearch_element_e candidate_type,
				polsearch_op_e opr, const polsearch_string_list parameter) throw(std::runtime_error, std::bad_alloc)
{
	//TODO compare string list
	return false;
}

template <> static bool compare(const apol_policy_t * p, const void *candidate, polsearch_element_e candidate_type,
				polsearch_op_e opr, const uint32_t parameter) throw(std::runtime_error, std::bad_alloc)
{
	if (opr != POLSEARCH_OP_RULE_TYPE ||
	    (candidate_type != POLSEARCH_ELEMENT_AVRULE && candidate_type != POLSEARCH_ELEMENT_TERULE))
		throw runtime_error("Incompatiple comparison attempted");

	uint32_t rule_type = 0;
	qpol_policy_t *q = apol_policy_get_qpol(p);

	if (candidate_type == POLSEARCH_ELEMENT_AVRULE)
		qpol_avrule_get_rule_type(q, static_cast < const qpol_avrule_t * >(candidate), &rule_type);
	else
		qpol_terule_get_rule_type(q, static_cast < const qpol_terule_t * >(candidate), &rule_type);

	return (rule_type == parameter);
}

template <> static bool compare(const apol_policy_t * p, const void *candidate, polsearch_element_e candidate_type,
				polsearch_op_e opr, const apol_mls_level_tp parameter) throw(std::runtime_error, std::bad_alloc)
{
	if ((opr != POLSEARCH_OP_AS_LEVEL_EXACT && opr != POLSEARCH_OP_AS_LEVEL_DOM && opr != POLSEARCH_OP_AS_LEVEL_DOMBY) ||
	    candidate_type != POLSEARCH_ELEMENT_USER)
		throw runtime_error("Incompatiple comparison attempted");

	qpol_policy_t *q = apol_policy_get_qpol(p);
	const qpol_mls_level_t *qlvl = NULL;
	qpol_user_get_dfltlevel(q, static_cast < const qpol_user_t * >(candidate), &qlvl);
	apol_mls_level_t *alvl = apol_mls_level_create_from_qpol_mls_level(p, qlvl);
	apol_mls_level_t *alvl2 = NULL;
	if (!alvl)
		throw bad_alloc();

	if (apol_mls_level_is_literal(parameter))
	{
		alvl2 = apol_mls_level_create_from_mls_level(parameter);
		if (!alvl2)
		{
			apol_mls_level_destroy(&alvl);
			throw bad_alloc();
		}
		if (apol_mls_level_convert(p, alvl2))
		{
			apol_mls_level_destroy(&alvl);
			apol_mls_level_destroy(&alvl2);
			throw runtime_error("Could not convert MLS level");
		}
	}

	int cmp = apol_mls_level_compare(p, alvl, (alvl2 ? alvl2 : parameter));
	apol_mls_level_destroy(&alvl);
	apol_mls_level_destroy(&alvl2);

	if (cmp == APOL_MLS_EQ)	       // A level dominates itself so equal satisfies all three conditions
		return true;
	if (cmp == APOL_MLS_DOM && opr == POLSEARCH_OP_AS_LEVEL_DOM)
		return true;
	if (cmp == APOL_MLS_DOMBY && opr == POLSEARCH_OP_AS_LEVEL_DOMBY)
		return true;

	return false;
}

template <> static bool compare(const apol_policy_t * p, const void *candidate, polsearch_element_e candidate_type,
				polsearch_op_e opr, const apol_mls_range_tp parameter) throw(std::runtime_error, std::bad_alloc)
{
	if (opr != POLSEARCH_OP_AS_RANGE_EXACT && opr != POLSEARCH_OP_AS_RANGE_SUPER && opr != POLSEARCH_OP_AS_RANGE_SUB)
		throw runtime_error("Incompatiple comparison attempted");
	if (candidate_type != POLSEARCH_ELEMENT_RANGE_TRANS && candidate_type != POLSEARCH_ELEMENT_USER &&
	    candidate_type != POLSEARCH_ELEMENT_FC_ENTRY)
		throw runtime_error("Incompatiple comparison attempted");

	qpol_policy_t *q = apol_policy_get_qpol(p);
	const qpol_mls_range_t *qrng = NULL;
	apol_mls_range_t *arng = NULL;
	apol_mls_range_t *arng2 = NULL;

	if (candidate_type == POLSEARCH_ELEMENT_RANGE_TRANS)
	{
		qpol_range_trans_get_range(q, static_cast < const qpol_range_trans_t * >(candidate), &qrng);
		arng = apol_mls_range_create_from_qpol_mls_range(p, qrng);
		if (!arng)
			throw bad_alloc();
	}
	else if (candidate_type == POLSEARCH_ELEMENT_USER)
	{
		qpol_user_get_range(q, static_cast < const qpol_user_t * >(candidate), &qrng);
		arng = apol_mls_range_create_from_qpol_mls_range(p, qrng);
		if (!arng)
			throw bad_alloc();
	}
	else			       // POLSEARCH_ELEMENT_FC_ENTRY
	{
		const sefs_entry *ent = static_cast < const sefs_entry * >(candidate);
		const apol_context_t *ctx = ent->context();
		arng = apol_mls_range_create_from_mls_range(apol_context_get_range(ctx));
		if (!arng)
			throw bad_alloc();
		if (apol_mls_range_is_literal(arng) && apol_mls_range_convert(p, arng))
			throw runtime_error("Could not convert MLS range");
	}

	if (apol_mls_range_is_literal(parameter))
	{
		arng2 = apol_mls_range_create_from_mls_range(parameter);
		if (!arng2)
		{
			apol_mls_range_destroy(&arng);
			throw bad_alloc();
		}
		if (apol_mls_range_convert(p, arng2))
		{
			apol_mls_range_destroy(&arng);
			apol_mls_range_destroy(&arng2);
			throw runtime_error("Could not convert MLS range");
		}
	}

	unsigned int apol_opr;
	if (opr == POLSEARCH_OP_AS_RANGE_EXACT)
		apol_opr = APOL_QUERY_EXACT;
	else if (opr == POLSEARCH_OP_AS_RANGE_SUB)
		apol_opr = APOL_QUERY_SUB;
	else if (opr == POLSEARCH_OP_AS_RANGE_SUPER)
		apol_opr = APOL_QUERY_SUPER;

	int cmp = apol_mls_range_compare(p, (arng2 ? arng2 : parameter), arng, apol_opr);
	apol_mls_range_destroy(&arng);
	apol_mls_range_destroy(&arng2);

	if (cmp < 0)
		throw runtime_error("Comparison of ranges failed");
	if (cmp > 0)
		return true;

	return false;
}

#endif				       /* POLSEARCH_CRITERION_CC */
