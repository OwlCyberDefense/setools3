/**
 * @file
 *
 * Routines to handle tests' criteria.
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
#include <polsearch/parameter.hh>
#include <polsearch/criterion.hh>
#include <polsearch/test.hh>
#include "polsearch_internal.hh"

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <string>
#include <vector>
#include <stdexcept>

#include <stdint.h>
#include <assert.h>

using std::runtime_error;
using std::invalid_argument;
using std::bad_alloc;
using std::vector;
using std::string;

polsearch_criterion::polsearch_criterion(const polsearch_test * test, polsearch_op_e opr, bool neg) throw(std::invalid_argument)
{
	if (!validate_operator(test->elementType(), test->testCond(), opr))
		throw invalid_argument("Invalid operator for the given test.");

	_op = opr;
	_negated = neg;
	_test = test;
}

polsearch_criterion::polsearch_criterion(const polsearch_criterion & rhs)
{
	_op = rhs._op;
	_negated = rhs._negated;
	_test = rhs._test;
}

polsearch_criterion::~polsearch_criterion()
{
	// no-op
}

polsearch_op_e polsearch_criterion::op() const
{
	return _op;
}

polsearch_op_e polsearch_criterion::op(polsearch_op_e opr)
{
	return _op = opr;
}

bool polsearch_criterion::negated() const
{
	return _negated;
}

bool polsearch_criterion::negated(bool neg)
{
	return _negated = neg;
}

const polsearch_test *polsearch_criterion::test() const
{
	return _test;
}

const polsearch_parameter *polsearch_criterion::param() const
{
	return _param;
}

polsearch_parameter *polsearch_criterion::param()
{
	return _param;
}

polsearch_parameter *polsearch_criterion::param(polsearch_parameter * p) throw(std::invalid_argument)
{
	if (!p || !validate_parameter_type(_test->elementType(), _test->testCond(), _op, p->paramType()))
		throw invalid_argument("Invalid parameter");

	delete _param;
	return _param = p;
}

std::vector < polsearch_param_type_e > polsearch_criterion::getValidParamTypes() const
{
	vector < polsearch_param_type_e > valid;
	for (int i = POLSEARCH_PARAM_TYPE_REGEX; i <= POLSEARCH_PARAM_TYPE_RANGE; i)
	{
		if (validate_parameter_type
		    (_test->elementType(), _test->testCond(), _op, static_cast < polsearch_param_type_e > (i)))
			valid.push_back(static_cast < polsearch_param_type_e > (i));
	}
	return valid;
}

std::string polsearch_criterion::toString() const
{
	//TODO
	return "";
}

//! Union of posible input to the parameter's match function.
union match_input
{
	bool bval;		       //!< State of a policy boolean.
	std::string * str;	       //!< Name of a policy symbol.
	uint32_t nval;		       //!< Generic numberic value.
	apol_mls_level_t *lvl;	       //!< User's default level.
	apol_mls_range_t *rng;	       //!< Range of user, context, or range_transition rule.
	std::vector < std::string > *list;	//!< List of type names expanded from an attribute.
};

//! Value to determine which type of matching is needed for the given input.
enum match_type
{
	MATCH_BOOL,		       //!< Input should be matched as a boolean value.
	MATCH_STRING,		       //!< Input should be matched as a string.
	MATCH_NUM,		       //!< Input should be matched as a numeric value (uint32_t).
	MATCH_LEVEL,		       //!< Input should be matched as a MLS level (apol_mls_level_t*).
	MATCH_RANGE,		       //!< Input should be matched as a MLS range (apol_mls_range_t*).
	MATCH_LIST		       //!< Input should be matched as an expanded list of symbol names.
};

enum match_type determine_match_type(const apol_policy_t * policy, const void *candidate, polsearch_element_e candidate_type,
				     polsearch_test_cond_e test_cond, polsearch_op_e opr,
				     union match_input &imput) throw(std::runtime_error, std::bad_alloc)
{
	//TODO determine match type and fill in input
}

void polsearch_criterion::check(const apol_policy_t * policy, std::vector < const void *>&test_candidates,
				const std::vector < std::string > &Xnames) throw(std::runtime_error, std::bad_alloc)
{
	if (!_test)
		throw runtime_error("Cannot check criteria until associated with a test.");

	polsearch_element_e candidate_type = determine_candidate_type(_test->elementType(), _test->testCond());
	for (size_t i = 0; i < test_candidates.size(); i++)
	{
		bool match = false;
		union match_input input;
		enum match_type which =
			determine_match_type(policy, test_candidates[i], candidate_type, _test->testCond(), _op, input);

		switch (which)
		{
		case MATCH_BOOL:
		{
			match = _param->match(input.bval);
		}
		case MATCH_STRING:
		{
			match = _param->match(*(input.str), Xnames);
			delete input.str;
		}
		case MATCH_NUM:
		{
			match = _param->match(input.nval);
		}
		case MATCH_LEVEL:
		{
			int method;
			if (_op == POLSEARCH_OP_AS_LEVEL_EXACT)
				method = APOL_MLS_EQ;
			else if (_op == POLSEARCH_OP_AS_LEVEL_DOM)
				method = APOL_MLS_DOM;
			else if (_op == POLSEARCH_OP_AS_LEVEL_DOMBY)
				method = APOL_MLS_DOMBY;
			else
			{
				assert(0);
				throw runtime_error("Impossible case reached.");
			}
			match = _param->match(policy, input.lvl, method);
		}
		case MATCH_RANGE:
		{
			unsigned int method;
			if (_op == POLSEARCH_OP_AS_RANGE_EXACT)
				method = APOL_QUERY_EXACT;
			else if (_op == POLSEARCH_OP_AS_RANGE_SUB)
				method = APOL_QUERY_SUB;
			else if (_op == POLSEARCH_OP_AS_RANGE_SUPER)
				method = APOL_QUERY_SUPER;
			else
			{
				assert(0);
				throw runtime_error("Impossible case reached.");
			}
			match = _param->match(policy, input.rng, method);
		}
		case MATCH_LIST:
		{
			match = _param->match(*(input.list), Xnames);
			delete input.list;
		}
		default:
		{
			assert(0);
			throw runtime_error("Impossible case reached.");
		}
		}

		if (_negated)
			match = !match;

		if (!match)
		{
			test_candidates.erase(test_candidates.begin() + i);
			i--;
		}
	}
}
