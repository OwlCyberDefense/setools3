/**
 * @file
 *
 * Routines to create policy element tests.
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
#include <polsearch/parameter.hh>
#include <polsearch/test.hh>
#include <polsearch/query.hh>
#include "polsearch_internal.hh"

#include <stdexcept>
#include <string>
#include <vector>

using std::invalid_argument;
using std::runtime_error;
using std::vector;
using std::string;
using std::bad_alloc;

polsearch_test::polsearch_test(polsearch_query * query, polsearch_test_cond_e test_cond) throw(std::invalid_argument)
{
	if (!validate_test_condition(query->elementType(), test_cond))
		throw invalid_argument("The given test condition is not valid for the given element.");

	_query = query;
	_test_cond = test_cond;
}

polsearch_test::polsearch_test(const polsearch_test & rhs)
{
	_criteria = rhs._criteria;
	_query = rhs._query;
	_test_cond = rhs._test_cond;
}

polsearch_test::~polsearch_test()
{
	// no-op
}

polsearch_element_e polsearch_test::elementType() const
{
	return _query->elementType();
}

polsearch_test_cond_e polsearch_test::testCond() const
{
	return _test_cond;
}

polsearch_test_cond_e polsearch_test::testCond(polsearch_test_cond_e test_cond) throw(std::invalid_argument)
{
	if (!validate_test_condition(_query->elementType(), test_cond))
		throw invalid_argument("Invalid test for this element.");

	return _test_cond = test_cond;
}

polsearch_criterion & polsearch_test::addCriterion(polsearch_op_e opr, bool neg) throw(std::invalid_argument)
{
	polsearch_criterion crit(this, opr, neg);
	_criteria.insert(_criteria.end(), crit);
	return _criteria.back();
}

/**
 * Get all valid names for a policy element.
 * @param element The element.
 * @param elem_type The type of element.
 * @param policy The policy from which \a element comes.
 * @return A vector of all valid names for the element. This vector may be
 * empty if \a element is of a type which cannot be identified by a name.
 * @exception std::bad_alloc Out of memory.
 */
static vector < string > get_all_names(const void *element, polsearch_element_e elem_type,
				       const apol_policy_t * policy) throw(std::bad_alloc)
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

/**
 * Get all candidates for a given test.
 * @param policy The policy being tested.
 * @param element The current element being tested.
 * @param elem_type The type of \a element.
 * @param test_cond The condition being tested.
 * @return A vector of candidates suitable for checking the test's criteria.
 * @exception std::runtime_error Error attempting to build the candidate list.
 * @exception std::bad_alloc Out of memory.
 */
static vector < const void *>get_candidates(const apol_policy_t * policy, const void *element, polsearch_element_e elem_type,
					    polsearch_test_cond_e test_cond) throw(std::runtime_error, std::bad_alloc)
{
	polsearch_element_e candidate_type = determine_candidate_type(test_cond);
	vector < const void *>ret_v;
	const qpol_policy_t *qp = apol_policy_get_qpol(policy);
	qpol_iterator_t *iter = NULL;
	apol_vector_t *candidates = NULL;

	switch (candidate_type)
	{
	case POLSEARCH_ELEMENT_TYPE:
	{
		if (elem_type == POLSEARCH_ELEMENT_ATTRIBUTE)
		{
			qpol_type_get_type_iter(qp, static_cast < const qpol_type_t * >(element), &iter);
		}
		else if (elem_type == POLSEARCH_ELEMENT_ROLE)
		{
			qpol_role_get_type_iter(qp, static_cast < const qpol_role_t * >(element), &iter);
		}
		if (!iter)
			throw bad_alloc();
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
		{
			void *type;
			qpol_iterator_get_item(iter, &type);
			ret_v.push_back(type);
		}
		qpol_iterator_destroy(&iter);
		break;
	}
	case POLSEARCH_ELEMENT_ATTRIBUTE:
	{
		qpol_type_get_attr_iter(qp, static_cast < const qpol_type_t * >(element), &iter);
		if (!iter)
			throw bad_alloc();
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
		{
			void *attr;
			qpol_iterator_get_item(iter, &attr);
			ret_v.push_back(attr);
		}
		qpol_iterator_destroy(&iter);
		break;
	}
	case POLSEARCH_ELEMENT_ROLE:
	{
		if (elem_type == POLSEARCH_ELEMENT_USER)
		{
			qpol_user_get_role_iter(qp, static_cast < const qpol_user_t * >(element), &iter);
			if (!iter)
				throw bad_alloc();
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
			{
				void *role;
				qpol_iterator_get_item(iter, &role);
				ret_v.push_back(role);
			}
			qpol_iterator_destroy(&iter);
		}
		else if (elem_type == POLSEARCH_ELEMENT_TYPE)
		{
			apol_role_query_t *rq = NULL;
			if (!(rq = apol_role_query_create()) ||
			    apol_role_query_set_type(policy, rq, symbol_get_name(element, POLSEARCH_ELEMENT_TYPE, policy)) ||
			    apol_role_get_by_query(policy, rq, &candidates))
			{
				apol_role_query_destroy(&rq);
				throw bad_alloc();
			}
			apol_role_query_destroy(&rq);
		}
		break;
	}
	case POLSEARCH_ELEMENT_USER:
	{
		apol_user_query_t *uq = NULL;
		if (!(uq = apol_user_query_create()) ||
		    apol_user_query_set_role(policy, uq, symbol_get_name(element, POLSEARCH_ELEMENT_ROLE, policy)) ||
		    apol_user_get_by_query(policy, uq, &candidates))
		{
			apol_user_query_destroy(&uq);
			throw bad_alloc();
		}
		apol_user_query_destroy(&uq);
		break;
	}
	case POLSEARCH_ELEMENT_COMMON:
	{
		const qpol_common_t *c = NULL;
		qpol_class_get_common(qp, static_cast < const qpol_class_t * >(element), &c);
		ret_v.push_back(static_cast < const void *>(c));
		break;
	}
	case POLSEARCH_ELEMENT_CATEGORY:
	{
		qpol_level_get_cat_iter(qp, static_cast < const qpol_level_t * >(element), &iter);
		if (!iter)
			throw bad_alloc();
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
		{
			void *cat;
			qpol_iterator_get_item(iter, &cat);
			ret_v.push_back(cat);
		}
		qpol_iterator_destroy(&iter);
		break;
	}
	case POLSEARCH_ELEMENT_LEVEL:
	{
		const qpol_mls_level_t *lvl = NULL;
		qpol_user_get_dfltlevel(qp, static_cast < const qpol_user_t * >(element), &lvl);
		ret_v.push_back(static_cast < const void *>(lvl));
		break;
	}
	case POLSEARCH_ELEMENT_STRING:
	{
		if (test_cond == POLSEARCH_TEST_NAME)
		{
			const char *name = symbol_get_name(element, elem_type, policy);
			if (!name)
				throw runtime_error("Could not get candidates.");
			ret_v.push_back(static_cast < const void *>(name));
			break;
		}
		else if (test_cond == POLSEARCH_TEST_ALIAS)
		{
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
			else
				throw runtime_error("Could not get candidates.");

			if (iter)
			{
				for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
				{
					void *name;
					qpol_iterator_get_item(iter, &name);
					ret_v.push_back(name);
				}
			}
			qpol_iterator_destroy(&iter);
			break;
		}
	}
	case POLSEARCH_ELEMENT_AVRULE:
	{
		apol_avrule_query_t *aq;
		if (!(aq = apol_avrule_query_create()) || apol_avrule_get_by_query(policy, aq, &candidates))
		{
			apol_avrule_query_destroy(&aq);
			throw bad_alloc();
		}
		apol_avrule_query_destroy(&aq);
		break;
	}
	case POLSEARCH_ELEMENT_TERULE:
	{
		apol_terule_query_t *tq;
		if (!(tq = apol_terule_query_create()) || apol_terule_get_by_query(policy, tq, &candidates))
		{
			apol_terule_query_destroy(&tq);
			throw bad_alloc();
		}
		apol_terule_query_destroy(&tq);
		break;
	}
	case POLSEARCH_ELEMENT_ROLE_ALLOW:
	{
		apol_role_allow_query_t *rq;
		if (!(rq = apol_role_allow_query_create()) || apol_role_allow_get_by_query(policy, rq, &candidates))
		{
			apol_role_allow_query_destroy(&rq);
			throw bad_alloc();
		}
		apol_role_allow_query_destroy(&rq);
		break;
	}
	case POLSEARCH_ELEMENT_ROLE_TRANS:
	{
		apol_role_trans_query_t *rq;
		if (!(rq = apol_role_trans_query_create()) || apol_role_trans_get_by_query(policy, rq, &candidates))
		{
			apol_role_trans_query_destroy(&rq);
			throw bad_alloc();
		}
		apol_role_trans_query_destroy(&rq);
		break;
	}
	case POLSEARCH_ELEMENT_RANGE_TRANS:
	{
		apol_range_trans_query_t *rq;
		if (!(rq = apol_range_trans_query_create()) || apol_range_trans_get_by_query(policy, rq, &candidates))
		{
			apol_range_trans_query_destroy(&rq);
			throw bad_alloc();
		}
		apol_range_trans_query_destroy(&rq);
		break;
	}
	case POLSEARCH_ELEMENT_MLS_RANGE:
	{
		const qpol_mls_range_t *rng = NULL;
		qpol_user_get_range(qp, static_cast < const qpol_user_t * >(element), &rng);
		ret_v.push_back(static_cast < const void *>(rng));
		break;
	}
	case POLSEARCH_ELEMENT_PERMISSION:
	{
		const qpol_common_t *c = NULL;
		if (elem_type = POLSEARCH_ELEMENT_CLASS)
		{
			qpol_class_get_perm_iter(qp, static_cast < const qpol_class_t * >(element), &iter);
			if (!iter)
				throw bad_alloc();
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
			{
				void *perm;
				qpol_iterator_get_item(iter, &perm);
				ret_v.push_back(perm);
			}
			qpol_iterator_destroy(&iter);
			qpol_class_get_common(qp, static_cast < const qpol_class_t * >(element), &c);
		}
		else if (elem_type == POLSEARCH_ELEMENT_COMMON)
		{
			c = static_cast < const qpol_common_t *>(element);
		}
		if (c)
		{
			qpol_common_get_perm_iter(qp, c, &iter);
			if (!iter)
				throw bad_alloc();
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
			{
				void *perm;
				qpol_iterator_get_item(iter, &perm);
				ret_v.push_back(perm);
			}
			qpol_iterator_destroy(&iter);
		}
		break;
	}
	case POLSEARCH_ELEMENT_BOOL_STATE:
	{
		int state = 0;
		qpol_bool_get_state(qp, static_cast < const qpol_bool_t * >(element), &state);
		ret_v.push_back(reinterpret_cast < const void *>(state));
		break;
	}
	case POLSEARCH_ELEMENT_FC_ENTRY:
	case POLSEARCH_ELEMENT_CLASS:
	case POLSEARCH_ELEMENT_BOOL:
	case POLSEARCH_ELEMENT_NONE:
	default:
	{
		assert(0);
		throw runtime_error("Impossible case reached.");
	}
	}
	if (!candidates && ret_v.empty())
		throw runtime_error("No match for requested candidates.");
	//note: get_size of NULL returns 0
	for (size_t i = 0; i < apol_vector_get_size(candidates); i++)
		ret_v.push_back(apol_vector_get_element(candidates, i));
	apol_vector_destroy(&candidates);

	return ret_v;
}

std::vector < polsearch_result * >polsearch_test::run(apol_policy_t * policy, sefs_fclist * fclist,
						      std::vector < const void *>&Xcandidates) const throw(std::runtime_error)
{
	if (_criteria.empty())
		throw runtime_error("No criteria to test.");

	for (size_t i = 0; i < _criteria.size(); i++)
		if (!validate_parameter_type
		    (_query->elementType(), _test_cond, _criteria[i].op(), _criteria[i].param()->paramType()))
			throw runtime_error("Attempt to test invalid criteria");

	vector < polsearch_result * >result_v;
	polsearch_element_e candidate_type = determine_candidate_type(_test_cond);

	for (size_t i = 0; i < Xcandidates.size(); i++)
	{
		vector < string > Xnames = get_all_names(Xcandidates[i], candidate_type, policy);
		//TODO test run function
		if (_test_cond == POLSEARCH_TEST_FCENTRY)
		{
			//TODO fcentry part of test.run()
		}
		else
		{
			vector < const void *>test_candidates =
				get_candidates(policy, Xcandidates[i], _query->elementType(), _test_cond);
			for (size_t j = 0; j < _criteria.size(); j++)
			{
				_criteria[j].check(policy, test_candidates, Xnames);
			}

			if (!test_candidates.empty())
			{
				//TODO create result entry
				for (size_t j = 0; j < test_candidates.size(); j++)
				{
					//TODO create proof and append to result
				}
				//TODO append result to result_v
			}
			else if (_query->match() == POLSEARCH_MATCH_ALL)
			{
				Xcandidates.erase(Xcandidates.begin() + i);
				i--;
			}
		}
	}

	return result_v;
}
