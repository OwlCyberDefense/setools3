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
#include <polsearch/result.hh>
#include <polsearch/proof.hh>
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

polsearch_test::polsearch_test()
{
	throw std::runtime_error("Cannot directly create tests.");
}

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
	update();
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
	_criteria.push_back(polsearch_criterion(this, opr, neg));
	return _criteria.back();
}

bool polsearch_test::isContinueable()
{
	switch (_test_cond)
	{
	case POLSEARCH_TEST_AVRULE:   /*!< there is an av rule */
	case POLSEARCH_TEST_TERULE:   /*!< there is a type rule */
	case POLSEARCH_TEST_ROLEALLOW:	/*!< there is a role allow rule */
	case POLSEARCH_TEST_ROLETRANS:	/*!< there is a role_transition rule */
	case POLSEARCH_TEST_RANGETRANS:	/*!< there is a range_transition rule */
	case POLSEARCH_TEST_FCENTRY:  /*!< there is a file_contexts entry */
		return true;
	case POLSEARCH_TEST_NAME:     /*!< primary name of the symbol */
	case POLSEARCH_TEST_ALIAS:    /*!< alias(es) of the symbol */
	case POLSEARCH_TEST_ATTRIBUTES:	/*!< assigned attributes */
	case POLSEARCH_TEST_ROLES:    /*!< assigned roles (or assigned to roles) */
	case POLSEARCH_TEST_TYPES:    /*!< assigned types */
	case POLSEARCH_TEST_USERS:    /*!< assigned to users */
	case POLSEARCH_TEST_DEFAULT_LEVEL:	/*!< its default level */
	case POLSEARCH_TEST_RANGE:    /*!< assigned range */
	case POLSEARCH_TEST_COMMON:   /*!< inherited common */
	case POLSEARCH_TEST_PERMISSIONS:	/*!< assigned permissions */
	case POLSEARCH_TEST_CATEGORIES:	/*!< assigned categories */
	case POLSEARCH_TEST_STATE:    /*!< boolean default state */
	case POLSEARCH_TEST_NONE:     /*!< only used for error conditions */
	default:
		return false;
	}
}

std::vector < polsearch_op_e > polsearch_test::getValidOperators()
{
	vector < polsearch_op_e > v;
	for (int i = POLSEARCH_OP_NONE; i <= POLSEARCH_OP_AS_TYPE; i++)
		if (validate_operator(_query->elementType(), _test_cond, static_cast < polsearch_op_e > (i)))
			v.push_back(static_cast < polsearch_op_e > (i));

	return v;
}

//! A holding structure for the file_contexts processing callback.
struct fcdata
{
	const vector < polsearch_criterion > *criteria;	//! The list of criteria to check for each entry.
	const apol_policy_t *policy;   //! The policy to use for symbols.
	vector < string > *Xnames;     //! The list of possible names for the symbol X.
	vector < polsearch_proof > *cur_proof;	//! The vector to which to append proof entries.
};

/**
 * Callback for processing one file_context entry at a time to avoid
 * potentially large vectors from becoming necessary for large filesystems.
 * @param fclist The file_contexts list from which \a entry comes.
 * @param entry The entry to test.
 * @param data An instance of struct fcdata with all necessary values to
 * check criteria and append a proof as necessary.
 * @return 0 if \a entry was processed successfully, and < 0 on error.
 */
int fcentry_callback(sefs_fclist * fclist, const sefs_entry * entry, void *data)
{
	struct fcdata *datum = static_cast < struct fcdata *>(data);

	for (vector < polsearch_criterion >::const_iterator i = datum->criteria->begin(); i != datum->criteria->end(); ++i)
	{
		vector < const void *>test_candidates;
		test_candidates.push_back(static_cast < const void *>(entry));
		(*i).check(datum->policy, test_candidates, *(datum->Xnames));
		if (test_candidates.size())
		{
			sefs_entry *entry_copy = new sefs_entry(entry);
			polsearch_proof *new_proof = new polsearch_proof(POLSEARCH_TEST_FCENTRY, POLSEARCH_ELEMENT_FC_ENTRY,
									 static_cast < void *>(entry_copy), datum->policy,
									 fclist, get_element_free_fn(POLSEARCH_ELEMENT_FC_ENTRY));
			datum->cur_proof->push_back(*new_proof);
		}
	}
	return 0;
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
static vector < const void *>get_test_candidates(const apol_policy_t * policy, const void *element, polsearch_element_e elem_type,
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
	case POLSEARCH_ELEMENT_MLS_LEVEL:
	{
		const qpol_mls_level_t *lvl = NULL;
		qpol_user_get_dfltlevel(qp, static_cast < const qpol_user_t * >(element), &lvl);
		const apol_mls_level_t *alvl = apol_mls_level_create_from_qpol_mls_level(policy, lvl);
		ret_v.push_back(static_cast < const void *>(alvl));
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
		if (elem_type == POLSEARCH_ELEMENT_CLASS)
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

const std::vector < polsearch_result > polsearch_test::run(const apol_policy_t * policy, sefs_fclist * fclist,
							   std::vector <
							   const void *>&Xcandidates) const throw(std::runtime_error)
{
	if (_criteria.empty())
		throw runtime_error("No criteria to test.");

	for (size_t i = 0; i < _criteria.size(); i++)
		if (!validate_parameter_type
		    (_query->elementType(), _test_cond, _criteria[i].op(), _criteria[i].param()->paramType()))
			throw runtime_error("Attempt to test invalid criteria");

	vector < polsearch_result > result_v;
	polsearch_element_e candidate_type = determine_candidate_type(_test_cond);

	for (size_t i = 0; i < Xcandidates.size(); i++)
	{
		vector < string > Xnames = get_all_names(Xcandidates[i], elementType(), policy);
		if (_test_cond == POLSEARCH_TEST_FCENTRY)
		{
			vector < polsearch_proof > *cur_proof = new vector < polsearch_proof > ();
			sefs_query *query = new sefs_query();
			struct fcdata datum = { &_criteria, policy, &Xnames, cur_proof };
			if (fclist->runQueryMap(query, fcentry_callback, static_cast < void *>(&datum)))
				throw runtime_error("Error while reading file_contexts list");
			if (!cur_proof->empty())
			{
				polsearch_result cur(_query->elementType(), Xcandidates[i], policy, fclist);
				for (vector < polsearch_proof >::const_iterator j = cur_proof->begin(); j != cur_proof->end(); j++)
				{
					cur.addProof(*j);
				}
				//append result to result_v
				result_v.push_back(cur);
			}
			else if (_query->match() == POLSEARCH_MATCH_ALL)
			{
				Xcandidates.erase(Xcandidates.begin() + i);
				i--;
			}
			delete cur_proof;
			delete query;
		}
		else
		{
			vector < const void *>test_candidates =
				get_test_candidates(policy, Xcandidates[i], _query->elementType(), _test_cond);
			for (vector < polsearch_criterion >::const_iterator j = _criteria.begin(); j != _criteria.end(); j++)
			{
				j->check(policy, test_candidates, Xnames);
			}

			if (!test_candidates.empty())
			{
				//create result entry for Xcandidates[i]
				polsearch_result res(_query->elementType(), Xcandidates[i], policy, fclist);
				for (size_t j = 0; j < test_candidates.size(); j++)
				{
					//create proof and append to result; const cast due to some qpol objects' need to be freed
					res.addProof(_test_cond, candidate_type, const_cast < void *>(test_candidates[j]),
						     get_element_free_fn(candidate_type));
				}
				//append result to result_v
				result_v.push_back(res);
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

void polsearch_test::update()
{
	for (vector < polsearch_criterion >::iterator i = _criteria.begin(); i != _criteria.end(); i++)
	{
		i->_test = this;
	}
}
