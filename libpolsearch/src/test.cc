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
#include "polsearch_internal.hh"

#include <qpol/iterator.h>
#include <qpol/policy.h>

#include <apol/vector.h>
#include <apol/policy.h>
#include <apol/mls_range.h>
#include <apol/mls_level.h>

#include <sefs/fclist.hh>
#include <sefs/entry.hh>
#include <sefs/query.hh>

#include <errno.h>
#include <stdexcept>
#include <cstring>
#include <stdlib.h>
#include <assert.h>

using std::string;
using std::bad_alloc;
using std::invalid_argument;
using std::runtime_error;

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

//! A holding structure for the file_contexts processing callback.
struct fcdata
{
	const apol_vector_t *criteria; //! The list of criteria to check for each entry.
	const apol_policy_t *policy;   //! The policy to use for symbols.
	const apol_vector_t *Xnames;   //! The list of possible names for the symbol X.
	apol_vector_t *cur_proof;      //! The vector to which to append proof entries.
};

static void free_entry(void *e)
{
	delete static_cast < sefs_entry * >(e);
}

/**
 * Callback for processing one file_context entry at a time to avoid
 * potentially large vectors from becoming necessary for large filesystems.
 * @param fclist The file_contexts list from which \a entry comes.
 * @param entry The entry to test.
 * @param data An instance of struct fcdata with all necessary values to
 * check criteria and append a proof as necessary.
 * @return 0 if \a entry was processed successfully, and < 0 on error.
 */
static int fcentry_callback(sefs_fclist * fclist, const sefs_entry * entry, void *data)
{
	struct fcdata *datum = static_cast < struct fcdata *>(data);

	for (size_t i = 0; i < apol_vector_get_size(datum->criteria); i++)
	{
		polsearch_base_criterion *crit =
			static_cast < polsearch_base_criterion * >(apol_vector_get_element(datum->criteria, i));
		apol_vector_t *test_candidates = apol_vector_create_with_capacity(1, NULL);
		if (!test_candidates ||
		    apol_vector_append(test_candidates, const_cast < void *>(static_cast < const void *>(entry))))
			return -1;
		try
		{
			crit->check(datum->policy, test_candidates, POLSEARCH_ELEMENT_FC_ENTRY, datum->Xnames);
			if (apol_vector_get_size(test_candidates))
			{
				sefs_entry *entry_copy = new sefs_entry(entry);
				polsearch_proof *new_proof = new polsearch_proof(POLSEARCH_TEST_FCENTRY, POLSEARCH_ELEMENT_FC_ENTRY,
										 static_cast < void *>(entry_copy), datum->policy,
										 fclist, free_entry);
				if (apol_vector_append(datum->cur_proof, static_cast < void *>(new_proof)))
					throw bad_alloc();
			}
		}
		catch(...)
		{
			apol_vector_destroy(&test_candidates);
			return -1;
		}
		apol_vector_destroy(&test_candidates);
	}
	return 0;
}

/**
 * Get a vector of all valid names for a given policy element.
 * @param elem_type The type of element.
 * @param element The element.
 * @param p The policy from which \a element comes.
 * @return A newly allocated vector of all names (const char *) for \a element.
 * The caller is responsible for calling apol_vector_destroy() on the returned
 * vector. The size of this vector may be zero if \a elem_type is not an element
 * type that can be matched by a name.
 * @exception std::bad_alloc Could not allocate space for the name vector.
 */
static apol_vector_t *get_all_names(polsearch_element_e elem_type, const void *element,
				    const apol_policy_t * p) throw(std::bad_alloc)
{
	apol_vector_t *names = NULL;
	const qpol_policy_t *q = apol_policy_get_qpol(p);
	qpol_iterator_t *iter = NULL;

	// if element is capable of having aliases, get the alias iterator
	if (elem_type == POLSEARCH_ELEMENT_TYPE)
	{
		qpol_type_get_alias_iter(q, static_cast < const qpol_type_t * >(element), &iter);
		if (!iter || (names = apol_vector_create_from_iter(iter, NULL)))
		{
			qpol_iterator_destroy(&iter);
			throw bad_alloc();
		}
	}
	else if (elem_type == POLSEARCH_ELEMENT_CATEGORY)
	{
		qpol_cat_get_alias_iter(q, static_cast < const qpol_cat_t * >(element), &iter);
		if (!iter || (names = apol_vector_create_from_iter(iter, NULL)))
		{
			qpol_iterator_destroy(&iter);
			throw bad_alloc();
		}
	}
	else if (elem_type == POLSEARCH_ELEMENT_LEVEL)
	{
		qpol_level_get_alias_iter(q, static_cast < const qpol_level_t * >(element), &iter);
		if (!iter || (names = apol_vector_create_from_iter(iter, NULL)))
		{
			qpol_iterator_destroy(&iter);
			throw bad_alloc();
		}
	}
	// otherwise, just allocate enough space for the primary name
	else
	{
		if (!(names = apol_vector_create_with_capacity(1, NULL)))
			throw bad_alloc();
	}

	// append the primary name for any element with a name
	if (elem_type <= POLSEARCH_ELEMENT_BOOL && elem_type != POLSEARCH_ELEMENT_NONE)
	{
		const char *prim = polsearch_symbol_get_name(element, static_cast < polsearch_symbol_e > (elem_type), p);
		if (apol_vector_append(names, const_cast < void *>(static_cast < const void *>(prim))))
		{
			apol_vector_destroy(&names);
			throw bad_alloc();
		}
	}

	return names;
}

/**
 * Get a vector of all candidates to test.
 * @param cond The condition being tested.
 * @param elem_type The type of element being tested.
 * @param element The current test element.
 * @param p The policy associated with \a element.
 * @param candidate_type Pointer in which to store the
 * type of candidates returned.
 * @return A newly allocated vector of candidates of the appropriate type
 * for the test \a cond. The caller is responsible for calling
 * apol_vector_destroy() on the returned vector.
 * @exception std::bad_alloc Could not allocate space for the candidate vector.
 * @exception std::runtime_error Could not obtain the candidates.
 */
static apol_vector_t *get_candidates(polsearch_test_cond_e cond, polsearch_element_e elem_type, const void *element,
				     const apol_policy_t * p, polsearch_element_e * candidate_type) throw(std::bad_alloc,
													  std::runtime_error)
{
	apol_vector_t *candidates = NULL;
	qpol_iterator_t *iter = NULL;
	const qpol_policy_t *q = apol_policy_get_qpol(p);

	if (!polsearch_validate_test_condition(elem_type, cond))
		throw runtime_error("Invalid test for given element type");

	switch (cond)
	{
	case POLSEARCH_TEST_NAME:
	{
		if (!(candidates = apol_vector_create_with_capacity(1, NULL)) ||
		    apol_vector_append(candidates,
				       const_cast < void *>(static_cast <
							    const void
							    *>(polsearch_symbol_get_name
							       (element, static_cast < polsearch_symbol_e > (elem_type), p)))))
		{
			apol_vector_destroy(&candidates);
			throw bad_alloc();
		}
		*candidate_type = POLSEARCH_ELEMENT_STRING;
		break;
	}
	case POLSEARCH_TEST_ALIAS:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE)
		{
			qpol_type_get_alias_iter(q, static_cast < const qpol_type_t * >(element), &iter);
			if (!iter || (candidates = apol_vector_create_from_iter(iter, NULL)))
			{
				qpol_iterator_destroy(&iter);
				throw bad_alloc();
			}
		}
		else if (elem_type == POLSEARCH_ELEMENT_CATEGORY)
		{
			qpol_cat_get_alias_iter(q, static_cast < const qpol_cat_t * >(element), &iter);
			if (!iter || (candidates = apol_vector_create_from_iter(iter, NULL)))
			{
				qpol_iterator_destroy(&iter);
				throw bad_alloc();
			}
		}
		else if (elem_type == POLSEARCH_ELEMENT_LEVEL)
		{
			qpol_level_get_alias_iter(q, static_cast < const qpol_level_t * >(element), &iter);
			if (!iter || (candidates = apol_vector_create_from_iter(iter, NULL)))
			{
				qpol_iterator_destroy(&iter);
				throw bad_alloc();
			}
		}
		qpol_iterator_destroy(&iter);
		*candidate_type = POLSEARCH_ELEMENT_STRING;
		break;
	}
	case POLSEARCH_TEST_ATTRIBUTES:
	{
		qpol_type_get_attr_iter(q, static_cast < const qpol_type_t * >(element), &iter);
		if (!iter || (candidates = apol_vector_create_from_iter(iter, NULL)))
		{
			qpol_iterator_destroy(&iter);
			throw bad_alloc();
		}
		qpol_iterator_destroy(&iter);
		*candidate_type = POLSEARCH_ELEMENT_ATTRIBUTE;
		break;
	}
	case POLSEARCH_TEST_ROLES:
	{
		if (elem_type == POLSEARCH_ELEMENT_USER)
		{
			qpol_user_get_role_iter(q, static_cast < const qpol_user_t * >(element), &iter);
			if (!iter || (candidates = apol_vector_create_from_iter(iter, NULL)))
			{
				qpol_iterator_destroy(&iter);
				throw bad_alloc();
			}
			qpol_iterator_destroy(&iter);
		}
		else if (elem_type == POLSEARCH_ELEMENT_TYPE)
		{
			apol_role_query_t *rq = NULL;
			if (!(rq = apol_role_query_create()) ||
			    apol_role_query_set_type(p, rq, polsearch_symbol_get_name(element, POLSEARCH_SYMBOL_TYPE, p)) ||
			    apol_role_get_by_query(p, rq, &candidates))
			{
				apol_role_query_destroy(&rq);
				throw bad_alloc();
			}
			apol_role_query_destroy(&rq);
		}
		*candidate_type = POLSEARCH_ELEMENT_ROLE;
		break;
	}
	case POLSEARCH_TEST_AVRULE:
	{
		apol_avrule_query_t *aq;
		if (!(aq = apol_avrule_query_create()) || apol_avrule_get_by_query(p, aq, &candidates))
		{
			apol_avrule_query_destroy(&aq);
			throw bad_alloc();
		}
		apol_avrule_query_destroy(&aq);
		*candidate_type = POLSEARCH_ELEMENT_AVRULE;
		break;
	}
	case POLSEARCH_TEST_TERULE:
	{
		apol_terule_query_t *tq;
		if (!(tq = apol_terule_query_create()) || apol_terule_get_by_query(p, tq, &candidates))
		{
			apol_terule_query_destroy(&tq);
			throw bad_alloc();
		}
		apol_terule_query_destroy(&tq);
		*candidate_type = POLSEARCH_ELEMENT_TERULE;
		break;
	}
	case POLSEARCH_TEST_ROLEALLOW:
	{
		apol_role_allow_query_t *rq;
		if (!(rq = apol_role_allow_query_create()) || apol_role_allow_get_by_query(p, rq, &candidates))
		{
			apol_role_allow_query_destroy(&rq);
			throw bad_alloc();
		}
		apol_role_allow_query_destroy(&rq);
		*candidate_type = POLSEARCH_ELEMENT_ROLE_ALLOW;
		break;
	}
	case POLSEARCH_TEST_ROLETRANS:
	{
		apol_role_trans_query_t *rq;
		if (!(rq = apol_role_trans_query_create()) || apol_role_trans_get_by_query(p, rq, &candidates))
		{
			apol_role_trans_query_destroy(&rq);
			throw bad_alloc();
		}
		apol_role_trans_query_destroy(&rq);
		*candidate_type = POLSEARCH_ELEMENT_ROLE_TRANS;
		break;
	}
	case POLSEARCH_TEST_RANGETRANS:
	{
		apol_range_trans_query_t *rq;
		if (!(rq = apol_range_trans_query_create()) || apol_range_trans_get_by_query(p, rq, &candidates))
		{
			apol_range_trans_query_destroy(&rq);
			throw bad_alloc();
		}
		apol_range_trans_query_destroy(&rq);
		*candidate_type = POLSEARCH_ELEMENT_RANGE_TRANS;
		break;
	}
	case POLSEARCH_TEST_TYPES:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE)
		{
			qpol_type_get_type_iter(q, static_cast < const qpol_type_t * >(element), &iter);
			if (!iter || (candidates = apol_vector_create_from_iter(iter, NULL)))
			{
				qpol_iterator_destroy(&iter);
				throw bad_alloc();
			}
		}
		else if (elem_type == POLSEARCH_ELEMENT_ROLE)
		{
			qpol_role_get_type_iter(q, static_cast < const qpol_role_t * >(element), &iter);
			if (!iter || (candidates = apol_vector_create_from_iter(iter, NULL)))
			{
				qpol_iterator_destroy(&iter);
				throw bad_alloc();
			}
		}
		qpol_iterator_destroy(&iter);
		*candidate_type = POLSEARCH_ELEMENT_TYPE;
		break;
	}
	case POLSEARCH_TEST_USERS:
	{
		apol_user_query_t *uq = NULL;
		if (!(uq = apol_user_query_create()) ||
		    apol_user_query_set_role(p, uq, polsearch_symbol_get_name(element, POLSEARCH_SYMBOL_ROLE, p)) ||
		    apol_user_get_by_query(p, uq, &candidates))
		{
			apol_user_query_destroy(&uq);
			throw bad_alloc();
		}
		apol_user_query_destroy(&uq);
		*candidate_type = POLSEARCH_ELEMENT_USER;
		break;
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	{
		const qpol_mls_level_t *lvl = NULL;
		qpol_user_get_dfltlevel(q, static_cast < const qpol_user_t * >(element), &lvl);
		if (!(candidates = apol_vector_create_with_capacity(1, NULL)) ||
		    apol_vector_append(candidates, const_cast < void *>(static_cast < const void *>(lvl))))
		{
			apol_vector_destroy(&candidates);
			throw bad_alloc();
		}
		*candidate_type = POLSEARCH_ELEMENT_LEVEL;
		break;
	}
	case POLSEARCH_TEST_RANGE:
	{
		const qpol_mls_range_t *rng = NULL;
		qpol_user_get_range(q, static_cast < const qpol_user_t * >(element), &rng);
		if (!(candidates = apol_vector_create_with_capacity(1, NULL)) ||
		    apol_vector_append(candidates, const_cast < void *>(static_cast < const void *>(rng))))
		{
			apol_vector_destroy(&candidates);
			throw bad_alloc();
		}
		*candidate_type = POLSEARCH_ELEMENT_MLS_RANGE;
		break;
	}
	case POLSEARCH_TEST_COMMON:
	{
		const qpol_common_t *c = NULL;
		qpol_class_get_common(q, static_cast < const qpol_class_t * >(element), &c);
		if (!(candidates = apol_vector_create_with_capacity(1, NULL)) ||
		    apol_vector_append(candidates, const_cast < void *>(static_cast < const void *>(c))))
		{
			apol_vector_destroy(&candidates);
			throw bad_alloc();
		}
		*candidate_type = POLSEARCH_ELEMENT_COMMON;
		break;
	}
	case POLSEARCH_TEST_PERMISSIONS:
	{
		const qpol_common_t *c = NULL;
		apol_vector_t *uniq = NULL;
		if (elem_type = POLSEARCH_ELEMENT_CLASS)
		{
			if (qpol_class_get_perm_iter(q, static_cast < const qpol_class_t * >(element), &iter) ||
			    !(uniq = apol_vector_create_from_iter(iter, NULL)))
			{
				qpol_iterator_destroy(&iter);
				throw bad_alloc();
			}
			qpol_iterator_destroy(&iter);
			qpol_class_get_common(q, static_cast < const qpol_class_t * >(element), &c);
		}
		else if (elem_type == POLSEARCH_ELEMENT_COMMON)
		{
			c = static_cast < const qpol_common_t *>(element);
		}
		if (c)
		{
			if (qpol_common_get_perm_iter(q, c, &iter) ||
			    !(candidates = apol_vector_create_from_iter(iter, NULL)) ||
			    (uniq ? apol_vector_cat(candidates, uniq) : 1))
			{
				apol_vector_destroy(&uniq);
				apol_vector_destroy(&candidates);
				qpol_iterator_destroy(&iter);
				throw bad_alloc();
			}
			apol_vector_destroy(&uniq);
		}
		else
		{
			candidates = uniq;
		}
		*candidate_type = POLSEARCH_ELEMENT_PERMISSION;
		break;
	}
	case POLSEARCH_TEST_CATEGORIES:
	{
		qpol_level_get_cat_iter(q, static_cast < const qpol_level_t * >(element), &iter);
		if (!iter || (candidates = apol_vector_create_from_iter(iter, NULL)))
		{
			qpol_iterator_destroy(&iter);
			throw bad_alloc();
		}
		qpol_iterator_destroy(&iter);
		*candidate_type = POLSEARCH_ELEMENT_CATEGORY;
		break;
	}
	case POLSEARCH_TEST_STATE:
	{
		int state = 0;
		qpol_bool_get_state(q, static_cast < const qpol_bool_t * >(element), &state);
		if (!(candidates = apol_vector_create_with_capacity(1, NULL)) ||
		    apol_vector_append(candidates, reinterpret_cast < void *>(state)))
		{
			apol_vector_destroy(&candidates);
			throw bad_alloc();
		}
		*candidate_type = POLSEARCH_ELEMENT_BOOL_STATE;
		break;
	}
	case POLSEARCH_TEST_FCENTRY:
	case POLSEARCH_TEST_NONE:
	default:
	{
		// should not be possible to get here
		assert(0);
		throw runtime_error("reached impossible state");
	}
	}

	return candidates;
}

apol_vector_t *polsearch_test::run(const apol_policy_t * p, sefs_fclist * fclist,
				   apol_vector_t * Xcandidates, bool prune) const throw(std::bad_alloc, std::runtime_error)
{
	if (!apol_vector_get_size(_criteria))
		throw runtime_error("No criteria to check");

	for (size_t i = 0; i < apol_vector_get_size(_criteria); i++)
	{
		polsearch_base_criterion *tmp = static_cast < polsearch_base_criterion * >(apol_vector_get_element(_criteria, i));
		if (!polsearch_validate_operator(_element_type, _test_cond, tmp->op()))
			throw runtime_error("Invalid criterion");
	}

	apol_vector_t *results = apol_vector_create(free_result);

	// test each candidates for X
	for (size_t j = 0; j < apol_vector_get_size(Xcandidates); j++)
	{
		apol_vector_t *Xnames = get_all_names(_element_type, apol_vector_get_element(Xcandidates, j), p);

		if (_test_cond == POLSEARCH_TEST_FCENTRY)
		{
			apol_vector_t *cur_proof = apol_vector_create(free_proof);
			sefs_query *query = new sefs_query();
			struct fcdata datum = { _criteria, p, Xnames, cur_proof };
			if (fclist->runQueryMap(query, fcentry_callback, static_cast < void *>(&datum)))
				throw runtime_error("Error while reading file_contexts list");
			if (apol_vector_get_size(cur_proof))
			{
				polsearch_result *cur =
					new polsearch_result(_element_type, apol_vector_get_element(Xcandidates, j), p, fclist);
				for (size_t i = 0; i < apol_vector_get_size(cur_proof); i++)
				{
					void *tmp = dup_proof(apol_vector_get_element(cur_proof, i), NULL);
					if (!tmp || apol_vector_append(cur->proof(), tmp))
						throw bad_alloc();
				}
			}
			else if (prune)
			{
				// prune Xcandidates; no test candidates matched the criteria.
				apol_vector_remove(Xcandidates, j);
				j--;
			}
			apol_vector_destroy(&cur_proof);
		}
		else
		{
			// get test candidates
			polsearch_element_e candidate_type;
			apol_vector_t *test_candidates =
				get_candidates(_test_cond, _element_type, apol_vector_get_element(Xcandidates, j), p,
					       &candidate_type);

			// check each criterion to prune the test candidates
			for (size_t i = 0; i < apol_vector_get_size(_criteria); i++)
			{
				polsearch_base_criterion *crit =
					static_cast < polsearch_base_criterion * >(apol_vector_get_element(_criteria, i));
				crit->check(p, test_candidates, candidate_type, Xnames);
			}

			// if there are remaining candidates, create a result entry and a proof entry for each candidate.
			if (apol_vector_get_size(test_candidates))
			{
				polsearch_result *cur =
					new polsearch_result(_element_type, apol_vector_get_element(Xcandidates, j), p, fclist);
				for (size_t i = 0; i < apol_vector_get_size(test_candidates); i++)
				{
					polsearch_proof *proof = new polsearch_proof(_test_cond, candidate_type,
										     apol_vector_get_element(test_candidates, i),
										     p, fclist);
					if (apol_vector_append(cur->proof(), static_cast < void *>(proof)))
						throw bad_alloc();
				}
				if (apol_vector_append(results, static_cast < void *>(cur)))
					throw bad_alloc();
			}
			else if (prune)
			{
				// prune Xcandidates; no test candidates matched the criteria.
				apol_vector_remove(Xcandidates, j);
				j--;
			}
			apol_vector_destroy(&test_candidates);
		}
		apol_vector_destroy(&Xnames);
	}

	return results;
}

// polsearch result

polsearch_result::polsearch_result(polsearch_element_e elem_type, const void *elem, const apol_policy_t * p,
				   sefs_fclist * fclist)throw(std::bad_alloc)
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
				 sefs_fclist * fclist, polsearch_proof_element_free_fn free_fn)
{
	_test_cond = test;
	_element_type = elem_type;
	_element = elem;
	_policy = p;
	_fclist = fclist;
	_free_fn = free_fn;
}

polsearch_proof::polsearch_proof(const polsearch_proof & pp)
{
	_test_cond = pp._test_cond;
	_element_type = pp._element_type;
	_policy = pp._policy;
	_fclist = pp._fclist;
	_free_fn = pp._free_fn;
	if (_free_fn)
		_element = element_copy(_element_type, pp._element);
	else
		_element = pp._element;
}

polsearch_proof::~polsearch_proof()
{
	if (_free_fn)
		_free_fn(_element);
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

	// comparison makes no sense if results are not same element type
	assert(left->elementType() == right->elementType());

	return element_compare(left->elementType(), left->element(), right->element(), policy);
}

void merge_results(const apol_policy_t * policy, apol_vector_t * master_results, apol_vector_t * cur_results,
		   polsearch_match_e m) throw(std::bad_alloc)
{
	apol_vector_sort(master_results, result_cmp, const_cast < void *>(static_cast < const void *>(policy)));
	apol_vector_sort(cur_results, result_cmp, const_cast < void *>(static_cast < const void *>(policy)));
	size_t i, j, master_orig_end = apol_vector_get_size(master_results);
	bool add_all = false;

	// if master is empty originally add all of current
	if (!master_orig_end)
		add_all = true;

	for (i = 0, j = 0; i < master_orig_end && j < apol_vector_get_size(cur_results);)
	{
		int cmp = result_cmp(apol_vector_get_element(master_results, i), apol_vector_get_element(cur_results, j),
				     const_cast < void *>(static_cast < const void *>(policy)));
		if (cmp < 0)
		{
			// entry in master but not current;
			if (m == POLSEARCH_MATCH_ALL)
			{
				// must match all tests remove this result.
				apol_vector_remove(master_results, i);
				master_orig_end--;
				continue;
			}
			else
			{
				// matching any; just move on
				i++;
				continue;
			}
		}
		else if (cmp > 0)
		{
			// entry new in current results
			if (m == POLSEARCH_MATCH_ALL)
			{
				// did not match previous test; move on
				j++;
				continue;
			}
			else
			{
				// copy it
				void *tmp = dup_result(apol_vector_get_element(cur_results, j), NULL);
				if (apol_vector_append(master_results, tmp))
				{
					free_result(tmp);
					throw bad_alloc();
				}
				j++;
				continue;
			}
		}
		else
		{
			polsearch_result *mr = static_cast < polsearch_result * >(apol_vector_get_element(master_results, i));
			polsearch_result *cr = static_cast < polsearch_result * >(apol_vector_get_element(cur_results, j));
			apol_vector_t *master_proof = mr->proof();
			apol_vector_t *cur_proof = cr->proof();
			merge_proof(policy, master_proof, cur_proof);
			i++;
			j++;
		}
	}
	if (m == POLSEARCH_MATCH_ANY || add_all)
	{
		// copy any remaining results to master
		for (; j < apol_vector_get_size(cur_results); j++)
		{
			void *tmp = dup_result(apol_vector_get_element(cur_results, j), NULL);
			if (apol_vector_append(master_results, tmp))
			{
				free_result(tmp);
				throw bad_alloc();
			}
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

int proof_cmp(const void *a, const void *b, void *data)
{
	const polsearch_proof *left = static_cast < const polsearch_proof * >(a);
	const polsearch_proof *right = static_cast < const polsearch_proof * >(b);
	apol_policy_t *policy = static_cast < apol_policy_t * >(data);

	// compare test condition
	if (left->testCond() != right->testCond())
		return static_cast < int >(left->testCond()) - static_cast < int >(right->testCond());

	// compare element type
	if (left->elementType() != right->elementType())
		return static_cast < int >(left->elementType()) - static_cast < int >(right->elementType());

	// compare element
	return element_compare(left->elementType(), left->element(), right->element(), policy);
}

void merge_proof(const apol_policy_t * policy, apol_vector_t * master_proof, apol_vector_t * cur_proof) throw(std::bad_alloc)
{
	apol_vector_sort(master_proof, proof_cmp, const_cast < void *>(static_cast < const void *>(policy)));
	apol_vector_sort(cur_proof, proof_cmp, const_cast < void *>(static_cast < const void *>(policy)));
	size_t i, j, master_orig_size = apol_vector_get_size(master_proof);

	for (i = 0, j = 0; i < master_orig_size && j < apol_vector_get_size(cur_proof);)
	{
		int cmp = proof_cmp(apol_vector_get_element(master_proof, i), apol_vector_get_element(cur_proof, j),
				    const_cast < void *>(static_cast < const void *>(policy)));
		if (cmp < 0)
		{
			// entry in master not current; move on
			i++;
			continue;
		}
		else if (cmp > 0)
		{
			// new proof; copy it
			void *tmp = dup_proof(apol_vector_get_element(cur_proof, j), NULL);
			if (apol_vector_append(master_proof, tmp))
			{
				free_proof(tmp);
				throw bad_alloc();
			}
			j++;
			continue;
		}
		else
		{
			// proof already exists; move on
			i++;
			j++;
		}
	}
	// copy any remaining proof
	for (; j < apol_vector_get_size(cur_proof); j++)
	{
		void *tmp = dup_proof(apol_vector_get_element(cur_proof, j), NULL);
		if (apol_vector_append(master_proof, tmp))
		{
			free_proof(tmp);
			throw bad_alloc();
		}
	}
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

apol_vector_t *polsearch_test_run(const polsearch_test_t * pt, const apol_policy_t * p, sefs_fclist_t * fclist,
				  apol_vector_t * Xcandidates, bool prune)
{
	if (!pt)
	{
		errno = EINVAL;
		return NULL;
	}

	try
	{
		return pt->run(p, fclist, Xcandidates, prune);
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
					    sefs_fclist_t * fclist)
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
					  const apol_policy_t * p, sefs_fclist_t * fclist)
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
