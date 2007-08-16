/**
 * @file
 *
 * Routines to create policy element test results.
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
#include <polsearch/result.hh>
#include <polsearch/test.hh>
#include <polsearch/proof.hh>
#include "polsearch_internal.hh"

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <string>
#include <vector>
#include <iterator>

using std::vector;
using std::iterator;
using std::string;
using std::invalid_argument;

polsearch_result::polsearch_result()
{
	throw std::runtime_error("Cannot directly create result entries.");
}

polsearch_result::polsearch_result(polsearch_element_e elem_type, const void *elem, const apol_policy_t * p, sefs_fclist * fclist)
{
	_element_type = elem_type;
	_element = elem;
	_policy = p;
	_fclist = fclist;
}

polsearch_result::polsearch_result(const polsearch_result & rhs)
{
	_element_type = rhs._element_type;
	_element = rhs._element;
	_policy = rhs._policy;
	_fclist = rhs._fclist;
	_proof = rhs._proof;
}

polsearch_result::~polsearch_result()
{
	//nothing to do
}

polsearch_element_e polsearch_result::elementType() const
{
	return _element_type;
}

const void *polsearch_result::element() const
{
	return _element;
}

const vector < polsearch_proof > &polsearch_result::proof() const
{
	return _proof;
}

string polsearch_result::toString() const
{
	string tmp;
	//TODO result to string
	return tmp;
}

void polsearch_result::merge(const polsearch_result & rhs) throw(std::invalid_argument)
{
	if (_element != rhs._element)
		throw invalid_argument("Results cannot be merged: different elements.");
	for (size_t i = 0; i < rhs._proof.size(); i++)
	{
		addProof(rhs._proof[i]);
	}
}

polsearch_proof & polsearch_result::addProof(polsearch_test_cond_e test, polsearch_element_e elem_type, void *elem,
					     polsearch_proof_element_free_fn free_fn)
{
	_proof.push_back(polsearch_proof(test, elem_type, element_copy(elem_type, elem), _policy, _fclist, free_fn));
	return _proof.back();
}

polsearch_proof & polsearch_result::addProof(const polsearch_proof & proof_entry)
{
	_proof.push_back(polsearch_proof(proof_entry));
	return _proof.back();
}
