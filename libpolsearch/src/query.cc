/**
 * @file
 *
 * Routines to perform complex queries on a selinux policy.
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

#include <polsearch/query.hh>
#include <polsearch/polsearch.hh>
#include <polsearch/criterion.hh>
#include <polsearch/test.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <vector>
#include <string>

using std::invalid_argument;

polsearch_query::polsearch_query(polsearch_match_e m) throw(std::invalid_argument)
{
	if (m != POLSEARCH_MATCH_ALL && m != POLSEARCH_MATCH_ANY)
		throw invalid_argument("Invalid matching behavior requested.");

	_match = m;
}

polsearch_query::polsearch_query(const polsearch_query & rhs)
{
	_match = rhs._match;
	_tests = rhs._tests;
}

polsearch_query::~polsearch_query()
{
	// no-op
}

polsearch_match_e polsearch_query::match() const
{
	return _match;
}

polsearch_match_e polsearch_query::match(polsearch_match_e m) throw(std::invalid_argument)
{
	if (m != POLSEARCH_MATCH_ALL && m != POLSEARCH_MATCH_ANY)
		throw invalid_argument("Invalid matching behavior requested.");

	return _match = m;
}
