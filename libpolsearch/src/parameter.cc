/**
 * @file
 *
 * Abstract parameter object for use in polsearch_criterion.
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

#include <string>
#include <vector>
#include <stdexcept>

#include <stdint.h>
#include <assert.h>

#include <polsearch/parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/mls_level.h>
#include <apol/mls_range.h>
#include <apol/mls-query.h>

using std::invalid_argument;

polsearch_parameter::polsearch_parameter()
{
	// no-op
}

polsearch_parameter::polsearch_parameter(const polsearch_parameter & rhs)
{
	// no-op
}

polsearch_parameter::~polsearch_parameter()
{
	// no-op
}

bool polsearch_parameter::match(bool b) const throw(std::invalid_argument)
{
	assert(0);
	throw invalid_argument("Invalid parameter comparison");
	return false;
}

bool polsearch_parameter::match(const std::string & str,
				const std::vector < std::string > &Xnames) const throw(std::invalid_argument)
{
	assert(0);
	throw invalid_argument("Invalid parameter comparison");
	return false;
}

bool polsearch_parameter::match(uint32_t val) const throw(std::invalid_argument)
{
	assert(0);
	throw invalid_argument("Invalid parameter comparison");
	return false;
}

bool polsearch_parameter::match(const apol_policy_t * policy, const apol_mls_level_t * lvl,
				int m) const throw(std::invalid_argument, std::bad_alloc)
{
	assert(0);
	throw invalid_argument("Invalid parameter comparison");
	return false;
}

bool polsearch_parameter::match(const apol_policy_t * policy, const apol_mls_range_t * rng,
				unsigned int m) const throw(std::invalid_argument, std::bad_alloc)
{
	assert(0);
	throw invalid_argument("Invalid parameter comparison");
	return false;
}

bool polsearch_parameter::match(const std::vector < std::string > &test_list,
				const std::vector < std::string > &Xnames) const throw(std::invalid_argument)
{
	assert(0);
	throw invalid_argument("Invalid parameter comparison");
	return false;
}
