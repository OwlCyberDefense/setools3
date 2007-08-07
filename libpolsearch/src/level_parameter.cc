/**
 * @file
 *
 * A parameter object for use in polsearch_criterion to check MLS levels.
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

#include <polsearch/polsearch.hh>
#include <polsearch/parameter.hh>
#include <polsearch/level_parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/mls-query.h>

using std::bad_alloc;

polsearch_level_parameter::polsearch_level_parameter(const apol_mls_level_t * lvl) throw(std::bad_alloc)
{
	_level = apol_mls_level_create_from_mls_level(lvl);
	if (!_level)
		throw bad_alloc();
}

polsearch_level_parameter::polsearch_level_parameter(const polsearch_level_parameter & rhs) throw(std::bad_alloc)
{
	_level = apol_mls_level_create_from_mls_level(rhs._level);
	if (!_level)
		throw bad_alloc();
}

polsearch_level_parameter::~polsearch_level_parameter()
{
	apol_mls_level_destroy(&_level);
}

const apol_mls_level_t *polsearch_level_parameter::level() const
{
	return _level;
}

apol_mls_level_t *polsearch_level_parameter::level(const apol_mls_level_t * lvl)throw(std::bad_alloc)
{
	apol_mls_level_destroy(&_level);
	_level = apol_mls_level_create_from_mls_level(lvl);
	if (!_level)
		throw bad_alloc();
	return _level;
}

bool polsearch_level_parameter::match(const apol_policy_t * policy, const apol_mls_level_t * lvl,
				      int m) const throw(std::invalid_argument, std::bad_alloc)
{
	apol_mls_level_t *alvl_in = NULL, *alvl_param = NULL;

	alvl_in = apol_mls_level_create_from_mls_level(lvl);
	if (!alvl_in)
		throw bad_alloc();
	apol_mls_level_convert(policy, alvl_in);

	alvl_param = apol_mls_level_create_from_mls_level(_level);
	if (!alvl_in)
		throw bad_alloc();
	apol_mls_level_convert(policy, alvl_param);

	int cmp = apol_mls_level_compare(policy, alvl_in, alvl_param);

	apol_mls_level_destroy(&alvl_in);
	apol_mls_level_destroy(&alvl_param);
	return (cmp == APOL_MLS_EQ || cmp == m);
}

polsearch_param_type_e polsearch_level_parameter::paramType() const
{
	return POLSEARCH_PARAM_TYPE_LEVEL;
}

std::string polsearch_level_parameter::toString() const
{
	//TODO polsearch_level_parameter.toString()
	return "";
}

polsearch_parameter *polsearch_level_parameter::clone() const throw(std::bad_alloc)
{
	return dynamic_cast < polsearch_parameter * >(new polsearch_level_parameter(*this));
}
