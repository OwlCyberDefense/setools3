/**
 * @file
 *
 * A parameter object for use in polsearch_criterion to check MLS ranges.
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
#include <typeinfo>

#include <stdint.h>

#include <polsearch/polsearch.hh>
#include <polsearch/range_parameter.hh>
#include <polsearch/parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

using std::bad_alloc;

polsearch_range_parameter::polsearch_range_parameter(const apol_mls_range_t * rng) throw(std::bad_alloc):polsearch_parameter()
{
	_range = apol_mls_range_create_from_mls_range(rng);
	if (!_range)
		throw bad_alloc();
}

polsearch_range_parameter::polsearch_range_parameter(const polsearch_range_parameter & rhs) throw(std::
												  bad_alloc):polsearch_parameter
	(rhs)
{
	_range = apol_mls_range_create_from_mls_range(rhs._range);
	if (!_range)
		throw bad_alloc();
}

polsearch_range_parameter::~polsearch_range_parameter()
{
	apol_mls_range_destroy(&_range);
}

const apol_mls_range_t *polsearch_range_parameter::range() const
{
	return _range;
}

apol_mls_range_t *polsearch_range_parameter::range(const apol_mls_range_t * rng)throw(std::bad_alloc)
{
	apol_mls_range_destroy(&_range);
	_range = apol_mls_range_create_from_mls_range(rng);
	if (!_range)
		throw bad_alloc();
	return _range;
}

bool polsearch_range_parameter::match(const apol_policy_t * policy, const apol_mls_range_t * rng,
				      unsigned int m) const throw(std::invalid_argument, std::bad_alloc)
{
	apol_mls_range_t *arng_in = NULL, *arng_param = NULL;

	arng_in = apol_mls_range_create_from_mls_range(rng);
	if (!arng_in)
		throw bad_alloc();
	apol_mls_range_convert(policy, arng_in);

	arng_param = apol_mls_range_create_from_mls_range(_range);
	if (!arng_in)
		throw bad_alloc();
	apol_mls_range_convert(policy, arng_param);

	int cmp = apol_mls_range_compare(policy, arng_param, arng_in, m);

	apol_mls_range_destroy(&arng_in);
	apol_mls_range_destroy(&arng_param);
	return cmp > 0;
}

const std::type_info & polsearch_range_parameter::paramType() const
{
	return typeid(*this);
}

std::string polsearch_range_parameter::toString() const
{
	//TODO polsearch_range_parameter.toString()
	return "";
}

polsearch_parameter *polsearch_range_parameter::clone() const throw(std::bad_alloc)
{
	return dynamic_cast < polsearch_parameter * >(new polsearch_range_parameter(*this));
}
