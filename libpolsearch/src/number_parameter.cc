/**
 * @file
 *
 * A parameter object for use in polsearch_criterion to check integer values.
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
#include <polsearch/parameter.hh>
#include <polsearch/number_parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

polsearch_number_parameter::polsearch_number_parameter(uint32_t val)
{
	_value = val;
}

polsearch_number_parameter::polsearch_number_parameter(const polsearch_number_parameter & rhs)
{
	_value = rhs._value;
}

polsearch_number_parameter::~polsearch_number_parameter()
{
	//nothing to do
}

uint32_t polsearch_number_parameter::value() const
{
	return _value;
}

uint32_t polsearch_number_parameter::value(uint32_t val)
{
	return _value = val;
}

bool polsearch_number_parameter::match(uint32_t val) const throw(std::invalid_argument)
{
	return _value == val;
}

const std::type_info & polsearch_number_parameter::paramType() const
{
	return typeid(*this);
}

std::string polsearch_number_parameter::toString() const
{
	//TODO polsearch_number_parameter.toString()
	return "";
}

polsearch_parameter *polsearch_number_parameter::clone() const throw(std::bad_alloc)
{
	return dynamic_cast < polsearch_parameter * >(new polsearch_number_parameter(*this));
}
