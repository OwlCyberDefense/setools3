/**
 * @file
 *
 * A parameter object for use in polsearch_criterion to check boolean values.
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
#include <polsearch/bool_parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

polsearch_bool_parameter::polsearch_bool_parameter(bool truth):polsearch_parameter()
{
	_truthValue = truth;
}

polsearch_bool_parameter::polsearch_bool_parameter(const polsearch_bool_parameter & rhs):polsearch_parameter(rhs)
{
	_truthValue = rhs._truthValue;
}

polsearch_bool_parameter::~polsearch_bool_parameter()
{
	// nothing to do
}

bool polsearch_bool_parameter::truthValue() const
{
	return _truthValue;
}

bool polsearch_bool_parameter::truthValue(bool truth)
{
	return _truthValue = truth;
}

bool polsearch_bool_parameter::match(bool b) const throw(std::invalid_argument)
{
	return _truthValue == b;
}

const std::type_info & polsearch_bool_parameter::paramType() const
{
	return typeid(*this);
}

std::string polsearch_bool_parameter::toString() const
{
	//TODO bool_parameter.toString()
	return "";
}

polsearch_parameter *polsearch_bool_parameter::clone() const throw(std::bad_alloc)
{
	return dynamic_cast < polsearch_parameter * >(new polsearch_bool_parameter(*this));
}
