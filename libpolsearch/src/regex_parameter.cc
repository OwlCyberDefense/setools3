/**
 * @file
 *
 * A parameter object for use in polsearch_criterion to check regular expressions.
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
#include <cstdlib>

#include <stdint.h>
#include <regex.h>

#include <polsearch/polsearch.hh>
#include <polsearch/regex_parameter.hh>
#include <polsearch/parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

using std::invalid_argument;
using std::bad_alloc;
using std::vector;
using std::string;

polsearch_regex_parameter::polsearch_regex_parameter(std::string expr, bool icase) throw(std::invalid_argument, std::bad_alloc)
{
	_expression = expr;
	_ignore_case = icase;
	int flags = (REG_EXTENDED | REG_NOSUB);
	if (icase)
		flags |= REG_ICASE;
	_compiled = static_cast < regex_t * >(malloc(sizeof(*_compiled)));
	if (!_compiled)
		throw bad_alloc();
	char errbuf[1024] = { '\0' };
	int regretv = regcomp(_compiled, _expression.c_str(), flags);
	if (regretv)
	{
		regerror(regretv, _compiled, errbuf, 1024);
		free(_compiled);
		throw invalid_argument(errbuf);
	}
}

polsearch_regex_parameter::polsearch_regex_parameter(const polsearch_regex_parameter & rhs) throw(std::bad_alloc)
{
	_expression = rhs._expression;
	_ignore_case = rhs._ignore_case;
	int flags = (REG_EXTENDED | REG_NOSUB);
	if (_ignore_case)
		flags |= REG_ICASE;
	_compiled = static_cast < regex_t * >(malloc(sizeof(*_compiled)));
	if (!_compiled)
		throw bad_alloc();
	char errbuf[1024] = { '\0' };
	int regretv = regcomp(_compiled, _expression.c_str(), flags);
	if (regretv)
	{
		regerror(regretv, _compiled, errbuf, 1024);
		free(_compiled);
		throw invalid_argument(errbuf);
	}
}

polsearch_regex_parameter::~polsearch_regex_parameter()
{
	if (_compiled)
		regfree(_compiled);
	free(_compiled);
}

const std::string & polsearch_regex_parameter::expression() const
{
	return _expression;
}

std::string & polsearch_regex_parameter::expression(const std::string & expr)throw(std::invalid_argument, std::bad_alloc)
{
	if (_compiled)
		regfree(_compiled);
	_expression = expr;
	int flags = (REG_EXTENDED | REG_NOSUB);
	if (_ignore_case)
		flags |= REG_ICASE;
	_compiled = static_cast < regex_t * >(malloc(sizeof(*_compiled)));
	if (!_compiled)
		throw bad_alloc();
	char errbuf[1024] = { '\0' };
	int regretv = regcomp(_compiled, _expression.c_str(), flags);
	if (regretv)
	{
		regerror(regretv, _compiled, errbuf, 1024);
		free(_compiled);
		throw invalid_argument(errbuf);
	}

	return _expression;
}

bool polsearch_regex_parameter::ignoreCase() const
{
	return _ignore_case;
}

bool polsearch_regex_parameter::ignoreCase(bool icase) throw(std::bad_alloc)
{
	if (_compiled)
		regfree(_compiled);
	_ignore_case = icase;
	int flags = (REG_EXTENDED | REG_NOSUB);
	if (_ignore_case)
		flags |= REG_ICASE;
	_compiled = static_cast < regex_t * >(malloc(sizeof(*_compiled)));
	if (!_compiled)
		throw bad_alloc();
	char errbuf[1024] = { '\0' };
	regcomp(_compiled, _expression.c_str(), flags);

	return _ignore_case;
}

bool polsearch_regex_parameter::match(const std::string & str,
				      const std::vector < std::string > &Xnames) const throw(std::invalid_argument)
{
	if (str == "X")
	{
		for (vector < string >::const_iterator i = Xnames.begin(); i != Xnames.end(); i++)
			if (!regexec(_compiled, i->c_str(), 0, NULL, 0))
				return true;
	}
	else
	{
		if (!regexec(_compiled, str.c_str(), 0, NULL, 0))
			return true;
	}
	return false;
}

bool polsearch_regex_parameter::match(const std::vector < std::string > &test_list,
				      const std::vector < std::string > &Xnames) const throw(std::invalid_argument)
{
	for (vector < string >::const_iterator i = test_list.begin(); i != test_list.end(); i++)
	{
		if (match(*i, Xnames))
			return true;
	}
	return false;
}

polsearch_param_type_e polsearch_regex_parameter::paramType() const
{
	return POLSEARCH_PARAM_TYPE_REGEX;
}

std::string polsearch_regex_parameter::toString() const
{
	//TODO polsearch_regex_parameter.toString()
	return "";
}

polsearch_parameter *polsearch_regex_parameter::clone() const throw(std::bad_alloc)
{
	return dynamic_cast < polsearch_parameter * >(new polsearch_regex_parameter(*this));
}
