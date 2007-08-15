/**
 * @file
 *
 * A parameter object for use in polsearch_criterion to check string
 * expressions representing symbol names.
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

#ifndef POLSEARCH_STRING_EXPRESSION_PARAMETER_HH
#define POLSEARCH_STRING_EXPRESSION_PARAMETER_HH

#include <string>
#include <vector>
#include <stdexcept>
#include <typeinfo>

#include <stdint.h>

#include <polsearch/polsearch.hh>
#include <polsearch/parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

/**
 * A parameter object for use in polsearch_criterion to check string
 * expressions representing symbol names.
 */
class polsearch_string_expression_parameter:public polsearch_parameter
{
      public:
	/**
	 * Create a string expression parameter.
	 * @param expr The string representing the expression to match.
	 * @exception std::invalid_argument Invalid expression.
	 */
	polsearch_string_expression_parameter(const std::string & expr) throw(std::invalid_argument);
	//! Copy constructor.
	 polsearch_string_expression_parameter(const polsearch_string_expression_parameter & rhs);
	//! Destructor.
	 virtual ~polsearch_string_expression_parameter();

	/**
	 * Determine if a string matches the parameter.
	 * @param str The string to match.
	 * @param Xnames A list of names valid for the symbol X.
	 * If empty, this list is ignored.
	 * @return If \a str matches, return \a true, otherwise return \a false.
	 * @exception std::invalid_argument This comparison is not valid for the
	 * given parameter's data.
	 */
	virtual bool match(const std::string & str, const std::vector < std::string > &Xnames) const throw(std::invalid_argument);
	/**
	 * Determine if any string in a list matches the parameter.
	 * @param test_list The list of strings to match.
	 * @param Xnames A list of names valid for the symbol X.
	 * If empty, this list is ignored.
	 * @return If any string in \a test_list matches, return \a true,
	 * otherwise return \a false.
	 * @exception std::invalid_argument This comparison is not valid for the
	 * given parameter's data.
	 */
	virtual bool match(const std::vector < std::string > &test_list,
			   const std::vector < std::string > &Xnames) const throw(std::invalid_argument);

	/**
	 * Get the type of parameter.
	 * @return The type of parameter.
	 */
	virtual const std::type_info & paramType() const;
	/**
	 * Get a string representing the parameter.
	 * @return A string representing the parameter.
	 */
	virtual std::string toString() const;
	/**
	 * Do not call this function from outside the library.
	 * Get a deep copy of the derived parameter class.
	 * @return A newly allocated parameter that is a deep copy of \a this.
	 * @exception std::bad_alloc Out of memory.
	 */
	virtual polsearch_parameter *clone() const throw(std::bad_alloc);

      private:
	 std::string _expression;      //!< The expression string. TODO the real members.
};

#endif				       /* POLSEARCH_STRING_EXPRESSION_PARAMETER_HH */
