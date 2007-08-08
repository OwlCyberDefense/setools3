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

#ifndef POLSEARCH_REGEX_PARAMETER_HH
#define POLSEARCH_REGEX_PARAMETER_HH

#include <string>
#include <vector>
#include <stdexcept>

#include <stdint.h>
#include <regex.h>

#include <polsearch/polsearch.hh>
#include <polsearch/parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

class polsearch_regex_parameter:public polsearch_parameter
{
      public:
	/**
	 * Create a regular expression parameter.
	 * @param expr The regular expression to which to compare when calling \a match().
	 * @param icase If \a true, ignore case when matching the expression.
	 * @exception std::invalid_argument Invalid regular expression.
	 * @exception std::bad_alloc Out of memory.
	 */
	polsearch_regex_parameter(std::string expr, bool icase = false) throw(std::invalid_argument, std::bad_alloc);
	//! Copy constructor.
	polsearch_regex_parameter(const polsearch_regex_parameter & rhs) throw(std::bad_alloc);
	//! Destructor.
	 virtual ~polsearch_regex_parameter();

	/**
	 * Get the expression to match when calling \a match().
	 * @return The expression matched.
	 */
	const std::string & expression() const;
	/**
	 * Set the expression to match when calling \a match().
	 * @param expr The regular expression to set.
	 * @return The expression set.
	 * @exception std::invalid_argument Invalid regular expression.
	 * @exception std::bad_alloc Out of memory.
	 */
	 std::string & expression(const std::string & expr) throw(std::invalid_argument, std::bad_alloc);;

	/**
	 * Determine if case is ignored when matching the regular expression.
	 * @return If case is ignored, return \a true; otherwise, return \a false.
	 */
	bool ignoreCase() const;
	/**
	 * Set the regular expression matching to match or ignore case.
	 * @param icase If \a true, ignore case when matching the expression;
	 * if \a false, matching is case sensitive.
	 * @return If case is ignored, return \a true; otherwise, return \a false.
	 * @exception std::bad_alloc Out of memory.
	 */
	bool ignoreCase(bool icase) throw(std::bad_alloc);;

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
	 * @return Always returns POLSEARCH_PARAM_TYPE_REGEX.
	 */
	virtual polsearch_param_type_e paramType() const;
	/**
	 * Get a string representing the parameter.
	 * @return A string representing the parameter.
	 */
	virtual std::string toString() const;
	/**
	 * Get a deep copy of the derived parameter class.
	 * @return A newly allocated parameter that is a deep copy of \a this.
	 * @exception std::bad_alloc Out of memory.
	 */
	virtual polsearch_parameter *clone() const throw(std::bad_alloc);

      private:
	 std::string _expression;      //!< The expression to match.
	bool _ignore_case;	       //!< If \a true, \a _expression is case insensitive.
	regex_t *_compiled;	       //!< The compiled regular expression.
};

#endif				       /* POLSEARCH_REGEX_PARAMETER_HH */
