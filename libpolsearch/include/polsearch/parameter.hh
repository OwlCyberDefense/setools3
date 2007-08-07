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

#ifndef POLSEARCH_PARAMETER_HH
#define POLSEARCH_PARAMETER_HH

#include <string>
#include <vector>
#include <stdexcept>

#include <stdint.h>

#include <polsearch/polsearch.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/mls_level.h>
#include <apol/mls_range.h>
#include <apol/mls-query.h>

/**
 * Abstract parameter interface for a criterion's parameter.
 * Inheriting sub-classes are expected to override all variants
 * of match() which are valid for its specific data.
 */
class polsearch_parameter
{
      public:
	//! Default constructor.
	polsearch_parameter();
	//! Copy constructor.
	polsearch_parameter(const polsearch_parameter & rhs);
	//! Destructor.
	virtual ~polsearch_parameter();

	/**
	 * Determine if a boolean state matches the parameter.
	 * @param b The boolean state to match.
	 * @return If \a b matches, return \a true, otherwise return \a false.
	 * @exception std::invalid_argument This comparison is not valid for the
	 * given parameter's data.
	 */
	virtual bool match(bool b) const throw(std::invalid_argument);
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
	 * Determine if a numeric value matches the parameter.
	 * @param val The value to match.
	 * @return If \a val matches, return \a true, otherwise return \a false.
	 * @exception std::invalid_argument This comparison is not valid for the
	 * given parameter's data.
	 */
	virtual bool match(uint32_t val) const throw(std::invalid_argument);
	/**
	 * Determine if a MLS level value matches the parameter.
	 * @param policy The policy to use to determine the semantic meanting
	 * of category sets.
	 * @param lvl The level to match.
	 * @param m The type of matching to use. Should be one of APOL_MLS_EQ,
	 * APOL_MLS_DOM, or APOL_MLS_DOMBY from \<apol/mls-query.h\>.
	 * @return If \a lvl matches, return \a true, otherwise return \a false.
	 * @exception std::invalid_argument This comparison is not valid for the
	 * given parameter's data.
	 * @exception std::bad_alloc Out of memory.
	 */
	virtual bool match(const apol_policy_t * policy, const apol_mls_level_t * lvl, int m) const throw(std::invalid_argument,
													  std::bad_alloc);
	/**
	 * Determine if a MLS range value matches the parameter.
	 * @param policy The policy to use to determine the semantic meanting
	 * of category sets.
	 * @param rng The range to match.
	 * @param m The type of matching to use. Should be one of APOL_QUERY_EXACT,
	 * APOL_QUERY_SUB, or APOL_QUERY_SUPER from \<apol/policy-query.h\>.
	 * @return If \a rng matches, return \a true, otherwise return \a false.
	 * @exception std::invalid_argument This comparison is not valid for the
	 * given parameter's data.
	 * @exception std::bad_alloc Out of memory.
	 */
	virtual bool match(const apol_policy_t * policy, const apol_mls_range_t * rng,
			   unsigned int m) const throw(std::invalid_argument, std::bad_alloc);
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
	virtual polsearch_param_type_e paramType() const = 0;
	/**
	 * Get a string representing the parameter.
	 * @return A string representing the parameter.
	 */
	virtual std::string toString() const = 0;
	/**
	 * Get a deep copy of the derived parameter class.
	 * @return A newly allocated parameter that is a deep copy of \a this.
	 */
	virtual polsearch_parameter *clone() const = 0;
};

#endif				       /* POLSEARCH_PARAMETER_HH */
