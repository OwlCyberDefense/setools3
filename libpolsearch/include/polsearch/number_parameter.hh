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

#ifndef POLSEARCH_NUMBER_PARAMETER_HH
#define POLSEARCH_NUMBER_PARAMETER_HH

#include <string>
#include <vector>
#include <stdexcept>

#include <stdint.h>

#include <polsearch/polsearch.hh>
#include <polsearch/parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

class polsearch_number_parameter:public polsearch_parameter
{
      public:
	/**
	 * Create a new number parameter.
	 * @param val The value to compare when calling \a match().
	 */
	polsearch_number_parameter(uint32_t val);
	//! Copy constructor.
	polsearch_number_parameter(const polsearch_number_parameter & rhs);
	//! Destructor.
	 virtual ~polsearch_number_parameter();

	/**
	 * Get the value compared when calling \a match().
	 * @return The value compared.
	 */
	uint32_t value() const;
	/**
	 * Set the value compared when calling \a match().
	 * @param val The value to set.
	 * @return The value set.
	 */
	uint32_t value(uint32_t val);

	/**
	 * Determine if a numeric value matches the parameter.
	 * @param val The value to match.
	 * @return If \a val matches, return \a true, otherwise return \a false.
	 * @exception std::invalid_argument This comparison is not valid for the
	 * given parameter's data.
	 */
	virtual bool match(uint32_t val) const throw(std::invalid_argument);

	/**
	 * Get the type of parameter.
	 * @return Always returns POLSEARCH_PARAM_TYPE_RULE_TYPE.
	 */
	virtual polsearch_param_type_e paramType() const;
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
	 uint32_t _value;	       //!< The value compared.
};

#endif				       /* POLSEARCH_NUMBER_PARAMETER_HH */
