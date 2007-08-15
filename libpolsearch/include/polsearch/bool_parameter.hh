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

#ifndef POLSEARCH_BOOL_PARAMETER_HH
#define POLSEARCH_BOOL_PARAMETER_HH

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
 * A parameter object for use in polsearch_criterion to check boolean values.
 */
class polsearch_bool_parameter:public polsearch_parameter
{
      public:
	/**
	 * Create a boolean parameter.
	 * @param truth The truth value to compare when calling \a match().
	 */
	polsearch_bool_parameter(bool truth);
	//! Copy constructor.
	polsearch_bool_parameter(const polsearch_bool_parameter & rhs);
	//! Destructor.
	 virtual ~polsearch_bool_parameter();

	/**
	 * Get the truth value the parameter uses in its comparison.
	 * @return The truth value used.
	 */
	bool truthValue() const;
	/**
	 * Set the truth value the parameter uses in its comparison.
	 * @param truth The value to set.
	 * @return The truth value set.
	 */
	bool truthValue(bool truth);

	/**
	 * Determine if a boolean state matches the parameter.
	 * @param b The boolean state to match.
	 * @return If \a b matches, return \a true, otherwise return \a false.
	 * @exception std::invalid_argument This comparison is not valid for the
	 * given parameter's data.
	 */
	virtual bool match(bool b) const throw(std::invalid_argument);
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
	 bool _truthValue;	       //!< The boolean state compared.
};

#endif				       /* POLSEARCH_BOOL_PARAMETER_HH */
