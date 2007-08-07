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

#ifndef POLSEARCH_LEVEL_PARAMETER_HH
#define POLSEARCH_LEVEL_PARAMETER_HH

#include <string>
#include <vector>
#include <stdexcept>

#include <stdint.h>

#include <polsearch/polsearch.hh>
#include <polsearch/parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

class polsearch_level_parameter:public polsearch_parameter
{
      public:
	/**
	 * Create a MLS level parameter.
	 * @param lvl The level to which to compare when calling \a match().
	 * This level will be duplicated by this call.
	 * @exception std::bad_alloc Out of memory.
	 */
	polsearch_level_parameter(const apol_mls_level_t * lvl) throw(std::bad_alloc);
	//! Copy constructor.
	 polsearch_level_parameter(const polsearch_level_parameter & rhs) throw(std::bad_alloc);
	//! Destructor.
	 virtual ~polsearch_level_parameter();

	/**
	 * Get the level compared when calling \a match().
	 * @return The level compared when calling \a match().
	 */
	const apol_mls_level_t *level() const;
	/**
	 * Set the level compared when calling \a match().
	 * @param lvl The level to set. This level will be duplicated by this call.
	 * @return The level set.
	 * @exception std::bad_alloc Out of memory.
	 */
	apol_mls_level_t *level(const apol_mls_level_t * lvl) throw(std::bad_alloc);
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
	 * Get the type of parameter.
	 * @return Always returns POLSEARCH_PARAM_TYPE_LEVEL.
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
	 apol_mls_level_t * _level;    //!<The level to compare when calling \a match().
};

#endif				       /* POLSEARCH_LEVEL_PARAMETER_HH */
