/**
 * @file
 *
 * Routines to handle tests criteria for logic queries.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2007 Tresys Technology, LLC
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

#ifndef POLSEARCH_CRITERION_H
#define POLSEARCH_CRITERION_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include <apol/mls-query.h>

#include "string_list.hh"

/** Value to indicate the comparison operator for a parameter */
	typedef enum polsearch_op
	{
		POLSEARCH_OP_NONE = 0,   /*!< only used for error conditions */
		POLSEARCH_OP_IS,	       /*!< symbol (or state) is */
		POLSEARCH_OP_MATCH_REGEX,	/*!< symbol name (or alias name) matches regular expression */
		POLSEARCH_OP_RULE_TYPE,  /*!< is rule type */
		POLSEARCH_OP_INCLUDE,    /*!< set includes */
		POLSEARCH_OP_AS_SOURCE,  /*!< has as rule source */
		POLSEARCH_OP_AS_TARGET,  /*!< has as rule target */
		POLSEARCH_OP_AS_CLASS,   /*!< has as rule class */
		POLSEARCH_OP_AS_PERM,    /*!< has as rule permission */
		POLSEARCH_OP_AS_DEFAULT, /*!< has as rule default */
		POLSEARCH_OP_AS_SRC_TGT, /*!< has as rule source or target */
		POLSEARCH_OP_AS_SRC_TGT_DFLT,	/*!< has as rule source, target, or default */
		POLSEARCH_OP_AS_SRC_DFLT,	/*!< has as rule source or default */
		POLSEARCH_OP_IN_COND,    /*!< is in a conditional with boolean */
		POLSEARCH_OP_LEVEL,      /*!< user level comparison */
		POLSEARCH_OP_RANGE,      /*!< has as range */
		POLSEARCH_OP_AS_USER,    /*!< has as user */
		POLSEARCH_OP_AS_ROLE,    /*!< has as role */
		POLSEARCH_OP_AS_TYPE,    /*!< has as type */
	} polsearch_op_e;

/** Value to indicate the type of the parameter value of a criterion */
	typedef enum polsearch_param_type
	{
		POLSEARCH_PARAM_TYPE_NONE = 0,	/*!< only used for error conditions */
		POLSEARCH_PARAM_TYPE_REGEX,	/*!< parameter is a string (char *) representing a regular expression */
		POLSEARCH_PARAM_TYPE_STR_LIST,	/*!< parameter is a string list */
		POLSEARCH_PARAM_TYPE_RULE_TYPE,	/*!< parameter is a rule type code (int) */
		POLSEARCH_PARAM_TYPE_BOOL,	/*!< parameter is a boolean value (bool) */
		POLSEARCH_PARAM_TYPE_LEVEL,	/*!< parameter is an apol_mls_level_t * */
		POLSEARCH_PARAM_TYPE_RANGE,	/*!< parameter is an apol_mls_range_t * */
	} polsearch_param_type_e;

#ifdef __cplusplus
}

class polsearch_criterion
{
      public:
	virtual polsearch_criterion(polsearch_op_e opr, bool neg = false);
	virtual polsearch_criterion(const polsearch_criterion & sc);
	virtual ~polsearch_criterion();

	polsearch_op_e op() const;
	bool negated() const;
	bool negated(bool neg);
	polsearch_param_type_e param_type() const;

	virtual apol_vector_t *check(apol_policy_t * p, sefs_fclist_t * fclist, apol_vector_t * test_candidates,
				     apol_vector_t * Xcandidtates) = 0;

      protected:
	 polsearch_op_e _op;
	bool _negated;
	polsearch_param_type_e _param_type;
};

class polsearch_regex_criterion:public polsearch_criterion
{
      public:
	polsearch_regex_criterion(polsearch_op_e opr, bool neg = false, char *expression = NULL);
	 polsearch_regex_criterion(const polsearch_regex_criterion & src);
	~polsearch_regex_criterion();

	const char *const regex() const;
	char *regex(char *expression);

      private:
	char *_regex;
};

class polsearch_strring_list_criterion:public polsearch_criterion
{
      public:
	polsearch_strring_list_criterion(polsearch_op_e opr, bool neg = false, polsearch_string_list * strlist = NULL);
	polsearch_strring_list_criterion(const polsearch_strring_list_criterion & sslc);
	~polsearch_strring_list_criterion();

	const polsearch_string_list *string_list() const;
	polsearch_string_list *string_list(polsearch_string_list * strlist);

      private:
	 polsearch_string_list * _string_list;
};

class polsearch_rule_type_criterion:public polsearch_criterion
{
      public:
	polsearch_rule_type_criterion(polsearch_op_e opr, bool neg = false, uint32_t ruletype = 0);
	polsearch_rule_type_criterion(const polsearch_rule_type_criterion & srtc);
	~polsearch_rule_type_criterion();

	uint32_t rule_type() const;
	uint32_t rule_type(uint32_t ruletype);
      private:
	 uint32_t _rule_type;
};

class polsearch_bool_criterion:public polsearch_criterion
{
      public:
	polsearch_bool_criterion();
	polsearch_bool_criterion();
	~polsearch_bool_criterion();

	bool value() const;
	bool value(bool val);

      private:
	 bool _value;
};

class polsearch_level_criterion:public polsearch_criterion
{
      public:
	polsearch_level_criterion(polsearch_op_e opr, bool neg = false, apol_mls_level_t * lvl = NULL, int m = APOL_MLS_EQ);
	polsearch_level_criterion(const polsearch_level_criterion & slc);
	~polsearch_level_criterion();

	const apol_mls_level_t *level() const;
	apol_mls_level_t *level(apol_mls_level_t * lvl);
	int match() const;
	int match(int m);

      private:
	apol_mls_level_t * _level;
	int _match;
};

class polsearch_range_criterion:public polsearch_criterion
{
      public:
	polsearch_range_criterion(polsearch_op_e opr, bool neg = false, apol_mls_range_t * rng = NULL, unsigned int m =
				APOL_QUERY_EXACT);
	 polsearch_range_criterion(polsearch_range_criterion & src);
	~polsearch_range_criterion();

	const apol_mls_range_t *range() const;
	apol_mls_range_t *range(apol_mls_range_t * rng);
	unsigned int match() const;
	unsigned int match(unsigned int m);

      private:
	 apol_mls_range_t * _range;
	unsigned int _match;
};

extern "C"
{
#endif

	//TODO extern C bindings

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_CRITERION_H */
