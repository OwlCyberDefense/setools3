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

#ifndef SERECON_CRITERION_H
#define SERECON_CRITERION_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include <apol/mls-query.h>

#include "string_list.hh"

/** Value to indicate the comparison operator for a parameter */
	typedef enum serecon_op
	{
		SERECON_OP_NONE = 0,   /*!< only used for error conditions */
		SERECON_OP_IS,	       /*!< symbol (or state) is */
		SERECON_OP_MATCH_REGEX,	/*!< symbol name (or alias name) matches regular expression */
		SERECON_OP_RULE_TYPE,  /*!< is rule type */
		SERECON_OP_INCLUDE,    /*!< set includes */
		SERECON_OP_AS_SOURCE,  /*!< has as rule source */
		SERECON_OP_AS_TARGET,  /*!< has as rule target */
		SERECON_OP_AS_CLASS,   /*!< has as rule class */
		SERECON_OP_AS_PERM,    /*!< has as rule permission */
		SERECON_OP_AS_DEFAULT, /*!< has as rule default */
		SERECON_OP_AS_SRC_TGT, /*!< has as rule source or target */
		SERECON_OP_AS_SRC_TGT_DFLT,	/*!< has as rule source, target, or default */
		SERECON_OP_AS_SRC_DFLT,	/*!< has as rule source or default */
		SERECON_OP_IN_COND,    /*!< is in a conditional with boolean */
		SERECON_OP_LEVEL,      /*!< user level comparison */
		SERECON_OP_RANGE,      /*!< has as range */
		SERECON_OP_AS_USER,    /*!< has as user */
		SERECON_OP_AS_ROLE,    /*!< has as role */
		SERECON_OP_AS_TYPE,    /*!< has as type */
	} serecon_op_e;

/** Value to indicate the type of the parameter value of a criterion */
	typedef enum serecon_param_type
	{
		SERECON_PARAM_TYPE_NONE = 0,	/*!< only used for error conditions */
		SERECON_PARAM_TYPE_REGEX,	/*!< parameter is a string (char *) representing a regular expression */
		SERECON_PARAM_TYPE_STR_LIST,	/*!< parameter is a string list */
		SERECON_PARAM_TYPE_RULE_TYPE,	/*!< parameter is a rule type code (int) */
		SERECON_PARAM_TYPE_BOOL,	/*!< parameter is a boolean value (bool) */
		SERECON_PARAM_TYPE_LEVEL,	/*!< parameter is an apol_mls_level_t * */
		SERECON_PARAM_TYPE_RANGE,	/*!< parameter is an apol_mls_range_t * */
	} serecon_param_type_e;

#ifdef __cplusplus
}

class serecon_criterion
{
      public:
	virtual serecon_criterion(serecon_op_e opr, bool neg = false);
	virtual serecon_criterion(const serecon_criterion & sc);
	virtual ~serecon_criterion();

	serecon_op_e op() const;
	bool negated() const;
	bool negated(bool neg);
	serecon_param_type_e param_type() const;

	virtual apol_vector_t *check(apol_policy_t * p, sefs_fclist_t * fclist, apol_vector_t * test_candidates,
				     apol_vector_t * Xcandidtates) = 0;

      protected:
	 serecon_op_e _op;
	bool _negated;
	serecon_param_type_e _param_type;
};

class serecon_regex_criterion:public serecon_criterion
{
      public:
	serecon_regex_criterion(serecon_op_e opr, bool neg = false, char *expression = NULL);
	 serecon_regex_criterion(const serecon_regex_criterion & src);
	~serecon_regex_criterion();

	const char *const regex() const;
	char *regex(char *expression);

      private:
	char *_regex;
};

class serecon_strring_list_criterion:public serecon_criterion
{
      public:
	serecon_strring_list_criterion(serecon_op_e opr, bool neg = false, serecon_string_list * strlist = NULL);
	serecon_strring_list_criterion(const serecon_strring_list_criterion & sslc);
	~serecon_strring_list_criterion();

	const serecon_string_list *string_list() const;
	serecon_string_list *string_list(serecon_string_list * strlist);

      private:
	 serecon_string_list * _string_list;
};

class serecon_rule_type_criterion:public serecon_criterion
{
      public:
	serecon_rule_type_criterion(serecon_op_e opr, bool neg = false, uint32_t ruletype = 0);
	serecon_rule_type_criterion(const serecon_rule_type_criterion & srtc);
	~serecon_rule_type_criterion();

	uint32_t rule_type() const;
	uint32_t rule_type(uint32_t ruletype);
      private:
	 uint32_t _rule_type;
};

class serecon_bool_criterion:public serecon_criterion
{
      public:
	serecon_bool_criterion();
	serecon_bool_criterion();
	~serecon_bool_criterion();

	bool value() const;
	bool value(bool val);

      private:
	 bool _value;
};

class serecon_level_criterion:public serecon_criterion
{
      public:
	serecon_level_criterion(serecon_op_e opr, bool neg = false, apol_mls_level_t * lvl = NULL, int m = APOL_MLS_EQ);
	serecon_level_criterion(const serecon_level_criterion & slc);
	~serecon_level_criterion();

	const apol_mls_level_t *level() const;
	apol_mls_level_t *level(apol_mls_level_t * lvl);
	int match() const;
	int match(int m);

      private:
	apol_mls_level_t * _level;
	int _match;
};

class serecon_range_criterion:public serecon_criterion
{
      public:
	serecon_range_criterion(serecon_op_e opr, bool neg = false, apol_mls_range_t * rng = NULL, unsigned int m =
				APOL_QUERY_EXACT);
	 serecon_range_criterion(serecon_range_criterion & src);
	~serecon_range_criterion();

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

#endif				       /* SERECON_CRITERION_H */
