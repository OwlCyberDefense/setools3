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
		POLSEARCH_OP_NONE = 0, /*!< only used for error conditions */
		POLSEARCH_OP_IS,       /*!< symbol (or state) is */
		POLSEARCH_OP_MATCH_REGEX,	/*!< symbol name (or alias name) matches regular expression */
		POLSEARCH_OP_RULE_TYPE,	/*!< is rule type */
		POLSEARCH_OP_INCLUDE,  /*!< set includes */
		POLSEARCH_OP_AS_SOURCE,	/*!< has as rule source */
		POLSEARCH_OP_AS_TARGET,	/*!< has as rule target */
		POLSEARCH_OP_AS_CLASS, /*!< has as rule class */
		POLSEARCH_OP_AS_PERM,  /*!< has as rule permission */
		POLSEARCH_OP_AS_DEFAULT,	/*!< has as rule default */
		POLSEARCH_OP_AS_SRC_TGT,	/*!< has as rule source or target */
		POLSEARCH_OP_AS_SRC_TGT_DFLT,	/*!< has as rule source, target, or default */
		POLSEARCH_OP_AS_SRC_DFLT,	/*!< has as rule source or default */
		POLSEARCH_OP_IN_COND,  /*!< is in a conditional with boolean */
		POLSEARCH_OP_LEVEL,    /*!< user level comparison */
		POLSEARCH_OP_RANGE,    /*!< has as range */
		POLSEARCH_OP_AS_USER,  /*!< has as user */
		POLSEARCH_OP_AS_ROLE,  /*!< has as role */
		POLSEARCH_OP_AS_TYPE,  /*!< has as type */
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

/**
 * A single criterion to be checked when running a test. This is the base
 * criterion with no parameter and by itself is not valid for use in a test;
 * use one of the specific criteria instead.
 */
class polsearch_criterion
{
      public:
		/**
		 * Create a generic criterion.
		 * @param opr Comparison operator to use.
		 * @param neg If \a true, invert the logic result of the operator.
		 */
	virtual polsearch_criterion(polsearch_op_e opr, bool neg = false);
		/**
		 * Copy a generic criterion.
		 * @param pc The criterion to copy.
		 */
	virtual polsearch_criterion(const polsearch_criterion & pc);
	//! Destructor.
	 virtual ~polsearch_criterion();

		/**
		 * Get the comparison operator used to check this criterion.
		 * @return The operator used.
		 */
	polsearch_op_e op() const;
		/**
		 * Determine if the comparison operator for this criterion is negated.
		 * @return \a true if negated, \a false otherwise
		  */
	bool negated() const;
		/**
		 * Set the flag to negate the comparison operator.
		 * @param neg If \a true, invert the logic result of the operator;
		 * if \a false do not invert.
		 * @return The state set.
		 */
	bool negated(bool neg);
		/**
		 * Get the type of parameter used by this criterion.
		 * @return The type of parameter (see polsearch_param_type_e).
		 */
	polsearch_param_type_e paramType() const;

		/**
		 * Check all candidates to find symbols that meet this criterion.
		 * @param p The policy containing the symbols to check.
		 * @param fclist The file_contexts list to use.
		 * @param test_candidates Vector of items to check (
		 */
	virtual apol_vector_t *check(const apol_policy_t * p, const sefs_fclist_t * fclist,
				     const apol_vector_t * test_candidates, apol_vector_t * Xcandidtates) const = 0;

      protected:
	 polsearch_op_e _op;
	bool _negated;
	polsearch_param_type_e _param_type;
};

/**
 * Criterion used to compare regular expressions to symbol names and aliases.
 */
class polsearch_regex_criterion:public polsearch_criterion
{
      public:
	polsearch_regex_criterion(polsearch_op_e opr, bool neg = false, const char *expression = NULL);
	 polsearch_regex_criterion(const polsearch_regex_criterion & prc);
	~polsearch_regex_criterion();

	const char *const regex() const;
	char *regex(const char *expression);

      private:
	char *_regex;
};

/**
 * Criterion used to compare symbols to a logical list of identifiers.
 */
class polsearch_strring_list_criterion:public polsearch_criterion
{
      public:
	polsearch_strring_list_criterion(polsearch_op_e opr, bool neg = false, const polsearch_string_list * strlist = NULL);
	 polsearch_strring_list_criterion(const polsearch_strring_list_criterion & pslc);
	~polsearch_strring_list_criterion();

	const polsearch_string_list *string_list() const;
	polsearch_string_list *string_list(const polsearch_string_list * strlist);

      private:
	 polsearch_string_list * _string_list;
};

/**
 * Criterion used to compare the type of rule in which a symbol appears.
 */
class polsearch_rule_type_criterion:public polsearch_criterion
{
      public:
	polsearch_rule_type_criterion(polsearch_op_e opr, bool neg = false, uint32_t ruletype = 0);
	polsearch_rule_type_criterion(const polsearch_rule_type_criterion & prtc);
	~polsearch_rule_type_criterion();

	uint32_t rule_type() const;
	uint32_t rule_type(uint32_t ruletype);
      private:
	 uint32_t _rule_type;
};

/**
 * Criterion used to compare a boolean state.
 */
class polsearch_bool_criterion:public polsearch_criterion
{
      public:
	polsearch_bool_criterion(polsearch_op_e opr, bool neg = false, bool val = false);
	polsearch_bool_criterion(const polsearch_bool_criterion & pbc);
	~polsearch_bool_criterion();

	bool value() const;
	bool value(bool val);

      private:
	 bool _value;
};

/**
 * Criterion used to compare user default levels.
 */
class polsearch_level_criterion:public polsearch_criterion
{
      public:
	polsearch_level_criterion(polsearch_op_e opr, bool neg = false, const apol_mls_level_t * lvl = NULL, int m = APOL_MLS_EQ);
	 polsearch_level_criterion(const polsearch_level_criterion & plc);
	~polsearch_level_criterion();

	const apol_mls_level_t *level() const;
	apol_mls_level_t *level(const apol_mls_level_t * lvl);
	int match() const;
	int match(int m);

      private:
	 apol_mls_level_t * _level;
	int _match;
};

/**
 * Criterion used for comparison of MLS ranges.
 */
class polsearch_range_criterion:public polsearch_criterion
{
      public:
	polsearch_range_criterion(polsearch_op_e opr, bool neg = false, const apol_mls_range_t * rng = NULL,
				  unsigned int m = APOL_QUERY_EXACT);
	 polsearch_range_criterion(polsearch_range_criterion & prc);
	~polsearch_range_criterion();

	const apol_mls_range_t *range() const;
	apol_mls_range_t *range(const apol_mls_range_t * rng);
	unsigned int match() const;
	unsigned int match(unsigned int m);

      private:
	 apol_mls_range_t * _range;
	unsigned int _match;
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore the compatibility section.
#ifndef SWIG

	typedef struct polsearch_criterion polsearch_criterion_t;
	typedef struct polsearch_regex_criterion polsearch_regex_criterion_t;
	typedef struct polsearch_strring_list_criterion polsearch_strring_list_criterion_t;
	typedef struct polsearch_rule_type_criterion polsearch_rule_type_criterion_t;
	typedef struct polsearch_bool_criterion polsearch_bool_criterion_t;
	typedef struct polsearch_level_criterion polsearch_level_criterion_t;
	typedef struct polsearch_range_criterion polsearch_range_criterion_t;

	/* constructor and destructor for polsearch_criterion base class intentionally not provided */
	polsearch_op_e polsearch_criterion_get_op(const polsearch_criterion_t * pc);
	bool polsearch_criterion_get_negated(const polsearch_criterion_t * pc);
	bool polsearch_criterion_set_negated(polsearch_criterion_t * pc);
	polsearch_param_type_e polsearch_criterion_get_param_type(const polsearch_criterion_t * pc);
	apol_vector_t *polsearch_criterion_check(const polsearch_criterion_t * pc, const apol_policy_t * p,
						 const sefs_fclist_t * fclist, const apol_vector_t * test_candidates,
						 apol_vector_t * Xcandidtates);

	polsearch_regex_criterion_t *polsearch_regex_criterion_create(polsearch_op_e opr, bool neg, const char *expression);
	polsearch_regex_criterion_t *polsearch_regex_criterion_create_from_criterion(const polsearch_regex_criterion_t * prc);
	void polsearch_regex_criterion_destroy(polsearch_regex_criterion_t ** prc);
	const char *const polsearch_regex_criterion_get_regex(const polsearch_regex_criterion_t * prc);
	char *polsearch_regex_criterion_set_regex(polsearch_regex_criterion_t * prc, const char *expression);

	polsearch_strring_list_criterion_t *polsearch_strring_list_criterion_create(polsearch_op_e opr, bool neg,
										    const polsearch_string_list * strlist);
	polsearch_strring_list_criterion_t *polsearch_strring_list_criterion_create_from_criterion(const
												   polsearch_strring_list_criterion_t
												   * pslc);
	void polsearch_strring_list_criterion_destroy(polsearch_strring_list_criterion_t ** pslc);
	const polsearch_string_list_t *polsearch_strring_list_criterion_get_string_list(const polsearch_strring_list_criterion_t *
											pslc);
	polsearch_string_list_t *polsearch_strring_list_criterion_set_string_list(polsearch_strring_list_criterion_t * pslc,
										  const polsearch_string_list_t * strlist);

	polsearch_rule_type_criterion_t *polsearch_rule_type_criterion_create(polsearch_op_e opr, bool neg, uint32_t ruletype);
	polsearch_rule_type_criterion_t *polsearch_rule_type_criterion_create_from_criterion(const polsearch_rule_type_criterion_t *
											     prtc);
	void polsearch_rule_type_criterion_destroy(polsearch_rule_type_criterion_t ** prtc);
	uint32_t polsearch_rule_type_criterion_get_rule_type(const polsearch_rule_type_criterion_t * prtc);
	uint32_t polsearch_rule_type_criterion_set_rule_type(polsearch_rule_type_criterion_t * prtc, uint32_t ruletype);

	polsearch_bool_criterion_t *polsearch_bool_criterion_create(polsearch_op_e opr, bool neg, bool val);
	polsearch_bool_criterion_t *polsearch_bool_criterion_create_from_criterion(const polsearch_bool_criterion_t * pbc);
	void polsearch_bool_criterion_destroy(polsearch_bool_criterion_t ** pbc);
	bool polsearch_bool_criterion_get_value(const polsearch_bool_criterion_t * pbc);
	bool polsearch_bool_criterion_set_value(polsearch_bool_criterion_t * pbc, bool val);

	polsearch_level_criterion_t *polsearch_level_criterion_create(polsearch_op_e opr, bool neg,
								      const apol_mls_level_t * lvl, int m);
	polsearch_level_criterion_t *polsearch_level_criterion_create_from_criterion(const polsearch_level_criterion_t * plc);
	void polsearch_level_criterion_destroy(polsearch_level_criterion_t ** plc);
	const apol_mls_level_t *polsearch_level_criterion_get_level(const polsearch_level_criterion_t * plc);
	apol_mls_level_t *polsearch_level_criterion_set_level(polsearch_level_criterion_t * plc, const apol_mls_level_t * lvl);
	int polsearch_level_criterion_get_match(const polsearch_level_criterion_t * plc);
	int polsearch_level_criterion_set_match(polsearch_level_criterion_t * plc, int m);

	polsearch_range_criterion_t *polsearch_range_criterion_create(polsearch_op_e opr, bool neg,
								      const apol_mls_range_t * rng, unsigned int m);
	polsearch_range_criterion_t *polsearch_range_criterion_create_from_criterion(const polsearch_range_criterion_t * prc);
	void polsearch_range_criterion_destroy(polsearch_range_criterion_t ** prc);
	const apol_mls_range_t *polsearch_range_criterion_get_range(const polsearch_range_criterion_t * prc);
	apol_mls_range_t *polsearch_range_criterion_set_range(polsearch_range_criterion_t * prc, const apol_mls_range_t * rng);
	unsigned int polsearch_range_criterion_get_match(const polsearch_range_criterion_t * prc);
	unsigned int polsearch_range_criterion_set_match(polsearch_range_criterion_t * prc, unsigned int m);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_CRITERION_H */
