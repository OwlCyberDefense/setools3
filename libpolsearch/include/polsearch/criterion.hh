/**
 * @file
 *
 * Routines to handle tests' criteria for logic queries.
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

#include "string_list.hh"

#include <sefs/fclist.hh>

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include <apol/mls-query.h>
#include <apol/vector.h>
#include <apol/policy.h>

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
		POLSEARCH_OP_AS_LEVEL, /*!< user level comparison */
		POLSEARCH_OP_AS_RANGE, /*!< has as range */
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

#include <stdexcept>

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
	polsearch_criterion(polsearch_op_e opr, bool neg = false);
	/**
	 * Copy a generic criterion.
	 * @param pc The criterion to copy.
	 */
	polsearch_criterion(const polsearch_criterion & pc);
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
	 * Check all candidates to find those meet this criterion.
	 * @param p The policy containing the symbols to check.
	 * @param fclist The file_contexts list to use.
	 * @param test_candidates Vector of items to check. This vector will be
	 * pruned to only those candidates satisfying this criterion.
	 * <b>Must be non-null.</b>
	 * @param Xcandidtates Current list of possible candidates for the symbol X.
	 * <b>Must be non-null. Must not be the same vector as \a test_candidates. </b>
	 * @return A vector of result entries 
	 */
	virtual apol_vector_t *check(const apol_policy_t * p, const sefs_fclist_t * fclist,
				     apol_vector_t * test_candidates, const apol_vector_t * Xcandidtates) const = 0;

      protected:
	 polsearch_op_e _op;	       /*!< The comparison operator. */
	bool _negated;		       /*!< Negate operator flag. */
	polsearch_param_type_e _param_type;	/*!< Type of parameter. */
};

/**
 * Criterion used to compare regular expressions to symbol names and aliases.
 */
class polsearch_regex_criterion:public polsearch_criterion
{
      public:
	/**
	 * Create a criterion with a regular expresion parameter.
	 * @param opr Comparison operator to use.
	 * @param neg If \a true, invert the logic result of the operator.
	 * @param expression The regular expression string; this string will
	 * be duplicated.
	 * @exception std::bad_alloc Could not duplicate the expression string.
	 */
	polsearch_regex_criterion(polsearch_op_e opr, bool neg = false, const char *expression = NULL) throw(std::bad_alloc);
	/**
	 * Copy a criterion with a regular expression parameter.
	 * @param prc The criterion to copy.
	 * @exception std::bad_alloc Could not duplicate the expression string.
	 */
	 polsearch_regex_criterion(const polsearch_regex_criterion & prc) throw(std::bad_alloc);
	//! Destructor.
	~polsearch_regex_criterion();

	/**
	 * Get the regular expression string.
	 * @return The regular expression string or NULL if it has been cleared.
	 */
	const char *const regex() const;
	/**
	 * Set the regular expression string.
	 * @param expression The expression to set, or NULL to clear any previous
	 * value. This string (if non-null) will be duplicated.
	 * @return The string set or NULL if cleared.
	 * @exception std::bad_alloc Could not duplicate the expression string.
	 */
	const char *regex(const char *expression) throw(std::bad_alloc);

      private:
	char *_regex;		       /*!< The regular expression string. */
};

/**
 * Criterion used to compare symbols to a logical list of identifiers.
 */
class polsearch_strring_list_criterion:public polsearch_criterion	//TODO doxy
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
	/**
	 * Create a criterion with a rule type parameter.
	 * @param opr Comparison operator to use.
	 * @param neg If \a true, invert the logic result of the operator.
	 * @param ruletype The type of rule. Must be one of QPOL_RULE_* from
	 * \link avrule_query.h \<qpol/avrule_query.h\> \endlink and
	 * \link terule_query.h \<qpol/terule_query.h\> \endlink or 0 to indicate
	 * that any rule type matches.
	 * @exception std::invalid_argument The provided rule type is not valid.
	 */
	polsearch_rule_type_criterion(polsearch_op_e opr, bool neg = false, uint32_t ruletype = 0) throw(std::invalid_argument);
	/**
	 * Copy a criterion with a rule type parameter.
	 * @param prtc The criterion to copy.
	 */
	polsearch_rule_type_criterion(const polsearch_rule_type_criterion & prtc);
	//! Destructor.
	~polsearch_rule_type_criterion();

	/**
	 * Get the rule type.
	 * @return The rule type. This will be one of QPOL_RULE_* from
	 * \link avrule_query.h \<qpol/avrule_query.h\> \endlink and
	 * \link terule_query.h \<qpol/terule_query.h\> \endlink or 0 to indicate
	 * that any rule type matches.
	 */
	uint32_t rule_type() const;
	/**
	 * Set the rule type.
	 * @param ruletype The rule type. Must be one of QPOL_RULE_* from
	 * \link avrule_query.h \<qpol/avrule_query.h\> \endlink and
	 * \link terule_query.h \<qpol/terule_query.h\> \endlink or 0 to indicate
	 * that any rule type matches.
	 * @return The rule type set.
	 * @exception std::invalid_argument The provided rule type is not valid.
	 */
	uint32_t rule_type(uint32_t ruletype) throw(std::invalid_argument);

      private:
	 uint32_t _rule_type;	       /*!< The rule type. */
};

/**
 * Criterion used to compare a boolean state.
 */
class polsearch_bool_criterion:public polsearch_criterion
{
      public:
	/**
	 * Create a criterion with a boolean state parameter.
	 * @param opr Comparison operator to use.
	 * @param neg If \a true, invert the logic result of the operator.
	 * @param val Value of the boolean.
	 */
	polsearch_bool_criterion(polsearch_op_e opr, bool neg = false, bool val = false);
	/**
	 * Copy a criterion with a boolean state parameter.
	 * @param pbc The criterion to copy.
	 */
	polsearch_bool_criterion(const polsearch_bool_criterion & pbc);
	//! Destructor.
	~polsearch_bool_criterion();

	/**
	 * Get the boolean state value.
	 * @return The boolean state value.
	 */
	bool value() const;
	/**
	 * Set the boolean state value.
	 * @return The boolean state value set.
	 */
	bool value(bool val);

      private:
	 bool _value;		       /*!< The boolean state value. */
};

/**
 * Criterion used to compare user default levels.
 */
class polsearch_level_criterion:public polsearch_criterion
{
      public:
	/**
	 * Create a criterion with a MLS level parameter.
	 * @param opr Comparison operator to use.
	 * @param neg If \a true, invert the logic result of the operator.
	 * @param lvl The MLS level; this level will be duplicated.
	 * @param m The type of matching to use for the level. This must be one
	 * of APOL_MLS_EQ, APOL_MLS_DOM, APOL_MLS_DOMBY, or APOL_MLS_INCOMP from
	 * \link mls-query.h \<apol/mls-query.h\>\endlink.
	 * @exception std::bad_alloc Could not copy the provided level.
	 * @exception std::invalid_argument Invalid level matching requested.
	 * @see polsearch_level_criterion::match(int) for details on each of
	 *	the types of matching.
	 * 
	 */
	polsearch_level_criterion(polsearch_op_e opr, bool neg = false, const apol_mls_level_t * lvl = NULL, int m =
				  APOL_MLS_EQ) throw(std::bad_alloc, std::invalid_argument);
	/**
	 * Copy a criterion with a MLS level parameter.
	 * @param plc The criterion to copy.
	 * @exception std::bad_alloc Could not copy the MLS level.
	 */
	 polsearch_level_criterion(const polsearch_level_criterion & plc) throw(std::bad_alloc);
	//! Destructor.
	~polsearch_level_criterion();

	/**
	 * Get the MLS level.
	 * @return The MLS level.
	 */
	const apol_mls_level_t *level() const;
	/**
	 * Set the MLS level.
	 * @param lvl The MLS level to set; this level will be duplicated.
	 * @return The MLS level set.
	 * @exception std::bad_alloc Could not copy the MLS level.
	 */
	const apol_mls_level_t *level(const apol_mls_level_t * lvl) throw(std::bad_alloc);
	/**
	 * Get the type of level matching.
	 * @return The type of level matching.
	 */
	int match() const;
	/**
	 * Set the type of level matching.
	 * @param m The type of matching to use for the level. This must be one of<ul>
	 * <li>APOL_MLS_EQ: The tested level is equal to the level parameter.
	 * This is the default method.</li>
	 * <li>APOL_MLS_DOM: The tested level dominates the level parameter.</li>
	 * <li>APOL_MLS_DOMBY: The tested level is dominated by the level parameter.</li>
	 * <li>APOL_MLS_INCOMP: The tested level is incomparable to the level
	 * parameter (i.e. none of the above).</li>
	 * </ul> see \link mls-query.h \<apol/mls-query.h\>\endlink.
	 * @return The type of matching set.
	 * @exception std::invalid_argument Invalid level matching requested.
	 */
	int match(int m) throw(std::invalid_argument);

      private:
	 apol_mls_level_t * _level;    /*!< The MLS level. */
	int _match;		       /*!< The type of level matching. */
};

/**
 * Criterion used for comparison of MLS ranges.
 */
class polsearch_range_criterion:public polsearch_criterion
{
      public:
	/**
	 * Create a criterion with a MLS range parameter.
	 * @param opr Comparison operator to use.
	 * @param neg If \a true, invert the logic result of the operator.
	 * @param rng The MLS range; this range will be duplicated.
	 * @param m The type of matching to use for the range.
	 * This must be one of APOL_QUERY_EXACT, APOL_QUERY_SUB, or
	 * APOL_QUERY_SUPER from \link policy-query.h \<apol/policy-query.h\>\endlink.
	 * @exception std::bad_alloc Could not duplicate the range.
	 * @exception std::invalid_argument Invalid range matching requested.
	 * @see polsearch_range_criterion::match(unsigned int) for details on
	 * each of the types of matching.
	 */
	polsearch_range_criterion(polsearch_op_e opr, bool neg = false, const apol_mls_range_t * rng = NULL,
				  unsigned int m = APOL_QUERY_EXACT) throw(std::bad_alloc, std::invalid_argument);
	/**
	 * Copy a criterion with a MLS range parameter.
	 * @param prc The criterion to copy.
	 * @exception std::bad_alloc Could not duplicate the range.
	 */
	 polsearch_range_criterion(polsearch_range_criterion & prc) throw(std::bad_alloc);
	//! Destructor.
	~polsearch_range_criterion();

	/**
	 * Get the MLS range.
	 * @return The MLS range.
	 */
	const apol_mls_range_t *range() const;
	/**
	 * Set the MLS range.
	 * @param rng The MLS range to set; this range will be duplicated.
	 * @return The MLS range set.
	 * @exception std::bad_alloc Could not duplicate the range.
	 */
	const apol_mls_range_t *range(const apol_mls_range_t * rng) throw(std::bad_alloc);
	/**
	 * Get the type of range matching.
	 * @return The type of range matching.
	 */
	unsigned int match() const;
	/**
	 * Set the type of range matching.
	 * @param m The type of range matching to use. This must be one of<ul>
	 * <li>APOL_QUERY_EXACT: The range parameter exactly matches the tested
	 * range. This is the default method.</li>
	 * <li>APOL_QUERY_SUB: The range parameter is a subset of the tested range.</li>
	 * <li>APOL_QUERY_SUPER: The range parameter is a superset of the tested range.</li>
	 * </ul> see \link policy-query.h \<apol/policy-query.h\>\endlink.
	 * @return The type of range matching set.
	 * @exception std::invalid_argument Invalid range matching requested.
	 */
	unsigned int match(unsigned int m) throw(std::invalid_argument);

      private:
	 apol_mls_range_t * _range;    /*!< The MLS range. */
	unsigned int _match;	       /*!< The type of range matching. */
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
	extern polsearch_op_e polsearch_criterion_get_op(const polsearch_criterion_t * pc);
	extern bool polsearch_criterion_get_negated(const polsearch_criterion_t * pc);
	extern bool polsearch_criterion_set_negated(polsearch_criterion_t * pc);
	extern polsearch_param_type_e polsearch_criterion_get_param_type(const polsearch_criterion_t * pc);
	extern apol_vector_t *polsearch_criterion_check(const polsearch_criterion_t * pc, const apol_policy_t * p,
							const sefs_fclist_t * fclist, const apol_vector_t * test_candidates,
							apol_vector_t * Xcandidtates);

	extern polsearch_regex_criterion_t *polsearch_regex_criterion_create(polsearch_op_e opr, bool neg, const char *expression);
	extern polsearch_regex_criterion_t *polsearch_regex_criterion_create_from_criterion(const polsearch_regex_criterion_t *
											    prc);
	extern void polsearch_regex_criterion_destroy(polsearch_regex_criterion_t ** prc);
	extern const char *const polsearch_regex_criterion_get_regex(const polsearch_regex_criterion_t * prc);
	extern char *polsearch_regex_criterion_set_regex(polsearch_regex_criterion_t * prc, const char *expression);

	extern polsearch_strring_list_criterion_t *polsearch_strring_list_criterion_create(polsearch_op_e opr, bool neg,
											   const polsearch_string_list * strlist);
	extern polsearch_strring_list_criterion_t *polsearch_strring_list_criterion_create_from_criterion(const
													  polsearch_strring_list_criterion_t
													  * pslc);
	extern void polsearch_strring_list_criterion_destroy(polsearch_strring_list_criterion_t ** pslc);
	extern const polsearch_string_list_t *polsearch_strring_list_criterion_get_string_list(const
											       polsearch_strring_list_criterion_t *
											       pslc);
	extern polsearch_string_list_t *polsearch_strring_list_criterion_set_string_list(polsearch_strring_list_criterion_t * pslc,
											 const polsearch_string_list_t * strlist);

	extern polsearch_rule_type_criterion_t *polsearch_rule_type_criterion_create(polsearch_op_e opr, bool neg,
										     uint32_t ruletype);
	extern polsearch_rule_type_criterion_t *polsearch_rule_type_criterion_create_from_criterion(const
												    polsearch_rule_type_criterion_t
												    * prtc);
	extern void polsearch_rule_type_criterion_destroy(polsearch_rule_type_criterion_t ** prtc);
	extern uint32_t polsearch_rule_type_criterion_get_rule_type(const polsearch_rule_type_criterion_t * prtc);
	extern uint32_t polsearch_rule_type_criterion_set_rule_type(polsearch_rule_type_criterion_t * prtc, uint32_t ruletype);

	extern polsearch_bool_criterion_t *polsearch_bool_criterion_create(polsearch_op_e opr, bool neg, bool val);
	extern polsearch_bool_criterion_t *polsearch_bool_criterion_create_from_criterion(const polsearch_bool_criterion_t * pbc);
	extern void polsearch_bool_criterion_destroy(polsearch_bool_criterion_t ** pbc);
	extern bool polsearch_bool_criterion_get_value(const polsearch_bool_criterion_t * pbc);
	extern bool polsearch_bool_criterion_set_value(polsearch_bool_criterion_t * pbc, bool val);

	extern polsearch_level_criterion_t *polsearch_level_criterion_create(polsearch_op_e opr, bool neg,
									     const apol_mls_level_t * lvl, int m);
	extern polsearch_level_criterion_t *polsearch_level_criterion_create_from_criterion(const polsearch_level_criterion_t *
											    plc);
	extern void polsearch_level_criterion_destroy(polsearch_level_criterion_t ** plc);
	extern const apol_mls_level_t *polsearch_level_criterion_get_level(const polsearch_level_criterion_t * plc);
	extern apol_mls_level_t *polsearch_level_criterion_set_level(polsearch_level_criterion_t * plc,
								     const apol_mls_level_t * lvl);
	extern int polsearch_level_criterion_get_match(const polsearch_level_criterion_t * plc);
	extern int polsearch_level_criterion_set_match(polsearch_level_criterion_t * plc, int m);

	extern polsearch_range_criterion_t *polsearch_range_criterion_create(polsearch_op_e opr, bool neg,
									     const apol_mls_range_t * rng, unsigned int m);
	extern polsearch_range_criterion_t *polsearch_range_criterion_create_from_criterion(const polsearch_range_criterion_t *
											    prc);
	extern void polsearch_range_criterion_destroy(polsearch_range_criterion_t ** prc);
	extern const apol_mls_range_t *polsearch_range_criterion_get_range(const polsearch_range_criterion_t * prc);
	extern apol_mls_range_t *polsearch_range_criterion_set_range(polsearch_range_criterion_t * prc,
								     const apol_mls_range_t * rng);
	extern unsigned int polsearch_range_criterion_get_match(const polsearch_range_criterion_t * prc);
	extern unsigned int polsearch_range_criterion_set_match(polsearch_range_criterion_t * prc, unsigned int m);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* POLSEARCH_CRITERION_H */
