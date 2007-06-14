/**
 * @file
 *
 * Implementation of utility functions for libpolsearch.
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

#include <config.h>

#include <polsearch/polsearch.hh>
#include <polsearch/test.hh>
#include <polsearch/util.h>
#include <sefs/fclist.hh>
#include <sefs/entry.hh>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

const char *libpolsearch_get_version(void)
{
	return LIBPOLSEARCH_VERSION_STRING;
}

const char *libpolsearch_symbol_get_name(const void *symbol, polsearch_symbol_e sym_type, const apol_policy_t * p)
{
	if (!p) {
		errno = EINVAL;
		return NULL;
	}
	qpol_policy_t *qp = apol_policy_get_qpol(p);
	const char *name = NULL;
	switch (sym_type) {
	case POLSEARCH_SYMBOL_TYPE:
	case POLSEARCH_SYMBOL_ATTRIBUTE:
	{
		qpol_type_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_ROLE:
	{
		qpol_role_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_USER:
	{
		qpol_user_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_CLASS:
	{
		qpol_class_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_COMMON:
	{
		qpol_common_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_CATEGORY:
	{
		qpol_cat_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_LEVEL:
	{
		qpol_level_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_BOOL:
	{
		qpol_bool_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_NONE:
	default:
	{
		errno = EINVAL;
		return NULL;
	}
	}
	return name;
}

const char *polsearch_symbol_type_to_string(polsearch_symbol_e sym_type)
{
	if (sym_type > POLSEARCH_SYMBOL_BOOL) {
		errno = EINVAL;
		return NULL;
	}

	return polsearch_element_type_to_string(sym_type);
}

polsearch_symbol_e polsearch_string_to_symbol_type(const char *str)
{
	if (!strcmp(str, "type"))
		return POLSEARCH_SYMBOL_TYPE;
	if (!strcmp(str, "attribute"))
		return POLSEARCH_SYMBOL_ATTRIBUTE;
	if (!strcmp(str, "role"))
		return POLSEARCH_SYMBOL_ROLE;
	if (!strcmp(str, "user"))
		return POLSEARCH_SYMBOL_USER;
	if (!strcmp(str, "class"))
		return POLSEARCH_SYMBOL_CLASS;
	if (!strcmp(str, "common"))
		return POLSEARCH_SYMBOL_COMMON;
	if (!strcmp(str, "category"))
		return POLSEARCH_SYMBOL_CATEGORY;
	if (!strcmp(str, "level"))
		return POLSEARCH_SYMBOL_LEVEL;
	if (!strcmp(str, "bool"))
		return POLSEARCH_SYMBOL_BOOL;

	/* no match */
	errno = EINVAL;
	return POLSEARCH_SYMBOL_NONE;
}

const char *polsearch_element_type_to_string(polsearch_element_e elem_type)
{
	switch (elem_type) {
	case POLSEARCH_ELEMENT_TYPE:
		return "type";
	case POLSEARCH_ELEMENT_ATTRIBUTE:
		return "attribute";
	case POLSEARCH_ELEMENT_ROLE:
		return "role";
	case POLSEARCH_ELEMENT_USER:
		return "user";
	case POLSEARCH_ELEMENT_CLASS:
		return "class";
	case POLSEARCH_ELEMENT_COMMON:
		return "common";
	case POLSEARCH_ELEMENT_CATEGORY:
		return "category";
	case POLSEARCH_ELEMENT_LEVEL:
		return "level";
	case POLSEARCH_ELEMENT_BOOL:
		return "bool";
	case POLSEARCH_ELEMENT_STRING:
		return "";	       /* empty string returned here, element is just a string. */
	case POLSEARCH_ELEMENT_AVRULE:
		return "av rule";
	case POLSEARCH_ELEMENT_TERULE:
		return "type rule";
	case POLSEARCH_ELEMENT_ROLE_ALLOW:
		return "role allow";
	case POLSEARCH_ELEMENT_ROLE_TRANS:
		return "role_transition";
	case POLSEARCH_ELEMENT_RANGE_TRANS:
		return "range_transition";
	case POLSEARCH_ELEMENT_FC_ENTRY:
		return "file_contexts entry";
	case POLSEARCH_ELEMENT_MLS_RANGE:
		return "range";
	case POLSEARCH_ELEMENT_PERMISSION:
		return "permission";
	case POLSEARCH_ELEMENT_BOOL_STATE:
		return "state";
	case POLSEARCH_ELEMENT_NONE:
	default:
	{
		errno = EINVAL;
		return NULL;
	}
	}
}

polsearch_element_e polsearch_string_to_element_type(const char *str)
{
	polsearch_symbol_e sym;
	if ((sym = polsearch_string_to_symbol_type(str)))
		return sym;

	if (!strcmp(str, ""))	       /* empty string matches POLSEARCH_ELEMENT_STRING. */
		return POLSEARCH_ELEMENT_STRING;
	if (!strcmp(str, "av rule"))
		return POLSEARCH_ELEMENT_AVRULE;
	if (!strcmp(str, "type rule"))
		return POLSEARCH_ELEMENT_TERULE;
	if (!strcmp(str, "role allow"))
		return POLSEARCH_ELEMENT_ROLE_ALLOW;
	if (!strcmp(str, "role_transition"))
		return POLSEARCH_ELEMENT_ROLE_TRANS;
	if (!strcmp(str, "role_transiion"))
		return POLSEARCH_ELEMENT_RANGE_TRANS;
	if (!strcmp(str, "range_transiion"))
		return POLSEARCH_ELEMENT_FC_ENTRY;
	if (!strcmp(str, "file_contexts entry"))
		return POLSEARCH_ELEMENT_MLS_RANGE;
	if (!strcmp(str, "range"))
		return POLSEARCH_ELEMENT_PERMISSION;
	if (!strcmp(str, "state"))
		return POLSEARCH_ELEMENT_BOOL_STATE;

	errno = EINVAL;
	return POLSEARCH_ELEMENT_NONE;
}

char *polsearch_element_to_string(const void *elem, polsearch_element_e elem_type, const apol_policy_t * p,
				  const sefs_fclist_t * fclist __attribute__ ((unused)))
{
	const char *tmp = NULL;

	if (!elem) {
		errno = EINVAL;
		return NULL;
	}

	switch (elem_type) {
	case POLSEARCH_ELEMENT_TYPE:
	case POLSEARCH_ELEMENT_ATTRIBUTE:
	case POLSEARCH_ELEMENT_ROLE:
	case POLSEARCH_ELEMENT_USER:
	case POLSEARCH_ELEMENT_CLASS:
	case POLSEARCH_ELEMENT_COMMON:
	case POLSEARCH_ELEMENT_CATEGORY:
	case POLSEARCH_ELEMENT_LEVEL:
	case POLSEARCH_ELEMENT_BOOL:
	{
		tmp = polsearch_symbol_type_to_string(elem_type);
		return strdup(tmp);
	}
	case POLSEARCH_ELEMENT_STRING:
	case POLSEARCH_ELEMENT_PERMISSION:
	{
		return strdup(elem);
	}
	case POLSEARCH_ELEMENT_AVRULE:
	{
		return apol_avrule_render(p, elem);
	}
	case POLSEARCH_ELEMENT_TERULE:
	{
		return apol_terule_render(p, elem);
	}
	case POLSEARCH_ELEMENT_ROLE_ALLOW:
	{
		return apol_role_allow_render(p, elem);
	}
	case POLSEARCH_ELEMENT_ROLE_TRANS:
	{
		return apol_role_trans_render(p, elem);
	}
	case POLSEARCH_ELEMENT_RANGE_TRANS:
	{
		return apol_range_trans_render(p, elem);
	}
	case POLSEARCH_ELEMENT_FC_ENTRY:
	{
		return sefs_entry_to_string(elem);
	}
	case POLSEARCH_ELEMENT_MLS_RANGE:
	{
		return apol_mls_range_render(p, elem);
	}
	case POLSEARCH_ELEMENT_BOOL_STATE:
	{
		return (bool) elem ? strdup("true") : strdup("false");
	}
	case POLSEARCH_ELEMENT_NONE:
	default:
	{
		errno = EINVAL;
		return NULL;
	}
	}
}

const char *polsearch_test_cond_to_string(polsearch_test_cond_e test)
{
	switch (test) {
	case POLSEARCH_TEST_NAME:
	{
		return "its name";
	}
	case POLSEARCH_TEST_ALIAS:
	{
		return "it has an alias";
	}
	case POLSEARCH_TEST_ATTRIBUTES:
	{
		return "its assigned attributes";
	}
	case POLSEARCH_TEST_ROLES:
	{
		return "its assigned roles";
	}
	case POLSEARCH_TEST_AVRULE:
	{
		return "there is an av tule";
	}
	case POLSEARCH_TEST_TERULE:
	{
		return "there is a type rule";
	}
	case POLSEARCH_TEST_ROLEALLOW:
	{
		return "there is a role allow rule";
	}
	case POLSEARCH_TEST_ROLETRANS:
	{
		return "there is a role_transition rule";
	}
	case POLSEARCH_TEST_RANGETRANS:
	{
		return "there is a range_transition rule";
	}
	case POLSEARCH_TEST_FCENTRY:
	{
		return "there is a file_context entry";
	}
	case POLSEARCH_TEST_TYPES:
	{
		return "its assigned types";
	}
	case POLSEARCH_TEST_USERS:
	{
		return "it is assigned to users";
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	{
		return "its default level";
	}
	case POLSEARCH_TEST_RANGE:
	{
		return "its assigned range";
	}
	case POLSEARCH_TEST_COMMON:
	{
		return "its inherited common";
	}
	case POLSEARCH_TEST_PERMISSIONS:
	{
		return "its assigned permissions";
	}
	case POLSEARCH_TEST_CATEGORIES:
	{
		return "its assigned categories";
	}
	case POLSEARCH_TEST_STATE:
	{
		return "its default state";
	}
	case POLSEARCH_TEST_NONE:
	default:
	{
		return "";
	}
	}
}

bool polsearch_validate_test_condition(polsearch_element_e elem_type, polsearch_test_cond_e cond)
{
	switch (cond) {
	case POLSEARCH_TEST_NAME:
	{
		if (elem_type <= POLSEARCH_ELEMENT_BOOL)
			return true;
		break;
	}
	case POLSEARCH_TEST_ALIAS:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_LEVEL ||
		    elem_type == POLSEARCH_ELEMENT_CATEGORY)
			return true;
		break;
	}
	case POLSEARCH_TEST_ATTRIBUTES:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLES:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_USER)
			return true;
		break;
	}
	case POLSEARCH_TEST_AVRULE:
	case POLSEARCH_TEST_TERULE:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_ATTRIBUTE ||
		    elem_type == POLSEARCH_ELEMENT_CLASS)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLEALLOW:
	case POLSEARCH_TEST_USERS:
	{
		if (elem_type == POLSEARCH_ELEMENT_ROLE)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLETRANS:
	{
		if (elem_type == POLSEARCH_ELEMENT_ROLE || elem_type == POLSEARCH_ELEMENT_TYPE ||
		    elem_type == POLSEARCH_ELEMENT_ATTRIBUTE)
			return true;
		break;
	}
	case POLSEARCH_TEST_RANGETRANS:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_ATTRIBUTE ||
		    elem_type == POLSEARCH_ELEMENT_CLASS || elem_type == POLSEARCH_ELEMENT_LEVEL ||
		    elem_type == POLSEARCH_ELEMENT_CATEGORY)
			return true;
		break;
	}
	case POLSEARCH_TEST_FCENTRY:
	{
		if (elem_type == POLSEARCH_ELEMENT_TYPE || elem_type == POLSEARCH_ELEMENT_ROLE ||
		    elem_type == POLSEARCH_ELEMENT_CLASS || elem_type == POLSEARCH_ELEMENT_LEVEL ||
		    elem_type == POLSEARCH_ELEMENT_CATEGORY)
			return true;
		break;
	}
	case POLSEARCH_TEST_TYPES:
	{
		if (elem_type == POLSEARCH_ELEMENT_ROLE || elem_type == POLSEARCH_ELEMENT_ATTRIBUTE)
			return true;
		break;
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	case POLSEARCH_TEST_RANGE:
	{
		if (elem_type == POLSEARCH_ELEMENT_USER)
			return true;
		break;
	}
	case POLSEARCH_TEST_COMMON:
	{
		if (elem_type == POLSEARCH_ELEMENT_CLASS)
			return true;
		break;
	}
	case POLSEARCH_TEST_PERMISSIONS:
	{
		if (elem_type == POLSEARCH_ELEMENT_CLASS || elem_type == POLSEARCH_ELEMENT_COMMON)
			return true;
		break;
	}
	case POLSEARCH_TEST_CATEGORIES:
	{
		if (elem_type == POLSEARCH_ELEMENT_LEVEL)
			return true;
		break;
	}
	case POLSEARCH_TEST_STATE:
	{
		if (elem_type == POLSEARCH_ELEMENT_BOOL)
			return true;
		break;
	}
	case POLSEARCH_TEST_NONE:
	default:
	{
		return false;
	}
	}
	return false;
}

bool polsearch_validate_operator(polsearch_element_e elem_type, polsearch_test_cond_e cond, polsearch_op_e opr)
{
	// First, validate that the condition makes sense for this element.
	if (!polsearch_validate_test_condition(elem_type, cond))
		return false;

	switch (cond) {
	case POLSEARCH_TEST_NAME:
	{
		if (opr == POLSEARCH_OP_IS || opr == POLSEARCH_OP_MATCH_REGEX)
			return true;
		break;
	}
	case POLSEARCH_TEST_ALIAS:
	{
		if (opr == POLSEARCH_OP_MATCH_REGEX)
			return true;
		break;
	}
	case POLSEARCH_TEST_ATTRIBUTES:
	case POLSEARCH_TEST_ROLES:
	case POLSEARCH_TEST_TYPES:
	case POLSEARCH_TEST_USERS:
	case POLSEARCH_TEST_COMMON:
	case POLSEARCH_TEST_PERMISSIONS:
	case POLSEARCH_TEST_CATEGORIES:
	{
		if (opr == POLSEARCH_OP_INCLUDE)
			return true;
		break;
	}
	case POLSEARCH_TEST_AVRULE:
	{
		if (opr == POLSEARCH_OP_RULE_TYPE || opr == POLSEARCH_OP_AS_SOURCE ||
		    opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_CLASS ||
		    opr == POLSEARCH_OP_AS_SRC_TGT || opr == POLSEARCH_OP_IN_COND || opr == POLSEARCH_OP_AS_PERM)
			return true;
		break;
	}
	case POLSEARCH_TEST_TERULE:
	{
		if (opr == POLSEARCH_OP_RULE_TYPE || opr == POLSEARCH_OP_AS_SOURCE ||
		    opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_CLASS ||
		    opr == POLSEARCH_OP_AS_SRC_TGT || opr == POLSEARCH_OP_IN_COND ||
		    opr == POLSEARCH_OP_AS_DEFAULT || opr == POLSEARCH_OP_AS_SRC_DFLT || opr == POLSEARCH_OP_AS_SRC_TGT_DFLT)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLEALLOW:
	{
		if (opr == POLSEARCH_OP_AS_SOURCE || opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_SRC_TGT)
			return true;
		break;
	}
	case POLSEARCH_TEST_ROLETRANS:
	{
		if (opr == POLSEARCH_OP_AS_SOURCE || opr == POLSEARCH_OP_AS_TARGET ||
		    opr == POLSEARCH_OP_AS_DEFAULT || opr == POLSEARCH_OP_AS_SRC_DFLT)
			return true;
		break;
	}
	case POLSEARCH_TEST_RANGETRANS:
	{
		if (opr == POLSEARCH_OP_AS_RANGE_EXACT || opr == POLSEARCH_OP_AS_RANGE_SUPER ||
		    opr == POLSEARCH_OP_AS_RANGE_SUB || opr == POLSEARCH_OP_AS_SOURCE ||
		    opr == POLSEARCH_OP_AS_TARGET || opr == POLSEARCH_OP_AS_CLASS || opr == POLSEARCH_OP_AS_SRC_TGT)
			return true;
		break;
	}
	case POLSEARCH_TEST_FCENTRY:
	{
		if (opr == POLSEARCH_OP_AS_USER || opr == POLSEARCH_OP_AS_ROLE ||
		    opr == POLSEARCH_OP_AS_TYPE || opr == POLSEARCH_OP_AS_RANGE_EXACT || opr == POLSEARCH_OP_AS_RANGE_SUPER ||
		    opr == POLSEARCH_OP_AS_RANGE_SUB || opr == POLSEARCH_OP_AS_CLASS)
			return true;
		break;
	}
	case POLSEARCH_TEST_DEFAULT_LEVEL:
	{
		if (opr == POLSEARCH_OP_AS_LEVEL_EXACT || opr == POLSEARCH_OP_AS_LEVEL_DOM || opr == POLSEARCH_OP_AS_LEVEL_DOMBY)
			return true;
		break;
	}
	case POLSEARCH_TEST_RANGE:
	{
		if (opr == POLSEARCH_OP_AS_RANGE_EXACT || opr == POLSEARCH_OP_AS_RANGE_SUPER || opr == POLSEARCH_OP_AS_RANGE_SUB)
			return true;
		break;
	}
	case POLSEARCH_TEST_STATE:
	{
		if (opr == POLSEARCH_OP_IS)
			return true;
		break;
	}
	case POLSEARCH_TEST_NONE:
	default:
	{
		return false;
	}
	}
	return false;
}

bool polsearch_validate_parameter_type(polsearch_element_e elem_type, polsearch_test_cond_e cond, polsearch_op_e opr,
				       polsearch_param_type_e param_type)
{
	if (!polsearch_validate_operator(elem_type, cond, opr))
		return false;

	switch (opr) {
	case POLSEARCH_OP_IS:
	{
		if (cond == POLSEARCH_TEST_STATE && param_type == POLSEARCH_PARAM_TYPE_BOOL)
			return true;
		else if (param_type == POLSEARCH_PARAM_TYPE_STR_LIST)
			return true;
		break;
	}
	case POLSEARCH_OP_MATCH_REGEX:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_REGEX)
			return true;
		break;
	}
	case POLSEARCH_OP_RULE_TYPE:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_RULE_TYPE)
			return true;
		break;
	}
	case POLSEARCH_OP_INCLUDE:
	case POLSEARCH_OP_AS_SOURCE:
	case POLSEARCH_OP_AS_TARGET:
	case POLSEARCH_OP_AS_CLASS:
	case POLSEARCH_OP_AS_PERM:
	case POLSEARCH_OP_AS_DEFAULT:
	case POLSEARCH_OP_AS_SRC_TGT:
	case POLSEARCH_OP_AS_SRC_TGT_DFLT:
	case POLSEARCH_OP_AS_SRC_DFLT:
	case POLSEARCH_OP_IN_COND:
	case POLSEARCH_OP_AS_USER:
	case POLSEARCH_OP_AS_ROLE:
	case POLSEARCH_OP_AS_TYPE:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_STR_LIST)
			return true;
		break;
	}
	case POLSEARCH_OP_AS_LEVEL_EXACT:
	case POLSEARCH_OP_AS_LEVEL_DOM:
	case POLSEARCH_OP_AS_LEVEL_DOMBY:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_LEVEL)
			return true;
		break;
	}
	case POLSEARCH_OP_AS_RANGE_EXACT:
	case POLSEARCH_OP_AS_RANGE_SUPER:
	case POLSEARCH_OP_AS_RANGE_SUB:
	{
		if (param_type == POLSEARCH_PARAM_TYPE_RANGE)
			return true;
		break;
	}
	case POLSEARCH_OP_NONE:
	default:
	{
		return false;
	}
	}

	return false;
}
