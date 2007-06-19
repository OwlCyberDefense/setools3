/**
 * @file
 *
 * Top level library routines.
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

#include <polsearch/polsearch.hh>
#include "polsearch_internal.hh"

#include <apol/policy.h>
#include <sefs/entry.hh>

// internal functions

int element_compare(polsearch_element_e elem_type, const void *left, const void *right, const apol_policy_t * policy)
{
	const qpol_policy_t *q = apol_policy_get_qpol(policy);

	switch (elem_type)
	{
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
		return strcmp(polsearch_symbol_get_name
			      (left, static_cast < polsearch_symbol_e > (elem_type), policy),
			      polsearch_symbol_get_name(right, static_cast < polsearch_symbol_e > (elem_type), policy));
	}
	case POLSEARCH_ELEMENT_STRING:
	case POLSEARCH_ELEMENT_PERMISSION:
	{
		return strcmp(static_cast < const char *>(left), static_cast < const char *>(right));
	}
	case POLSEARCH_ELEMENT_AVRULE:
	{
		const qpol_avrule_t *lrule = static_cast < const qpol_avrule_t * >(left);
		const qpol_avrule_t *rrule = static_cast < const qpol_avrule_t * >(right);
		int retv = 0;
		// compare rule type
		uint32_t lt;
		qpol_avrule_get_rule_type(q, lrule, &lt);
		uint32_t rt;
		qpol_avrule_get_rule_type(q, rrule, &rt);
		if ((retv = lt - rt))
			return retv;
		// compare source name
		const qpol_type_t *ltype;
		qpol_avrule_get_source_type(q, lrule, &ltype);
		const qpol_type_t *rtype;
		qpol_avrule_get_source_type(q, rrule, &rtype);
		const char *lname;
		qpol_type_get_name(q, ltype, &lname);
		const char *rname;
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare target name
		qpol_avrule_get_target_type(q, lrule, &ltype);
		qpol_avrule_get_target_type(q, rrule, &rtype);
		qpol_type_get_name(q, ltype, &lname);
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare class name
		const qpol_class_t *lclass;
		qpol_avrule_get_object_class(q, lrule, &lclass);
		const qpol_class_t *rclass;
		qpol_avrule_get_object_class(q, rrule, &rclass);
		qpol_class_get_name(q, lclass, &lname);
		qpol_class_get_name(q, rclass, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare conditional (pointer comparison only)
		const qpol_cond_t *lcond;
		qpol_avrule_get_cond(q, lrule, &lcond);
		const qpol_cond_t *rcond;
		qpol_avrule_get_cond(q, rrule, &rcond);
		if ((retv = reinterpret_cast < const ssize_t > (lcond) - reinterpret_cast < const ssize_t > (rcond)))
			return retv;
		// semantic rules with same key; should be the same rule.
		return 0;
	}
	case POLSEARCH_ELEMENT_TERULE:
	{
		const qpol_terule_t *lrule = static_cast < const qpol_terule_t * >(left);
		const qpol_terule_t *rrule = static_cast < const qpol_terule_t * >(right);
		int retv = 0;
		// compare rule type
		uint32_t lt;
		qpol_terule_get_rule_type(q, lrule, &lt);
		uint32_t rt;
		qpol_terule_get_rule_type(q, rrule, &rt);
		if ((retv = lt - rt))
			return retv;
		// compare source name
		const qpol_type_t *ltype;
		qpol_terule_get_source_type(q, lrule, &ltype);
		const qpol_type_t *rtype;
		qpol_terule_get_source_type(q, rrule, &rtype);
		const char *lname;
		qpol_type_get_name(q, ltype, &lname);
		const char *rname;
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare target name
		qpol_terule_get_target_type(q, lrule, &ltype);
		qpol_terule_get_target_type(q, rrule, &rtype);
		qpol_type_get_name(q, ltype, &lname);
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare class name
		const qpol_class_t *lclass;
		qpol_terule_get_object_class(q, lrule, &lclass);
		const qpol_class_t *rclass;
		qpol_terule_get_object_class(q, rrule, &rclass);
		qpol_class_get_name(q, lclass, &lname);
		qpol_class_get_name(q, rclass, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare conditional (pointer comparison only)
		const qpol_cond_t *lcond;
		qpol_terule_get_cond(q, lrule, &lcond);
		const qpol_cond_t *rcond;
		qpol_terule_get_cond(q, rrule, &rcond);
		if ((retv = reinterpret_cast < const ssize_t > (lcond) - reinterpret_cast < const ssize_t > (rcond)))
			return retv;
		// semantic rules with same key; should be the same rule.
		return 0;
	}
	case POLSEARCH_ELEMENT_ROLE_ALLOW:
	{
		const qpol_role_allow_t *lrule = static_cast < const qpol_role_allow_t * >(left);
		const qpol_role_allow_t *rrule = static_cast < const qpol_role_allow_t * >(right);
		// compare source role
		const qpol_role_t *lrole;
		qpol_role_allow_get_source_role(q, lrule, &lrole);
		const qpol_role_t *rrole;
		qpol_role_allow_get_source_role(q, rrule, &rrole);
		const char *lname;
		qpol_role_get_name(q, lrole, &lname);
		const char *rname;
		qpol_role_get_name(q, rrole, &rname);
		int retv;
		if ((retv = strcmp(lname, rname)))
			return retv;
		// conpare target
		qpol_role_allow_get_target_role(q, lrule, &lrole);
		qpol_role_allow_get_target_role(q, rrule, &rrole);
		qpol_role_get_name(q, lrole, &lname);
		qpol_role_get_name(q, rrole, &rname);
		return strcmp(lname, rname);
	}
	case POLSEARCH_ELEMENT_ROLE_TRANS:
	{
		const qpol_role_trans_t *lrule = static_cast < const qpol_role_trans_t * >(left);
		const qpol_role_trans_t *rrule = static_cast < const qpol_role_trans_t * >(right);
		// compare source role
		const qpol_role_t *lrole;
		qpol_role_trans_get_source_role(q, lrule, &lrole);
		const qpol_role_t *rrole;
		qpol_role_trans_get_source_role(q, rrule, &rrole);
		const char *lname;
		qpol_role_get_name(q, lrole, &lname);
		const char *rname;
		qpol_role_get_name(q, rrole, &rname);
		int retv;
		if ((retv = strcmp(lname, rname)))
			return retv;
		// conpare target type
		const qpol_type_t *ltype;
		qpol_role_trans_get_target_type(q, lrule, &ltype);
		const qpol_type_t *rtype;
		qpol_role_trans_get_target_type(q, rrule, &rtype);
		qpol_type_get_name(q, ltype, &lname);
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare default role
		qpol_role_trans_get_default_role(q, lrule, &lrole);
		qpol_role_trans_get_default_role(q, rrule, &rrole);
		qpol_role_get_name(q, lrole, &lname);
		qpol_role_get_name(q, rrole, &rname);
		return strcmp(lname, rname);
	}
	case POLSEARCH_ELEMENT_RANGE_TRANS:
	{
		const qpol_range_trans_t *lrule = static_cast < const qpol_range_trans_t * >(left);
		const qpol_range_trans_t *rrule = static_cast < const qpol_range_trans_t * >(right);
		// compare source type
		const qpol_type_t *ltype;
		qpol_range_trans_get_source_type(q, lrule, &ltype);
		const qpol_type_t *rtype;
		qpol_range_trans_get_source_type(q, rrule, &rtype);
		const char *lname;
		qpol_type_get_name(q, ltype, &lname);
		const char *rname;
		qpol_type_get_name(q, rtype, &rname);
		int retv;
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare target type
		qpol_range_trans_get_target_type(q, lrule, &ltype);
		qpol_range_trans_get_target_type(q, rrule, &rtype);
		qpol_type_get_name(q, ltype, &lname);
		qpol_type_get_name(q, rtype, &rname);
		if ((retv = strcmp(lname, rname)))
			return retv;
		// compare object class
		const qpol_class_t *lclass;
		qpol_range_trans_get_target_class(q, lrule, &lclass);
		const qpol_class_t *rclass;
		qpol_range_trans_get_target_class(q, rrule, &rclass);
		qpol_class_get_name(q, lclass, &lname);
		qpol_class_get_name(q, rclass, &rname);
		return strcmp(lname, rname);
	}
	case POLSEARCH_ELEMENT_FC_ENTRY:
	{
		const sefs_entry *le = static_cast < const sefs_entry * >(left);
		const sefs_entry *re = static_cast < const sefs_entry * >(right);
		char *ls = le->toString();
		char *rs = re->toString();
		int ret = strcmp(ls, rs);
		free(ls);
		free(rs);
		return ret;
	}
	case POLSEARCH_ELEMENT_MLS_RANGE:
	{
		const apol_mls_range_t *lr = static_cast < const apol_mls_range_t * >(left);
		const apol_mls_range_t *rr = static_cast < const apol_mls_range_t * >(right);

		if (apol_mls_range_compare(policy, lr, rr, APOL_QUERY_EXACT) > 0)
			return 0;
		if (apol_mls_range_compare(policy, lr, rr, APOL_QUERY_SUB) > 0)
			return 1;
		if (apol_mls_range_compare(policy, lr, rr, APOL_QUERY_SUPER) > 0)
			return -1;
		// no clear dominance; fallback on sensitivity name of low level
		return strcmp(apol_mls_level_get_sens(apol_mls_range_get_low(lr)),
			      apol_mls_level_get_sens(apol_mls_range_get_low(rr)));
	}
	case POLSEARCH_ELEMENT_BOOL_STATE:
	{
		if (left == right)
			return 0;
		else if (left)
			return 1;
		else
			return -1;
	}
	case POLSEARCH_ELEMENT_NONE:
	default:
	{
		return 0;	       // not comparable, don't sort
	}
	}
}
