/**
 *  @file policy_query.h
 *  Defines the public interface for searching and iterating over specific 
 *  policy components.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#ifndef QPOL_POLICY_QUERY_H
#define QPOL_POLICY_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/bool_query.h>
#include <qpol/cond_query.h>
#include <qpol/class_perm_query.h>
#include <qpol/constraint_query.h>
#include <qpol/mls_query.h>
#include <qpol/role_query.h>
#include <qpol/type_query.h>
#include <qpol/user_query.h>
#include <qpol/context_query.h>
#include <qpol/nodecon_query.h>
#include <qpol/portcon_query.h>
#include <qpol/netifcon_query.h>
#include <qpol/fs_use_query.h>
#include <qpol/genfscon_query.h>
#include <qpol/isid_query.h>
#include <qpol/avrule_query.h>
#include <qpol/terule_query.h>
#include <qpol/rbacrule_query.h>
#include <qpol/mlsrule_query.h>
#include <qpol/syn_rule_query.h>

/* generic information about policydb*/

/**
 *  List of capabilities a policy may have. This list represents features
 *  of policy that may differ from version to version or based upon the
 *  format of the policy file.
 */
	typedef enum qpol_capability
	{
		/** The policy format stores the names of attributes. */
		QPOL_CAP_ATTRIB_NAMES,
		/** The policy format stores the syntactic rule type sets. */
		QPOL_CAP_SYN_RULES,
		/** The policy format stores rule line numbers (implies QPOL_CAP_SYN_RULES). */
		QPOL_CAP_LINE_NOS,
		/** The policy version supports booleans and conditional statements. */
		QPOL_CAP_CONDITIONALS,
		/** The policy version supports MLS components and statements. */
		QPOL_CAP_MLS,
		/** The policy format supports linking loadable modules. */
		QPOL_CAP_MODULES,
		/** The policy was loaded with av/te rules. */
		QPOL_CAP_RULES_LOADED
	} qpol_capability_e;

/**
 *  Determine if the policy is MLS enabled.
 *  @param policy The policy to check.
 *  @return Returns 1 if MLS is enabled, 0 if MLS is disabled, and
 *  < 0 if there was an error; if the call fails, errno will be set.
 */
	extern int qpol_policy_is_mls_enabled(qpol_policy_t * policy);

/**
 *  Get the version number of the policy.
 *  @param policy The policy for which to get the version.
 *  @param version Pointer to the integer to set to the version number.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *version will be 0.
 */
	extern int qpol_policy_get_policy_version(qpol_policy_t * policy, unsigned int *version);

/**
 *  Get the type of policy (source, binary, or module).
 *  @param policy The policy from which to get the type.
 *  @param type Pointer to the integer in which to store the type.
 *  Value will be one of QPOL_POLICY_* from above.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *type will be QPOL_POLICY_UNKNOWN.
 */
	extern int qpol_policy_get_type(qpol_policy_t * policy, int *type);

/**
 *  Determine if a policy has support for a specific capability.
 *  @param policy The policy to check.
 *  @param cap The capability for which to check. Must be one of QPOL_CAP_*
 *  defined above.
 *  @return Non-zero if the policy has the specified capability, and zero otherwise.
 */
	extern int qpol_policy_has_capability(qpol_policy_t * policy, qpol_capability_e cap);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_POLICYDB_QUERY_H */
