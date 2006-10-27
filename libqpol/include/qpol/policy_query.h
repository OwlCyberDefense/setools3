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

#endif				       /* QPOL_POLICYDB_QUERY_H */
