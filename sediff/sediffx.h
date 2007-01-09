/**
 *  @file
 *  Headers for main sediffx program.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
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

#ifndef SEDIFFX_H
#define SEDIFFX_H

#include <apol/policy.h>
#include <apol/policy-path.h>
#include <poldiff/poldiff.h>

typedef struct sediffx sediffx_t;

/** enumeration of which policy to affect -- the original policy (used
    to be called "policy 1") or the modified policy ("policy 2") */
typedef enum sediff_policy
{
	SEDIFF_ORIG_POLICY, SEDIFF_MOD_POLICY
} sediff_policy_e;

#define COPYRIGHT_INFO "Copyright (C) 2004-2007 Tresys Technology, LLC"

/**
 * Return the policy path for the policy given.  If the policy has not
 * yet been leaded then return NULL.
 *
 * @param which Which policy path to get.
 *
 * @return Path to the policy, or NULL if none set.
 */
apol_policy_path_t *sediff_get_policy_path(sediffx_t * sediffx, const sediff_policy_e which);

#endif
