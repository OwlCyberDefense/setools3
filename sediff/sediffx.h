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
typedef enum sediffx_policy
{
	SEDIFFX_POLICY_ORIG = 0, SEDIFFX_POLICY_MOD, SEDIFFX_POLICY_NUM
} sediffx_policy_e;

#define COPYRIGHT_INFO "Copyright (C) 2004-2007 Tresys Technology, LLC"

/**
 * Set one of the policies for sediffx.  This will invalidate any
 * currently executed poldiff_t objects.
 *
 * @param s sediffx object to query.
 * @param which Which policy to set.
 * @param policy New policy file for sediffx.  If NULL then no policy
 * is opened.  Afterwards sediffx takes ownership of the policy.
 * @param path If policy is not NULL, then the path that was used to
 * open the policy.
 */
void sediffx_set_policy(sediffx_t * s, sediffx_policy_e which, apol_policy_t * policy, apol_policy_path_t * path);

/**
 * Return the policy path for the policy given.  If the policy has not
 * yet been loaded then return NULL.
 *
 * @param s sediffx object to query.
 * @param which Which policy path to get.
 *
 * @return Path to the policy, or NULL if none set.
 */
const apol_policy_path_t *sediffx_get_policy_path(sediffx_t * s, const sediffx_policy_e which);

/**
 * Return the currently active poldiff object.  If one is not yet
 * created or if a policy has changed since the last time this
 * function was called, then build a new one and return it.  Note that
 * this does not actually call poldiff_run(); it is up to the caller
 * of this function to do that.
 *
 * @param s sediffx object to query.
 * @param fn If a poldiff object is being created, a valid callback
 * function to receive poldiff messages.
 * @param arg Arbitrary argument to poldiff callback handler.
 *
 * @return Poldiff object for currently loaded policies, or NULL upon
 * error.
 */
poldiff_t *sediffx_get_poldiff(sediffx_t * s, poldiff_handle_fn_t fn, void *arg);

#endif
