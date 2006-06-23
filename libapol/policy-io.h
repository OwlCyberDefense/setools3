/**
 * @file policy-io.h
 *
 * Loads a policy, either source or binary policy, from disk.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

#ifndef _APOL_POLICY_IO_H_
#define _APOL_POLICY_IO_H_

#include "policy.h"

/**
 *  Open a policy file and load it into a newly created apol_policy.
 *  @param path The path of the policy file to open.
 *  @param policy The policy to create from the file.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *policy will be NULL;
 */
extern int apol_policy_open(const char *path, apol_policy_t **policy);

/**
 * Deallocate all memory associated with a policy, and then set it to
 * NULL.  Does nothing if the pointer is already NULL.
 *
 * @param policy Policy to destroy, if not already NULL.
 */
extern void apol_policy_destroy(apol_policy_t **policy);

#endif
