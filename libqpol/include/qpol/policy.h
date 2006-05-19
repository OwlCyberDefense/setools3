 /**
 *  @file policy.h
 *  Defines the public interface the QPol policy.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
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

#ifndef QPOL_POLICY_H
#define QPOL_POLICY_H

#include <sepol/policydb.h>

typedef sepol_policydb_t qpol_policy_t;

/* Policy type macros */
#define QPOL_TYPE_UNKNOWN	0
#define QPOL_TYPE_BINARY	1
#define QPOL_TYPE_SOURCE	2

/**
 *  Open a policy from a passed in file path.
 *  @param policy The policy to populate.  The caller should not free
 *  this pointer.
 *  @param filename The name of the file to open.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *policy will be NULL.
 */
extern int qpol_load_policy_from_file(qpol_policy_t **policy, const char *filename);

/**
 *  Close a policy.
 *  @param policy The policy to close.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 */
extern int qpol_close_policy(qpol_policy_t **policy);

#endif
