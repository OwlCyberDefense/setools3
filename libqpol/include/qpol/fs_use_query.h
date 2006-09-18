/**
 *  @file fs_use_query.h
 *  Defines the public interface for searching and iterating over fs_use statements.
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

#ifndef QPOL_FS_USE_QUERY_H
#define QPOL_FS_USE_QUERY_H

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/context_query.h>

typedef struct qpol_fs_use qpol_fs_use_t;

/**
 *  Get a fs_use statement by file system name.
 *  @param policy The policy from which to get the fs_use statement.
 *  @param name The name of the file system.
 *  @param ocon Pointer in which to store the fs_use statement.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *ocon will be NULL.
 */
extern int qpol_policy_get_fs_use_by_name(qpol_policy_t *policy, const char *name, qpol_fs_use_t **ocon);

/**
 *  Get an iterator for the fs_use statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_fs_use_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy 
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails, 
 *  errno will be set and *iter will be NULL.
 */
extern int qpol_policy_get_fs_use_iter(qpol_policy_t *policy, qpol_iterator_t **iter);

/**
 *  Get the file system name from a fs_use statement.
 *  @param policy The policy associated with the fs_use statement.
 *  @param ocon The fs_use statement from which to get the name.
 *  @param name Pointer to the string in which to store the name.
 *  The caller should not free this string.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
extern int qpol_fs_use_get_name(qpol_policy_t *policy, qpol_fs_use_t *ocon, char **name);

/* The defines QPOL_FS_USE_XATTR through QPOL_FS_USE_NONE are 
 * copied from sepol/policydb/services.h.
 * QPOL_FS_USE_PSID is an extension to support v12 policies. */
#define QPOL_FS_USE_XATTR 1
#define QPOL_FS_USE_TRANS 2
#define QPOL_FS_USE_TASK  3
#define QPOL_FS_USE_GENFS 4
#define QPOL_FS_USE_NONE  5
#define QPOL_FS_USE_PSID  6

/**
 *  Get the labeling behavior from a fs_use statement.
 *  @param policy The policy associated with the fs_use statement.
 *  @param ocon The fs_use statement from which to get the behavior.
 *  @param behavior Pointer to be set to the value of the labeling behavior.
 *  The value will be one of the QPOL_FS_USE_* values defined above.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *behavior will be 0.
 */
extern int qpol_fs_use_get_behavior(qpol_policy_t *policy, qpol_fs_use_t *ocon, uint32_t *behavior);

/**
 *  Get the context from a fs_use statement.
 *  @param policy The policy associated with the fs_use statement.
 *  @param ocon The fs_use statement from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL. It is considered an 
 *  error to call this function if behavior is QPOL_FS_USE_PSID.
 */
extern int qpol_fs_use_get_context(qpol_policy_t *policy, qpol_fs_use_t *ocon, qpol_context_t **context);

#endif /* QPOL_FS_USE_QUERY_H */
