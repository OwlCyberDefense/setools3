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

#include <stdarg.h>

/* * Return codes for qpol_find_default_policy_file() function. */
#define QPOL_FIND_DEFAULT_SUCCESS               0
#define QPOL_GENERAL_ERROR                     -1
#define QPOL_BIN_POL_FILE_DOES_NOT_EXIST       -2
#define QPOL_SRC_POL_FILE_DOES_NOT_EXIST       -3
#define QPOL_BOTH_POL_FILE_DO_NOT_EXIST        -4
#define QPOL_POLICY_INSTALL_DIR_DOES_NOT_EXIST -5
#define QPOL_INVALID_SEARCH_OPTIONS            -6

/* Policy type macros */
#define QPOL_TYPE_UNKNOWN	0
#define QPOL_TYPE_BINARY	1
#define QPOL_TYPE_SOURCE	2

typedef struct qpol_policy qpol_policy_t;
typedef void (*qpol_callback_fn_t) (void* varg, struct qpol_policy* policy, int level, const char* fmt, va_list va_args);

#define QPOL_POLICY_KERNEL_SOURCE 0
#define QPOL_POLICY_KERNEL_BINARY 1
#define QPOL_POLICY_MODULE_BINARY 2

/**
 *  Open a policy from a passed in file path.
 *  @param filename The name of the file to open.
 *  @param policy The policy to populate.  The caller should not free
 *  this pointer.
 *  @param fn (Optional) If non-NULL, the callback to be used by the handle.
 *  @param varg (Optional) The argument needed by the handle callback.
 *  @return Returns one of QPOL_POLICY_* above on success and < 0 on failure;
 *  if the call fails, errno will be set and *policy will be NULL.
 */
extern int qpol_open_policy_from_file(const char *filename, qpol_policy_t **policy, qpol_callback_fn_t fn, void *varg);

/**
 *  Open a policy from a passed in file path but do not load any rules.
 *  @param filename The name of the file to open.
 *  @param policy The policy to populate.  The caller should not free
 *  this pointer.
 *  @param fn (Optional) If non-NULL, the callback to be used by the handle.
 *  @param varg (Optional) The argument needed by the handle callback.
 *  @return Returns one of QPOL_POLICY_* above on success and < 0 on failure;
 *  if the call fails, errno will be set and *policy will be NULL.
 */
extern int qpol_open_policy_from_file_no_rules(const char *filename, qpol_policy_t **policy, qpol_callback_fn_t fn, void *varg);

/**
 *  Open a policy from a passed in buffer.
 *  @param policy The policy to populate.  The caller should not free
 *  this pointer.
 *  @param filedata The policy file stored in memory .
 *  @param size The size of filedata
 *  @param fn (Optional) If non-NULL, the callback to be used by the handle.
 *  @param varg (Optional) The argument needed by the handle callback.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *policy will be NULL.
 */
extern int qpol_open_policy_from_memory(qpol_policy_t **policy, const char *filedata, int size,
					qpol_callback_fn_t fn, void *varg);

/**
 *  Close a policy and deallocate its memory.  Does nothing if it is
 *  already NULL.
 *  @param policy Reference to the policy to close.  The pointer will
 *  be set to NULL afterwards.
 */
extern void qpol_policy_destroy(qpol_policy_t **policy);

/**
 *  Find the default policy file given a policy type. 
 *  @param serach_opt Search options bitmask, defined in this file
 *  @param policy_file_path Character buffer to store policy path in  
 *  @return Returns one of the return codes defined in this file
 */
extern int qpol_find_default_policy_file(unsigned int search_opt, char **policy_file_path);

/**
 *  Get a string for the error code of qpol_find_default_policy_file().
 *  @param err Error code returned by qpol_find_default_policy_file().
 *  @return a string describing the error. <b>The caller should not
 *  free this string.</b>
 */
extern const char *qpol_find_default_policy_file_strerr(int err);

/**
 *  Re-evaluate all conditionals in the policy updating the state
 *  and setting the appropriate rule list as emabled for each.
 *  This call modifies the policy.
 *  @param policy The policy for which to re-evaluate the conditionals.
 *  This policy will be modified by this function.
 *  @return 0 on success and < 0 on failure; if the call fails.
 *  errno will be set. On failure, the policy state may be inconsistent.
 */
extern int qpol_policy_reevaluate_conds(qpol_policy_t *policy);

#endif
