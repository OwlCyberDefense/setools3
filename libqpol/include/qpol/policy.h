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

#include <byteswap.h>
#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le16(x) bswap_16(x)
#define le16_to_cpu(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#endif

/* * Return codes for qpol_find_default_policy_file() function. */
#define FIND_DEFAULT_SUCCESS                    0
#define GENERAL_ERROR                           -1
#define BIN_POL_FILE_DOES_NOT_EXIST             -2
#define SRC_POL_FILE_DOES_NOT_EXIST             -3
#define BOTH_POL_FILE_DO_NOT_EXIST              -4
#define POLICY_INSTALL_DIR_DOES_NOT_EXIST       -5
#define INVALID_SEARCH_OPTIONS                  -6

/* Policy type macros */
#define QPOL_TYPE_UNKNOWN	0
#define QPOL_TYPE_BINARY	1
#define QPOL_TYPE_SOURCE	2

/* forward declaration, full declaration in policy_extend.c */
struct qpol_extended_image;

typedef struct qpol_policy {
	struct sepol_policydb *p;
	struct qpol_extended_image *ext;
} qpol_policy_t;
typedef struct sepol_handle qpol_handle_t;
typedef void (*qpol_handle_callback_fn_t) (void* varg, qpol_handle_t* handle, const char* fmt, ...);

#define QPOL_POLICY_KERNEL_SOURCE 0
#define QPOL_POLICY_KERNEL_BINARY 1
#define QPOL_POLICY_MODULE_BINARY 2

/**
 *  Open a policy from a passed in file path.
 *  @param filename The name of the file to open.
 *  @param policy The policy to populate.  The caller should not free
 *  this pointer.
 *  @param handle The policy handle.
 *  @param fn (Optional) If non-NULL, the callback to be used by the handle.
 *  @param varg (Optional) The argument needed by the handle callback.
 *  @return Returns one of QPOL_POLICY_* above on success and < 0 on failure;
 *  if the call fails, errno will be set and *policy will be NULL.
 */
extern int qpol_open_policy_from_file(const char *filename, qpol_policy_t **policy, qpol_handle_t **handle, qpol_handle_callback_fn_t fn, void *varg);

/**
 *  Open a policy from a passed in buffer.
 *  @param policy The policy to populate.  The caller should not free
 *  this pointer.
 *  @param filedata The policy file stored in memory .
 *  @param size The size of filedata
 *  @param handle The handle for the policy
 *  @param fn (Optional) If non-NULL, the callback to be used by the handle.
 *  @param varg (Optional) The argument needed by the handle callback.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *policy will be NULL.
 */
extern int qpol_open_policy_from_memory(qpol_policy_t **policy, const char *filedata, int size,
					qpol_handle_t **handle, qpol_handle_callback_fn_t fn, void *varg);

/**
 *  Close a policy.
 *  @param policy The policy to close.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set.
 */
extern int qpol_close_policy(qpol_policy_t **policy);

/**
 *  Destroy the handle.
 *  @param handle The handle to destroy.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set.
 */
extern int qpol_handle_destroy(qpol_handle_t **handle);

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
 *  @param handle Error handler for the policy database.
 *  @param policy The policy for which to re-evaluate the conditionals.
 *  This policy will be modified by this function.
 *  @return 0 on success and < 0 on failure; if the call fails.
 *  errno will be set. On failure, the policy state may be inconsistent.
 */
extern int qpol_policy_reevaluate_conds(qpol_handle_t *handle, qpol_policy_t *policy);

#endif
