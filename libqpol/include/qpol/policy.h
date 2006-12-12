/**
 *  @file
 *  Defines the public interface the QPol policy.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stdarg.h>
#include <stdint.h>

	typedef struct qpol_policy qpol_policy_t;

#include <qpol/avrule_query.h>
#include <qpol/bool_query.h>
#include <qpol/class_perm_query.h>
#include <qpol/cond_query.h>
#include <qpol/constraint_query.h>
#include <qpol/context_query.h>
#include <qpol/fs_use_query.h>
#include <qpol/isid_query.h>
#include <qpol/iterator.h>
#include <qpol/genfscon_query.h>
#include <qpol/mls_query.h>
#include <qpol/mlsrule_query.h>
#include <qpol/module.h>
#include <qpol/netifcon_query.h>
#include <qpol/nodecon_query.h>
#include <qpol/portcon_query.h>
#include <qpol/rbacrule_query.h>
#include <qpol/role_query.h>
#include <qpol/syn_rule_query.h>
#include <qpol/terule_query.h>
#include <qpol/type_query.h>
#include <qpol/user_query.h>

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

	typedef void (*qpol_callback_fn_t) (void *varg, struct qpol_policy * policy, int level, const char *fmt, va_list va_args);

#define QPOL_POLICY_UNKNOWN       -1
#define QPOL_POLICY_KERNEL_SOURCE  0
#define QPOL_POLICY_KERNEL_BINARY  1
#define QPOL_POLICY_MODULE_BINARY  2

/**
 *  List of capabilities a policy may have. This list represents
 *  features of policy that may differ from version to version or
 *  based upon the format of the policy file.
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
 *  Open a policy from a passed in file path.
 *  @param filename The name of the file to open.
 *  @param policy The policy to populate.  The caller should not free
 *  this pointer.
 *  @param fn (Optional) If non-NULL, the callback to be used by the handle.
 *  @param varg (Optional) The argument needed by the handle callback.
 *  @return Returns one of QPOL_POLICY_KERNEL_SOURCE,
 *  QPOL_POLICY_KERNEL_BINARY, or QPOL_POLICY_MODULE_BINARY on success
 *  and < 0 on failure; if the call fails, errno will be set and
 *  *policy will be NULL.
 */
	extern int qpol_open_policy_from_file(const char *filename, qpol_policy_t ** policy, qpol_callback_fn_t fn, void *varg);

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
	extern int qpol_open_policy_from_file_no_rules(const char *filename, qpol_policy_t ** policy, qpol_callback_fn_t fn,
						       void *varg);

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
	extern int qpol_open_policy_from_memory(qpol_policy_t ** policy, const char *filedata, size_t size, qpol_callback_fn_t fn,
						void *varg);

/**
 *  Close a policy and deallocate its memory.  Does nothing if it is
 *  already NULL.
 *  @param policy Reference to the policy to close.  The pointer will
 *  be set to NULL afterwards.
 */
	extern void qpol_policy_destroy(qpol_policy_t ** policy);

/**
 *  Find the default policy file given a policy type.
 *  @param search_opt Search options bitmask, defined in this file
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
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent.
 */
	extern int qpol_policy_reevaluate_conds(qpol_policy_t * policy);


/**
 *  Append a module to a policy. The policy now owns the module.
 *  Note that the caller must still invoke qpol_policy_rebuild()
 *  to update the policy.
 *  @param policy The policy to which to add the module.
 *  @param module The module to append. <b>The caller should not
 *  destroy this module if this function succeeds.</b>
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and both the policy and the module will
 *  remain unchanged. If the call fails, the caller is still
 *  responsible for calling qpol_module_destroy().
 */
	extern int qpol_policy_append_module(qpol_policy_t * policy, qpol_module_t * module);

/**
 *  Rebuild the policy. Re-link all enabled modules with the base
 *  and then call expand. <b>This function should be called after
 *  appending new modules or changing which modules are enabled.</b>
 *  @param policy The policy to rebuild <b>(Must be a modular policy).</b>
 *  This policy will be altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and the policy will be reverted to its previous state.
 */
	extern int qpol_policy_rebuild(qpol_policy_t * policy);

/**
 *  Get an iterator of all modules in a policy.
 *  @param policy The policy from which to get the iterator.
 *  @param iter Iteraror of modules (of type qpol_module_t) returned.
 *  The caller should not destroy the modules returned by
 *  qpol_iterator_get_item().
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_module_iter(qpol_policy_t * policy, qpol_iterator_t ** iter);

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

#endif
