/**
 * @file
 *
 * Public interface for SELinux policies.  This function declares
 * apol_policy_t, a convenience structure that contains all of the
 * other structures use by the setools project.  Almost all setools
 * files will need to #include this header.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#ifndef APOL_POLICY_H
#define APOL_POLICY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy-path.h"
#include <stdarg.h>
#include <qpol/policy.h>

	typedef struct apol_policy apol_policy_t;

	typedef void (*apol_callback_fn_t) (void *varg, apol_policy_t * p, int level, const char *fmt, va_list argp);

/**
 * When creating an apol_policy, load all components except rules
 * (both AV and TE rules).  For modular policies, this affects both
 * the base policy and subsequent modules.
 */
#define APOL_POLICY_OPTION_NO_RULES 1

/**
 * Create a new apol_policy initialized from one or more policy files.
 *
 * @param path Policy path object specifying which policy file or
 * files to load.
 * @param options Bitfield specifying options for the returned policy.
 * Currently the only acceptable option is
 * APOL_POLICY_OPTION_NO_RULES.
 * @param msg_callback Callback to invoke as errors/warnings are
 * generated.  If NULL, then write messages to standard error.
 * @param varg Value to be passed as the first parameter to the
 * callback function.
 *
 * @return A newly allocated policy that may be used for analysis, or
 * NULL upon error.  The caller is responsible for calling
 * apol_policy_destroy() upon the returned value afterwards.
 */
	extern apol_policy_t *apol_policy_create_from_policy_path(const apol_policy_path_t * path, const int options,
								  apol_callback_fn_t msg_callback, void *varg);

/**
 * Open a monolithic policy from disk.
 *
 * @deprecated Use apol_policy_create_from_path() instead.
 */
	extern int apol_policy_open(const char *path, apol_policy_t ** policy, apol_callback_fn_t msg_callback, void *varg)
		__attribute__ ((deprecated));

/**
 * Open a monolithic policy and load all components except rules.
 *
 * @deprecated Use apol_policy_create_from_path() instead.
 */
	extern int apol_policy_open_no_rules(const char *path, apol_policy_t ** policy,
					     apol_callback_fn_t msg_callback, void *varg) __attribute__ ((deprecated));

/**
 * Deallocate all memory associated with a policy, including all
 * auxillary data structures, and then set it to NULL.  Does nothing
 * if the pointer is already NULL.
 *
 * @param policy Policy to destroy, if not already NULL.
 */
	extern void apol_policy_destroy(apol_policy_t ** policy);

/**
 * Given a policy, return the policy type.  This will be one of
 * QPOL_POLICY_KERNEL_SOURCE, QPOL_POLICY_KERNEL_BINARY, or
 * QPOL_POLICY_MODULE_BINARY.  (You will need to #include
 * <qpol/policy.h> to get these definitions.)
 *
 * @param policy Policy to which check.
 *
 * @return The policy type, or < 0 upon error.
 */
	extern int apol_policy_get_policy_type(apol_policy_t * policy);

/**
 * Given a policy, return a pointer to the underlying qpol policy.
 * This is needed, for example, to access details of particulary qpol
 * components.
 *
 * @param policy Policy containing qpol policy.
 *
 * @return Pointer to underlying qpol policy, or NULL on error.  Do
 * not free() this pointer.
 */
	extern qpol_policy_t *apol_policy_get_qpol(apol_policy_t * policy);

/**
 * Given a policy, return 1 if the policy within is MLS, 0 if not.  If
 * it cannot be determined or upon error, return < 0.
 *
 * @param p Policy to which check.
 * @return 1 if policy is MLS, 0 if not, < 0 upon error.
 */
	extern int apol_policy_is_mls(apol_policy_t * p);

/**
 * Given a policy, return 1 if the policy is binary, 0 if not.  If it
 * cannot be determined or upon error, return < 0.
 *
 * @deprecated Instead of checking if a policy is "binary" or not, one
 * typically really wants to know if the policy is capable of showing
 * rules or something else.  See qpol_policy_has_capability().
 *
 * @param p Policy to which check.
 * @return 1 if policy is binary, 0 if not, < 0 upon error.
 */
	extern int apol_policy_is_binary(apol_policy_t * p) __attribute__ ((deprecated));

/**
 * Given a policy, allocate and return a string that describes the
 * policy (policy version, source/binary, mls/non-mls).
 *
 * @param p Policy to check.
 * @return String that describes policy, or NULL upon error.  The
 * caller must free() this afterwards.
 */
	extern char *apol_policy_get_version_type_mls_str(apol_policy_t * p);

#define APOL_MSG_ERR 1
#define APOL_MSG_WARN 2
#define APOL_MSG_INFO 3

/**
 * Write a message to the callback stored within an apol error
 * handler.  If the msg_callback field is empty then suppress the
 * message.
 *
 * @param p Error reporting handler.  If NULL then write message to
 * stderr.
 * @param level Severity of message, one of APOL_MSG_ERR,
 * APOL_MSG_WARN, or APOL_MSG_INFO.
 * @param fmt Format string to print, using syntax of printf(3).
 */
	__attribute__ ((format(printf, 3, 4)))
	extern void apol_handle_msg(apol_policy_t * p, int level, const char *fmt, ...);

/**
 * Invoke a apol_policy_t's callback for an error, passing it a format
 * string and arguments.
 */
#define ERR(p, format, ...) apol_handle_msg(p, APOL_MSG_ERR, format, __VA_ARGS__)

/**
 * Invoke a apol_policy_t's callback for a warning, passing it a
 * format string and arguments.
 */
#define WARN(p, format, ...) apol_handle_msg(p, APOL_MSG_WARN, format, __VA_ARGS__)

/**
 * Invoke a apol_policy_t's callback for an informational messag,
 * passing it a format string and arguments.
 */
#define INFO(p, format, ...) apol_handle_msg(p, APOL_MSG_INFO, format, __VA_ARGS__)

#ifdef	__cplusplus
}
#endif

#endif
