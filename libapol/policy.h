/**
 * @file policy.h
 *
 * Public interface for SELinux policies.  This function declares
 * apol_policy_t, a convenience structure that contains all of the
 * other structures use by the setools project.  Almost all setools
 * files will need to #include this header.
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

#ifndef APOL_POLICY_H
#define APOL_POLICY_H

#include <stdarg.h>
#include <qpol/policy.h>

/* XXX */typedef struct policy policy_t;

/* forward declaration.  the definition resides within perm-map.c */
struct apol_permmap;

typedef struct apol_policy {
        qpol_policy_t *p;
        qpol_handle_t *qh;
	void (*msg_callback) (void *varg, struct apol_policy *p, const char *fmt, va_list argp);
	void *msg_callback_arg;
	int policy_type;
	struct apol_permmap *pmap; /* permission mapping for this policy */
} apol_policy_t;

/**
 * Given a policy, return 1 if the policy within is MLS, 0 if not.  If
 * it cannot be determined or upon error, return <0.
 *
 * @param p Policy to which check.
 * @return 1 if policy is MLS, 0 if not, < 0 upon error.
 */
extern int apol_policy_is_mls(apol_policy_t *p);

/**
 * Given a qpol policy, return 1 if the policy is binary, 0 if
 * not.  If it cannot be determined or upon error, return <0.
 *
 * @param p Policy to which check.
 * @return 1 if policy is binary, 0 if not, < 0 upon error.
 */
extern int apol_policy_is_binary(apol_policy_t *p);

/**
 * Given a policy, allocate and return a string that describes the
 * policy (policy version, source/binary, mls/non-mls).
 *
 * @param p Policy to check.
 * @return String that describes policy, or NULL upon error.  The
 * caller must free() this afterwards.
 */
extern char *apol_policy_get_version_type_mls_str(apol_policy_t *p);


/**
 * Invoke a apol_policy_t's error callback function, passing it a
 * format string and arguments.
 */
#define ERR(p, ...)  \
	do { \
		if ((p) != NULL && (p)->msg_callback != NULL) { \
			apol_handle_route_to_callback((p)->msg_callback_arg, \
						      (p), __VA_ARGS__); \
		} \
	} while(0);

/**
 * Write a message to the callback stored within an apol error
 * handler.  This function satisfies limitations of C's variable
 * arguments syntax (comp.lang.c FAQ, question 15.12).
 *
 * @param varg Arbitrary callback argument.
 * @param p Error reporting handler.
 * @param fmt Format string to print, using syntax of printf(3).
 */
extern void apol_handle_route_to_callback(void *varg, apol_policy_t *p,
					  const char *fmt, ...);

#endif
