//typedef struct ap_constraint_expr {
//	#define AP_CEXPR_NOT		1	/* not expr */
//	#define AP_CEXPR_AND		2	/* expr and expr */
//	#define AP_CEXPR_OR			3	/* expr or expr */
//	#define AP_CEXPR_ATTR		4	/* attr op attr */
//	#define AP_CEXPR_NAMES		5	/* attr op names */
//	unsigned int expr_type;			/* expression type */
//
//	#define AP_CEXPR_USER			1	/* user */
//	#define AP_CEXPR_ROLE			2	/* role */
//	#define AP_CEXPR_TYPE			4	/* type */
//	#define AP_CEXPR_TARGET			8	/* target if set, source otherwise */
//	#define AP_CEXPR_XTARGET		16	/* special 3rd target for validatetrans rule */
//	#define AP_CEXPR_MLS_LOW1_LOW2	32	/* low level 1 vs. low level 2 */
//	#define AP_CEXPR_MLS_LOW1_HIGH2	64	/* low level 1 vs. high level 2 */
//	#define AP_CEXPR_MLS_HIGH1_LOW2	128	/* high level 1 vs. low level 2 */
//	#define AP_CEXPR_MLS_HIGH1_HIGH2 256	/* high level 1 vs. high level 2 */
//	#define AP_CEXPR_MLS_LOW1_HIGH1	512	/* low level 1 vs. high level 1 */
//	#define AP_CEXPR_MLS_LOW2_HIGH2	1024	/* low level 2 vs. high level 2 */
//	unsigned int attr;			/* attribute */
//
//	#define AP_CEXPR_EQ			1	/* == or eq */
//	#define AP_CEXPR_NEQ		2	/* != */
//	#define AP_CEXPR_DOM		3	/* dom */
//	#define AP_CEXPR_DOMBY		4	/* domby  */
//	#define AP_CEXPR_INCOMP		5	/* incomp */
//	unsigned int op;				/* operator */
//
//	ta_item_t *names;			/* this will index int apol structs so we can just figure out what it is at lookup time */
//	#define AP_CEXPR_STAR		0x01
//	#define AP_CEXPR_TILDA		0x02
//	unsigned char name_flags;			/* flags for handling "*" and "~" in names list */
//	struct ap_constraint_expr *next;
//} ap_constraint_expr_t;

/* the ap_constraint_t structure is used for both constraints
 * and validatetrans statements */
//typedef struct ap_constraint {
//	bool_t is_mls;
//	ap_constraint_expr_t *expr;
//	ta_item_t *perms;	/* index into policy_t array (not used for validatetrans) */
//	ta_item_t *classes;	/* index into policy_t array */
//	unsigned long lineno;	/* for use in apol and sediff */
//} ap_constraint_t;

/* typedef for clarity */
//typedef struct ap_constraint ap_validatetrans_t;


/******************** new stuff here ********************/

/**
 * @file policy.h
 *
 * Public interface for SELinux policies.  (FIX ME!)
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
#include "util.h"

/* XXX */typedef struct policy policy_t;

typedef struct apol_policy {
        qpol_policy_t *p;
        qpol_handle_t *qh;
	void (*msg_callback) (void *varg, struct apol_policy *p, const char *fmt, va_list argp);
	void *msg_callback_arg;
	int policy_type;
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
extern char *apol_get_policy_version_type_mls_str(apol_policy_t *p);


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
