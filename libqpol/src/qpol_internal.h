/**
 *  @file qpol_internal.h
 *  Defines common debug symbols and the internal policy structure.
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

#ifndef QPOL_INTERNAL_H
#define QPOL_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <sepol/handle.h>
#include <qpol/policy.h>

#define STATUS_SUCCESS  0
#define STATUS_ERR     -1
#define STATUS_NODATA   1

#define QPOL_MSG_ERR  1
#define QPOL_MSG_WARN 2
#define QPOL_MSG_INFO 3

/* forward declaration, full declaration in policy_extend.c */
	struct qpol_extended_image;

	struct qpol_policy
	{
		struct sepol_policydb *p;
		struct sepol_handle *sh;
		qpol_callback_fn_t fn;
		void *varg;
		int rules_loaded;
		struct qpol_extended_image *ext;
	};

	extern void qpol_handle_msg(qpol_policy_t * policy, int level, const char *fmt, ...);

#define ERR(policy, format, ...) qpol_handle_msg(policy, QPOL_MSG_ERR, format, __VA_ARGS__)
#define WARN(policy, format, ...) qpol_handle_msg(policy, QPOL_MSG_WARN, format, __VA_ARGS__)
#define INFO(policy, format, ...) qpol_handle_msg(policy, QPOL_MSG_INFO, format, __VA_ARGS__)

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_INTERNAL_H */
