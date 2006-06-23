/**
 * @file policy.c
 *
 * Public interface for SELinux policies.
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

#include "policy.h"
#include <qpol/policy_query.h>
#include <stdio.h>
#include <string.h>

int apol_policy_is_mls(apol_policy_t *p)
{
	if (p == NULL) {
		return -1;
	}
	return qpol_policy_is_mls_enabled(p->qh, p->p);
}

int apol_policy_is_binary(apol_policy_t *p)
{
	return (p->policy_type != QPOL_POLICY_KERNEL_SOURCE);
}

char *apol_policy_get_version_type_mls_str(apol_policy_t *p)
{
	unsigned int version;
	char *policy_type, *mls, buf[64];
	if (qpol_policy_get_policy_version(p->qh, p->p, &version) < 0) {
		return NULL;
	}
	switch (p->policy_type) {
	case QPOL_POLICY_KERNEL_SOURCE:
	    policy_type = "source"; break;
	case QPOL_POLICY_KERNEL_BINARY:
	    policy_type = "binary"; break;
	default:
	    policy_type = "unknown"; break;
	}
	if (qpol_policy_is_mls_enabled(p->qh, p->p)) {
		mls = "mls";
	}
	else {
		mls = "non-mls";
	}
	if (snprintf(buf, sizeof(buf), "v.%u (%s, %s)", version, policy_type, mls) == -1) {
		return NULL;
	}
	return strdup(buf);
}

__attribute__ ((format (printf, 3, 4)))
void apol_handle_route_to_callback(void *varg, apol_policy_t *p,
				   const char *fmt, ...)
{
	va_list ap;
	if (p != NULL && p->msg_callback != NULL) {
		va_start(ap, fmt);
		p->msg_callback(varg, p, fmt, ap);
		va_end(ap);
	}
}
