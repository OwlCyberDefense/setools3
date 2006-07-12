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
#include "perm-map.h"

#include <qpol/policy_extend.h>
#include <qpol/policy_query.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

__attribute__ ((format (printf, 3, 4)))
static void qpol_handle_route_to_callback(void *varg, qpol_handle_t *handle,
					  const char *fmt, ...)
{
	apol_policy_t *p = (apol_policy_t *) varg;
	va_list ap;
	va_start(ap, fmt);
	if (p != NULL && p->msg_callback != NULL) {
		p->msg_callback(p->msg_callback_arg, p, fmt, ap);
	}
	va_end(ap);
}

static void apol_handle_default_callback(void *varg __attribute__ ((unused)),
					 apol_policy_t *p __attribute__ ((unused)),
					 const char *fmt, va_list ap)
{
	 vfprintf(stderr, fmt, ap);
	 fprintf(stderr, "\n");
}

int apol_policy_open(const char *path, apol_policy_t **policy)
{
	int policy_type;
	if (!path || !policy) {
		errno = EINVAL;
		return -1;
	}

	if (policy)
		*policy = NULL;

	if (!(*policy = calloc(1, sizeof(apol_policy_t)))) {
		fprintf(stderr, "Out of memory!\n");
		return -1; /* errno set by calloc */
	}
	(*policy)->msg_callback = apol_handle_default_callback;
	(*policy)->msg_callback_arg = (*policy);

        policy_type = qpol_open_policy_from_file(path, &((*policy)->p), &((*policy)->qh), qpol_handle_route_to_callback, (*policy));
        if (policy_type < 0) {
		ERR(*policy, "Unable to open policy at %s.", path);
		apol_policy_destroy(policy);
		return -1; /* qpol sets errno */
        }
        (*policy)->policy_type = policy_type;
	return 0;
}

void apol_policy_destroy(apol_policy_t **policy)
{
	if (policy != NULL && *policy != NULL) {
		qpol_close_policy(&((*policy)->p));
		qpol_handle_destroy(&((*policy)->qh));
		apol_permmap_destroy(&(*policy)->pmap);
		free(*policy);
		*policy = NULL;
	}
}

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
