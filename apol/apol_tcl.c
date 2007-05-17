/**
 * @file
 *
 * Support routines for the apol program that are faster/easier when
 * written in C than in Tcl.
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

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tcl.h>

#include <apol/policy.h>

/** severity of most recent message */
int msg_level = INT_MAX;

/** pointer to most recent message string */
char *message = NULL;

/**
 * Take the formated string, allocate space for it, and then write it
 * the policy's msg_callback_arg.  If there is already a string
 * stored, then append to the string if the message level is equal to
 * the previous one, overwrite the string if message level is less
 * than previous, else ignore the message.
 */
static void apol_tcl_route_handle_to_string(void *varg
					    __attribute__ ((unused)), apol_policy_t * p
					    __attribute__ ((unused)), int level, const char *fmt, va_list ap)
{
	char *s, *t;
	if (level == APOL_MSG_INFO && msg_level >= APOL_MSG_INFO) {
		/* generate an info event */
		free(message);
		message = NULL;
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(errno));
			return;
		}
		message = s;
		msg_level = level;
		Tcl_DoOneEvent(TCL_IDLE_EVENTS | TCL_DONT_WAIT);
	} else if (message == NULL || level < msg_level) {
		/* overwrite the existing stored message string with a
		 * new, higher priority message */
		free(message);
		message = NULL;
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(errno));
			return;
		}
		message = s;
		msg_level = level;
	} else if (level == msg_level) {
		/* append to existing error message */
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(errno));
			return;
		}
		if (asprintf(&t, "%s\n%s", message, s) < 0) {
			free(s);
			fprintf(stderr, "%s\n", strerror(errno));
			return;
		}
		free(s);
		free(message);
		message = t;
	}
}

void apol_tcl_clear_info_string(void)
{
	if (message != NULL) {
		free(message);
		message = NULL;
	}
	msg_level = INT_MAX;
}

int apol_tcl_get_info_level(void)
{
	return msg_level;
}

char *apol_tcl_get_info_string(void)
{
	return message;
}

/**
 * Open a policy file, either source or binary, on disk.  Note that
 * this will not load neverallows; apol must rebuild neverallows (and
 * qpol_policy_build_syn_rule_table) when it needs to.  If the file
 * was opened successfully then allocate and return an apol_policy_t
 * object.  Otherwise throw an error and return a string that
 * describes the error.
 *
 * @param argv This function takes one parameter, an apol_policy_path
 * object.
 */
apol_policy_t *apol_tcl_open_policy(const apol_policy_path_t *ppath)
{
	return apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_NEVERALLOWS, apol_tcl_route_handle_to_string, NULL);
}
