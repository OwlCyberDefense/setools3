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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tcl.h>

#include <apol/policy.h>

/** severity of most recent message */
static int msg_level = INT_MAX;

/** pointer to most recent message string */
static char *message = NULL;

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

static void apol_tcl_clear_error(void)
{
	free(message);
	message = NULL;
	msg_level = INT_MAX;
}

static void apol_tcl_write_error(Tcl_Interp * interp)
{
	if (message != NULL) {
		Tcl_Obj *obj = Tcl_NewStringObj(message, -1);
		Tcl_ResetResult(interp);
		Tcl_SetObjResult(interp, obj);
		apol_tcl_clear_error();
	}
}

static int hi(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[]) {
    Tcl_SetResult(interp, "Hello, world!", TCL_STATIC);
    return TCL_OK;
}


/* Package initialization */
int Apol_tcl_Init(Tcl_Interp * interp)
{
	Tcl_CreateCommand(interp, "apol_tcl_hi", hi, NULL, NULL);
	Tcl_PkgProvide(interp, "apol_tcl", LIBAPOL_VERSION_STRING);

	return TCL_OK;
}
