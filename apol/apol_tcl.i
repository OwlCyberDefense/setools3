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

%module apol_tcl
%import apol.i
%import qpol.i

%{
#include <apol/avrule-query.h>
#include <apol/terule-query.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
%}

/* implement a custom non thread-safe error handler */
%{
extern void apol_tcl_clear_info_string(void);
extern int apol_tcl_get_info_level(void);
extern char *apol_tcl_get_info_string(void);
extern apol_policy_t *apol_tcl_open_policy(const apol_policy_path_t *ppath);
extern int msg_level;
extern char *message;
static void tcl_clear_error(void)
{
	apol_tcl_clear_info_string();
}
static void tcl_throw_error(const char *s)
{
	free(message);
	message = strdup(s);
}
static char *tcl_get_error(void)
{
	if (msg_level != APOL_MSG_ERR) {
		return NULL;
	}
	return apol_tcl_get_info_string();
}
#undef SWIG_exception
#define SWIG_exception(code, msg) {tcl_throw_error(msg); goto fail;}
%}

%newobject wrap_apol_tcl_open_policy;
%rename(apol_tcl_open_policy) wrap_apol_tcl_open_policy;
%inline %{
	apol_policy_t *wrap_apol_tcl_open_policy(const apol_policy_path_t *ppath) {
		apol_policy_t *p = apol_tcl_open_policy(ppath);
		if (p == NULL) {
			SWIG_exception(SWIG_RuntimeError, "Could not open policy");
		}
	fail:
		return p;
	};
%}

%rename(apol_rule_render) apol_avrule_render;
extern char *apol_avrule_render(apol_policy_t *policy, qpol_avrule_t *rule);
%rename(apol_rule_render) apol_terule_render;
extern char *apol_terule_render(apol_policy_t *policy, qpol_terule_t *rule);
%rename(apol_rule_render) apol_syn_avrule_render;
extern char *apol_syn_avrule_render(apol_policy_t *policy, qpol_syn_avrule_t *rule);
%rename(apol_rule_render) apol_syn_terule_render;
extern char *apol_syn_terule_render(apol_policy_t *policy, qpol_syn_terule_t *rule);

// disable the exception handler, otherwise it will delete the error
// message when this function gets called
%exception;
extern void apol_tcl_clear_info_string(void);
extern int apol_tcl_get_info_level(void);
extern char *apol_tcl_get_info_string(void);
