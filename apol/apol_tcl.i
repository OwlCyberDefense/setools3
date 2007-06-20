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
#include <config.h>

#include <apol/avrule-query.h>
#include <apol/terule-query.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <apol/util.h>
#include <sefs/db.hh>
#include <sefs/filesystem.hh>
%}

/* implement a custom non thread-safe error handler */
%{
/* Note that these must be placed in a different file rather than
 * being inlined directly into this SWIG interface file.  The reason
 * is because they use some GNU functions that are only available when
 * config.h is included prior to stdio.h.  Unfortunately, SWIG will
 * always place its own headers, which includes stdio.h, prior to any
 * inlined headers when generating the wrapped C file.  As a result,
 * those GNU functions would not be available to the inlined
 * functions.
 */
extern void apol_tcl_clear_info_string(void);
extern int apol_tcl_get_info_level(void);
extern char *apol_tcl_get_info_string(void);
extern void apol_tcl_set_info_string(apol_policy_t *p, const char *s);
extern void apol_tcl_route_apol_to_string(void *arg, const apol_policy_t * p, int level, const char *fmt, va_list ap);
extern void apol_tcl_route_sefs_to_string(void *arg, const sefs_fclist * s, int level, const char *fmt, va_list ap);
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

/* Major hackery here to pass in the Tcl interpreter object as
 * apol_policy_create_from_policy_path()'s callback argument.  This is
 * needed so that the callback can properly update apol's progress
 * dialog without deadlocking itself.
 */
%newobject apol_tcl_open_policy;
%typemap (in) (const apol_policy_path_t *ppath, Tcl_Interp *interp) {
  int res = SWIG_ConvertPtr($input, SWIG_as_voidptrptr(&$1), $1_descriptor, 0);
  if (res) {
    SWIG_exception_fail(SWIG_ArgError(res), "in method '" "apol_tcl_open_policy" "', argument " "1"" of type '" "apol_policy_path_t const *""'"); 
  }
  $2 = interp;
};
%inline %{
	/**
	 * Open a policy file, either source or binary, on disk.  Note
	 * that this will not load neverallows; apol must rebuild
	 * neverallows (and call qpol_policy_build_syn_rule_table())
	 * when it needs to.  If the file was opened successfully then
	 * allocate and return an apol_policy_t object.  Otherwise
	 * throw an error and return a string that describes the
	 * error.
	 *
	 * @param ppath apol_policy_path object representing policy to
	 * open.
	 */
	apol_policy_t *apol_tcl_open_policy(const apol_policy_path_t *ppath, Tcl_Interp *interp) {
		apol_policy_t *p = apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_NEVERALLOWS,
								       apol_tcl_route_apol_to_string, interp);
		if (p == NULL) {
			SWIG_exception(SWIG_RuntimeError, "Could not open policy");
		}
	fail:
		return p;
	}

	static int avrule_sort(const void *a, const void *b, void *arg) {
		const qpol_avrule_t *r1 = static_cast<const qpol_avrule_t *>(a);
		const qpol_avrule_t *r2 = static_cast<const qpol_avrule_t *>(b);
		apol_policy_t *p = static_cast<apol_policy_t *>(arg);
		qpol_policy_t *q = apol_policy_get_qpol(p);

		uint32_t rule_type1, rule_type2;
		const char *cs1, *cs2;
		int compval;
		if (qpol_avrule_get_rule_type(q, r1, &rule_type1) < 0 ||
		    qpol_avrule_get_rule_type(q, r2, &rule_type2) < 0) {
			return 0;
		}
		if ((cs1 = apol_rule_type_to_str(rule_type1)) == NULL ||
		    (cs2 = apol_rule_type_to_str(rule_type2)) == NULL) {
			return 0;
		}
		if ((compval = strcmp(cs1, cs2)) != 0) {
			return compval;
		}

		const qpol_type_t *t1, *t2;
		const char *s1, *s2;
		if (qpol_avrule_get_source_type(q, r1, &t1) < 0 ||
		    qpol_avrule_get_source_type(q, r2, &t2) < 0) {
			return 0;
		}
		if (qpol_type_get_name(q, t1, &s1) < 0 ||
		    qpol_type_get_name(q, t2, &s2) < 0) {
			return 0;
		}
		if ((compval = strcmp(s1, s2)) != 0) {
			return compval;
		}

		if (qpol_avrule_get_target_type(q, r1, &t1) < 0 ||
		    qpol_avrule_get_target_type(q, r2, &t2) < 0) {
			return 0;
		}
		if (qpol_type_get_name(q, t1, &s1) < 0 ||
		    qpol_type_get_name(q, t2, &s2) < 0) {
			return 0;
		}
		if ((compval = strcmp(s1, s2)) != 0) {
			return compval;
		}

		const qpol_class_t *c1, *c2;
		if (qpol_avrule_get_object_class(q, r1, &c1) < 0 ||
		    qpol_avrule_get_object_class(q, r2, &c2) < 0) {
			return 0;
		}
		if (qpol_class_get_name(q, c1, &s1) < 0 ||
		    qpol_class_get_name(q, c2, &s2) < 0) {
			return 0;
		}
		return strcmp(s1, s2);
	}

	/**
	 * Sort a vector of qpol_avrule_t, sorting by rule type, then
	 * source type, then target type, and then by object class.
	 */
	void apol_tcl_avrule_sort(apol_policy_t *policy, apol_vector_t *v) {
		if (policy != NULL && v != NULL) {
			apol_vector_sort(v, avrule_sort, policy);
		}
	}

	static int terule_sort(const void *a, const void *b, void *arg) {
		const qpol_terule_t *r1 = static_cast<const qpol_terule_t *>(a);
		const qpol_terule_t *r2 = static_cast<const qpol_terule_t *>(b);
		apol_policy_t *p = static_cast<apol_policy_t *>(arg);
		qpol_policy_t *q = apol_policy_get_qpol(p);

		uint32_t rule_type1, rule_type2;
		const char *cs1, *cs2;
		int compval;
		if (qpol_terule_get_rule_type(q, r1, &rule_type1) < 0 ||
		    qpol_terule_get_rule_type(q, r2, &rule_type2) < 0) {
			return 0;
		}
		if ((cs1 = apol_rule_type_to_str(rule_type1)) == NULL ||
		    (cs2 = apol_rule_type_to_str(rule_type2)) == NULL) {
			return 0;
		}
		if ((compval = strcmp(cs1, cs2)) != 0) {
			return compval;
		}

		const qpol_type_t *t1, *t2;
		const char *s1, *s2;
		if (qpol_terule_get_source_type(q, r1, &t1) < 0 ||
		    qpol_terule_get_source_type(q, r2, &t2) < 0) {
			return 0;
		}
		if (qpol_type_get_name(q, t1, &s1) < 0 ||
		    qpol_type_get_name(q, t2, &s2) < 0) {
			return 0;
		}
		if ((compval = strcmp(s1, s2)) != 0) {
			return compval;
		}

		if (qpol_terule_get_target_type(q, r1, &t1) < 0 ||
		    qpol_terule_get_target_type(q, r2, &t2) < 0) {
			return 0;
		}
		if (qpol_type_get_name(q, t1, &s1) < 0 ||
		    qpol_type_get_name(q, t2, &s2) < 0) {
			return 0;
		}
		if ((compval = strcmp(s1, s2)) != 0) {
			return compval;
		}

		const qpol_class_t *c1, *c2;
		if (qpol_terule_get_object_class(q, r1, &c1) < 0 ||
		    qpol_terule_get_object_class(q, r2, &c2) < 0) {
			return 0;
		}
		if (qpol_class_get_name(q, c1, &s1) < 0 ||
		    qpol_class_get_name(q, c2, &s2) < 0) {
			return 0;
		}
		return strcmp(s1, s2);
	}

	/**
	 * Sort a vector of qpol_terule_t, sorting by rule type, then
	 * source type, then target type, and then by object class.
	 */
	void apol_tcl_terule_sort(apol_policy_t *policy, apol_vector_t *v) {
		if (policy != NULL && v != NULL) {
			apol_vector_sort(v, terule_sort, policy);
		}
	}

	/**
	 * Returns the policy version number for the currently opened
	 * policy.  If the policy is modular, return the maximum
	 * allowed policy as per libsepol.
	 */
	unsigned int apol_tcl_get_policy_version(apol_policy_t *policy) {
		if (policy == NULL) {
			SWIG_exception(SWIG_RuntimeError, "No policy opened");
		}
		if (apol_policy_get_policy_type(policy) != QPOL_POLICY_MODULE_BINARY) {
			unsigned int version;
			if (qpol_policy_get_policy_version(apol_policy_get_qpol(policy), &version) < 0) {
				SWIG_exception(SWIG_RuntimeError, "Could not get policy version");
			}
			return version;
		} else {
			return (unsigned int) SEPOL_POLICY_VERSION_MAX;
		}
	fail:
		return 0;
	}
%}

%rename(apol_tcl_rule_render) apol_avrule_render;
extern char *apol_avrule_render(apol_policy_t *policy, qpol_avrule_t *rule);
%rename(apol_tcl_rule_render) apol_terule_render;
extern char *apol_terule_render(apol_policy_t *policy, qpol_terule_t *rule);
%rename(apol_tcl_rule_render) apol_syn_avrule_render;
extern char *apol_syn_avrule_render(apol_policy_t *policy, qpol_syn_avrule_t *rule);
%rename(apol_tcl_rule_render) apol_syn_terule_render;
extern char *apol_syn_terule_render(apol_policy_t *policy, qpol_syn_terule_t *rule);

void apol_tcl_avrule_sort(apol_policy_t *policy, apol_vector_t *v);
void apol_tcl_terule_sort(apol_policy_t *policy, apol_vector_t *v);
unsigned int apol_tcl_get_policy_version(apol_policy_t *policy);

%{
	/**
	 * Open a sefs database from file.
	 *
	 * @param filename Database's filename.
	 */
	sefs_db *apol_tcl_open_database(const char * filename, Tcl_Interp * interp)
	{
		try {
			return new sefs_db(filename, apol_tcl_route_sefs_to_string, interp);
		}
		catch (...) {
			return NULL;
		}
	}

	/**
	 * Construct an in-memory database from part of a filesystem.
	 *
	 * @param filename Starting root directory.
	 */
	sefs_db *apol_tcl_open_database_from_dir(const char * filename, Tcl_Interp * interp)
	{
		sefs_filesystem *fs = NULL;
		sefs_db *db = NULL;
		try {
			fs = new sefs_filesystem(filename, apol_tcl_route_sefs_to_string, interp);
			db = new sefs_db(fs, apol_tcl_route_sefs_to_string, interp);
		}
		catch (...) {
			delete fs;
			delete db;
			return NULL;
		}
		delete fs;
		return db;
	}
%}
/* Major hackery here to pass in the Tcl interpreter object as
 * sefs_db's callback argument.  This is needed so that the callback
 * can properly update apol's progress dialog without deadlocking
 * itself.
 */
%typemap (in) (const char * filename, Tcl_Interp *interp) {
  $1 = Tcl_GetString($input);
  $2 = interp;
};
sefs_db *apol_tcl_open_database(const char * filename, Tcl_Interp * interp);
sefs_db *apol_tcl_open_database_from_dir(const char * filename, Tcl_Interp * interp);
%newobject apol_tcl_open_database;
%newobject apol_tcl_open_database_from_dir;

// disable the exception handler, otherwise it will delete the error
// message when this function gets called
%exception;
extern void apol_tcl_clear_info_string(void);
extern int apol_tcl_get_info_level(void);
extern char *apol_tcl_get_info_string(void);
extern void apol_tcl_set_info_string(apol_policy_t *p, const char *s);
