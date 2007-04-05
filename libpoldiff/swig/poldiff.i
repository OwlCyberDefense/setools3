/**
 * @file
 * SWIG declarations for libpoldiff.
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

%module poldiff

#define __attribute__(x)

%{
#include "../include/poldiff/attrib_diff.h"
#include "../include/poldiff/avrule_diff.h"
#include "../include/poldiff/bool_diff.h"
#include "../include/poldiff/cat_diff.h"
#include "../include/poldiff/class_diff.h"
#include "../include/poldiff/level_diff.h"
#include "../include/poldiff/poldiff.h"
#include "../include/poldiff/range_diff.h"
#include "../include/poldiff/range_trans_diff.h"
#include "../include/poldiff/rbac_diff.h"
#include "../include/poldiff/role_diff.h"
#include "../include/poldiff/terule_diff.h"
#include "../include/poldiff/type_diff.h"
#include "../include/poldiff/type_map.h"
#include "../include/poldiff/user_diff.h"
#include "../include/poldiff/util.h"
%}

#ifdef SWIGJAVA
%javaconst(1);
%{extern JNIEnv*jenv;%}
#endif

%include exception.i

#ifdef SWIGJAVA
/* remove $null not valid outside of type map */
#undef SWIG_exception
#define SWIG_exception(code, msg) SWIG_JavaException(jenv, code, msg)
#endif

/* sized integer handling -
 * NOTE cannot include stdint.h here as seig does not parse it right
 * also some integer types are treated identically in many target languages */
%typedef unsigned int uint32_t;
%typedef unsigned long size_t;

%typedef struct apol_policy apol_policy_t;
%{typedef struct apol_vector apol_string_vector_t;%} /* see apol.i */

const char *libpoldiff_get_version (void);

/* diff element flags */
#define POLDIFF_DIFF_CLASSES     0x00000001
#define POLDIFF_DIFF_COMMONS     0x00000002
#define POLDIFF_DIFF_TYPES       0x00000004
#define POLDIFF_DIFF_ATTRIBS     0x00000008
#define POLDIFF_DIFF_ROLES       0x00000010
#define POLDIFF_DIFF_USERS       0x00000020
#define POLDIFF_DIFF_BOOLS       0x00000040
#define POLDIFF_DIFF_LEVELS      0x00000080
#define POLDIFF_DIFF_CATS        0x00000100
#define POLDIFF_DIFF_AVRULES     0x00000200
#define POLDIFF_DIFF_TERULES     0x00000400
#define POLDIFF_DIFF_ROLE_ALLOWS 0x00000800
#define POLDIFF_DIFF_ROLE_TRANS  0x00001000
#define POLDIFF_DIFF_RANGE_TRANS 0x00002000
#define POLDIFF_DIFF_SYMBOLS     (POLDIFF_DIFF_CLASSES|POLDIFF_DIFF_COMMONS|POLDIFF_DIFF_TYPES|POLDIFF_DIFF_ATTRIBS|POLDIFF_DIFF_ROLES|POLDIFF_DIFF_USERS|POLDIFF_DIFF_BOOLS)
#define POLDIFF_DIFF_RULES       (POLDIFF_DIFF_AVRULES|POLDIFF_DIFF_TERULES|POLDIFF_DIFF_ROLE_ALLOWS|POLDIFF_DIFF_ROLE_TRANS)
#define POLDIFF_DIFF_RBAC        (POLDIFF_DIFF_ROLES|POLDIFF_DIFF_ROLE_ALLOWS|POLDIFF_DIFF_ROLE_TRANS)
#define POLDIFF_DIFF_MLS         (POLDIFF_DIFF_LEVELS|POLDIFF_DIFF_CATS|POLDIFF_DIFF_RANGE_TRANS)
/* NOTE: while defined OCONS are not currently supported */
#define POLDIFF_DIFF_OCONS       0
#define POLDIFF_DIFF_REMAPPED    (POLDIFF_DIFF_TYPES|POLDIFF_DIFF_ATTRIBS|POLDIFF_DIFF_AVRULES|POLDIFF_DIFF_TERULES|POLDIFF_DIFF_ROLES|POLDIFF_DIFF_ROLE_TRANS|POLDIFF_DIFF_RANGE_TRANS|POLDIFF_DIFF_OCONS)
#define POLDIFF_DIFF_ALL         (POLDIFF_DIFF_SYMBOLS|POLDIFF_DIFF_RULES|POLDIFF_DIFF_MLS|POLDIFF_DIFF_OCONS)

%typemap(check) uint32_t flags {
	if ($1 & ~(POLDIFF_DIFF_ALL)) {
		SWIG_exception(SWIG_ValueError, "Invalid diff flag specified");
	}
}

/* poldiff form */
typedef enum poldiff_form
{
	POLDIFF_FORM_NONE,
	POLDIFF_FORM_ADDED,
	POLDIFF_FORM_REMOVED,
	POLDIFF_FORM_MODIFIED,
	POLDIFF_FORM_ADD_TYPE,
	POLDIFF_FORM_REMOVE_TYPE
} poldiff_form_e;

/* for handling the get_stats function */
%{
	typedef struct poldiff_stats {
		size_t stats[5];
	} poldiff_stats_t;
	poldiff_stats_t *poldiff_stats_create() {
		return calloc(1, sizeof(poldiff_stats_t));
	}
	void poldiff_stats_destroy(poldiff_stats_t **x) {
		if (!x || !(*x))
			return;
		free(*x);
		*x = NULL;
	}
%}
typedef struct poldiff_stats {} poldiff_stats_t;
%extend poldiff_stats_t {
	poldiff_stats_t() {
		poldiff_stats_t *s;
		s = poldiff_stats_create();
		if (!s) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return s;
	};
	~poldiff_stats_t() {
		poldiff_stats_destroy(&self);
	};
	size_t get_stat(poldiff_form_e form) {
		switch(form) {
			case POLDIFF_FORM_ADDED:
			{
				return self->stats[0];
			}
			case POLDIFF_FORM_REMOVED:
			{
				return self->stats[1];
			}
			case POLDIFF_FORM_MODIFIED:
			{
				return self->stats[2];
			}
			case POLDIFF_FORM_ADD_TYPE:
			{
				return self->stats[3];
			}
			case POLDIFF_FORM_REMOVE_TYPE:
			{
				return self->stats[4];
			}
			case POLDIFF_FORM_NONE:
			default:
			{
				SWIG_exception(SWIG_ValueError, "Invalid poldiff form");
			}
		}
	fail:
		return 0;
	};
};

/* for handling vector of line numbers stored as unsigned long but returned as void* */
%{
	unsigned long to_ulong(void *x) {
		return (unsigned long)x;
	}
%}
unsigned long to_ulong(void *x);

/* poldiff object */
#ifdef SWIGPYTHON
%typemap(in) apol_policy_t *op {
	void *x = NULL;
	Py_IncRef($input);
	SWIG_ConvertPtr($input, &x,SWIGTYPE_p_apol_policy, 0 |  0 );
	$1 = (apol_policy_t*)x;
}
%typemap(in) apol_policy_t *mp {
	void *x = NULL;
	Py_IncRef($input);
	SWIG_ConvertPtr($input, &x,SWIGTYPE_p_apol_policy, 0 |  0 );
	$1 = (apol_policy_t*)x;
}
#endif
typedef struct poldiff {} poldiff_t;
%extend poldiff_t {
	poldiff_t(apol_policy_t *op, apol_policy_t *mp) {
		poldiff_t *p;
		/* TODO handle callback rather than force default */
		p = poldiff_create(op, mp, NULL, NULL);
		if (!p) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		return p;
	fail:
		return NULL;
	};
	~poldiff_t() {
		poldiff_destroy(&self);
	};
	void run(uint32_t flags) {
		if (poldiff_run(self, flags)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run diff");
		}
	fail:
		return;
	};
	int is_run(uint32_t flags) {
		return poldiff_is_run(self, flags);
	};
	%newobject get_stats();
	poldiff_stats_t *get_stats(uint32_t flags) {
		poldiff_stats_t *s = poldiff_stats_create();
		if (!s) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		if (poldiff_get_stats(self, flags, s->stats)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get stats");
		}
		return s;
	fail:
		poldiff_stats_destroy(&s);
		return NULL;
	};
	void enable_line_numbers() {
		if (poldiff_enable_line_numbers(self)) {
			SWIG_exception(SWIG_RuntimeError, "Could not enable line numbers");
		}
	fail:
		return;
	};
	const apol_vector_t *get_attrib_vector() {
		return poldiff_get_attrib_vector(self);
	};
	const apol_vector_t *get_avrule_vector() {
		return poldiff_get_avrule_vector(self);
	};
	const apol_vector_t *get_bool_vector() {
		return poldiff_get_bool_vector(self);
	};
	const apol_vector_t *get_cat_vector() {
		return poldiff_get_cat_vector(self);
	};
	const apol_vector_t *get_class_vector() {
		return poldiff_get_class_vector(self);
	};
	const apol_vector_t *get_common_vector() {
		return poldiff_get_common_vector(self);
	};
	const apol_vector_t *get_level_vector() {
		return poldiff_get_level_vector(self);
	};
	const apol_vector_t *get_range_trans_vector() {
		return poldiff_get_range_trans_vector(self);
	};
	const apol_vector_t *get_role_allow_vector() {
		return poldiff_get_role_allow_vector(self);
	};
	const apol_vector_t *get_role_trans_vector() {
		return poldiff_get_role_trans_vector(self);
	};
	const apol_vector_t *get_role_vector() {
		return poldiff_get_role_vector(self);
	};
	const apol_vector_t *get_terule_vector() {
		return poldiff_get_terule_vector(self);
	};
	const apol_vector_t *get_type_vector() {
		return poldiff_get_type_vector(self);
	};
	const apol_vector_t *get_user_vector() {
		return poldiff_get_user_vector(self);
	};
	const apol_vector_t *get_type_remap_entries() {
		return poldiff_type_remap_get_entries(self);
	};
	void type_remap_create(apol_string_vector_t *orig_types, apol_string_vector_t *mod_types) {
		if (poldiff_type_remap_create(self, (apol_vector_t*)orig_types, (apol_vector_t*)mod_types)) {
			SWIG_exception(SWIG_RuntimeError, "Could not remap types");
		}
	fail:
		return;
	};
	void type_remap_remove(poldiff_type_remap_entry_t *ent) {
		poldiff_type_remap_entry_remove(self, ent);
	};
};

/* attribute diff */
typedef struct poldiff_attrib {} poldiff_attrib_t;
%extend poldiff_attrib_t {
	poldiff_attrib_t(void *x) {
		return (poldiff_attrib_t*)x;
	};
	~poldiff_attrib_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_attrib_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_attrib_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_attrib_get_form(self);
	};
	const apol_string_vector_t *get_added_types() {
		return (apol_string_vector_t*)poldiff_attrib_get_added_types(self);
	};
	const apol_string_vector_t *get_removed_types() {
		return (apol_string_vector_t*)poldiff_attrib_get_removed_types(self);
	};
};

/* av rule diff */
typedef struct poldiff_avrule {} poldiff_avrule_t;
%extend poldiff_avrule_t {
	poldiff_avrule_t(void *x) {
		return (poldiff_avrule_t*)x;
	};
	~poldiff_avrule_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_avrule_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	poldiff_form_e get_form() {
		return poldiff_avrule_get_form(self);
	};
	uint32_t get_rule_type() {
		return poldiff_avrule_get_rule_type(self);
	};
	const char *get_source_type() {
		return poldiff_avrule_get_source_type(self);
	};
	const char *get_target_type() {
		return poldiff_avrule_get_target_type(self);
	};
	const char *get_object_class() {
		return poldiff_avrule_get_object_class(self);
	};
	const qpol_cond_t *get_cond(poldiff_t *p) {
		qpol_cond_t *cond;
		uint32_t which_list;
		apol_policy_t *which_pol;
		poldiff_avrule_get_cond(p, self, &cond, &which_list, &which_pol);
		return cond;
	};
	uint32_t get_cond_list(poldiff_t *p) {
		qpol_cond_t *cond;
		uint32_t which_list;
		apol_policy_t *which_pol;
		poldiff_avrule_get_cond(p, self, &cond, &which_list, &which_pol);
		return which_list;
	};
	const apol_policy_t *get_cond_policy(poldiff_t *p) {
		qpol_cond_t *cond;
		uint32_t which_list;
		apol_policy_t *which_pol;
		poldiff_avrule_get_cond(p, self, &cond, &which_list, &which_pol);
		return which_pol;
	};
	const apol_string_vector_t *get_unmodified_perms() {
		return poldiff_avrule_get_unmodified_perms(self);
	};
	const apol_string_vector_t *get_added_perms() {
		return poldiff_avrule_get_added_perms(self);
	};
	const apol_string_vector_t *get_removed_perms() {
		return poldiff_avrule_get_removed_perms(self);
	};
	const apol_vector_t *get_orig_line_numbers() {
		return poldiff_avrule_get_orig_line_numbers(self);
	};
	%newobject get_orig_line_numbers_for_perm();
	apol_vector_t *get_orig_line_numbers_for_perm(poldiff_t *p, char *perm) {
		apol_vector_t *v;
		v = poldiff_avrule_get_orig_line_numbers_for_perm(p, self, perm);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return v;
	};
	const apol_vector_t *get_mod_line_numbers() {
		return poldiff_avrule_get_mod_line_numbers(self);
	};
	%newobject get_mod_line_numbers_for_perm();
	apol_vector_t *get_mod_line_numbers_for_perm(poldiff_t *p, char *perm) {
		apol_vector_t *v;
		v = poldiff_avrule_get_mod_line_numbers_for_perm(p, self, perm);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return v;
	};
};

/* boolean diff */
typedef struct poldiff_bool {} poldiff_bool_t;
%extend poldiff_bool_t {
	poldiff_bool_t(void *x) {
		return (poldiff_bool_t*)x;
	};
	~poldiff_bool_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_bool_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_bool_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_bool_get_form(self);
	};
};

/* category diff */
typedef struct poldiff_cat {} poldiff_cat_t;
%extend poldiff_cat_t {
	poldiff_cat_t(void *x) {
		return (poldiff_cat_t*)x;
	};
	~poldiff_cat_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_cat_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_cat_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_cat_get_form(self);
	};
};

/* class diff */
typedef struct poldiff_class {} poldiff_class_t;
%extend poldiff_class_t {
	poldiff_class_t(void *x) {
		return (poldiff_class_t*)x;
	};
	~poldiff_class_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_class_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_class_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_class_get_form(self);
	};
	const apol_string_vector_t *get_added_perms() {
		return (apol_string_vector_t*)poldiff_class_get_added_perms(self);
	};
	const apol_string_vector_t *get_removed_perms() {
		return (apol_string_vector_t*)poldiff_class_get_removed_perms(self);
	};
};

/* common diff */
typedef struct poldiff_common {} poldiff_common_t;
%extend poldiff_common_t {
	poldiff_common_t(void *x) {
		return (poldiff_common_t*)x;
	};
	~poldiff_common_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_common_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_common_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_common_get_form(self);
	};
	const apol_string_vector_t *get_added_perms() {
		return (apol_string_vector_t*)poldiff_common_get_added_perms(self);
	};
	const apol_string_vector_t *get_removed_perms() {
		return (apol_string_vector_t*)poldiff_common_get_removed_perms(self);
	};
};

/* level diff */
typedef struct poldiff_level {} poldiff_level_t;
%extend poldiff_level_t {
	poldiff_level_t(void *x) {
		return (poldiff_level_t*)x;
	};
	~poldiff_level_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_level_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	%newobject to_string_brief();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_level_to_string_brief(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_level_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_level_get_form(self);
	};
	const apol_string_vector_t *get_unmodified_cats() {
		return (apol_string_vector_t*)poldiff_level_get_unmodified_cats(self);
	};
	const apol_string_vector_t *get_added_cats() {
		return (apol_string_vector_t*)poldiff_level_get_added_cats(self);
	};
	const apol_string_vector_t *get_removed_cats() {
		return (apol_string_vector_t*)poldiff_level_get_removed_cats(self);
	};
};

/* range diff */
typedef struct poldiff_range {} poldiff_range_t;
%extend poldiff_range_t {
	poldiff_range_t(void *x) {
		return (poldiff_range_t*)x;
	};
	~poldiff_range_t() {
		/* no op */
		return;
	};
	%newobject to_string_brief();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_range_to_string_brief(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const apol_vector_t *get_levels() {
		return poldiff_range_get_levels(self);
	};
	const apol_mls_range_t *get_original_range() {
		return poldiff_range_get_original_range(self);
	};
	const apol_mls_range_t *get_modified_range() {
		return poldiff_range_get_modified_range(self);
	};
};

/* range_transition rule diff */
typedef struct poldiff_range_trans {} poldiff_range_trans_t;
%extend poldiff_range_trans_t {
	poldiff_range_trans_t(void *x) {
		return (poldiff_range_trans_t *)x;
	};
	~poldiff_range_trans_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_range_trans_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	poldiff_form_e get_form() {
		return poldiff_range_trans_get_form(self);
	};
	const char *get_source_type() {
		return poldiff_range_trans_get_source_type(self);
	};
	const char *get_target_type() {
		return poldiff_range_trans_get_target_type(self);
	};
	const char *get_target_class() {
		return poldiff_range_trans_get_target_class(self);
	};
	const poldiff_range_t *get_range() {
		return poldiff_range_trans_get_range(self);
	};
};

/* role allow rule diff */
typedef struct poldiff_role_allow {} poldiff_role_allow_t;
%extend poldiff_role_allow_t {
	poldiff_role_allow_t(void *x) {
		return (poldiff_role_allow_t *)x;
	};
	~poldiff_role_allow_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_role_allow_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_role_allow_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_role_allow_get_form(self);
	};
	const apol_string_vector_t *get_added_roles() {
		return (apol_string_vector_t*)poldiff_role_allow_get_added_roles(self);
	};
	const apol_string_vector_t *get_removed_roles() {
		return (apol_string_vector_t*)poldiff_role_allow_get_removed_roles(self);
	};
};

/* role_transition rule diff */
typedef struct poldiff_role_trans {} poldiff_role_trans_t;
%extend poldiff_role_trans_t {
	poldiff_role_trans_t(void *x) {
		return (poldiff_role_trans_t *)x;
	};
	~poldiff_role_trans_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_role_trans_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	poldiff_form_e get_form() {
		return poldiff_role_trans_get_form(self);
	};
	const char *get_source_role() {
		return poldiff_role_trans_get_source_role(self);
	};
	const char *get_target_type() {
		return poldiff_role_trans_get_target_type(self);
	};
	const char *get_original_default() {
		return poldiff_role_trans_get_original_default(self);
	};
	const char *get_modified_default() {
		return poldiff_role_trans_get_modified_default(self);
	};
};

/* role diff */
typedef struct poldiff_role {} poldiff_role_t;
%extend poldiff_role_t {
	poldiff_role_t(void *x) {
		return (poldiff_role_t*)x;
	};
	~poldiff_role_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_role_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_role_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_role_get_form(self);
	};
	const apol_string_vector_t *get_added_types() {
		return (apol_string_vector_t*)poldiff_role_get_added_types(self);
	};
	const apol_string_vector_t *get_removed_types() {
		return (apol_string_vector_t*)poldiff_role_get_removed_types(self);
	};
};

/* te rule diff */
typedef struct poldiff_terule {} poldiff_terule_t;
%extend poldiff_terule_t {
	poldiff_terule_t(void *x) {
		return (poldiff_terule_t*)x;
	};
	~poldiff_terule_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_terule_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	poldiff_form_e get_form() {
		return poldiff_terule_get_form(self);
	};
	uint32_t get_rule_type() {
		return poldiff_terule_get_rule_type(self);
	};
	const char *get_source_type() {
		return poldiff_terule_get_source_type(self);
	};
	const char *get_target_type() {
		return poldiff_terule_get_target_type(self);
	};
	const char *get_object_class() {
		return poldiff_terule_get_object_class(self);
	};
	const qpol_cond_t *get_cond(poldiff_t *p) {
		qpol_cond_t *cond;
		uint32_t which_list;
		apol_policy_t *which_pol;
		poldiff_terule_get_cond(p, self, &cond, &which_list, &which_pol);
		return cond;
	};
	uint32_t get_cond_list(poldiff_t *p) {
		qpol_cond_t *cond;
		uint32_t which_list;
		apol_policy_t *which_pol;
		poldiff_terule_get_cond(p, self, &cond, &which_list, &which_pol);
		return which_list;
	};
	const apol_policy_t *get_cond_policy(poldiff_t *p) {
		qpol_cond_t *cond;
		uint32_t which_list;
		apol_policy_t *which_pol;
		poldiff_terule_get_cond(p, self, &cond, &which_list, &which_pol);
		return which_pol;
	};
	const char *get_original_default() {
		return poldiff_terule_get_original_default(self);
	};
	const char *get_modified_default() {
		return poldiff_terule_get_modified_default(self);
	};
	const apol_vector_t *get_orig_line_numbers() {
		return poldiff_terule_get_orig_line_numbers(self);
	};
	const apol_vector_t *get_mod_line_numbers() {
		return poldiff_terule_get_mod_line_numbers(self);
	};
};

/* type diff */
typedef struct poldiff_type {} poldiff_type_t;
%extend poldiff_type_t {
	poldiff_type_t(void *x) {
		return (poldiff_type_t*)x;
	};
	~poldiff_type_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_type_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_type_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_type_get_form(self);
	};
	const apol_string_vector_t *get_added_attribs() {
		return poldiff_type_get_added_attribs(self);
	};
	const apol_string_vector_t *get_removed_attribs() {
		return poldiff_type_get_removed_attribs(self);
	};
};

/* user diff */
typedef struct poldiff_user {} poldiff_user_t;
%extend poldiff_user_t {
	poldiff_user_t(void *x) {
		return (poldiff_user_t*)x;
	};
	~poldiff_user_t() {
		/* no op */
		return;
	};
	%newobject to_string();
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_user_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	const char *get_name() {
		return poldiff_user_get_name(self);
	};
	poldiff_form_e get_form() {
		return poldiff_user_get_form(self);
	};
	const apol_string_vector_t *get_unmodified_roles() {
		return poldiff_user_get_unmodified_roles(self);
	};
	const apol_string_vector_t *get_added_roles() {
		return poldiff_user_get_added_roles(self);
	};
	const apol_string_vector_t *get_removed_roles() {
		return poldiff_user_get_removed_roles(self);
	};
	const poldiff_level_t *get_original_dfltlevel() {
		return poldiff_user_get_original_dfltlevel(self);
	};
	const poldiff_level_t *get_modified_dfltlevel() {
		return poldiff_user_get_modified_dfltlevel(self);
	};
	const poldiff_range_t *get_range() {
		return poldiff_user_get_range(self);
	};
};

/* type remap */
typedef struct poldiff_type_remap_entry {} poldiff_type_remap_entry_t;
%extend poldiff_type_remap_entry_t {
	poldiff_type_remap_entry_t(void *x) {
		return (poldiff_type_remap_entry_t*)x;
	};
	~poldiff_type_remap_entry_t() {
		/* no op */
		return;
	};
	%newobject get_original_types();
	apol_string_vector_t *get_original_types(poldiff_t *p) {
		apol_vector_t *v;
		v = poldiff_type_remap_entry_get_original_types(p, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return (apol_string_vector_t*)v;
	};
	%newobject get_modified_types();
	apol_string_vector_t *get_modified_types(poldiff_t *p) {
		apol_vector_t *v;
		v = poldiff_type_remap_entry_get_modified_types(p, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return (apol_string_vector_t*)v;
	};
	int get_is_inferred() {
		return poldiff_type_remap_entry_get_is_inferred(self);
	};
	int get_is_enabled() {
		return poldiff_type_remap_entry_get_is_enabled(self);
	};
	void set_enabled(int enable) {
		poldiff_type_remap_entry_set_enabled(self, enable);
	};
};

