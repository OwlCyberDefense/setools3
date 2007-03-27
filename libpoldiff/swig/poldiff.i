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
#include "../include/poldiff/rbac_diff.h"
#include "../include/poldiff/role_diff.h"
#include "../include/poldiff/terule_diff.h"
#include "../include/poldiff/type_diff.h"
#include "../include/poldiff/type_map.h"
#include "../include/poldiff/user_diff.h"
#include "../include/poldiff/util.h"
%}

%include exception.i

/* sized integer handling -
 * NOTE cannot include stdint.h here as seig does not parse it right
 * also some integer types are treated identically in many target languages */
%typedef unsigned int uint32_t;
%typedef unsigned long size_t;

%typedef struct apol_policy apol_policy_t;

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
};

//TODO
// %include "../include/poldiff/attrib_diff.h"
// %include "../include/poldiff/avrule_diff.h"
// %include "../include/poldiff/bool_diff.h"
// %include "../include/poldiff/cat_diff.h"
// %include "../include/poldiff/class_diff.h"
// %include "../include/poldiff/level_diff.h"
// %include "../include/poldiff/range_diff.h"
// %include "../include/poldiff/rbac_diff.h"
// %include "../include/poldiff/role_diff.h"
// %include "../include/poldiff/terule_diff.h"
// %include "../include/poldiff/type_diff.h"
// %include "../include/poldiff/type_map.h"
// %include "../include/poldiff/user_diff.h"
