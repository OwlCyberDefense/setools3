/**
 * SWIG declarations for libqpol.
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

%module qpol

#define __attribute__(x)

%{
#include "../include/qpol/avrule_query.h"
#include "../include/qpol/bool_query.h"
#include "../include/qpol/class_perm_query.h"
#include "../include/qpol/cond_query.h"
#include "../include/qpol/constraint_query.h"
#include "../include/qpol/context_query.h"
#include "../include/qpol/fs_use_query.h"
#include "../include/qpol/genfscon_query.h"
#include "../include/qpol/isid_query.h"
#include "../include/qpol/iterator.h"
#include "../include/qpol/mls_query.h"
#include "../include/qpol/mlsrule_query.h"
#include "../include/qpol/module.h"
#include "../include/qpol/netifcon_query.h"
#include "../include/qpol/nodecon_query.h"
#include "../include/qpol/policy.h"
#include "../include/qpol/policy_extend.h"
#include "../include/qpol/portcon_query.h"
#include "../include/qpol/rbacrule_query.h"
#include "../include/qpol/role_query.h"
#include "../include/qpol/syn_rule_query.h"
#include "../include/qpol/terule_query.h"
#include "../include/qpol/type_query.h"
#include "../include/qpol/user_query.h"
#include "../include/qpol/util.h"
%}

%include exception.i

//%include headers to wrap directly here

/* utility functions */
const char *libqpol_get_version(void);

%rename(qpol_default_policy_find) wrap_qpol_default_policy_find;
%newobject wrap_qpol_default_policy_find;
%inline %{
	char * wrap_qpol_default_policy_find() {
		char *path;
		int retv;
		retv = qpol_default_policy_find(&path);
		if (retv < 0) {
			SWIG_exception(SWIG_IOError, "Error searching for default policy");
		} else if (retv > 0) {
			SWIG_exception(SWIG_RuntimeError, "Could not find default policy");
		} else {
			return path;
		}
	fail: /* SWIG_exception calls goto fail */
		return NULL;
	}
%}

/* qpol_module */

/* qpol_policy */
typedef struct qpol_policy {} qpol_policy_t;
typedef void (*qpol_callback_fn_t) (void *varg, struct qpol_policy * policy, int level, const char *fmt, va_list va_args);
#define QPOL_POLICY_UNKNOWN       -1
#define QPOL_POLICY_KERNEL_SOURCE  0
#define QPOL_POLICY_KERNEL_BINARY  1
#define QPOL_POLICY_MODULE_BINARY  2
typedef enum qpol_capability
{
	QPOL_CAP_ATTRIB_NAMES,
	QPOL_CAP_SYN_RULES,
	QPOL_CAP_LINE_NUMBERS,
	QPOL_CAP_CONDITIONALS,
	QPOL_CAP_MLS,
	QPOL_CAP_MODULES,
	QPOL_CAP_RULES_LOADED,
	QPOL_CAP_SOURCE,
	QPOL_CAP_NEVERALLOW
} qpol_capability_e;

%extend qpol_policy_t {
	qpol_policy_t(const char *path, qpol_callback_fn_t fn=NULL, void *arg=NULL) {
		qpol_policy_t *p;
		if (qpol_policy_open_from_file(path, &p, fn, arg)) {
			SWIG_exception(SWIG_IOError, "Error opening policy");
		}
		return p;
	fail:
		return NULL;
	};
	~qpol_policy_t() {
		qpol_policy_destroy(&self);
	};
	void reevaluate_conds() {
		if (qpol_policy_reevaluate_conds(self)) {
			SWIG_exception(SWIG_ValueError, "Error evaluating conditional expressions");
		}
	fail:
		return;
	};
	void append_module(qpol_module_t *mod) {
		if (qpol_policy_append_module(self, mod)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
		return;
	};
	void rebuild () {
		if (qpol_policy_rebuild(self)) {
			SWIG_exception(SWIG_RuntimeError, "Failed rebuilding policy");
		}
	fail:
		return;
	};
	qpol_iterator_t *get_module_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_module_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
		return NULL;
	};
};

