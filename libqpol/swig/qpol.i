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
%typedef unsigned long size_t;

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

const char * to_str(void *x) {
	return (const char *)x;
}

/* qpol_module */
#define QPOL_MODULE_UNKNOWN 0
#define QPOL_MODULE_BASE    1
#define QPOL_MODULE_OTHER   2
typedef struct qpol_module {} qpol_module_t;
%extend qpol_module_t {
	qpol_module_t(const char *path) {
		qpol_module_t *m;
		if (qpol_module_create_from_file(path, &m)) {
			SWIG_exception(SWIG_IOError, "Error opening module");
		}
		return m;
	fail:
		return NULL;
	};
	~qpol_module_t() {
		qpol_module_destroy(&self);
	};
	char *qpol_module_get_path() {
		char *p;
		if (qpol_module_get_path(self, &p)) {
			SWIG_exception(SWIG_ValueError,"Could not get module path");
		}
		return p;
	fail:
		return NULL;
	};
	char *qpol_module_get_name() {
		char *n;
		if (qpol_module_get_name(self, &n)) {
			SWIG_exception(SWIG_ValueError,"Could not get module name");
		}
		return n;
	fail:
			return NULL;
	};
	char *qpol_module_get_version() {
		char *v;
		if (qpol_module_get_version(self, &v)) {
			SWIG_exception(SWIG_ValueError,"Could not get module version");
		}
		return v;
	fail:
			return NULL;
	};
	int qpol_module_get_type() {
		int t;
		if (qpol_module_get_type(self, &t)) {
			SWIG_exception(SWIG_ValueError,"Could not get module type");
		}
	fail:
		return t;
	};
	int qpol_module_get_enabled() {
		int e;
		if (qpol_module_get_enabled(self, &e)) {
			SWIG_exception(SWIG_ValueError,"Could not get module state");
		}
	fail:
			return e;
	};
	void qpol_module_set_enabled(int state) {
		if (qpol_module_set_enabled(self, state)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set module state");
		}
	fail:
		return;
	};
};

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
	/* open no rules currently unavailable pending neverallow decision */
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
	int get_version () {
		int v;
		(void)qpol_policy_get_policy_version(self, &v); /* only error is on null parameters neither can be here */
		return v;
	};
	int get_type () {
		int t;
		(void)qpol_policy_get_type(self, &t); /* only error is on null parameters neither can be here */
		return t;
	};
	int has_capability (qpol_capability_e cap) {
		return qpol_policy_has_capability(self, cap);
	};
	void build_syn_rule_table() {
		if (qpol_policy_build_syn_rule_table(self)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
		return;
	};
	%newobject get_module_iter();
	qpol_iterator_t *get_module_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_module_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
		return NULL;
	};
	%newobject get_type_iter();
	qpol_iterator_t *get_type_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_type_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
			return NULL;
	};
	%newobject get_role_iter();
	qpol_iterator_t *get_role_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_role_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
			return NULL;
	};
	%newobject get_level_iter();
	qpol_iterator_t *get_level_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_level_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
			return NULL;
	};
	%newobject get_cat_iter();
	qpol_iterator_t *get_cat_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_cat_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
			return NULL;
	};
	%newobject get_user_iter();
	qpol_iterator_t *get_user_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_user_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
			return NULL;
	};
	%newobject get_bool_iter();
	qpol_iterator_t *get_bool_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_bool_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
			return NULL;
	};
	%newobject get_class_iter();
	qpol_iterator_t *get_class_iter(char *perm=NULL) {
		qpol_iterator_t *iter;
		if (perm) {
			if (qpol_perm_get_class_iter(self, perm, &iter)) {
				SWIG_exception(SWIG_RuntimeError, "Could not get class iterator");
			}
		} else {
			if (qpol_policy_get_class_iter(self, &iter)) {
				SWIG_exception(SWIG_MemoryError, "Out of Memory");
			}
		}
	fail:
			return NULL;
	};
	%newobject get_common_iter();
	qpol_iterator_t *get_common_iter(char *perm=NULL) {
		qpol_iterator_t *iter;
		if (perm) {
			if (qpol_perm_get_common_iter(self, perm, &iter)) {
				SWIG_exception(SWIG_RuntimeError, "Could not get common iterator");
			}
		} else {
			if (qpol_policy_get_common_iter(self, &iter)) {
				SWIG_exception(SWIG_MemoryError, "Out of Memory");
			}
		}
	fail:
			return NULL;
	};
	//other get_*_iter functions here
};

/* qpol iterator */
typedef struct qpol_iterator {} qpol_iterator_t;
%extend qpol_iterator_t {
	/* user never directly creates, but SWIG expects a constructor */
	qpol_iterator_t() {
		SWIG_exception(SWIG_TypeError, "User may not create iterators difectly");
	fail:
		return NULL;
	};
	~qpol_iterator_t() {
		qpol_iterator_destroy(&self);
	};
	void *get_item() {
		void *i;
		if (qpol_iterator_get_item(self, &i)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get item");
		}
		return i;
	fail:
		return NULL;
	};
	void next() {
		if (qpol_iterator_next(self)) {
			SWIG_exception(SWIG_RuntimeError, "Error advancing iterator");
		}
	fail:
		return;
	};
	int end() {
		return qpol_iterator_end(self);
	};
	size_t get_size() {
		size_t s;
		if (qpol_iterator_get_size(self, &s)) {
			SWIG_exception(SWIG_ValueError, "Could not get iterator size");
		}
		return s;
	fail:
		return 0;
	};
};

/* qpol type */
typedef struct qpol_type {} qpol_type_t;
%extend qpol_type_t {
	qpol_type_t(qpol_policy_t *p, char *name) {
		qpol_type_t *t;
		if (qpol_policy_get_type_by_name(p, name, &t)) {
			SWIG_exception(SWIG_RuntimeError, "Type does not exist");
		}
		return t;
	fail:
		return NULL;
	};
	qpol_type_t(void *x) {
		return (qpol_type_t*)x;
	};
	~qpol_type_t() {
		/* no op */
		return;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_type_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get type name");
		}
		return name;
	fail:
		return NULL;
	};
	int get_value(qpol_policy_t *p) {
		int v;
		if (qpol_type_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get type value");
		}
	fail:
		return v;
	};
	int get_isattr(qpol_policy_t *p) {
		int i;
		if (qpol_type_get_is_attr(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine whether type is an attribute");
		}
	fail:
		return i;
	};
	int get_isalias(qpol_policy_t *p) {
		int i;
		if (qpol_type_get_is_alias(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine whether type is an alias");
		}
	fail:
			return i;
	};
	%newobject get_type_iter;
	qpol_iterator_t *get_type_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		int retv = qpol_type_get_type_iter(p, self, &iter);
		if (retv < 0) {
			SWIG_exception(SWIG_RuntimeError, "Could not get attribute types");
		} else if (retv > 0) {
			SWIG_exception(SWIG_TypeError, "Type is not an attribute");
		}
	fail:
		return iter;
	};
	%newobject get_attr_iter;
	qpol_iterator_t *get_attr_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		int retv = qpol_type_get_attr_iter(p, self, &iter);
		if (retv < 0) {
			SWIG_exception(SWIG_RuntimeError, "Could not get type attributes");
		} else if (retv > 0) {
			SWIG_exception(SWIG_TypeError, "Type is an attribute");
		}
	fail:
		return iter;
	};
	%newobject get_alias_iter;
	qpol_iterator_t *get_alias_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_type_get_alias_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get type aliases");
		}
	fail:
		return iter;
	};
 };

/* qpol role */
typedef struct qpol_role {} qpol_role_t;
%extend qpol_role_t {
	qpol_role_t(qpol_policy_t *p, char *name) {
		qpol_role_t *r;
		if (qpol_policy_get_role_by_name(p, name, &r)) {
			SWIG_exception(SWIG_RuntimeError, "Role does not exist");
		}
		return r;
	fail:
		return NULL;
	};
	qpol_role_t(void *x) {
		return (qpol_role_t*)x;
	};
	~qpol_role_t() {
		/* no op */
		return;
	};
	int get_value (qpol_policy_t *p) {
		int v;
		if (qpol_role_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get role value");
		}
	fail:
		return v;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_role_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get role name");
		}
		return name;
	fail:
		return NULL;
	};
	%newobject get_type_iter;
	qpol_iterator_t *get_type_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_role_get_type_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get role types");
		}
	fail:
		return iter;
	};
	%newobject get_dominate_iter;
	qpol_iterator_t *get_dominate_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_role_get_dominate_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get dominated roles");
		}
	fail:
		return iter;
	};
};

/* qpol level */
typedef struct qpol_level {} qpol_level_t;
%extend qpol_level_t {
	qpol_level_t(qpol_policy_t *p, char *name) {
		qpol_level_t *l;
		if (qpol_policy_get_level_by_name(p, name, &l)) {
			SWIG_exception(SWIG_RuntimeError, "Level does not exist");
		}
		return l;
	fail:
		return NULL;
	};
	qpol_level_t(void *x) {
		return (qpol_level_t*)x;
	};
	~qpol_level_t() {
		/* no op */
		return;
	};
	int get_isalias(qpol_policy_t *p) {
		int i;
		if (qpol_level_get_is_alias(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine whether level is an alias");
		}
	fail:
			return i;
	};
	int get_value(qpol_policy_t *p) {
		int v;
		if (qpol_level_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get level sensitivity value");
		}
	fail:
		return v;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_level_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get level sensitivity name");
		}
		return name;
	fail:
		return NULL;
	};
	%newobject get_cat_iter;
	qpol_iterator_t *get_cat_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_level_get_cat_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get level categories");
		}
	fail:
		return iter;
	};
	%newobject get_alias_iter;
	qpol_iterator_t *get_alias_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_level_get_alias_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get level aliases");
		}
	fail:
		return iter;
	};
};

/* qpol cat */
typedef struct qpol_cat {} qpol_cat_t;
%extend qpol_cat_t {
	qpol_cat_t(qpol_policy_t *p, char *name) {
		qpol_cat_t *c;
		if (qpol_policy_get_cat_by_name(p, name, &c)) {
			SWIG_exception(SWIG_RuntimeError, "Category does not exist");
		}
		return c;
	fail:
		return NULL;
	};
	qpol_cat_t(void *x) {
		return (qpol_cat_t*)x;
	};
	~qpol_cat_t() {
		/* no op */
		return;
	};
	int get_isalias(qpol_policy_t *p) {
		int i;
		if (qpol_cat_get_is_alias(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine whether category is an alias");
		}
	fail:
			return i;
	};
	int get_value(qpol_policy_t *p) {
		int v;
		if (qpol_cat_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get category value");
		}
	fail:
		return v;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_cat_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get category name");
		}
		return name;
	fail:
		return NULL;
	};
	%newobject get_alias_iter;
	qpol_iterator_t *get_alias_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_cat_get_alias_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get category aliases");
		}
	fail:
		return iter;
	};
};

/* qpol mls range */
typedef struct qpol_mls_range {} qpol_mls_range_t;
%extend qpol_mls_range_t {
	qpol_mls_range_t(void *x) {
		return (qpol_mls_range_t*)x;
	};
	~qpol_mls_range_t() {
		/* no op */
		return;
	};
	qpol_mls_level_t *get_high_level(qpol_policy_t *p) {
		qpol_mls_level_t *l;
		if (qpol_mls_range_get_high_level(p, self, &l)) {
			SWIG_exception(SWIG_ValueError, "Could not get range high levl");
		}
	fail:
		return l;
	};
	qpol_mls_level_t *get_low_level(qpol_policy_t *p) {
		qpol_mls_level_t *l;
		if (qpol_mls_range_get_low_level(p, self, &l)) {
			SWIG_exception(SWIG_ValueError, "Could not get range low levl");
		}
	fail:
		return l;
	};
};

/* qpol mls level */
typedef struct qpol_mls_level {} qpol_mls_level_t;
%extend qpol_mls_level_t {
	qpol_mls_level_t(void *x) {
		return (qpol_mls_level_t*)x;
	};
	~qpol_mls_level_t() {
		/* no op */
		return;
	};
	const char *get_sens_name(qpol_policy_t *p) {
		char *name;
		if (qpol_mls_level_get_sens_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get level sensitivity name");
		}
	fail:
		return name;
	};
	%newobject get_cat_iter;
	qpol_iterator_t *get_cat_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_mls_level_get_cat_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get level categories");
		}
	fail:
		return iter;
	};
};

/* qpol user */
typedef struct qpol_user {} qpol_user_t;
%extend qpol_user_t {
	qpol_user_t(qpol_policy_t *p, char *name) {
		qpol_user_t *u;
		if (qpol_policy_get_user_by_name(p, name, &u)) {
			SWIG_exception(SWIG_RuntimeError, "User does not exist");
		}
		return u;
	fail:
		return NULL;
	};
	qpol_user_t(void *x) {
		return (qpol_user_t*)x;
	};
	~qpol_user_t() {
		/* no op */
		return;
	};
	int get_value(qpol_policy_t *p) {
		int v;
		if (qpol_user_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get user value");
		}
	fail:
		return v;
	};
	%newobject get_role_iter;
	qpol_iterator_t *get_role_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_user_get_role_iter(p, self, &iter)) {
		}
	fail:
		return iter;
	};
	qpol_mls_range_t *get_range(qpol_policy_t *p) {
		qpol_mls_range_t *r;
		if (qpol_user_get_mls_range(p, self, &r)) {
			SWIG_exception(SWIG_ValueError, "Could not get user range");
		}
	fail:
		return r;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_user_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get user name");
		}
	fail:
		return name;
	};
	qpol_mls_level_t *get_dfltlevel(qpol_policy_t *p) {
		qpol_mls_level_t *l;
		if (qpol_user_get_dfltlevel(p, self, &l)) {
			SWIG_exception(SWIG_ValueError, "Could not get user default level");
		}
	fail:
		return l;
	};
};

/* qpol bool */
typedef struct qpol_bool {} qpol_bool_t;
%extend qpol_bool_t {
	qpol_bool_t(qpol_policy_t *p, char *name) {
		qpol_bool_t *b;
		if (qpol_policy_get_bool_by_name(p, name, &b)) {
			SWIG_exception(SWIG_RuntimeError, "Boolean does not exist");
		}
	fail:
		return b;
	};
	qpol_bool_t(void *x) {
		return (qpol_bool_t*)x;
	};
	~qpol_bool_t() {
		/* no op */
		return;
	};
	int get_value(qpol_policy_t *p) {
		int v;
		if (qpol_bool_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get boolean value");
		}
	fail:
		return v;
	};
	int get_state(qpol_policy_t *p) {
		int s;
		if (qpol_bool_get_state(p, self, &s)) {
			SWIG_exception(SWIG_ValueError, "Could not get boolean state");
		}
	fail:
		return s;
	};
	void set_state(qpol_policy_t *p, int state) {
		if (qpol_bool_set_state(p, self, state)) {
			SWIG_exception(SWIG_RuntimeError, "Error setting boolean state");
		}
	fail:
		return;
	};
	void set_state_no_eval(qpol_policy_t *p, int state) {
		if (qpol_bool_set_state_no_evel(p, self, state)) {
			SWIG_exception(SWIG_RuntimeError, "Error setting boolean state");
		}
	fail:
		return;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_bool_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get boolean name");
		}
	fail:
		return name;
	};
};

/* qpol context */
typedef struct qpol_context {} qpol_context_t;
%extend qpol_context_t {
	qpol_context_t(void *x) {
		return (qpol_context_t*)x;
	};
	~qpol_context_t() {
		/* no op */
		return;
	};
	 qpol_user_t *get_user(qpol_policy_t *p) {
		qpol_user_t *u;
		if (qpol_context_get_user(p, self, &u)) {
			SWIG_exception(SWIG_ValueError, "Could not get user from context");
		}
	fail:
		return u;
	 };
	 qpol_role_t *get_role(qpol_policy_t *p) {
		qpol_role_t *r;
		if (qpol_context_get_role(p, self, &r)) {
			SWIG_exception(SWIG_ValueError, "Could not get role from context");
		}
	fail:
		return r;
	 };
	 qpol_type_t *get_type(qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_context_get_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get type from context");
		}
	fail:
		return t;
	 };
	 qpol_mls_range_t *get_range(qpol_policy_t *p) {
		qpol_mls_range_t *r;
		if (qpol_context_get_range(p, self, &r)) {
			SWIG_exception(SWIG_ValueError, "Could not get range from context");
		}
	fail:
		return r;
	 };
};

/* qpol class */
typedef struct qpol_class {} qpol_class_t;
%extend qpol_class_t {
	qpol_class_t(qpol_policy_t *p, char *name) {
		qpol_class_t *c;
		if (qpol_policy_get_class_by_name(p, name, &c)) {
			SWIG_exception(SWIG_RuntimeError, "Class does not exist");
		}
	fail:
		return c;
	};
	qpol_class_t(void *x) {
		return (qpol_class_t*)x;
	};
	~qpol_class_t() {
		/* no op */
		return;
	};
	int get_value(qpol_policy_t *p) {
		int v;
		if (qpol_class_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get value for class");
		}
	fail:
		return v;
	};
	qpol_common_t *get_common(qpol_policy_t *p) {
		qpol_common_t *c;
		if(qpol_class_get_common(p, self, &c)) {
			SWIG_exception(SWIG_ValueError, "Could not get common for class");
		}
	fail:
		return c;
	};
	%newobject get_perm_iter();
	qpol_iterator_t *get_perm_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if(qpol_class_get_perm_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get class permissions");
		}
	fail:
		return iter;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_class_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get class name");
		}
	fail:
		return name;
	};
};

/* qpol common */
typedef struct qpol_common {} qpol_common_t;
%extend qpol_common_t {
	qpol_common_t(qpol_policy_t *p, char *name) {
		qpol_common_t *c;
		if (qpol_policy_get_common_by_name(p, name, &c)) {
			SWIG_exception(SWIG_RuntimeError, "Common does not exist");
		}
	fail:
		return c;
	};
	qpol_common_t(void *x) {
		return (qpol_common_t*)x;
	};
	~qpol_common_t() {
		/* no op */
		return;
	};
	int get_value(qpol_policy_t *p) {
		int v;
		if (qpol_common_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get value for common");
		}
	fail:
		return v;
	};
	%newobject get_perm_iter();
	qpol_iterator_t *get_perm_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if(qpol_common_get_perm_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get common permissions");
		}
	fail:
		return iter;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_common_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get common name");
		}
	fail:
		return name;
	};
};

