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

#ifdef SWIGJAVA
%javaconst(1);
%{extern JNIEnv*jenv;%}
#endif

%include exception.i

#ifdef SWIGJAVA
/* remove $null not valid outside of type map */
#undef SWIG_exception
#define SWIG_exception(code, msg) {SWIG_JavaException(jenv, code, msg); goto fail;}
#endif

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

%inline %{
const char * to_str(void *x) {
	return (const char *)x;
}
%}

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
		unsigned int v;
		(void)qpol_policy_get_policy_version(self, &v); /* only error is on null parameters neither can be here */
		return (int) v;
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
		return iter;
	fail:
		return NULL;
	};
	%newobject get_type_iter();
	qpol_iterator_t *get_type_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_type_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_role_iter();
	qpol_iterator_t *get_role_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_role_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_level_iter();
	qpol_iterator_t *get_level_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_level_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_cat_iter();
	qpol_iterator_t *get_cat_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_cat_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_user_iter();
	qpol_iterator_t *get_user_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_user_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_bool_iter();
	qpol_iterator_t *get_bool_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_bool_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
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
		return iter;
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
		return iter;
	fail:
		return NULL;
	};
	%newobject get_fs_use_iter();
	qpol_iterator_t *get_fs_use_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_fs_use_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_genfscon_iter();
	qpol_iterator_t *get_genfscon_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_genfscon_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_isid_iter();
	qpol_iterator_t *get_isid_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_isid_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_netifcon_iter();
	qpol_iterator_t *get_netifcon_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_netifcon_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
			return NULL;
	};
	%newobject get_nodecon_iter();
	qpol_iterator_t *get_nodecon_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_nodecon_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_constraint_iter();
	qpol_iterator_t *get_constraint_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_constraint_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
	}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_validatetrans_iter();
	qpol_iterator_t *get_validatetrans_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_validatetrans_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
	}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_role_allow_iter();
	qpol_iterator_t *get_role_allow_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_role_allow_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_role_trans_iter();
	qpol_iterator_t *get_role_trans_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_role_trans_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_range_trans_iter();
	qpol_iterator_t *get_range_trans_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_range_trans_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_avrule_iter();
	qpol_iterator_t *get_avrule_iter(int rule_types) {
		qpol_iterator_t *iter;
		if (qpol_policy_get_avrule_iter(self, rule_types, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_terule_iter();
	qpol_iterator_t *get_terule_iter(int rule_types) {
		qpol_iterator_t *iter;
		if (qpol_policy_get_terule_iter(self, rule_types, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
	%newobject get_cond_iter();
	qpol_iterator_t *get_cond_iter() {
		qpol_iterator_t *iter;
		if (qpol_policy_get_cond_iter(self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
		return iter;
	fail:
		return NULL;
	};
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
		uint32_t v;
		if (qpol_type_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get type value");
		}
	fail:
		return (int) v;
	};
	int get_isattr(qpol_policy_t *p) {
		unsigned char i;
		if (qpol_type_get_isattr(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine whether type is an attribute");
		}
	fail:
			return (int)i;
	};
	int get_isalias(qpol_policy_t *p) {
		unsigned char i;
		if (qpol_type_get_isalias(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine whether type is an alias");
		}
	fail:
			return (int)i;
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
		uint32_t v;
		if (qpol_role_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get role value");
		}
	fail:
		return (int) v;
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
		unsigned char i;
		if (qpol_level_get_isalias(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine whether level is an alias");
		}
	fail:
			return (int)i;
	};
	int get_value(qpol_policy_t *p) {
		uint32_t v;
		if (qpol_level_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get level sensitivity value");
		}
	fail:
		return (int) v;
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
		unsigned char i;
		if (qpol_cat_get_isalias(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine whether category is an alias");
		}
	fail:
			return (int)i;
	};
	int get_value(qpol_policy_t *p) {
		uint32_t v;
		if (qpol_cat_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get category value");
		}
	fail:
		return (int) v;
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
		uint32_t v;
		if (qpol_user_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get user value");
		}
	fail:
		return (int) v;
	};
	%newobject get_role_iter;
	qpol_iterator_t *get_role_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_user_get_role_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of Memory");
		}
	fail:
		return iter;
	};
	qpol_mls_range_t *get_range(qpol_policy_t *p) {
		qpol_mls_range_t *r;
		if (qpol_user_get_range(p, self, &r)) {
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
		uint32_t v;
		if (qpol_bool_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get boolean value");
		}
	fail:
		return (int) v;
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
		if (qpol_bool_set_state_no_eval(p, self, state)) {
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
		uint32_t v;
		if (qpol_class_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get value for class");
		}
	fail:
		return (int) v;
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
	%newobject get_constraint_iter();
	qpol_iterator_t *get_constraint_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if(qpol_class_get_constraint_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get class constraints");
		}
	fail:
		return iter;
	};
	%newobject get_validatetrans_iter();
	qpol_iterator_t *get_validatetrans_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if(qpol_class_get_validatetrans_iter(p, self, &iter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get class validatetrans statements");
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
		uint32_t v;
		if (qpol_common_get_value(p, self, &v)) {
			SWIG_exception(SWIG_ValueError, "Could not get value for common");
		}
	fail:
		return (int) v;
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

/* qpol fs_use */
/* The defines QPOL_FS_USE_XATTR through QPOL_FS_USE_NONE are 
 * copied from sepol/policydb/services.h.
 * QPOL_FS_USE_PSID is an extension to support v12 policies. */
#define QPOL_FS_USE_XATTR 1
#define QPOL_FS_USE_TRANS 2
#define QPOL_FS_USE_TASK  3
#define QPOL_FS_USE_GENFS 4
#define QPOL_FS_USE_NONE  5
#define QPOL_FS_USE_PSID  6
typedef struct qpol_fs_use {} qpol_fs_use_t;
%extend qpol_fs_use_t {
	qpol_fs_use_t(qpol_policy_t *p, char *name) {
		qpol_fs_use_t *f;
		if (qpol_policy_get_fs_use_by_name(p, name, &f)) {
			SWIG_exception(SWIG_RuntimeError, "FS Use Statement does not exist");
		}
	fail:
		return f;
	};
	qpol_fs_use_t(void *x) {
		return (qpol_fs_use_t*)x;
	};
	~qpol_fs_use_t() {
		/* no op */
		return;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_fs_use_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get file system name");
		}
	fail:
		return name;
	};
	int get_behavior(qpol_policy_t *p) {
		uint32_t behav;
		if (qpol_fs_use_get_behavior(p, self, &behav)) {
			SWIG_exception(SWIG_ValueError, "Could not get file system labeling behavior");
		}
	fail:
		return (int) behav;
	};
	qpol_context_t *get_context(qpol_policy_t *p) {
		uint32_t behav;
		qpol_context_t *ctx = NULL;
		qpol_fs_use_get_behavior(p, self, &behav);
		if (behav == QPOL_FS_USE_PSID) {
			SWIG_exception(SWIG_TypeError, "Cannot get context for fs_use_psid statements");
		} else if (qpol_fs_use_get_context(p, self, &ctx)) {
			SWIG_exception(SWIG_ValueError, "Could not get file system context");
		}
	fail:
		return ctx;
	};
};

/* qpol genfscon */
/* values from flask do not change */
#define QPOL_CLASS_ALL        0
#define QPOL_CLASS_BLK_FILE  11
#define QPOL_CLASS_CHR_FILE  10
#define QPOL_CLASS_DIR        7
#define QPOL_CLASS_FIFO_FILE 13
#define QPOL_CLASS_FILE       6
#define QPOL_CLASS_LNK_FILE   9
#define QPOL_CLASS_SOCK_FILE 12
typedef struct qpol_genfscon {} qpol_genfscon_t;
%extend qpol_genfscon_t {
	qpol_genfscon_t(qpol_policy_t *p, char *name, char *path) {
		qpol_genfscon_t *g;
		if (qpol_policy_get_genfscon_by_name(p, name, path, &g)) {
			SWIG_exception(SWIG_RuntimeError, "Genfscon statement does not exist");
		}
	fail:
		return g;
	};
	qpol_genfscon_t(void *x) {
		return (qpol_genfscon_t*)x;
	};
	~qpol_genfscon_t() {
		free(self);
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_genfscon_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get file system name");
		}
	fail:
		return name;
	};
	const char *get_path(qpol_policy_t *p) {
		char *path;
		if (qpol_genfscon_get_path(p, self, &path)) {
			SWIG_exception(SWIG_ValueError, "Could not get file system path");
		}
	fail:
		return path;
	};
	int get_class(qpol_policy_t *p) {
		uint32_t cls;
		if (qpol_genfscon_get_class(p, self, &cls)) {
			SWIG_exception(SWIG_ValueError, "Could not get genfscon statement class");
		}
	fail:
		return (int) cls;
	};
	qpol_context_t *get_context(qpol_policy_t *p) {
		qpol_context_t *ctx;
		if (qpol_genfscon_get_context(p, self, &ctx)) {
			SWIG_exception(SWIG_ValueError, "Could not get context for genfscon statement");
		}
	fail:
		return ctx;
	};
};

/* qpol isid */
typedef struct qpol_isid {} qpol_isid_t;
%extend qpol_isid_t {
	qpol_isid_t(qpol_policy_t *p, char *name) {
		qpol_isid_t *i;
		if (qpol_policy_get_isid_by_name(p, name, &i)) {
			SWIG_exception(SWIG_RuntimeError, "Isid does not exist");
		}
	fail:
		return i;
	};
	qpol_isid_t(void *x) {
		return (qpol_isid_t*)x;
	};
	~qpol_isid_t() {
		/* no op */
		return;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_isid_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get name for initial sid");
		}
	fail:
		return name;
	};
	qpol_context_t *get_context(qpol_policy_t *p) {
		qpol_context_t *ctx;
		if (qpol_isid_get_context(p, self, &ctx)) {
			SWIG_exception(SWIG_ValueError, "Could not get context for initial sid");
		}
	fail:
		return ctx;
	};
};

/* qpol netifcon */
typedef struct qpol_netifcon {} qpol_netifcon_t;
%extend qpol_netifcon_t {
	qpol_netifcon_t(qpol_policy_t *p, char *name) {
		qpol_netifcon_t *n;
		if (qpol_policy_get_netifcon_by_name(p, name, &n)) {
			SWIG_exception(SWIG_RuntimeError, "Netifcon statement does not exist");
		}
	fail:
		return n;
	};
	qpol_netifcon_t(void *x) {
		return (qpol_netifcon_t*)x;
	};
	~qpol_netifcon_t() {
		/* no op */
		return;
	};
	const char *get_name(qpol_policy_t *p) {
		char *name;
		if (qpol_netifcon_get_name(p, self, &name)) {
			SWIG_exception(SWIG_ValueError, "Could not get name for netifcon statement");
		}
	fail:
		return name;
	};
	qpol_context_t *get_msg_con(qpol_policy_t *p) {
		qpol_context_t *ctx;
		if (qpol_netifcon_get_msg_con(p, self, &ctx)) {
			SWIG_exception(SWIG_ValueError, "Could not get message context for netifcon statement");
		}
	fail:
		return ctx;
	};
	qpol_context_t *get_if_con(qpol_policy_t *p) {
		qpol_context_t *ctx;
		if (qpol_netifcon_get_if_con(p, self, &ctx)) {
			SWIG_exception(SWIG_ValueError, "Could not get interface context for netifcon statement");
		}
	fail:
		return ctx;
	};
};

/* qpol nodecon */
#define QPOL_IPV4 0
#define QPOL_IPV6 1
typedef struct qpol_nodecon {} qpol_nodecon_t;
%extend qpol_nodecon_t {
	qpol_nodecon_t(qpol_policy_t *p, int addr[4], int mask[4], int protocol) {
		uint32_t a[4], m[4];
		qpol_nodecon_t *n;
		a[0] = (uint32_t) addr[0]; a[1] = (uint32_t) addr[1];
		a[2] = (uint32_t) addr[2]; a[3] = (uint32_t) addr[3];
		m[0] = (uint32_t) mask[0]; m[1] = (uint32_t) mask[1];
		m[2] = (uint32_t) mask[2]; m[3] = (uint32_t) mask[3];
		if (qpol_policy_get_nodecon_by_node(p, a, m, protocol, &n)) {
			SWIG_exception(SWIG_RuntimeError, "Nodecon statement does not exist");
		}
	fail:
		return n;
	}
	qpol_nodecon_t(void *x) {
		return (qpol_nodecon_t*)x;
	};
	~qpol_nodecon_t() {
		free(self);
	};
	int *get_addr(qpol_policy_t *p) {
		uint32_t *a;
		unsigned char proto; /* currently dropped; stores the protocol - call get_protocol() */
		if (qpol_nodecon_get_addr(p, self, &a, &proto)) {
			SWIG_exception(SWIG_ValueError, "Could not get address of nodecon statement");
		}
	fail:
		return (int*)a;
	};
	int *get_mask(qpol_policy_t *p) {
		uint32_t *m;
		unsigned char proto; /* currently dropped; stores the protocol - call get_protocol() */
		if (qpol_nodecon_get_mask(p, self, &m, &proto)) {
			SWIG_exception(SWIG_ValueError, "Could not get mask of nodecon statement");
		}
	fail:
			return (int*)m;
	};
	int get_protocol(qpol_policy_t *p) {
		unsigned char proto;
		if (qpol_nodecon_get_protocol(p, self, &proto)) {
			SWIG_exception(SWIG_ValueError, "Could not get protocol for nodecon statement");
		}
	fail:
		return proto;
	};
	qpol_context_t *get_context(qpol_policy_t *p) {
		qpol_context_t *ctx;
		if (qpol_nodecon_get_context(p, self, &ctx)) {
			SWIG_exception(SWIG_ValueError, "Could not get context for nodecon statement");
		}
	fail:
		return ctx;
	};
};

/* qpol constraint */
typedef struct qpol_constraint {} qpol_constraint_t;
%extend qpol_constraint_t {
	qpol_constraint_t(void *x) {
		return (qpol_constraint_t*)x;
	};
	~qpol_constraint_t() {
		free(self);
	};
	qpol_class_t *get_class(qpol_policy_t *p) {
		qpol_class_t *cls;
		if (qpol_constraint_get_class(p, self, &cls)) {
			SWIG_exception(SWIG_ValueError, "Could not get class for constraint");
		}
	fail:
		return cls;
	};
	%newobject get_perm_iter();
	qpol_iterator_t *get_perm_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_constraint_get_perm_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	%newobject get_expr_iter;
	qpol_iterator_t *get_expr_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_constraint_get_expr_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return iter;
	};
};

/* qpol validatetrans */
typedef struct qpol_validatetrans {} qpol_validatetrans_t;
%extend qpol_validatetrans_t {
	qpol_validatetrans_t(void *x) {
		return (qpol_validatetrans_t*)x;
	};
	~qpol_validatetrans_t() {
		free(self);
	};
	qpol_class_t *get_class(qpol_policy_t *p) {
		qpol_class_t *cls;
		if (qpol_validatetrans_get_class(p, self, &cls)) {
			SWIG_exception(SWIG_ValueError, "Could not get class for constraint");
		}
	fail:
		return cls;
	};
	%newobject get_expr_iter();
	qpol_iterator_t *get_expr_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_validatetrans_get_expr_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return iter;
	};
};

/* qpol constraint expression node */
/* expr_type values */
#define QPOL_CEXPR_TYPE_NOT   1
#define QPOL_CEXPR_TYPE_AND   2
#define QPOL_CEXPR_TYPE_OR    3
#define QPOL_CEXPR_TYPE_ATTR  4
#define QPOL_CEXPR_TYPE_NAMES 5
/* symbol type values */
#define QPOL_CEXPR_SYM_USER       1
#define QPOL_CEXPR_SYM_ROLE       2
#define QPOL_CEXPR_SYM_TYPE       4
#define QPOL_CEXPR_SYM_TARGET     8
#define QPOL_CEXPR_SYM_XTARGET   16
#define QPOL_CEXPR_SYM_L1L2      32
#define QPOL_CEXPR_SYM_L1H2      64
#define QPOL_CEXPR_SYM_H1L2     128
#define QPOL_CEXPR_SYM_H1H2     256
#define QPOL_CEXPR_SYM_L1H1     512
#define QPOL_CEXPR_SYM_L2H2    1024
/* op values */
#define QPOL_CEXPR_OP_EQ     1
#define QPOL_CEXPR_OP_NEQ    2
#define QPOL_CEXPR_OP_DOM    3
#define QPOL_CEXPR_OP_DOMBY  4
#define QPOL_CEXPR_OP_INCOMP 5
typedef struct qpol_constraint_expr_node {} qpol_constraint_expr_node_t;
%extend qpol_constraint_expr_node_t {
	qpol_constraint_expr_node_t(void *x) {
		return (qpol_constraint_expr_node_t*)x;
	};
	~qpol_constraint_expr_node_t() {
		/* no op */
		return;
	};
	int get_expr_type(qpol_policy_t *p) {
		uint32_t et;
		if (qpol_constraint_expr_node_get_expr_type(p, self, &et)) {
			SWIG_exception(SWIG_ValueError, "Could not get expression type for node");
		}
	fail:
		return (int) et;
	};
	int get_sym_type(qpol_policy_t *p) {
		uint32_t st;
		if (qpol_constraint_expr_node_get_sym_type(p, self, &st)) {
			SWIG_exception(SWIG_ValueError, "Could not get symbol type for node");
		}
	fail:
		return (int) st;
	};
	int get_op(qpol_policy_t *p) {
		uint32_t op;
		if (qpol_constraint_expr_node_get_op(p, self, &op)) {
			SWIG_exception(SWIG_ValueError, "Could not get operator for node");
		}
	fail:
		return (int) op;
	};
	%newobject get_names_iter;
	qpol_iterator_t *get_names_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_constraint_expr_node_get_names_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
};

/* qpol role allow */
typedef struct qpol_role_allow {} qpol_role_allow_t;
%extend qpol_role_allow_t {
	qpol_role_allow_t(void *x) {
		return (qpol_role_allow_t*)x;
	};
	~qpol_role_allow_t() {
		/* no op */
		return;
	};
	qpol_role_t *get_source_role(qpol_policy_t *p) {
		qpol_role_t *r;
		if (qpol_role_allow_get_source_role(p, self, &r)) {
			SWIG_exception(SWIG_ValueError, "Could not get source for role allow rule");
		}
	fail:
		return r;
	};
	qpol_role_t *get_target_role(qpol_policy_t *p) {
		qpol_role_t *r;
		if (qpol_role_allow_get_target_role(p, self, &r)) {
			SWIG_exception(SWIG_ValueError, "Could not get target for role allow rule");
		}
	fail:
		return r;
	};
};

/* qpol role trans */
typedef struct qpol_role_trans {} qpol_role_trans_t;
%extend qpol_role_trans_t {
	qpol_role_trans_t(void *x) {
		return (qpol_role_trans_t*)x;
	};
	~qpol_role_trans_t() {
		/* no op */
		return;
	};
	qpol_role_t *get_source_role(qpol_policy_t *p) {
		qpol_role_t *r;
		if (qpol_role_trans_get_source_role(p, self, &r)) {
			SWIG_exception(SWIG_ValueError, "Could not get source for role_transition rule");
		}
	fail:
		return r;
	};
	qpol_type_t *get_target_type(qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_role_trans_get_target_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get target for role_transition rule");
		}
	fail:
		return t;
	};
	qpol_role_t *get_default_role(qpol_policy_t *p) {
		qpol_role_t *r;
		if (qpol_role_trans_get_default_role(p, self, &r)) {
			SWIG_exception(SWIG_ValueError, "Could not get default for role_transition rule");
		}
	fail:
		return r;
	};
};

/* qpol range trans */
typedef struct qpol_range_trans {} qpol_range_trans_t;
%extend qpol_range_trans_t {
	qpol_range_trans_t(void *x) {
		return (qpol_range_trans_t*)x;
	};
	~qpol_range_trans_t() {
		/* no op */
		return;
	};
	qpol_type_t *get_source_type (qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_range_trans_get_source_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get source for range_transition rule");
		}
	fail:
		return t;
	};
	qpol_type_t *get_target_type (qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_range_trans_get_target_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get target for range_transition rule");		}
	fail:
		return t;
	};
	qpol_class_t *get_target_class(qpol_policy_t *p) {
		qpol_class_t *cls;
		if (qpol_range_trans_get_target_class(p, self, &cls)) {
			SWIG_exception(SWIG_ValueError, "Could not get class for range_transition rule");		}
	fail:
		return cls;
	};
	qpol_mls_range_t *get_range(qpol_policy_t *p) {
		qpol_mls_range_t *r;
		if (qpol_range_trans_get_range(p, self, &r)) {
			SWIG_exception(SWIG_ValueError, "Could not get range for range_transition rule");
		}
	fail:
		return r;
	};
};

/* qpol av rule */
#define QPOL_RULE_ALLOW         1
#define QPOL_RULE_NEVERALLOW  128
#define QPOL_RULE_AUDITALLOW    2
#define QPOL_RULE_DONTAUDIT     4
typedef struct qpol_avrule {} qpol_avrule_t;
%extend qpol_avrule_t {
	qpol_avrule_t(void *x) {
		return (qpol_avrule_t*)x;
	};
	~qpol_avrule_t() {
		/* no op */
		return;
	};
	int get_rule_type(qpol_policy_t *p) {
		uint32_t rt;
		if (qpol_avrule_get_rule_type(p, self, &rt)) {
			SWIG_exception(SWIG_ValueError, "Could not get rule type for av rule");
		}
	fail:
		return (int) rt;
	};
	qpol_type_t *get_source_type(qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_avrule_get_source_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get source for av rule");
		}
	fail:
		return t;
	};
	qpol_type_t *get_target_type(qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_avrule_get_target_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get target for av rule");
		}
	fail:
		return t;
	};
	qpol_class_t *get_object_class(qpol_policy_t *p) {
		qpol_class_t *cls;
		if (qpol_avrule_get_object_class(p, self, &cls)) {
			SWIG_exception(SWIG_ValueError, "Could not get class for av rule");
		}
	fail:
		return cls;
	};
	%newobject get_perm_iter(qpol_policy_t *p);
	qpol_iterator_t *get_perm_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_avrule_get_perm_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	qpol_cond_t *get_cond(qpol_policy_t *p) {
		qpol_cond_t *c;
		if (qpol_avrule_get_cond(p, self, &c)) {
			SWIG_exception(SWIG_ValueError, "Could not get conditional for av rule");
		}
	fail:
		return c;
	};
	int get_is_enabled(qpol_policy_t *p) {
		uint32_t e;
		if (qpol_avrule_get_is_enabled(p, self, &e)) {
			SWIG_exception(SWIG_ValueError, "Could not determine if av rule is enabled");
		}
	fail:
		return (int) e;
	};
	int get_which_list(qpol_policy_t *p) {
		qpol_cond_t *c;
		uint32_t which = 0;
		qpol_avrule_get_cond(p, self, &c);
		if (c == NULL) {
			SWIG_exception(SWIG_TypeError, "Rule is not conditional");
		} else if (qpol_avrule_get_which_list(p, self, &which)) {
			SWIG_exception(SWIG_ValueError, "Could not get conditional list for av rule");
		}
	fail:
		return (int) which;
	};
	%newobject get_syn_avrule_iter();
	qpol_iterator_t *get_syn_avrule_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_avrule_get_syn_avrule_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
};

/* qpol te rule */
#define QPOL_RULE_TYPE_TRANS   16
#define QPOL_RULE_TYPE_CHANGE  64
#define QPOL_RULE_TYPE_MEMBER  32
typedef struct qpol_terule {} qpol_terule_t;
%extend qpol_terule_t {
	qpol_terule_t(void *x) {
		return (qpol_terule_t*)x;
	};
	~qpol_terule_t() {
		/* no op */
		return;
	};
	int get_rule_type(qpol_policy_t *p) {
		uint32_t rt;
		if (qpol_terule_get_rule_type(p, self, &rt)) {
			SWIG_exception(SWIG_ValueError, "Could not get rule type for te rule");
		}
	fail:
		return (int) rt;
	};
	qpol_type_t *get_source_type(qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_terule_get_source_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get source for te rule");
		}
	fail:
		return t;
	};
	qpol_type_t *get_target_type(qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_terule_get_target_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get target for te rule");
		}
	fail:
		return t;
	};
	qpol_class_t *get_object_class(qpol_policy_t *p) {
		qpol_class_t *cls;
		if (qpol_terule_get_object_class(p, self, &cls)) {
			SWIG_exception(SWIG_ValueError, "Could not get class for te rule");
		}
	fail:
		return cls;
	};
	qpol_type_t *get_default_type(qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_terule_get_default_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get default for te rule");
		}
	fail:
		return t;
	};
	qpol_cond_t *get_cond(qpol_policy_t *p) {
		qpol_cond_t *c;
		if (qpol_terule_get_cond(p, self, &c)) {
			SWIG_exception(SWIG_ValueError, "Could not get conditional for te rule");
		}
	fail:
		return c;
	};
	int get_is_enabled(qpol_policy_t *p) {
		uint32_t e;
		if (qpol_terule_get_is_enabled(p, self, &e)) {
			SWIG_exception(SWIG_ValueError, "Could not determine if te rule is enabled");
		}
	fail:
		return (int) e;
	};
	int get_which_list(qpol_policy_t *p) {
		qpol_cond_t *c;
		uint32_t which = 0;
		qpol_terule_get_cond(p, self, &c);
		if (c == NULL) {
			SWIG_exception(SWIG_TypeError, "Rule is not conditional");
		} else if (qpol_terule_get_which_list(p, self, &which)) {
			SWIG_exception(SWIG_ValueError, "Could not get conditional list for te rule");
		}
	fail:
		return (int) which;
	};
	%newobject get_syn_terule_iter();
	qpol_iterator_t *get_syn_terule_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_terule_get_syn_terule_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
};

/* qpol conditional */
typedef struct qpol_cond {} qpol_cond_t;
%extend qpol_cond_t {
	qpol_cond_t(void *x) {
		return (qpol_cond_t*)x;
	};
	~qpol_cond_t() {
		/* no op */
		return;
	};
	%newobject get_expr_node_iter();
	qpol_iterator_t *get_expr_node_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_cond_get_expr_node_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	%newobject get_av_true_iter();
	qpol_iterator_t *get_av_true_iter(qpol_policy_t *p, int rule_types) {
		qpol_iterator_t *iter;
		if (qpol_cond_get_av_true_iter(p, self, rule_types, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	%newobject get_av_false_iter();
	qpol_iterator_t *get_av_false_iter(qpol_policy_t *p, int rule_types) {
		qpol_iterator_t *iter;
		if (qpol_cond_get_av_false_iter(p, self, rule_types, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	%newobject get_te_true_iter();
	qpol_iterator_t *get_te_true_iter(qpol_policy_t *p, int rule_types) {
		qpol_iterator_t *iter;
		if (qpol_cond_get_te_true_iter(p, self, rule_types, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	%newobject get_te_false_iter();
	qpol_iterator_t *get_te_false_iter(qpol_policy_t *p, int rule_types) {
		qpol_iterator_t *iter;
		if (qpol_cond_get_te_false_iter(p, self, rule_types, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return iter;
	};
	int eval(qpol_policy_t *p) {
		uint32_t e;
		if (qpol_cond_eval(p, self, &e)) {
			SWIG_exception(SWIG_RuntimeError, "Could not evaluate conditional");
		}
	fail:
		return (int) e;
	};
};

/* qpol conditional expression node */
#define QPOL_COND_EXPR_BOOL 1      /* plain bool */
#define QPOL_COND_EXPR_NOT  2      /* !bool */
#define QPOL_COND_EXPR_OR   3      /* bool || bool */
#define QPOL_COND_EXPR_AND  4      /* bool && bool */
#define QPOL_COND_EXPR_XOR  5      /* bool ^ bool */
#define QPOL_COND_EXPR_EQ   6      /* bool == bool */
#define QPOL_COND_EXPR_NEQ  7      /* bool != bool */
typedef struct qpol_cond_expr_node {} qpol_cond_expr_node_t;
%extend qpol_cond_expr_node_t {
	qpol_cond_expr_node_t(void *x) {
		return (qpol_cond_expr_node_t*)x;
	};
	~qpol_cond_expr_node_t() {
		/* no op */
		return;
	};
	int get_expr_type(qpol_policy_t *p) {
		uint32_t et;
		if (qpol_cond_expr_node_get_expr_type(p, self, &et)) {
			SWIG_exception(SWIG_ValueError, "Could not get node expression type");
		}
	fail:
		return (int) et;
	};
	qpol_bool_t *get_bool(qpol_policy_t *p) {
		uint32_t et;
		qpol_bool_t *b = NULL;
		qpol_cond_expr_node_get_expr_type(p, self, &et);
		if (et != QPOL_COND_EXPR_BOOL) {
			SWIG_exception(SWIG_TypeError, "Node does not contain a boolean");
		} else if (qpol_cond_expr_node_get_bool(p, self, &b)) {
			SWIG_exception(SWIG_ValueError, "Could not get boolean for node");
		}
	fail:
		return b;
	};
};

/* qpol type set */
typedef struct qpol_type_set {} qpol_type_set_t;
%extend qpol_type_set_t {
	qpol_type_set_t(void *x) {
		return (qpol_type_set_t*)x;
	};
	~qpol_type_set_t() {
		/* no op */
		return;
	};
	%newobject get_included_types_iter();
	qpol_iterator_t *get_included_types_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_type_set_get_included_types_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	%newobject get_subtracted_types_iter();
	qpol_iterator_t *get_subtracted_types_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_type_set_get_subtracted_types_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	int get_is_star(qpol_policy_t *p) {
		uint32_t s;
		if (qpol_type_set_get_is_star(p, self, &s)) {
			SWIG_exception(SWIG_ValueError, "Could not determine if type set contains star");
		}
	fail:
		return (int) s;
	};
	int get_is_comp(qpol_policy_t *p) {
		uint32_t c;
		if (qpol_type_set_get_is_comp(p, self, &c)) {
			SWIG_exception(SWIG_ValueError, "Could not determine if type set is complemented");
		}
	fail:
		return (int) c;
	};
};

/* qpol syn av rule */
typedef struct qpol_syn_avrule {} qpol_syn_avrule_t;
%extend qpol_syn_avrule_t {
	qpol_syn_avrule_t(void *x) {
		return (qpol_syn_avrule_t*)x;
	};
	~qpol_syn_avrule_t() {
		/* no op */
		return;
	};
	int get_rule_type(qpol_policy_t *p) {
		uint32_t rt;
		if (qpol_syn_avrule_get_rule_type(p, self, &rt)) {
			SWIG_exception(SWIG_ValueError, "Could not get rule type for syn av rule");
		}
	fail:
		return (int) rt;
	};
	qpol_type_set_t *get_source_type_set(qpol_policy_t *p) {
		qpol_type_set_t *ts;
		if (qpol_syn_avrule_get_source_type_set(p, self, &ts)) {
			SWIG_exception(SWIG_ValueError, "Could not get source type set for syn av rule");
		}
	fail:
		return ts;
	};
	qpol_type_set_t *get_target_type_set(qpol_policy_t *p) {
		qpol_type_set_t *ts;
		if (qpol_syn_avrule_get_target_type_set(p, self, &ts)) {
			SWIG_exception(SWIG_ValueError, "Could not get target type set for syn av rule");
		}
	fail:
		return ts;
	};
	int get_is_target_self(qpol_policy_t *p) {
		uint32_t i;
		if (qpol_syn_avrule_get_is_target_self(p, self, &i)) {
			SWIG_exception(SWIG_ValueError, "Could not determine if target is self for syn av rule");
		}
	fail:
		return (int) i;
	};
	%newobject get_class_iter();
	qpol_iterator_t *get_class_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_syn_avrule_get_class_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	%newobject get_perm_iter();
	qpol_iterator_t *get_perm_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_syn_avrule_get_perm_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return iter;
	};
	long get_lineno(qpol_policy_t *p) {
		unsigned long l;
		if (qpol_syn_avrule_get_lineno(p, self, &l)) {
			SWIG_exception(SWIG_ValueError, "Could not get line number for syn av rule");
		}
	fail:
		return (long)l;
	};
	qpol_cond_t *get_cond(qpol_policy_t *p) {
		qpol_cond_t *c;
		if (qpol_syn_avrule_get_cond(p, self, &c)) {
			SWIG_exception(SWIG_ValueError, "Could not get conditional for syn av rule");
		}
	fail:
		return c;
	};
	int get_is_enabled(qpol_policy_t *p) {
		uint32_t e;
		if (qpol_syn_avrule_get_is_enabled(p, self, &e)) {
			SWIG_exception(SWIG_ValueError, "Could not determine if syn av rule is enabled");
		}
	fail:
		return e;
	};
};

/* qpol syn te rule */
typedef struct qpol_syn_terule {} qpol_syn_terule_t;
%extend qpol_syn_terule_t {
	qpol_syn_terule_t(void *x) {
		return (qpol_syn_terule_t*)x;
	};
	~qpol_syn_terule_t() {
		/* no op */
		return;
	};
	int get_rule_type(qpol_policy_t *p) {
		uint32_t rt;
		if (qpol_syn_terule_get_rule_type(p, self, &rt)) {
			SWIG_exception(SWIG_ValueError, "Could not get rule type for syn te rule");
		}
	fail:
		return rt;
	};
	qpol_type_set_t *get_source_type_set(qpol_policy_t *p) {
		qpol_type_set_t *ts;
		if (qpol_syn_terule_get_source_type_set(p, self, &ts)) {
			SWIG_exception(SWIG_ValueError, "Could not get source type set for syn te rule");
		}
	fail:
		return ts;
	};
	qpol_type_set_t *get_target_type_set(qpol_policy_t *p) {
		qpol_type_set_t *ts;
		if (qpol_syn_terule_get_target_type_set(p, self, &ts)) {
			SWIG_exception(SWIG_ValueError, "Could not get target type set for syn te rule");
		}
	fail:
		return ts;
	};
	%newobject get_class_iter();
	qpol_iterator_t *get_class_iter(qpol_policy_t *p) {
		qpol_iterator_t *iter;
		if (qpol_syn_terule_get_class_iter(p, self, &iter)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return iter;
	};
	qpol_type_t *get_default_type(qpol_policy_t *p) {
		qpol_type_t *t;
		if (qpol_syn_terule_get_default_type(p, self, &t)) {
			SWIG_exception(SWIG_ValueError, "Could not get default type for syn te rule");
		}
	fail:
		return t;
	};
	long get_lineno(qpol_policy_t *p) {
		unsigned long l;
		if (qpol_syn_terule_get_lineno(p, self, &l)) {
			SWIG_exception(SWIG_ValueError, "Could not get line number for syn te rule");
		}
	fail:
		return (long)l;
	};
	qpol_cond_t *get_cond(qpol_policy_t *p) {
		qpol_cond_t *c;
		if (qpol_syn_terule_get_cond(p, self, &c)) {
			SWIG_exception(SWIG_ValueError, "Could not get conditional for syn te rule");
		}
	fail:
		return c;
	};
	int get_is_enabled(qpol_policy_t *p) {
		uint32_t e;
		if (qpol_syn_terule_get_is_enabled(p, self, &e)) {
			SWIG_exception(SWIG_ValueError, "Could not determine if syn te rule is enabled");
		}
	fail:
		return (int) e;
	};
};
