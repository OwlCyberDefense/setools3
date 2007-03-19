/**
 * @file
 * SWIG declarations for libapol.
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

%module apol

#define __attribute__(x)

%{
#include "../include/apol/avl-util.h"
#include "../include/apol/avrule-query.h"
#include "../include/apol/bool-query.h"
#include "../include/apol/bst.h"
#include "../include/apol/class-perm-query.h"
#include "../include/apol/condrule-query.h"
#include "../include/apol/constraint-query.h"
#include "../include/apol/context-query.h"
#include "../include/apol/domain-trans-analysis.h"
#include "../include/apol/fscon-query.h"
#include "../include/apol/infoflow-analysis.h"
#include "../include/apol/isid-query.h"
#include "../include/apol/mls-query.h"
#include "../include/apol/netcon-query.h"
#include "../include/apol/perm-map.h"
#include "../include/apol/policy.h"
#include "../include/apol/policy-path.h"
#include "../include/apol/policy-query.h"
#include "../include/apol/range_trans-query.h"
#include "../include/apol/rbacrule-query.h"
#include "../include/apol/relabel-analysis.h"
#include "../include/apol/render.h"
#include "../include/apol/role-query.h"
#include "../include/apol/terule-query.h"
#include "../include/apol/type-query.h"
#include "../include/apol/types-relation-analysis.h"
#include "../include/apol/user-query.h"
#include "../include/apol/util.h"
#include "../include/apol/vector.h"
%}

%include exception.i

/* sized integer handling -
 * NOTE cannot include stdint.h here as seig does not parse it right
 * also some integer types are treated identically in many target languages */
%typedef unsigned char uint8_t;
%typedef unsigned int uint32_t;
%typedef unsigned long size_t;

/* defines from policy-query.h */
/* Many libapol queries act upon MLS contexts.  Use these defines to
 * specify set operations upon contexts.
 */
#define APOL_QUERY_SUB	 0x02	       /* query is subset of rule range */
#define APOL_QUERY_SUPER 0x04	       /* query is superset of rule range */
#define APOL_QUERY_EXACT (APOL_QUERY_SUB|APOL_QUERY_SUPER)
#define APOL_QUERY_INTERSECT 0x08      /* query overlaps any part of rule range */
#define APOL_QUERY_FLAGS \
	(APOL_QUERY_SUB | APOL_QUERY_SUPER | APOL_QUERY_EXACT | \
	 APOL_QUERY_INTERSECT)
/* The AV rule search and TE rule search use these flags when
 * specifying what kind of symbol is being searched.  Strings are
 * normally interpreted either as a type or as an attribute; the behavior
 * can be changed to use only types or only attributes.
 */
#define APOL_QUERY_SYMBOL_IS_TYPE 0x01
#define APOL_QUERY_SYMBOL_IS_ATTRIBUTE 0x02

/* from util.h */
const char *libapol_get_version(void);
/* defines from netinet/in.h for ip protocols */
#define IPPROTO_TCP  6
#define IPPROTO_UDP 17
const char *apol_protocol_to_str(uint8_t protocol);
%typemap(newfree) uint32_t * "free($1);";
%rename(apol_str_to_internal_ipv6) wrap_apol_str_to_internal_ipv6;
%newobject wrap_apol_str_to_internal_ipv6;
%rename(apol_str_to_internal_ipv4) wrap_apol_str_to_internal_ipv4;
%inline %{
	uint32_t *wrap_apol_str_to_internal_ipv6(char *str) {
		uint32_t *ip = calloc(4, sizeof(uint32_t));
		int retv = 0;
		if (!ip) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		retv = apol_str_to_internal_ip(str, ip);
		if (retv < 0) {
			SWIG_exception(SWIG_RuntimeError, "Could not convert string to ip");
		} else if (retv == QPOL_IPV4) {
			SWIG_exception(SWIG_TypeError, "Address uses wrong protocol");
		}
	fail:
		return ip;
	}
	uint32_t wrap_apol_str_to_internal_ipv4(char *str) {
		uint32_t *ip = calloc(4, sizeof(uint32_t));
		int retv = 0;
		if (!ip) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		retv = apol_str_to_internal_ip(str, ip);
		if (retv < 0) {
			SWIG_exception(SWIG_RuntimeError, "Could not convert string to ip");
		} else if (retv == QPOL_IPV6) {
			SWIG_exception(SWIG_TypeError, "Address uses wrong protocol");
		}
	fail:
		return ip[0];
	}
%}
const char *apol_objclass_to_str(uint32_t objclass);
const char *apol_fs_use_behavior_to_str(uint32_t behavior);
int apol_str_to_fs_use_behavior(const char *behavior);
const char *apol_rule_type_to_str(uint32_t rule_type);
const char *apol_cond_expr_type_to_str(uint32_t expr_type);

/* directly include and wrap */
%include "../include/apol/render.h"

/* derived vector types here */
%inline %{
	typedef struct apol_vector apol_string_vector_t;
	typedef struct apol_vector apol_level_vector_t;
	typedef struct apol_vector apol_constraint_vector_t;
	typedef struct apol_vector apol_validatetrans_vector_t;
	typedef struct apol_vector apol_genfscon_vector_t;
%}
typedef struct apol_vector {} apol_vector_t;
%extend apol_vector_t {
	apol_vector_t() {
		return apol_vector_create();
	};
	apol_vector_t(qpol_iterator_t *iter) {
		return apol_vector_create_from_iter(iter);
	};
	apol_vector_t(apol_vector_t *v) {
		return apol_vector_create_from_vector(v, NULL, NULL);
	};
	apol_vector_t(apol_vector_t *a, apol_vector_t *b) {
		return apol_vector_create_from_intersection(a, b, NULL, NULL);
	};
	size_t get_size() {
		return apol_vector_get_size(self);
	};
	size_t get_capacity() {
		return apol_vector_get_capacity(self);
	};
	void *get_element(size_t i) {
		return apol_vector_get_element(self, i);
	};
	~apol_vector_t() {
		apol_vector_destroy(&self, NULL);
	};
	//TODO get_index ??
	void append(void *x) {
		if (apol_vector_append(self, x)) {
			SWIG_exception(SWIG_MemoryError, "Oout of memory");
		}
	fail:
		return;
	};
	void append_unique(void *x) {
		if (apol_vector_append_unique(self, x, NULL, NULL)) {
			SWIG_exception(SWIG_MemoryError, "Oout of memory");
		}
	fail:
		return;
	};
	void cat(apol_vector_t *src) {
		if (apol_vector_cat(self, src)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void remove(size_t idx) {
		if (apol_vector_remove(self, idx)) {
			SWIG_exception(SWIG_RuntimeError, "Error removing vector element");
		}
	fail:
		return;
	};
	void sort() {
		apol_vector_sort(self, NULL, NULL);
	};
	void sort_uniquify() {
		apol_vector_sort_uniquify(self, NULL, NULL, NULL);
	};
};
%rename(apol_vector_compare) wrap_apol_vector_compare;
%inline %{
	int wrap_apol_vector_compare(apol_vector_t *a, apol_vector_t *b) {
		size_t idx; /* tracks first difference - currently dropped */
		return apol_vector_compare(a, b, NULL, NULL, &idx);
	}
%}
typedef struct apol_vector {} apol_string_vector_t;
%extend apol_string_vector_t {
	apol_string_vector_t() {
		return (apol_string_vector_t*)apol_vector_create();
	};
	apol_string_vector_t(apol_string_vector_t *v) {
		return (apol_string_vector_t*)apol_vector_create_from_vector((apol_vector_t*)v, apol_str_strdup, NULL);
	};
	apol_string_vector_t(apol_string_vector_t *a, apol_string_vector_t *b) {
		return (apol_string_vector_t*)apol_vector_create_from_intersection((apol_vector_t*)a, (apol_vector_t*)b, apol_str_strcmp, NULL);
	};
	size_t get_size() {
		return apol_vector_get_size(self);
	};
	size_t get_capacity() {
		return apol_vector_get_capacity(self);
	};
	char *get_element(size_t i) {
		return (char*)apol_vector_get_element(self, i);
	};
	~apol_string_vector_t() {
		apol_vector_destroy(&self, free);
	};
	size_t get_index(char *str) {
		size_t idx;
		if (apol_vector_get_index(self, str, apol_str_strcmp, NULL, &idx))
			return apol_vector_get_size(self) + 1;
		return idx;
	};
	void append(char *str) {
		char *tmp = strdup(str);
		if (!tmp || apol_vector_append(self, tmp)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void append_unique(char *str) {
		char *tmp = strdup(str);
		if (!tmp || apol_vector_append_unique(self, tmp, apol_str_strcmp, NULL)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void cat(apol_vector_t *src) {
		if (apol_vector_cat(self, src)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return;
	};
	void remove(size_t idx) {
		char *x = apol_vector_get_element(self, idx);
		if (apol_vector_remove(self, idx)) {
			SWIG_exception(SWIG_RuntimeError, "Error removing vector element");
		}
		free(x);
	fail:
			return;
	};
	void sort() {
		apol_vector_sort(self, apol_str_strcmp, NULL);
	};
	void sort_uniquify() {
		apol_vector_sort_uniquify(self, apol_str_strcmp, NULL, free);
	};
};
typedef struct apol_vector {} apol_level_vector_t;
%extend apol_level_vector_t {
	apol_level_vector_t() {
		return (apol_level_vector_t*)apol_vector_create();
	};
	size_t get_size() {
		return apol_vector_get_size(self);
	};
	size_t get_capacity() {
		return apol_vector_get_capacity(self);
	};
	const apol_mls_level_t *get_element(size_t i) {
		return (const apol_mls_level_t*)apol_vector_get_element(self, i);
	};
	~apol_level_vector_t() {
		apol_vector_destroy(&self, apol_mls_level_free);
	};
};
typedef struct apol_vector {} apol_constraint_vector_t;
%extend apol_constraint_vector_t {
	apol_constraint_vector_t() {
		return (apol_constraint_vector_t*)apol_vector_create();
	};
	size_t get_size() {
		return apol_vector_get_size(self);
	};
	size_t get_capacity() {
		return apol_vector_get_capacity(self);
	};
	const qpol_constraint_t *get_element(size_t i) {
		return (const qpol_constraint_t*)apol_vector_get_element(self, i);
	};
	~apol_level_vector_t() {
		apol_vector_destroy(&self, free);
	};
};
typedef struct apol_vector {} apol_validatetrans_vector_t;
%extend apol_validatetrans_vector_t {
	apol_validatetrans_vector_t() {
		return (apol_validatetrans_vector_t*)apol_vector_create();
	};
	size_t get_size() {
		return apol_vector_get_size(self);
	};
	size_t get_capacity() {
		return apol_vector_get_capacity(self);
	};
	const qpol_validatetrans_t *get_element(size_t i) {
		return (const qpol_validatetrans_t*)apol_vector_get_element(self, i);
	};
	~apol_level_vector_t() {
		apol_vector_destroy(&self, free);
	};
};
typedef struct apol_vector {} apol_genfscon_vector_t;
%extend apol_genfscon_vector_t {
	apol_genfscon_vector_t() {
		return (apol_genfscon_vector_t*)apol_vector_create();
	};
	size_t get_size() {
		return apol_vector_get_size(self);
	};
	size_t get_capacity() {
		return apol_vector_get_capacity(self);
	};
	const qpol_genfscon_t *get_element(size_t i) {
		return (const qpol_genfscon_t*)apol_vector_get_element(self, i);
	};
	~apol_level_vector_t() {
		apol_vector_destroy(&self, free);
	};
};

/* apol policy path */
	typedef enum apol_policy_path_type
{
	APOL_POLICY_PATH_TYPE_MONOLITHIC = 0,
	APOL_POLICY_PATH_TYPE_MODULAR
} apol_policy_path_type_e;
typedef struct apol_policy_path {} apol_policy_path_t;
%extend apol_policy_path_t {
	apol_policy_path_t(apol_policy_path_type_e type, char * primary, apol_string_vector_t *modules = NULL) {
		apol_policy_path_t *p;
		if ((p = apol_policy_path_create(type, primary, modules))) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return p;
	};
	apol_policy_path_t(char *str) {
		apol_policy_path_t *p;
		if ((p = apol_policy_path_create_from_string(str))) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return p;
	};
	apol_policy_path_t(apol_policy_path_t *in) {
		apol_policy_path_t *p;
		if ((p = apol_policy_path_create_from_policy_path(in))) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return p;
	};
	~apol_policy_path_t() {
		apol_policy_path_destroy(&self);
	};
	apol_policy_path_type_e get_type() {
		return apol_policy_path_get_type(self);
	};
	const char *get_primary() {
		return apol_policy_path_get_primary(self);
	};
	const apol_string_vector_t *get_modules() {
		return apol_policy_path_get_modules(self);
	};
	%newobject to_string();
	char *to_string() {
		char *str;
		str = apol_policy_path_to_string(self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
};
int apol_policy_path_compare(const apol_policy_path_t * a, const apol_policy_path_t * b);

/* apol policy */
typedef struct apol_policy {} apol_policy_t;
%extend apol_policy_t {
	apol_policy_t(apol_policy_path_t *path, int options = 0) {
		apol_policy_t *p;
		/* TODO handle callback rather than force default */
		p = apol_policy_create_from_policy_path(path, options, NULL, NULL);
		if (!p) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return p;
	};
	~apol_policy_t() {
		apol_policy_destroy(&self);
	};
	int get_policy_type() {
		return apol_policy_get_policy_type(self);
	};
	qpol_policy_t *get_qpol() {
		return apol_policy_get_qpol(self);
	};
	int is_mls() {
		return apol_policy_is_mls(self);
	};
	%newobject get_version_type_mls_str();
	char *get_version_type_mls_str() {
		char *str;
		str = apol_policy_get_version_type_mls_str(self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
};

/* apol type query */
typedef struct apol_type_query {} apol_type_query_t;
%extend apol_type_query_t {
	apol_type_query_t() {
		apol_type_query_t *tq;
		tq = apol_type_query_create();
		if (!tq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return tq;
	};
	~apol_type_query_t() {
		apol_type_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_type_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run type query");
		}
	fail:
		return v;
	};
	void set_type(apol_policy_t *p, char *name) {
		if (apol_type_query_set_type(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_type_query_set_regex(p, self, regex);
	};
};

/* apol attribute query */
typedef struct apol_attr_query {} apol_attr_query_t;
%extend apol_attr_query_t {
	apol_attr_query_t() {
		apol_attr_query_t *aq;
		aq = apol_attr_query_create();
		if (!aq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return aq;
	};
	~apol_attr_query_t() {
		apol_attr_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_attr_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run attribute query");
		}
	fail:
		return v;
	};
	void set_attr(apol_policy_t *p, char *name) {
		if (apol_attr_query_set_attr(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_attr_query_set_regex(p, self, regex);
	};
};

/* apol role query */
typedef struct apol_role_query {} apol_role_query_t;
%extend apol_role_query_t {
	apol_role_query_t() {
		apol_role_query_t *rq;
		rq = apol_role_query_create();
		if (!rq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return rq;
	};
	~apol_role_query_t() {
		apol_role_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_role_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run role query");
		}
	fail:
		return v;
	};
	void set_role(apol_policy_t *p, char *name) {
		if (apol_role_query_set_role(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_type(apol_policy_t *p, char *name) {
		if (apol_role_query_set_type(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_role_query_set_regex(p, self, regex);
	};
};
int apol_role_has_type(apol_policy_t * p, qpol_role_t * r, qpol_type_t * t);

/* apol class query */
typedef struct apol_class_query {} apol_class_query_t;
%extend apol_class_query_t {
	apol_class_query_t() {
		apol_class_query_t *cq;
		cq = apol_class_query_create();
		if (!cq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return cq;
	};
	~apol_class_query_t() {
		apol_class_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_class_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run class query");
		}
	fail:
		return v;
	};
	void set_class(apol_policy_t *p, char *name) {
		if (apol_class_query_set_class(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_common(apol_policy_t *p, char *name) {
		if (apol_class_query_set_common(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_class_query_set_regex(p, self, regex);
	};
};

/* apol common query */
typedef struct apol_common_query {} apol_common_query_t;
%extend apol_common_query_t {
	apol_common_query_t() {
		apol_common_query_t *cq;
		cq = apol_common_query_create();
		if (!cq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return cq;
	};
	~apol_common_query_t() {
		apol_common_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_common_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run common query");
		}
	fail:
		return v;
	};
	void set_common(apol_policy_t *p, char *name) {
		if (apol_common_query_set_common(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_common_query_set_regex(p, self, regex);
	};
};

/* apol perm query */
typedef struct apol_perm_query {} apol_perm_query_t;
%extend apol_perm_query_t {
	apol_perm_query_t() {
		apol_perm_query_t *pq;
		pq = apol_perm_query_create();
		if (!pq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return pq;
	};
	~apol_perm_query_t() {
		apol_perm_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_perm_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run permission query");
		}
	fail:
		return v;
	};
	void set_perm(apol_policy_t *p, char *name) {
		if (apol_perm_query_set_perm(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_perm_query_set_regex(p, self, regex);
	};
};

/* apol bool query */
typedef struct apol_bool_query {} apol_bool_query_t;
%extend apol_bool_query_t {
	apol_bool_query_t() {
		apol_bool_query_t *bq;
		bq = apol_bool_query_create();
		if (!bq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return bq;
	};
	~apol_bool_query_t() {
		apol_bool_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_bool_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run boolean query");
		}
	fail:
		return v;
	};
	void set_bool(apol_policy_t *p, char *name) {
		if (apol_bool_query_set_bool(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_bool_query_set_regex(p, self, regex);
	};
};

/* apol mls level */
typedef struct apol_mls_level {} apol_mls_level_t;
%extend apol_mls_level_t {
	apol_mls_level_t() {
		apol_mls_level_t *aml;
		aml = apol_mls_level_create();
		if (!aml) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return aml;
	};
	apol_mls_level_t(apol_mls_level_t *in) {
		apol_mls_level_t *aml;
		aml = apol_mls_level_create_from_mls_level(in);
		if (!aml) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return aml;
	};
	apol_mls_level_t(apol_policy_t *p, char *str) {
		apol_mls_level_t *aml;
		aml = apol_mls_level_create_from_string(p, str);
		if (!aml) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return aml;
	};
	apol_mls_level_t(apol_policy_t *p, qpol_mls_level_t *qml) {
		apol_mls_level_t *aml;
		aml = apol_mls_level_create_from_qpol_mls_level(p, qml);
		if (!aml) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return aml;
	};
	apol_mls_level_t(apol_policy_t *p, qpol_level_t *ql) {
		apol_mls_level_t *aml;
		aml = apol_mls_level_create_from_qpol_level_datum(p, ql);
		if (!aml) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return aml;
	};
	apol_mls_level_t(void *x) {
		return (apol_mls_level_t*)x;
	};
	~apol_mls_level_t() {
		apol_mls_level_destroy(&self);
	};
	void set_sens(apol_policy_t *p, char *sens) {
		if (apol_mls_level_set_sens(p, self, sens)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set level sensitivity");
		}
	fail:
		return;
	};
	void append_cats(apol_policy_t *p, char *cats) {
		if (apol_mls_level_append_cats(p, self, cats)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append level category");
		}
	fail:
		return;
	};
	%newobject render();
	char *render(apol_policy_t *p) {
		char *str;
		str = apol_mls_level_render(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
};
#define APOL_MLS_EQ 0
#define APOL_MLS_DOM 1
#define APOL_MLS_DOMBY 2
#define APOL_MLS_INCOMP 3
int apol_mls_level_compare(apol_policy_t * p, const apol_mls_level_t * level1, const apol_mls_level_t * level2);
int apol_mls_sens_compare(apol_policy_t * p, const char *sens1, const char *sens2);
int apol_mls_cats_compare(apol_policy_t * p, const char *cat1, const char *cat2);

/* apol mls range */
typedef struct apol_mls_range {} apol_mls_range_t;
%extend apol_mls_range_t {
	apol_mls_range_t() {
		apol_mls_range_t *amr;
		amr = apol_mls_range_create();
		if (!amr) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return amr;
	};
	apol_mls_range_t(apol_mls_range_t *in) {
		apol_mls_range_t *amr;
		amr = apol_mls_range_create_from_mls_range(in);
		if (!amr) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return amr;
	};
	apol_mls_range_t(apol_policy_t *p, qpol_mls_range_t *in) {
		apol_mls_range_t *amr;
		amr = apol_mls_range_create_from_qpol_mls_range(p, in);
		if (!amr) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return amr;
	};
	apol_mls_range_t(void *x) {
		return (apol_mls_range_t*)x;
	};
	~apol_mls_range_t() {
		apol_mls_range_destroy(&self);
	};
	void set_low(apol_policy_t *p, apol_mls_level_t *lvl) {
		if (apol_mls_range_set_low(p, self, lvl)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set low level");
		}
	fail:
		return;
	};
	void set_high(apol_policy_t *p, apol_mls_level_t *lvl) {
		if (apol_mls_range_set_high(p, self, lvl)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set high level");
		}
	fail:
			return;
	};
	%newobject render();
	char *render(apol_policy_t *p) {
		char *str;
		str = apol_mls_range_render(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	%newobject get_levels();
	apol_level_vector_t *get_levels(apol_policy_t *p) {
		apol_vector_t *v;
		v = apol_mls_range_get_levels(p, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return (apol_level_vector_t*)v;
	};
};
int apol_mls_range_compare(apol_policy_t * p, const apol_mls_range_t * target, const apol_mls_range_t * search, unsigned int range_compare_type);
int apol_mls_range_contain_subrange(apol_policy_t * p, const apol_mls_range_t * range,	const apol_mls_range_t * subrange);
int apol_mls_range_validate(apol_policy_t * p, const apol_mls_range_t * range);

/* apol level query */
typedef struct apol_level_query {} apol_level_query_t;
%extend apol_level_query_t {
	apol_level_query_t() {
		apol_level_query_t * alq;
		alq = apol_level_query_create();
		if (!alq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return alq;
	};
	~apol_level_query_t() {
		apol_level_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_level_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run level query");
		}
	fail:
		return v;
	};
	void set_sens(apol_policy_t *p, char *name) {
		if (apol_level_query_set_sens(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_cat(apol_policy_t *p, char *name) {
		if (apol_level_query_set_cat(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_level_query_set_regex(p, self, regex);
	};
};

/* apol cat query */
typedef struct apol_cat_query {} apol_cat_query_t;
%extend apol_cat_query_t {
	apol_cat_query_t() {
		apol_cat_query_t * acq;
		acq = apol_cat_query_create();
		if (!acq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return acq;
	};
	~apol_cat_query_t() {
		apol_cat_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_cat_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run category query");
		}
	fail:
		return v;
	};
	void set_cat(apol_policy_t *p, char *name) {
		if (apol_cat_query_set_cat(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_cat_query_set_regex(p, self, regex);
	};
};

/* apol user query */
typedef struct apol_user_query {} apol_user_query_t;
%extend apol_user_query_t {
	apol_user_query_t() {
		apol_user_query_t *auq;
		auq = apol_user_query_create();
		if (!auq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return auq;
	};
	~apol_user_query_t() {
		apol_user_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_user_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run user query");
		}
	fail:
		return v;
	};
	void set_user(apol_policy_t *p, char *name) {
		if (apol_user_query_set_user(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_role(apol_policy_t *p, char *name) {
		if (apol_user_query_set_role(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_default_level(apol_policy_t *p, apol_mls_level_t *lvl) {
		if (apol_user_query_set_default_level(p, self, lvl)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_range(apol_policy_t *p, apol_mls_range_t *rng, int range_match) {
		if (apol_user_query_set_range(p, self, rng, range_match)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_user_query_set_regex(p, self, regex);
	};
};

/* apol context */
typedef struct apol_context {} apol_context_t;
%extend apol_context_t {
	apol_context_t() {
		apol_context_t *ctx;
		ctx = apol_context_create();
		if (!ctx) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return ctx;
	};
	apol_context_t(apol_policy_t *p, qpol_context_t *in) {
		apol_context_t *ctx;
		ctx = apol_context_create_from_qpol_context(p, in);
		if (!ctx) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
	return ctx;
	};
	~apol_context_t() {
		apol_context_destroy(&self);
	};
	void set_user(apol_policy_t *p, char *name) {
		if (apol_context_set_user(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	const char *get_user() {
		return self->user;
	};
	void set_role(apol_policy_t *p, char *name) {
		if (apol_context_set_role(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	const char *get_role() {
		return self->role;
	};
	void set_type(apol_policy_t *p, char *name) {
		if (apol_context_set_type(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	const char *get_type() {
		return self->type;
	};
	void set_range(apol_policy_t *p, apol_mls_range_t *rng) {
		if (apol_context_set_range(p, self, rng)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	const apol_mls_range_t *get_range() {
		return self->range;
	};
	%newobject render();
	char *render(apol_policy_t *p) {
		char *str;
		str = apol_context_render(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
};
int apol_context_compare(apol_policy_t * p, apol_context_t * target, apol_context_t * search, unsigned int range_compare_type);
int apol_context_validate(apol_policy_t * p, apol_context_t * context);
int apol_context_validate_partial(apol_policy_t * p, apol_context_t * context);

/* apol constraint query */
typedef struct apol_constraint_query {} apol_constraint_query_t;
%extend apol_constraint_query_t {
	apol_constraint_query_t() {
		apol_constraint_query_t *acq;
		acq = apol_constraint_query_create();
		if (!acq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return acq;
	};
	~apol_constraint_query_t() {
		apol_constraint_query_destroy(&self);
	};
	%newobject run();
	apol_constraint_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_constraint_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run constraint query");
		}
	fail:
		return (apol_constraint_vector_t*)v;
	};
	void set_class(apol_policy_t *p, char *name) {
		if (apol_constraint_query_set_class(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	}
	void set_perm(apol_policy_t *p, char *name) {
		if (apol_constraint_query_set_perm(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	}
	void set_regex(apol_policy_t *p, int regex) {
		apol_constraint_query_set_regex(p, self, regex);
	};
};

/* apol validatetrans query */
typedef struct apol_validatetrans_query {} apol_validatetrans_query_t;
%extend apol_validatetrans_query_t {
	apol_validatetrans_query_t() {
		apol_validatetrans_query_t *avq;
		avq = apol_validatetrans_query_create();
		if (!avq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return avq;
	};
	~apol_validatetrans_query_t() {
		apol_validatetrans_query_destroy(&self);
	};
	%newobject run();
	apol_validatetrans_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_validatetrans_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run validatetrans query");
		}
	fail:
		return (apol_validatetrans_vector_t*)v;
	};
	void set_class(apol_policy_t *p, char *name) {
		if (apol_validatetrans_query_set_class(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	}
	void set_regex(apol_policy_t *p, int regex) {
		apol_validatetrans_query_set_regex(p, self, regex);
	};
};

/* apol genfscon query */
typedef struct apol_genfscon_query {} apol_genfscon_query_t;
%extend apol_genfscon_query_t {
	apol_genfscon_query_t() {
		apol_genfscon_query_t *agq;
		agq = apol_genfscon_query_create();
		if (!agq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return agq;
	};
	~apol_genfscon_query_t() {
		apol_genfscon_query_destroy(&self);
	};
	%newobject run();
	apol_genfscon_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_genfscon_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run validatetrans query");
		}
	fail:
		return (apol_genfscon_vector_t*)v;
	};
	void set_filesystem(apol_policy_t *p, char *fs) {
		if (apol_genfscon_query_set_filesystem(p, self, fs)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_path(apol_policy_t *p, char *path) {
		if (apol_genfscon_query_set_path(p, self, path)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_objclass(apol_policy_t *p, int objclass) {
		if (apol_genfscon_query_set_objclass(p, self, objclass)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set object class for genfscon query");
		}
	fail:
		return;
	};
	void set_context(apol_policy_t *p, apol_context_t *ctx, int range_match) {
		apol_genfscon_query_set_context(p, self, ctx, range_match);
	};
};
%newobject apol_genfscon_render();
char *apol_genfscon_render(apol_policy_t * p, qpol_genfscon_t * genfscon);

/* apol fs_use query */
typedef struct apol_fs_use_query {} apol_fs_use_query_t;
%extend apol_fs_use_query_t {
	apol_fs_use_query_t() {
		apol_fs_use_query_t *afq;
		afq = apol_fs_use_query_create();
		if (!afq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return afq;
	};
	~apol_fs_use_query_t() {
		apol_fs_use_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_fs_use_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run fs_use query");
		}
	fail:
		return v;
	};
	void set_filesystem(apol_policy_t *p, char *fs) {
		if (apol_fs_use_query_set_filesystem(p, self, fs)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_behavior(apol_policy_t *p, int behavior) {
		if (apol_fs_use_query_set_behavior(p, self, behavior)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set behavior for fs_use query");
		}
	fail:
		return;
	};
	void set_context(apol_policy_t *p, apol_context_t *ctx, int range_match) {
		apol_fs_use_query_set_context(p, self, ctx, range_match);
	};
};
%newobject apol_fs_use_render();
char *apol_fs_use_render(apol_policy_t * p, qpol_fs_use_t * fsuse);

/* TODO */
%include "../include/apol/avrule-query.h"
%include "../include/apol/condrule-query.h"
%include "../include/apol/domain-trans-analysis.h"
%include "../include/apol/infoflow-analysis.h"
%include "../include/apol/isid-query.h"
%include "../include/apol/netcon-query.h"
%include "../include/apol/perm-map.h"
%include "../include/apol/range_trans-query.h"
%include "../include/apol/rbacrule-query.h"
%include "../include/apol/relabel-analysis.h"
%include "../include/apol/terule-query.h"
%include "../include/apol/types-relation-analysis.h"
