/**
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
#include "../include/apol/rangetrans-query.h"
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
	};
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

/* TODO */
%include "../include/apol/avrule-query.h"
%include "../include/apol/bool-query.h"
%include "../include/apol/class-perm-query.h"
%include "../include/apol/condrule-query.h"
%include "../include/apol/constraint-query.h"
%include "../include/apol/context-query.h"
%include "../include/apol/domain-trans-analysis.h"
%include "../include/apol/fscon-query.h"
%include "../include/apol/infoflow-analysis.h"
%include "../include/apol/isid-query.h"
%include "../include/apol/mls-query.h"
%include "../include/apol/netcon-query.h"
%include "../include/apol/perm-map.h"
%include "../include/apol/policy.h"
%include "../include/apol/policy-path.h"
%include "../include/apol/rangetrans-query.h"
%include "../include/apol/rbacrule-query.h"
%include "../include/apol/relabel-analysis.h"
%include "../include/apol/role-query.h"
%include "../include/apol/terule-query.h"
%include "../include/apol/type-query.h"
%include "../include/apol/types-relation-analysis.h"
%include "../include/apol/user-query.h"
%include "../include/apol/vector.h"
