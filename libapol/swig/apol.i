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

%{
#include <apol/avl-util.h>
#include <apol/avrule-query.h>
#include <apol/bool-query.h>
#include <apol/bst.h>
#include <apol/class-perm-query.h>
#include <apol/condrule-query.h>
#include <apol/constraint-query.h>
#include <apol/context-query.h>
#include <apol/domain-trans-analysis.h>
#include <apol/fscon-query.h>
#include <apol/infoflow-analysis.h>
#include <apol/isid-query.h>
#include <apol/mls-query.h>
#include <apol/netcon-query.h>
#include <apol/perm-map.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <apol/policy-query.h>
#include <apol/range_trans-query.h>
#include <apol/rbacrule-query.h>
#include <apol/relabel-analysis.h>
#include <apol/render.h>
#include <apol/role-query.h>
#include <apol/terule-query.h>
#include <apol/type-query.h>
#include <apol/types-relation-analysis.h>
#include <apol/user-query.h>
#include <apol/util.h>
#include <apol/vector.h>
%}

#ifdef SWIGJAVA
%javaconst(1);
/* get the java environment so we can throw exceptions */
%{
	static JNIEnv *jenv;
	jint JNI_OnLoad(JavaVM *vm, void *reserved) {
		(*vm)->AttachCurrentThread(vm, (void **)&jenv, NULL);
		return JNI_VERSION_1_2;
	}
%}
#endif

%include exception.i
%include stdint.i
%import qpol.i

#ifdef SWIGJAVA

/* handle size_t correctly in java as architecture independent */
%typemap(jni) size_t "jlong"
%typemap(jtype) size_t "long"
%typemap(jstype) size_t "long"
%typemap("javaimports") SWIGTYPE %{import com.tresys.setools.qpol.*;%}
%typemap(javabody) SWIGTYPE %{
    private long swigCPtr;
    protected boolean swigCMemOwn;

    public $javaclassname(long cPtr, boolean cMemoryOwn) {
        swigCMemOwn = cMemoryOwn;
        swigCPtr = cPtr;
    }

    public static long getCPtr($javaclassname obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }
%}
/* the following handles the dependencies on qpol */
%pragma(java) jniclassimports=%{import com.tresys.setools.qpol.*;%}
%pragma(java) jniclasscode=%{
	static {
		System.loadLibrary("japol");
	}
%}
%pragma(java) moduleimports=%{import com.tresys.setools.qpol.*;%}
#else
/* not in java so handle size_t as architecture dependent */
#ifdef SWIGWORDSIZE64
typedef uint64_t size_t;
#else
typedef uint32_t size_t;
#endif
#endif

#ifdef SWIGJAVA
/* if java, pass the new exception macro to C not just SWIG */
#undef SWIG_exception
#define SWIG_exception(code, msg) {SWIG_JavaException(jenv, code, msg); goto fail;}
%inline %{
#undef SWIG_exception
#define SWIG_exception(code, msg) {SWIG_JavaException(jenv, code, msg); goto fail;}
%}
#endif

#ifdef SWIGTCL
/* implement a custom non thread-safe error handler */
%{
static char *message = NULL;
static void tcl_clear_error(void)
{
        free(message);
        message = NULL;
}
static void tcl_throw_error(const char *s)
{
	free(message);
	message = strdup(s);
}
static char *tcl_get_error(void)
{
	return message;
}
#undef SWIG_exception
#define SWIG_exception(code, msg) {tcl_throw_error(msg); goto fail;}
%}

%wrapper %{
/* Tcl module's initialization routine is expected to be named
 * Apol_Init(), but the output file will be called libtapol.so instead
 * of libapol.so.  Therefore add an alias from Tapol_Init() to the
 * real Apol_Init().
 */
SWIGEXPORT int Tapol_Init(Tcl_Interp *interp) {
	return SWIG_init(interp);
}
%}

%exception {
	char *err;
	tcl_clear_error();
	$action
	if ((err = tcl_get_error()) != NULL) {
                Tcl_Obj *obj = Tcl_NewStringObj(message, -1);
                Tcl_ResetResult(interp);
                Tcl_SetObjResult(interp, obj);
		goto fail;
	}
}
#undef SWIG_exception
#define SWIG_exception(code, msg) {tcl_throw_error(msg); goto fail;}
#endif


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
%newobject wrap_apol_str_to_internal_ip;
%rename(apol_str_to_internal_ip) wrap_apol_str_to_internal_ip;

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
	uint32_t *wrap_apol_str_to_internal_ip(char *str) {
		uint32_t *ip = calloc(4, sizeof(uint32_t));
		int retv = 0;
		if (!ip) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		retv = apol_str_to_internal_ip(str, ip);
		if (retv < 0) {
			SWIG_exception(SWIG_RuntimeError, "Could not convert string to ip");
		}
	fail:
		return ip;
	}
%}
const char *apol_objclass_to_str(uint32_t objclass);
const char *apol_fs_use_behavior_to_str(uint32_t behavior);
int apol_str_to_fs_use_behavior(const char *behavior);
const char *apol_rule_type_to_str(uint32_t rule_type);
const char *apol_cond_expr_type_to_str(uint32_t expr_type);

/* directly include and wrap */
%include "apol/render.h"

/* derived vector type here */
%inline %{
	typedef struct apol_string_vector apol_string_vector_t;
%}
typedef struct apol_vector {} apol_vector_t;
%extend apol_vector_t {
	apol_vector_t() {
		return apol_vector_create(NULL);
	};
	apol_vector_t(qpol_iterator_t *iter) {
		return apol_vector_create_from_iter(iter, NULL);
	};
	apol_vector_t(apol_vector_t *v) {
		return apol_vector_create_from_vector(v, NULL, NULL, NULL);
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
		apol_vector_destroy(&self);
	};
	void append(void *x) {
		if (apol_vector_append(self, x)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void append_unique(void *x) {
		if (apol_vector_append_unique(self, x, NULL, NULL)) {
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
		apol_vector_sort_uniquify(self, NULL, NULL);
	};
};
%rename(apol_vector_compare) wrap_apol_vector_compare;
%inline %{
	int wrap_apol_vector_compare(apol_vector_t *a, apol_vector_t *b) {
		size_t idx; /* tracks first difference - currently dropped */
		return apol_vector_compare(a, b, NULL, NULL, &idx);
	}
%}
typedef struct apol_string_vector {} apol_string_vector_t;
%extend apol_string_vector_t {
	apol_string_vector_t() {
		return (apol_string_vector_t*)apol_vector_create(free);
	};
	apol_string_vector_t(apol_string_vector_t *v) {
		return (apol_string_vector_t*)apol_vector_create_from_vector((apol_vector_t*)v, apol_str_strdup, NULL, free);
	};
	apol_string_vector_t(apol_string_vector_t *a, apol_string_vector_t *b) {
		return (apol_string_vector_t*)apol_vector_create_from_intersection((apol_vector_t*)a, (apol_vector_t*)b, apol_str_strcmp, NULL);
	};
	size_t get_size() {
		return apol_vector_get_size((apol_vector_t*)self);
	};
	size_t get_capacity() {
		return apol_vector_get_capacity((apol_vector_t*)self);
	};
	char *get_element(size_t i) {
		return (char*)apol_vector_get_element((apol_vector_t*)self, i);
	};
	~apol_string_vector_t() {
		apol_vector_destroy((apol_vector_t**)&self);
	};
	size_t get_index(char *str) {
		size_t idx;
		if (apol_vector_get_index((apol_vector_t*)self, str, apol_str_strcmp, NULL, &idx))
			return apol_vector_get_size((apol_vector_t*)self) + 1;
		return idx;
	};
	void append(char *str) {
		char *tmp = strdup(str);
		if (!tmp || apol_vector_append((apol_vector_t*)self, tmp)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void append_unique(char *str) {
		char *tmp = strdup(str);
		if (!tmp || apol_vector_append_unique((apol_vector_t*)self, tmp, apol_str_strcmp, NULL)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void cat(apol_string_vector_t *src) {
		if (apol_vector_cat((apol_vector_t*)self, (apol_vector_t*)src)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return;
	};
	void remove(size_t idx) {
		char *x = apol_vector_get_element((apol_vector_t*)self, idx);
		if (apol_vector_remove((apol_vector_t*)self, idx)) {
			SWIG_exception(SWIG_RuntimeError, "Error removing vector element");
		}
		free(x);
	fail:
			return;
	};
	void sort() {
		apol_vector_sort((apol_vector_t*)self, apol_str_strcmp, NULL);
	};
	void sort_uniquify() {
		apol_vector_sort_uniquify((apol_vector_t*)self, apol_str_strcmp, NULL);
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
		if ((p = apol_policy_path_create(type, primary,	(apol_vector_t*)modules)) == NULL) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return p;
	};
	apol_policy_path_t(char *path) {
		apol_policy_path_t *p;
		if ((p = apol_policy_path_create_from_file(path)) == NULL) {
			SWIG_exception(SWIG_RuntimeError, "Input/output error");
		}
	fail:
		return p;
	};
	apol_policy_path_t(char *str, int unused) {
		apol_policy_path_t *p;
		if ((p = apol_policy_path_create_from_string(str)) == NULL) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return p;
	};
	apol_policy_path_t(apol_policy_path_t *in) {
		apol_policy_path_t *p;
		if ((p = apol_policy_path_create_from_policy_path(in)) == NULL) {
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
		return (apol_string_vector_t*)apol_policy_path_get_modules(self);
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
	void to_file(char *path) {
		if (apol_policy_path_to_file(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Input/outpet error");
		}
	fail:
		return;
	};
};
int apol_policy_path_compare(const apol_policy_path_t * a, const apol_policy_path_t * b);
int apol_file_is_policy_path_list(const char *filename);

/* apol policy */
typedef struct apol_policy {} apol_policy_t;
#define APOL_PERMMAP_MAX_WEIGHT 10
#define APOL_PERMMAP_MIN_WEIGHT 1
#define APOL_PERMMAP_UNMAPPED	0x00
#define	APOL_PERMMAP_READ	0x01
#define APOL_PERMMAP_WRITE	0x02
#define APOL_PERMMAP_BOTH	(APOL_PERMMAP_READ | APOL_PERMMAP_WRITE)
#define APOL_PERMMAP_NONE	0x10
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
	void load_permmap(char *path) {
		if (apol_permmap_load(self, path) < 0) {
			SWIG_exception(SWIG_RuntimeError, "Error loading permission map");
		}
	fail:
		return;
	};
	void save_permmap(char *path) {
		if (apol_permmap_save(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not save permission map");
		}
	fail:
		return;
	};
	int get_permmap_weight(char *class_name, char *perm_name) {
		int dir, weight;
		if (apol_permmap_get(self, class_name, perm_name, &dir, &weight)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get permission map weight");
		}
	fail:
		return weight;
	};
	int get_permmap_direction(char *class_name, char *perm_name) {
		int dir, weight;
		if (apol_permmap_get(self, class_name, perm_name, &dir, &weight)) {
			SWIG_exception(SWIG_RuntimeError, "Could not get permission map direction");
		}
	fail:
		return dir;
	};
	void permmap_set(char *class_name, char *perm_name, int direction, int weight) {
		if (apol_permmap_set(self, class_name, perm_name, direction, weight)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set permission mapping");
		}
	fail:
		return;
	};
	void build_domain_trans_table() {
		if (apol_policy_domain_trans_table_build(self)) {
			SWIG_exception(SWIG_RuntimeError, "Could not build domain transition table");
		}
	fail:
		return;
	};
	void reset_domain_trans_table() {
		apol_domain_trans_table_reset(self);
	}
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
	const char *get_sens() {
		return apol_mls_level_get_sens(self);
	};
	void append_cats(apol_policy_t *p, char *cats) {
		if (apol_mls_level_append_cats(p, self, cats)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append level category");
		}
	fail:
		return;
	};
	const apol_vector_t *get_cats() {
		return apol_mls_level_get_cats(self);
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
#ifdef SWIGPYTHON
%typemap(in) apol_mls_level_t *lvl {
	void *x = NULL;
	Py_IncRef($input);
	SWIG_ConvertPtr($input, &x,SWIGTYPE_p_apol_mls_level, 0 |  0 );
	$1 = (apol_mls_level_t*)x;
}
#endif
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
	apol_vector_t *get_levels(apol_policy_t *p) {
		apol_vector_t *v;
		v = apol_mls_range_get_levels(p, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
			return v;
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
#ifdef SWIGPYTHON
%typemap(in) apol_mls_range_t *rng {
	void *x = NULL;
	Py_IncRef($input);
	SWIG_ConvertPtr($input, &x,SWIGTYPE_p_apol_mls_range, 0 |  0 );
	$1 = (apol_mls_range_t*)x;
}
#endif
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
		return apol_context_get_user(self);
	};
	void set_role(apol_policy_t *p, char *name) {
		if (apol_context_set_role(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	const char *get_role() {
		return apol_context_get_role(self);
	};
	void set_type(apol_policy_t *p, char *name) {
		if (apol_context_set_type(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	const char *get_type() {
		return apol_context_get_type(self);
	};
	void set_range(apol_policy_t *p, apol_mls_range_t *rng) {
		if (apol_context_set_range(p, self, rng)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	const apol_mls_range_t *get_range() {
		return apol_context_get_range(self);
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
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_constraint_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run constraint query");
		}
	fail:
		return v;
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
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_validatetrans_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run validatetrans query");
		}
	fail:
		return v;
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
#ifdef SWIGPYTHON
%typemap(in) apol_context_t *ctx {
	void *x = NULL;
	Py_IncRef($input);
	SWIG_ConvertPtr($input, &x,SWIGTYPE_p_apol_context, 0 |  0 );
	$1 = (apol_context_t*)x;
}
#endif
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
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_genfscon_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run validatetrans query");
		}
	fail:
		return v;
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

/* apol initial sid query */
typedef struct apol_isid_query {} apol_isid_query_t;
%extend apol_isid_query_t {
	apol_isid_query_t() {
		apol_isid_query_t *aiq;
		aiq = apol_isid_query_create();
		if (!aiq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return aiq;
	};
	~apol_isid_query_t() {
		apol_isid_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_isid_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run initial sid query");
		}
	fail:
		return v;
	};
	void set_name(apol_policy_t *p, char *name) {
		if (apol_isid_query_set_name(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_context(apol_policy_t *p, apol_context_t *ctx, int range_match) {
		apol_isid_query_set_context(p, self, ctx, range_match);
	};
};

/* apol portcon query */
typedef struct apol_portcon_query {} apol_portcon_query_t;
%extend apol_portcon_query_t {
	apol_portcon_query_t() {
		apol_portcon_query_t *apq;
		apq = apol_portcon_query_create();
		if (!apq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return apq;
	};
	~apol_portcon_query_t() {
		apol_portcon_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_portcon_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run portcon query");
		}
	fail:
		return v;
	};
	void set_proto(apol_policy_t *p, int protocol) {
		apol_portcon_query_set_proto(p, self, protocol);
	};
	void set_low(apol_policy_t *p, int port) {
		apol_portcon_query_set_low(p, self, port);
	};
	void set_high(apol_policy_t *p, int port) {
		apol_portcon_query_set_high(p, self, port);
	};
	void set_context(apol_policy_t *p, apol_context_t *ctx, int range_match) {
		apol_portcon_query_set_context(p, self, ctx, range_match);
	};
};
%newobject apol_portcon_render();
char *apol_portcon_render(apol_policy_t * p, qpol_portcon_t * portcon);

/* apol netifcon query */
typedef struct apol_netifcon_query {} apol_netifcon_query_t;
%extend apol_netifcon_query_t {
	apol_netifcon_query_t() {
		apol_netifcon_query_t *anq;
		anq = apol_netifcon_query_create();
		if (!anq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return anq;
	};
	~apol_netifcon_query_t() {
		apol_netifcon_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_netifcon_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run netifcon query");
		}
	fail:
		return v;
	};
	void set_device(apol_policy_t *p, char *name) {
		if (apol_netifcon_query_set_device(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_if_context(apol_policy_t *p, apol_context_t *ctx, int range_match) {
		apol_netifcon_query_set_if_context(p, self, ctx, range_match);
	};
	void set_msg_context(apol_policy_t *p, apol_context_t *ctx, int range_match) {
		apol_netifcon_query_set_msg_context(p, self, ctx, range_match);
	};
};
%newobject apol_netifcon_render();
char *apol_netifcon_render(apol_policy_t * p, qpol_netifcon_t * netifcon);

/* apol nodecon query */
typedef struct apol_nodecon_query {} apol_nodecon_query_t;
%extend apol_nodecon_query_t {
	apol_nodecon_query_t() {
		apol_nodecon_query_t *anq;
		anq = apol_nodecon_query_create();
		if (!anq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return anq;
	};
	~apol_nodecon_query_t() {
		apol_nodecon_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_nodecon_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run nodecon query");
		}
	fail:
		return v;
	};
	void set_proto(apol_policy_t *p, int protocol) {
		if (apol_nodecon_query_set_proto(p, self, protocol)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set protocol for nodecon query");
		}
	fail:
		return;
	};
	void set_addr(apol_policy_t *p, uint32_t *addr, int protocol) {
		if (apol_nodecon_query_set_addr(p, self, addr, protocol)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set address for nodecon query");
		}
	fail:
		return;
	};
	void set_mask(apol_policy_t *p, uint32_t *mask, int protocol) {
		if (apol_nodecon_query_set_mask(p, self, mask, protocol)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set mask for nodecon query");
		}
	fail:
		return;
	};
	void set_context(apol_policy_t *p, apol_context_t *ctx, int range_match) {
		apol_nodecon_query_set_context(p, self, ctx, range_match);
	};
};
%newobject apol_nodecon_render();
char *apol_nodecon_render(apol_policy_t * p, qpol_nodecon_t * nodecon);

/* apol avrule query */
typedef struct apol_avrule_query {} apol_avrule_query_t;
%extend apol_avrule_query_t {
	apol_avrule_query_t() {
		apol_avrule_query_t *avq;
		avq = apol_avrule_query_create();
		if (!avq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return avq;
	};
	~apol_avrule_query_t() {
		apol_avrule_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_avrule_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run avrule query");
		}
	fail:
		return v;
	};
	%newobject run_syn();
	apol_vector_t *run_syn(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_syn_avrule_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run avrule query");
		}
	fail:
		return v;
	};
	void set_rules(apol_policy_t *p, int rules) {
		apol_avrule_query_set_rules(p, self, rules);
	};
	void set_source(apol_policy_t *p, char *name, int indirect) {
		if (apol_avrule_query_set_source(p, self, name, indirect)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source for avrule query");
		}
	fail:
		return;
	};
	void set_source_component(apol_policy_t *p, int component) {
		if (apol_avrule_query_set_source_component(p, self, component)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source component for avrule query");
		}
	fail:
		return;
	};
	void set_target(apol_policy_t *p, char *name, int indirect) {
		if (apol_avrule_query_set_target(p, self, name, indirect)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set target for avrule query");
		}
	fail:
		return;
	};
	void set_target_component(apol_policy_t *p, int component) {
		if (apol_avrule_query_set_target_component(p, self, component)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set target component for avrule query");
		}
	fail:
		return;
	};
	void append_class(apol_policy_t *p, char *name) {
		if (apol_avrule_query_append_class(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append class to avrule query");
		}
	fail:
		return;
	};
	void append_perm(apol_policy_t *p, char *name) {
		if (apol_avrule_query_append_perm(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append permission to avrule query");
		}
	fail:
		return;
	};
	void set_bool(apol_policy_t *p, char *name) {
		if (apol_avrule_query_set_bool(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set boolean for avrule query");
		}
	fail:
		return;
	};
	void set_enabled(apol_policy_t *p, int enabled) {
		apol_avrule_query_set_enabled(p, self, enabled);
	};
	void set_all_perms(apol_policy_t *p, int all_perms) {
		apol_avrule_query_set_all_perms(p, self, all_perms);
	};
	void set_source_any(apol_policy_t *p, int is_any) {
		apol_avrule_query_set_source_any(p, self, is_any);
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_avrule_query_set_regex(p, self, regex);
	};
};
%newobject apol_avrule_render();
char *apol_avrule_render(apol_policy_t * policy, qpol_avrule_t * rule);
%newobject apol_syn_avrule_render();
char *apol_syn_avrule_render(apol_policy_t * policy, qpol_syn_avrule_t * rule);
%newobject wrap_apol_avrule_to_syn_avrules;
%rename(apol_avrule_to_syn_avrules) wrap_apol_avrule_to_syn_avrules;
%newobject wrap_apol_avrule_list_to_syn_avrules;
%rename(apol_avrule_list_to_syn_avrules) wrap_apol_avrule_list_to_syn_avrules;
%inline %{
	apol_vector_t *wrap_apol_avrule_to_syn_avrules(apol_policy_t *p, qpol_avrule_t *rule, apol_string_vector_t *perms) {
		apol_vector_t *v;
		v = apol_avrule_to_syn_avrules(p, rule, (apol_vector_t*)perms);
		if (!v) {
			SWIG_exception(SWIG_RuntimeError, "Could not convert avrule to syntactic avrules");
		}
	fail:
		return v;
	}
	apol_vector_t *wrap_apol_avrule_list_to_syn_avrules(apol_policy_t *p, apol_vector_t *rules, apol_string_vector_t *perms) {
		apol_vector_t *v;
		v = apol_avrule_list_to_syn_avrules(p, rules, (apol_vector_t*)perms);
		if (!v) {
			SWIG_exception(SWIG_RuntimeError, "Could not convert avrules to syntactic avrules");
		}
	fail:
		return v;
	}
%}

/* apol terule query */
typedef struct apol_terule_query {} apol_terule_query_t;
%extend apol_terule_query_t {
	apol_terule_query_t() {
		apol_terule_query_t *atq;
		atq = apol_terule_query_create();
		if (!atq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return atq;
	};
	~apol_terule_query_t() {
		apol_terule_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_terule_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run terule query");
		}
	fail:
		return v;
	};
	%newobject run_syn();
	apol_vector_t *run_syn(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_syn_terule_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run terule query");
		}
	fail:
		return v;
	};
	void set_rules(apol_policy_t *p, int rules) {
		apol_terule_query_set_rules(p, self, rules);
	};
	void set_source(apol_policy_t *p, char *name, int indirect) {
		if (apol_terule_query_set_source(p, self, name, indirect)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source for terule query");
		}
	fail:
		return;
	};
	void set_source_component(apol_policy_t *p, int component) {
		if (apol_terule_query_set_source_component(p, self, component)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source component for terule query");
		}
	fail:
		return;
	};
	void set_target(apol_policy_t *p, char *name, int indirect) {
		if (apol_terule_query_set_target(p, self, name, indirect)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set target for terule query");
		}
	fail:
		return;
	};
	void set_target_component(apol_policy_t *p, int component) {
		if (apol_terule_query_set_target_component(p, self, component)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set target component for terule query");
		}
	fail:
		return;
	};
	void append_class(apol_policy_t *p, char *name) {
		if (apol_terule_query_append_class(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append class to terule query");
		}
	fail:
		return;
	};
	void set_default(apol_policy_t *p, char *name) {
		if (apol_terule_query_set_default(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set default for terule query");
		}
	fail:
		return;
	};
	void set_bool(apol_policy_t *p, char *name) {
		if (apol_terule_query_set_bool(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set boolean for terule query");
		}
	fail:
		return;
	};
	void set_enabled(apol_policy_t *p, int enabled) {
		apol_terule_query_set_enabled(p, self, enabled);
	};
	void set_source_any(apol_policy_t *p, int is_any) {
		apol_terule_query_set_source_any(p, self, is_any);
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_terule_query_set_regex(p, self, regex);
	};
};
%newobject apol_terule_render();
char *apol_terule_render(apol_policy_t * policy, qpol_terule_t * rule);
%newobject apol_syn_terule_render();
char *apol_syn_terule_render(apol_policy_t * policy, qpol_syn_terule_t * rule);
%newobject apol_terule_to_syn_terules();
apol_vector_t *apol_terule_to_syn_terules(apol_policy_t * p, qpol_terule_t * rule);
%newobject apol_terule_list_to_syn_terules();
apol_vector_t *apol_terule_list_to_syn_terules(apol_policy_t * p, apol_vector_t * rules);

/* apol cond rule query */
typedef struct apol_cond_query {} apol_cond_query_t;
%extend apol_cond_query_t {
	apol_cond_query_t() {
		apol_cond_query_t *acq;
		acq = apol_cond_query_create();
		if (!acq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return acq;
	};
	~apol_cond_query_t() {
		apol_cond_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_cond_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run condiional query");
		}
	fail:
		return v;
	};
	void set_bool(apol_policy_t *p, char *name) {
		if (apol_cond_query_set_bool(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set boolean for condiional query");
		}
	fail:
		return;
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_cond_query_set_regex(p, self, regex);
	};
};
%newobject apol_cond_expr_render();
char *apol_cond_expr_render(apol_policy_t * p, qpol_cond_t * cond);

/* apol role allow query */
typedef struct apol_role_allow_query {} apol_role_allow_query_t;
%extend apol_role_allow_query_t {
	apol_role_allow_query_t() {
		apol_role_allow_query_t *arq;
		arq = apol_role_allow_query_create();
		if (!arq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return arq;
	};
	~apol_role_allow_query_t() {
		apol_role_allow_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_role_allow_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run role allow query");
		}
	fail:
		return v;
	};
	void set_source(apol_policy_t *p, char *name) {
		if (apol_role_allow_query_set_source(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_target(apol_policy_t *p, char *name) {
		if (apol_role_allow_query_set_target(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_source_any(apol_policy_t *p, int is_any) {
		apol_role_allow_query_set_source_any(p, self, is_any);
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_role_allow_query_set_regex(p, self, regex);
	};
};
%newobject apol_role_allow_render();
char *apol_role_allow_render(apol_policy_t * policy, qpol_role_allow_t * rule);

/* apol role transition rule query */
typedef struct apol_role_trans_query {} apol_role_trans_query_t;
%extend apol_role_trans_query_t {
	apol_role_trans_query_t() {
		apol_role_trans_query_t *arq;
		arq = apol_role_trans_query_create();
		if (!arq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return arq;
	};
	~apol_role_trans_query_t() {
		apol_role_trans_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_role_trans_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run role transition query");
		}
	fail:
		return v;
	};
	void set_source(apol_policy_t *p, char *name) {
		if (apol_role_trans_query_set_source(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_target(apol_policy_t *p, char *name, int indirect) {
		if (apol_role_trans_query_set_target(p, self, name, indirect)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_default(apol_policy_t *p, char *name) {
		if (apol_role_trans_query_set_default(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_source_any(apol_policy_t *p, int is_any) {
		apol_role_trans_query_set_source_any(p, self, is_any);
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_role_trans_query_set_regex(p, self, regex);
	};
};
%newobject apol_role_trans_render();
char *apol_role_trans_render(apol_policy_t * policy, qpol_role_trans_t * rule);

/* apol range transition rule query */
typedef struct apol_range_trans_query {} apol_range_trans_query_t;
%extend apol_range_trans_query_t {
	apol_range_trans_query_t() {
		apol_range_trans_query_t *arq;
		arq = apol_range_trans_query_create();
		if (!arq) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return arq;
	};
	~apol_range_trans_query_t() {
		apol_range_trans_query_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_range_trans_get_by_query(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run range transition query");
		}
	fail:
		return v;
	};
	void set_source(apol_policy_t *p, char *name, int indirect) {
		if (apol_range_trans_query_set_source(p, self, name, indirect)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_target(apol_policy_t *p, char *name, int indirect) {
		if (apol_range_trans_query_set_target(p, self, name, indirect)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void append_class(apol_policy_t *p, char *name) {
		if (apol_range_trans_query_append_class(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append class to range transition query");
		}
	fail:
		return;
	};
	void set_range(apol_policy_t *p, apol_mls_range_t *rng, int range_match) {
		if (apol_range_trans_query_set_range(p, self, rng, range_match)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_source_any(apol_policy_t *p, int is_any) {
		apol_range_trans_query_set_source_any(p, self, is_any);
	};
	void set_regex(apol_policy_t *p, int regex) {
		apol_range_trans_query_set_regex(p, self, regex);
	};
};
%newobject apol_range_trans_render();
char *apol_range_trans_render(apol_policy_t * policy, qpol_range_trans_t * rule);

/* domain transition analysis */
#define APOL_DOMAIN_TRANS_DIRECTION_FORWARD 0x01
#define APOL_DOMAIN_TRANS_DIRECTION_REVERSE 0x02
#define APOL_DOMAIN_TRANS_SEARCH_VALID		0x01
#define APOL_DOMAIN_TRANS_SEARCH_INVALID	0x02
#define APOL_DOMAIN_TRANS_SEARCH_BOTH		(APOL_DOMAIN_TRANS_SEARCH_VALID|APOL_DOMAIN_TRANS_SEARCH_INVALID)
typedef struct apol_domain_trans_analysis {} apol_domain_trans_analysis_t;
%extend apol_domain_trans_analysis_t {
	apol_domain_trans_analysis_t() {
		apol_domain_trans_analysis_t *dta;
		dta = apol_domain_trans_analysis_create();
		if (!dta) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return dta;
	};
	~apol_domain_trans_analysis_t() {
		apol_domain_trans_analysis_destroy(&self);
	};
	void set_direction(apol_policy_t *p, int direction) {
		if (apol_domain_trans_analysis_set_direction(p, self, (unsigned char)direction)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set direction for domain transition analysis");
		}
	fail:
		return;
	};
	void set_valid(apol_policy_t *p, int valid) {
		if (apol_domain_trans_analysis_set_valid(p, self, (unsigned char)valid)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set valid flag for domain transition analysis");
		}
	fail:
		return;
	};
	void set_start_type(apol_policy_t *p, char *name) {
		if (apol_domain_trans_analysis_set_start_type(p, self, name)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void set_result_regex(apol_policy_t *p, char *regex) {
		if (apol_domain_trans_analysis_set_result_regex(p, self, regex)) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return;
	};
	void append_access_type(apol_policy_t *p, char *name) {
		if (apol_domain_trans_analysis_append_access_type(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append access type for domain transition analysis");
		}
	fail:
		return;
	};
	void append_class_perm(apol_policy_t *p, char *class_name, char *perm_name) {
		if (apol_domain_trans_analysis_append_class_perm(p, self, class_name, perm_name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append access class and permission for domain transition analysis");
		}
	fail:
		return;
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_domain_trans_analysis_do(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run domain transition analysis");
		}
	fail:
		return v;
	};
};
typedef struct apol_domain_trans_result {} apol_domain_trans_result_t;
%extend apol_domain_trans_result_t {
	apol_domain_trans_result_t(void *x) {
		return (apol_domain_trans_result_t*)x;
	};
	apol_domain_trans_result_t(apol_domain_trans_result_t *in) {
		apol_domain_trans_result_t *dtr;
		dtr = apol_domain_trans_result_create_from_domain_trans_result(in);
		if (!dtr) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return dtr;
	};
	~apol_domain_trans_result_t() {
		apol_domain_trans_result_destroy(&self);
	};
	const qpol_type_t *get_start_type() {
		return apol_domain_trans_result_get_start_type(self);
	};
	const qpol_type_t *get_entrypoint_type() {
		return apol_domain_trans_result_get_entrypoint_type(self);
	};
	const qpol_type_t *get_end_type() {
		return apol_domain_trans_result_get_end_type(self);
	};
	int get_is_valid() {
		return apol_domain_trans_result_is_trans_valid(self);
	};
	const apol_vector_t *get_proc_trans_rules() {
		return apol_domain_trans_result_get_proc_trans_rules(self);
	};
	const apol_vector_t *get_entrypoint_rules() {
		return apol_domain_trans_result_get_entrypoint_rules(self);
	};
	const apol_vector_t *get_exec_rules() {
		return apol_domain_trans_result_get_exec_rules(self);
	};
	const apol_vector_t *get_setexec_rules() {
		return apol_domain_trans_result_get_setexec_rules(self);
	};
	const apol_vector_t *get_type_trans_rules() {
		return apol_domain_trans_result_get_type_trans_rules(self);
	};
	const apol_vector_t *get_access_rules() {
		return apol_domain_trans_result_get_access_rules(self);
	};
};
#define APOL_DOMAIN_TRANS_RULE_PROC_TRANS       0x01
#define APOL_DOMAIN_TRANS_RULE_EXEC             0x02
#define APOL_DOMAIN_TRANS_RULE_EXEC_NO_TRANS    0x04
#define APOL_DOMAIN_TRANS_RULE_ENTRYPOINT       0x08
#define APOL_DOMAIN_TRANS_RULE_TYPE_TRANS       0x10
#define APOL_DOMAIN_TRANS_RULE_SETEXEC          0x20
int apol_domain_trans_table_verify_trans(apol_policy_t * policy, qpol_type_t * start_dom, qpol_type_t * ep_type,	qpol_type_t * end_dom);

/* apol infoflow analysis */
%{
	typedef struct apol_infoflow {
		apol_infoflow_graph_t *g;
		apol_vector_t *v;
	} apol_infoflow_t;
	apol_infoflow_t *apol_infoflow_create() {
		return calloc(1, sizeof(apol_infoflow_t));
	}
	void apol_infoflow_destroy(apol_infoflow_t **in) {
		if (!in || !(*in)) {
			return;
		}
		free(*in); /* NOTE: does not free contents intentionally */
		*in = NULL;
	}
%}
typedef struct apol_infoflow {} apol_infoflow_t;
%extend apol_infoflow_t {
	apol_infoflow_t() {
		SWIG_exception(SWIG_RuntimeError, "Cannot directly create apol_infoflow_t objects");
	fail:
		return NULL;
	};
	~apol_infoflow_t() {
		apol_infoflow_destroy(&self);
	};
	%newobject extract_graph();
	apol_infoflow_graph_t *extract_graph() {
		apol_infoflow_graph_t *g = self->g;
		self->g = NULL;
		return g;
	};
	%newobject extract_result_vector();
	apol_vector_t *extract_result_vector() {
		apol_vector_t *v = self->v;
		self->v = NULL;
		return v;
	};
};
typedef struct apol_infoflow_analysis {} apol_infoflow_analysis_t;
%extend apol_infoflow_analysis_t {
	apol_infoflow_analysis_t() {
		apol_infoflow_analysis_t *aia;
		aia = apol_infoflow_analysis_create();
		if (!aia) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return aia;
	};
	~apol_infoflow_analysis_t() {
		apol_infoflow_analysis_destroy(&self);
	};
	%newobject run();
	apol_infoflow_t *run(apol_policy_t *p) {
		apol_infoflow_t *ai = apol_infoflow_create();
		if (!ai) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		if (apol_infoflow_analysis_do(p, self, &ai->v, &ai->g)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run information flow analysis");
		}
		return ai;
	fail:
		apol_vector_destroy(&ai->v);
		apol_infoflow_graph_destroy(&ai->g);
		apol_infoflow_destroy(&ai);
		return NULL;
	};
	void set_mode(apol_policy_t *p, int mode) {
		if (apol_infoflow_analysis_set_mode(p, self, (unsigned int)mode)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set mode for information flow analysis");
		}
	fail:
		return;
	};
	void set_direction(apol_policy_t *p, int direction) {
		if (apol_infoflow_analysis_set_dir(p, self, (unsigned int)direction)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set direction for information flow analysis");
		}
	fail:
		return;
	};
	void set_type(apol_policy_t *p, char *name) {
		if (apol_infoflow_analysis_set_type(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set type for information flow analysis");
		}
	fail:
		return;
	};
	void append_intermediate(apol_policy_t *p, char *name) {
		if (apol_infoflow_analysis_append_intermediate(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append intermediate type for information flow analysis");
		}
	fail:
		return;
	};
	void append_class_perm(apol_policy_t *p, char *class_name, char *perm_name) {
		if (apol_infoflow_analysis_append_class_perm(p, self, class_name, perm_name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append class and permission for information flow analysis");
		}
	fail:
		return;
	};
	void set_min_weight(apol_policy_t *p, int weight) {
		apol_infoflow_analysis_set_min_weight(p, self, weight);
	};
	void set_result_regex(apol_policy_t *p, char *regex) {
		if (apol_infoflow_analysis_set_result_regex(p, self, regex)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set result regular expression for information flow analysis");
		}
	fail:
		return;
	};
};
typedef struct apol_infoflow_graph {} apol_infoflow_graph_t;
%extend apol_infoflow_graph_t {
	apol_infoflow_graph_t() {
		SWIG_exception(SWIG_RuntimeError, "Cannot directly create apol_infoflow_graph_t objects");
	fail:
		return NULL;
	};
	~apol_infoflow_graph_t() {
		apol_infoflow_graph_destroy(&self);
	};
	%newobject do_more();
	apol_vector_t *do_more(apol_policy_t *p, char *type) {
		apol_vector_t *v;
		if (apol_infoflow_analysis_do_more(p, self, type, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not do more analysis of information flow graph");
		}
	fail:
		return v;
	};
	void trans_further_prepare(apol_policy_t *p, char *start_type, char *end_type) {
		if (apol_infoflow_analysis_trans_further_prepare(p, self, start_type, end_type)) {
			SWIG_exception(SWIG_MemoryError, "Error preparing graph for further information flow analysis");
		}
	fail:
		return;
	};
	void trans_further_next(apol_policy_t *p, apol_vector_t *v) {
		if (apol_infoflow_analysis_trans_further_next(p, self, (&v))) {
			SWIG_exception(SWIG_RuntimeError, "Could not run further analysis");
		}
	fail:
		return;
	};
};
typedef struct apol_infoflow_result {} apol_infoflow_result_t;
%extend apol_infoflow_result_t {
	apol_infoflow_result_t(void *x) {
		return (apol_infoflow_result_t*)x;
	};
	~apol_infoflow_result_t() {
		/* no op - vector will destroy */
		return;
	};
	int get_dir() {
		return (int)apol_infoflow_result_get_dir(self);
	};
	const qpol_type_t *get_start_type() {
		return apol_infoflow_result_get_start_type(self);
	};
	const qpol_type_t *get_end_type() {
		return apol_infoflow_result_get_end_type(self);
	};
	int get_length() {
		return (int) apol_infoflow_result_get_length(self);
	}
	const apol_vector_t *get_steps() {
		return apol_infoflow_result_get_steps(self);
	};
};
typedef struct apol_infoflow_step {} apol_infoflow_step_t;
%extend apol_infoflow_step_t {
	apol_infoflow_step_t(void *x) {
		return (apol_infoflow_step_t*)x;
	};
	~apol_infoflow_step_t() {
		/* no op */
		return;
	};
	const qpol_type_t *get_start_type() {
		return apol_infoflow_step_get_start_type(self);
	};
	const qpol_type_t *get_end_type() {
		return apol_infoflow_step_get_end_type(self);
	};
	int get_weight() {
		return apol_infoflow_step_get_weight(self);
	};
	const apol_vector_t *get_rules() {
		return apol_infoflow_step_get_rules(self);
	};
};

/* apol relabel analysis */
#define APOL_RELABEL_DIR_TO      0x01
#define APOL_RELABEL_DIR_FROM    0x02
#define APOL_RELABEL_DIR_BOTH    (APOL_RELABEL_DIR_TO|APOL_RELABEL_DIR_FROM)
#define APOL_RELABEL_DIR_SUBJECT 0x04
typedef struct apol_relabel_analysis {} apol_relabel_analysis_t;
%extend apol_relabel_analysis_t {
	apol_relabel_analysis_t() {
		apol_relabel_analysis_t *ara;
		ara = apol_relabel_analysis_create();
		if (!ara) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return ara;
	};
	~apol_relabel_analysis_t() {
		apol_relabel_analysis_destroy(&self);
	};
	%newobject run();
	apol_vector_t *run(apol_policy_t *p) {
		apol_vector_t *v;
		if (apol_relabel_analysis_do(p, self, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run relabel analysis");
		}
	fail:
		return v;
	};
	void set_dir(apol_policy_t *p, int direction) {
		if (apol_relabel_analysis_set_dir(p, self, (unsigned int)direction)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set direction for relabel analysis");
		}
	fail:
		return;
	};
	void set_type(apol_policy_t *p, char *name) {
		if (apol_relabel_analysis_set_type(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set type for relabel analysis");
		}
	fail:
		return;
	};
	void append_class(apol_policy_t *p, char *name) {
		if (apol_relabel_analysis_append_class(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append class to relabel analysis");
		}
	fail:
		return;
	};
	void append_subject(apol_policy_t *p, char *name) {
		if (apol_relabel_analysis_append_subject(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append subject to relabel analysis");
		}
	fail:
		return;
	};
	void set_result_regex(apol_policy_t *p, char *regex) {
		if (apol_relabel_analysis_set_result_regex(p, self, regex)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set result regular expression for relabel analysis");
		}
	fail:
		return;
	};
};
typedef struct apol_relabel_result {} apol_relabel_result_t;
%extend apol_relabel_result_t {
	apol_relabel_result_t(void *x) {
		return (apol_relabel_result_t*)x;
	};
	~apol_relabel_result_t() {
		/* no op - vector will destroy */
		return;
	};
	const apol_vector_t *get_to() {
		return apol_relabel_result_get_to(self);
	};
	const apol_vector_t *get_from() {
		return apol_relabel_result_get_from(self);
	};
	const apol_vector_t *get_both() {
		return apol_relabel_result_get_both(self);
	};
	const qpol_type_t *get_result_type() {
		return apol_relabel_result_get_result_type(self);
	};
};
typedef struct apol_relabel_result_pair {} apol_relabel_result_pair_t;
%extend apol_relabel_result_pair_t {
	apol_relabel_result_pair_t(void *x) {
		return (apol_relabel_result_pair_t*)x;
	};
	~apol_relabel_result_pair_t() {
		/* no op - owned and free()'d by apol_relabel_result_t */
		return;
	};
	const qpol_avrule_t *get_ruleA() {
		return apol_relabel_result_pair_get_ruleA(self);
	};
	const qpol_avrule_t *get_ruleB() {
		return apol_relabel_result_pair_get_ruleB(self);
	};
	const qpol_type_t *get_intermediate_type() {
		return apol_relabel_result_pair_get_intermediate_type(self);
	};
};

/* apol type relation analysis */
#define APOL_TYPES_RELATION_COMMON_ATTRIBS 0x0001
#define APOL_TYPES_RELATION_COMMON_ROLES 0x0002
#define APOL_TYPES_RELATION_COMMON_USERS 0x0004
#define APOL_TYPES_RELATION_SIMILAR_ACCESS 0x0010
#define APOL_TYPES_RELATION_DISSIMILAR_ACCESS 0x0020
#define APOL_TYPES_RELATION_ALLOW_RULES 0x0100
#define APOL_TYPES_RELATION_TYPE_RULES 0x0200
#define APOL_TYPES_RELATION_DOMAIN_TRANS_AB 0x0400
#define APOL_TYPES_RELATION_DOMAIN_TRANS_BA 0x0800
#define APOL_TYPES_RELATION_DIRECT_FLOW 0x1000
#define APOL_TYPES_RELATION_TRANS_FLOW_AB 0x4000
#define APOL_TYPES_RELATION_TRANS_FLOW_BA 0x8000
typedef struct apol_types_relation_analysis {} apol_types_relation_analysis_t;
%extend apol_types_relation_analysis_t {
	apol_types_relation_analysis_t() {
		apol_types_relation_analysis_t *atr;
		atr = apol_types_relation_analysis_create();
		if (!atr) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return atr;
	};
	~apol_types_relation_analysis_t() {
		apol_types_relation_analysis_destroy(&self);
	}
	%newobject run();
	apol_types_relation_result_t *run(apol_policy_t *p) {
		apol_types_relation_result_t *res;
		if (apol_types_relation_analysis_do(p, self, &res)) {
			SWIG_exception(SWIG_RuntimeError, "Could not run types relation analysis");
		}
	fail:
		return res;
	};
	void set_first_type(apol_policy_t *p, char *name) {
		if (apol_types_relation_analysis_set_first_type(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set first type for types relation analysis");
		}
	fail:
		return;
	};
	void set_other_type(apol_policy_t *p, char *name) {
		if (apol_types_relation_analysis_set_other_type(p, self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set other type for types relation analysis");
		}
	fail:
		return;
	};
	void set_analyses(apol_policy_t *p, int analyses) {
		if (apol_types_relation_analysis_set_analyses(p, self, (unsigned int)analyses)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set analyses to run for types relation analysis");
		}
	fail:
		return;
	};
};
typedef struct apol_types_relation_result {} apol_types_relation_result_t;
%extend apol_types_relation_result_t {
	apol_types_relation_result_t() {
		SWIG_exception(SWIG_RuntimeError, "Cannot directly create apol_types_relation_result_t objects");
	fail:
		return NULL;
	};
	~apol_types_relation_result_t() {
		apol_types_relation_result_destroy(&self);
	};
	const apol_vector_t *get_attributes() {
		return apol_types_relation_result_get_attributes(self);
	};
	const apol_vector_t *get_roles() {
		return apol_types_relation_result_get_roles(self);
	};
	const apol_vector_t *get_users() {
		return apol_types_relation_result_get_users(self);
	};
	const apol_vector_t *get_similar_first() {
		return apol_types_relation_result_get_similar_first(self);
	};
	const apol_vector_t *get_similar_other() {
		return apol_types_relation_result_get_similar_other(self);
	};
	const apol_vector_t *get_dissimilar_first() {
		return apol_types_relation_result_get_dissimilar_first(self);
	};
	const apol_vector_t *get_similar_other() {
		return apol_types_relation_result_get_dissimilar_other(self);
	};
	const apol_vector_t *get_allowrules() {
		return apol_types_relation_result_get_allowrules(self);
	};
	const apol_vector_t *get_typerules() {
		return apol_types_relation_result_get_typerules(self);
	};
	const apol_vector_t *get_directflows() {
		return apol_types_relation_result_get_directflows(self);
	};
	const apol_vector_t *get_transflowsAB() {
		return apol_types_relation_result_get_transflowsAB(self);
	};
	const apol_vector_t *get_transflowsBA() {
		return apol_types_relation_result_get_transflowsBA(self);
	};
	const apol_vector_t*get_domainsAB() {
		return apol_types_relation_result_get_domainsAB(self);
	};
	const apol_vector_t*get_domainsBA() {
		return apol_types_relation_result_get_domainsBA(self);
	};
};
typedef struct apol_types_relation_access {} apol_types_relation_access_t;
%extend apol_types_relation_access_t {
	apol_types_relation_access_t(void *x) {
		return (apol_types_relation_access_t*)x;
	};
	~apol_types_relation_access_t() {
		/* no op - vector will destroy */
		return;
	};
	const qpol_type_t *get_type() {
		return apol_types_relation_access_get_type(self);
	};
	const apol_vector_t *get_rules() {
		return apol_types_relation_access_get_rules(self);
	};
};
