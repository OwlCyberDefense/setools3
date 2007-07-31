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

%{
#include <poldiff/attrib_diff.h>
#include <poldiff/avrule_diff.h>
#include <poldiff/bool_diff.h>
#include <poldiff/cat_diff.h>
#include <poldiff/class_diff.h>
#include <poldiff/level_diff.h>
#include <poldiff/poldiff.h>
#include <poldiff/range_diff.h>
#include <poldiff/range_trans_diff.h>
#include <poldiff/rbac_diff.h>
#include <poldiff/role_diff.h>
#include <poldiff/terule_diff.h>
#include <poldiff/type_diff.h>
#include <poldiff/type_map.h>
#include <poldiff/user_diff.h>
#include <poldiff/util.h>

/* Provide hooks so that language-specific modules can define the
 * callback function, used by the handler in poldiff_create().
 */
SWIGEXPORT poldiff_handle_fn_t poldiff_swig_message_callback = NULL;
SWIGEXPORT void * poldiff_swig_message_callback_arg = NULL;

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
%import apol.i

#ifdef SWIGJAVA

/* handle size_t correctly in java as architecture independent */
%typemap(jni) size_t "jlong"
%typemap(jtype) size_t "long"
%typemap(jstype) size_t "long"
%typemap("javaimports") SWIGTYPE %{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
%}
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
/* the following handles the dependencies on qpol and apol */
%pragma(java) jniclassimports=%{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
%}
%pragma(java) jniclasscode=%{
	static {
		try
		{
			libpoldiff_get_version ();
		}
		catch (UnsatisfiedLinkError ule)
		{
			System.loadLibrary("jpoldiff");
		}
	}
%}
%pragma(java) moduleimports=%{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
%}
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
#define SWIG_exception_typemap(code, msg) {SWIG_JavaException(jenv, code, msg);}
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
 * Poldiff_Init(), but the output file will be called libtpoldiff.so instead
 * of libpoldiff.so.  Therefore add an alias from Tpoldiff_Init() to the
 * real Poldiff_Init().
 */
SWIGEXPORT int Tpoldiff_Init(Tcl_Interp *interp) {
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

%inline %{
	typedef struct apol_string_vector apol_string_vector_t;
%}

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
#ifdef SWIGJAVA
		SWIG_exception_typemap(SWIG_ValueError, "Invalid diff flag specified");
#else
		SWIG_exception(SWIG_ValueError, "Invalid diff flag specified");
#endif
	}
}

%inline %{
/* if java, pass the new exception macro to C not just SWIG */
#ifdef SWIGJAVA
#undef SWIG_exception
#define SWIG_exception(code, msg) {SWIG_JavaException(jenv, code, msg); goto fail;}
#endif
%}

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
/* the following type maps handle the poldiff object taking ownership of the policies */
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
		p = poldiff_create(op, mp, poldiff_swig_message_callback, poldiff_swig_message_callback_arg);
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
	%newobject get_stats(uint32_t);
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
	const apol_vector_t *get_avrule_vector_allow() {
		return poldiff_get_avrule_vector_allow(self);
	};
	const apol_vector_t *get_avrule_vector_auditallow() {
		return poldiff_get_avrule_vector_auditallow(self);
	};
	const apol_vector_t *get_avrule_vector_dontaudit() {
		return poldiff_get_avrule_vector_dontaudit(self);
	};
	const apol_vector_t *get_avrule_vector_neverallow() {
		return poldiff_get_avrule_vector_neverallow(self);
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
	const apol_vector_t *get_terule_vector_change() {
		return poldiff_get_terule_vector_change(self);
	};
	const apol_vector_t *get_terule_vector_member() {
		return poldiff_get_terule_vector_member(self);
	};
	const apol_vector_t *get_terule_vector_trans() {
		return poldiff_get_terule_vector_trans(self);
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
   poldiff_attrib_t () {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_attrib_t objects");
   fail:
      return NULL;
   }
	~poldiff_attrib_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
%inline %{
	poldiff_attrib_t *poldiff_attrib_from_void(void *x) {
		return (poldiff_attrib_t*)x;
	};
%}

/* av rule diff */
typedef struct poldiff_avrule {} poldiff_avrule_t;
%extend poldiff_avrule_t {
   poldiff_avrule_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_avrule_t objects");
   fail:
      return NULL;
 	}
	~poldiff_avrule_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
		const qpol_cond_t *cond;
		uint32_t which_list;
		const apol_policy_t *which_pol;
		poldiff_avrule_get_cond(p, self, &cond, &which_list, &which_pol);
		return cond;
	};
	uint32_t get_cond_list(poldiff_t *p) {
		const qpol_cond_t *cond;
		uint32_t which_list;
		const apol_policy_t *which_pol;
		poldiff_avrule_get_cond(p, self, &cond, &which_list, &which_pol);
		return which_list;
	};
	const apol_policy_t *get_cond_policy(poldiff_t *p) {
		const qpol_cond_t *cond;
		uint32_t which_list;
		const apol_policy_t *which_pol;
		poldiff_avrule_get_cond(p, self, &cond, &which_list, &which_pol);
		return which_pol;
	};
	const apol_string_vector_t *get_unmodified_perms() {
		return (apol_string_vector_t*)poldiff_avrule_get_unmodified_perms(self);
	};
	const apol_string_vector_t *get_added_perms() {
		return (apol_string_vector_t*)poldiff_avrule_get_added_perms(self);
	};
	const apol_string_vector_t *get_removed_perms() {
		return (apol_string_vector_t*)poldiff_avrule_get_removed_perms(self);
	};
	const apol_vector_t *get_orig_line_numbers() {
		return poldiff_avrule_get_orig_line_numbers(self);
	};
	%newobject get_orig_line_numbers_for_perm(poldiff_t*, char*);
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
	%newobject get_mod_line_numbers_for_perm(poldiff_t*, char*);
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
%inline %{
	poldiff_avrule_t *poldiff_avrule_from_void(void *x) {
		return (poldiff_avrule_t*)x;
	};
%}

/* boolean diff */
typedef struct poldiff_bool {} poldiff_bool_t;
%extend poldiff_bool_t {
	poldiff_bool_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_bool_t objects");
   fail:
      return NULL;
 	}
	~poldiff_bool_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
%inline %{
	poldiff_bool_t *poldiff_bool_from_void(void *x) {
		return (poldiff_bool_t*)x;
	};
%}

/* category diff */
typedef struct poldiff_cat {} poldiff_cat_t;
%extend poldiff_cat_t {
	poldiff_cat_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_cat_t objects");
   fail:
      return NULL;
 	}
	~poldiff_cat_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
%inline %{
	poldiff_cat_t *poldiff_cat_from_void(void *x) {
		return (poldiff_cat_t*)x;
	};
%}

/* class diff */
typedef struct poldiff_class {} poldiff_class_t;
%extend poldiff_class_t {
	poldiff_class_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_class_t objects");
   fail:
      return NULL;
 	}
	~poldiff_class_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
%inline %{
	poldiff_class_t *poldiff_class_from_void(void *x) {
		return (poldiff_class_t*)x;
	};
%}

/* common diff */
typedef struct poldiff_common {} poldiff_common_t;
%extend poldiff_common_t {
	poldiff_common_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_common_t objects");
   fail:
      return NULL;
 	}
	~poldiff_common_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
%inline %{
	poldiff_common_t *poldiff_common_from_void(void *x) {
		return (poldiff_common_t*)x;
	};
%}

/* level diff */
typedef struct poldiff_level {} poldiff_level_t;
%extend poldiff_level_t {
	poldiff_level_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_level_t objects");
   fail:
      return NULL;
 	}
	~poldiff_level_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
	char *to_string(poldiff_t *p) {
		char *str;
		str = poldiff_level_to_string(p, self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	%newobject to_string_brief(poldiff_t*);
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
%inline %{
	poldiff_level_t *poldiff_level_from_void(void *x) {
		return (poldiff_level_t*)x;
	};
%}

/* range diff */
typedef struct poldiff_range {} poldiff_range_t;
%extend poldiff_range_t {
	poldiff_range_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_range_t objects");
   fail:
      return NULL;
 	}
	~poldiff_range_t() {
		/* no op */
		return;
	};
	%newobject to_string_brief(poldiff_t*);
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
	const apol_string_vector_t *get_min_added_cats() {
		return (apol_string_vector_t*)poldiff_range_get_min_added_cats(self);
	};
	const apol_string_vector_t *get_min_removed_cats() {
		return (apol_string_vector_t*)poldiff_range_get_min_removed_cats(self);
	};
	const apol_string_vector_t *get_min_unmodified_cats() {
		return (apol_string_vector_t*)poldiff_range_get_min_unmodified_cats(self);
	};
};
%inline %{
	poldiff_range_t *poldiff_range_from_void(void *x) {
		return (poldiff_range_t*)x;
	};
%}

/* range_transition rule diff */
typedef struct poldiff_range_trans {} poldiff_range_trans_t;
%extend poldiff_range_trans_t {
	poldiff_range_trans_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_range_trans_t objects");
   fail:
      return NULL;
 	}
	~poldiff_range_trans_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
%inline %{
	poldiff_range_trans_t *poldiff_range_trans_from_void(void *x) {
		return (poldiff_range_trans_t *)x;
	};
%}

/* role allow rule diff */
typedef struct poldiff_role_allow {} poldiff_role_allow_t;
%extend poldiff_role_allow_t {
	poldiff_role_allow_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_role_allow_t objects");
   fail:
      return NULL;
 	}
	~poldiff_role_allow_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
	const apol_string_vector_t *get_unmodified_roles() {
		return (apol_string_vector_t*)poldiff_role_allow_get_unmodified_roles(self);
	};
	const apol_string_vector_t *get_added_roles() {
		return (apol_string_vector_t*)poldiff_role_allow_get_added_roles(self);
	};
	const apol_string_vector_t *get_removed_roles() {
		return (apol_string_vector_t*)poldiff_role_allow_get_removed_roles(self);
	};
};
%inline %{
	poldiff_role_allow_t *poldiff_role_allow_from_void(void *x) {
		return (poldiff_role_allow_t *)x;
	};
%}

/* role_transition rule diff */
typedef struct poldiff_role_trans {} poldiff_role_trans_t;
%extend poldiff_role_trans_t {
	poldiff_role_trans_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_role_trans_t objects");
   fail:
      return NULL;
 	}
	~poldiff_role_trans_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
%inline %{
	poldiff_role_trans_t *poldiff_role_trans_from_void(void *x) {
		return (poldiff_role_trans_t *)x;
	};
%}

/* role diff */
typedef struct poldiff_role {} poldiff_role_t;
%extend poldiff_role_t {
	poldiff_role_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_role_t objects");
   fail:
      return NULL;
 	}
	~poldiff_role_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
%inline %{
	poldiff_role_t *poldiff_role_from_void(void *x) {
		return (poldiff_role_t*)x;
	};
%}

/* te rule diff */
typedef struct poldiff_terule {} poldiff_terule_t;
%extend poldiff_terule_t {
	poldiff_terule_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_terule_t objects");
   fail:
      return NULL;
 	}
	~poldiff_terule_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
		const qpol_cond_t *cond;
		uint32_t which_list;
		const apol_policy_t *which_pol;
		poldiff_terule_get_cond(p, self, &cond, &which_list, &which_pol);
		return cond;
	};
	uint32_t get_cond_list(poldiff_t *p) {
		const qpol_cond_t *cond;
		uint32_t which_list;
		const apol_policy_t *which_pol;
		poldiff_terule_get_cond(p, self, &cond, &which_list, &which_pol);
		return which_list;
	};
	const apol_policy_t *get_cond_policy(poldiff_t *p) {
		const qpol_cond_t *cond;
		uint32_t which_list;
		const apol_policy_t *which_pol;
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
%inline %{
	poldiff_terule_t *poldiff_terule_from_void(void *x) {
		return (poldiff_terule_t*)x;
	};
%}

/* type diff */
typedef struct poldiff_type {} poldiff_type_t;
%extend poldiff_type_t {
	poldiff_type_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_type_t objects");
   fail:
      return NULL;
 	}
	~poldiff_type_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
		return (apol_string_vector_t*)poldiff_type_get_added_attribs(self);
	};
	const apol_string_vector_t *get_removed_attribs() {
		return (apol_string_vector_t*)poldiff_type_get_removed_attribs(self);
	};
};
%inline %{
	poldiff_type_t *poldiff_type_from_void(void *x) {
		return (poldiff_type_t*)x;
	};
%}

/* user diff */
typedef struct poldiff_user {} poldiff_user_t;
%extend poldiff_user_t {
	poldiff_user_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_user_t objects");
   fail:
      return NULL;
 	}
	~poldiff_user_t() {
		/* no op */
		return;
	};
	%newobject to_string(poldiff_t*);
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
		return (apol_string_vector_t*)poldiff_user_get_unmodified_roles(self);
	};
	const apol_string_vector_t *get_added_roles() {
		return (apol_string_vector_t*)poldiff_user_get_added_roles(self);
	};
	const apol_string_vector_t *get_removed_roles() {
		return (apol_string_vector_t*)poldiff_user_get_removed_roles(self);
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
%inline %{
	poldiff_user_t *poldiff_user_from_void(void *x) {
		return (poldiff_user_t*)x;
	};
%}

/* type remap */
typedef struct poldiff_type_remap_entry {} poldiff_type_remap_entry_t;
%extend poldiff_type_remap_entry_t {
	poldiff_type_remap_entry_t() {
      SWIG_exception(SWIG_RuntimeError, "Cannot directly create poldiff_type_remap_entry_t objects");
   fail:
      return NULL;
 	}
	~poldiff_type_remap_entry_t() {
		/* no op */
		return;
	};
	%newobject get_original_types(poldiff_t*);
	apol_string_vector_t *get_original_types(poldiff_t *p) {
		apol_vector_t *v;
		v = poldiff_type_remap_entry_get_original_types(p, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return (apol_string_vector_t*)v;
	};
	%newobject get_modified_types(poldiff_t*);
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
%inline %{
	poldiff_type_remap_entry_t *poldiff_type_remap_entry_from_void(void *x) {
		return (poldiff_type_remap_entry_t*)x;
	};
%}

