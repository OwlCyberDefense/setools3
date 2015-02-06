/**
 * @file
 * SWIG declarations for libseaudit.
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

%module seaudit

%{
#include <seaudit/avc_message.h>
#include <seaudit/bool_message.h>
#include <seaudit/filter.h>
#include <seaudit/load_message.h>
#include <seaudit/log.h>
#include <seaudit/message.h>
#include <seaudit/model.h>
#include <seaudit/parse.h>
#include <seaudit/report.h>
#include <seaudit/sort.h>
#include <seaudit/util.h>
#include <time.h>

/* Provide hooks so that language-specific modules can define the
 * callback function, used by the handler in seaudit_log_create().
 */
SWIGEXPORT seaudit_handle_fn_t seaudit_swig_message_callback = NULL;
SWIGEXPORT void * seaudit_swig_message_callback_arg = NULL;

%}

#ifdef SWIGJAVA
%javaconst(1);
/* get the java environment so we can throw exceptions */
%{
	static JNIEnv *seaudit_global_jenv;
	jint JNI_OnLoad(JavaVM *vm, void *reserved) {
		(*vm)->AttachCurrentThread(vm, (void **)&seaudit_global_jenv, NULL);
		return JNI_VERSION_1_2;
	}
%}
#endif

%include exception.i
%include stdint.i
%import apol.i

%{
#undef BEGIN_EXCEPTION
#undef END_EXCEPTION
%}

#ifdef SWIGJAVA

%exception {
	seaudit_global_jenv = jenv;
	$action
}

%{
#define BEGIN_EXCEPTION JNIEnv *local_jenv = seaudit_global_jenv; {
#define END_EXCEPTION }
%}

/* handle size_t correctly in java as architecture independent */
%typemap(jni) size_t "jlong"
%typemap(jtype) size_t "long"
%typemap(jstype) size_t "long"
%typemap("javaimports") SWIGTYPE, FILE* %{
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
			libseaudit_get_version ();
		}
		catch (UnsatisfiedLinkError ule)
		{
			System.loadLibrary("jseaudit");
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
%{
#define BEGIN_EXCEPTION
#define END_EXCEPTION
%}
#endif

#ifdef SWIGJAVA
/* if java, pass the new exception macro to C not just SWIG */
#undef SWIG_exception
#define SWIG_exception(code, msg) {SWIG_JavaException(local_jenv, code, msg); goto fail;}
%inline %{
#undef SWIG_exception
#define SWIG_exception(code, msg) {SWIG_JavaException(local_jenv, code, msg); goto fail;}
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
 * Seaudit_Init(), but the output file will be called libtseaudit.so instead
 * of libseaudit.so.  Therefore add an alias from Tseaudit_Init() to the
 * real Seaudit_Init().
 */
SWIGEXPORT int Tseaudit_Init(Tcl_Interp *interp) {
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


#ifdef SWIGPYTHON
/* map python file to C FILE struct pointer */
%typemap(in) FILE * {
	if (!PyFile_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "Need a file!");
		return NULL;
	}
	$1 = PyFile_AsFile($input);
}
/* map string into C-style memory buffer */
%typemap(in) (const char *buffer, const size_t bufsize) {
	$1 = PyString_AsString($input);
	$2 = (size_t) PyString_Size($input);
}
#endif
#ifdef SWIGJAVA
/* map string into C-style memory buffer */
%typemap(in, noblock=1) (const char *buffer, const size_t bufsize) {
  $1 = 0;
  $2 = 0;
  if ($input) {
    $1 = ($1_ltype)JCALL2(GetStringUTFChars, jenv, $input, 0);
    if (!$1) return $null;
    $2 = strlen($1);
  }
}
%typemap(freearg, noblock=1) (const char *buffer, const size_t bufsize) {
  if ($1) JCALL2(ReleaseStringUTFChars, jenv, $input, $1);
}
#endif
#ifdef SWIGTCL
%typemap(in) FILE * {
	ClientData c;
	if (Tcl_GetOpenFile(interp, Tcl_GetString($input), 0, 1, &c) == TCL_ERROR)
		SWIG_exception(SWIG_RuntimeError, Tcl_GetStringResult(interp));
	$1 = (FILE*)c;
}
#endif

/* from <time.h> */
%{
	typedef struct tm tm_t;
%}
typedef struct tm {
	int tm_sec;   /* seconds */
	int tm_min;   /* minutes */
	int tm_hour;  /* hours */
	int tm_mday;  /* day of the month */
	int tm_mon;   /* month */
	int tm_year;  /* year */
	int tm_wday;  /* day of the week */
	int tm_yday;  /* day in the year */
	int tm_isdst; /* daylight saving time */
} tm_t;
%extend tm_t {
	tm() {
		struct tm *t;
		BEGIN_EXCEPTION
		t = calloc(1, sizeof(struct tm));
		if (!t) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return t;
	};
	~tm() {
		free(self);
	}
	/* use default accessor style for the rest */
};

const char *libseaudit_get_version(void);

/* seaudit log */
typedef enum seaudit_log_type
{
	SEAUDIT_LOG_TYPE_INVALID = 0,
	SEAUDIT_LOG_TYPE_SYSLOG,
	SEAUDIT_LOG_TYPE_AUDITD
} seaudit_log_type_e;
typedef struct seaudit_log {} seaudit_log_t;
%extend seaudit_log_t {
	seaudit_log() {
		seaudit_log_t *slog;
		BEGIN_EXCEPTION
		slog = seaudit_log_create(seaudit_swig_message_callback, seaudit_swig_message_callback_arg);
		if (!slog) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return slog;
	};
	~seaudit_log() {
		seaudit_log_destroy(&self);
	};
	%rename(clear) wrap_clear;
	void wrap_clear () {
		seaudit_log_clear(self);
	};
	%newobject get_users();
	%rename(get_users) wrap_get_users;
	apol_string_vector_t *wrap_get_users() {
		apol_vector_t *v;
		BEGIN_EXCEPTION
		v = seaudit_log_get_users(self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return (apol_string_vector_t*)v;
	};
	%newobject get_roles();
	%rename(get_roles) wrap_get_roles;
	apol_string_vector_t *wrap_get_roles() {
		apol_vector_t *v;
		BEGIN_EXCEPTION
		v = seaudit_log_get_roles(self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return (apol_string_vector_t*)v;
	};
	%newobject get_types();
	%rename(get_types) wrap_get_types;
	apol_string_vector_t *wrap_get_types() {
		apol_vector_t *v;
		BEGIN_EXCEPTION
		v = seaudit_log_get_types(self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return (apol_string_vector_t*)v;
	};
	%newobject get_classes();
	%rename(get_classes) wrap_get_classes;
	apol_string_vector_t *wrap_get_classes() {
		apol_vector_t *v;
		BEGIN_EXCEPTION
		v = seaudit_log_get_classes(self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return (apol_string_vector_t*)v;
	};
};

/* seaudit message */
typedef enum seaudit_message_type
{
	SEAUDIT_MESSAGE_TYPE_INVALID = 0,
	SEAUDIT_MESSAGE_TYPE_BOOL,
	SEAUDIT_MESSAGE_TYPE_AVC,
	SEAUDIT_MESSAGE_TYPE_LOAD
} seaudit_message_type_e;
typedef struct seaudit_message {} seaudit_message_t;
%extend seaudit_message_t {
	seaudit_message() {
		BEGIN_EXCEPTION
		SWIG_exception(SWIG_RuntimeError, "Canot directly create seaudit_message_t objects");
		END_EXCEPTION
	fail:
		return NULL;
	};
	~seaudit_message() {
		/* no op */
		return;
	};
	seaudit_message_type_e get_type() {
		seaudit_message_type_e te;
		(void)seaudit_message_get_data(self, &te);
		return te;
	};
	%rename(get_data) wrap_get_data;
	void *wrap_get_data() {
		seaudit_message_type_e te;
		return seaudit_message_get_data(self, &te);
	};
	%rename(get_host) wrap_get_host;
	const char *wrap_get_host() {
		return seaudit_message_get_host(self);
	};
	%rename(get_time) wrap_get_time;
	const tm_t *wrap_get_time() {
		return seaudit_message_get_time(self);
	}
	%newobject to_string();
	%rename(to_string) wrap_to_string;
	char *wrap_to_string() {
		char *str;
		BEGIN_EXCEPTION
		str = seaudit_message_to_string(self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return str;
	};
	%newobject to_string_html();
	%rename(to_string_html) wrap_to_string_html;
	char *wrap_to_string_html() {
		char *str;
		BEGIN_EXCEPTION
		str = seaudit_message_to_string_html(self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return str;
	};
	%newobject to_misc_string();
	%rename(to_misc_string) wrap_to_misc_string;
	char *wrap_to_misc_string() {
		char *str;
		BEGIN_EXCEPTION
		str = seaudit_message_to_misc_string(self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return str;
	};
};
%inline %{
	seaudit_message_t *seaudit_message_from_void(void *x) {
		return (seaudit_message_t*)x;
	};
%}

/* seaudit load message */
typedef struct seaudit_load_message {} seaudit_load_message_t;
%extend seaudit_load_message_t {
	seaudit_load_message() {
		BEGIN_EXCEPTION
		SWIG_exception(SWIG_RuntimeError, "Cannot directly create seaudit_load_message_t objects");
		END_EXCEPTION
	fail:
		return NULL;
	};
	~seaudit_load_message() {
		/* no op */
		return;
	};
};
%inline %{
	seaudit_load_message_t *seaudit_load_message_from_void(void *msg) {
		return (seaudit_load_message_t*)msg;
	};
%}

/* seaudit bool message */
typedef struct seaudit_bool_message {} seaudit_bool_message_t;
%extend seaudit_bool_message_t {
	seaudit_bool_message(void *msg) {
		BEGIN_EXCEPTION
		SWIG_exception(SWIG_RuntimeError, "Cannot directly create seaudit_bool_message_t objects");
		END_EXCEPTION
	fail:
		return NULL;
	};
	~seaudit_bool_message() {
		/* no op */
		return;
	};
};
%inline %{
	seaudit_bool_message_t *seaudit_bool_message_from_void(void *msg) {
		return (seaudit_bool_message_t*)msg;
	};
%}

/* seaudit avc message */
typedef enum seaudit_avc_message_type
{
	SEAUDIT_AVC_UNKNOWN = 0,
	SEAUDIT_AVC_DENIED,
	SEAUDIT_AVC_GRANTED
} seaudit_avc_message_type_e;
typedef struct seaudit_avc_message {} seaudit_avc_message_t;
%extend seaudit_avc_message_t {
	seaudit_avc_message() {
		BEGIN_EXCEPTION
		SWIG_exception(SWIG_RuntimeError, "Cannot directly create seaudit_avc_message_t objects");
		END_EXCEPTION
	fail:
		return NULL;
	};
	~seaudit_avc_message() {
		/* no op */
		return;
	};
	%rename(get_message_type) wrap_get_message_type;
	seaudit_avc_message_type_e wrap_get_message_type() {
		return seaudit_avc_message_get_message_type(self);
	};
	%rename(get_timestamp_nano) wrap_get_timestamp_nano;
	long wrap_get_timestamp_nano() {
		return seaudit_avc_message_get_timestamp_nano(self);
	};
	%rename(get_source_user) wrap_get_source_user;
	const char *wrap_get_source_user() {
		return seaudit_avc_message_get_source_user(self);
	};
	%rename(get_source_role) wrap_get_source_role;
	const char *wrap_get_source_role() {
		return seaudit_avc_message_get_source_role(self);
	};
	%rename(get_source_type) wrap_get_source_type;
	const char *wrap_get_source_type() {
		return seaudit_avc_message_get_source_type(self);
	};
	%rename(get_target_user) wrap_get_target_user;
	const char *wrap_get_target_user() {
		return seaudit_avc_message_get_target_user(self);
	};
	%rename(get_target_role) wrap_get_target_role;
	const char *wrap_get_target_role() {
		return seaudit_avc_message_get_target_role(self);
	};
	%rename(get_target_type) wrap_get_target_type;
	const char *wrap_get_target_type() {
		return seaudit_avc_message_get_target_type(self);
	};
	%rename(get_object_class) wrap_get_object_class;
	const char *wrap_get_object_class() {
		return seaudit_avc_message_get_object_class(self);
	};
	%rename(get_perm) wrap_get_perm;
	const apol_string_vector_t *wrap_get_perm() {
		return (apol_string_vector_t*)seaudit_avc_message_get_perm(self);
	};
	%rename(get_exe) wrap_get_exe;
	const char *wrap_get_exe() {
		return seaudit_avc_message_get_exe(self);
	};
	%rename(get_comm) wrap_get_comm;
	const char *wrap_get_comm() {
		return seaudit_avc_message_get_comm(self);
	};
	%rename(get_name) wrap_get_name;
	const char *wrap_get_name() {
		return seaudit_avc_message_get_name(self);
	};
	%rename(get_pid) wrap_get_pid;
	int wrap_get_pid() {
		return (int)seaudit_avc_message_get_pid(self);
	};
	%rename(get_inode) wrap_get_inode;
	long wrap_get_inode() {
		return (long)seaudit_avc_message_get_inode(self);
	};
	%rename(get_path) wrap_get_path;
	const char *wrap_get_path() {
		return seaudit_avc_message_get_path(self);
	};
	%rename(get_dev) wrap_get_dev;
	const char *wrap_get_dev() {
		return seaudit_avc_message_get_dev(self);
	};
	%rename(get_netif) wrap_get_netif;
	const char *wrap_get_netif() {
		return seaudit_avc_message_get_netif(self);
	};
	%rename(get_port) wrap_get_port;
	int wrap_get_port() {
		return seaudit_avc_message_get_port(self);
	};
	%rename(get_laddr) wrap_get_laddr;
	const char *wrap_get_laddr() {
		return seaudit_avc_message_get_laddr(self);
	};
	%rename(get_lport) wrap_get_lport;
	int wrap_get_lport() {
		return seaudit_avc_message_get_lport(self);
	};
	%rename(get_faddr) wrap_get_faddr;
	const char *wrap_get_faddr() {
		return seaudit_avc_message_get_faddr(self);
	};
	%rename(get_fport) wrap_get_fport;
	int wrap_get_fport() {
		return seaudit_avc_message_get_fport(self);
	};
	%rename(get_saddr) wrap_get_saddr;
	const char *wrap_get_saddr() {
		return seaudit_avc_message_get_saddr(self);
	};
	%rename(get_sport) wrap_get_sport;
	int wrap_get_sport() {
		return seaudit_avc_message_get_sport(self);
	};
	%rename(get_daddr) wrap_get_daddr;
	const char *wrap_get_daddr() {
		return seaudit_avc_message_get_daddr(self);
	};
	%rename(get_dport) wrap_get_dport;
	int wrap_get_dport() {
		return seaudit_avc_message_get_dport(self);
	};
	%rename(get_key) wrap_get_key;
	int wrap_get_key() {
		return seaudit_avc_message_get_key(self);
	};
	%rename(get_cap) wrap_get_cap;
	int wrap_get_cap() {
		return seaudit_avc_message_get_cap(self);
	};
};
%inline %{
	seaudit_avc_message_t *seaudit_avc_message_from_void(void *msg) {
		return (seaudit_avc_message_t*)msg;
	};
%}

/* Java does not permit parsing directly from a file; parsing may only
   be done through a memory buffer. */
#ifndef SWIGJAVA
int seaudit_log_parse(seaudit_log_t * log, FILE * syslog);
#endif
int seaudit_log_parse_buffer(seaudit_log_t * log, const char *buffer, const size_t bufsize);

/* seaudit filter */
typedef enum seaudit_filter_match
{
	SEAUDIT_FILTER_MATCH_ALL = 0,
	SEAUDIT_FILTER_MATCH_ANY
} seaudit_filter_match_e;
typedef enum seaudit_filter_visible
{
	SEAUDIT_FILTER_VISIBLE_SHOW = 0,
	SEAUDIT_FILTER_VISIBLE_HIDE
} seaudit_filter_visible_e;
typedef enum seaudit_filter_date_match
{
	SEAUDIT_FILTER_DATE_MATCH_BEFORE = 0,
	SEAUDIT_FILTER_DATE_MATCH_AFTER,
	SEAUDIT_FILTER_DATE_MATCH_BETWEEN
} seaudit_filter_date_match_e;
typedef struct seaudit_filter {} seaudit_filter_t;
%extend seaudit_filter_t {
	seaudit_filter(char *name = NULL) {
		seaudit_filter_t *sf = NULL;
		BEGIN_EXCEPTION
		sf = seaudit_filter_create(name);
		if (!sf) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return sf;
	};
	seaudit_filter(seaudit_filter_t *in) {
		seaudit_filter_t *sf = NULL;
		BEGIN_EXCEPTION
		sf = seaudit_filter_create_from_filter(in);
		if (!sf) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return sf;
	};
	~seaudit_filter() {
		seaudit_filter_destroy(&self);
	};
	void save(char *path) {
		BEGIN_EXCEPTION
		if (seaudit_filter_save_to_file(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not save filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(set_match) wrap_set_match;
	void wrap_set_match(seaudit_filter_match_e match) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_match(self, match)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter matching method");
		}
		END_EXCEPTION
	fail:
		return;
	}
	%rename(get_match) wrap_get_match;
	seaudit_filter_match_e wrap_get_match() {
		return seaudit_filter_get_match(self);
	};
	%rename(set_name) wrap_set_name;
	void wrap_set_name(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_name(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter name");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_name) wrap_get_name;
	const char *wrap_get_name() {
		return seaudit_filter_get_name(self);
	};
	%rename(set_description) wrap_set_description;
	void wrap_set_description(char *description) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_description(self, description)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter description");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_description) wrap_get_description;
	const char *wrap_get_description() {
		return seaudit_filter_get_description(self);
	};
	%rename(set_strict) wrap_set_strict;
	void wrap_set_strict(bool is_strict) {
		seaudit_filter_set_strict(self, is_strict);
	};
	%rename(get_strict) wrap_get_strict;
	bool wrap_get_strict() {
		return seaudit_filter_get_strict(self);
	};
	%rename(set_source_user) wrap_set_source_user;
	void wrap_set_source_user(apol_string_vector_t *v) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_source_user(self, (apol_vector_t*)v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source user list for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_source_user) wrap_get_source_user;
	const apol_string_vector_t *wrap_get_source_user() {
		return (apol_string_vector_t*)seaudit_filter_get_source_user(self);
	};
	%rename(set_source_role) wrap_set_source_role;
	void wrap_set_source_role(apol_string_vector_t *v) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_source_role(self, (apol_vector_t*)v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source role list for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_source_role) wrap_get_source_role;
	const apol_string_vector_t *wrap_get_source_role() {
		return (apol_string_vector_t*)seaudit_filter_get_source_role(self);
	};
	%rename(set_source_type) wrap_set_source_type;
	void wrap_set_source_type(apol_string_vector_t *v) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_source_type(self, (apol_vector_t*)v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source type list for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_source_type) wrap_get_source_type;
	const apol_string_vector_t *wrap_get_source_type() {
		return (apol_string_vector_t*)seaudit_filter_get_source_type(self);
	};
	%rename(set_target_user) wrap_set_target_user;
	void wrap_set_target_user(apol_string_vector_t *v) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_target_user(self, (apol_vector_t*)v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set target user list for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_target_user) wrap_get_target_user;
	const apol_string_vector_t *wrap_get_target_user() {
		return (apol_string_vector_t*)seaudit_filter_get_target_user(self);
	};
	%rename(set_target_role) wrap_set_target_role;
	void wrap_set_target_role(apol_string_vector_t *v) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_target_role(self, (apol_vector_t*)v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set target role list for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_target_role) wrap_get_target_role;
	const apol_string_vector_t *wrap_get_target_role() {
		return (apol_string_vector_t*)seaudit_filter_get_target_role(self);
	};
	%rename(set_target_type) wrap_set_target_type;
	void wrap_set_target_type(apol_string_vector_t *v) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_target_type(self, (apol_vector_t*)v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set target type list for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_target_type) wrap_get_target_type;
	const apol_string_vector_t *wrap_get_target_type() {
		return (apol_string_vector_t*)seaudit_filter_get_target_type(self);
	};
	%rename(set_target_class) wrap_set_target_class;
	void wrap_set_target_class(apol_string_vector_t *v) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_target_class(self, (apol_vector_t*)v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set target class list for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_target_class) wrap_get_target_class;
	const apol_string_vector_t *wrap_get_target_class() {
		return (apol_string_vector_t*)seaudit_filter_get_target_class(self);
	};
	%rename(set_permission) wrap_set_permission;
	void wrap_set_permission(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_permission(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set permission for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_permission) wrap_get_permission;
	const char *wrap_get_permission() {
		return seaudit_filter_get_permission(self);
	};
	%rename(set_executable) wrap_set_executable;
	void wrap_set_executable(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_executable(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set executable for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_executable) wrap_get_executable;
	const char *wrap_get_executable() {
		return seaudit_filter_get_executable(self);
	};
	%rename(set_host) wrap_set_host;
	void wrap_set_host(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_host(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set host for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_host) wrap_get_host;
	const char *wrap_get_host() {
		return seaudit_filter_get_host(self);
	};
	%rename(set_path) wrap_set_path;
	void wrap_set_path(char *path) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_path(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set path for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_path) wrap_get_path;
	const char *wrap_get_path() {
		return seaudit_filter_get_path(self);
	};
	%rename(set_command) wrap_set_command;
	void wrap_set_command(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_command(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set command for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(set_inode) wrap_set_inode;
	void wrap_set_inode(long inode) {
		seaudit_filter_set_inode(self, (long) inode);
	};
	%rename(get_inode) wrap_get_inode;
	long wrap_get_inode() {
		return (long) seaudit_filter_get_inode(self);
	};
	%rename(set_pid) wrap_set_pid;
	void wrap_set_pid(long pid) {
		seaudit_filter_set_pid(self, (unsigned int) pid);
	};
	%rename(get_pid) wrap_get_pid;
	long wrap_get_pid() {
		return (long) seaudit_filter_get_pid(self);
	};
	%rename(get_command) wrap_get_command;
	const char *wrap_get_command() {
		return seaudit_filter_get_command(self);
	};
	%rename(set_anyaddr) wrap_set_anyaddr;
	void wrap_set_anyaddr(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_anyaddr(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set ip address for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_anyaddr) wrap_get_anyaddr;
	const char *wrap_get_anyaddr() {
		return seaudit_filter_get_anyaddr(self);
	};
	%rename(set_anyport) wrap_set_anyport;
	void wrap_set_anyport(int port) {
		seaudit_filter_set_anyport(self, port);
	};
	%rename(get_anyport) wrap_get_anyport;
	int wrap_get_anyport() {
		return seaudit_filter_get_anyport(self);
	};
	%rename(set_laddr) wrap_set_laddr;
	void wrap_set_laddr(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_laddr(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set local address for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_laddr) wrap_get_laddr;
	const char *wrap_get_laddr() {
		return seaudit_filter_get_laddr(self);
	};
	%rename(set_lport) wrap_set_lport;
	void wrap_set_lport(int port) {
		seaudit_filter_set_lport(self, port);
	};
	%rename(get_lport) wrap_get_lport;
	int wrap_get_lport() {
		return seaudit_filter_get_lport(self);
	};
	%rename(set_faddr) wrap_set_faddr;
	void wrap_set_faddr(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_faddr(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set foreign address for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_faddr) wrap_get_faddr;
	const char *wrap_get_faddr() {
		return seaudit_filter_get_faddr(self);
	};
	%rename(set_fport) wrap_set_fport;
	void wrap_set_fport(int port) {
		seaudit_filter_set_fport(self, port);
	};
	%rename(get_fport) wrap_get_fport;
	int wrap_get_fport() {
		return seaudit_filter_get_fport(self);
	};
	%rename(set_saddr) wrap_set_saddr;
	void wrap_set_saddr(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_saddr(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source address for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_saddr) wrap_get_saddr;
	const char *wrap_get_saddr() {
		return seaudit_filter_get_saddr(self);
	};
	%rename(set_sport) wrap_set_sport;
	void wrap_set_sport(int port) {
		seaudit_filter_set_sport(self, port);
	};
	%rename(get_sport) wrap_get_sport;
	int wrap_get_sport() {
		return seaudit_filter_get_sport(self);
	};
	%rename(set_daddr) wrap_set_daddr;
	void wrap_set_daddr(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_daddr(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set destination address for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_daddr) wrap_get_daddr;
	const char *wrap_get_daddr() {
		return seaudit_filter_get_daddr(self);
	};
	%rename(set_dport) wrap_set_dport;
	void wrap_set_dport(int port) {
		seaudit_filter_set_dport(self, port);
	};
	%rename(get_dport) wrap_get_dport;
	int wrap_get_dport() {
		return seaudit_filter_get_dport(self);
	};
	%rename(set_port) wrap_set_port;
	void wrap_set_port(int port) {
		seaudit_filter_set_port(self, port);
	};
	%rename(get_port) wrap_get_port;
	int wrap_get_port() {
		return seaudit_filter_get_port(self);
	};
	%rename(set_netif) wrap_set_netif;
	void wrap_set_netif(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_netif(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set network interface for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_netif) wrap_get_netif;
	const char *wrap_get_netif() {
		return seaudit_filter_get_netif(self);
	};
	%rename(set_key) wrap_set_key;
	void wrap_set_key(int key) {
		seaudit_filter_set_key(self, key);
	};
	%rename(get_key) wrap_get_key;
	int wrap_get_key() {
		return seaudit_filter_get_key(self);
	};
	%rename(set_cap) wrap_set_cap;
	void wrap_set_cap(int cap) {
		seaudit_filter_set_cap(self, cap);
	};
	%rename(get_cap) wrap_get_cap;
	int wrap_get_cap() {
		return seaudit_filter_get_cap(self);
	};
	%rename(set_message_type) wrap_set_message_type;
	void wrap_set_message_type(seaudit_avc_message_type_e mtype) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_message_type(self, mtype)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set message type for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_message_type) wrap_get_message_type;
	seaudit_message_type_e wrap_get_message_type() {
		return seaudit_filter_get_message_type(self);
	};
	%rename(set_date) wrap_set_date;
	void wrap_set_date(struct tm *start, struct tm *end, seaudit_filter_date_match_e match) {
		BEGIN_EXCEPTION
		if (seaudit_filter_set_date(self, start, end, match)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set date for filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	const struct tm *get_start_date() {
		const struct tm *s;
		const struct tm *e;
		seaudit_filter_date_match_e m;
		seaudit_filter_get_date(self, &s, &e, &m);
		return s;
	};
	const struct tm *get_end_date() {
		const struct tm *s;
		const struct tm *e;
		seaudit_filter_date_match_e m;
		seaudit_filter_get_date(self, &s, &e, &m);
		return e;
	};
	seaudit_filter_date_match_e get_date_match() {
		const struct tm *s;
		const struct tm *e;
		seaudit_filter_date_match_e m;
		seaudit_filter_get_date(self, &s, &e, &m);
		return m;
	};
};
%newobject seaudit_filter_create_from_file(const char*);
apol_vector_t *seaudit_filter_create_from_file(const char *filename);
%inline %{
	seaudit_filter_t *seaudit_filter_from_void(void *x) {
		return (seaudit_filter_t*)x;
	};
%}

/* seaudit sort */
typedef struct seaudit_sort {} seaudit_sort_t;
%extend seaudit_sort_t {
	seaudit_sort() {
		BEGIN_EXCEPTION
		SWIG_exception(SWIG_RuntimeError, "Cannot directly create seaudit_sort_t objects");
		END_EXCEPTION
	fail:
		return NULL;
	};
	seaudit_sort(seaudit_sort_t *in) {
		seaudit_sort_t *ss = NULL;
		BEGIN_EXCEPTION
		ss = seaudit_sort_create_from_sort(in);
		if (!ss) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return ss;
	};
        ~seaudit_sort() {
		seaudit_sort_destroy(&self);
	};
};
%newobject seaudit_sort_by_message_type(const int);
seaudit_sort_t *seaudit_sort_by_message_type(const int direction);
%newobject seaudit_sort_by_date(const int);
seaudit_sort_t *seaudit_sort_by_date(const int direction);
%newobject seaudit_sort_by_host(const int);
seaudit_sort_t *seaudit_sort_by_host(const int direction);
%newobject seaudit_sort_by_permission(const int);
seaudit_sort_t *seaudit_sort_by_permission(const int direction);
%newobject seaudit_sort_by_source_user(const int);
seaudit_sort_t *seaudit_sort_by_source_user(const int direction);
%newobject seaudit_sort_by_source_role(const int);
seaudit_sort_t *seaudit_sort_by_source_role(const int direction);
%newobject seaudit_sort_by_source_type(const int);
seaudit_sort_t *seaudit_sort_by_source_type(const int direction);
%newobject seaudit_sort_by_target_user(const int);
seaudit_sort_t *seaudit_sort_by_target_user(const int direction);
%newobject seaudit_sort_by_target_role(const int);
seaudit_sort_t *seaudit_sort_by_target_role(const int direction);
%newobject seaudit_sort_by_target_type(const int);
seaudit_sort_t *seaudit_sort_by_target_type(const int direction);
%newobject seaudit_sort_by_object_class(const int);
seaudit_sort_t *seaudit_sort_by_object_class(const int direction);
%newobject seaudit_sort_by_executable(const int);
seaudit_sort_t *seaudit_sort_by_executable(const int direction);
%newobject seaudit_sort_by_command(const int);
seaudit_sort_t *seaudit_sort_by_command(const int direction);
%newobject seaudit_sort_by_name(const int);
seaudit_sort_t *seaudit_sort_by_name(const int direction);
%newobject seaudit_sort_by_path(const int);
seaudit_sort_t *seaudit_sort_by_path(const int direction);
%newobject seaudit_sort_by_device(const int);
seaudit_sort_t *seaudit_sort_by_device(const int direction);
%newobject seaudit_sort_by_inode(const int);
seaudit_sort_t *seaudit_sort_by_inode(const int direction);
%newobject seaudit_sort_by_pid(const int);
seaudit_sort_t *seaudit_sort_by_pid(const int direction);
%newobject seaudit_sort_by_port(const int);
extern seaudit_sort_t *seaudit_sort_by_port(const int direction);
%newobject seaudit_sort_by_laddr(const int);
extern seaudit_sort_t *seaudit_sort_by_laddr(const int direction);
%newobject seaudit_sort_by_lport(const int);
extern seaudit_sort_t *seaudit_sort_by_lport(const int direction);
%newobject seaudit_sort_by_faddr(const int);
extern seaudit_sort_t *seaudit_sort_by_faddr(const int direction);
%newobject seaudit_sort_by_fport(const int);
extern seaudit_sort_t *seaudit_sort_by_fport(const int direction);
%newobject seaudit_sort_by_saddr(const int);
extern seaudit_sort_t *seaudit_sort_by_saddr(const int direction);
%newobject seaudit_sort_by_sport(const int);
extern seaudit_sort_t *seaudit_sort_by_sport(const int direction);
%newobject seaudit_sort_by_daddr(const int);
extern seaudit_sort_t *seaudit_sort_by_daddr(const int direction);
%newobject seaudit_sort_by_dport(const int);
extern seaudit_sort_t *seaudit_sort_by_dport(const int direction);
%newobject seaudit_sort_by_key(const int);
extern seaudit_sort_t *seaudit_sort_by_key(const int direction);
%newobject seaudit_sort_by_cap(const int);
extern seaudit_sort_t *seaudit_sort_by_cap(const int direction);

/* seaudit model */
#ifdef SWIGPYTHON
/* handle ownership of filters and sorts passed to the model */
%typemap(in) seaudit_filter_t *filter {
	void *x = NULL;
	Py_IncRef($input);
	SWIG_ConvertPtr($input, &x,SWIGTYPE_p_seaudit_filter, 0 |  0 );
	$1 = (seaudit_filter_t*)x;
}
%typemap(in) seaudit_sort_t *ssort {
	void *x = NULL;
	Py_IncRef($input);
	SWIG_ConvertPtr($input, &x,SWIGTYPE_p_seaudit_sort, 0 |  0 );
	$1 = (seaudit_sort_t*)x;
}
#endif
typedef struct seaudit_model {} seaudit_model_t;
%extend seaudit_model_t {
	seaudit_model(char *name = NULL, seaudit_log_t *slog = NULL) {
		seaudit_model_t *smod;
		BEGIN_EXCEPTION
		smod = seaudit_model_create(name, slog);
		if (!smod) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return smod;
	};
	seaudit_model(seaudit_model_t *in) {
		seaudit_model_t *smod;
		BEGIN_EXCEPTION
		smod = seaudit_model_create_from_model(in);
		if (!smod) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return smod;
	};
	seaudit_model(char *path) {
		seaudit_model_t *smod;
		BEGIN_EXCEPTION
		smod = seaudit_model_create_from_file(path);
		if (!smod) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return smod;
	}
	~seaudit_model() {
		seaudit_model_destroy(&self);
	};
	void save(char *path) {
		BEGIN_EXCEPTION
		if (seaudit_model_save_to_file(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not save seaudit model");
		}
		END_EXCEPTION
	fail:
		return;
	}
	%rename(get_name) wrap_get_name;
	const char *wrap_get_name() {
		return seaudit_model_get_name(self);
	};
	%rename(set_name) wrap_set_name;
	void wrap_set_name(char *name) {
		BEGIN_EXCEPTION
		if (seaudit_model_set_name(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set model name");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(append_log) wrap_append_log;
	void wrap_append_log(seaudit_log_t *slog) {
		BEGIN_EXCEPTION
		if (seaudit_model_append_log(self, slog)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append log to model");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(append_filter) wrap_append_filter;
	void wrap_append_filter(seaudit_filter_t *filter) {
		BEGIN_EXCEPTION
#ifdef SWIGJAVA /* duplicate so the garbage collector does not double free */
		seaudit_filter_t *tmp = seaudit_filter_create_from_filter(filter);
		if (seaudit_model_append_filter(self, tmp)) {
			seaudit_filter_destroy(&tmp);
			SWIG_exception(SWIG_RuntimeError, "Could not append filter to model");
		}
#else
		if (seaudit_model_append_filter(self, filter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append filter to model");
		}
#endif
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_filters) wrap_get_filters;
	const apol_vector_t *wrap_get_filters() {
		return seaudit_model_get_filters(self);
	};
	%delobject remove_filter();
	%rename(remove_filter) wrap_remove_filter;
	void wrap_remove_filter(seaudit_filter_t *filter) {
		BEGIN_EXCEPTION
		if (seaudit_model_remove_filter(self, filter)) {
			SWIG_exception(SWIG_ValueError, "Could not remove filter");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(set_filter_match) wrap_set_filter_match;
	void wrap_set_filter_match(seaudit_filter_match_e match) {
		BEGIN_EXCEPTION
		if (seaudit_model_set_filter_match(self, match)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter matching method for model");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_filter_match) wrap_get_filter_match;
	seaudit_filter_match_e wrap_get_filter_match() {
		return seaudit_model_get_filter_match(self);
	};
	%rename(set_filter_visible) wrap_set_filter_visible;
	void wrap_set_filter_visible(seaudit_filter_visible_e vis) {
		BEGIN_EXCEPTION
		if (seaudit_model_set_filter_visible(self, vis)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter visibility for model");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(get_filter_visible) wrap_get_filter_visible;
	seaudit_filter_visible_e wrap_get_filter_visible() {
		return seaudit_model_get_filter_visible(self);
	};
	%rename(append_sort) wrap_append_sort;
	void wrap_append_sort(seaudit_sort_t *ssort) {
		BEGIN_EXCEPTION
#ifdef SWIGJAVA
		seaudit_sort_t *tmp = seaudit_sort_create_from_sort(ssort);
		if (seaudit_model_append_sort(self, tmp)) {
			seaudit_sort_destroy(&tmp);
			SWIG_exception(SWIG_RuntimeError, "Could not append sort to model");
		}
#else
		if (seaudit_model_append_sort(self, ssort)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append sort to model");
		}
#endif
		END_EXCEPTION
	fail:
		return;
	};
	%rename(clear_sorts) wrap_clear_sorts;
	void wrap_clear_sorts() {
		BEGIN_EXCEPTION
		if (seaudit_model_clear_sorts(self)) {
			SWIG_exception(SWIG_RuntimeError, "Could not clear model sorting criteria");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(is_changed) wrap_is_changed;
	int wrap_is_changed() {
		return seaudit_model_is_changed(self);
	};
	%newobject get_messages(seaudit_log_t*);
	%rename(get_messages) wrap_get_messages;
	apol_vector_t *wrap_get_messages(seaudit_log_t *slog) {
		apol_vector_t *v = NULL;
		BEGIN_EXCEPTION
		v = seaudit_model_get_messages(slog, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return v;
	};
	%newobject get_malformed_messages(seaudit_log_t*);
	%rename(get_malformed_messages) wrap_get_malformed_messages;
	apol_vector_t *wrap_get_malformed_messages(seaudit_log_t *slog) {
		apol_vector_t *v = NULL;
		BEGIN_EXCEPTION
		v = seaudit_model_get_malformed_messages(slog, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return v;
	};
	%rename(hide_message) wrap_hide_message;
	void wrap_hide_message(seaudit_message_t *message) {
		seaudit_model_hide_message(self, message);
	};
	%rename(get_num_allows) wrap_get_num_allows;
	size_t wrap_get_num_allows(seaudit_log_t *slog) {
		return seaudit_model_get_num_allows(slog, self);
	};
	%rename(get_num_denies) wrap_get_num_denies;
	size_t wrap_get_num_denies(seaudit_log_t *slog) {
		return seaudit_model_get_num_denies(slog, self);
	};
	%rename(get_num_bools) wrap_get_num_bools;
	size_t wrap_get_num_bools(seaudit_log_t *slog) {
		return seaudit_model_get_num_bools(slog, self);
	};
	%rename(get_num_loads) wrap_get_num_loads;
	size_t wrap_get_num_loads(seaudit_log_t *slog) {
		return seaudit_model_get_num_loads(slog, self);
	};
};

/* seaudit report */
typedef enum seaudit_report_format
{
	SEAUDIT_REPORT_FORMAT_TEXT,
	SEAUDIT_REPORT_FORMAT_HTML
} seaudit_report_format_e;
typedef struct seaudit_report {} seaudit_report_t;
%extend seaudit_report_t {
	seaudit_report(seaudit_model_t *m) {
		seaudit_report_t *sr;
		BEGIN_EXCEPTION
		sr = seaudit_report_create(m);
		if (!sr) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		END_EXCEPTION
	fail:
		return sr;
	};
	~seaudit_report() {
		seaudit_report_destroy(&self);
	};
	%rename(write) wrap_write;
	void wrap_write(seaudit_log_t *slog, char *path) {
		BEGIN_EXCEPTION
		if (seaudit_report_write(slog, self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not write report to file");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(set_format) wrap_set_format;
	void wrap_set_format(seaudit_log_t *slog, seaudit_report_format_e format) {
		BEGIN_EXCEPTION
		if (seaudit_report_set_format(slog, self, format)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set report format");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(set_configuration) wrap_set_configuration;
	void wrap_set_configuration(seaudit_log_t *slog, char *path) {
		BEGIN_EXCEPTION
		if (seaudit_report_set_configuration(slog, self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set report configuration file");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(set_stylesheet) wrap_set_stylesheet;
	void wrap_set_stylesheet(seaudit_log_t *slog, char *path, int use_stylesheet) {
		BEGIN_EXCEPTION
		if (seaudit_report_set_stylesheet(slog, self, path, use_stylesheet)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set report stylesheet");
		}
		END_EXCEPTION
	fail:
		return;
	};
	%rename(set_malformed) wrap_set_malformed;
	void wrap_set_malformed(seaudit_log_t *slog, int do_malformed) {
		BEGIN_EXCEPTION
		if (seaudit_report_set_malformed(slog, self, do_malformed)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set report malformed flag");
		}
		END_EXCEPTION
	fail:
		return;
	};
};
