/**
 * @file
 * SWIG declarations for libsefs.
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

%module sefs

%{
#include <sefs/file_contexts.h>
#include <sefs/fsdata.h>
#include <sefs/fshash.h>
#include <sefs/util.h>
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
		System.loadLibrary("jseaudit");
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

const char *libsefs_get_version(void);

/* file type IDs, used by sefs_fc_entry::filetype */
#define SEFS_FILETYPE_NONE 0	       /* none */
/* the following values must correspond to libsepol flask.h */
#define SEFS_FILETYPE_REG  6	       /* Regular file */
#define SEFS_FILETYPE_DIR  7	       /* Directory */
#define SEFS_FILETYPE_LNK  9	       /* Symbolic link */
#define SEFS_FILETYPE_CHR  10	       /* Character device */
#define SEFS_FILETYPE_BLK  11	       /* Block device */
#define SEFS_FILETYPE_SOCK 12	       /* Socket */
#define SEFS_FILETYPE_FIFO 13	       /* FIFO */
#define SEFS_FILETYPE_ANY  14	       /* any type */

/* general file context */
typedef struct sefs_security_context
{
	char *user;
	char *role;
	char *type;
	char *range;
} sefs_security_con_t;
%extend sefs_security_con_t {
	sefs_security_con_t() {
		sefs_security_con_t *ssc = NULL;
		ssc = calloc(1, sizeof(sefs_security_con_t));
		if (!ssc) {
			SWIG_exception(SWIG_MemoryError, "Out of memory.");
		}
	fail:
		return ssc;
	};
	sefs_security_con_t(const sefs_security_con_t *in) {
		sefs_security_con_t *ssc = NULL;
		if (!in) {
			SWIG_exception(SWIG_ValueError, "Invalid argument");
		}
		ssc = calloc(1, sizeof(sefs_security_con_t));
		if (!ssc) {
			SWIG_exception(SWIG_MemoryError, "Out of memory.");
		}
		if ((in->user && !(ssc->user = strdup(in->user))) ||
			(in->role && !(ssc->role = strdup(in->role))) ||
			(in->type && !(ssc->type = strdup(in->type))) ||
			(in->range && !(ssc->range = strdup(in->range)))) {
			SWIG_exception(SWIG_MemoryError, "Out of memory.");
		}
		return ssc;
	fail:
		if (ssc) {
			free(ssc->user);
			free(ssc->role);
			free(ssc->type);
			free(ssc->range);
		}
		free(ssc);
		return NULL;
	};
	~sefs_security_con_t() {
		if (!self)
			return;
		free(self->user);
		free(self->role);
		free(self->type);
		free(self->range);
		free(self);
	};
};

/* fc file entry */
typedef struct sefs_fc_entry
{
	char *path;
	int filetype;
	sefs_security_con_t *context;
} sefs_fc_entry_t;
%extend sefs_fc_entry_t {
	sefs_fc_entry_t() {
		sefs_fc_entry_t *sfe = NULL;
		sfe = calloc(1, sizeof(sefs_fc_entry_t));
		if (!sfe) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		sfe->context = calloc(1, sizeof(sefs_security_con_t));
		if (!sfe->context)  {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		return sfe;
	fail:
		free(sfe);
		return NULL;
	};
	sefs_fc_entry_t(sefs_fc_entry_t *in) {
		sefs_fc_entry_t *sfe = NULL;
		if (!in) {
			SWIG_exception(SWIG_ValueError, "Invalid argument");
		}
		sfe = calloc(1, sizeof(sefs_fc_entry_t));
		if (!sfe) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		sfe->context = calloc(1, sizeof(sefs_security_con_t));
		if (!sfe->context)  {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}

		if (in->path && !(sfe->path = strdup(in->path))) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		sfe->filetype = in->filetype;
		if ((in->context->user && !(sfe->context->user = strdup(in->context->user))) ||
			(in->context->role && !(sfe->context->role = strdup(in->context->role))) ||
			(in->context->type && !(sfe->context->type = strdup(in->context->type))) ||
			(in->context->range && !(sfe->context->range = strdup(in->context->range)))) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}

		return sfe;
	fail:
		if (sfe) {
			if (sfe->context) {
				free(sfe->context->user);
				free(sfe->context->role);
				free(sfe->context->type);
				free(sfe->context->range);
			}
			free(sfe->context);
			free(sfe->path);
		}
		free(sfe);
		return NULL;
	};
	~sefs_fc_entry_t() {
		if (!self)
			return;
		free(self->path);
		if (self->context) {
			free(self->context->user);
			free(self->context->role);
			free(self->context->type);
			free(self->context->range);
		}
		free(self->context);
		free(self);
	};
};
%rename(sefs_fc_entry_parse_file_contexts) wrap_sefs_fc_entry_parse_file_contexts();
%newobject sefs_fc_entry_parse_file_contexts();
%rename(sefs_fc_find_default_file_contexts) wrap_sefs_fc_find_default_file_contexts();
%newobject sefs_fc_find_default_file_contexts();
%inline %{
	apol_vector_t *wrap_sefs_fc_entry_parse_file_contexts(apol_policy_t *p, const char *path) {
		apol_vector_t *v = NULL;
		if (sefs_fc_entry_parse_file_contexts(p, path, &v)) {
			SWIG_exception(SWIG_RuntimeError, "Error parsing file contexts");
		}
	fail:
		return v;
	}
	const char *wrap_sefs_fc_find_default_file_contexts() {
		char *path = NULL;
		if (sefs_fc_find_default_file_contexts(&path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not find default file contexts file");
		}
	fail:
		return path;
	}
%}

/* filesystem */
typedef struct sefs_filesystem_db {} sefs_filesystem_db_t;
%extend sefs_filesystem_db_t {
	sefs_filesystem_db_t(const char *path) {
		sefs_filesystem_db_t *db = NULL;
		db = calloc(1, sizeof(sefs_filesystem_db_t));
		if (!db) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
		if (sefs_filesystem_db_load(db, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not load database");
		}
		return db;
	fail:
		free(db);
		return NULL;
	};
	~sefs_filesystem_db_t() {
		sefs_filesystem_db_close(self);
		free(self);
	};
	void save(const char *path) {
		if (sefs_filesystem_db_save(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not save database");
		}
	fail:
		return;
	};
	void populate(const char *path) {
		if (sefs_filesystem_db_populate(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not populate database");
		}
	fail:
		return;
	};
};


