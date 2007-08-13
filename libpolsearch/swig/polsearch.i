/**
 * @file
 * SWIG declarations for libpolsearch.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2007 Tresys Technology, LLC
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

%module polsearch

%{
#include <polsearch/polsearch.hh>
#include <polsearch/query.hh>
#include <polsearch/bool_query.hh>
#include <polsearch/test.hh>
#include <polsearch/criterion.hh>
#include <polsearch/parameter.hh>
#include <polsearch/bool_parameter.hh>
#include <polsearch/level_parameter.hh>
#include <polsearch/number_parameter.hh>
#include <polsearch/range_parameter.hh>
#include <polsearch/regex_parameter.hh>
#include <polsearch/result.hh>
#include <polsearch/proof.hh>
#include <polsearch/util.hh>
#include <sefs/fclist.hh>
#include <sefs/fcfile.hh>
#include <sefs/filesystem.hh>
#include <sefs/db.hh>
#include <sefs/entry.hh>
#include <string>
#include <vector>
#include <stdexcept>
%}

%import qpol.i
%import apol.i
%import sefs.i

#ifdef SWIGJAVA

/* handle size_t correctly in java as architecture independent */
%typemap(jni) size_t "jlong"
%typemap(jtype) size_t "long"
%typemap(jstype) size_t "long"
%typemap("javaimports") SWIGTYPE, FILE* %{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
import com.tresys.setools.sefs.*;
%}
/* the following handles the dependencies on qpol, apol, and sefs */
%pragma(java) jniclassimports=%{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
import com.tresys.setools.sefs.*;
%}
%pragma(java) jniclasscode=%{
	static {
		System.loadLibrary("jpolsearch");
	}
%}
%pragma(java) moduleimports=%{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
import com.tresys.setools.sefs.*;
%}

%javaconst(1);

#else
/* not in java so handle size_t as architecture dependent */
#ifdef SWIGWORDSIZE64
typedef uint64_t size_t;
#else
typedef uint32_t size_t;
#endif

#endif  // end of Java specific code

#ifdef SWIGTCL

/* implement a custom non thread-safe error handler */
%{
static char *message = NULL;
static void tcl_clear_error(void)
{
        free(message);
        message = NULL;
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
 * Sefs_Init(), but the output file will be called libtsefs.so instead
 * of libsefs.so.  Therefore add an alias from Tsefs_Init() to the
 * real Sefs_Init().
 */
SWIGEXPORT int Tsefs_Init(Tcl_Interp *interp) {
	return SWIG_init(interp);
}
%}

%typemap(out) time_t {
	Tcl_SetObjResult(interp, Tcl_NewLongObj((long) $1));
}

#endif  // end of Tcl specific code


%nodefaultctor;
%include std_string.i
%include std_vector.i
%naturalvar std::string;

%ignore fcentry_callback;
//Java can't handle const and non-const versions of same function
%ignore polsearch_criterion::param()const;

#define __attribute__(x)

#define SWIG_FRIENDS

const char *libpolsearch_get_version (void);

%include <polsearch/polsearch.hh>
%include <polsearch/query.hh>
%include <polsearch/bool_query.hh>
%include <polsearch/test.hh>
%include <polsearch/criterion.hh>
%include <polsearch/parameter.hh>
%include <polsearch/bool_parameter.hh>
%include <polsearch/level_parameter.hh>
%include <polsearch/number_parameter.hh>
%include <polsearch/range_parameter.hh>
%include <polsearch/regex_parameter.hh>
%include <polsearch/result.hh>
%include <polsearch/proof.hh>

//tell SWIg which types of vectors the target language will need
namespace std {
	%template(testVector) vector<polsearch_test>;
	%template(criterionVector) vector<polsearch_criterion>;
	%template(resultVector) vector<polsearch_result>;
	%template(proofVector) vector<polsearch_proof>;
	%template(testCondVector) vector<polsearch_test_cond_e>;
	%template(opVector) vector<polsearch_op_e>;
	%template(paramTypeVector) vector<polsearch_param_type_e>;
	%template(stringVector) vector<string>;
	%template(cvoidVector) vector<const void *>;
}

#ifdef SWIGPYTHON
%wrapper %{
	namespace swig {
		template <>
		struct traits<void> {
			typedef pointer_category category;
			static const char *type_name() {return "void*";}
		};
	}
%}
#endif
