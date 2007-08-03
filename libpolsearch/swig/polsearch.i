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
/*#include <polsearch/criterion.hh>
#include <polsearch/polsearch.hh>
#include <polsearch/query.hh>
//#include <polsearch/string_list.hh>   TODO
#include <polsearch/symbol_query.hh>
#include <polsearch/test.hh>          */
#include <polsearch/util.hh>            /*

#include <sefs/fclist.hh>
#include <sefs/fcfile.hh>
#include <sefs/filesystem.hh>
#include <sefs/db.hh>
#include <sefs/entry.hh>
  */
#include <string>
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
%naturalvar std::string;

#define __attribute__(x)

const char *libpolsearch_get_version (void);

#if 0 //TODO put stuff back
%include <polsearch/criterion.hh>
#ifndef SWIGJAVA
%include <polsearch/polsearch.hh>
#endif
%include <polsearch/query.hh>
%include <polsearch/symbol_query.hh>
%include <polsearch/test.hh>


%template(polsearch_regex_criterion) polsearch_criterion<std::string>;
//%template(polsearch_string_list_criterion) polsearch_criterion<polsearch_string_list>; TODO
%template(polsearch_rule_type_criterion) polsearch_criterion<uint32_t>;
%template(polsearch_bool_criterion) polsearch_criterion<bool>;
%template(polsearch_level_criterion) polsearch_criterion<apol_mls_level_t*>;
%template(polsearch_range_criterion) polsearch_criterion<apol_mls_range_t*>;

%extend polsearch_result
{
	polsearch_result(void *x)
	{
		return static_cast<polsearch_result*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

%extend polsearch_proof
{
	polsearch_proof(void *x)
	{
		return static_cast<polsearch_proof*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

%extend polsearch_test
{
	polsearch_test(void *x)
	{
		return static_cast<polsearch_test*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

%extend polsearch_base_criterion
{
	polsearch_base_criterion(void *x)
	{
		return static_cast<polsearch_base_criterion*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

%extend polsearch_criterion<std::string>
{
	polsearch_criterion<std::string>(void *x)
	{
		return static_cast<polsearch_criterion<std::string>*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

%extend polsearch_criterion<uint32_t>
{
	polsearch_criterion<uint32_t>(void *x)
	{
		return static_cast<polsearch_criterion<uint32_t>*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

%extend polsearch_criterion<apol_mls_level_t*>
{
	polsearch_criterion<apol_mls_level_t*>(void *x)
	{
		return static_cast<polsearch_criterion<apol_mls_level_t*>*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

%extend polsearch_criterion<bool>
{
	polsearch_criterion<bool>(void *x)
	{
		return static_cast<polsearch_criterion<bool>*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

%extend polsearch_criterion<apol_mls_range_t*>
{
	polsearch_criterion<apol_mls_range_t*>(void *x)
	{
		return static_cast<polsearch_criterion<apol_mls_range_t*>*>(x);
	}
	void *toVoid()
	{
		return static_cast<void*>(self);
	}
};

// %extend polsearch_criterion<polsearch_string_list>
// {
// 	polsearch_criterion<polsearch_string_list>(void *x)
// 	{
// 		return static_cast<polsearch_criterion<polsearch_string_list>*>(x);
// 	}
// 	void *toVoid()
// 	{
// 		return static_cast<void*>(self);
// 	}
// };

// Java does not handle enums defined with other enum values correctly do this instead
#ifdef SWIGJAVA
	/** Value to indicate the overall matching behavior of the query */
	typedef enum polsearch_match
	{
		POLSEARCH_MATCH_ERROR = -1,	/*!< Error condition. */
		POLSEARCH_MATCH_ALL = 0,	/*!< Returned symbols must match all tests. */
		POLSEARCH_MATCH_ANY    /*!< Returned symbols must match at least one test. */
	} polsearch_match_e;

	/** Values to indicate the type of symbol for which to search */
	typedef enum polsearch_symbol
	{
		POLSEARCH_SYMBOL_NONE = 0,	/*!< only used for error conditions */
		POLSEARCH_SYMBOL_TYPE, /*!< query returns qpol_type_t */
		POLSEARCH_SYMBOL_ATTRIBUTE,	/*!< query returns qpol_type_t */
		POLSEARCH_SYMBOL_ROLE, /*!< query returns qpol_role_t */
		POLSEARCH_SYMBOL_USER, /*!< query returns qpol_user_t */
		POLSEARCH_SYMBOL_CLASS,	/*!< query returns qpol_class_t */
		POLSEARCH_SYMBOL_COMMON,	/*!< query returns qpol_common_t */
		POLSEARCH_SYMBOL_CATEGORY,	/*!< query returns qpol_cat_t */
		POLSEARCH_SYMBOL_LEVEL,	/*!< query returns qpol_level_t */
		POLSEARCH_SYMBOL_BOOL  /*!< query returns qpol_bool_t */
	} polsearch_symbol_e;

	/** Values to indicate the type of policy element. This is a superset of polsearch_symbol_e */
	typedef enum polsearch_element
	{
		POLSEARCH_ELEMENT_NONE = 0,	/*!< only used for error conditions */
		POLSEARCH_ELEMENT_TYPE,
		POLSEARCH_ELEMENT_ATTRIBUTE,
		POLSEARCH_ELEMENT_ROLE,
		POLSEARCH_ELEMENT_USER,
		POLSEARCH_ELEMENT_CLASS,
		POLSEARCH_ELEMENT_COMMON,
		POLSEARCH_ELEMENT_CATEGORY,
		POLSEARCH_ELEMENT_LEVEL,
		POLSEARCH_ELEMENT_BOOL,
		POLSEARCH_ELEMENT_STRING,	/*!< char * */
		POLSEARCH_ELEMENT_AVRULE,	/*!< qpol_avrule_t */
		POLSEARCH_ELEMENT_TERULE,	/*!< qpol_terule_t */
		POLSEARCH_ELEMENT_ROLE_ALLOW,	/*!< qpol_role_allow_t */
		POLSEARCH_ELEMENT_ROLE_TRANS,	/*!< qpol_role_trans_t */
		POLSEARCH_ELEMENT_RANGE_TRANS,	/*!< qpol_range_trans_t */
		POLSEARCH_ELEMENT_FC_ENTRY,	/*!< sefs_entry_t */
		POLSEARCH_ELEMENT_MLS_RANGE,	/*!< apol_mls_range_t */
		POLSEARCH_ELEMENT_PERMISSION,	/*!< char * */
		POLSEARCH_ELEMENT_BOOL_STATE	/*!< bool */
	} polsearch_element_e;

	/** Value to indicate the test condition */
	typedef enum polsearch_test_cond
	{
		POLSEARCH_TEST_NONE = 0,	/*!< only used for error conditions */
		POLSEARCH_TEST_NAME,   /*!< primary name of the symbol */
		POLSEARCH_TEST_ALIAS,  /*!< alias(es) of the symbol */
		POLSEARCH_TEST_ATTRIBUTES,	/*!< assigned attributes */
		POLSEARCH_TEST_ROLES,  /*!< assigned roles (or assigned to roles) */
		POLSEARCH_TEST_AVRULE, /*!< there is an av rule */
		POLSEARCH_TEST_TERULE, /*!< there is a type rule */
		POLSEARCH_TEST_ROLEALLOW,	/*!< there is a role allow rule */
		POLSEARCH_TEST_ROLETRANS,	/*!< there is a role_transition rule */
		POLSEARCH_TEST_RANGETRANS,	/*!< there is a range_transition rule */
		POLSEARCH_TEST_FCENTRY,	/*!< there is a file_contexts entry */
		POLSEARCH_TEST_TYPES,  /*!< assigned types */
		POLSEARCH_TEST_USERS,  /*!< assigned to users */
		POLSEARCH_TEST_DEFAULT_LEVEL,	/*!< its default level */
		POLSEARCH_TEST_RANGE,  /*!< assigned range */
		POLSEARCH_TEST_COMMON, /*!< inherited common */
		POLSEARCH_TEST_PERMISSIONS,	/*!< assigned permissions */
		POLSEARCH_TEST_CATEGORIES,	/*!< assigned categories */
		POLSEARCH_TEST_STATE   /*!< boolean default state */
	} polsearch_test_cond_e;

	/** Value to indicate the comparison operator for a parameter */
	typedef enum polsearch_op
	{
		POLSEARCH_OP_NONE = 0, /*!< only used for error conditions */
		POLSEARCH_OP_IS,       /*!< symbol (or state) is */
		POLSEARCH_OP_MATCH_REGEX,	/*!< symbol name (or alias name) matches regular expression */
		POLSEARCH_OP_RULE_TYPE,	/*!< is rule type */
		POLSEARCH_OP_INCLUDE,  /*!< set includes */
		POLSEARCH_OP_AS_SOURCE,	/*!< has as rule source */
		POLSEARCH_OP_AS_TARGET,	/*!< has as rule target */
		POLSEARCH_OP_AS_CLASS, /*!< has as rule class */
		POLSEARCH_OP_AS_PERM,  /*!< has as rule permission */
		POLSEARCH_OP_AS_DEFAULT,	/*!< has as rule default */
		POLSEARCH_OP_AS_SRC_TGT,	/*!< has as rule source or target */
		POLSEARCH_OP_AS_SRC_TGT_DFLT,	/*!< has as rule source, target, or default */
		POLSEARCH_OP_AS_SRC_DFLT,	/*!< has as rule source or default */
		POLSEARCH_OP_IN_COND,  /*!< is in a conditional with boolean */
		POLSEARCH_OP_AS_LEVEL_EXACT,	/*!< user level exact comparison */
		POLSEARCH_OP_AS_LEVEL_DOM,	/*!< user level dominates parameter */
		POLSEARCH_OP_AS_LEVEL_DOMBY,	/*!< user level dominated by parameter */
		POLSEARCH_OP_AS_RANGE_EXACT,	/*!< has exactly range */
		POLSEARCH_OP_AS_RANGE_SUPER,	/*!< has range that is a superset of parameter */
		POLSEARCH_OP_AS_RANGE_SUB,	/*!< has that is a subset of parameter range */
		POLSEARCH_OP_AS_USER,  /*!< has as user */
		POLSEARCH_OP_AS_ROLE,  /*!< has as role */
		POLSEARCH_OP_AS_TYPE   /*!< has as type */
	} polsearch_op_e;

	/** Value to indicate the type of the parameter value of a criterion */
	typedef enum polsearch_param_type
	{
		POLSEARCH_PARAM_TYPE_NONE = 0,	/*!< only used for error conditions */
		POLSEARCH_PARAM_TYPE_REGEX,	/*!< parameter is a string (std::string) representing a regular expression */
		POLSEARCH_PARAM_TYPE_STR_LIST,	/*!< parameter is a string list (polsearch_string_list) */
		POLSEARCH_PARAM_TYPE_RULE_TYPE,	/*!< parameter is a rule type code (uint32_t) */
		POLSEARCH_PARAM_TYPE_BOOL,	/*!< parameter is a boolean value (bool) */
		POLSEARCH_PARAM_TYPE_LEVEL,	/*!< parameter is an apol_mls_level_t * */
		POLSEARCH_PARAM_TYPE_RANGE	/*!< parameter is an apol_mls_range_t * */
	} polsearch_param_type_e;

#endif

#endif //TODO end of if 0
