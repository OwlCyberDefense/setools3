/**
 *  @file
 *  Defines the public interface for all sechecker modules and the library.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef SECHECKER_H
#define SECHECKER_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <config.h>

#include <stdbool.h>

#include <apol/policy.h>
#include <apol/policy-path.h>
#include <apol/policy-query.h>
#include <apol/vector.h>
#include <apol/util.h>

#include <sefs/file_contexts.h>
#include <libxml/xmlstring.h>

/* These should be defined from the make environment */
#ifndef PROF_SUBDIR
#define PROF_SUBDIR "/sechecker-profiles"
#endif
#ifndef DEFAULT_PROFILE
#define DEFAULT_PROFILE ""
#endif

/* defined flags for outformat */
/* report components */
#define SECHK_OUT_STATS		0x01
#define SECHK_OUT_LIST		0x02
#define SECHK_OUT_PROOF		0x04
/* mode flags from command line and test profiles */
/* NOTE: none is only valid in profiles */
#define SECHK_OUT_NONE    0x00
#define SECHK_OUT_QUIET   0x20
#define SECHK_OUT_SHORT   (SECHK_OUT_STATS|SECHK_OUT_LIST)
#define SECHK_OUT_VERBOSE (SECHK_OUT_STATS|SECHK_OUT_PROOF)

	typedef void (*free_fn_t) (void *x);

/* severity categories */
#define SECHK_SEV_NONE "none"
#define SECHK_SEV_LOW  "low"
#define SECHK_SEV_MED  "med"
#define SECHK_SEV_HIGH "high"

/* module requirement name strings */
/** Require that the loaded policy has a given capability;
 *  values should be set as one of SECHK_REQ_CAP_* from below. */
#define SECHK_REQ_POLICY_CAP       "capability"
/** Require that the running system supports a given feature;
 *  values should be set as one of SECHK_REQ_SYS_* from below. */
#define SECHK_REQ_SYSTEM           "system"
/** Require a file_contexts file to be loaded.
 *  This requirement has no associated value text. */
#define SECHK_REQ_FILE_CONTEXTS    "file_contexts"
/** Require a default_contexts file to be loaded.
 *  This requirement has no associated value text. */
#define SECHK_REQ_DEFAULT_CONTEXTS "default_contexts"

/* policy capability requirement strings: map to QPOL_CAP_* in policy_query.h */
/** Require that the loaded policy supports attribute names. */
#define SECHK_REQ_CAP_ATTRIB_NAMES "attribute names"
/** Require that the loaded policy supports syntactic rules. */
#define SECHK_REQ_CAP_SYN_RULES    "syntactic rules"
/** Require that the loaded policy supports line numbers. */
#define SECHK_REQ_CAP_LINE_NOS     "line numbers"
/** Require that the loaded policy supports booleans and conditional statements. */
#define SECHK_REQ_CAP_CONDITIONALS "conditionals"
/** Require that the loaded policy supports MLS. */
#define SECHK_REQ_CAP_MLS          "mls"
/** Require that the loaded policy supports module loading. */
#define SECHK_REQ_CAP_MODULES      "module loading"
/** Require that the loaded policy includes av/te rules. */
#define SECHK_REQ_CAP_RULES_LOADED "rules loaded"

/* system requirement strings */
/** Require that the running system is a SELinux system. */
#define SECHK_REQ_SYS_SELINUX "selinux"
/** Require that the running system supports MLS*/
#define SECHK_REQ_SYS_MLS     "mls"

/** item and proof element types to denote casting of the void pointer */
	typedef enum sechk_item_type
	{
		SECHK_ITEM_CLASS,      /* qpol_class_t */
		SECHK_ITEM_COMMON,     /* qpol_common_t */
		SECHK_ITEM_PERM,       /* char * representing the permission name */
		SECHK_ITEM_CONSTR,     /* qpol_constraint_t */
		SECHK_ITEM_VTRANS,     /* qpol_validatetrans_t */
		SECHK_ITEM_QLEVEL,     /* qpol_level_t */
		SECHK_ITEM_CAT,	       /* qpol_cat_t */
		SECHK_ITEM_QMLSLEVEL,  /* qpol_mls_level_t */
		SECHK_ITEM_QMLSRANGE,  /* qpol_mls_range_t */
		SECHK_ITEM_AMLSLEVEL,  /* apol_mls_level_t */
		SECHK_ITEM_AMLSRANGE,  /* apol_mls_range_t */
		SECHK_ITEM_TYPE,       /* qpol_type_t */
		SECHK_ITEM_ATTRIB,     /* qpol_type_t but is an atribute not a type */
		SECHK_ITEM_ROLE,       /* qpol_role_t */
		SECHK_ITEM_USER,       /* qpol_user_t */
		SECHK_ITEM_COND,       /* qpol_cond_t */
		SECHK_ITEM_AVRULE,     /* qpol_avrule_t */
		SECHK_ITEM_TERULE,     /* qpol_terule_t */
		SECHK_ITEM_RALLOW,     /* qpol_role_allow_t */
		SECHK_ITEM_RTRAMS,     /* qpol_role_trans_t */
		SECHK_ITEM_RANGETRANS, /* qpol_range_trans_t */
		SECHK_ITEM_BOOL,       /* qpol_bool_t */
		SECHK_ITEM_FSUSE,      /* qpol_fs_use_t */
		SECHK_ITEM_GENFSCON,   /* qpol_genfscon_t */
		SECHK_ITEM_ISID,       /* qpol_isid_t */
		SECHK_ITEM_NETIFCON,   /* qpol_netifcon_t */
		SECHK_ITEM_NODECON,    /* qpol_nodecon_t */
		SECHK_ITEM_PORTCON,    /* qpol_portcon_t */
		SECHK_ITEM_CONTEXT,    /* qpol_context_t */
		/* add more here as needed */
		SECHK_ITEM_FCENT,      /* sefs_fc_entry_t */
		SECHK_ITEM_STR,	       /* char* generic string */
		SECHK_ITEM_DTR,	       /* apol_domain_trans_result_t */
		SECHK_ITEM_OTHER,      /* void* data is something else (module specific) */
		SECHK_ITEM_NONE	       /* there is no proof element only text */
	} sechk_item_type_e;

/** Module results proof element: This represents a single reason for the
 *  inclusion of an item in the results. */
	typedef struct sechk_proof
	{
	/** Component, rule, or other object relative to the policy */
		void *elem;
	/** The type of element stored by this proof */
		sechk_item_type_e type;
	/** Description of proof for prining the report */
		char *text;
		xmlChar *xml_out;      /* currently unused but retained for future use */
	/** Function to call if elem should be free()'d or NULL */
		free_fn_t elem_free_fn;
	} sechk_proof_t;

/** Module results item:
 *  This represents an item for which results were found. */
	typedef struct sechk_item
	{
	/** The policy item */
		void *item;
	/** Test result code for this item. This field is reserved for use
	 *  only within the module creating the item. */
		unsigned char test_result;
	/** Vector of proof elements (of type sechk_proof_t) indicating
	 *  why an item appears in the results. */
		apol_vector_t *proof;
	/** Function to call if item should be free()'d or NULL */
		free_fn_t item_free_fn;
	} sechk_item_t;

/** Module results: This represents the results generated by a module's
 *  run function. This structure is used both to generate the report and
 *  to comunicate with other modules that depend on the generating module. */
	typedef struct sechk_result
	{
	/** Name of the module that created the results. */
		char *test_name;
	/** The type of policy item processed by the module. */
		sechk_item_type_e item_type;
	/** Vector of items for which results were found (of type sechk_item_t). */
		apol_vector_t *items;
	} sechk_result_t;

/** Generic name value pair:
 *  Used for storing options, dependencies and requirements. */
	typedef struct sechk_name_value
	{
		char *name;
		char *value;
	} sechk_name_value_t;

/** Module library:
 *  This structure tracks all modules that SEChecker can run,
 *  the policy, and other policy related data. */
	typedef struct sechk_lib
	{
	/** Vector of the modules (of type sechk_module_t) */
		apol_vector_t *modules;
	/** The policy to analyze when running modules */
		apol_policy_t *policy;
	/** Vector of file contexts data (of type sefs_fc_entry_t).
	 *  (Only available with libsefs support) */
		apol_vector_t *fc_entries;
	/** File name of the file_contexts file loaded.
	 *  (Only available with libsefs support) */
		char *fc_path;
	/** The default output format for the report */
		unsigned char outputformat;
	/** The path for the selinux configuration file */
		char *selinux_config_path;
	/** File name of the policy loaded.*/
		apol_policy_path_t *policy_path;
	/** Minimum severity level specified for the report. */
		const char *minsev;
	} sechk_lib_t;

	typedef struct sechk_module
	{
	/** Unique module name */
		char *name;
	/** Brief description of the module */
		const char *brief_description;
	/** Detailed description of the module. This should include a listing of
	 *  of all steps performed by the module's checks. */
		const char *detailed_description;
	/** Description of options, requirements, and dependencies */
		const char *opt_description;
	/** Results generated by this module. */
		sechk_result_t *result;
	/** Vector (of type sechk_name_value_t) containing all user specified
	 *  options for this module. */
		apol_vector_t *options;
	/** Vector (of type sechk_name_value_t) containing all conditions required
	 *  by the module such as policy version or type. See profile documentation
	 *  for a complete listing of possible requirements. */
		apol_vector_t *requirements;
	/** Vector (of type sechk_name_value_t) containing a list of modules
	 *  which need to run before this module may access their results. */
		apol_vector_t *dependencies;
	/** Vector (of type sechk_fn_t) of all functions registered for this module.
	 *  All modules are required to have at least three: init, run, and print. */
		apol_vector_t *functions;
	/** Default output format for the report. */
		unsigned char outputformat;
	/** This field is used by the library to indicate that the user or another
	 *  module has selected this module to be run. */
		bool selected;
	/** The severity level of this module's results. One of SECHK_SEV_* above. */
		const char *severity;
	/** The module's private data. This includes data generated when processing
	 *  options and from reading its dependencies' results. */
		void *data;
	/** Function to be used to free the private data. */
		free_fn_t data_free;
	/** Pointer to the module's parent library. */
		const sechk_lib_t *parent_lib;
	} sechk_module_t;

/* Module function signatures */
/**
 *  Function signature for the function to register a module with the library.
 *
 *  @param lib The library with which to register.
 *
 *  @return 0 on success and < 0 on failure; if the call fails, errno will be
 *  set and the library should be destroyed.
 */
	typedef int (*sechk_register_fn_t) (sechk_lib_t * lib);

/**
 *  Function signature for functions registed by a module.
 *
 *  @param mod The module performing the operation.
 *  @param policy The policy accessed by the module.
 *  @param arg Arbitrary third parameter for use by the function.
 *
 *  @return 0 on success, or < 0 on fatal error. If the call fails,
 *  it is expected to set errno. Special: a run function is permitted
 *  to return > 0 upon finding results; only the run function may return > 0.
 */
	typedef int (*sechk_mod_fn_t) (sechk_module_t * mod, apol_policy_t * policy, void *arg);

/* Module function names */
#define SECHK_MOD_FN_INIT    "init"
#define SECHK_MOD_FN_RUN     "run"
#define SECHK_MOD_FN_PRINT   "print"

/** Registered function container: used to allow the library and modules
 *  to request functions of a specific name. */
	typedef struct sechk_fn
	{
	/** Name of the function without any module prefix */
		char *name;
	/** The function. */
		sechk_mod_fn_t fn;
	} sechk_fn_t;

/** Module name registration structure: used when the library tries to
 *  discover all known modules. */
	typedef struct sechk_module_name_reg
	{
	/** The name of the module. */
		char *name;
	/** The register function for this module. */
		sechk_register_fn_t fn;
	} sechk_module_name_reg_t;

/** Profile name registration structure; used when the library tries to
 *  discover all known installed profiles. */
	typedef struct sechk_profile_name_reg
	{
	/** Name of the profile. */
		char *name;
	/** Path of the profile file. */
		char *file;
	/** Description of the modules run by the profile. */
		char *desc;
	} sechk_profile_name_reg_t;

/* alloc methods */

/**
 *  Create a new module library object.
 *
 *  @return A newly allocated module library or NULL on ENOMEM.
 *  The caller is responsible for calling sechk_lib_destroy()
 *  to free memory used by the library returned.
 */
	sechk_lib_t *sechk_lib_new(void);

/**
 *  Create a new module structure.
 *
 *  @return A newly allocated module or NULL on ENOMEM.
 *  The caller is resbonsible for calling sechk_module_free()
 *  to free memory used by the module returned.
 */
	sechk_module_t *sechk_module_new(void);

/**
 *  Create a new module function structre.
 *
 *  @return A newly allocated module function structure or NULL on ENOMEM.
 *  The caller is responsible for calling sechk_fn_free() to free memory
 *  used by the function structure returned.
 */
	sechk_fn_t *sechk_fn_new(void);

/**
 *  Create and initialize a new name value pair.
 *  The incoming strings are duplicated.
 *
 *  @param name Name to assign.
 *  @param value Value to assign to name.
 *
 *  @return A newly allocated name value pair of NULL on error; if the
 *  call fails errno will be set.
 */
	sechk_name_value_t *sechk_name_value_new(const char *name, const char *value);

/**
 *  Create a new results structure.
 *
 *  @return A newly allocated results structure or NULL on ENOMEM.
 *  The caller is responsible for calling sechk_result_destroy() to free
 *  the memory used by the returned result structure.
 */
	sechk_result_t *sechk_result_new(void);

/**
 *  Create a new result item.
 *
 *  @param fn Function to be used to free the item stored.
 *
 *  @return A newly allocated result item or NULL on ENOMEM.
 *  The caller is responsible for calling sechk_item_free() to free
 *  the memory used by the returned item.
 */
	sechk_item_t *sechk_item_new(free_fn_t fn);

/**
 *  Create a new result item proof entry.
 *
 *  @param fn Function to be used to free the element stored.
 *
 *  @return A newly allocated proof structure or NULL on ENOMEM.
 *  The caller is responsible for calling sechk_proof_free() to free
 *  the memory used by teh returned proof.
 */
	sechk_proof_t *sechk_proof_new(free_fn_t fn);

/* free methods */

/**
 *  Free all memory used by a module library and set it to NULL.
 *
 *  @param The library to destroy.
 */
	void sechk_lib_destroy(sechk_lib_t ** lib);

/**
 *  Free all memory used by a module function structure.
 *
 *  @param fn_struct The function structure to free.
 */
	void sechk_fn_free(void *fn_struct);

/**
 *  Free all memory used by a result structure and set it to NULL.
 *
 *  @param res The result structure to destroy.
 */
	void sechk_result_destroy(sechk_result_t ** res);

/**
 *  Free all memory used by a result item.
 *
 *  @param item The result item to free.
 */
	void sechk_item_free(void *item);

/**
 *  Free all memory used by a result item proof element.
 *
 *  @param proof The proof element to free.
 */
	void sechk_proof_free(void *proof);

/**
 *  Free all memory used by a module.
 *
 *  @param module The module to free.
 */
	void sechk_module_free(void *module);

/**
 *  Free all memory used by a name value pair.
 *
 *  @param nv The name value pair to free.
 */
	void sechk_name_value_free(void *nv);

/* register/check_dep/init/run/print -  modules */
/**
 *  Register all known modules with the library.
 *
 *  @param regiser_fns NULL terminated array of module registration structures.
 *  @param lib The library with which to register the modules in the array.
 *
 *  @return 0 on success or < 0 on error; if the call fails, errno will be
 *  set and the library should be destroyed.
 */
	int sechk_lib_register_modules(const sechk_module_name_reg_t * register_fns, sechk_lib_t * lib);

/**
 *  Check that the dependencies of all selected modules can be met.
 *  This function will select additional modules if needed by those
 *  already selected to be run.
 *
 *  @param lib The library containing the modules to check.
 *
 *  @return 0 on success and < 0 on error; if the call fails,
 *  errno will be set.
 */
	int sechk_lib_check_module_dependencies(sechk_lib_t * lib);

/**
 *  Check that the requirements of all selected modules are met.  If the
 *  requirements are not met for a module and the library's default reporting
 *  mode is not SECHK_OUT_QUIET, the module will be deselected so that others
 *  might be checked.  If the library is set to quiet, this function exits on
 *  the first module found to not meet its requirements.  <b>This function
 *  should only be called after sechk_lib_check_module_dependencies()</b>
 *
 *  @param lib The library containing the modules to check.
 *
 *  @return 0 on success and < 0 on error; if the call fails,
 *  errno will be set.
 */
	int sechk_lib_check_module_requirements(sechk_lib_t * lib);

/**
 *  Initialize all selected modules. <b>This function should only be called
 *  after both sechk_lib_check_module_dependencies() and
 *  sechk_lib_check_module_requirements() have been called.</b>
 *
 *  @param lib The library containing the modules to initialize.
 *
 *  @return 0 on success and < 0 on failure; if the call fails, errno will be
 *  set and the library should be destroyed.
 */
	int sechk_lib_init_modules(sechk_lib_t * lib);

/**
 *  Run all selected modules. The modules must have been initialized.
 *
 *  @param lib The library containing the modules to run.
 *
 *  @return 0 on success or < 0 on error. Note that in quiet mode this
 *  function is considered to fail if a module finds results.
 */
	int sechk_lib_run_modules(sechk_lib_t * lib);

/**
 *  Print a report of all selected modules' results to stdout.
 *  Modules must have been run.
 *
 *  @param lib The library containing the modules with results to print.
 *
 *  @return 0 on success and < 0 on error.
 */
	int sechk_lib_print_modules_report(sechk_lib_t * lib);

/* module accessors */

/**
 *  Find a module in the library.
 *
 *  @param module_name The name of the module to find.
 *  @param lib The library to search.
 *
 *  @return A pointer to the module or NULL if not found.
 */
	sechk_module_t *sechk_lib_get_module(const char *module_name, const sechk_lib_t * lib);

/**
 *  Get a pointer to a function registered for a module.
 *
 *  @param module_name Name of the module containing the function.
 *  @param function_name Name of the function with out any module prefix.
 *  @param lib The library containing the module.
 *
 *  @return A pointer to the requested function, or NULL if either the module
 *  or the function cannot be found.
 */
	sechk_mod_fn_t sechk_lib_get_module_function(const char *module_name, const char *function_name, const sechk_lib_t * lib);

/**
 *  Get the results of a module. If the module has not been run, it will be run
 *  and its results will be returned if it succeeds.
 *
 *  @param module_name Name of the module containing the results.
 *  @param lib The library containing the module.
 *
 *  @return The requested module's results or NULL on error. If the module
 *  was not previously run and it fails when run by this function, NULL
 *  will be returned. If the call fails, errno will be set.
 */
	sechk_result_t *sechk_lib_get_module_result(const char *module_name, const sechk_lib_t * lib);

/* library utility functions */

/**
 *  Load the policy the library will analyze.
 *
 *  @param policy_mods Policy path object to use to load the policy.
 *  @param lib The library into which to load the policy.
 *
 *  @return 0 on success and < 0 on failure.
 */
	int sechk_lib_load_policy(apol_policy_path_t * policy_mods, sechk_lib_t * lib);

/**
 *  Load the file contexts file the library will use during analysis.
 *  (Only available with libsefs support)
 *
 *  @param fcfilelocation Path of the file contexts file to load, or
 *  NULL to search for system default file contexts.
 *  @param lib The library into which to load the file contexts.
 *
 *  @return 0 on success and < 0 on failure.
 */
	int sechk_lib_load_fc(const char *fcfilelocation, sechk_lib_t * lib);

/**
 *  Load a profile containing module options.
 *
 *  @param prof_name Name of a known installed profile or the absolute path
 *  to a user created profile.
 *  @param lib The library containing the modules specified in the profile.
 *
 *  @return 0 on success and < 0 on failure; if the call fails errno will be
 *  set and the library should be destroyed.
 */
	int sechk_lib_load_profile(const char *prof_name, sechk_lib_t * lib);

/**
 *  Clear an option of all previous values.
 *
 *  @param module Module containing the option to clear.
 *  @param option Name of the option to clear.
 *
 *  @return 0 on success or < 0 on failure; if the call fails,
 *  errno will be set, and the module should be freed.
 */
	int sechk_lib_module_clear_option(sechk_module_t * module, char *option);

/**
 *  Check that the library can meet a single requirement.
 *
 *  @param req The requirement to check.
 *  @param lib The library to query.
 *
 *  @return 1 if the requirement is met, and 0 if it is either unmet or
 *  if the library is unable to determine.
 */
	bool sechk_lib_check_requirement(sechk_name_value_t * req, sechk_lib_t * lib);

/**
 *  Check that the library can meet a single module dependency.
 *
 *  @param dep The dependency to check.
 *  @param lib The library to query for the existence of the dependency.
 *
 *  @return 1 if the dependency exists, and 0 if it either does not or
 *  if the library is unable to determine.
 */
	bool sechk_lib_check_dependency(sechk_name_value_t * dep, sechk_lib_t * lib);

/**
 *  Set the default output format for the library.
 *
 *  @param out The format to use as a bit-wise or of SECHK_OUT_*.
 *  @param lib The library for which to set the output format.
 *
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set.
 */
	int sechk_lib_set_outputformat(unsigned char out, sechk_lib_t * lib);

/**
 *  Set the minimum severity level of the library.
 *
 *  @param sev Severity level to set as the minimum level for reporting.
 *  Must be one of SECHK_SEV_*.
 *  @param lib The library for which to set the minimum severity level.
 *
 *  @return 0 on success and < 0 on failure; if the call fials,
 *  errno will be set.
 */
	int sechk_lib_set_minsev(const char *sev, sechk_lib_t * lib);

/**
 *  Get the index of a module in the library by name.
 *
 *  @param name Name of the module for which to get the index.
 *  @param lib The library containing the desired module.
 *
 *  @return index of the module or -1 if it was not found.
 *  If not found, errno will be set.
 */
	int sechk_lib_get_module_idx(const char *name, sechk_lib_t * lib);

/* other utility functions */

/**
 *  Copy a proof element. Note: the element in the proof is a shallow copy.
 *
 *  @param orig The original proof to copy.
 *
 *  @return a copy of the proof or NULL on error. If the call fails,
 *  errno will be set.
 */
	sechk_proof_t *sechk_proof_copy(sechk_proof_t * orig);

/**
 *  Callback for vector comparison of proof elements.
 *  This callback takes two different type objects both cast to void
 *  it is important that the order of the parameters is correct or the
 *  vector code will fail when using this callback.
 *
 *  @param in_proof One member of the vector of proofs.
 *  @param elem A policy item to compare to the proof's element.
 *  @param unused Unused. Needed to satisfy vector prototype.
 *
 *  @return Pointer comparison value of < 0, 0 or > 0 if the element in the
 *  proof is respectively less than, equal to, or greater than that of the
 *  comparison element supplied.
 */
	int sechk_proof_with_element_compare(const void *in_proof, const void *elem, void *unused);

#ifdef	__cplusplus
}
#endif

#endif				       /* SECHECKER_H */
