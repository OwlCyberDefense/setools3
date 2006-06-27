/* Copyright (C) 2005-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/*
 * Author: jmowery@tresys.com
 *
 * sechecker.h
 *
 */

#ifndef SECHECKER_H
#define SECHECKER_H

#include <config.h>

#include <policy.h>
#include <vector.h>
#include <util.h>

#ifdef LIBSEFS
#include <libsefs/file_contexts.h>
#endif
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
/* mode flags from command line, test profiles, and comfig file */
/* NOTE: none is only valid in profiles */
#define SECHK_OUT_NONE    0x00
#define SECHK_OUT_QUIET   0x20
#define SECHK_OUT_SHORT   (SECHK_OUT_STATS|SECHK_OUT_LIST)
#define SECHK_OUT_VERBOSE (SECHK_OUT_STATS|SECHK_OUT_PROOF)

typedef void (*free_fn_t)(void *x);

/* severity categories used in proof elements */
#define SECHK_SEV_NONE "none"
#define SECHK_SEV_LOW  "low"
#define SECHK_SEV_MED  "med"
#define SECHK_SEV_HIGH "high"

/* item and proof element types to denote casting of the void pointer */
typedef enum sechk_item_type {
	SECHK_ITEM_CLASS,	/* qpol_class_t */
	SECHK_ITEM_COMMON,	/* qpol_common_t */
	SECHK_ITEM_PERM,	/* char * representing the permission name */
	SECHK_ITEM_CONSTR,	/* qpol_constraint_t */
	SECHK_ITEM_VTRANS,	/* qpol_validatetrans_t */
	SECHK_ITEM_QLEVEL,	/* qpol_level_t */
	SECHK_ITEM_CAT,		/* qpol_cat_t */
	SECHK_ITEM_QMLSLEVEL,	/* qpol_mls_level_t */
	SECHK_ITEM_QMLSRANGE,	/* qpol_mls_range_t */
	SECHK_ITEM_AMLSLEVEL,	/* apol_mls_level_t */
	SECHK_ITEM_AMLSRANGE,	/* apol_mls_range_t */
	SECHK_ITEM_TYPE,	/* qpol_type_t */
	SECHK_ITEM_ATTRIB,	/* qpol_type_t but is an atribute not a type */
	SECHK_ITEM_ROLE,	/* qpol_role_t */
	SECHK_ITEM_USER,	/* qpol_user_t */
	SECHK_ITEM_COND,	/* qpol_cond_t */
	SECHK_ITEM_AVRULE,	/* qpol_avrule_t */
	SECHK_ITEM_TERULE,	/* qpol_terule_t */
	SECHK_ITEM_RALLOW,	/* qpol_role_allow_t */
	SECHK_ITEM_RTRAMS,	/* qpol_role_trans_t */
	SECHK_ITEM_RANGETRANS,	/* qpol_range_trans_t */
	SECHK_ITEM_BOOL,	/* qpol_bool_t */
	SECHK_ITEM_FSUSE,	/* qpol_fs_use_t */
	SECHK_ITEM_GENFSCON,	/* qpol_genfscon_t */
	SECHK_ITEM_ISID,	/* qpol_isid_t */
	SECHK_ITEM_NETIFCON,	/* qpol_netifcon_t */
	SECHK_ITEM_NODECON,	/* qpol_nodecon_t */
	SECHK_ITEM_PORTCON,	/* qpol_portcon_t */
	SECHK_ITEM_CONTEXT,	/* qpol_context_t */
	/* add more here as needed */
	SECHK_ITEM_FCENT,	/* sefs_fc_entry_t */
	SECHK_ITEM_STR,		/* char* generic string */
	SECHK_ITEM_OTHER,	/* void* data is something else (module specific) */
	SECHK_ITEM_NONE		/* there is no proof only text */
} sechk_item_type_e;

/* module results proof element */
typedef struct sechk_proof {
	void			*elem;
	sechk_item_type_e	type;
	char			*text;
	xmlChar			*xml_out;	/* currently unused but retained for future use */
	free_fn_t		elem_free_fn;	/* function to call if elem should be free()'d or NULL */
} sechk_proof_t;

typedef struct sechk_item {
	void		*item;
	unsigned char	test_result;
	apol_vector_t	*proof;		/* of type sechk_proof_t */
	free_fn_t	item_free_fn;	/* function to call if item should be free()'d or NULL */
} sechk_item_t;

typedef struct sechk_result {
	char			*test_name;
	sechk_item_type_e	item_type;	/* type of item in results */
	apol_vector_t		*items;		/* of type sechk_item_t */
} sechk_result_t;

typedef struct sechk_name_value {
	char		 *name;
	char		 *value;
} sechk_name_value_t;

typedef struct sechk_lib {
	apol_vector_t	*modules;		/* test modules (sechk_module_t)*/
	apol_policy_t	*policy;		/* policy data */
#ifdef LIBSEFS
	apol_vector_t	*fc_entries;		/* file contexts data (sefs_fc_entry_t) */
	char		*fc_path;		/* file contexts filename */
#endif
	unsigned char	outputformat;
	char		*selinux_config_path;
	char		*policy_path;		/* policy filename */
	const char      *minsev;
} sechk_lib_t;

typedef struct sechk_module {
	char		*name;			/* unique module name */
	const char	*brief_description;	/* brief description of the module */
	const char	*detailed_description;	/* detailed description of the module */
	const char	*opt_description;	/* description of options, requirements, and dependencies */
	sechk_result_t	*result;		/* test results */
	/* three vectors of sechk_name_value_t */ 
	apol_vector_t	*options;		/* test inputs */ 
	apol_vector_t	*requirements;		/* conditions required such as policy version */
	apol_vector_t	*dependencies;		/* other modules needed to run */
	apol_vector_t	*functions;		/* register/init/run/free/print of sechk_fn_t */
	unsigned char	outputformat;		/* default output format */
	bool_t		selected;
	const char	*severity;
	void		*data;
	const sechk_lib_t *parent_lib;		/* pointer to parent library */
} sechk_module_t;

/* Module function signatures */
typedef int (*sechk_register_fn_t)(sechk_lib_t *lib);
typedef int (*sechk_init_fn_t)(sechk_module_t *mod, apol_policy_t *policy);
typedef int (*sechk_run_fn_t)(sechk_module_t *mod, apol_policy_t *policy);
typedef void (*sechk_data_free_fn_t)(void *data);
typedef int (*sechk_print_output_fn_t)(sechk_module_t *mod, apol_policy_t *policy);
typedef sechk_result_t *(*sechk_get_result_fn_t)(sechk_module_t *mod);

/* Module function names */
#define SECHK_MOD_FN_INIT    "init"
#define SECHK_MOD_FN_RUN     "run"
#define SECHK_MOD_FN_FREE    "data_free"
#define SECHK_MOD_FN_PRINT   "print_output"
#define SECHK_MOD_FN_GET_RES "get_result"

typedef struct sechk_fn {
	char	*name;
	void	*fn;
} sechk_fn_t;

typedef struct sechk_module_name_reg {
	char			*name;
	sechk_register_fn_t	fn;
} sechk_module_name_reg_t;

typedef struct sechk_profile_name_reg {
	char *name;
	char *file;
	char *desc;
} sechk_profile_name_reg_t;

/* alloc methods */
sechk_lib_t *sechk_lib_new(void);
sechk_module_t *sechk_module_new(void);
sechk_fn_t *sechk_fn_new(void);
sechk_name_value_t *sechk_name_value_new(const char *name, const char *value);
sechk_result_t *sechk_result_new(void);
sechk_item_t *sechk_item_new(free_fn_t fn);
sechk_proof_t *sechk_proof_new(free_fn_t fn);

/* free methods */
void sechk_lib_destroy(sechk_lib_t **lib);
void sechk_fn_free(void *fn_struct);
void sechk_result_destroy(sechk_result_t **res);
void sechk_item_free(void *item);
void sechk_proof_free(void *proof);
void sechk_module_free(void *module);
void sechk_name_value_free(void *nv);

/* register/check_dep/init/run/print -  modules */
int sechk_lib_register_modules(const sechk_module_name_reg_t *register_fns, sechk_lib_t *lib);
int sechk_lib_check_module_dependencies(sechk_lib_t *lib);
int sechk_lib_check_module_requirements(sechk_lib_t *lib);
int sechk_lib_init_modules(sechk_lib_t *lib);
int sechk_lib_run_modules(sechk_lib_t *lib);
int sechk_lib_print_modules_report(sechk_lib_t *lib);

/* module accessors */
sechk_module_t *sechk_lib_get_module(const char *module_name, const sechk_lib_t *lib);
void *sechk_lib_get_module_function(const char *module_name, const char *function_name, const sechk_lib_t *lib);

/* library utility functions */
int sechk_lib_load_policy(const char *policyfilelocation, sechk_lib_t *lib);
#ifdef LIBSEFS
int sechk_lib_load_fc(const char *fcfilelocation, sechk_lib_t *lib);
#endif
int sechk_lib_load_profile(const char *prof_name, sechk_lib_t *lib);
int sechk_lib_module_add_option_list(sechk_module_t *module, sechk_name_value_t *options);
int sechk_lib_module_clear_option(sechk_module_t *module, char *option);
char **sechk_lib_get_profiles(int *num_profiles);
bool_t sechk_lib_check_requirement(sechk_name_value_t *req, sechk_lib_t *lib);
bool_t sechk_lib_check_dependency(sechk_name_value_t *dep, sechk_lib_t *lib);
int sechk_lib_set_outputformat(unsigned char out, sechk_lib_t *lib);
int sechk_lib_set_minsev(const char *sev, sechk_lib_t *lib);
int sechk_lib_get_module_idx(const char *name, sechk_lib_t *lib);

/* other utility functions */
int sechk_get_installed_profile_names(char ***names, int *num_profiles);
sechk_proof_t *sechk_proof_copy(sechk_proof_t *orig);
#endif /* SECHECKER_H */

