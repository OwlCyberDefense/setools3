/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/*
 * Author: jmowery@tresys.com
 *
 * sechecker.h
 *
 */

#ifndef SECHECKER_H
#define SECHECKER_H

#include "policy.h"
#ifdef LIBSEFS
#include "file_contexts.h"
#endif
#include <libxml/xmlstring.h>

/* This should be defined from the make environment */
#ifndef PROFILE_INSTALL_DIR
#define PROFILE_INSTALL_DIR /usr/share/setools/profiles.sechecker
#endif

/* defined flags for outformat */
/* report components */
#define SECHK_OUT_STATS   0x01
#define SECHK_OUT_LIST    0x02
#define SECHK_OUT_PROOF   0x04
#define SECHK_OUT_HEADER  0x08
/* mode flags from command line, test profiles, and comfig file */
/* NOTE: none is only valid in profiles */
#define SECHK_OUT_NONE    0x00
#define SECHK_OUT_QUIET   (SECHK_OUT_STATS|SECHK_OUT_HEADER)
#define SECHK_OUT_SHORT   (SECHK_OUT_QUIET|SECHK_OUT_LIST)
#define SECHK_OUT_LONG    (SECHK_OUT_QUIET|SECHK_OUT_PROOF)
#define SECHK_OUT_VERBOSE (SECHK_OUT_SHORT|SECHK_OUT_LONG)

/* module results proof element */
typedef struct sechk_proof {
	int		idx;
	unsigned char	type;
	char		*text;
	xmlChar		*xml_out;
	int		severity;
	struct sechk_proof *next;
} sechk_proof_t;

/* severity categories used in proof elements */
#define SECHK_SEV_NONE 0
#define SECHK_SEV_MIN  1
#define SECHK_SEV_LOW  2
#define SECHK_SEV_MOD  3
#define SECHK_SEV_HIGH 4
#define SECHK_SEV_DNGR 5

/* The following definitions are expanding
 * POL_LIST (see policy.h) for aditional items stored
 * neither in policy structure not in the policy
 * sorce file. This list is used by result->item_type
 * and proof->type */
#define POL_LIST_FCENT (POL_NUM_LISTS + 1)

typedef struct sechk_item {
	int		item_id;
	unsigned char	test_result;
	sechk_proof_t	*proof;
	struct sechk_item *next;
} sechk_item_t;

typedef struct sechk_result {
	char		*test_name;
	unsigned char	item_type;
	sechk_item_t	*items;
	int		num_items;
} sechk_result_t;

typedef struct sechk_name_value {
	char		 *name;
	char		 *value;
	struct sechk_name_value *next;
} sechk_name_value_t;

typedef struct sechk_fn {
	char		*name;
	void		*fn;
	struct sechk_fn	*next;
} sechk_fn_t;

typedef struct sechk_module {
	char               *name;                /* unique module name */
	char		*header;		/* description of the module */
	sechk_result_t	   *result;              /* test results */
	sechk_name_value_t *options;             /* test inputs */ 
	sechk_name_value_t *requirements;		/* conditions required such as policy version */
	sechk_name_value_t *dependencies;		/* other modules needed to run */
	sechk_fn_t	   *functions;           /* register/init/run/free/print */
	unsigned char	   outputformat;            /* default output format */
	void		   *data;
} sechk_module_t;

typedef struct sechk_lib {
	sechk_module_t	*modules;             /* test modules */
	bool_t		*module_selection;    /* selected test modules */
	int             modules_size;
	int 		num_modules;
	policy_t 	*policy;              /* policy data */
#ifdef LIBSEFS
	sefs_fc_entry_t		*fc_entries;          /* file contexts data */
	int		num_fc_entries;
	char		*fc_path;             /* file contexts filename */
#endif
	unsigned char	outputformat;
	char		*selinux_config_path;
	char		*policy_path;         /* policy filename */
} sechk_lib_t;

/* Module function signatures */
typedef int (*sechk_register_fn_t)(sechk_lib_t *lib);
typedef int (*sechk_init_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef int (*sechk_run_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef void (*sechk_free_fn_t)(sechk_module_t *mod);
typedef int (*sechk_print_output_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef sechk_result_t *(*sechk_get_result_fn_t)(sechk_module_t *mod);

/* Module function names */
#define SECHK_MOD_FN_INIT    "init"
#define SECHK_MOD_FN_RUN     "run"
#define SECHK_MOD_FN_FREE    "data_free"
#define SECHK_MOD_FN_PRINT   "print_output"
#define SECHK_MOD_FN_GET_RES "get_result"

/* alloc methods */
#ifdef LIBSEFS
sechk_lib_t *sechk_lib_new(const char *policyfilelocation, const char *fcfilelocation);
#else
sechk_lib_t *sechk_lib_new(const char *policyfilelocation);
#endif
sechk_fn_t *sechk_fn_new(void);
sechk_name_value_t *sechk_name_value_new(void);
sechk_result_t *sechk_result_new(void);
sechk_item_t *sechk_item_new(void);
sechk_proof_t *sechk_proof_new(void);

/* free methods */
void sechk_lib_free(sechk_lib_t *lib);
void sechk_fn_free(sechk_fn_t *fn_struct);
void sechk_result_free(sechk_result_t *res);
void sechk_item_free(sechk_item_t *item);
void sechk_proof_free(sechk_proof_t *proof);
void sechk_module_free(sechk_module_t *module, sechk_free_fn_t free_fn);
void sechk_name_value_destroy(sechk_name_value_t *opt);

/* register/check_dep/init/run/print -  modules */
int sechk_lib_register_modules(sechk_register_fn_t *register_fns, sechk_lib_t *lib);
int sechk_lib_check_module_dependencies(sechk_lib_t *lib);
int sechk_lib_check_module_requirements(sechk_lib_t *lib);
int sechk_lib_init_modules(sechk_lib_t *lib);
int sechk_lib_run_modules(sechk_lib_t *lib);
int sechk_lib_print_modules_output(sechk_lib_t *lib);

/* module accessors */
sechk_module_t *sechk_lib_get_module(const char *module_name, sechk_lib_t *lib);
void *sechk_lib_get_module_function(const char *module_name, const char *function_name, sechk_lib_t *lib);

/* utility functions */
int sechk_lib_load_profile(const char *prof_name, sechk_lib_t *lib);
int sechk_get_installed_profile_names(char ***names, int *num_profiles);
bool_t sechk_lib_check_requirement(sechk_name_value_t *req, sechk_lib_t *lib);
bool_t sechk_lib_check_dependency(sechk_name_value_t *dep, sechk_lib_t *lib);
int sechk_lib_set_outputformat(unsigned char out, sechk_lib_t *lib);
int sechk_item_sev(sechk_item_t *item);
sechk_item_t *sechk_result_get_item(int item_id, unsigned char item_type, sechk_result_t *res);
sechk_proof_t *sechk_proof_copy(sechk_proof_t *orig);
bool_t sechk_item_has_proof(int idx, unsigned char type, sechk_item_t *item);
int sechk_lib_get_module_idx(const char *name, sechk_lib_t *lib);

#endif /* SECHECKER_H */

