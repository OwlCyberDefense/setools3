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
#include <libxml/xmlstring.h>
#include <file_contexts.h>

/* defined flags for outformat */
#define SECHK_OUT_STATS  0x01
#define SECHK_OUT_LIST   0x02
#define SECHK_OUT_LONG   0x04
#define SECHK_OUT_HEADER 0x08

/* xml parser keywords */
#define PARSE_SECHECKER_TAG      (xmlChar*)"sechecker"
#define PARSE_MODULE_TAG         (xmlChar*)"module"
#define PARSE_OPTION_TAG         (xmlChar*)"option"
#define PARSE_REQUIRE_TAG        (xmlChar*)"require"
#define PARSE_DEPENDENCY_TAG     (xmlChar*)"dependency"
#define PARSE_VALUE_ATTRIB       (xmlChar*)"value"
#define PARSE_NAME_ATTRIB        (xmlChar*)"name"
#define PARSE_VERSION_ATTRIB     (xmlChar*)"version"

/* module results proof */
typedef struct sechk_proof {
	int		idx;
	unsigned char	type;
	char		*text;
	xmlChar		*xml_out;
	int		severity;
	struct sechk_proof *next;
} sechk_proof_t;

#define SECHK_SEV_NONE 0
#define SECHK_SEV_MIN  1
#define SECHK_SEV_LOW  2
#define SECHK_SEV_MOD  3
#define SECHK_SEV_HIGH 4
#define SECHK_SEV_DNGR 5

/* expanding POL_LIST for aditional items */
#define POL_LIST_FCENT 17

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
	char		   *name;                /* unique module name */
	sechk_result_t	  *result;              /* test results */
	sechk_name_value_t *options;             /* test inputs */ 
	sechk_name_value_t *requirements;
	sechk_name_value_t *dependencies;
	sechk_fn_t	   *functions;           /* register/init/run/free/print */
	void		   *data;
} sechk_module_t;

typedef struct sechk_lib {
	sechk_module_t	*modules;             /* test modules */
	bool_t		*module_selection;    /* selected test modules */
	int             modules_size;
	int 		num_modules;
	policy_t 	*policy;              /* policy data */
	fscon_t		*fc_entries;          /* file contexts data */
	int		num_fc_entries;
	unsigned char	outformat;
	char		*selinux_config_path;
	char		*policy_path;         /* policy filename */
	char		*fc_path;             /* file contexts filename */

} sechk_lib_t;

/* Module function signatures */
typedef int (*sechk_register_fn_t)(sechk_lib_t *lib);
typedef int (*sechk_init_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef int (*sechk_run_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef void (*sechk_free_fn_t)(sechk_module_t *mod);
typedef int (*sechk_print_output_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef sechk_result_t *(*sechk_get_result_fn_t)(sechk_module_t *mod);

/* alloc methods */
sechk_lib_t *sechk_lib_new(const char *policyfilelocation, const char *fcfilelocation);
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

/* register/init/run -  modules */
int sechk_lib_register_modules(sechk_register_fn_t *register_fns, sechk_lib_t *lib);
int sechk_lib_init_modules(sechk_lib_t *lib);
int sechk_lib_run_modules(sechk_lib_t *lib);

/* module accessors */
sechk_module_t *sechk_lib_get_module(const char *module_name, sechk_lib_t *lib);
void *sechk_lib_get_module_function(const char *module_name, const char *function_name, sechk_lib_t *lib);

/* utility functions */
int sechk_item_sev(sechk_item_t *item);
sechk_item_t *get_sechk_item_from_result(int item_id, unsigned char item_type, sechk_result_t *res);
sechk_proof_t *copy_sechk_proof(sechk_proof_t *orig);
bool_t is_sechk_proof_in_item(int idx, unsigned char type, sechk_item_t *item);

#endif /* SECHECKER_H */

