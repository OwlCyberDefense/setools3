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

/* defined flags for outformat */
#define SECHK_OUT_STATS  0x01
#define SECHK_OUT_LIST   0x02
#define SECHK_OUT_LONG   0x04
#define SECHK_OUT_HEADER 0x08

typedef struct sechk_conf {
	unsigned char	outformat;
	char		*selinux_config_path;
	char		*policy_src_tree_path;
	bool_t		*module_selection;
} sechk_conf_t;

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

typedef struct sechk_opt {
	char		*name;
	char		*value;
	struct sechk_opt *next;
} sechk_opt_t;

typedef struct sechk_fn {
	char		*name;
	void		*fn;
	struct sechk_fn	*next;
} sechk_fn_t;

#define SECHK_MOD_TYPE_NONE 0x00
#define SECHK_MOD_TYPE_SYS  0x01
#define SECHK_MOD_TYPE_DEV  0x02
#define SECHK_MOD_TYPE_BOTH (SECHK_MOD_TYPE_SYS|SECHK_MOD_TYPE_DEV)

typedef struct sechk_module {
	char		*name;
	unsigned char	type;
	sechk_result_t	*result;
	sechk_opt_t	*options;
	sechk_fn_t	*functions;
	void		*data;
} sechk_module_t;

typedef struct sechk_lib {
	sechk_module_t	*modules;
	int 		num_modules;
	sechk_conf_t	*conf;
	policy_t 	*policy;
} sechk_lib_t;

typedef int (*sechk_register_fn_t)(sechk_lib_t *lib);
typedef int (*sechk_init_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef int (*sechk_run_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef void (*sechk_free_fn_t)(sechk_module_t *mod);
typedef char *(*sechk_get_output_str_fn_t)(sechk_module_t *mod, policy_t *policy);
typedef sechk_result_t *(*sechk_get_result_fn_t)(sechk_module_t *mod);

sechk_lib_t *new_sechk_lib(char *policyfilelocation, char *conffilelocation, unsigned char output_override);
int parse_config_file(FILE *conffile, unsigned char output_override, sechk_lib_t *lib);
void free_sechk_lib(sechk_lib_t **lib);

void free_sechk_fn(sechk_fn_t **fn_struct);
void free_sechk_opt(sechk_opt_t **opt);
void free_sechk_result(sechk_result_t **res);
void free_sechk_item(sechk_item_t **item);
void free_sechk_proof(sechk_proof_t **proof);
void free_sechk_conf(sechk_conf_t **conf);

sechk_fn_t *new_sechk_fn(void);
sechk_opt_t *new_sechk_opt(void);
sechk_result_t *new_sechk_result(void);
sechk_item_t *new_sechk_item(void);
sechk_proof_t *new_sechk_proof(void);
sechk_conf_t *new_sechk_conf(void);

int register_modules(sechk_register_fn_t *register_fns, sechk_lib_t *lib);
void *get_module_function(char *module_name, char *function_name, sechk_lib_t *lib);
sechk_module_t *get_module(char *module_name, sechk_lib_t *lib);
int init_modules(sechk_lib_t *lib);
int run_modules(unsigned char run_mode, sechk_lib_t *lib);
void free_modules(sechk_lib_t *lib);

/* utility functions */
int intlen(int n);
int sechk_item_sev(sechk_item_t *item);
sechk_item_t *get_sechk_item_from_result(int item_id, unsigned char item_type, sechk_result_t *res);
sechk_proof_t *copy_sechk_proof(sechk_proof_t *orig);
bool_t is_sechk_proof_in_item(int idx, unsigned char type, sechk_item_t *item);

#endif /* SECHECKER_H */

