/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: David Windsor <dwindsor@tresys.com>
 *
 */

#include "sechecker.h"
#include <apol/policy.h>
//#include "dta.h" FIXME

#define SECHK_INC_DOM_TRANS_HAS_TT      0x08
#define SECHK_INC_DOM_TRANS_HAS_EXEC    0x04
#define SECHK_INC_DOM_TRANS_HAS_TRANS   0x02
#define SECHK_INC_DOM_TRANS_HAS_EP      0x01
#define SECHK_INC_DOM_TRANS_COMPLETE    (SECHK_INC_DOM_TRANS_HAS_EP|SECHK_INC_DOM_TRANS_HAS_TRANS|SECHK_INC_DOM_TRANS_HAS_EXEC)

/* The unreachable_doms_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct unreachable_doms_data {
	char *ctx_file_path;
	int *ctx_list;    /* contains domains found in default_contexts */
	int ctx_list_sz;
} unreachable_doms_data_t;

int unreachable_doms_register(sechk_lib_t *lib);
int unreachable_doms_init(sechk_module_t *mod, apol_policy_t *policy);
int unreachable_doms_run(sechk_module_t *mod, apol_policy_t *policy);
void unreachable_doms_data_free(void *data);
int unreachable_doms_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *unreachable_doms_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
unreachable_doms_data_t *unreachable_doms_data_new(void);

