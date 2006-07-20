/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef INC_DOM_TRANS
#define INC_DOM_TRANS

#include "sechecker.h"

//#include "dta.h" FIXME

#define SECHK_INC_DOM_TRANS_HAS_TT	0x08
#define SECHK_INC_DOM_TRANS_HAS_EXEC	0x04
#define SECHK_INC_DOM_TRANS_HAS_TRANS	0x02
#define SECHK_INC_DOM_TRANS_HAS_EP		0x01
#define SECHK_INC_DOM_TRANS_COMPLETE	(SECHK_INC_DOM_TRANS_HAS_EP|SECHK_INC_DOM_TRANS_HAS_TRANS|SECHK_INC_DOM_TRANS_HAS_EXEC)

/* The inc_dom_transition_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct inc_dom_trans_data {
	//dta_trans_t *trans_list; FIXME
} inc_dom_trans_data_t;

int inc_dom_trans_register(sechk_lib_t *lib);
int inc_dom_trans_init(sechk_module_t *mod, policy_t *policy);
int inc_dom_trans_run(sechk_module_t *mod, policy_t *policy);
void inc_dom_trans_data_free(void *data);
int inc_dom_trans_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *inc_dom_trans_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
inc_dom_trans_data_t *inc_dom_trans_data_new(void);

#endif
