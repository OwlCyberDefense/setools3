/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

/* NOTE: TODO This is a module template, which includes all the necessary
 * infrastructure to implement a basic SEChecker module. To use this template
 * first replace all instances of the string xx with the name of the module,
 * then edit or complete all sections marked TODO as instructed. Do not forget
 * to add a block to the config file and to place the register function in
 * the register_list files (see these files for further instruction) */

#include "sechecker.h"
#include "policy.h"

/* The xx_data structure is used to hold the check specific
 *  private data of a module.
 *  TODO: Add any members you need to perform the check */
typedef struct xx_data {
	/* TODO: define members of this data structure
	 * for module's private data */
} xx_data_t;

/* Module functions: 
 * Do not change any of these prototypes or you will not be
 * able to run the module in the library
 * (do, however, replace the xx with the module name)
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. Be sure to choose a unique name
 * for each module and to set the module name prefix xx everywhere */
int xx_register(sechk_lib_t *lib);
int xx_init(sechk_module_t *mod, policy_t *policy);
int xx_run(sechk_module_t *mod, policy_t *policy);
void xx_free(sechk_module_t *mod);
int xx_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *xx_get_result(sechk_module_t *mod);
 
/* TODO: (optional) Declare any other functions
 * needed by other modules here. For use by the
 * get_module_function() function, be sure to add
 * a block in the xx_register function to register
 * your function.
 * NOTE: While SEChecker is build statically, it is
 * intended that no module directly call a function
 * from another but instead use get_module_function()
 * to get the desired function from the library. */

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
xx_data_t *xx_data_new(void);

