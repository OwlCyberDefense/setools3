/**
 *  @file xx.h
 *  Defines the interface for the xx module.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

/* NOTE: TODO This is a module template, which includes all the necessary
 * infrastructure to implement a basic SEChecker module. To use this template
 * first replace all instances of the string xx with the name of the module,
 * then edit or complete all sections marked TODO as instructed. Do not forget
 * to add an entry in the register_list files (see these files for further
 * instruction) */

#include "sechecker.h"
#include <apol/policy.h>

/* The xx_data structure is used to hold the check specific
 * private data of a module.
 * TODO: Add any members you need to perform the check or if the module is not
 * going to need private data remove this declaration and the data_new() and
 * data_free() functions */
typedef struct xx_data
{
	/* TODO: define members of this data structure
	 * for module's private data */
} xx_data_t;

/* The following functions are used to allocate and initialize the private data
 * storage structure for this module and to free all memory used by it. */
xx_data_t *xx_data_new(void);
void xx_data_free(void *data);

/* The register function places the needed information about the module in the
 * library, including description fields and the functions available. TODO: be
 * sure to add an entry for this function in the register_list files. */
int xx_register(sechk_lib_t * lib);

/* Module functions:
 * The following three functions (init, run, and print) must exist for all
 * modules.  NOTE: while using a modular format SEChecker is built statically;
 * this means that all modules and their functions are in the same namespace.
 * Be sure to choose a unique name for each module and to set the module name
 * prefix xx everywhere */
int xx_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int xx_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int xx_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);

/* TODO: (optional) Declare any other functions needed by other modules here.
 * The prototype of the function must be int xx_fn(sechk_module_t *mod,
 * apol_policy_t *policy, void *arg).  For use by the get_module_function()
 * function, be sure to add a block in the xx_register function to register
 * your function.
 * NOTE: While SEChecker is build statically, it is intended that no module
 * directly call a function from another but instead use get_module_function()
 * to get the desired function from the library. */
