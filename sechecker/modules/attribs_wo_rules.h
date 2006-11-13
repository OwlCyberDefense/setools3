/**
 *  @file attribs_wo_rules.h
 *  Defines the interface for the attributes without rules module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
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

#ifndef ATTRIBS_WO_RULES
#define ATTRIBS_WO_RULES

#ifdef	__cplusplus
extern "C"
{
#endif

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/role-query.h>
#include <apol/avrule-query.h>
#include <apol/terule-query.h>
#include <apol/type-query.h>

/* Module functions:
 * Do not change any of these prototypes or you will not be
 * able to run the module in the library
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. */
	int attribs_wo_rules_register(sechk_lib_t * lib);
	int attribs_wo_rules_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int attribs_wo_rules_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int attribs_wo_rules_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);

/* NOTE: While SEChecker is build statically, it is
 * intended that no module directly call a function
 * from another but instead use get_module_function()
 * to get the desired function from the library. */

	int attribs_wo_rules_get_list(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#ifdef	__cplusplus
}
#endif

#endif
