/**
 *  @file
 *  Defines the interface for the types without allow rules module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
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

#ifndef TYPES_WO_ALLOW
#define TYPES_WO_ALLOW

#ifdef	__cplusplus
extern "C"
{
#endif

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/avrule-query.h>
#include <apol/type-query.h>

	int types_wo_allow_register(sechk_lib_t * lib);
	int types_wo_allow_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int types_wo_allow_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int types_wo_allow_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int types_wo_allow_get_list(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#ifdef	__cplusplus
}
#endif

#endif
