/**
 *  @file roles_wo_users.h
 *  Defines the interface for the roles without users module. 
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

#ifndef ROLES_WO_USERS
#define ROLES_WO_USERS

#ifdef	__cplusplus
extern "C" {
#endif

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/user-query.h>
#include <apol/role-query.h>

/* Module functions:
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. */
int roles_wo_users_register(sechk_lib_t * lib);
int roles_wo_users_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int roles_wo_users_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int roles_wo_users_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int roles_wo_users_get_list(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#ifdef	__cplusplus
}
#endif

#endif
