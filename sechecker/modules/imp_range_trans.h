/**
 *  @file imp_range_trans.h
 *  Defines the interface for the impossible range_transition module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author: David Windsor <dwindsor@tresys.com>
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

#ifndef IMP_RANGE_TRANS
#define IMP_RANGE_TRANS

#ifdef	__cplusplus
extern "C" {
#endif

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/role-query.h>
#include <apol/user-query.h>
#include <apol/rangetrans-query.h>
#include <apol/rbacrule-query.h>
#include <apol/domain-trans-analysis.h>
#include <apol/policy-query.h>

int imp_range_trans_register(sechk_lib_t * lib);
int imp_range_trans_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int imp_range_trans_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int imp_range_trans_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#ifdef	__cplusplus
}
#endif

#endif /* IMP_RANGE_TRANS */

