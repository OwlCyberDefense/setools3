/**
 *  @file inc_dom_trans.h
 *  Defines the interface for the incomplete domain transition module. 
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

#ifndef INC_DOM_TRANS
#define INC_DOM_TRANS

#ifdef	__cplusplus
extern "C" {
#endif

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/domain-trans-analysis.h>
#include <apol/user-query.h>
#include <apol/rbacrule-query.h>
#include <apol/role-query.h>

#define SECHK_INC_DOM_TRANS_HAS_TT	0x08
#define SECHK_INC_DOM_TRANS_HAS_EXEC	0x04
#define SECHK_INC_DOM_TRANS_HAS_TRANS	0x02
#define SECHK_INC_DOM_TRANS_HAS_EP		0x01
#define SECHK_INC_DOM_TRANS_COMPLETE	(SECHK_INC_DOM_TRANS_HAS_EP|SECHK_INC_DOM_TRANS_HAS_TRANS|SECHK_INC_DOM_TRANS_HAS_EXEC)

int inc_dom_trans_register(sechk_lib_t * lib);
int inc_dom_trans_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int inc_dom_trans_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int inc_dom_trans_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#ifdef	__cplusplus
}
#endif

#endif
