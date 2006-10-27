/**
 *  @file spurious_audit.h
 *  Defines the interface for the spurious audit rule module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Ryan Jordan rjordan@tresys.com
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

/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef SPURIOUS_AUDIT
#define SPURIOUS_AUDIT

#include "sechecker.h"
#include <apol/policy.h>

#define SECHK_SPUR_AU_AA_MISS 0x01
#define SECHK_SPUR_AU_AA_PART 0x02
#define SECHK_SPUR_AU_DA_FULL 0x04
#define SECHK_SPUR_AU_DA_PART 0x08

/* Module functions: */
int spurious_audit_register(sechk_lib_t * lib);
int spurious_audit_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int spurious_audit_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int spurious_audit_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#endif
