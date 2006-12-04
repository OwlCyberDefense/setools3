/**
 *  @file unreachable_doms.h
 *  Defines the interface for the unreachable domains module.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author David Windsor <dwindsor@tresys.com>
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

#ifndef UNREACHABLE_DOMS
#define UNREACHABLE_DOMS

#ifdef	__cplusplus
extern "C"
{
#endif

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/user-query.h>
#include <apol/role-query.h>
#include <apol/isid-query.h>
#include <apol/rbacrule-query.h>
#include <apol/domain-trans-analysis.h>
#include <selinux/selinux.h>

#define SECHK_INC_DOM_TRANS_HAS_TT      0x08
#define SECHK_INC_DOM_TRANS_HAS_EXEC    0x04
#define SECHK_INC_DOM_TRANS_HAS_TRANS   0x02
#define SECHK_INC_DOM_TRANS_HAS_EP      0x01
#define SECHK_INC_DOM_TRANS_COMPLETE    (SECHK_INC_DOM_TRANS_HAS_EP|SECHK_INC_DOM_TRANS_HAS_TRANS|SECHK_INC_DOM_TRANS_HAS_EXEC)

#define APOL_STR_SZ 128

/* The unreachable_doms_data structure is used to hold the check specific
 *  private data of a module. */
	typedef struct unreachable_doms_data
	{
		char *ctx_file_path;
		/* vector of strings, read from default contexts file */
		apol_vector_t *ctx_vector;
	} unreachable_doms_data_t;

	unreachable_doms_data_t *unreachable_doms_data_new(void);
	void unreachable_doms_data_free(void *data);

	int unreachable_doms_register(sechk_lib_t * lib);
	int unreachable_doms_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int unreachable_doms_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int unreachable_doms_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#ifdef	__cplusplus
}
#endif

#endif				       /* UNREACHABLE_DOMS */
