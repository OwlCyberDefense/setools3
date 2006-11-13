/**
 *  @file find_file_types.h
 *  Defines the interface for the find file types utility module.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
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

#ifndef FIND_FILE_TYPES
#define FIND_FILE_TYPES

#ifdef	__cplusplus
extern "C"
{
#endif

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/type-query.h>
#include <apol/avrule-query.h>
#include <apol/terule-query.h>

	typedef struct find_file_types_data
	{
		apol_vector_t *file_type_attribs;
		int num_file_type_attribs;
	} find_file_types_data_t;

	void find_file_types_data_free(void *data);
	find_file_types_data_t *find_file_types_data_new(void);

	int find_file_types_register(sechk_lib_t * lib);
	int find_file_types_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int find_file_types_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int find_file_types_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);
	int find_file_types_get_list(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#ifdef	__cplusplus
}
#endif

#endif
