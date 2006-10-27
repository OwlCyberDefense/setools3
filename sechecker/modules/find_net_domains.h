/**
 *  @file find_net_domains.h
 *  Defines the interface for the network domain utility module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author David Windsor dwindsor@tresys.com
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

#ifndef FIND_NET_DOMAINS
#define FIND_NET_DOMAINS

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/avrule-query.h>

/* The find_net_domains_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct find_net_domains_data
{
	apol_vector_t *net_objs;
} find_net_domains_data_t;

find_net_domains_data_t *find_net_domains_data_new(void);
void find_net_domains_data_free(void *data);

int find_net_domains_register(sechk_lib_t * lib);
int find_net_domains_init(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int find_net_domains_run(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int find_net_domains_print(sechk_module_t * mod, apol_policy_t * policy, void *arg);
int find_net_domains_get_list(sechk_module_t * mod, apol_policy_t * policy, void *arg);

#endif
