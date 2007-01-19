/*  Copyright (C) 2005-2007 Tresys Technology, LLC
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

/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef SECHK_REGISTER_LIST_H
#define SECHK_REGISTER_LIST_H

#include "sechecker.h"

/* TODO: to add a module declare it's register function as
 * extern int <module_name>_register(sechk_lib_t *lib);
 * here and add it's address to the array in register_list.c
 * don't forget to add any necessary options to the config file */

/* extern register functions declarations */
extern int find_domains_register(sechk_lib_t * lib);
extern int find_file_types_register(sechk_lib_t * lib);
extern int domain_and_file_register(sechk_lib_t * lib);
extern int attribs_wo_types_register(sechk_lib_t * lib);
extern int roles_wo_types_register(sechk_lib_t * lib);
extern int users_wo_roles_register(sechk_lib_t * lib);
extern int roles_wo_allow_register(sechk_lib_t * lib);
extern int types_wo_allow_register(sechk_lib_t * lib);
extern int spurious_audit_register(sechk_lib_t * lib);
extern int attribs_wo_rules_register(sechk_lib_t * lib);
extern int inc_mount_register(sechk_lib_t * lib);
extern int roles_wo_users_register(sechk_lib_t * lib);
/* Deprecated *
 extern int rules_exp_nothing_register(sechk_lib_t *lib); 
*/
extern int domains_wo_roles_register(sechk_lib_t * lib);
extern int inc_dom_trans_register(sechk_lib_t * lib);
extern int find_port_types_register(sechk_lib_t * lib);
extern int find_node_types_register(sechk_lib_t * lib);
extern int find_netif_types_register(sechk_lib_t * lib);
extern int find_assoc_types_register(sechk_lib_t * lib);
extern int find_net_domains_register(sechk_lib_t * lib);
extern int inc_net_access_register(sechk_lib_t * lib);
extern int unreachable_doms_register(sechk_lib_t * lib);
extern int imp_range_trans_register(sechk_lib_t * lib);
/* TODO: additional externs go here ... */

size_t sechk_register_list_get_num_modules();
const sechk_module_name_reg_t *sechk_register_list_get_modules();
size_t sechk_register_list_get_num_profiles();
const sechk_profile_name_reg_t *sechk_register_list_get_profiles();
#endif				       /* SECHK_REGISTER_LIST_H */
