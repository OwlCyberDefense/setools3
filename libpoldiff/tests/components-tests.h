/**
 *  @file
 *
 *  Header file for libpoldiff's correctness of components.
 *
 *  @author Paul Rosenfeld prosenfeld@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#ifndef COMPONENTS_TEST
#define COMPONENTS_TEST

#define WRAP_NAME_FUNC(component) const char *poldiff_##component##_get_name_w(const void *arg) { \
	const poldiff_##component##_t *cls = (const poldiff_##component##_t *)arg; \
	return poldiff_##component##_get_name(cls); }

#define WRAP_MOD_FUNC(component,mod_component,mod_type) const apol_vector_t* poldiff_##component##_get_##mod_type##_##mod_component##_w(const void* arg) { \
	const poldiff_##component##_t *cls = (const poldiff_##component##_t *)arg; \
	return poldiff_##component##_get_##mod_type##_##mod_component(cls); }

void build_component_vecs(component_funcs_t *);

int components_test_init();
int components_test_cleanup();

void components_attributes_tests();
void components_bools_tests();
void components_commons_tests();
void components_roles_tests();
void components_users_tests();
void components_class_tests();
void components_types_tests();

#endif
