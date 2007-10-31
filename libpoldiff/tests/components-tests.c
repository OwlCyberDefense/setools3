/**
 *  @file
 *
 *  Test the libpoldiff's correctness for components.
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

#include <config.h>

#include "libpoldiff-tests.h"
#include "components-tests.h"
#include "policy-defs.h"
#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>

#include <apol/util.h>

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *unchanged_attributes[] = {
/* 00.0 */
	"data",
	NULL
};
char *added_attributes[] = {
/* 00.1 */
	"mineral",
	NULL
};
char *removed_attributes[] = {
/* 00.2 */
	"other",
	NULL
};
char *modified_attributes[] = {
/* 00.3.0 */
	"tree +holly_t",
/* 00.3.1 */
	"fish -bass_t",
	"plant -daikon_t",
/* 00.3.2 */
	"animal +hippo_t",
	"animal -bass_t",
	"animal -koala_t",
	"mammal +hippo_t",
	"mammal -bear_t",
	NULL
};
char *unchanged_bools[] = {
/* 02.0 */
	"frog",
	NULL
};
char *added_bools[] = {
/* 02.1 */
	"shark",
	NULL
};
char *removed_bools[] = {
/* 02.2 */
	"dog",
	NULL
};
char *modified_bools[] = {
/* 02.3 */
	"wark",
	NULL
};
char *unchanged_classes[] = {
/* 04.0 */
	"filesystem", "dir", "blk_file", "sock_file", "fifo_file", "netif",
	"process", "msg", "security", "system", "capability", "passwd",
	"window", "font", "colormap", "property", "cursor", "xclient",
	"xinput", "xserver", "xextension", "pax", "dbus", "ncsd",
	"association", "context", NULL
};
char *added_classes[] = {
/* 04.1 */
	"thing",
	NULL
};
char *removed_classes[] = {
/* 04.2 */
	"key",
	NULL
};
char *modified_classes[] = {
/* 04.3.00 */
	"fd +be",
/* 04.3.01 */
	"chr_file -execmod",
/* 04.3.02*/
	"file +newperm",
	"file -execmod",
/* 04.3.03 */
	"ipc +unix_exec",
	"sem +unix_exec",
/* 04.3.04 */
	"socket -name_bind",
	"tcp_socket -name_bind",
	"udp_socket -name_bind",
	"netlink_socket -name_bind",
	"packet_socket -name_bind",
	"key_socket -name_bind",
	"unix_dgram_socket -name_bind",
	"dccp_socket -name_bind",
	"netlink_route_socket -name_bind",
	"netlink_firewall_socket -name_bind",
	"netlink_tcpdiag_socket -name_bind",
	"netlink_nflog_socket -name_bind",
	"netlink_xfrm_socket -name_bind",
	"netlink_selinux_socket -name_bind",
	"netlink_audit_socket -name_bind",
	"netlink_ip6fw_socket -name_bind",
	"netlink_dnrt_socket -name_bind",
	"appletalk_socket -name_bind",
	"netlink_kobject_uevent_socket -name_bind",
/* 04.3.05 */
	"drawable +bar",
	"drawable -blah",
/* 04.3.06 */
	"msgq +unix_exec",
	"msgq +dequeue",
/* 04.3.07 */
	"rawip_socket -name_bind",
	"rawip_socket +ip_bind",
/* 04.3.08 */
	"shm +unix_exec",
	"shm -lock",
/* 04.3.09 */
	"unix_stream_socket -newconn",
	"unix_stream_socket -name_bind",
/* 04.3.10 */
	"gc +bar",
	"gc +remove",
	"gc -blah",
	"gc -free",
	NULL
};

char *unchanged_commons[] = {
/* 05.0 */
	"file",
	NULL
};
char *added_commons[] = {
/* 05.1 */
	"new",
	NULL
};
char *removed_commons[] = {
/* 05.2 */
	"old",
	NULL
};
char *modified_commons[] = {
/* 05.3.0 */
	"ipc +unix_exec",
/* 05.3.1 */
	"socket -name_bind",
/* 05.3.2 */
	"bob -blah",
	"bob +bar",
	NULL
};

char *unchanged_roles[] = {
/* 08.0 */
	"placeholder_r", "admin_r", "intern_r",
	NULL
};
char *added_roles[] = {
/* 08.1 */
	"strange_r",
	NULL
};
char *removed_roles[] = {
/* 08.2 */
	"guest_r",
	NULL
};
char *modified_roles[] = {
/* 08.3.0 */
	"user_r +hippo_t",
/* 08.3.1 */
	"lumberjack_r +holly_t",
/* 08.3.2 */
	"staff_r -bass_t",
/* 08.3.3 */
	"aquarium_r -bass_t",
	"garden_r -daikon_t",
/* 08.3.4 */
	"object_r +hippo_t",
	"object_r +acorn_t",
	"object_r -bass_t",
	"object_r -koala_t",
	"deity_r +acorn_t",
	"deity_r +hippo_t",
	"deity_r -bass_t",
	"deity_r -dirt_t",
	"deity_r -koala_t",
/* 08.3.5 */
	"zoo_r +hippo_t",
	"zoo_r -bass_t",
	"zoo_r -koala_t",
	"mammal_r +hippo_t",
	"mammal_r -bear_t",
	NULL
};

char *unchanged_types[] = {
/* 12.0.0 */
	"placeholder_t", "finch_t", "trout_t",
	"birch_t", "oak_t", "potato_t", "tiger_t",
	"lion_t", "pine_t", "log_t", "file_t",
/* 12.0.1 */
	"firefly_t", "lightningbug_t",
/* 12.0.2 */
	"rock_t", "big_stone_t",
	NULL
};

char *added_types[] = {
/* 12.1.0 */
	"hippo_t",
	"acorn_t",
	NULL
};

/* 12.1.1 */
char *removed_types[] = {
/* 12.2.0 */
	"bass_t",
/* 12.2.1 */
	"koala_t",
	NULL
};

char *modified_types[] = {
/* 12.3.0 */
	"holly_t +tree",
/* 12.3.1 */
	"bear_t -mammal",
/* 12.3.2 */
	"daikon_t -plant",
	"daikon_t +mineral",
/* 12.3.3 */
	"glass_t -> crystal_t +mineral",
/* 12.3.4 */
	"dirt_t -> soil_t +mineral",
/* NEED TO BE ADDED */
	"stone_t -other",
	"system_t -other",
	NULL
};
char *aliased_types[] = {
	/* 12.2.1 */
	"bear_t -> koala_t",
	NULL
};

char *unchanged_users[] = {
/* 13.0 */
	"placeholder_u", "su_u", "cyn_u", "danika_u",
	NULL
};
char *added_users[] = {
/* 13.1 */
	"gai_u",
	NULL
};
char *removed_users[] = {
/* 13.2 */
	"mehnlo_u",
	NULL
};
char *modified_users[] = {
/* 13.3.0 */
	"devona_u +aquarium_r",
	"eve_u +strange_r",
/* 13.3.1 */
	"nika_u -user_r",
/* 13.3.2 */
	"meloni_u +garden_r",
	"meloni_u -user_r",
	NULL
};

/* This #define is kind of like a template since all of the "get_name" classes
 * follow the same pattern. The wrapped function name comes out the same as the
 * original, but with a _w at the end (for example: poldiff_attribute_get_name_w
 * see definition in components-tests.h */
WRAP_NAME_FUNC(attrib)
	WRAP_NAME_FUNC(bool)
	WRAP_NAME_FUNC(class)
	WRAP_NAME_FUNC(common)
	WRAP_NAME_FUNC(role)
	WRAP_NAME_FUNC(type)
	WRAP_NAME_FUNC(user)
	WRAP_NAME_FUNC(cat)
/* This is the same idea except for with "get_added" and "get_removed" */
	WRAP_MOD_FUNC(class, perms, added)
	WRAP_MOD_FUNC(class, perms, removed)
	WRAP_MOD_FUNC(attrib, types, added)
	WRAP_MOD_FUNC(attrib, types, removed)
	WRAP_MOD_FUNC(common, perms, added)
	WRAP_MOD_FUNC(common, perms, removed)
	WRAP_MOD_FUNC(role, types, added)
	WRAP_MOD_FUNC(role, types, removed)
	WRAP_MOD_FUNC(user, roles, added)
	WRAP_MOD_FUNC(user, roles, removed)
	WRAP_MOD_FUNC(type, attribs, added)
	WRAP_MOD_FUNC(type, attribs, removed)

void build_component_vecs(component_funcs_t * component_funcs)
{
	size_t i;
	const void *item = NULL;
	const apol_vector_t *v = NULL;
	v = component_funcs->get_diff_vector(diff);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		const char *name_only = NULL;
		name_only = component_funcs->get_name(item);
		if (component_funcs->get_form(item) == POLDIFF_FORM_ADDED) {
			apol_vector_append(added_v, strdup(name_only));
		} else if (component_funcs->get_form(item) == POLDIFF_FORM_REMOVED) {
			apol_vector_append(removed_v, strdup(name_only));
		} else if (component_funcs->get_form(item) == POLDIFF_FORM_MODIFIED) {
			apol_vector_append(modified_name_only_v, strdup(name_only));
			size_t j;
			if (component_funcs->get_added) {
				const apol_vector_t *added_elements = component_funcs->get_added(item);
				for (j = 0; j < apol_vector_get_size(added_elements); ++j) {
					char *added_element;
					added_element = apol_vector_get_element(added_elements, j);
					char *modification_str = NULL;
					size_t modification_str_len = 0;
					apol_str_appendf(&modification_str, &modification_str_len, "%s %s%s", name_only, "+",
							 added_element);
					apol_vector_append(modified_v, modification_str);
				}
			}
			if (component_funcs->get_removed) {
				const apol_vector_t *removed_elements = component_funcs->get_removed(item);
				for (j = 0; j < apol_vector_get_size(removed_elements); ++j) {
					char *removed_element;
					removed_element = apol_vector_get_element(removed_elements, j);
					char *modification_str = NULL;
					size_t modification_str_len = 0;
					apol_str_appendf(&modification_str, &modification_str_len, "%s %s%s", name_only, "-",
							 removed_element);
					apol_vector_append(modified_v, modification_str);
				}
			}
			if (!(component_funcs->get_added && component_funcs)) {
				apol_vector_append(modified_v, strdup(name_only));
			}
		}
	}
}

void components_types_tests()
{
	poldiff_test_answers_t *answers = init_answer_vectors(added_types, removed_types, unchanged_types, modified_types);
	component_funcs_t *funcs = init_test_funcs(poldiff_get_type_vector, poldiff_type_get_name_w,
						   poldiff_type_get_form, poldiff_type_get_added_attribs_w,
						   poldiff_type_get_removed_attribs_w);
	run_test(funcs, answers, COMPONENT);
	free(funcs);
	/* this is for the alias tests */
	size_t i;
	apol_vector_t *orig_aliases_v = apol_vector_create(free);
	apol_vector_t *mod_aliases_v = apol_vector_create(free);
	apol_vector_t *final_aliases_v = apol_vector_create(free);
	apol_vector_t *correct_final_aliases_v = string_array_to_vector(aliased_types);
	apol_vector_t *changed_aliases_v;

	qpol_policy_t *orig_qpolicy = apol_policy_get_qpol(orig_policy);
	qpol_policy_t *mod_qpolicy = apol_policy_get_qpol(mod_policy);

	qpol_iterator_t *orig_types;
	qpol_iterator_t *mod_types;

	qpol_policy_get_type_iter(mod_qpolicy, &orig_types);
	for (; !qpol_iterator_end(orig_types); qpol_iterator_next(orig_types)) {
		unsigned char isalias = 0;
		qpol_type_t *qpol_type;
		const char *name;
		qpol_iterator_get_item(orig_types, (void **)&qpol_type);
		qpol_type_get_name(orig_qpolicy, qpol_type, &name);
		qpol_type_get_isalias(orig_qpolicy, qpol_type, &isalias);
		if (!isalias) {
			apol_vector_append(orig_aliases_v, strdup(name));
		}
	}
	qpol_policy_get_type_iter(mod_qpolicy, &mod_types);
	for (; !qpol_iterator_end(mod_types); qpol_iterator_next(mod_types)) {
		unsigned char isalias = 0;
		const qpol_type_t *qpol_type;
		const char *name;
		qpol_iterator_get_item(mod_types, (void **)&qpol_type);
		qpol_type_get_name(mod_qpolicy, qpol_type, &name);
		qpol_type_get_isalias(mod_qpolicy, qpol_type, &isalias);
		if (isalias) {
			apol_vector_append(mod_aliases_v, strdup(name));
		}
	}

	changed_aliases_v = apol_vector_create_from_intersection(orig_aliases_v, mod_aliases_v, apol_str_strcmp, NULL);
	char *alias_str = NULL, *str = NULL;
	size_t alias_str_len = 0, str_len = 0;
	for (i = 0; i < apol_vector_get_size(changed_aliases_v); ++i) {
		char *name = apol_vector_get_element(changed_aliases_v, i);
		qpol_iterator_t *aliased_to;
		const qpol_type_t *qtype;
		qpol_policy_get_type_by_name(mod_qpolicy, name, &qtype);
		qpol_type_get_alias_iter(mod_qpolicy, qtype, &aliased_to);
		for (; !qpol_iterator_end(aliased_to); qpol_iterator_next(aliased_to)) {
			const char *name;
			qpol_iterator_get_item(aliased_to, (void **)&name);
			apol_str_append(&alias_str, &alias_str_len, name);
		}
		apol_str_appendf(&str, &str_len, "%s -> %s", name, alias_str);
		free(alias_str);
		apol_vector_append(final_aliases_v, str);
		qpol_iterator_destroy(&aliased_to);
	}
	apol_vector_sort(final_aliases_v, compare_str, NULL);
	apol_vector_sort(correct_final_aliases_v, compare_str, NULL);
	size_t first_diff = 0;
	int test_result;

	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(final_aliases_v, correct_final_aliases_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(final_aliases_v, correct_final_aliases_v, first_diff, "Aliases");
	}
	apol_vector_destroy(&orig_aliases_v);
	apol_vector_destroy(&mod_aliases_v);
	apol_vector_destroy(&final_aliases_v);
	apol_vector_destroy(&correct_final_aliases_v);
	apol_vector_destroy(&changed_aliases_v);
	qpol_iterator_destroy(&mod_types);
	qpol_iterator_destroy(&orig_types);

	cleanup_test(answers);
}

void components_bools_tests()
{
	poldiff_test_answers_t *answers = init_answer_vectors(added_bools, removed_bools, unchanged_bools, modified_bools);
	component_funcs_t *funcs = init_test_funcs(poldiff_get_bool_vector, poldiff_bool_get_name_w,
						   poldiff_bool_get_form, NULL, NULL);
	run_test(funcs, answers, COMPONENT);
	free(funcs);
	cleanup_test(answers);
}

void components_users_tests()
{
	poldiff_test_answers_t *answers = init_answer_vectors(added_users, removed_users, unchanged_users, modified_users);
	component_funcs_t *funcs = init_test_funcs(poldiff_get_user_vector, poldiff_user_get_name_w,
						   poldiff_user_get_form, poldiff_user_get_added_roles_w,
						   poldiff_user_get_removed_roles_w);
	run_test(funcs, answers, COMPONENT);
	free(funcs);
	cleanup_test(answers);
}

void components_roles_tests()
{
	poldiff_test_answers_t *answers = init_answer_vectors(added_roles, removed_roles, unchanged_roles, modified_roles);
	component_funcs_t *funcs = init_test_funcs(poldiff_get_role_vector, poldiff_role_get_name_w, poldiff_role_get_form,
						   poldiff_role_get_added_types_w, poldiff_role_get_removed_types_w);
	run_test(funcs, answers, COMPONENT);
	free(funcs);
	cleanup_test(answers);
}

void components_commons_tests()
{
	poldiff_test_answers_t *answers = init_answer_vectors(added_commons, removed_commons, unchanged_commons, modified_commons);
	component_funcs_t *funcs = init_test_funcs(poldiff_get_common_vector, poldiff_common_get_name_w, poldiff_common_get_form,
						   poldiff_common_get_added_perms_w, poldiff_common_get_removed_perms_w);
	run_test(funcs, answers, COMPONENT);
	free(funcs);
	cleanup_test(answers);
}

void components_attributes_tests()
{
	poldiff_test_answers_t *answers =
		init_answer_vectors(added_attributes, removed_attributes, unchanged_attributes, modified_attributes);
	component_funcs_t *funcs = init_test_funcs(poldiff_get_attrib_vector, poldiff_attrib_get_name_w,
						   poldiff_attrib_get_form, poldiff_attrib_get_added_types_w,
						   poldiff_attrib_get_removed_types_w);

	run_test(funcs, answers, COMPONENT);
	free(funcs);
	cleanup_test(answers);
}

void components_class_tests()
{
	poldiff_test_answers_t *answers = init_answer_vectors(added_classes, removed_classes, unchanged_classes, modified_classes);
	component_funcs_t *funcs = init_test_funcs(poldiff_get_class_vector, poldiff_class_get_name_w,
						   poldiff_class_get_form, poldiff_class_get_added_perms_w,
						   poldiff_class_get_removed_perms_w);
	run_test(funcs, answers, COMPONENT);
	free(funcs);
	cleanup_test(answers);
}

int components_test_init()
{
	if (!(diff = init_poldiff(COMPONENTS_ORIG_POLICY, COMPONENTS_MOD_POLICY))) {
		return 1;
	} else {
		return 0;
	}
}
