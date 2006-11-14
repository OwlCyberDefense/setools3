/**
 *  @file unreachable_doms.c
 *  Implementation of the unreachable domains module.
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

#include <config.h>

#include "unreachable_doms.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

static bool_t parse_default_contexts(const char *ctx_file_path, apol_vector_t * ctx_vector, apol_policy_t * policy);
static bool_t in_isid_ctx(char *type_name, apol_policy_t * policy);
static bool_t in_def_ctx(char *type_name, unreachable_doms_data_t * datum);
/* for some reason we have to define this here to remove compile warnings */
extern ssize_t getline(char **lineptr, size_t * n, FILE * stream);

/* This string is the name  f the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "unreachable_doms";

int unreachable_doms_register(sechk_lib_t * lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		errno = EINVAL;
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		errno = EINVAL;
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "unreachable domains";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds all domains in a policy which are unreachable.  A domain is\n"
		"unreachable if any of the following apply:\n"
		"   1) There is insufficient type enforcement policy to allow a transition,\n"
		"   2) There is insufficient RBAC policy to allow a transition,\n"
		"   3) There are no users with proper roles to allow a transition.\n"
		"However, if any of the above rules indicate an unreachable domain, yet the\n"
		"domain appears in the system default contexts file, it is considered reachable.\n";
	mod->opt_description =
		"  Module requirements:\n"
		"    source policy\n"
		"    default contexts file\n"
		"  Module dependencies:\n" "    find_domains module\n" "  Module options:\n" "    none\n";
	mod->severity = SECHK_SEV_MED;

	/* assign dependencies */
	if (apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_domains")) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = unreachable_doms_init;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = unreachable_doms_run;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	mod->data_free = unreachable_doms_data_free;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = unreachable_doms_print;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int unreachable_doms_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	unreachable_doms_data_t *datum = NULL;
	bool_t retv;
	const char *ctx_file_path = NULL;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	datum = unreachable_doms_data_new();
	if (!datum) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	mod->data = datum;

	/* Parse default contexts file */
	if (!(datum->ctx_vector = apol_vector_create())) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
#ifdef LIBSELINUX
	ctx_file_path = selinux_default_context_path();
	if (!ctx_file_path) {
		ERR(policy, "%s", "Unable to find default contexts file");
		errno = ENOENT;
		return -1;
	} else {
		retv = parse_default_contexts(ctx_file_path, datum->ctx_vector, policy);
		if (!retv) {
			ERR(policy, "%s", "Unable to parse default contexts file");
			errno = EIO;
			return -1;
		}
	}
#endif

	return 0;
}

typedef enum dom_need
{
	KEEP_SEARCHING = 0,	       /* keep checking way to reach not found yet */
	USER,			       /* missing a user for role(s) associated with the type */
	COMMON_USER,		       /* missing user for the role in a transition to that type */
	ROLE_TRANS,		       /* transition is valid but need a role transition as well */
	ROLE_ALLOW,		       /* transition is valid and has a role_transition but not role allow */
	RBAC,			       /* there is a transition but insufficient RBAC rules to permit or to determie a user */
	VALID_TRANS,		       /* only transitions to the type are invalid ones needs one or more rules to complete */
	ROLE,			       /* type has no associated role */
	TRANSITION,		       /* no transition exists */
	DONE			       /* done searching a valid way to reach the type has been found */
} dom_need_e;

/**
 *  Finds user witn at least one role from each vector.
 *  @param policy The policy.
 *  @param src_roles The first set of roles.
 *  @param tgt_roles The second set of roles.
 *  @return 1 if a common user can be found 0 other wise.
 */
static int exists_common_user(apol_policy_t * policy, apol_vector_t * src_roles, apol_vector_t * tgt_roles, qpol_role_t ** which_sr,
			      qpol_role_t ** which_tr, qpol_user_t ** which_u)
{
	int retv = 0;
	apol_user_query_t *uq;
	char *name = NULL;
	qpol_role_t *role = NULL;
	qpol_user_t *user = NULL;
	qpol_iterator_t *iter = NULL;
	apol_vector_t *user_v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, j, k;

	if (!policy || !src_roles || !tgt_roles)
		return 0;

	if (which_sr)
		*which_sr = NULL;
	if (which_tr)
		*which_tr = NULL;
	if (which_u)
		*which_u = NULL;

	if (!(uq = apol_user_query_create()))
		return 0;

	for (i = 0; i < apol_vector_get_size(src_roles); i++) {
		role = apol_vector_get_element(src_roles, i);
		if (which_sr)
			*which_sr = role;
		qpol_role_get_name(q, role, &name);
		apol_user_query_set_role(policy, uq, name);
		apol_user_get_by_query(policy, uq, &user_v);
		for (j = 0; j < apol_vector_get_size(user_v); j++) {
			user = apol_vector_get_element(user_v, j);
			qpol_user_get_role_iter(q, user, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void **)&role);
				if (!apol_vector_get_index(tgt_roles, role, NULL, NULL, &k)) {
					retv = 1;
					if (which_tr)
						*which_tr = role;
					if (which_u)
						*which_u = user;
					goto exists_done;
				}
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&user_v, NULL);
	}

      exists_done:
	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&user_v, NULL);
	apol_user_query_destroy(&uq);
	apol_vector_destroy(&user_v, NULL);
	return retv;
}

/* The run function performs the check. This function runs only once even if
 * called multiple times. This function allocates the result structure and
 * fills in all relevant item and proof data.
 * Return Values:
 *  -1 System error
 *   0 The module "succeeded"	- no negative results found
 *   1 The module "failed"		- some negative results found */
int unreachable_doms_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	unreachable_doms_data_t *datum;
	sechk_name_value_t *dep = NULL;
	sechk_result_t *res = NULL, *find_domains_res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i, j, k, l;
	sechk_mod_fn_t run_fn = NULL;
	int error = 0, trans_missing = 0;
	apol_vector_t *dom_vector = NULL, *dom_results = NULL, *dom_roles = NULL;
	apol_vector_t *valid_rev_trans = NULL, *invalid_rev_trans = NULL;
	apol_vector_t *start_roles = NULL, *intersect_roles = NULL;
	apol_vector_t *tmp_users = NULL, *role_users = NULL;
	apol_vector_t *role_trans_vector = NULL, *role_allow_vector = NULL;
	apol_domain_trans_analysis_t *dta = NULL;
	apol_domain_trans_result_t *dtr = NULL;
	char *tmp_name = NULL, *cur_dom_name = NULL, *tmp2 = NULL, *tmp3 = NULL;
	qpol_type_t *cur_dom = NULL, *ep_type = NULL, *start_type = NULL;
	qpol_type_t *last_type = NULL;
	qpol_role_t *last_role = NULL, *src_role = NULL, *dflt_role = NULL;
	qpol_role_t *last_dflt = NULL;
	qpol_user_t *last_user = NULL;
	dom_need_e need = KEEP_SEARCHING;
	apol_role_query_t *role_q = NULL;
	apol_user_query_t *user_q = NULL;
	apol_role_trans_query_t *rtq = NULL;
	apol_role_allow_query_t *raq = NULL;
	qpol_role_trans_t *role_trans = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (unreachable_doms_data_t *) mod->data;
	res = sechk_result_new();
	if (!res) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto unreachable_doms_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
	if (!(res->items = apol_vector_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto unreachable_doms_run_fail;
	}

	/* run dependencies and get results */
	for (i = 0; i < apol_vector_get_size(mod->dependencies); i++) {
		dep = apol_vector_get_element(mod->dependencies, i);
		run_fn = sechk_lib_get_module_function(dep->value, SECHK_MOD_FN_RUN, mod->parent_lib);
		run_fn(sechk_lib_get_module(dep->value, mod->parent_lib), policy, NULL);
	}

	find_domains_res = sechk_lib_get_module_result("find_domains", mod->parent_lib);
	dom_results = find_domains_res->items;
	if (!(dom_vector = apol_vector_create())) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto unreachable_doms_run_fail;
	}
	for (i = 0; i < apol_vector_get_size(dom_results); i++) {
		item = apol_vector_get_element(dom_results, i);
		if (apol_vector_append(dom_vector, (void *)(item->item))) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto unreachable_doms_run_fail;
		}
	}
	item = NULL;
	dom_results = NULL;	       /* no need to destroy, belongs to another module. */

	/* initialize query objects */
	dta = apol_domain_trans_analysis_create();
	if (!dta) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto unreachable_doms_run_fail;
	}
	apol_domain_trans_analysis_set_direction(policy, dta, APOL_DOMAIN_TRANS_DIRECTION_REVERSE);

	role_q = apol_role_query_create();
	if (!role_q) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto unreachable_doms_run_fail;
	}

	user_q = apol_user_query_create();
	if (!user_q) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto unreachable_doms_run_fail;
	}

	rtq = apol_role_trans_query_create();
	if (!rtq) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto unreachable_doms_run_fail;
	}

	raq = apol_role_allow_query_create();
	if (!raq) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto unreachable_doms_run_fail;
	}

	/* dom_vector now contains all types considered domains */
	for (i = 0; i < apol_vector_get_size(dom_vector); i++) {
		cur_dom = apol_vector_get_element(dom_vector, i);
		qpol_type_get_name(q, cur_dom, &cur_dom_name);
		need = KEEP_SEARCHING;

		if (in_def_ctx(cur_dom_name, datum) || in_isid_ctx(cur_dom_name, policy))
			continue;

		/* collect information about roles and transitions to this domain */
		apol_role_query_set_type(policy, role_q, cur_dom_name);
		apol_role_get_by_query(policy, role_q, &dom_roles);
		apol_domain_trans_table_reset(policy);
		apol_domain_trans_analysis_set_start_type(policy, dta, cur_dom_name);
		apol_domain_trans_analysis_set_valid(policy, dta, APOL_DOMAIN_TRANS_SEARCH_VALID);
		apol_domain_trans_analysis_do(policy, dta, &valid_rev_trans);
		apol_domain_trans_table_reset(policy);
		apol_domain_trans_analysis_set_valid(policy, dta, APOL_DOMAIN_TRANS_SEARCH_INVALID);
		apol_domain_trans_analysis_do(policy, dta, &invalid_rev_trans);

		/* for valid transitions - validate RBAC, and then users */
		for (j = 0; j < apol_vector_get_size(valid_rev_trans); j++) {
			dtr = apol_vector_get_element(valid_rev_trans, j);
			start_type = apol_domain_trans_result_get_start_type(dtr);
			ep_type = apol_domain_trans_result_get_entrypoint_type(dtr);
			qpol_type_get_name(q, start_type, &tmp_name);
			apol_role_query_set_type(policy, role_q, tmp_name);
			apol_role_get_by_query(policy, role_q, &start_roles);
			intersect_roles = apol_vector_create_from_intersection(dom_roles, start_roles, NULL, NULL);
			if (apol_vector_get_size(intersect_roles) > 0) {
				/* find user with role in intersect */
				role_users = apol_vector_create();
				for (k = 0; k < apol_vector_get_size(intersect_roles); k++) {
					last_role = apol_vector_get_element(intersect_roles, k);
					qpol_role_get_name(q, last_role, &tmp_name);
					apol_user_query_set_role(policy, user_q, tmp_name);
					apol_user_get_by_query(policy, user_q, &tmp_users);
					if (apol_vector_cat(role_users, tmp_users)) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					apol_vector_destroy(&tmp_users, NULL);
				}
				if (apol_vector_get_size(role_users) > 0)
					need = DONE;
				else
					need = USER;
				apol_vector_destroy(&role_users, NULL);
			}
			if (need == DONE)
				break;
			/* look for role_transitions */
			qpol_type_get_name(q, ep_type, &tmp_name);
			apol_role_trans_query_set_target(policy, rtq, tmp_name, 1);
			apol_role_trans_get_by_query(policy, rtq, &role_trans_vector);
			for (k = 0; need != DONE && k < apol_vector_get_size(role_trans_vector); k++) {
				role_trans = apol_vector_get_element(role_trans_vector, k);
				qpol_role_trans_get_source_role(q, role_trans, &src_role);
				qpol_role_trans_get_default_role(q, role_trans, &dflt_role);
				if (apol_vector_get_index(start_roles, src_role, NULL, NULL, &l)
				    || apol_vector_get_index(dom_roles, dflt_role, NULL, NULL, &l))
					continue;	/* start domain must have the source role and cur_dom must have default role or transition does not apply */
				if (exists_common_user(policy, start_roles, dom_roles, NULL, NULL, NULL)) {
					qpol_role_get_name(q, src_role, &tmp_name);
					apol_role_allow_query_set_source(policy, raq, tmp_name);
					qpol_role_get_name(q, dflt_role, &tmp_name);
					apol_role_allow_query_set_target(policy, raq, tmp_name);
					apol_role_allow_get_by_query(policy, raq, &role_allow_vector);
					if (apol_vector_get_size(role_allow_vector) > 0) {
						need = DONE;
					} else {
						need = ROLE_ALLOW;
						last_role = src_role;
						last_dflt = dflt_role;
					}
					apol_vector_destroy(&role_allow_vector, NULL);
				} else {
					need = COMMON_USER;
					last_role = src_role;
					last_dflt = dflt_role;
				}
			}
			/* no roles usable in intersection and no transitions so pick first set with common user */
			if (apol_vector_get_size(role_trans_vector) == 0) {
				if (exists_common_user(policy, start_roles, dom_roles, &src_role, &dflt_role, &last_user)) {
					need = ROLE_TRANS;
					last_role = src_role;
					last_dflt = dflt_role;
					last_type = ep_type;
				} else {
					need = RBAC;
				}
			}
			apol_vector_destroy(&role_trans_vector, NULL);
			if (need == DONE)
				break;
		}
		/* if no valid transition found - check what is needed to complete invalid ones */
		if (need == KEEP_SEARCHING) {
			for (j = 0; j < apol_vector_get_size(invalid_rev_trans); j++) {
				dtr = apol_vector_get_element(invalid_rev_trans, j);
				start_type = apol_domain_trans_result_get_start_type(dtr);
				ep_type = apol_domain_trans_result_get_entrypoint_type(dtr);
				trans_missing = apol_domain_trans_table_verify_trans(policy, start_type, ep_type, cur_dom);
				need = VALID_TRANS;
				/* since incomplete transitions can be missing types break if we
				 * found one with all three types specified, else keep the last one */
				if (start_type && ep_type)
					break;
			}
		}
		/* if no transition exists (valid or otherwise) check that at least one role and user pair is valid */
		if (need == KEEP_SEARCHING) {
			role_users = apol_vector_create();
			for (j = 0; j < apol_vector_get_size(dom_roles); j++) {
				last_role = apol_vector_get_element(dom_roles, j);
				qpol_role_get_name(q, last_role, &tmp_name);
				apol_user_query_set_role(policy, user_q, tmp_name);
				apol_user_get_by_query(policy, user_q, &tmp_users);
				apol_vector_cat(role_users, tmp_users);
				apol_vector_destroy(&tmp_users, NULL);
			}
			if (apol_vector_get_size(dom_roles) == 0) {
				need = ROLE;
			} else if (apol_vector_get_size(role_users) == 0) {
				need = USER;
			} else {
				need = TRANSITION;
			}
			apol_vector_destroy(&role_users, NULL);
		}
		/* if something needs to be reported do so now */
		if (need != DONE) {
			assert(need != KEEP_SEARCHING);
			item = sechk_item_new(NULL);
			if (!item) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto unreachable_doms_run_fail;
			}
			item->item = (void *)cur_dom;
			item->test_result = (unsigned char)need;
			item->proof = apol_vector_create();
			if (!item->proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto unreachable_doms_run_fail;
			}
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto unreachable_doms_run_fail;
			}
			proof->type = SECHK_ITEM_NONE;
			proof->elem = NULL;
			switch (need) {
			case USER:
				{
					qpol_role_get_name(q, last_role, &tmp_name);
					if (asprintf(&proof->text, "No user associated with role %s for %s", tmp_name, cur_dom_name)
					    < 0) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					break;
				}
			case COMMON_USER:
				{
					qpol_role_get_name(q, last_role, &tmp_name);
					qpol_role_get_name(q, last_dflt, &tmp2);
					if (asprintf
					    (&proof->text, "Role transition required but no user associated with role %s and %s",
					     tmp_name, tmp2) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					break;
				}
			case ROLE_TRANS:
				{
					qpol_role_get_name(q, last_role, &tmp_name);
					qpol_role_get_name(q, last_dflt, &tmp2);
					qpol_type_get_name(q, last_type, &tmp3);
					if (asprintf(&proof->text, "Missing: role_transition %s %s %s;", tmp_name, tmp3, tmp2) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					break;
				}
			case ROLE_ALLOW:
				{
					qpol_role_get_name(q, last_role, &tmp_name);
					qpol_role_get_name(q, last_dflt, &tmp2);
					if (asprintf
					    (&proof->text,
					     "Role transition required but missing role allow rule.\n\tMissing: allow %s %s;",
					     tmp_name, tmp2) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					break;
				}
			case RBAC:
				{
					if (asprintf
					    (&proof->text,
					     "Valid domain transition to %s exists but indufficient RBAC rules to permit it.",
					     cur_dom_name) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					break;
				}
			case VALID_TRANS:
				{
					if (start_type)
						qpol_type_get_name(q, start_type, &tmp2);
					else
						tmp2 = "<start_type>";
					if (ep_type)
						qpol_type_get_name(q, ep_type, &tmp3);
					else
						tmp3 = "<entrypont>";
					if (asprintf
					    (&proof->text,
					     "Partial transition to %s found:\n\t%s: allow %s %s : process transition;\n\t%s: allow %s %s : file execute;\n\t%s: allow %s %s : file entrypoint;\n\t%s one of:\n\tallow %s self : process setexec;\n\ttype_transition %s %s : process %s;",
					     cur_dom_name,
					     ((trans_missing & APOL_DOMAIN_TRANS_RULE_PROC_TRANS) ? "Missing" : "Has"), tmp2,
					     cur_dom_name, ((trans_missing & APOL_DOMAIN_TRANS_RULE_EXEC) ? "Missing" : "Has"),
					     tmp2, tmp3, ((trans_missing & APOL_DOMAIN_TRANS_RULE_ENTRYPOINT) ? "Missing" : "Has"),
					     cur_dom_name, tmp3,
					     ((trans_missing & (APOL_DOMAIN_TRANS_RULE_TYPE_TRANS | APOL_DOMAIN_TRANS_RULE_SETEXEC))
					      ? "May need" : "Has"), cur_dom_name, tmp2, tmp3, cur_dom_name) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					break;
				}
			case ROLE:
				{
					if (asprintf(&proof->text, "No role associated with domain %s", cur_dom_name) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					break;
				}
			case TRANSITION:
				{
					if (asprintf(&proof->text, "There are no transitions to domain %s", cur_dom_name) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto unreachable_doms_run_fail;
					}
					break;
				}
			case DONE:
			case KEEP_SEARCHING:
			default:
				{
					assert(0);
					error = EDOM;
					goto unreachable_doms_run_fail;
				}
			}
			if (apol_vector_append(item->proof, (void *)proof) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto unreachable_doms_run_fail;
			}
			proof = NULL;
			if (apol_vector_append(res->items, (void *)item) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto unreachable_doms_run_fail;
			}
			item = NULL;
		}
		apol_vector_destroy(&dom_roles, NULL);
		apol_vector_destroy(&valid_rev_trans, apol_domain_trans_result_free);
		apol_vector_destroy(&invalid_rev_trans, apol_domain_trans_result_free);
	}

	apol_vector_destroy(&dom_vector, NULL);
	apol_domain_trans_analysis_destroy(&dta);
	apol_role_query_destroy(&role_q);
	apol_user_query_destroy(&user_q);
	apol_role_trans_query_destroy(&rtq);
	apol_role_allow_query_destroy(&raq);
	mod->result = res;

	if (apol_vector_get_size(res->items))
		return 1;
	return 0;

      unreachable_doms_run_fail:
	apol_vector_destroy(&dom_vector, NULL);
	apol_domain_trans_analysis_destroy(&dta);
	apol_role_query_destroy(&role_q);
	apol_user_query_destroy(&user_q);
	apol_role_trans_query_destroy(&rtq);
	apol_role_allow_query_destroy(&raq);
	apol_vector_destroy(&dom_roles, NULL);
	apol_vector_destroy(&valid_rev_trans, apol_domain_trans_result_free);
	apol_vector_destroy(&invalid_rev_trans, apol_domain_trans_result_free);
	apol_vector_destroy(&tmp_users, NULL);
	apol_vector_destroy(&role_users, NULL);
	apol_vector_destroy(&role_trans_vector, NULL);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The free function frees the private data of a module */
void unreachable_doms_data_free(void *data)
{
	unreachable_doms_data_t *d = data;
	if (!data)
		return;

	free(d->ctx_file_path);
	apol_vector_destroy(&d->ctx_vector, free);
	free(data);
}

/* The print function generates the text and prints the results to stdout. */
int unreachable_doms_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	unreachable_doms_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0, k, l, num_items;
	qpol_type_t *type;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	char *type_name;

	if (!mod || !policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	datum = (unreachable_doms_data_t *) mod->data;
	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0;	       /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i unreachable domains.\n", num_items);
	}

	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			j %= 4;
			item = apol_vector_get_element(mod->result->items, i);
			type = (qpol_type_t *) item->item;
			qpol_type_get_name(q, type, &type_name);
			printf("%s%s", type_name, (char *)((j && i != num_items - 1) ? ", " : "\n"));
		}
		printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		if (apol_vector_get_size(datum->ctx_vector) > 0) {
			printf("Found %d domains in %s:\n", apol_vector_get_size(datum->ctx_vector),
			       selinux_default_context_path());
			for (j = 0; j < apol_vector_get_size(datum->ctx_vector); j++) {
				type_name = apol_vector_get_element(datum->ctx_vector, j);
				printf("\t%s\n", type_name);
			}
		}

		printf("\n");
		for (k = 0; k < num_items; k++) {
			item = apol_vector_get_element(mod->result->items, k);
			if (item) {
				type = item->item;
				qpol_type_get_name(q, type, &type_name);
				printf("%s\n", (char *)type_name);
				for (l = 0; l < apol_vector_get_size(item->proof); l++) {
					proof = apol_vector_get_element(item->proof, l);
					if (proof)
						printf("\t%s\n", proof->text);
				}
			}
			printf("\n");
		}
	}

	return 0;
}

/* The unreachable_doms_data_new function allocates and returns an initialized
 * private data storage structure for this module. */
unreachable_doms_data_t *unreachable_doms_data_new(void)
{
	unreachable_doms_data_t *datum = NULL;

	datum = (unreachable_doms_data_t *) calloc(1, sizeof(unreachable_doms_data_t));

	return datum;
}

/* Parses default_contexts and adds source domains to datum->ctx_list.
 * The vector will contain newly allocated strings. */
static bool_t parse_default_contexts(const char *ctx_file_path, apol_vector_t * ctx_vector, apol_policy_t * policy)
{
	int str_sz, i, charno, error = 0;
	FILE *ctx_file;
	char *line = NULL, *src_role = NULL, *src_dom = NULL, *dst_role = NULL, *dst_dom = NULL;
	size_t retv, line_len = 0;
	bool_t uses_mls = FALSE;

	printf("Using default contexts: %s\n", ctx_file_path);
	ctx_file = fopen(ctx_file_path, "r");
	if (!ctx_file) {
		error = errno;
		ERR(policy, "Opening default contexts file %s", ctx_file_path);
		goto parse_default_contexts_fail;
	}

	while (!feof(ctx_file)) {
		retv = getline(&line, &line_len, ctx_file);
		if (retv == -1) {
			if (feof(ctx_file)) {
				break;
			} else {
				error = errno;
				ERR(policy, "%s", "Reading default contexts file");
				goto parse_default_contexts_fail;
			}
		}

		uses_mls = FALSE;
		str_sz = APOL_STR_SZ + 128;
		i = 0;

		/* source role */
		src_role = malloc(str_sz);
		if (!src_role) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto parse_default_contexts_fail;
		}

		memset(src_role, 0x0, str_sz);
		charno = 0;
		while (line[i] != ':') {
			if (!isspace(line[i])) {
				src_role[i] = line[i];
				charno++;
			}
			i++;
		}
		i++;		       /* skip ':' */

		/* source type */
		src_dom = malloc(str_sz);
		if (!src_dom) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto parse_default_contexts_fail;
		}
		memset(src_dom, 0x0, str_sz);
		charno = 0;
		while (1) {
			if (isspace(line[i]))
				break;
			/* Check for MLS */
			if (line[i] == ':') {
				uses_mls = TRUE;
				i++;   /* skip ':' */
				while (!isspace(line[i]))
					i++;
			}
			if (uses_mls)
				break;

			src_dom[charno] = line[i];
			charno++;
			i++;
		}

		/* dest role */
		dst_role = malloc(str_sz);
		if (!dst_role) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto parse_default_contexts_fail;
		}
		memset(dst_role, 0x0, str_sz);
		charno = 0;
		while (line[i] != ':') {
			if (!isspace(line[i])) {
				dst_role[charno] = line[i];
				charno++;
			}

			i++;
		}
		i++;		       /* skip ':' */

		/* dest type */
		dst_dom = malloc(str_sz);
		if (!dst_dom) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto parse_default_contexts_fail;
		}
		memset(dst_dom, 0x0, str_sz);
		charno = 0;
		while (line[i]) {
			if (uses_mls)
				if (line[i] == ':')
					break;

			if (!isspace(line[i]))
				dst_dom[charno] = line[i];

			charno++;
			i++;
		}

		if (apol_vector_append(ctx_vector, (void *)strdup(src_dom)) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto parse_default_contexts_fail;
		}
		free(line);
		line = NULL;
		free(src_role);
		free(src_dom);
		free(dst_role);
		free(dst_dom);
	}
	free(line);
	fclose(ctx_file);
	return TRUE;
      parse_default_contexts_fail:
	if (ctx_file != NULL) {
		fclose(ctx_file);
	}
	free(line);
	free(src_role);
	free(src_dom);
	free(dst_role);
	free(dst_dom);
	errno = error;
	return FALSE;
}

/* Returns true if type_idx is in datum->ctx_list */
static bool_t in_def_ctx(char *type_name, unreachable_doms_data_t * datum)
{
	size_t i;
	if (apol_vector_get_index(datum->ctx_vector, type_name, apol_str_strcmp, NULL, &i) < 0) {
		return FALSE;
	}
	return TRUE;
}

/* Returns true if type is a type assigned to an isid */
static bool_t in_isid_ctx(char *type_name, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	qpol_policy_get_isid_iter(q, &iter);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_isid_t *isid;
		qpol_context_t *ocon;
		qpol_type_t *context_type;
		char *context_type_name;

		qpol_iterator_get_item(iter, (void **)&isid);
		qpol_isid_get_context(q, isid, &ocon);
		qpol_context_get_type(q, ocon, &context_type);
		qpol_type_get_name(q, context_type, &context_type_name);
		if (!strcmp(type_name, context_type_name)) {
			qpol_iterator_destroy(&iter);
			return TRUE;
		}
	}
	qpol_iterator_destroy(&iter);
	return FALSE;
}
