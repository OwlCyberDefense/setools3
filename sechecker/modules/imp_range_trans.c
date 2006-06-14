/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: David Windsor <dwindsor@tresys.com>
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "render.h"
#include "imp_range_trans.h"
#include "semantic/avsemantics.h"

#include <stdio.h>
#include <string.h>

#define SECHK_NO_ROLES          0x000002
#define SECHK_BAD_USER_MLS_LOW  0x000040
#define SECHK_BAD_USER_MLS_HIGH 0x000600
#define SECHK_NO_USERS          0x008000
#define SECHK_NO_EXEC_PERMS     0x020000

static sechk_lib_t *library;
static const char *const mod_name = "imp_range_trans";

int imp_range_trans_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "Error: no library\n");
		return -1;
	}

	library = lib;

	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: module unknown\n");
		return -1;
	}
	
	/* assign the descriptions */
	mod->brief_description = "finds impossible range transitions";
	mod->detailed_description =
"--------------------------------------------------------------------------------\n"
"This module finds impossible range transitions in a policy.\n"
"A range transition is possible if and only if all of the following conditions\n" 
"are satisfied:\n"
"   1) there exist TE rules allowing the range transition to occur\n"
"   2) there exist RBAC rules allowing the range transition to occur\n"
"   3) at least one user must be able to transition to the target MLS range\n";
	mod->opt_description = 
"  Module requirements:\n"
"    none\n"
"  Module dependencies:\n"
"    none\n"
"  Module options:\n"
"    none\n";
	mod->severity = SECHK_SEV_MED;
	/* assign requirements */
	mod->requirements = NULL;

	/* assign dependencies */
	mod->dependencies = NULL;

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &imp_range_trans_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &imp_range_trans_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_FREE);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &imp_range_trans_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &imp_range_trans_print_output;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_GET_RES);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &imp_range_trans_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int imp_range_trans_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	imp_range_trans_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = imp_range_trans_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->options;
	while (opt) {
		opt = opt->next;
	}

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relavant item and proof data. 
 * Return Values:
 *  -1 System error
 *   0 The module "succeeded"	- no negative results found
 *   1 The module "failed" 		- some negative results found */
int imp_range_trans_run(sechk_module_t *mod, policy_t *policy)
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	imp_range_trans_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	ap_rangetrans_t *r_trans = NULL;
	ta_item_t *src_types = NULL;
	int i, num_roles = 0, num_users = 0;
	int *valid_roles = NULL, valid_roles_sz = 0;
	int *valid_users = NULL, valid_users_sz = 0;
	bool_t found_role = FALSE, found_user = FALSE, found_valid_user_mls = FALSE;
	int file_idx, exec_idx;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (imp_range_trans_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto imp_range_trans_run_fail;
	}
	res->item_type = POL_LIST_TYPE;
	
	if (!avh_hash_table_present(policy->avh)) {
                if (avh_build_hashtab(policy) != 0) {
                        fprintf(stderr, "Error: could not build hash table\n");
                        goto imp_range_trans_run_fail;
                }
        }
	
	/* resolve "file" object class to idx */
	file_idx = get_obj_class_idx("file", policy);
	if (file_idx < 0) {
		fprintf(stderr, "Error: getting file object class index\n");
		goto imp_range_trans_run_fail;
	}

	/* resolve "execute" permission to idx */
	exec_idx = get_perm_idx("execute", policy);
	if (exec_idx < 0) {
		fprintf(stderr, "Error: getting exec permissions index\n");
		goto imp_range_trans_run_fail;
	}

	for (i = 0; i < policy->num_rangetrans; i++) {
		found_role = FALSE;
		found_user = FALSE;
		found_valid_user_mls = FALSE;

		r_trans = &(policy->rangetrans[i]);
		if (!r_trans) {
			fprintf(stderr, "Error: invalid rangetrans\n");
			goto imp_range_trans_run_fail;
		}
	
		/* Examine each source type */
		for (src_types = r_trans->src_types; src_types; src_types = src_types->next) {
			num_roles = 0;
			num_users = 0;

			/* Verify that source domain has file execute permissions in target domain */
			if (!has_exec_perms(r_trans->tgt_types, src_types->idx, file_idx, exec_idx, policy)) {
				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto imp_range_trans_run_fail;
				}
				proof->idx = -1;
				proof->type = POL_LIST_TYPE;
				proof->text = build_no_exec_proof_str(r_trans, policy);
				if (!proof->text) {
					fprintf(stderr, "Error: unable to build proof element\n");
					goto imp_range_trans_run_fail;
				}

				if (res->num_items > 0) {
					item = sechk_result_get_item(i, POL_LIST_TYPE, res);
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto imp_range_trans_run_fail;
						}
						item->item_id = i;
					}
				} else {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto imp_range_trans_run_fail;
					}
					item->item_id = i;
				}
				item->test_result |= SECHK_NO_EXEC_PERMS;
				
				proof->next = item->proof;
				item->proof = proof;

				if (res->num_items > 0) {
					if (!sechk_result_get_item(i, POL_LIST_TYPE, res)) {
						item->next = res->items;
						res->items = item;
						(res->num_items)++;
					}
				} else {
					item->next = res->items;
					res->items = item;
					(res->num_items)++;
				}

				continue;
			}			

			/* Find roles associated with src_types->idx */
			num_roles = get_valid_roles(&valid_roles, &valid_roles_sz, src_types->idx, policy);
			if (num_roles == -1) {
				fprintf(stderr, "Error: unable to get roles\n");
				goto imp_range_trans_run_fail;
			}
			
			/* No valid roles were found */
			if (num_roles == 0) {
				proof = sechk_proof_new();
                                if (!proof) {
                                        fprintf(stderr, "Error: out of memory\n");
                                        goto imp_range_trans_run_fail;
                                }
                                proof->idx = -1;
                                proof->type = POL_LIST_TYPE;
                                proof->text = build_no_roles_proof_str(r_trans, src_types->idx, policy);
                                if (!proof->text) {
                                        fprintf(stderr, "Error: unable to build proof element\n");
                                        goto imp_range_trans_run_fail;
                                }

				if (res->num_items > 0) {
					item = sechk_result_get_item(i, POL_LIST_TYPE, res);
					if (!item) {
						/* Result doesn't include this item; create new */
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto imp_range_trans_run_fail;
						}
						item->item_id = i;
					}
				} else {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto imp_range_trans_run_fail;
					}
					item->item_id = i;
				}
				item->test_result |= SECHK_NO_ROLES;
				
				proof->next = item->proof;
				item->proof = proof;
				
				if (res->num_items > 0) {
					if (!sechk_result_get_item(i, POL_LIST_TYPE, res)) {
						item->next = res->items;
						res->items = item;
						(res->num_items)++;
					}
				} else {
					item->next = res->items;
					res->items = item;
					(res->num_items)++;
				}

				continue;  /* Process next src_type within this range trans */
			}
			
			/* Find users allowed with roles in valid_roles */
			num_users = get_valid_users(&valid_users, &valid_users_sz, valid_roles, valid_roles_sz, &found_user, r_trans->range, policy);
			if (num_users == -1) {
				fprintf(stderr, "Error: getting users\n");
				goto imp_range_trans_run_fail;
			}
			found_valid_user_mls = (num_users > 0) ? TRUE : FALSE;

			/* No user was found with a role in valid_roles */
			if (!found_user) {
		      		proof = sechk_proof_new();
		       		if (!proof) {
		       			fprintf(stderr, "Error: out of memory\n");
		       			goto imp_range_trans_run_fail;
		       		}
			       	proof->idx = -1;
			       	proof->type = POL_LIST_TYPE;
			       	proof->text = build_no_user_proof_str(valid_roles, valid_roles_sz, policy);
				if (!proof->text)
					goto imp_range_trans_run_fail;

       				if (res->num_items > 0) {
				       	item = sechk_result_get_item(i, POL_LIST_TYPE, res);
				       	if (!item) {
				       		item = sechk_item_new();
				       		if (!item) {
				       			fprintf(stderr, "Error: out of memory\n");
				       			goto imp_range_trans_run_fail;
       						}
       						item->item_id = i;
       					}
       				}

			       	item->test_result |= SECHK_NO_USERS;
			       	proof->next = item->proof;
			      	item->proof = proof;
				if (res->num_items > 0) {
					if (!sechk_result_get_item(i, POL_LIST_TYPE, res)) {
						item->next = res->items;
						res->items = item;
						(res->num_items)++;
					}
					
				} else {
					item->next = res->items;
					res->items = item;
					(res->num_items)++;
				}
			} else if (!found_valid_user_mls) {
				/* A user was found with role in valid_roles, but MLS range insufficient for trans */
				verify_user_range(valid_roles, valid_roles_sz, i, r_trans, res, policy); 
			}

			if (valid_roles_sz > 0) {
				free(valid_roles);
				valid_roles_sz = 0;
			}
			if (valid_users_sz > 0) {
				free(valid_users);
				valid_users_sz = 0;
			}
		}
	}
	mod->result = res;

	if (valid_roles_sz > 0) {
		free(valid_roles);
		valid_roles_sz = 0;
	}
	if (valid_users_sz > 0) {
		free(valid_users);
		valid_users_sz = 0;
	}

	/* If module finds something that would be considered a fail 
	 * on the policy return 1 here */
	if (res->num_items > 0)
		return 1;

	return 0;

imp_range_trans_run_fail:
	if (valid_roles_sz > 0)
		free(valid_roles);
	if (valid_users_sz > 0)
		free(valid_users);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
#endif
	return -1;
}

/* The free function frees the private data of a module */
void imp_range_trans_free(sechk_module_t *mod)
{
	imp_range_trans_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (imp_range_trans_data_t*)mod->data;
	if (datum) {
	}

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a report section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief) */
int imp_range_trans_print_output(sechk_module_t *mod, policy_t *policy) 
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	imp_range_trans_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;

	if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}
	
	datum = (imp_range_trans_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i impossible range transitions.\n", mod->result->num_items);
	}

	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s\n", re_render_rangetrans(FALSE, item->item_id, policy));			
		}
		printf("\n");
	}
	
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s\n", re_render_rangetrans(FALSE, item->item_id, policy));
			for (proof = item->proof; proof; proof = proof->next) {
				printf("\t%s\n", proof->text);
			}
			printf("\n");
		}
	}

#endif
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *imp_range_trans_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return NULL;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

/* The imp_range_trans_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. Initialization expected is as follows:
 * all arrays (including strings) are initialized to NULL
 * array sizes are set to 0
 * any other pointers should be NULL
 * indices into other arrays (such as type or permission indices)
 * should be initialized to -1
 * any other data should be initialized as needed by the check logic */
imp_range_trans_data_t *imp_range_trans_data_new(void)
{
	imp_range_trans_data_t *datum = NULL;

	datum = (imp_range_trans_data_t*)calloc(1,sizeof(imp_range_trans_data_t));

	return datum;
}

/*
 * Returns a string indicating that no roles were
 * found to be valid for a particular type.  
 * This function allocates the returned string; caller must free
 */
static char *build_no_roles_proof_str(ap_rangetrans_t *r_trans, const int type_idx, policy_t *policy)
{
	char *str = NULL;
	int str_sz = APOL_STR_SZ + 128;

	if (!r_trans || !policy)
		return NULL;
	if (!is_valid_type_idx(type_idx, policy))
		return NULL;

	str = malloc(str_sz);
	if (!str) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	memset(str, 0x0, str_sz);
	
	snprintf(str, str_sz, "No valid roles exist for domain %s.\n\tRule needed: role <<role_r>> types %s", 
		 is_valid_type_idx(type_idx, policy) ? policy->types[type_idx].name : "",
		 is_valid_type_idx(type_idx, policy) ? policy->types[type_idx].name : "");

	return str;
}

/*
 * Returns a string indicating that there is 
 * no user that can transition to a particular MLS
 * level.
 * This function allocates the returned string; caller must free.  
 */
static char *build_bad_user_mls_proof_str(ap_user_t *user, const int *valid_roles, const int valid_roles_sz, ap_rangetrans_t *r_trans, policy_t *policy)
{
	char *str = NULL;
	int str_sz = APOL_STR_SZ + 128;
	int i, user_idx, role_idx;
	int *valid_users = NULL, valid_users_sz = 0;

	if (!user || !r_trans || !policy)
		return NULL;

	str = malloc(str_sz);
	if (!str) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	memset(str, 0x0, str_sz);

	/* Find users which are in valid_roles */
	for (role_idx = 0; role_idx < valid_roles_sz; role_idx++) {
		for (user_idx = 0; user_idx < policy->num_users; user_idx++) {
			if (does_user_have_role(user_idx, valid_roles[role_idx], policy)) {
				/* Valid user */
				if (find_int_in_array(user_idx, valid_users, valid_users_sz) == -1)
					add_i_to_a(user_idx, &valid_users_sz, &valid_users);								
			}
		}
	}
	
	snprintf(str, str_sz, "No users can transition to range %s.\n\tPossible users: ",
		 re_render_mls_range(r_trans->range, policy));
	
	for (i = 0; i < valid_users_sz; i++) {
		user_idx = valid_users[i];
		if (is_valid_user_idx(user_idx, policy)) {
			if (i > 0)
				append_str(&str, &str_sz, ", ");
			append_str(&str, &str_sz, policy->users[user_idx].name);
		}
	}

	if (valid_users_sz > 0)
		free(valid_users);

	return str;
}

/* 
 * Returns a string indicating that execute permissions
 * for file objects in a particular domain were not found.
 * This function allocates the returned string; caller must free.
 */
static char *build_no_exec_proof_str(ap_rangetrans_t *r_trans, policy_t *policy)
{
	char *str = NULL;
	int str_sz = APOL_STR_SZ + 128;

	if (!r_trans || !policy)
		return NULL;

	if (!r_trans->src_types || !r_trans->tgt_types)
		return NULL;
	
	str = malloc(str_sz);
	if (!str) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	memset(str, 0x0, str_sz);
	
	snprintf(str, str_sz, "No execute permissions found on file objects in domain %s.\n\tRule needed: allow %s %s:file { execute }",
		 is_valid_type_idx(r_trans->tgt_types->idx, policy) ? policy->types[r_trans->tgt_types->idx].name : "", 
		 is_valid_type_idx(r_trans->src_types->idx, policy) ? policy->types[r_trans->src_types->idx].name : "",
		 is_valid_type_idx(r_trans->tgt_types->idx, policy) ? policy->types[r_trans->tgt_types->idx].name : "");
	return str;	
}

/*
 * Returns a string indicating that a user with a valid
 * role could not be found in the policy.
 * This function allocates the returned string; caller must free.
 */
static char *build_no_user_proof_str(const int *valid_roles, const int valid_roles_sz, policy_t *policy)
{
	char *str = NULL;
	int i, role_idx, str_sz = 0;
	
	append_str(&str, &str_sz, "A user with a valid role could not be found.\n\tValid roles: ");
	for (i = 0; i < valid_roles_sz; i++) {
		role_idx = valid_roles[i];
		if (is_valid_role_idx(role_idx, policy)) {
			if (i > 0)
				append_str(&str, &str_sz, ", ");
			append_str(&str, &str_sz, policy->roles[role_idx].name);
		}		
	}	

	return str;
}

/*
 * Verifies that a user's MLS range is sufficient to
 * transition into another MLS range.
 * Returns TRUE if the user's MLS range is sufficient
 * Returns FALSE otherwise
 */
static bool_t verify_user_range(const int *valid_roles, const int valid_roles_sz, const int rtrans_idx, ap_rangetrans_t *r_trans, sechk_result_t *res, policy_t *policy) 
{
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	ap_user_t *user = NULL;
	int user_no, i, role_idx, mls_comp = 0;

	if (!r_trans || !res || !policy)
		return FALSE;

	for (i = 0; i < valid_roles_sz; i++) {
		role_idx = valid_roles[i];
		if (!is_valid_role_idx(role_idx, policy))
			return FALSE;

		/* Find the first valid user for this role */
		for (user_no = 0; user_no < policy->num_users; user_no++) {
			if (does_user_have_role(user_no, role_idx, policy)) {
				user = (ap_user_t *) &(policy->users[user_no]);
				if (!user) {
					fprintf(stderr, "Error: invalid user\n");
					return FALSE;
				}
				break;
			}
		}	
	}

	mls_comp = ap_mls_level_compare(user->range->low, r_trans->range->low, policy);
	if (mls_comp != AP_MLS_DOMBY && mls_comp != AP_MLS_EQ) {
		proof = sechk_proof_new();
		if (!proof) {
			fprintf(stderr, "Error: out of memory\n");
			return FALSE;
		}
		proof->idx = -1;
		proof->type = POL_LIST_TYPE;
		proof->text = build_bad_user_mls_proof_str(user, valid_roles, valid_roles_sz, r_trans, policy);
		if (!proof->text) {
			fprintf(stderr, "Error: unable to build proof element\n");
			return FALSE;
		}

		if (res->num_items > 0) {
			item = sechk_result_get_item(rtrans_idx, POL_LIST_TYPE, res);
			if (!item) {
				/* Result doesn't include this item; create new */
				item = sechk_item_new();
				if (!item) {
					fprintf(stderr, "Error: out of memory\n");
					return FALSE;
				}
				item->item_id = rtrans_idx;
			}
		} else {
			item = sechk_item_new();
			if (!item) {
				fprintf(stderr, "Error: out of memory\n");
				return FALSE;
			}
			item->item_id = rtrans_idx;
		}
		item->test_result |= SECHK_BAD_USER_MLS_LOW;

		proof->next = item->proof;
		item->proof = proof;
		
		if (res->num_items == 0) {
			item->next = res->items;
			res->items = item;
			(res->num_items)++;
		} else {
			/* We don't have results for this rtrans_idx yet */
			if (!sechk_result_get_item(rtrans_idx, POL_LIST_TYPE, res)) {
				item->next = res->items;
				res->items = item;
				(res->num_items)++;
			}
		}
	}

	mls_comp = ap_mls_level_compare(user->range->high, r_trans->range->high, policy);
	if (mls_comp != AP_MLS_DOM && mls_comp != AP_MLS_EQ) {
		proof = sechk_proof_new();
		if (!proof) {
			fprintf(stderr, "Error: out of memory\n");
			return FALSE;
		}
		proof->idx = -1;
		proof->type = POL_LIST_TYPE;
		proof->text = build_bad_user_mls_proof_str(user, valid_roles, valid_roles_sz, r_trans, policy);
		if (!proof->text) {
			fprintf(stderr, "Error: unable to build proof element\n");
			return FALSE;
		}

		if (res->num_items > 0) {
			item = sechk_result_get_item(rtrans_idx, POL_LIST_TYPE, res);
			if (!item) {
				/* Result doesn't include this item; create new */
				item = sechk_item_new();
				if (!item) {
					fprintf(stderr, "Error: out of memory\n");
					return FALSE;
				}
				item->item_id = rtrans_idx;
			}
		} else {
			item = sechk_item_new();
			if (!item) {
				fprintf(stderr, "Error: out of memory\n");
				return FALSE;
			}
			item->item_id = rtrans_idx;
		}
		item->test_result |= SECHK_BAD_USER_MLS_HIGH;

		proof->next = item->proof;
		item->proof = proof;

		if (res->num_items > 0) {
			if (!sechk_result_get_item(rtrans_idx, POL_LIST_TYPE, res)) {
				item->next = res->items;
				res->items = item;
				(res->num_items++);
			}
		} else {
			item->next = res->items;
			res->items = item;
			(res->num_items)++;
		}
	}

	return TRUE;
}

/*
 * Populates valid_roles with roles valid for type with index type_idx
 * Returns number of valid roles added on success 
 * Returns -1 on failure
 */
static int get_valid_roles(int **valid_roles, int *valid_roles_sz, const int type_idx, policy_t *policy)
{
	int role_no;
	int *tmp_roles = NULL, tmp_roles_sz = 0;
	bool_t found_role;

	for (role_no = 0; role_no < policy->num_roles; role_no++) {
		if (does_role_use_type(role_no, type_idx, policy)) {
			found_role = TRUE;
			if (add_i_to_a(role_no, &tmp_roles_sz, &tmp_roles) < 0) {
				fprintf(stderr, "Error: out of memory\n");
				return -1;
			}
		}
	}	
	
	*valid_roles = tmp_roles;
	*valid_roles_sz = tmp_roles_sz;
	return *valid_roles_sz;
}

/*
 * Finds users with roles in valid_roles.
 * Returns number of users if at least 1 user can be found
 * Returns -1 on error
 */
static int get_valid_users(int **valid_users, int *valid_users_sz, const int *valid_roles, const int valid_roles_sz, bool_t *found_user, ap_mls_range_t *range, policy_t *policy)
{
	int i, user_no, low_lvl_cmp, high_lvl_cmp;
	int *tmp_users = NULL, tmp_users_sz = 0;
	ap_user_t *user = NULL;

	if (!range || !policy)
		return -1;

	/* Process each valid role */
	for (i = 0; i < valid_roles_sz; i++) {
		for (user_no = 0; user_no < policy->num_users; user_no++) {
			if (does_user_have_role(user_no, valid_roles[i], policy)) {
				*found_user = TRUE;
					
				/* Verify that used_user->range->low domby r_trans->range->low */
				if (is_valid_user_idx(user_no, policy)) {
					user = &(policy->users[user_no]);
					if (!user) {
						fprintf(stderr, "Error: invalid user\n");
						return -1;
					}
					
					/* Compare user range with original range transition */
					low_lvl_cmp = ap_mls_level_compare(user->range->low, range->low, policy);
					high_lvl_cmp = ap_mls_level_compare(user->range->high, range->high, policy);
					
					if ((low_lvl_cmp == AP_MLS_DOMBY || low_lvl_cmp == AP_MLS_EQ) &&
					    (high_lvl_cmp == AP_MLS_DOM  || high_lvl_cmp == AP_MLS_EQ)) {
						if (add_i_to_a(user_no, &tmp_users_sz, &tmp_users) < 0) {
							fprintf(stderr, "Error: out of memory\n");
							return -1;
						}
						*valid_users_sz = tmp_users_sz;
					}
				}
			}
		} /* end for - users */
	} /* end for - roles */

	*valid_users = tmp_users;
	*valid_users_sz = tmp_users_sz;

	return *valid_users_sz;
}

/*
 * Verifies that a domain has execute perms
 * on a file object of a domain. 
 * Returns TRUE if domain src_idx has execute permissions
 *     on file objects in domain tgt_types
 * Returns FALSE otherwise
 */
static bool_t has_exec_perms(ta_item_t *tgt_types, const int src_idx, const int file_idx, const int exec_idx, policy_t *policy)
{
	ta_item_t *tgt = NULL;
	avh_node_t *tmp_node = NULL;
	avh_key_t key;
	int retv;

	for (tgt = tgt_types; tgt; tgt= tgt->next) {
		key.src = src_idx;
		key.tgt = tgt->idx;
		key.cls = file_idx;
		key.rule_type = RULE_TE_ALLOW;

		for (tmp_node = avh_find_first_node(&(policy->avh), &key); tmp_node; tmp_node = tmp_node->next) {
			retv = find_int_in_array(exec_idx, tmp_node->data, tmp_node->num_data);
			if (retv > -1)
				return TRUE;
		}
	}

	return FALSE;
}
