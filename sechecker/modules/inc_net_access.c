/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: dwindsor@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "inc_net_access.h"
#include "render.h"
#include "policy-query.h"
#include "old-policy-query.h"

#include <stdio.h>
#include <string.h>

static const char *const mod_name = "inc_net_access";

#if 0
static void init_net_state(inc_net_access_data_t *net_data);
static void init_idx_cache(idx_cache_t *idx_cache, apol_policy_t *policy);
static int check_perms(const int type_idx, apol_policy_t * policy, sechk_item_t **item, inc_net_access_data_t *net_state);
static bool_t check_type_perms(const int src_idx, const int dst_idx, const int obj_idx, const int perm_idx, apol_policy_t *policy);
static char *build_proof_str(char *src_type, char *dst_type, char *obj_class, char *perms);
static int build_have_perms_proof(const int type_idx, sechk_proof_t **proof, apol_policy_t *policy, idx_cache_t *idx_cache);
static int validate_net_state(const int type_idx, inc_net_access_data_t *net_data, sechk_proof_t **proof, apol_policy_t *policy);
static void check_socket_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state);
static void check_netif_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state);
static void check_port_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state);
static void check_node_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state);
static void check_assoc_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state);
static bool_t uses_tcp(const int domain_idx, idx_cache_t *idx_cache, apol_policy_t *policy);
static bool_t uses_udp(const int domain_idx, idx_cache_t *idx_cache, apol_policy_t *policy);
#endif

/* result lists */
#if 0
static int *net_domains_list = NULL, *netif_types_list = NULL, *port_types_list = NULL, *node_types_list = NULL, *assoc_types_list = NULL;
static int net_domains_list_sz = 0, netif_types_list_sz = 0, port_types_list_sz = 0, node_types_list_sz = 0, assoc_types_list_sz = 0;
#endif

/* The register function registers all of a module's functions
 * with the library.  You should not need to edit this function
 * unless you are adding additional functions you need other modules
 * to call. See the note at the bottom of this function to do so. */
int inc_net_access_register(sechk_lib_t *lib)
{
#if 0
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;
	sechk_name_value_t *nv = NULL;

	if (!lib) {
		fprintf(stderr, "Error: no library\n");
		return -1;
	}

	library = lib;

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: module unknown\n");
		return -1;
	}
	
	/* assign the descriptions */
	mod->brief_description = "finds network domains with inadequate permissions";
	mod->detailed_description =
"--------------------------------------------------------------------------------\n"
"This module finds all network domains in a policy which do not have the         \n"
"required permissions needed to facilitate network communication. For network\n"
"domains to communicate, the following conditions must be true:\n"
"   1) the domain must have read or write permissions on a socket of the same\n"
"      type\n"
"   2) the domain must have send or receive permissions on an IPsec association\n"
"      (see find_assoc_types)\n"
"   3) the domain must have send or receive permissions on netif objects for a\n"
"      netif type (see find_netif_types)\n"
"   4) the domain must have send or receive permissions on node objects for a\n"
"      node type (see find_node_types)\n"
"   5) the domain must have send or receive permissions on port objects for a\n"
"      port type (see find_port_types)\n"; 
	mod->opt_description = 
"  Module requirements:\n"
"    policy source\n"
"  Module dependencies:\n"
"    find_net_domains module\n"
"    find_assoc_types module\n"
"    find_netif_types module\n"
"    find_port_types module\n"
"    find_node_types module\n"
"  Module options:\n"
"    none\n";
	mod->severity = SECHK_SEV_MED;
	/* assign requirements */
	mod->requirements = sechk_name_value_new("apol_policy_type", "source");

	/* assign dependencies */      
	mod->dependencies = sechk_name_value_new("module", "find_net_domains");
	nv = sechk_name_value_new("module", "find_netif_types");
	nv->next = mod->dependencies;
	mod->dependencies = nv;
	
	nv = sechk_name_value_new("module", "find_port_types");
	nv->next = mod->dependencies;
	mod->dependencies = nv;

	nv = sechk_name_value_new("module", "find_node_types");
	nv->next = mod->dependencies;
	mod->dependencies = nv;

	nv = sechk_name_value_new("module", "find_assoc_types");
	nv->next = mod->dependencies;
	mod->dependencies = nv;
	
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
	fn_struct->fn = &inc_net_access_init;
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
	fn_struct->fn = &inc_net_access_run;
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
	fn_struct->fn = &inc_net_access_free;
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
	fn_struct->fn = &inc_net_access_print_output;
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
	fn_struct->fn = &inc_net_access_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

#endif
	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file.
 * Add any option processing logic as indicated below. */
int inc_net_access_init(sechk_module_t *mod, apol_policy_t *policy)
{
#if 0
	sechk_name_value_t *opt = NULL;
	inc_net_access_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = inc_net_access_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}

	/* Initialize index cache */
	init_idx_cache(&(datum->idx_cache), policy);

	mod->data = datum;

	opt = mod->options;
	while (opt) {
		opt = opt->next;
	}

#endif
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
int inc_net_access_run(sechk_module_t *mod, apol_policy_t *policy)
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	inc_net_access_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	int (* net_domains_list_fn)(sechk_module_t *, int **, int *) = NULL;
	int (* netif_types_list_fn)(sechk_module_t *, int **, int *) = NULL;
	int (* port_types_list_fn)(sechk_module_t *, int **, int *) = NULL;
	int (* node_types_list_fn)(sechk_module_t *, int **, int *) = NULL;
	int (* assoc_types_list_fn)(sechk_module_t *, int **, int *) = NULL;
	sechk_name_value_t *dep = NULL;
	sechk_run_fn_t run_fn = NULL;
	int i = 0, retv = 0, nd = 0;

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

	datum = (inc_net_access_data_t *)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto inc_net_access_run_fail;
	}
	res->item_type = POL_LIST_TYPE;

	/* run dependencies */
	for (dep = mod->dependencies; dep; dep = dep->next) {
		run_fn = sechk_lib_get_module_function(dep->value, SECHK_MOD_FN_RUN, library);
		run_fn(sechk_lib_get_module(dep->value, library), policy);
	}
      
	/* get lists */
	net_domains_list_fn = sechk_lib_get_module_function("find_net_domains", "get_list", library);
        retv = net_domains_list_fn(sechk_lib_get_module("find_net_domains", library), &net_domains_list, &net_domains_list_sz);
        if (retv) {
                fprintf(stderr, "Error: unable to get net domains list\n");
                goto inc_net_access_run_fail;
        }
	netif_types_list_fn = sechk_lib_get_module_function("find_netif_types", "get_list", library);
        retv = netif_types_list_fn(sechk_lib_get_module("find_netif_types", library), &netif_types_list, &netif_types_list_sz);
        if (retv) {
                fprintf(stderr, "Error: unable to get netif types list\n");
                goto inc_net_access_run_fail;
        }
        port_types_list_fn = sechk_lib_get_module_function("find_port_types", "get_list", library);
        retv = port_types_list_fn(sechk_lib_get_module("find_port_types", library), &port_types_list, &port_types_list_sz);
        if (retv) {
                fprintf(stderr, "Error: unable to get port types list\n");
                goto inc_net_access_run_fail;
        }
	node_types_list_fn = sechk_lib_get_module_function("find_node_types", "get_list", library);
        retv = node_types_list_fn(sechk_lib_get_module("find_node_types", library), &node_types_list, &node_types_list_sz);
        if (retv) {
                fprintf(stderr, "Error: unable to get node types list\n");
                goto inc_net_access_run_fail;
        }
	assoc_types_list_fn = sechk_lib_get_module_function("find_assoc_types", "get_list", library);
        retv = assoc_types_list_fn(sechk_lib_get_module("find_assoc_types", library), &assoc_types_list, &assoc_types_list_sz);
        if (retv) {
                fprintf(stderr, "Error: unable to get association types list\n");
                goto inc_net_access_run_fail;
        }

	/* build avh table */
	if (!avh_hash_table_present(policy->avh)) {
		if (avh_build_hashtab(policy) != 0) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto inc_net_access_run_fail;
		}
	}

	/* for each net domain, check permissions */
	for (i = 0; i < net_domains_list_sz; i++) {
		nd = net_domains_list[i];
		switch (check_perms(net_domains_list[i], policy, &item, mod->data)) {
		case inc_net_access_ERR:
			goto inc_net_access_run_fail;
			break;
		case inc_net_access_SUCCESS:
			break;
		case inc_net_access_FAIL:
			/* check_perms() mallocs item */
			if (!item) {
				fprintf(stderr, "Error: item not present\n");
				goto inc_net_access_run_fail;				
			}
	 
			item->next = res->items;
			res->items = item;
			(res->num_items)++;
			break;
		}
		item = NULL;
	}

	mod->result = res;

	/* If module finds something that would be considered a fail 
	 * on the policy return 1 here */
	if (res->num_items > 0)
		return 1;

#endif
	return 0;

#if 0
inc_net_access_run_fail:
	if (res->num_items > 0) {
		sechk_item_free(item);
		sechk_result_free(res);
	}
	return -1;
#endif
}

/* The free function frees the private data of a module */
void inc_net_access_data_free(void *data)
{
#if 0
	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	free(mod->data);
	mod->data = NULL;
#endif
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a renode section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief) */
int inc_net_access_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
#if 0
	inc_net_access_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *tmp_proof = NULL;
	int i = 0, type_idx = 0;
	char *type_str = NULL;
	bool_t print_header = FALSE;

	if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}
	
	datum = (inc_net_access_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i network domains with insufficient permissions.\n", mod->result->num_items);
	}

	/* Print current permissions then the permissions that are missing */
	if (outformat & SECHK_OUT_PROOF) {  
		item = mod->result->items;
		for (i = 0; i < mod->result->num_items; i++) {
			type_idx = item->item_id;
			type_str = policy->types[type_idx].name;			
			printf("\n%s\n", type_str);
			
			print_header = FALSE;
                       	/* Print possessed capabilities first */
			for (tmp_proof = item->proof; tmp_proof; tmp_proof = tmp_proof->next) {
				if (tmp_proof->type == inc_net_access_HAVE_PERMS) {
					if (!print_header) {
						printf("Current Permissions:\n");
						print_header = TRUE;
					}
					printf("%s", tmp_proof->text);
				}
			}
			
			/* Print needed capabilities */
			print_header = FALSE;
			for (tmp_proof = item->proof; tmp_proof; tmp_proof = tmp_proof->next) {
				if (tmp_proof->type == inc_net_access_NEEDED_PERMS) {
					if (!print_header) {
						printf("Missing Permissions:\n");
						print_header = TRUE;
					}
					printf("%s", tmp_proof->text);
				}
			}
			item = item->next;
		}
		printf("\n");
	}

	i = 0;
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			type_idx = item->item_id;
			type_str = policy->types[type_idx].name;
			printf("%s%s", type_str, (i&&item->next) ? ", " : "\n");
		}
		printf("\n");
	}

#endif
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *inc_net_access_get_result(sechk_module_t *mod) 
{
#if 0
	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return NULL;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
#endif
	return NULL;
}


inc_net_access_data_t *inc_net_access_data_new(void)
{
#if 0
	inc_net_access_data_t *datum = NULL;

	datum = (inc_net_access_data_t*)calloc(1,sizeof(inc_net_access_data_t));

	return datum;
#endif
	return NULL;
}

#if 0
/* This function checks a type for sufficient network access permissions.
 * If all checks succees, inc_net_access_SUCCESS is returned.
 * If a permission is missing, inc_net_access_FAIL is returned and item is created.
 * If an error occurs during any of the checks, inc_net_access_ERR is returned. */
static int check_perms(const int type_idx, apol_policy_t *policy, sechk_item_t **item, inc_net_access_data_t *net_state)
{
	/* inc_net_access_data_t net_state; */
	sechk_proof_t *proof = NULL;
	bool_t failed = FALSE;

	init_net_state(net_state);

	/* determine the state of this type's network access permissions */
	check_assoc_perms(type_idx, policy, net_state);
	check_socket_perms(type_idx, policy, net_state);
	check_netif_perms(type_idx, policy, net_state);
	check_port_perms(type_idx, policy, net_state);
	check_node_perms(type_idx, policy, net_state);

	/* determine if this type's state is valid: 
	 *  if validate_net_state() returns inc_net_access_SUCCESS: state is valid
         *  if validate_net_state() returns inc_net_access_FAIL: invalid state; proof created 
	 *  if validate_net_state() returns inc_net_access_ERR: an error has occurred */
	switch (validate_net_state(type_idx, net_state, &proof, policy)) {
	case inc_net_access_SUCCESS:
		break;
	case inc_net_access_ERR:
		return inc_net_access_ERR;
		break;
	case inc_net_access_FAIL:
		if (!(*item)) {
                        (*item) = sechk_item_new();
                        if (!(*item)){
                                fprintf(stderr, "Error: out of memory\n");
                                return inc_net_access_ERR;
                        }
                        (*item)->item_id = type_idx;
                        (*item)->test_result = 1;
                }

                /* sanity check: if validate_net_state fails, proof should be allocated */
                if (!proof) {
                        fprintf(stderr, "Error: unable to create proof element\n");
                        return inc_net_access_ERR;
                }

		(*item)->proof = proof;
		failed = TRUE;
		break;
	default:
		fprintf(stderr, "Error: illegal case reached\n");
		return inc_net_access_ERR;
	}
	
	/* if tests have failed, construct proof of permissions this domain already has */	
	if (failed) {
                proof = NULL;
                build_have_perms_proof(type_idx, &proof, policy, &(net_state->idx_cache));
                if (!proof) {
                        fprintf(stderr, "Error: unable to create proof element\n");
                        return inc_net_access_ERR;
                }
		proof->next = (*item)->proof;
		(*item)->proof = proof;
	}
	
		
	/* sufficient network permissions exist for this type */
	return (failed ? inc_net_access_FAIL : inc_net_access_SUCCESS);
	return 0;
}

static bool_t check_type_perms(const int src_idx, const int dst_idx, const int obj_idx, const int perm_idx, apol_policy_t *policy)
{
	avh_key_t key;
        avh_node_t *node = NULL, *tmp_node = NULL;
	int retv;

	key.src = src_idx;
	key.tgt = dst_idx;
	key.cls = obj_idx;
	key.rule_type = RULE_TE_ALLOW;
	node = avh_find_first_node(&(policy->avh), &key);
	/* If node is found, perms exist */
	if (!node) 
		return FALSE;

	for (tmp_node = avh_find_first_node(&(policy->avh), &key); tmp_node; tmp_node = avh_find_next_node(tmp_node)) {
		retv = find_int_in_array(perm_idx, tmp_node->data, tmp_node->num_data);
		/* required permission found */
		if (retv > -1)
			return TRUE;
	}
	
	return FALSE;
}

static void check_assoc_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state)
{
	int i, src_idx, obj_idx, perm_idx;

	/* Testing: - assoc_type: assoc { recvfrom } */
	src_idx = type_idx;
	obj_idx = net_state->idx_cache.ASSOC_OBJ;
	perm_idx = net_state->idx_cache.RECVFROM_PERM;
	for (i = 0; i < assoc_types_list_sz; i++) {		
		if (check_type_perms(src_idx, assoc_types_list[i], obj_idx, perm_idx, policy)) 
			net_state->ANY_ASSOC_RECVFROM = TRUE;				
	}

	/* Testing: - assoc_type: assoc { sendto } */
	perm_idx = net_state->idx_cache.SENDTO_PERM;
	for (i = 0; i < assoc_types_list_sz; i++) {
		if (check_type_perms(src_idx, assoc_types_list[i], obj_idx, perm_idx, policy)) 
			net_state->ANY_ASSOC_SENDTO = TRUE;   
	}
}

static void check_socket_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state)
{
	int src_idx, dst_idx, obj_idx, perm_idx;

	src_idx = type_idx;
	dst_idx = src_idx;

	/* Testing: - self: tcp_socket{create} */
	obj_idx = net_state->idx_cache.TCP_SOCKET_OBJ;
        if (obj_idx < 0) {
                fprintf(stderr, "Error: unable to get object class index\n");
                return;
        }

	perm_idx = net_state->idx_cache.CREATE_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        if (check_type_perms(src_idx, dst_idx, obj_idx, perm_idx, policy))
                net_state->SELF_TCPSOCK_CREATE = TRUE;

	/* Testing: - self: tcp_socket{read} */
	perm_idx = net_state->idx_cache.READ_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        if (check_type_perms(src_idx, dst_idx, obj_idx, perm_idx, policy))
                net_state->SELF_TCPSOCK_READ = TRUE;

	/* Testing: - self: tcp_socket{write} */
	perm_idx = net_state->idx_cache.WRITE_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        if (check_type_perms(src_idx, dst_idx, obj_idx, perm_idx, policy))
                net_state->SELF_TCPSOCK_WRITE = TRUE;

	/* Testing: - self: udp_socket{create} */
	obj_idx = net_state->idx_cache.UDP_SOCKET_OBJ;
        if (obj_idx < 0) {
                fprintf(stderr, "Error: unable to get object class index\n");
                return;
        }
	perm_idx = net_state->idx_cache.CREATE_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        if (check_type_perms(src_idx, dst_idx, obj_idx, perm_idx, policy))
                net_state->SELF_UDPSOCK_CREATE = TRUE;

	/* Testing: - self: udp_socket{read} */
	perm_idx = net_state->idx_cache.READ_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        if (check_type_perms(src_idx, dst_idx, obj_idx, perm_idx, policy))
                net_state->SELF_UDPSOCK_READ = TRUE;

	/* Testing: - self: udp_socket{write} */
	perm_idx = net_state->idx_cache.WRITE_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        if (check_type_perms(src_idx, dst_idx, obj_idx, perm_idx, policy))
                net_state->SELF_UDPSOCK_WRITE = TRUE;
}

static void check_netif_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state)
{
        int src_idx, obj_idx, perm_idx, i;

	src_idx = type_idx;

	/* Testing: - netif_type: netif{tcp_recv} */
	obj_idx = net_state->idx_cache.NETIF_OBJ;
        if (obj_idx < 0) {
                fprintf(stderr, "Error: unable to get object class index\n");
                return;
        }
       
	perm_idx = net_state->idx_cache.TCP_RECV_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < netif_types_list_sz; i++) {
                if (check_type_perms(src_idx, netif_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->ANY_NETIF_TCPRECV = TRUE;
			break;
		}
        }

	/* Testing: - netif_type: netif{tcp_send} */
	perm_idx = net_state->idx_cache.TCP_SEND_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < netif_types_list_sz; i++) {
                if (check_type_perms(src_idx, netif_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->ANY_NETIF_TCPSEND = TRUE;
			break;
		}
        }

        /* Testing: - netif_type: netif{udp_recv} */
	perm_idx = net_state->idx_cache.UDP_RECV_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < netif_types_list_sz; i++) {
                if (check_type_perms(src_idx, netif_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->ANY_NETIF_UDPRECV = TRUE;
			break;
		}
        }

        /* Testing: - netif_type: netif{udp_send} */
	perm_idx = net_state->idx_cache.UDP_SEND_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < netif_types_list_sz; i++) {
                if (check_type_perms(src_idx, netif_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->ANY_NETIF_UDPSEND = TRUE;
			break;
		}
        }
}

static void check_port_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state)
{
        int src_idx, obj_idx, perm_idx, i;

	src_idx = type_idx;
	
	/* Testing: - port_type: tcp_socket{recv_msg} */
	obj_idx = net_state->idx_cache.TCP_SOCKET_OBJ;
        if (obj_idx < 0) {
                fprintf(stderr, "Error: unable to get object class index\n");
                return;
        }

	perm_idx = net_state->idx_cache.RECV_MSG_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < port_types_list_sz; i++) {
                if (check_type_perms(src_idx, port_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->PORT_TCPSOCK_RECVMSG = TRUE;
			break;
                }
        }

	/* Testing: - port_type: tcp_socket{send_msg} */
	perm_idx = net_state->idx_cache.SEND_MSG_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < port_types_list_sz; i++) {
                if (check_type_perms(src_idx, port_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->PORT_TCPSOCK_SENDMSG = TRUE;
			break;
                }
        }

	/* Testing: - port_type: udp_socket{recv_msg} */
	obj_idx = net_state->idx_cache.UDP_SOCKET_OBJ;
        if (obj_idx < 0) {
                fprintf(stderr, "Error: unable to get object class index\n");
                return;
        }

	perm_idx = net_state->idx_cache.RECV_MSG_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < port_types_list_sz; i++) {
                if (check_type_perms(src_idx, port_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->PORT_UDPSOCK_RECVMSG = TRUE;
			break;
                }
        }

	/* Testing: - port_type: udp_socket{send_msg} */
	perm_idx = net_state->idx_cache.SEND_MSG_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < port_types_list_sz; i++) {
                if (check_type_perms(src_idx, port_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->PORT_UDPSOCK_SENDMSG = TRUE;
			break;
                }
        }
}

static void check_node_perms(const int type_idx, apol_policy_t *policy, inc_net_access_data_t *net_state)
{
        int src_idx, obj_idx, perm_idx, i;

        src_idx = type_idx;

	/* Testing: - node_type: node{tcp_recv} */
       	obj_idx = net_state->idx_cache.NODE_OBJ;
        if (obj_idx < 0) {
                fprintf(stderr, "Error: unable to get object class index\n");
                return;
        }
       
	perm_idx = net_state->idx_cache.TCP_RECV_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < node_types_list_sz; i++) {
                if (check_type_perms(src_idx, node_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->ANY_NODE_TCPRECV = TRUE;
                        break;
                }
        }

	/* Testing: - node_type: node{tcp_send} */
	perm_idx = net_state->idx_cache.TCP_SEND_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < node_types_list_sz; i++) {
                if (check_type_perms(src_idx, node_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->ANY_NODE_TCPSEND = TRUE;
                        break;
                }
        }

	/* Testing: - node_type: node{udp_recv} */
	perm_idx = net_state->idx_cache.UDP_RECV_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < node_types_list_sz; i++) {
                if (check_type_perms(src_idx, node_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->ANY_NODE_UDPRECV = TRUE;
                        break;
                }
        }

	/* Testing: - node_type: node{udp_send} */
	perm_idx = net_state->idx_cache.UDP_SEND_PERM;
        if (perm_idx < 0) {
                fprintf(stderr, "Error: unable to get permission index\n");
                return;
        }
        for (i = 0; i < node_types_list_sz; i++) {
                if (check_type_perms(src_idx, node_types_list[i], obj_idx, perm_idx, policy)) {
                        net_state->ANY_NODE_UDPSEND = TRUE;
                        break;
                }
        }
}

/* The following function determines whether the net_state_t
 * object is in a valid state. Valid states are defined as:
 *   1) self create permissions on either tcp_socket OR udp_socket objects */
static int validate_net_state(const int type_idx, inc_net_access_data_t *ns, sechk_proof_t **proof, apol_policy_t *policy)
{
	char *proof_str = NULL;
	sechk_proof_t *tmp_proof = NULL;
	bool_t socket_failed = FALSE, assoc_failed = FALSE, netif_failed = FALSE, port_failed = FALSE, 
		node_failed = FALSE, failed = FALSE;
	bool_t skip = FALSE;    /* Used to skip rest of tests if no access is available */
	int proof_str_sz = 0;

	/* socket permissions */
	if (uses_tcp(type_idx, &(ns->idx_cache), policy) && !ns->SELF_TCPSOCK_CREATE) {		
		tmp_proof = sechk_proof_new();
		if (!tmp_proof) {
			fprintf(stderr, "Error: out of memory\n");
			return inc_net_access_ERR;
		}
		tmp_proof->idx = type_idx;
		tmp_proof->type = inc_net_access_NEEDED_PERMS;
		proof_str = build_proof_str(policy->types[type_idx].name, policy->types[type_idx].name,
					    "tcp_socket", "{ create }");
		if (!proof_str) {
			fprintf(stderr, "Error: unable to build proof\n");
			return inc_net_access_ERR;
		}
		tmp_proof->text = proof_str;

		tmp_proof->next = (*proof);
		(*proof) = tmp_proof;
		socket_failed = TRUE;
		skip = TRUE;
	}
	if (uses_udp(type_idx, &(ns->idx_cache), policy) && !ns->SELF_UDPSOCK_CREATE) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
                
                proof_str = build_proof_str(policy->types[type_idx].name, policy->types[type_idx].name,
                                            "udp_socket", "{ create }");
                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;

                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
                socket_failed = TRUE;
                skip = TRUE;
        }

	/* need both read/write on tcp_socket */
	if (uses_tcp(type_idx, &(ns->idx_cache), policy) && !(ns->SELF_TCPSOCK_READ && ns->SELF_TCPSOCK_WRITE))
	{
		tmp_proof = sechk_proof_new();
		if (!tmp_proof) {
			fprintf(stderr, "Error: out of memory\n");
			return inc_net_access_ERR;
		}
		tmp_proof->idx = type_idx;
		tmp_proof->type = inc_net_access_NEEDED_PERMS;
		if (!ns->SELF_TCPSOCK_READ && !ns->SELF_TCPSOCK_WRITE) {
			proof_str = build_proof_str(policy->types[type_idx].name, policy->types[type_idx].name,
                                                    "tcp_socket", "{ read write }");
		} else if (!ns->SELF_TCPSOCK_READ) {
			proof_str = build_proof_str(policy->types[type_idx].name, policy->types[type_idx].name,
						    "tcp_socket", "{ read }");
		} else if (!ns->SELF_TCPSOCK_WRITE) {
			proof_str = build_proof_str(policy->types[type_idx].name, policy->types[type_idx].name,
                                                    "tcp_socket", "{ write }");
		}
		if (!proof_str) {
			fprintf(stderr, "Error: unable to build proof\n");
			return inc_net_access_ERR;
		}
		
		tmp_proof->text = proof_str;
		tmp_proof->next = (*proof);
		(*proof) = tmp_proof;
		socket_failed = TRUE;
	}
        if (uses_udp(type_idx, &(ns->idx_cache), policy) && (!ns->SELF_UDPSOCK_READ && !ns->SELF_UDPSOCK_WRITE))
        {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
                proof_str = build_proof_str(policy->types[type_idx].name, policy->types[type_idx].name,
                                            "udp_socket", "{ read write }");
		if (!proof_str) {
			fprintf(stderr, "Error: unable to build proof\n");
			return inc_net_access_ERR;
		}
		tmp_proof->text = proof_str;
		tmp_proof->next = (*proof);
		(*proof) = tmp_proof;
		socket_failed = TRUE;
        }    

	/* association permissions */
	if (uses_tcp(type_idx, &(ns->idx_cache), policy) && 
	    (!ns->ANY_ASSOC_RECVFROM || !ns->ANY_ASSOC_SENDTO)) {
		tmp_proof = sechk_proof_new();
		if (!tmp_proof) {
			fprintf(stderr, "Error: out of memory\n");
			return inc_net_access_ERR;
		}
		tmp_proof->idx = type_idx;
		tmp_proof->type = inc_net_access_NEEDED_PERMS;

		if (!ns->ANY_ASSOC_RECVFROM && !ns->ANY_ASSOC_SENDTO) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<association type>", 
						    "association", "{ recvfrom sendto }");
		} else if (!ns->ANY_ASSOC_RECVFROM) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<association type>",
						    "association", "{ recvfrom }");
		} else {
			proof_str = build_proof_str(policy->types[type_idx].name, "<association type>",
						    "association", "{ sendto }");
		}

		if (!proof_str) {
			fprintf(stderr, "Error: unable to build proof\n");
			return inc_net_access_ERR;
		}
		tmp_proof->text = proof_str;
		tmp_proof->next = *proof;
		*proof = tmp_proof;
		assoc_failed = TRUE;
	}	
	skip = FALSE;
	if (uses_udp(type_idx, &(ns->idx_cache), policy) && (!ns->ANY_ASSOC_RECVFROM && !ns->ANY_ASSOC_SENDTO)) {
		tmp_proof = sechk_proof_new();
		if (!tmp_proof) {
			fprintf(stderr, "Error: out of memory\n");
			return inc_net_access_ERR;
		}
		tmp_proof->idx = type_idx;
		tmp_proof->type = inc_net_access_NEEDED_PERMS;
		tmp_proof->text = build_proof_str(policy->types[type_idx].name, "<association type>", 
						  "association", "{ sendto recvfrom }");
		tmp_proof->next = *proof;
		*proof = tmp_proof;
		skip = TRUE;
		assoc_failed = TRUE;
	}
	if (!skip && uses_udp(type_idx, &(ns->idx_cache), policy) && ns->SELF_UDPSOCK_READ && !ns->ANY_ASSOC_RECVFROM) {
		tmp_proof = sechk_proof_new();
		if (!tmp_proof) {
			fprintf(stderr, "Error: out of memory\n");
			return inc_net_access_ERR;
		}
		tmp_proof->idx = type_idx;
		tmp_proof->type = inc_net_access_NEEDED_PERMS;
		tmp_proof->text = build_proof_str(policy->types[type_idx].name, "<association type>", 
						  "association", "{ recvfrom }");
		tmp_proof->next = *proof;
		*proof = tmp_proof;
		assoc_failed = TRUE;
	}
	if (!skip && uses_udp(type_idx, &(ns->idx_cache), policy) && ns->SELF_UDPSOCK_WRITE && !ns->ANY_ASSOC_SENDTO) {
		tmp_proof = sechk_proof_new();
		if (!tmp_proof) {
			fprintf(stderr, "Error: out of memory\n");
			return inc_net_access_ERR;
		}
		tmp_proof->idx = type_idx;
		tmp_proof->type = inc_net_access_NEEDED_PERMS;
		tmp_proof->text = build_proof_str(policy->types[type_idx].name, "<association type>", 
						  "association", "{ sendto }");
		tmp_proof->next = *proof;
		*proof = tmp_proof;
		assoc_failed = TRUE;
	}

	proof_str = NULL;
	proof_str_sz = 0;
	skip = FALSE;
	/* netif permissions */
	if (!ns->ANY_NETIF_TCPRECV && !ns->ANY_NETIF_TCPSEND && !ns->ANY_NETIF_UDPRECV && !ns->ANY_NETIF_UDPSEND) {
		tmp_proof = sechk_proof_new();
		if (!tmp_proof) {
			fprintf(stderr, "Error: out of memory\n");
			return inc_net_access_ERR;
		}
		tmp_proof->idx = type_idx;
		tmp_proof->type = inc_net_access_NEEDED_PERMS;

		if (uses_tcp(type_idx, &(ns->idx_cache), policy)) {
			append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ tcp_recv tcp_send }"));
		}
		if(uses_udp(type_idx, &(ns->idx_cache), policy)) {
			if ((ns->SELF_UDPSOCK_READ && ns->SELF_UDPSOCK_WRITE) || (!ns->SELF_UDPSOCK_READ && !ns->SELF_UDPSOCK_WRITE))
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ udp_recv udp_send }"));
			else if (ns->SELF_UDPSOCK_READ)
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ udp_recv }"));
			else if (ns->SELF_UDPSOCK_WRITE)
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ udp_send }"));
		}

		if (!proof_str) {
			fprintf(stderr, "Error: unable to build proof\n");
			return inc_net_access_ERR;
		}
		tmp_proof->text = proof_str;
		tmp_proof->next = (*proof);
		(*proof) = tmp_proof;
		netif_failed = TRUE;
		skip = TRUE;
	}
	
	if (uses_tcp(type_idx, &(ns->idx_cache), policy) && !(ns->ANY_NETIF_TCPRECV && ns->ANY_NETIF_TCPSEND) && !skip) {
		tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
		if (!ns->ANY_NETIF_TCPRECV && !ns->ANY_NETIF_TCPSEND) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ tcp_recv tcp_send }");
		} else if (!ns->ANY_NETIF_TCPRECV) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ tcp_recv }");
		} else if (!ns->ANY_NETIF_TCPSEND) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ tcp_send }");
		}

                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
                netif_failed = TRUE;
	}

	if (uses_udp(type_idx, &(ns->idx_cache), policy) && ns->SELF_UDPSOCK_READ && !ns->ANY_NETIF_UDPRECV && !skip) {
		tmp_proof = sechk_proof_new();
		if (!tmp_proof) {
			fprintf(stderr, "Error: out of memory\n");
			return inc_net_access_ERR;
		}
		tmp_proof->idx = type_idx;
		tmp_proof->type = inc_net_access_NEEDED_PERMS;
		proof_str = build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ udp_recv }");
		if (!proof_str) {
			fprintf(stderr, "Error: unable to build proof\n");
			return inc_net_access_ERR;
		}
		tmp_proof->text = proof_str;
		tmp_proof->next = (*proof);
		(*proof) = tmp_proof;
		netif_failed = TRUE;
	}
	if (uses_udp(type_idx, &(ns->idx_cache), policy) && ns->SELF_UDPSOCK_WRITE && !ns->ANY_NETIF_UDPSEND && !skip) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
                proof_str = build_proof_str(policy->types[type_idx].name, "<netif type>", "netif", "{ udp_send }");
                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
                netif_failed = TRUE;
        }
	
	proof_str = NULL;
	proof_str_sz = 0;
	skip = FALSE;
	/* port permissions */
	if (!ns->PORT_TCPSOCK_RECVMSG && !ns->PORT_TCPSOCK_SENDMSG && !ns->PORT_UDPSOCK_RECVMSG && !ns->PORT_UDPSOCK_SENDMSG) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;

		if (uses_tcp(type_idx, &(ns->idx_cache), policy)) {
			/* okay to allocate space for proof_str here */
			append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<port type>", "tcp_socket", "{ recv_msg send_msg }"));
		}
		if (uses_udp(type_idx, &(ns->idx_cache), policy)) {
			if ((ns->SELF_UDPSOCK_READ && ns->SELF_UDPSOCK_WRITE) || (!ns->SELF_UDPSOCK_READ && !ns->SELF_UDPSOCK_WRITE))
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<port type>", "udp_socket", "{ recv_msg send_msg }"));
			else if (ns->SELF_UDPSOCK_READ) 
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<port type>", "udp_socket", "{ recv_msg }"));
			else if (ns->SELF_UDPSOCK_WRITE)
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<port type>", "udp_socket", "{ send_msg }"));
		}
         
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
                port_failed = TRUE;
		skip = TRUE;
        }
	if (uses_tcp(type_idx, &(ns->idx_cache), policy) && !(ns->PORT_TCPSOCK_RECVMSG && ns->PORT_TCPSOCK_SENDMSG) && !skip) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
		if (!ns->PORT_TCPSOCK_RECVMSG && !ns->PORT_TCPSOCK_SENDMSG) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<port type>", "tcp_socket", "{ recv_msg send_msg }");
		} else if (!ns->PORT_TCPSOCK_RECVMSG) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<port type>", "tcp_socket", "{ recv_msg }");
		} else if (!ns->PORT_TCPSOCK_SENDMSG) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<port type>", "tcp_socket", "{ send_msg }");
		}

                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
		port_failed = TRUE;
        } 
 
	if (uses_udp(type_idx, &(ns->idx_cache), policy) && ns->ANY_NETIF_UDPRECV && !ns->PORT_UDPSOCK_RECVMSG && !skip) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
                proof_str = build_proof_str(policy->types[type_idx].name, "<port type>", "udp_socket", "{ recv_msg }");
                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
		port_failed = TRUE;
        }
	if (uses_udp(type_idx, &(ns->idx_cache), policy) && ns->ANY_NETIF_UDPSEND && !ns->PORT_UDPSOCK_SENDMSG && !skip) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
                proof_str = build_proof_str(policy->types[type_idx].name, "<port type>", "udp_socket", "{ send_msg }");
                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
        }

	proof_str = NULL;
	proof_str_sz = 0;
	skip = FALSE;
	/* node permissions */
	if (!ns->ANY_NODE_TCPRECV && !ns->ANY_NODE_TCPSEND && !ns->ANY_NODE_UDPRECV && !ns->ANY_NODE_UDPSEND) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
		
		if (uses_tcp(type_idx, &(ns->idx_cache), policy)) {
			append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<node type>", "node", "{ tcp_recv tcp_send }"));
		} 
		if (uses_udp(type_idx, &(ns->idx_cache), policy)) {
			if ((ns->SELF_UDPSOCK_READ && ns->SELF_UDPSOCK_WRITE) || (!ns->SELF_UDPSOCK_READ && !ns->SELF_UDPSOCK_WRITE))
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<node type>", "node", "{ udp_recv udp_send }"));
			else if (ns->SELF_UDPSOCK_READ)
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<node type>", "node", "{ udp_recv }"));
			else if (ns->SELF_UDPSOCK_WRITE)
				append_str(&proof_str, &proof_str_sz, build_proof_str(policy->types[type_idx].name, "<node type>", "node", "{ udp_send }"));
		}

		if (!proof_str) {
			fprintf(stderr, "UNABLE TO BUILD PROOF\n");
		}
	
		if (proof_str) {
			tmp_proof->text = proof_str;
			tmp_proof->next = (*proof);
			(*proof) = tmp_proof;
			node_failed = TRUE;
			skip = TRUE;
		}
        }
	if (uses_tcp(type_idx, &(ns->idx_cache), policy) && !(ns->ANY_NODE_TCPRECV && ns->ANY_NODE_TCPSEND) && !skip) {
		tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;		
		if (!ns->ANY_NODE_TCPRECV && !ns->ANY_NODE_TCPSEND) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<node_type>", "node", "{ tcp_recv tcp_send }");
		} else if (!ns->ANY_NODE_TCPRECV) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<node_type>", "node", "{ tcp_recv }");
		} else if (!ns->ANY_NODE_TCPSEND) {
			proof_str = build_proof_str(policy->types[type_idx].name, "<node_type>", "node", "{ tcp_send }");
		}

                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
                node_failed = TRUE;
	}

	if (ns->PORT_UDPSOCK_RECVMSG && !ns->ANY_NODE_UDPRECV && !skip) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
                proof_str = build_proof_str(policy->types[type_idx].name, "<node_type>", "node", "{ udp_recv }");
                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
                node_failed = TRUE;
        }
	if (ns->PORT_UDPSOCK_SENDMSG && !ns->ANY_NODE_UDPSEND && !skip) {
                tmp_proof = sechk_proof_new();
                if (!tmp_proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->idx = type_idx;
                tmp_proof->type = inc_net_access_NEEDED_PERMS;
                proof_str = build_proof_str(policy->types[type_idx].name, "<node_type>", "node", "{ udp_send }");
                if (!proof_str) {
                        fprintf(stderr, "Error: unable to build proof\n");
                        return inc_net_access_ERR;
                }
                tmp_proof->text = proof_str;
                tmp_proof->next = (*proof);
                (*proof) = tmp_proof;
                node_failed = TRUE;
        }

	failed = (socket_failed || assoc_failed || netif_failed || port_failed || node_failed);
	return (failed ? inc_net_access_FAIL : inc_net_access_SUCCESS);
}

static char *build_proof_str(char *src_type, char *dst_type, char *obj_class, char *perms)
{
	char *proof_str = NULL;
	int proof_str_sz = 0;

	if (append_str(&proof_str, &proof_str_sz, "\t") != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	if (append_str(&proof_str, &proof_str_sz, src_type) != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	if (append_str(&proof_str, &proof_str_sz, " ") != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	if (append_str(&proof_str, &proof_str_sz, dst_type) != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	if (append_str(&proof_str, &proof_str_sz, ": ") != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	if (append_str(&proof_str, &proof_str_sz, obj_class) != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	if (append_str(&proof_str, &proof_str_sz, " ") != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	if (append_str(&proof_str, &proof_str_sz, perms) != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	
	if (append_str(&proof_str, &proof_str_sz, "\n") != 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	
	return proof_str;
	return NULL;
}

static int build_have_perms_proof(const int type_idx, sechk_proof_t **proof, apol_policy_t *policy, idx_cache_t *idx_cache) 
{
	int i, num_nodes, proof_str_sz = 0, tmp_proof_str_sz = 0, used_rules_sz = 0;
	char *proof_str = NULL, *tmp_proof_str = NULL;
	avh_idx_t *hash_idx = NULL;
	avh_rule_t *hash_rule = NULL;
	sechk_proof_t *tmp_proof = NULL;
	int net_objs[5] = {idx_cache->TCP_SOCKET_OBJ,
			   idx_cache->UDP_SOCKET_OBJ,
			   idx_cache->NETIF_OBJ,
			   idx_cache->NODE_OBJ,
	                   idx_cache->ASSOC_OBJ};
	int *used_rules = NULL;

	/* find all rules with net_dom as subject */
	hash_idx = avh_src_type_idx_find(&(policy->avh), type_idx);
	if (!hash_idx)
		num_nodes = 0;
	else
		num_nodes = hash_idx->num_nodes;

	tmp_proof = sechk_proof_new();
	if (!tmp_proof) {
		fprintf(stderr, "Error: out of memory\n");
		return inc_net_access_ERR;
	}

	/* include only those rules with object in net_objs */
	for (i = 0; i < num_nodes; i++) {
		for (hash_rule = hash_idx->nodes[i]->rules; hash_rule; hash_rule = hash_rule->next) {
			if (find_int_in_array(hash_rule->rule, used_rules, used_rules_sz) == -1) {
				tmp_proof_str = NULL;
				tmp_proof_str_sz = 0;
				switch (hash_idx->nodes[i]->key.rule_type) {
				case RULE_TE_ALLOW:
					if (find_int_in_array(hash_idx->nodes[i]->key.cls, net_objs, 5) != -1) {				 
						tmp_proof->idx = type_idx;
						tmp_proof->type = inc_net_access_HAVE_PERMS;
						append_str(&tmp_proof_str, &tmp_proof_str_sz, "\t");
						append_str(&tmp_proof_str, &tmp_proof_str_sz, re_render_av_rule(0, hash_rule->rule, 0, policy));
						append_str(&tmp_proof_str, &tmp_proof_str_sz, "\n");
						append_str(&proof_str, &proof_str_sz, tmp_proof_str);
					}
					if (add_i_to_a(hash_rule->rule, &used_rules_sz, &used_rules) != 0) {
						fprintf(stderr, "Error: out of memory\n");
						return inc_net_access_ERR;
					}
					
					break;
				
				default:
					break;
				}
			}
		}
	}

	if (tmp_proof) {
		tmp_proof->text = proof_str;
		tmp_proof->next = (*proof);
		(*proof) = tmp_proof;
	}

	return inc_net_access_SUCCESS;
	return 0;
}

static void init_net_state(inc_net_access_data_t *ns)
{
	ns->SELF_TCPSOCK_CREATE = FALSE;
	ns->SELF_UDPSOCK_CREATE = FALSE;
	ns->SELF_TCPSOCK_READ = FALSE;
	ns->SELF_TCPSOCK_WRITE = FALSE;
	ns->SELF_UDPSOCK_READ = FALSE;
	ns->SELF_UDPSOCK_WRITE = FALSE;
	ns->ANY_NETIF_TCPRECV = FALSE;
	ns->ANY_NETIF_TCPSEND = FALSE;
	ns->ANY_NETIF_UDPRECV = FALSE;
	ns->ANY_NETIF_UDPSEND = FALSE;
	ns->PORT_TCPSOCK_RECVMSG = FALSE;
	ns->PORT_TCPSOCK_SENDMSG = FALSE;
	ns->PORT_UDPSOCK_RECVMSG = FALSE;
	ns->PORT_UDPSOCK_SENDMSG = FALSE;
	ns->ANY_NODE_TCPRECV = FALSE;
	ns->ANY_NODE_TCPSEND = FALSE;
	ns->ANY_NODE_UDPRECV = FALSE;
	ns->ANY_NODE_UDPSEND = FALSE;
	ns->ANY_ASSOC_RECVFROM = FALSE;
	ns->ANY_ASSOC_SENDTO = FALSE;
}

static void init_idx_cache(idx_cache_t *idx_cache, apol_policy_t *policy)
{
	int idx = 0;

	idx = get_obj_class_idx("tcp_socket", policy);
	if (idx >= 0)
		idx_cache->TCP_SOCKET_OBJ = idx;

	idx = get_obj_class_idx("udp_socket", policy);
	if (idx >= 0)
		idx_cache->UDP_SOCKET_OBJ = idx;

	idx = get_obj_class_idx("netif", policy);
	if (idx >= 0)
		idx_cache->NETIF_OBJ = idx;

        idx = get_obj_class_idx("node", policy);
        if (idx >= 0) 
                idx_cache->NODE_OBJ = idx;

	idx = get_obj_class_idx("association", policy);
	if (idx >= 0)
		idx_cache->ASSOC_OBJ = idx;
	
	idx = get_perm_idx("create", policy);
	if (idx >= 0)
		idx_cache->CREATE_PERM = idx;		

	idx = get_perm_idx("read", policy);
	if (idx >= 0)
		idx_cache->READ_PERM = idx;

	idx = get_perm_idx("write", policy);
        if (idx >= 0)
                idx_cache->WRITE_PERM = idx;

        idx = get_perm_idx("tcp_recv", policy);
        if (idx >= 0)
                idx_cache->TCP_RECV_PERM = idx;

        idx = get_perm_idx("tcp_send", policy);
        if (idx >= 0)
                idx_cache->TCP_SEND_PERM = idx;

	idx = get_perm_idx("udp_recv", policy);
        if (idx >= 0)
                idx_cache->UDP_RECV_PERM = idx;

        idx = get_perm_idx("udp_send", policy);
        if (idx >= 0)
                idx_cache->UDP_SEND_PERM = idx;

        idx = get_perm_idx("recv_msg", policy);
        if (idx >= 0)
                idx_cache->RECV_MSG_PERM = idx;

        idx = get_perm_idx("send_msg", policy);
        if (idx >= 0)
                idx_cache->SEND_MSG_PERM = idx;
	
	idx = get_perm_idx("recvfrom", policy);
	if (idx >= 0)
		idx_cache->RECVFROM_PERM = idx;

	idx = get_perm_idx("sendto", policy);
	if (idx >= 0)
		idx_cache->SENDTO_PERM = idx;
}

/*
 * Checks to see whether a domain uses TCP
 * for network communication. 
 * Returns TRUE if any of the following is true:
 *   - The domain has permissions on a tcp_socket object
 *   - The domain has tcp_recv/tcp_send perms on a netif object
 *   - The domain has tcp_recv/tcp_send perms on a node object
 */
static bool_t uses_tcp(const int domain_idx, idx_cache_t *idx_cache, apol_policy_t *policy)
{
	teq_query_t query;
	teq_results_t res;
	int retv = 0;

	init_teq_query(&query);
	init_teq_results(&res);
	query.use_regex = FALSE;
	query.rule_select |= TEQ_ALLOW;
	query.only_enabled = 0;

	/* this query specifies a src domain and an object class */
	retv = add_i_to_a(idx_cache->TCP_SOCKET_OBJ, &(query.num_classes), &(query.classes));
	if (retv == -1) {
		fprintf(stderr, "Error: out of memory\n");
		return FALSE;
	}

	query.ta1.ta = policy->types[domain_idx].name;
	query.ta1.indirect = TRUE;
	query.ta1.t_or_a = IDX_BOTH;
	query.perms = NULL;
	query.num_perms = 0;
	query.bool_name = NULL;
	
	retv = search_te_rules(&query, &res, policy);
	if (retv == 0) {
		if (res.num_av_access > 0)
			return TRUE;
	        else
			return FALSE;
		
	}
	if (retv == -1) {
		fprintf(stderr, "Error: searching TE rules\n");
		return FALSE;
	}
	
	return FALSE;
}

/*
 * Checks to see whether a domain uses UDP
 * for network communication.
 * Returns TRUE if any of the following is true:
 *   - The domain has permissions on a udp_socket object
 *   - The domain has udp_recv/udp_send perms on a netif object
 *   - The domain has udp_recv/udp_send perms on a node object
 */
static bool_t uses_udp(const int domain_idx, idx_cache_t *idx_cache, apol_policy_t *policy)
{
	teq_query_t query;
	teq_results_t res;
	int retv = 0;

	init_teq_query(&query);
	init_teq_results(&res);
	query.use_regex = FALSE;
	query.rule_select |= TEQ_ALLOW;
	query.only_enabled = 0;

	/* this query specifies a src domain and an object class */
	retv = add_i_to_a(idx_cache->UDP_SOCKET_OBJ, &(query.num_classes), &(query.classes));
	if (retv == -1) {
		fprintf(stderr, "Error: out of memory\n");
		return FALSE;
	}

	query.ta1.ta = policy->types[domain_idx].name;
	query.ta1.indirect = TRUE;
	query.ta1.t_or_a = IDX_BOTH;
	query.perms = NULL;
	query.num_perms = 0;
	query.bool_name = NULL;

	retv = search_te_rules(&query, &res, policy);
	if (retv == 0) {
		if (res.num_av_access > 0)                      
			return TRUE;
		else                       
			return FALSE;		
	}
	if (retv == -1) {
		fprintf(stderr, "Error: searching TE rules\n");
		return FALSE;
	}

	return FALSE;
}
#endif

