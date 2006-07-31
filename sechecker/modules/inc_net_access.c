/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: dwindsor@tresys.com
 *
 */

#include "inc_net_access.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char *const mod_name = "inc_net_access";

/* The register function registers all of a module's functions
 * with the library.  You should not need to edit this function
 * unless you are adding additional functions you need other modules
 * to call. See the note at the bottom of this function to do so. */
int inc_net_access_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "Error: no library\n");
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: module unknown\n");
		return -1;
	}
	mod->parent_lib = lib;
	
	/* assign the descriptions */
	mod->brief_description = "finds network domains with inadequate permissions";
	mod->detailed_description =
"--------------------------------------------------------------------------------\n"
"This module finds all network domains in a policy which do not have the         \n"
"required permissions needed to facilitate network communication. For network\n"
"domains to communicate, the following conditions must be true:\n"
"   1) the domain must have read or receive permissions on a socket of the same\n"
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
	/* assign dependencies */      
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_net_domains")) < 0 ) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_netif_types")) < 0 ) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_port_types")) < 0 ) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_node_types")) < 0 ) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_assoc_types")) < 0 ) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	
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
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
	fn_struct->fn = &inc_net_access_data_free;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file.
 * Add any option processing logic as indicated below. */
int inc_net_access_init(sechk_module_t *mod, apol_policy_t *policy)
{
	inc_net_access_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: Invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: Wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = inc_net_access_data_new();
	if (!datum) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}

	mod->data = datum;
	
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
	inc_net_access_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	sechk_result_t *net_domain_res = NULL, *netif_res = NULL, *port_res = NULL, *node_res = NULL, *assoc_type_res = NULL;
        sechk_get_result_fn_t get_res = NULL;
	sechk_name_value_t *dep = NULL;
	sechk_run_fn_t run_fn = NULL;
	size_t i = 0, j = 0, k = 0, error;
	int buff_sz;
	char *buff = NULL;
	apol_vector_t *net_domain_vector;
	apol_vector_t *netif_vector;
	apol_vector_t *port_vector;
	apol_vector_t *node_vector;
	apol_vector_t *assoc_type_vector;
	apol_avrule_query_t *avrule_query;
	apol_vector_t *avrule_vector;

	if (!mod || !policy) {
		fprintf(stderr, "Error: Invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: Wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (inc_net_access_data_t *)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: Out of memory\n");
		goto inc_net_access_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
        if ( !(res->items = apol_vector_create()) ) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                goto inc_net_access_run_fail;
        }

	/* run dependencies */
	for (i=0;i<apol_vector_get_size(mod->dependencies);i++) {
		dep = apol_vector_get_element(mod->dependencies, i);
		run_fn = sechk_lib_get_module_function(dep->value, SECHK_MOD_FN_RUN, mod->parent_lib);
		run_fn(sechk_lib_get_module(dep->value, mod->parent_lib), policy);
	}
      
	/* get lists */
	/* Net Domains */
	get_res = sechk_lib_get_module_function("find_net_domains", SECHK_MOD_FN_GET_RES, mod->parent_lib);
	if (!get_res) {
                fprintf(stderr, "Error: Unable to get net domains result function\n");
                goto inc_net_access_run_fail;
        }
	net_domain_res = get_res(sechk_lib_get_module("find_net_domains", mod->parent_lib));
	if (!net_domain_res) {
                fprintf(stderr, "Error: Unable to get net domains list\n");
                goto inc_net_access_run_fail;
        }
	net_domain_vector = (apol_vector_t *)net_domain_res->items;

	/* Netif Types */
	get_res = sechk_lib_get_module_function("find_netif_types", SECHK_MOD_FN_GET_RES, mod->parent_lib);
        if (!get_res) {
                fprintf(stderr, "Error: Unable to get netif types result function\n");
                goto inc_net_access_run_fail;
        }
	netif_res = get_res(sechk_lib_get_module("find_netif_types", mod->parent_lib));
	if (!netif_res) {
                fprintf(stderr, "Error: Unable to get netif types list\n");
                goto inc_net_access_run_fail;
        }
	netif_vector = (apol_vector_t *)netif_res->items;

	/* Port Types */
        get_res = sechk_lib_get_module_function("find_port_types", SECHK_MOD_FN_GET_RES, mod->parent_lib);
	if (!get_res) {
                fprintf(stderr, "Error: Unable to get port types result function\n");
                goto inc_net_access_run_fail;
        }
        port_res = get_res(sechk_lib_get_module("find_port_types", mod->parent_lib));
        if (!port_res) {
                fprintf(stderr, "Error: Unable to get port types list\n");
                goto inc_net_access_run_fail;
        }
	port_vector = (apol_vector_t *)port_res->items;

	/* Node Type */
	get_res = sechk_lib_get_module_function("find_node_types", SECHK_MOD_FN_GET_RES, mod->parent_lib);
	if (!get_res) {
                fprintf(stderr, "Error: Unable to get node types result function\n");
                goto inc_net_access_run_fail;
        }
        node_res = get_res(sechk_lib_get_module("find_node_types", mod->parent_lib));
        if (!node_res) {
                fprintf(stderr, "Error: unable to get node types list\n");
                goto inc_net_access_run_fail;
        }
	node_vector = (apol_vector_t *)node_res->items;

	/* Assoc Types */
	get_res = sechk_lib_get_module_function("find_assoc_types", SECHK_MOD_FN_GET_RES, mod->parent_lib);
	if (!get_res) {
                fprintf(stderr, "Error: Unable to get association types result function\n");
                goto inc_net_access_run_fail;
        }
        assoc_type_res = get_res(sechk_lib_get_module("find_assoc_types", mod->parent_lib));
        if (!assoc_type_res) {
                fprintf(stderr, "Error: unable to get association types list\n");
                goto inc_net_access_run_fail;
        }
	assoc_type_vector = (apol_vector_t *)assoc_type_res->items;
	
	/* Create avrule query object */
	avrule_query = apol_avrule_query_create();

	/* for each net domain, check permissions */
	for (i=0; i<apol_vector_get_size(net_domain_vector); i++) {
		sechk_item_t *item;
		qpol_type_t *net_domain = NULL;
		char *net_domain_name = NULL;

		item = apol_vector_get_element(net_domain_vector, i);
		net_domain = item->item;
		qpol_type_get_name(policy->qh, policy->p, net_domain, &net_domain_name);
	
		/* Check netif types */
		for (j=0; j<apol_vector_get_size(netif_vector); j++) {
			sechk_item_t *item;
			qpol_type_t *netif = NULL;
			char *netif_name = NULL;

			item = apol_vector_get_element(netif_vector, j);
			netif = item->item;
			qpol_type_get_name(policy->qh, policy->p, netif, &netif_name);
	
		        avrule_query = apol_avrule_query_create();
			apol_avrule_query_set_source(policy, avrule_query, net_domain_name, 1);
			apol_avrule_query_set_target(policy, avrule_query, netif_name, 1);
			apol_avrule_query_append_class(policy, avrule_query, "netif");
			apol_avrule_query_append_perm(policy, avrule_query, "tcp_send");
			apol_avrule_query_append_perm(policy, avrule_query, "udp_send");
			apol_avrule_query_append_perm(policy, avrule_query, "tcp_recv");
			apol_avrule_query_append_perm(policy, avrule_query, "udp_recv");
			apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
			if ( apol_vector_get_size(avrule_vector) > 0 ) continue;
			else {
				item = NULL;
				proof = sechk_proof_new(NULL);
				buff_sz = 1+strlen(netif_name)+strlen("Domain has no send or receive permissions for netif ");
				buff = (char *)calloc(buff_sz, sizeof(char));
				if (!buff) {
					error = errno;
					ERR(policy, strerror(error));
					goto inc_net_access_run_fail;
				}
				snprintf(buff, buff_sz, "Domain has no send or receive permissions for netif %s\n", netif_name);
				proof->text = strdup(buff);
				if (!proof->text) {
					error = errno;
					ERR(policy, strerror(error));	
				}
				for (k=0;k<apol_vector_get_size(res->items);k++) {
					sechk_item_t *res_item = NULL;
					qpol_type_t *res_type;
					char *res_type_name;

                                        res_item = apol_vector_get_element(res->items, k);
                                        res_type = res_item->item;
                                        qpol_type_get_name(policy->qh, policy->p, res_type, &res_type_name);
                                        if (!strcmp(res_type_name, net_domain_name)) item = res_item;
				}
                                if ( !item) {
                                        item = sechk_item_new(NULL);
                                        if (!item) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                        item->test_result = 1;
                                        item->item = (void *)net_domain;
                                        if ( apol_vector_append(res->items, (void *)item) < 0 ) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                }
                                if ( !item->proof ) {
                                        if ( !(item->proof = apol_vector_create()) ) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                }
                                if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
                                        ERR(policy, "Out of memory");
                                        goto inc_net_access_run_fail;
                                }
                                item = NULL;
			}
			apol_avrule_query_destroy(&avrule_query);
		}

		/* Check port types */
                for (j=0; j<apol_vector_get_size(port_vector); j++) {
			sechk_item_t *item;
                        qpol_type_t *port = NULL;
                        char *port_name = NULL;

                        item = apol_vector_get_element(port_vector, j);
			port = item->item;
                        qpol_type_get_name(policy->qh, policy->p, port, &port_name);

                        avrule_query = apol_avrule_query_create();
                        apol_avrule_query_set_source(policy, avrule_query, net_domain_name, 1);
                        apol_avrule_query_set_target(policy, avrule_query, port_name, 1);
                        apol_avrule_query_append_class(policy, avrule_query, "tcp_socket");
                        apol_avrule_query_append_class(policy, avrule_query, "udp_socket");
                        apol_avrule_query_append_perm(policy, avrule_query, "acceptfrom");
                        apol_avrule_query_append_perm(policy, avrule_query, "recvfrom");
                        apol_avrule_query_append_perm(policy, avrule_query, "send_msg");
                        apol_avrule_query_append_perm(policy, avrule_query, "recv_msg");
                        apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
                        if ( apol_vector_get_size(avrule_vector) > 0 ) continue;
                        else {
                                /* Add to results */
				item = NULL;
				proof = sechk_proof_new(NULL);
				buff_sz = 1+strlen(port_name)+strlen("Domain has no send or receive permissions for port ");
				buff = (char *)calloc(buff_sz, sizeof(char));
				if (!buff) {
					error = errno;
					ERR(policy, strerror(error));
					goto inc_net_access_run_fail;
				}
				snprintf(buff, buff_sz, "Domain has no send or receive permissions for port %s\n", port_name);
				proof->text = strdup(buff);
				if (!proof->text) {
					error = errno;
					ERR(policy, strerror(error));	
				}
				for (k=0;k<apol_vector_get_size(res->items);k++) {
					sechk_item_t *res_item = NULL;
					qpol_type_t *res_type;
					char *res_type_name;

                                        res_item = apol_vector_get_element(res->items, k);
                                        res_type = res_item->item;
                                        qpol_type_get_name(policy->qh, policy->p, res_type, &res_type_name);
                                        if (!strcmp(res_type_name, net_domain_name)) item = res_item;
				}
                                if ( !item) {
                                        item = sechk_item_new(NULL);
                                        if (!item) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                        item->test_result = 1;
                                        item->item = (void *)net_domain;
                                        if ( apol_vector_append(res->items, (void *)item) < 0 ) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                }
                                if ( !item->proof ) {
                                        if ( !(item->proof = apol_vector_create()) ) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                }
                                if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
                                        ERR(policy, "Out of memory");
                                        goto inc_net_access_run_fail;
                                }
                                item = NULL;
                        }
                        apol_avrule_query_destroy(&avrule_query);
                }

                for (j=0; j<apol_vector_get_size(node_vector); j++) {
			sechk_item_t *item;
                        qpol_type_t *node = NULL;
                        char *node_name = NULL;

                        item = apol_vector_get_element(node_vector, j);
			node = item->item;
                        qpol_type_get_name(policy->qh, policy->p, node, &node_name);

                        avrule_query = apol_avrule_query_create();
                        apol_avrule_query_set_source(policy, avrule_query, net_domain_name, 1);
                        apol_avrule_query_set_target(policy, avrule_query, node_name, 1);
                        apol_avrule_query_append_class(policy, avrule_query, "node");
                        apol_avrule_query_append_perm(policy, avrule_query, "tcp_send");
                        apol_avrule_query_append_perm(policy, avrule_query, "udp_send");
                        apol_avrule_query_append_perm(policy, avrule_query, "tcp_recv");
                        apol_avrule_query_append_perm(policy, avrule_query, "udp_recv");
                        apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
                        if ( apol_vector_get_size(avrule_vector) > 0 ) continue;
                        else {
                                /* Add to results */
				item = NULL;
				proof = sechk_proof_new(NULL);
				buff_sz = 1+strlen(node_name)+strlen("Domain has no send or receive permissions for node ");
				buff = (char *)calloc(buff_sz, sizeof(char));
				if (!buff) {
					error = errno;
					ERR(policy, strerror(error));
					goto inc_net_access_run_fail;
				}
				snprintf(buff, buff_sz, "Domain has no send or receive permissions for node %s\n", node_name);
				proof->text = strdup(buff);
				if (!proof->text) {
					error = errno;
					ERR(policy, strerror(error));	
				}
				for (k=0;k<apol_vector_get_size(res->items);k++) {
					sechk_item_t *res_item = NULL;
					qpol_type_t *res_type;
					char *res_type_name;

                                        res_item = apol_vector_get_element(res->items, k);
                                        res_type = res_item->item;
                                        qpol_type_get_name(policy->qh, policy->p, res_type, &res_type_name);
                                        if (!strcmp(res_type_name, net_domain_name)) item = res_item;
				}
                                if ( !item) {
                                        item = sechk_item_new(NULL);
                                        if (!item) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                        item->test_result = 1;
                                        item->item = (void *)net_domain;
                                        if ( apol_vector_append(res->items, (void *)item) < 0 ) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                }
                                if ( !item->proof ) {
                                        if ( !(item->proof = apol_vector_create()) ) {
                                                ERR(policy, "Out of memory");
                                                goto inc_net_access_run_fail;
                                        }
                                }
                                if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
                                        ERR(policy, "Out of memory");
                                        goto inc_net_access_run_fail;
                                }
                                item = NULL;
                        }
                        apol_avrule_query_destroy(&avrule_query);
                }
		item = NULL;
	}

	mod->result = res;

	return 0;

inc_net_access_run_fail:
	sechk_item_free(item);
	return -1;
}

/* The free function frees the private data of a module */
void inc_net_access_data_free(void *data)
{
	free(data);
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
	inc_net_access_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0, j=0, k=0, l=0, num_items;
	qpol_type_t *type;
	char *type_name;

	if (!mod || !policy){
		ERR(policy, "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}
	
	datum = (inc_net_access_data_t*)mod->data;
	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "Module has not been run");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i network domains with insufficient permissions.\n", num_items);
	}

	/* Print current permissions then the permissions that are missing */
	if (outformat & SECHK_OUT_PROOF) {  
                printf("\n");
                for (k=0;k< num_items;k++) {
                        item = apol_vector_get_element(mod->result->items, k);
                        if ( item ) {
                                type = item->item;
                                qpol_type_get_name(policy->qh, policy->p, type, &type_name);
                                printf("%s\n", (char*)type_name);
                                for (l=0; l<apol_vector_get_size(item->proof);l++) {
					/* Change to print possessed elements first - then add needed elements */
                                        proof = apol_vector_get_element(item->proof,l);
                                        if ( proof )
                                                printf("\t%s\n", proof->text);
                                }
                        }
                }
                printf("\n");
	}

	i = 0;
	if (outformat & SECHK_OUT_LIST) {
                printf("\n");
                for (i = 0; i < num_items; i++) {
                        j++;
                        item  = apol_vector_get_element(mod->result->items, i);
                        type = item->item;
                        qpol_type_get_name(policy->qh, policy->p, type, &type_name);
                        j %= 4;
                        printf("%s%s", type_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
                }
                printf("\n");
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *inc_net_access_get_result(sechk_module_t *mod) 
{
	if (!mod) {
		fprintf(stderr, "Error: Invalid parameters\n");
		return NULL;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: Wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}


inc_net_access_data_t *inc_net_access_data_new(void)
{
	inc_net_access_data_t *datum = NULL;

	datum = (inc_net_access_data_t*)calloc(1,sizeof(inc_net_access_data_t));

	return datum;
}

#if 0
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
#endif
