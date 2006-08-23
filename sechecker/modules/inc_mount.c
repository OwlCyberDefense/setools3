/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "inc_mount.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "inc_mount";

/* The register function registers all of a module's functions
 * with the library.  */
int inc_mount_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "no library");
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		return -1;
	}
	mod->parent_lib = lib;
	
	/* assign the descriptions */
	mod->brief_description = "domains with partial mount permissions";
	mod->detailed_description = 
"--------------------------------------------------------------------------------\n"
"This module finds domains that have incomplete mount permissions.  In order for \n"
"a mount operation to be allowed by the policy the follow rules must be present: \n"
"\n"
"   1.) allow somedomain_d sometype_t : filesystem  { mount };\n"
"   2.) allow somedomain_d sometype_t : dir { mounton };\n"
"\n"
"This module finds domains that have only one of the rules listed above.\n";
	mod->opt_description = 
"Module requirements:\n"
"   none\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   none\n";
	mod->severity = SECHK_SEV_MED;
	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_mount_init;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_mount_run;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_FREE);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_mount_data_free;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_mount_print_output;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_GET_RES);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_mount_get_result;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int inc_mount_init(sechk_module_t *mod, apol_policy_t *policy)
{
	inc_mount_data_t *datum = NULL;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	datum = inc_mount_data_new();
	if (!datum) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	mod->data = datum;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. This function allocates the result
 * structure and fills in all relavant item and proof data. */
 
int inc_mount_run(sechk_module_t *mod, apol_policy_t *policy)
{
	inc_mount_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i, j;
	bool_t both = FALSE;
	int buff_sz;
	char *buff = NULL;
	apol_vector_t *mount_vector;
	apol_vector_t *mounton_vector;
	apol_avrule_query_t *mount_avrule_query = NULL;
	apol_avrule_query_t *mounton_avrule_query = NULL;

	if (!mod || !policy) {
                ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
                ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (inc_mount_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
                ERR(policy, "%s", strerror(ENOMEM));
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
                ERR(policy, "%s", strerror(ENOMEM));
		goto inc_mount_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
        if ( !(res->items = apol_vector_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
                goto inc_mount_run_fail;
        }
	
	if (!(mount_avrule_query = apol_avrule_query_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
                goto inc_mount_run_fail;
	}

	if (!(mounton_avrule_query = apol_avrule_query_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
                goto inc_mount_run_fail;
	}

	/* Get avrules for filesystem mount */
	apol_avrule_query_set_rules(policy, mount_avrule_query, QPOL_RULE_ALLOW);
	apol_avrule_query_append_class(policy, mount_avrule_query, "filesystem");
	apol_avrule_query_append_perm(policy, mount_avrule_query, "mount");
	apol_get_avrule_by_query(policy, mount_avrule_query, &mount_vector);
	
	/* Get avrules for dir mounton */
	apol_avrule_query_set_rules(policy, mounton_avrule_query, QPOL_RULE_ALLOW);
	apol_avrule_query_append_class(policy, mounton_avrule_query, "dir");
	apol_avrule_query_append_perm(policy, mounton_avrule_query, "mounton");
	apol_get_avrule_by_query(policy, mounton_avrule_query, &mounton_vector);

	for ( i=0; i<apol_vector_get_size(mount_vector); i++) {
		qpol_avrule_t *mount_rule;
		qpol_type_t *mount_source;
		qpol_type_t *mount_target;
		char *mount_source_name, *mount_target_name;
		
		both = FALSE;
		mount_rule = apol_vector_get_element(mount_vector, i);
		qpol_avrule_get_source_type(policy->qh, policy->p, mount_rule, &mount_source);
		qpol_avrule_get_target_type(policy->qh, policy->p, mount_rule, &mount_target);
		qpol_type_get_name(policy->qh, policy->p, mount_source, &mount_source_name);
		qpol_type_get_name(policy->qh, policy->p, mount_target, &mount_target_name);

		for ( j = 0; j<apol_vector_get_size(mounton_vector); j++) {
			qpol_avrule_t *mounton_rule;
			qpol_type_t *mounton_source;
			qpol_type_t *mounton_target;
			char *mounton_source_name, *mounton_target_name;

			mounton_rule = apol_vector_get_element(mounton_vector, j);
			qpol_avrule_get_source_type(policy->qh, policy->p, mounton_rule, &mounton_source);
			qpol_avrule_get_target_type(policy->qh, policy->p, mounton_rule, &mounton_target);
			qpol_type_get_name(policy->qh, policy->p, mounton_source, &mounton_source_name);
			qpol_type_get_name(policy->qh, policy->p, mounton_target, &mounton_target_name);
			
			/* Check to see if they match */
			if ( !strcmp(mount_source_name, mounton_source_name) && 
			     !strcmp(mount_target_name, mounton_target_name)) both = TRUE;
		}
		if ( !both ) {
			proof = sechk_proof_new(NULL);
			if (!proof) {
		                ERR(policy, "%s", strerror(ENOMEM));
				goto inc_mount_run_fail;
			}
			proof->type = SECHK_ITEM_TYPE;
			buff = NULL;	
			buff_sz = 6 + strlen(apol_avrule_render(policy, mount_rule))+strlen("\tMissing:\n\tallow ")+
					strlen(mount_source_name)+strlen(mount_target_name)+strlen(" : dir mounton;\n");
			buff = (char *)calloc(buff_sz, sizeof(char));
			if ( !buff ) {
		                ERR(policy, "%s", strerror(ENOMEM));
                                goto inc_mount_run_fail;
                        }
			snprintf(buff, buff_sz, "%s\n\tMissing:\n\tallow %s %s : dir mounton;\n",apol_avrule_render(policy, mount_rule),
					mount_source_name, mount_target_name);	
			proof->text = strdup(buff);
			if ( !proof->text ) {
		                ERR(policy, "%s", strerror(ENOMEM));
                                goto inc_mount_run_fail;
			}
			buff = NULL;
	                item = sechk_item_new(NULL);
	                if (!item) {
		                ERR(NULL, "%s", strerror(ENOMEM));
                       		goto inc_mount_run_fail;
                	}
	                item->item = (void *)mount_source;
	                if ( !item->proof ) {
        	                if ( !(item->proof = apol_vector_create()) ) {
			                ERR(policy, "%s", strerror(ENOMEM));
                        	        goto inc_mount_run_fail;
                        	}
                	}
	                if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
		                ERR(policy, "%s", strerror(ENOMEM));
                        	goto inc_mount_run_fail;
	                }
        	        if ( apol_vector_append(res->items, (void*)item) < 0 ) {
		                ERR(policy, "%s", strerror(ENOMEM));
	                        goto inc_mount_run_fail;
        	        }
                	item = NULL;
	                proof = NULL;
		}
	}

	for ( i=0; i<apol_vector_get_size(mounton_vector); i++) {
		qpol_avrule_t *mounton_rule;
		qpol_type_t *mounton_source;
		qpol_type_t *mounton_target;
		char *mounton_source_name, *mounton_target_name;
		
		both = FALSE;
		mounton_rule = apol_vector_get_element(mounton_vector, i);
		qpol_avrule_get_source_type(policy->qh, policy->p, mounton_rule, &mounton_source);
		qpol_avrule_get_target_type(policy->qh, policy->p, mounton_rule, &mounton_target);
		qpol_type_get_name(policy->qh, policy->p, mounton_source, &mounton_source_name);
		qpol_type_get_name(policy->qh, policy->p, mounton_target, &mounton_target_name);

		for ( j = 0; j<apol_vector_get_size(mount_vector); j++) {
			qpol_avrule_t *mount_rule;
			qpol_type_t *mount_source;
			qpol_type_t *mount_target;
			char *mount_source_name, *mount_target_name;

			mount_rule = apol_vector_get_element(mount_vector, j);
			qpol_avrule_get_source_type(policy->qh, policy->p, mount_rule, &mount_source);
			qpol_avrule_get_target_type(policy->qh, policy->p, mount_rule, &mount_target);
			qpol_type_get_name(policy->qh, policy->p, mount_source, &mount_source_name);
			qpol_type_get_name(policy->qh, policy->p, mount_target, &mount_target_name);
			
			/* Check to see if they match */
			if ( !strcmp(mount_source_name, mounton_source_name) && 
			     !strcmp(mount_target_name, mounton_target_name)) both = TRUE;
		}
		if ( !both ) {
			proof = sechk_proof_new(NULL);
			if (!proof) {
		                ERR(policy, "%s", strerror(ENOMEM));
				goto inc_mount_run_fail;
			}
			proof->type = SECHK_ITEM_TYPE;
                        buff = NULL;
                        buff_sz = 6 + strlen(apol_avrule_render(policy,mounton_rule))+strlen("\tMissing:\n\t\tallow ")+strlen(mounton_source_name)+
					strlen(mounton_target_name)+strlen(" : filesystem mount;\n");
                        buff = (char *)calloc(buff_sz, sizeof(char));
                        if ( !buff ) {
		                ERR(policy, "%s", strerror(ENOMEM));
                                goto inc_mount_run_fail;
                        }
                        snprintf(buff, buff_sz, "%s\n\tMissing:\n\t\tallow %s %s : filesystem mount;\n",apol_avrule_render(policy,mounton_rule),
					mounton_source_name, mounton_target_name);
                        proof->text = strdup(buff);
			if ( !proof->text ) {
		                ERR(policy, "%s", strerror(ENOMEM));
                                goto inc_mount_run_fail;
			}
	                item = sechk_item_new(NULL);
	                if (!item) {
		                ERR(policy, "%s", strerror(ENOMEM));
                       		goto inc_mount_run_fail;
                	}
	                item->item = (void *)mounton_source;
	                if ( !item->proof ) {
        	                if ( !(item->proof = apol_vector_create()) ) {
			                ERR(policy, "%s", strerror(ENOMEM));
                        	        goto inc_mount_run_fail;
                        	}
                	}
	                if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
		                ERR(policy, "%s", strerror(ENOMEM));
                        	goto inc_mount_run_fail;
	                }
        	        if ( apol_vector_append(res->items, (void*)item) < 0 ) {
		                ERR(policy, "%s", strerror(ENOMEM));
	                        goto inc_mount_run_fail;
        	        }
                	item = NULL;
	                proof = NULL;
		}
	}

	mod->result = res;

	return 0;

inc_mount_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	return -1;
}

/* The free function frees the private data of a module */
void inc_mount_data_free(void *data)
{
	free(data);
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int inc_mount_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	inc_mount_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0, j, k, l, num_items;
	qpol_type_t *type;
	char *type_name;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	datum = (inc_mount_data_t*)mod->data;
	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
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
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with the severity. 
	 * Each proof element is then displayed in an indented list one per 
	 * line below it. */
	if (outformat & SECHK_OUT_PROOF) {
                printf("\n");
                for (k=0;k< num_items;k++) {
                        item = apol_vector_get_element(mod->result->items, k);
                        if ( item ) {
                                type = item->item;
                                qpol_type_get_name(policy->qh, policy->p, type, &type_name);
                                printf("%s\n", (char*)type_name);
                                for (l=0; l<apol_vector_get_size(item->proof);l++) {
                                        proof = apol_vector_get_element(item->proof,l);
                                        if ( proof )
                                                printf("\t%s\n", proof->text);
                                }
                        }
                }
                printf("\n");
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *inc_mount_get_result(sechk_module_t *mod) 
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

/* The inc_mount_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
inc_mount_data_t *inc_mount_data_new(void)
{
	inc_mount_data_t *datum = NULL;

	datum = (inc_mount_data_t*)calloc(1,sizeof(inc_mount_data_t));

	return datum;
}
