/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "find_domains.h"
#include "render.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char *const mod_name = "find_domains";

int find_domains_register(sechk_lib_t *lib) 
{
		sechk_module_t *mod = NULL;
		sechk_fn_t *fn_struct = NULL;

		if (!lib) {
				fprintf(stderr, "Error: no library\n");
				return -1;
		}


		mod = sechk_lib_get_module(mod_name, lib);
		if (!mod) {
				fprintf(stderr, "Error: module unknown\n");
				return -1;
		}
		mod->parent_lib = lib;

		/* assign descriptions */
		mod->brief_description = "utility module";
		mod->detailed_description = 
				"--------------------------------------------------------------------------------\n"
				"This is a utility module which finds types in a policy that are treated as a    \n"
				"domain.  A type is considered a domain if any of the following is true:\n"
				"\n"
				"   1) it has an attribute associated with domains\n"
				"   2) it is the source of a TE rule for object class other than filesystem\n"
				"   3) it is the default type in a type_transition rule for object class process \n"
				"   4) it is associated with a role other than object_r\n";
		mod->opt_description = 
				"Module requirements:\n"
				"   none\n"
				"Module dependencies:\n"
				"   none\n"
				"Module options:\n"
				"   domain_attributes can be set in a profile\n";
		mod->severity = SECHK_SEV_NONE;
		/* assign requirements */
		apol_vector_append(mod->requirements, sechk_name_value_new("policy_type", "source"));

		/* assign options */
		apol_vector_append(mod->options, sechk_name_value_new("domain_attribute", "domain"));

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
		fn_struct->fn = &find_domains_init;
		apol_vector_append(mod->functions, fn_struct);

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
		fn_struct->fn = &find_domains_run;
		apol_vector_append(mod->functions, fn_struct);

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
		fn_struct->fn = &find_domains_data_free;
		apol_vector_append(mod->functions, fn_struct);

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
		fn_struct->fn = &find_domains_print_output;
		apol_vector_append(mod->functions, fn_struct);

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
		fn_struct->fn = &find_domains_get_result;
		apol_vector_append(mod->functions, fn_struct);

		fn_struct = sechk_fn_new();
		if (!fn_struct) {
				fprintf(stderr, "Error: out of memory\n");
				return -1;
		}
		fn_struct->name = strdup("get_list");
		if (!fn_struct->name) {
				fprintf(stderr, "Error: out of memory\n");
				return -1;
		}
		fn_struct->fn = &find_domains_get_list;
		apol_vector_append(mod->functions, fn_struct);
		return 0;
}

int find_domains_init(sechk_module_t *mod, apol_policy_t *policy) 
{
	sechk_name_value_t *opt = NULL;
	find_domains_data_t *datum = NULL;
	size_t i, j, error;
	qpol_type_t *attr = NULL;
        apol_vector_t *attr_vector = NULL;
        apol_attr_query_t *attr_query = apol_attr_query_create();

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = find_domains_data_new();
	if (!datum) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
		return -1;
	}

	if ( !(datum->domain_attribs = apol_vector_create()) ) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
		return -1;
	}

	mod->data = datum;

	//opt = mod->options;
        for (i = 0; i < apol_vector_get_size(mod->options); i++) {
                opt = apol_vector_get_element(mod->options, i);
                if (!strcmp(opt->name, "domain_attribute")) {
                        apol_attr_query_set_attr(policy, attr_query, opt->value);
                        apol_get_attr_by_query(policy, attr_query, &attr_vector);
                        for (j=0;j<apol_vector_get_size(attr_vector);j++) {
                                char *domain_attrib;
                                attr = apol_vector_get_element(attr_vector, j);
                                qpol_type_get_name(policy->qh, policy->p, attr, &domain_attrib);
                                if ( apol_vector_append( datum->domain_attribs,(void*) domain_attrib ) < 0 ) {
			                error = errno;
        			        ERR(policy, "Error: %s\n", strerror(error));
               				return -1;	

				}
                        }
                }
        }
        return 0;
}

int find_domains_run(sechk_module_t *mod, apol_policy_t *policy) 
{
	int i, j, error;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	char *type_name = NULL;
	find_domains_data_t *datum = NULL;
	char *buff = NULL;
	int buff_sz;
	size_t num_items, rule_type, proof_idx;
	uint32_t type_val, t_val;
	apol_vector_t *domain_vector, *terule_vector, *role_vector;
	apol_terule_query_t * terule_query;
	qpol_terule_t *tmp_terule;
	apol_role_query_t * role_query;

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

        res = sechk_result_new();
        if (!res) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

	datum = (find_domains_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
		return -1;
	}
	res->item_type = SECHK_ITEM_TYPE;
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
		goto find_domains_run_fail;
	}
	
        if ( !(res->items = apol_vector_create()) ) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                goto find_domains_run_fail;
	}

	if (apol_get_type_by_query(policy, NULL, &domain_vector) < 0){
		goto find_domains_run_fail;
	}

	if ( (num_items = apol_vector_get_size ( domain_vector )) < 0){
		goto find_domains_run_fail;
	}

        for (i=0;i<apol_vector_get_size(domain_vector);i++) {
                qpol_iterator_t *domain_attr_iter;

                qpol_type_t *type = apol_vector_get_element(domain_vector,i);
                qpol_type_get_name(policy->qh, policy->p, type, &type_name);

                if ( qpol_type_get_attr_iter(policy->qh, policy->p, type, &domain_attr_iter) < 0 ) {
                        fprintf(stderr, "Error: could not get attributes for %s\n",type_name);
                        goto find_domains_run_fail;
                }

                for (;!qpol_iterator_end(domain_attr_iter);qpol_iterator_next(domain_attr_iter)) {
                        char *attr_name;
                        qpol_type_t *attr;
                        int nfta;

                        buff = NULL;
                        proof = sechk_proof_new(NULL);
                        if (!proof) {
		                error = errno;
        		        ERR(policy, "Error: %s\n", strerror(error));
                                goto find_domains_run_fail;
                        }
                        qpol_iterator_get_item(domain_attr_iter, (void **)&attr);
                        qpol_type_get_name(policy->qh, policy->p, attr, &attr_name);
                        for (nfta=0;nfta<apol_vector_get_size(datum->domain_attribs); nfta++) {
                                char *domain_attrib;

                                domain_attrib = apol_vector_get_element(datum->domain_attribs,nfta);
                                if (!strcmp(attr_name, domain_attrib)) {
                        		proof->type = SECHK_ITEM_ATTRIB;
		                        buff_sz = 1+strlen(type_name)+strlen(attr_name)+strlen("has attribute ");
        		                buff = (char*)calloc(buff_sz, sizeof(char));
                		        if (!buff) {
				                error = errno;
      	 					ERR(policy, "Error: %s\n", strerror(error));
		                                goto find_domains_run_fail;
		                        }
        	        	        strcat(buff, "has attribute ");
        	        	        strcat(buff, attr_name);
	        	                proof->text = buff;
	                	        if (!proof->text) {
				                error = errno;
				                ERR(policy, "Error: %s\n", strerror(error));
        	        	                goto find_domains_run_fail;
        	        	        }
                       			if (!item) {
                     			           item = sechk_item_new(NULL);
                 			           if (!item) {
      			                                  fprintf(stderr, "Error: out of memory\n");
                		                        goto find_domains_run_fail;
                        		           }
                                	 	   item->test_result = 1;
                        		}
                        		if ( !item->proof ) {
                                		if ( !(item->proof = apol_vector_create()) ) {
                					error = errno;
                					ERR(policy, "Error: %s\n", strerror(error));
                					goto find_domains_run_fail;
						}
                        		}
                        		if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
				                error = errno;
				                ERR(policy, "Error: %s\n", strerror(error));
				                goto find_domains_run_fail;
					}
                        		buff = NULL;
				}
				buff = NULL;
			}
			buff = NULL;
                }
                qpol_iterator_destroy(&domain_attr_iter);

                /* rule src check filesystem associate */
                if ( !(terule_query = apol_terule_query_create()) ) {
                	error = errno;
	                ERR(policy, "Error: %s\n", strerror(error));
	                goto find_domains_run_fail;
		}
                apol_terule_query_set_source(policy, terule_query, type_name, 0);
                if ( apol_get_terule_by_query(policy, terule_query, &terule_vector) < 0 ) {
	                error = errno;
        	        ERR(policy, "Error: %s\n", strerror(error));
        	        goto find_domains_run_fail;
		}
                for ( j=0;j<apol_vector_get_size(terule_vector);j++) {
                        qpol_terule_t *terule = NULL;
			qpol_class_t * class = NULL;
			char * class_name = NULL;
	
                        terule = apol_vector_get_element(terule_vector, j);
			qpol_terule_get_object_class(policy->qh, policy->p, terule, &class);
			qpol_class_get_name(policy->qh, policy->p, class, &class_name);
                        if (strcmp("filesystem", class_name)){
	                        if( qpol_terule_get_rule_type(policy->qh, policy->p, terule, &rule_type)){
			                error = errno;
               				 ERR(policy, "Error: %s\n", strerror(error));
       		                         exit(-1);
                                }
                                buff = NULL;
                                proof = sechk_proof_new(NULL);
                                if (!proof) {
			                error = errno;
			                ERR(policy, "Error: %s\n", strerror(error));
                                        goto find_domains_run_fail;
                                }
                                proof->type = SECHK_ITEM_AVRULE;
                                proof->text = apol_terule_render(policy, terule);
                                if (!item) {
  	                        	item = sechk_item_new(NULL);
        	                      	if (!item) {
                                      		fprintf(stderr, "Error: out of memory\n");
                                		goto find_domains_run_fail;
                                      	}
                                	item->test_result = 1;
                                }
                                if ( !item->proof ) {
                                	if ( !(item->proof = apol_vector_create()) ) {
				                error = errno;
				                ERR(policy, "Error: %s\n", strerror(error));
				                goto find_domains_run_fail;

					}
				}
                                if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
			                error = errno;
			                ERR(policy, "Error: %s\n", strerror(error));
			                goto find_domains_run_fail;
				}
                        }
                }
                apol_vector_destroy(&terule_vector,NULL);
                apol_terule_query_destroy(&terule_query);

                /* type rule check file object */
                if ( !(terule_query = apol_terule_query_create()) ) {
	                error = errno;
        	        ERR(policy, "Error: %s\n", strerror(error));
        	        goto find_domains_run_fail;
		}
                apol_terule_query_set_default(policy, terule_query, type_name);
                if ( apol_get_terule_by_query(policy, terule_query, &terule_vector) < 0 ) {
                	error = errno;
	                ERR(policy, "Error: %s\n", strerror(error));
        	        goto find_domains_run_fail;
		}
                for ( j=0;j<apol_vector_get_size(terule_vector);j++) {
                        qpol_terule_t *terule     = NULL;
			qpol_class_t  *objclass   = NULL;
			qpol_type_t   *dflt_type  = NULL;
			char	      *class_name = NULL;

                        terule = apol_vector_get_element(terule_vector, j);
			qpol_terule_get_object_class(policy->qh, policy->p, terule, &objclass);
			qpol_class_get_name(policy->qh, policy->p, objclass, &class_name);
			qpol_terule_get_default_type(policy->qh, policy->p, terule, &dflt_type);
			qpol_type_get_value(policy->qh, policy->p, dflt_type, &type_val);
			if ( type_val == t_val && !strcmp("process", class_name)) {
				if ( apol_vector_get_index(item->proof, tmp_terule, sechk_proof_with_element_compare, NULL, &proof_idx) == 0 ) {
					continue;
				}
                                buff = NULL;
                                proof = sechk_proof_new(NULL);
                                if (!proof) {
	        	        	error = errno;
        	        		ERR(policy, "Error: %s\n", strerror(error));
                                        goto find_domains_run_fail;
                                }
                                proof->type = SECHK_ITEM_TERULE;
                                proof->text = apol_terule_render(policy, terule);
                               	if (!item) {
                                        item = sechk_item_new(NULL);
                                        if (!item) {
				                error = errno;
                				ERR(policy, "Error: %s\n", strerror(error));
                                                goto find_domains_run_fail;
                                        }
                                        item->test_result = 1;
                                }
                                if ( !item->proof ) {
                                        if ( !(item->proof = apol_vector_create()) ) {
				                error = errno;
				                ERR(policy, "Error: %s\n", strerror(error));
				                goto find_domains_run_fail;
					}
				}
                                if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
			                error = errno;
			                ERR(policy, "Error: %s\n", strerror(error));
			                goto find_domains_run_fail;
				}
                        }
                }
                apol_vector_destroy(&terule_vector,NULL);
                apol_terule_query_destroy(&terule_query);

		/* Check Roles */
		if ( !(role_query = apol_role_query_create()) ) {
                	error = errno;
	                ERR(policy, "Error: %s\n", strerror(error));
	                goto find_domains_run_fail;
		}
		apol_role_query_set_type(policy, role_query, type_name);
		apol_get_role_by_query(policy, role_query, &role_vector);
		if ( (num_items = apol_vector_get_size ( role_vector )) < 0){
			goto find_domains_run_fail;
		}
		for (j=0;j<apol_vector_get_size(role_vector);j++) {
			qpol_role_t *role; 
			char *role_name;
			
			role = (qpol_role_t*)apol_vector_get_element(role_vector, j);
			qpol_role_get_name(policy->qh, policy->p, role, &role_name);
			if (!strcmp("object_r", role_name)) continue;
			buff = NULL;
			buff_sz = 1 + strlen("role types ;") + strlen(role_name) + strlen(type_name);
			buff = (char*)calloc(buff_sz, sizeof(char));
			if (!buff) {
		                error = errno;
		                ERR(policy, "Error: %s\n", strerror(error));
				goto find_domains_run_fail;
			}
			snprintf(buff, buff_sz, "role %s types %s;", role_name, type_name);
			proof = sechk_proof_new(NULL);
			if (!proof) {
		                error = errno;
		                ERR(policy, "Error: %s\n", strerror(error));
				goto find_domains_run_fail;
			}
			proof->type = SECHK_ITEM_ROLE;
			proof->text = buff;
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
			                error = errno;
			                ERR(policy, "Error: %s\n", strerror(error));
					goto find_domains_run_fail;
				}
				item->test_result = 1;
			}
			if ( !item->proof ) {
				if ( !(item->proof = apol_vector_create()) ) {
			                error = errno;
			                ERR(policy, "Error: %s\n", strerror(error));
			                goto find_domains_run_fail;

				}
			}
			if ( apol_vector_append(item->proof,(void *) proof) < 0 ) {
		                error =	errno;
		                ERR(policy, "Error: %s\n", strerror(error));
		                goto find_domains_run_fail;
			}
			buff = NULL;
		}

                /* insert any results for this type */
                if (item) {
                        item->item = type_name;
                        if ( apol_vector_append(res->items, (void*)item) < 0 ) {
		                error = errno;
		                ERR(policy, "Error: %s\n", strerror(error));
		                goto find_domains_run_fail;
			}
                }
                item = NULL;
                type = NULL;
                type_name = NULL;
	}

	/* results are valid at this point */
	mod->result = res;
	return 0;

find_domains_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	free(buff);
	return -1;
}

void find_domains_data_free(void *data) 
{
        find_domains_data_t *datum = (find_domains_data_t*)data;

        if (datum) {
                free(datum->domain_attribs);
        }
        free(data);
}

int find_domains_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	find_domains_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0, j = 0 , k = 0, l=0, num_items;
	sechk_proof_t *proof = NULL;

	if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp("find_domains", mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (find_domains_data_t*)mod->data;
	outformat = mod->outputformat;
        num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET)) {
		return 0; /* not an error - no output is requested */
	}
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i domain types.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types are domains.\n");
	}

        if (outformat & SECHK_OUT_LIST) {
                printf("\n");
                for (i = 0; i < num_items; i++) {
                        j++;
                        item  = apol_vector_get_element(mod->result->items, i);
                        j %= 4;
                        printf("%s%s", (char *)item->item, (char *)( (j) ? ", " : "\n" ));
                }
                printf("\n");
        }

        if (outformat & SECHK_OUT_PROOF) {
                printf("\n");
                for (k=0;k< num_items;k++) {
                        item = apol_vector_get_element(mod->result->items, k);
                        if ( item ) {
                                printf("%s\n", (char*)item->item);
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

sechk_result_t *find_domains_get_result(sechk_module_t *mod) 
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

int find_domains_get_list(sechk_module_t *mod, int **array, int *size) 
{
	int i, num_items;
	sechk_item_t *item = NULL;

	if (!mod || !array || !size) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}
	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	num_items = apol_vector_get_size(mod->result->items);
	*size = num_items;
	*array = (int*)malloc(num_items *sizeof(int));
	if (!(*array)) {
		fprintf(stderr, "Error: out of memory\n");
			return -1;
	}

        for (i = 0; i < apol_vector_get_size(mod->result->items); i++) {
                item  = apol_vector_get_element(mod->result->items, i);
                (*array)[i] = i;
        }

	return 0;
}

find_domains_data_t *find_domains_data_new(void) 
{
	find_domains_data_t *datum = NULL;

	datum = (find_domains_data_t*)calloc(1,sizeof(find_domains_data_t));

	return datum;
}
