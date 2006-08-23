/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "find_file_types.h"
#ifdef LIBSEFS
#include <sefs/file_contexts.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static const char *const mod_name = "find_file_types";

int find_file_types_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;
	sechk_name_value_t *nv = NULL;

	if (!lib) {
                ERR(NULL, "%s", "No library");
		return -1;
	}

	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
                ERR(NULL, "%s", "Module unknown");
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */

	mod->brief_description = "utility module";
	mod->detailed_description = 
"--------------------------------------------------------------------------------\n"
"This module finds all types in the policy treated as a file type.  A type is    \n"
"considered a file type if any of the following is true:\n"
"\n"
"   1) it has an attribute associated with file types\n"
"   2) it is the source of a rule to allow filesystem associate permission\n"
"   3) it is the default type of a type transition rule with an object class\n"
"      other than process\n"
"   4) it is specified in a context in the file_contexts file\n";
	mod->opt_description = 
"Module requirements:\n"
"   none\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   file_type_attribute can be modified in a profile\n";
	mod->severity = SECHK_SEV_NONE;
	/* assign requirements */
	nv = sechk_name_value_new("policy_type","source");
	apol_vector_append(mod->requirements, (void*)nv);

	/* assign options */
	nv = sechk_name_value_new("file_type_attribute", "file_type");
	apol_vector_append(mod->options, (void*)nv);

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
	fn_struct->fn = &find_file_types_init;
	apol_vector_append(mod->functions, (void*)fn_struct);

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
	fn_struct->fn = &find_file_types_run;
	apol_vector_append(mod->functions, (void*)fn_struct);

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
	fn_struct->fn = &find_file_types_data_free;
	apol_vector_append(mod->functions, (void*)fn_struct);

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
	fn_struct->fn = &find_file_types_print_output;
	apol_vector_append(mod->functions, (void*)fn_struct);

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
	fn_struct->fn = &find_file_types_get_result;
	apol_vector_append(mod->functions, (void*)fn_struct);

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup("get_list");
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &find_file_types_get_list;
	apol_vector_append(mod->functions, (void*)fn_struct);

	return 0;
}

int find_file_types_init(sechk_module_t *mod, apol_policy_t *policy) 
{
        sechk_name_value_t *opt = NULL;
        find_file_types_data_t *datum = NULL;
	apol_vector_t *attr_vector = NULL;
	apol_attr_query_t *attr_query = apol_attr_query_create();
	qpol_type_t *attr = NULL;	
        size_t i=0, j=0;

        if (!mod || !policy) {
                ERR(policy, "%s", "Invalid parameters");
                return -1;
        }
        if (strcmp(mod_name, mod->name)) {
                ERR(policy, "Wrong module (%s)", mod->name);
                return -1;
        }

        datum = find_file_types_data_new();
        if (!datum) {
                ERR(policy, "%s", strerror(ENOMEM));
                return -1;
        }
	if ( !(datum->file_type_attribs = apol_vector_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
		return -1;
	}
        mod->data = datum;

        for (i = 0; i < apol_vector_get_size(mod->options); i++) {
                opt = apol_vector_get_element(mod->options, i);
		if (!strcmp(opt->name, "file_type_attribute")) {
			apol_attr_query_set_attr(policy, attr_query, opt->value);
			apol_get_attr_by_query(policy, attr_query, &attr_vector);
			for (j=0;j<apol_vector_get_size(attr_vector);j++) {
				char *file_attrib;
				attr = apol_vector_get_element(attr_vector, j);
				qpol_type_get_name(policy->qh, policy->p, attr, &file_attrib);
	                       	if ( apol_vector_append( datum->file_type_attribs,(void*) file_attrib ) < 0 ) {
			                ERR(policy, "%s", strerror(ENOMEM));
					return -1;
				}
			} 
		}
	}
        return 0;
}

int find_file_types_run(sechk_module_t *mod, apol_policy_t *policy) 
{
	find_file_types_data_t *datum;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	sechk_result_t *res = NULL;
	char *type_name = NULL;
	apol_avrule_query_t *avrule_query = NULL;
	apol_terule_query_t *terule_query = NULL;
	apol_vector_t *avrule_vector = NULL;	
	apol_vector_t *terule_vector = NULL;
	size_t i, j, x, retv;
	char *buff = NULL;
	int buff_sz;

	/* NEW */
	int num_fc_entries = 0;
	apol_vector_t *type_vector = NULL;
	apol_vector_t *fc_entry_vector = NULL;

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

	res = sechk_result_new();
	if (!res) {
                ERR(policy, "%s", strerror(ENOMEM));
		return -1;
	}

	datum = (find_file_types_data_t*)mod->data;
	res->item_type = SECHK_ITEM_TYPE;
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
                ERR(policy, "%s", strerror(ENOMEM));
		goto find_file_types_run_fail;
	}
	if ( !(res->items = apol_vector_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
		goto find_file_types_run_fail;
	}

#ifdef LIBSEFS
	if (mod->parent_lib->fc_entries) {
		if (mod->parent_lib->fc_path) {
			retv = sefs_fc_entry_parse_file_contexts(policy, mod->parent_lib->fc_path, &fc_entry_vector);
			if (retv)
		                ERR(policy, "%s", "Unable to parse file contexts file");
			else
			    num_fc_entries = apol_vector_get_size(fc_entry_vector);
		} else 
	                ERR(policy, "%s", "Unable to find file contexts file");
	}
#endif

	/* Get an iterator for the types */
	if (apol_get_type_by_query(policy, NULL, &type_vector) < 0) {
                ERR(policy, "%s", "Unable to retrieve types");
		return -1;
	}
	
	for (i=0;i<apol_vector_get_size(type_vector);i++) {
		qpol_iterator_t *file_attr_iter;

		qpol_type_t *type = apol_vector_get_element(type_vector,i);
		qpol_type_get_name(policy->qh, policy->p, type, &type_name);

		if ( qpol_type_get_attr_iter(policy->qh, policy->p, type, &file_attr_iter) < 0 ) {
			ERR(policy, "Could not get attributes for %s\n", type_name); 
			goto find_file_types_run_fail;
		}

		for (;!qpol_iterator_end(file_attr_iter);qpol_iterator_next(file_attr_iter)) {
			char *attr_name;
			qpol_type_t *attr;
			int nfta;

			buff = NULL;
			proof = sechk_proof_new(NULL);
			if (!proof) {
		                ERR(policy, "%s", strerror(ENOMEM));
		                goto find_file_types_run_fail;
			}
			qpol_iterator_get_item(file_attr_iter, (void **)&attr);
			qpol_type_get_name(policy->qh, policy->p, attr, &attr_name);
			for (nfta=0;nfta<apol_vector_get_size(datum->file_type_attribs); nfta++) {
				char *file_type_attrib;

				file_type_attrib = apol_vector_get_element(datum->file_type_attribs,nfta);
				if (!strcmp(attr_name, file_type_attrib)) {
					proof->type = SECHK_ITEM_ATTRIB;
					buff_sz = 1+strlen(attr_name)+strlen("has attribute ");
					buff = (char*)calloc(buff_sz, sizeof(char));
					if (!buff) {
				                ERR(policy, "%s", strerror(ENOMEM));
				                goto find_file_types_run_fail;
					}
					strcat(buff, "has attribute ");
					strcat(buff, attr_name);
					proof->text = buff;
					if (!item) {
						item = sechk_item_new(NULL);
						if (!item) {
					                ERR(policy, "%s", strerror(ENOMEM));
       					         	goto find_file_types_run_fail;
						}
						item->test_result = 1;
					}
					if ( !item->proof ) {
						if ( !(item->proof = apol_vector_create()) ) {
					                ERR(policy, "%s", strerror(ENOMEM));
					                goto find_file_types_run_fail;
						}
					}
					if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
				                ERR(policy, "%s", strerror(ENOMEM));
				                goto find_file_types_run_fail;
					}
				}
				buff = NULL;
			}
			buff = NULL;
		}
		qpol_iterator_destroy(&file_attr_iter);

		/* rule src check filesystem associate */
		if ( !(avrule_query = apol_avrule_query_create()) ) {
	                ERR(policy, "%s", "Could not retrieve AV rules");
	                goto find_file_types_run_fail;
		}
		apol_avrule_query_set_source(policy, avrule_query, type_name, 0);	
		apol_avrule_query_append_class(policy, avrule_query, "filesystem");
		apol_avrule_query_append_perm (policy, avrule_query, "associate");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for ( x=0;x<apol_vector_get_size(avrule_vector);x++) {
			qpol_avrule_t *avrule;
			avrule = apol_vector_get_element(avrule_vector, x);
			if ( avrule ) {
				buff = NULL;
				proof = sechk_proof_new(NULL);
				if (!proof) {
			                ERR(policy, "%s", strerror(ENOMEM));
			                goto find_file_types_run_fail;
				}
				proof->type = SECHK_ITEM_AVRULE;
				proof->text = apol_avrule_render(policy, avrule);
                                if (!item) {
                                        item = sechk_item_new(NULL);
                                        if (!item) {
				                ERR(policy, "%s", strerror(ENOMEM));
				                goto find_file_types_run_fail;
                                        }
                                        item->test_result = 1;
                                }
                                if ( !item->proof ) {
                                        if ( !(item->proof = apol_vector_create()) ) {
				                ERR(policy, "%s", strerror(ENOMEM));
				                goto find_file_types_run_fail;
					}
                                }
				item->test_result = 1;
				if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
			                ERR(policy, "%s", strerror(ENOMEM));
			                goto find_file_types_run_fail;
				}
				buff = NULL;
			}
			buff = NULL;
		}	
		buff = NULL;
		apol_vector_destroy(&avrule_vector,NULL);
		apol_avrule_query_destroy(&avrule_query);

		/* type rule check file object */
		if ( !(terule_query = apol_terule_query_create()) ) {
		        ERR(policy, "%s", "Could not retrieve TE rules");
	                goto find_file_types_run_fail;
		}
		apol_terule_query_set_default(policy, terule_query, type_name);
		apol_get_terule_by_query(policy, terule_query, &terule_vector);
		for ( x=0;x<apol_vector_get_size(terule_vector);x++) {
			qpol_terule_t *terule;
			qpol_class_t  *objclass;
			char *class_name;

			terule = apol_vector_get_element(terule_vector, x);
			qpol_terule_get_object_class(policy->qh, policy->p, terule, &objclass);
			qpol_class_get_name(policy->qh, policy->p, objclass, &class_name);
			if (strcmp(class_name,"process")) {
				buff = NULL;
				proof = sechk_proof_new(NULL);
				if (!proof) {
			                ERR(policy, "%s", strerror(ENOMEM));
			                goto find_file_types_run_fail;
				}
				proof->type = SECHK_ITEM_TERULE;
				proof->text = apol_terule_render(policy, terule);
                                if (!item) {
                                        item = sechk_item_new(NULL);
                                        if (!item) {
				                ERR(policy, "%s", strerror(ENOMEM));
				                goto find_file_types_run_fail;
                                        }
                                        item->test_result = 1;
                                }
                                if ( !item->proof ) {
                                        if ( !(item->proof = apol_vector_create()) ) {
				                ERR(policy, "%s", strerror(ENOMEM));
				                goto find_file_types_run_fail;
					}
                                }
				item->test_result = 1;
				if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
			                ERR(policy, "%s", strerror(ENOMEM));
			                goto find_file_types_run_fail;
				}
				buff = NULL;
			}
			buff = NULL;
		} 
		buff = NULL;
		apol_vector_destroy(&terule_vector,NULL);
		apol_terule_query_destroy(&terule_query);

#ifdef LIBSEFS 
		/* assigned in fc check */
		if (fc_entry_vector) {
			for (j=0; j < num_fc_entries; j++) {
				sefs_fc_entry_t *fc_entry;
				char *fc_type_name = NULL;
				fc_entry = apol_vector_get_element(fc_entry_vector, j);
				if (!fc_entry->context) continue;
				if (fc_entry->context->type ) fc_type_name = fc_entry->context->type;
				if (fc_entry->context && !strcmp(type_name,fc_type_name)) {
					buff_sz = 1;
					buff_sz += strlen(fc_entry->path);
					switch (fc_entry->filetype) {
					case SEFS_FILETYPE_DIR: /* Directory */
					case SEFS_FILETYPE_CHR: /* Character device */
					case SEFS_FILETYPE_BLK: /* Block device */
					case SEFS_FILETYPE_REG: /* Regular file */
					case SEFS_FILETYPE_FIFO: /* FIFO */
					case SEFS_FILETYPE_LNK: /* Symbolic link */
					case SEFS_FILETYPE_SOCK: /* Socket */
						buff_sz += 4;
						break;
					case SEFS_FILETYPE_ANY: /* any type */
						buff_sz += 2;
						break;
					case SEFS_FILETYPE_NONE: /* none */
					default:
				                ERR(policy, "%s", "Invalid file type");
						goto find_file_types_run_fail;
						break;
					}
					if (apol_vector_get_size(mod->parent_lib->fc_entries)>0) {
						buff_sz += (strlen(fc_entry->context->user) + 1);
						buff_sz += (strlen(fc_entry->context->role) + 1);
						buff_sz +=  strlen(fc_entry->context->type);
					} else {
						buff_sz += strlen("<<none>>");
					}
					buff = (char*)calloc(buff_sz, sizeof(char));
					strcat(buff, fc_entry->path);
					switch (fc_entry->filetype) {
					case SEFS_FILETYPE_DIR: /* Directory */
						strcat(buff, "\t-d\t");
						break;
					case SEFS_FILETYPE_CHR: /* Character device */
						strcat(buff, "\t-c\t");
						break;
					case SEFS_FILETYPE_BLK: /* Block device */
						strcat(buff, "\t-b\t");
						break;
					case SEFS_FILETYPE_REG: /* Regular file */
						strcat(buff, "\t--\t");
						break;
					case SEFS_FILETYPE_FIFO: /* FIFO */
						strcat(buff, "\t-p\t");
						break;
					case SEFS_FILETYPE_LNK: /* Symbolic link */
						strcat(buff, "\t-l\t");
						break;
					case SEFS_FILETYPE_SOCK: /* Socket */
						strcat(buff, "\t-s\t");
						break;
					case SEFS_FILETYPE_ANY: /* any type */
						strcat(buff, "\t\t");
						break;
					case SEFS_FILETYPE_NONE: /* none */
					default:
				                ERR(policy, "%s", "Invalid file type");
						goto find_file_types_run_fail;
						break;
					}
					if (fc_entry->context) {
						strcat(buff, fc_entry->context->user);
						strcat(buff, ":");
						strcat(buff, fc_entry->context->role);
						strcat(buff, ":");
						strcat(buff, fc_entry->context->type);
					} else {
						strcat(buff, "<<none>>");
					}
					proof = sechk_proof_new(NULL);
					if (!proof) {
				                ERR(policy, "%s", strerror(ENOMEM));
				                goto find_file_types_run_fail;
					}
					proof->type = SECHK_ITEM_FCENT;
					proof->text = buff;
					if (!item) {
						item = sechk_item_new(NULL);
						if (!item) {
					                ERR(policy, "%s", strerror(ENOMEM));
					                goto find_file_types_run_fail;
						}
						item->test_result = 1;
					}
					if ( !item->proof ) { 
						if ( !(item->proof = apol_vector_create()) ) {
					                ERR(policy, "%s", strerror(ENOMEM));
					                goto find_file_types_run_fail;
						}
					}
					if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
				                ERR(policy, "%s", strerror(ENOMEM));
				                goto find_file_types_run_fail;
					}
				}
			}
		}
#endif
		/* insert any results for this type */
		if (item) {
			item->item = type;
			if ( apol_vector_append(res->items, (void*)item) < 0 ) {
       			        ERR(policy, "%s", strerror(ENOMEM));
		                goto find_file_types_run_fail;
			}
		}
		item = NULL;
		type = NULL;
		type_name = NULL;
	}

	/* results are valid at this point */ 
	mod->result = res;

	return 0;

find_file_types_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	free(buff);
	return -1;
}

void find_file_types_data_free(void *data) 
{
	find_file_types_data_t *datum = (find_file_types_data_t*)data;

	if (datum) {
		free(datum->file_type_attribs);
	}
	free(data);
}

int find_file_types_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	find_file_types_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0, k=0, l=0, num_items = 0;
	qpol_type_t *type;
	char *type_name;

        if (!mod || !policy){
                ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
                ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	datum = (find_file_types_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
                ERR(policy, "%s", "Module has not been run");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */
	if (outformat & SECHK_OUT_STATS) {
		num_items = apol_vector_get_size(mod->result->items);
		printf("Found %i file types.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types are file types.\n\n");
	}
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
	        for (i = 0; i < apol_vector_get_size(mod->result->items); i++) {
			j++;
			item  = apol_vector_get_element(mod->result->items, i);
			type = item->item;
			qpol_type_get_name(policy->qh, policy->p, type, &type_name);
			j %= 4;
                        printf("%s%s", type_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
		}
		printf("\n");
	}

        if (outformat & SECHK_OUT_PROOF) {
                printf("\n");
                for (k=0; k< apol_vector_get_size(mod->result->items); k++) {
                        item = apol_vector_get_element(mod->result->items, k);
			if ( item ) {
				type = item->item;
				qpol_type_get_name(policy->qh, policy->p, type, &type_name);
                        	printf("%s\n", (char*)type_name);
                        	for (l=0; l < apol_vector_get_size(item->proof); l++) {
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


sechk_result_t *find_file_types_get_result(sechk_module_t *mod) 
{ 
	if (!mod) {
                ERR(NULL, "%s", "Invalid parameters");
		return NULL;
	}
	if (strcmp(mod_name, mod->name)) {
                ERR(NULL, "Wrong module (%s)", mod->name);
		return NULL;
	}

	return mod->result;
}

find_file_types_data_t *find_file_types_data_new(void) 
{
	find_file_types_data_t *datum = NULL;

	datum = (find_file_types_data_t*)calloc(1,sizeof(find_file_types_data_t));

	return datum;
}

int find_file_types_get_list(sechk_module_t *mod, apol_vector_t **v) 
{ 
        if (!mod || !v) {
                ERR(NULL, "%s", "Invalid parameters");
                return -1;
        }
        if (strcmp(mod_name, mod->name)) {
                ERR(NULL, "Wrong module (%s)", mod->name);
                return -1;
        }
        if (!mod->result) {
                ERR(NULL, "%s", "Module has not been run");
                return -1;
        }

        v = &mod->result->items;

        return 0;
}
