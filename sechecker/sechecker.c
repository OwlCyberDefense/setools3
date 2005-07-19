 /* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com, kcarr@tresys.com
 *
 * sechecker.c
 *
 */

#include "sechecker.h"
#include "register_list.h"
#include <stdio.h>
#include <string.h> 
#include <assert.h>
#include <libxml/xmlreader.h>
#include <policy.h>
#include <policy-io.h>
#include <util.h>
#include <file_contexts.h>

#ifdef LIBSELINUX
#include <selinux/selinux.h>
#endif

/* static methods */
static int sechk_lib_parse_config_file(const char *filename, sechk_lib_t *lib);
static int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t *lib);
static int sechk_lib_grow_modules(sechk_lib_t *lib);
static int sechk_lib_get_module_indx(const char *name, sechk_lib_t *lib);

/* 'public' methods */
sechk_lib_t *sechk_lib_new(const char *policyfilelocation, const char *fcfilelocation) 
{
	sechk_lib_t *lib = NULL;
	char *default_policy_path = NULL, *default_fc_path = NULL;
	const char *CONFIG_FILE="/.sechecker", *DEFAULT_CONFIG_FILE="/dot_sechecker";
	char *conf_path = NULL, *conf_filename = NULL;
	int retv;


	/* allocate the new sechk_lib_t structure */
	lib = (sechk_lib_t*)calloc(1, sizeof(sechk_lib_t));
	if (!lib) {
		fprintf(stderr, "Error: out of memory\n");
		goto exit_err;
	}
	/* find the configuration file */
	conf_path = find_user_config_file(CONFIG_FILE);
	if (!conf_path) {
		conf_path = find_file(DEFAULT_CONFIG_FILE);
		if (!conf_path) {
			fprintf(stderr, "Error: could not find config file\n");
			goto exit_err;
		} else {
			/* concat path and filename */
			conf_filename = (char*)calloc(1+strlen(conf_path) + strlen(DEFAULT_CONFIG_FILE), sizeof(char));
			if (!conf_filename) {
				fprintf(stderr, "Error: out of memory\n");
				goto exit_err;
			}
			strcat(conf_filename, conf_path);
			strcat(conf_filename, DEFAULT_CONFIG_FILE);
		}
	} else {
		/* concat path and filename */
		conf_filename = (char*)calloc(1 + strlen(conf_path) + strlen(CONFIG_FILE), sizeof(char));
		if (!conf_path) {
			fprintf(stderr, "Error: out of memory\n");
			goto exit_err;
		}
		strcat(conf_filename, conf_path);
		strcat(conf_filename, CONFIG_FILE);
	}
	assert(conf_filename);
	/* parse the configuration file */
	if ((retv = sechk_lib_parse_config_file(conf_filename, lib)) != 0) {
		fprintf(stderr, "Error: could not parse config file\n");
		goto exit_err;
	}

	/* if no policy is given, attempt to find default */
	if (!policyfilelocation) {
		retv = find_default_policy_file((POL_TYPE_SOURCE|POL_TYPE_BINARY), &default_policy_path);
		if (retv) {
			fprintf(stderr, "Error: could not find default policy\n");
			goto exit_err;
		}
		retv = open_policy(default_policy_path, &(lib->policy));
		if (retv) {
			fprintf(stderr, "Error: failed opening default policy\n");
			goto exit_err;
		}
		lib->policy_path = strdup(default_policy_path);
	} else {
		retv = open_policy(policyfilelocation, &(lib->policy));
		if (retv) {
			fprintf(stderr, "Error: failed opening policy %s\n", policyfilelocation);
			goto exit_err;
		}
		lib->policy_path = strdup(policyfilelocation);
		}

	/* if no file_contexts file is given attempt to find the default */
	if (!fcfilelocation) {
		retv = find_default_file_contexts_file(&default_fc_path);
		if (retv) {
			fprintf(stderr, "Warning: unable to find default file_contexts file\n");
		}
		retv = parse_file_contexts_file(default_fc_path, &(lib->fc_entries), &(lib->num_fc_entries), lib->policy);
		if (retv) {
			fprintf(stderr, "Warning: unable to process file_contexts file\n");
		} else {
			lib->fc_path = strdup(default_fc_path);
		}
	} else {
		retv = parse_file_contexts_file(fcfilelocation, &(lib->fc_entries), &(lib->num_fc_entries), lib->policy);
		if (retv) {
			fprintf(stderr, "Warning: unable to process file_contexts file\n");
		} else {
			lib->fc_path = strdup(fcfilelocation);
		}

	}

exit:
	if (default_policy_path)
		free(default_policy_path);
	if (conf_path)
		free(conf_path);
	if (conf_filename)
		free(conf_filename);
	return lib;

exit_err:
	if (lib) {
		sechk_lib_free(lib);
		free(lib);
		lib = NULL;
	}
	goto exit;
}

void sechk_lib_free(sechk_lib_t *lib) 
{
	int i;
	sechk_free_fn_t free_fn;

	if (lib == NULL)
		return;

	if (lib->policy) {
		free_policy(&lib->policy);
		lib->policy = NULL;
	}
	if (lib->modules) {
		for (i = 0; i < lib->num_modules; i++) {
			if (lib->modules[i].data)
				free_fn = sechk_lib_get_module_function(lib->modules[i].name, SECHK_MOD_FN_FREE, lib);
			else
				free_fn = NULL;
			sechk_module_free(&lib->modules[i], free_fn);
		}
		free(lib->modules);
		lib->modules_size = 0;
		lib->num_modules = 0;
	}
	if (lib->fc_entries) {
		for (i = 0; i < lib->num_fc_entries; i++)
			sefs_fc_entry_free(&lib->fc_entries[i]);
		lib->num_fc_entries = 0;
		free(lib->fc_entries);
	}
	free(lib->selinux_config_path);
	free(lib->policy_path);
	free(lib->fc_path);
	free(lib->module_selection);
}

void sechk_module_free(sechk_module_t *module, sechk_free_fn_t free_fn)
{
	if (!module)
		return;

	free(module->header);
	sechk_result_free(module->result);
	sechk_name_value_destroy(module->options);
	sechk_name_value_destroy(module->requirements);
	sechk_name_value_destroy(module->dependencies);
	if (module->data) {
		assert(free_fn);
		free_fn(module);
	}
	sechk_fn_free(module->functions);
	free(module->name);
}

void sechk_fn_free(sechk_fn_t *fn_struct)
{
	sechk_fn_t *next_fn_struct = NULL;

	if (!fn_struct)
		return;

	while(fn_struct) {
		next_fn_struct = fn_struct->next;
		free(fn_struct->name);
		/* NEVER free fn_struct->fn */
		free(fn_struct);
		fn_struct = next_fn_struct;
	}
}

void sechk_name_value_destroy(sechk_name_value_t *opt)
{
	sechk_name_value_t *next_opt = NULL;

	if (!opt)
		return;

	while(opt) {
		next_opt = opt->next;
		free(opt->name);
		free(opt->value);
		free(opt);
		opt = next_opt;
	}
}

void sechk_result_free(sechk_result_t *res) 
{
	if (!res)
		return;
	if (res->test_name)
		free(res->test_name);
	if (res->items)
		sechk_item_free(res->items);
}

void sechk_item_free(sechk_item_t *item) 
{
	sechk_item_t *next_item = NULL;

	if (!item)
		return;

	while(item) {
		next_item = item->next;
		sechk_proof_free(item->proof);
		free(item);
		item = next_item;
	}
}

void sechk_proof_free(sechk_proof_t *proof) 
{
	sechk_proof_t *next_proof = NULL;

	if (!proof)
		return;

	while(proof) {
		next_proof = proof->next;
		free(proof->text);
		free(proof->xml_out);
		free(proof);
		proof = next_proof;
	}
}

sechk_fn_t *sechk_fn_new(void) 
{
	/* no initialization needed here */
	return (sechk_fn_t*)calloc(1, sizeof(sechk_fn_t));
}

sechk_name_value_t *sechk_name_value_new(void)
{
	/* no initialization needed here */
	return (sechk_name_value_t*)calloc(1, sizeof(sechk_name_value_t));
}

sechk_result_t *sechk_result_new(void) 
{
	/* initilization to zero is sufficient here */
	return (sechk_result_t*)calloc(1, sizeof(sechk_result_t));
}

sechk_item_t *sechk_item_new(void) 
{
	sechk_item_t *item = NULL;
	item = (sechk_item_t*)calloc(1, sizeof(sechk_item_t));
	if (!item)
		return NULL;
	item->item_id = -1;
	return item;
}

sechk_proof_t *sechk_proof_new(void) 
{
	sechk_proof_t *proof = NULL;
	proof = (sechk_proof_t*)calloc(1, sizeof(sechk_proof_t));
	if (!proof)
		return NULL;
	proof->idx = -1;
	return proof;
}

int sechk_lib_register_modules(sechk_register_fn_t *register_fns, sechk_lib_t *lib) 
{
	int i, retv;

	if (!register_fns || !lib) {
		fprintf(stderr, "Error: could not register modules\n");
		return -1;
	}
	if (lib->num_modules != sechk_register_list_get_num_modules()) {
		printf("%d\n%d\n", lib->num_modules, sechk_register_list_get_num_modules());
		fprintf(stderr, "Error: the number of registered modules does not match the number of modules in the configuration file.\n");
		return -1;
	}
	for (i = 0; i < lib->num_modules; i++) {
		retv = register_fns[i](lib);
		if (retv) {
			fprintf(stderr, "Error: could not register module #%i\n", i);
			return retv;
		}
	}
	
	return 0;
}

void *sechk_lib_get_module_function(const char *module_name, const char *function_name, sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!module_name || !function_name || !lib) {
		fprintf(stderr, "Error: failed to get function from module\n");
		return NULL;
	}

	/* find the correct module */
	mod = sechk_lib_get_module(module_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: %s: no such module\n", module_name);
		return NULL;
	}

	/* find function in module */
	fn_struct = mod->functions;
	while (fn_struct && strcmp(fn_struct->name, function_name)) {
		fn_struct = fn_struct->next;
	}
	if (!fn_struct) {
		fprintf(stderr, "Error: %s: no such function in module %s\n", function_name, module_name);
		return NULL;
	}

	return fn_struct->fn;
}

sechk_module_t *sechk_lib_get_module(const char *module_name, sechk_lib_t *lib) 
{
	int i;
	
	if (!module_name || !lib) {
		fprintf(stderr, "Error: failed to get module\n");
		return NULL;
	}

	for (i = 0; i < lib->num_modules; i++) {
		if (!strcmp(lib->modules[i].name, module_name))
			return &(lib->modules[i]);
	}
	fprintf(stderr, "Error: %s: no such module\n", module_name);
	return NULL;
}

int sechk_lib_init_modules(sechk_lib_t *lib) 
{
	int i, retv;
	sechk_init_fn_t init_fn = NULL;

	if (lib == NULL || lib->modules == NULL)
		return -1;
	for (i = 0; i < lib->num_modules; i++) {
		init_fn = (sechk_init_fn_t)sechk_lib_get_module_function(lib->modules[i].name, SECHK_MOD_FN_INIT, lib);
		if (!init_fn) {
			fprintf(stderr, "Error: could not initialize module %s\n", lib->modules[i].name);
			return -1;
		}
		retv = init_fn(&(lib->modules[i]), lib->policy);
		if (retv)
			return retv;
	}

	return 0;
}

int sechk_lib_run_modules(sechk_lib_t *lib) 
{
	int i, retv, rc = 0;
	sechk_run_fn_t run_fn = NULL;

	if (!lib) {
		fprintf(stderr, "Error: invalid library\n");
		return -1;
	}

	for (i = 0; i < lib->num_modules; i++) {
		/* if module is "off" do not run unless requested by another module */
		if (!lib->module_selection[i])
			continue;
		assert(lib->modules[i].name);
		run_fn = (sechk_run_fn_t)sechk_lib_get_module_function(lib->modules[i].name, SECHK_MOD_FN_RUN, lib);
		if (!run_fn) {
			fprintf(stderr, "Error: could not run module %s\n", lib->modules[i].name);
			return -1;
		}
		retv = run_fn(&(lib->modules[i]), lib->policy);
		if (retv) {
			fprintf(stderr, "Error: module %s failed\n", lib->modules[i].name);
			rc = -1;
		}
	}

	return rc;
}

int sechk_lib_print_modules_output(sechk_lib_t *lib)
{
	int i, retv, rc = 0;
	sechk_print_output_fn_t print_fn = NULL;

	if (!lib) {
		fprintf(stderr, "Error: invalid library\n");
		return -1;
	}

	for (i = 0; i < lib->num_modules; i++) {
		/* if module is "off" do not print its results */
		if (!lib->module_selection[i])
			continue;
		assert(lib->modules[i].name);
		print_fn = (sechk_run_fn_t)sechk_lib_get_module_function(lib->modules[i].name, SECHK_MOD_FN_PRINT, lib);
		if (!print_fn) {
			fprintf(stderr, "Error: could not get print function for module %s\n", lib->modules[i].name);
			return -1;
		}
		retv = print_fn(&(lib->modules[i]), lib->policy);
		if (retv) {
			fprintf(stderr, "Error: unable to print results for module %s \n", lib->modules[i].name);
			rc = -1;
		}
	}

	return -1;
}

bool_t sechk_lib_check_requirement(sechk_name_value_t *req, sechk_lib_t *lib)
{
	int pol_ver = POL_VER_UNKNOWN;

	if (!req) {
		fprintf(stderr, "Error: invalid requirement\n");
		return FALSE;
	}

	if (!lib || !lib->policy) {
		fprintf(stderr, "Error: invalid library\n");
		return FALSE;
	}

	if (!strcmp(req->name, SECHK_PARSE_REQUIRE_POL_TYPE)) {
		if (!strcmp(req->value, SECHK_PARSE_REQUIRE_POL_TYPE_SRC)) {
			if (is_binary_policy(lib->policy)) {
				fprintf(stderr, "Error: module required source policy but was given binary\n");
				return FALSE;
			}
		} else if (!strcmp(req->value, SECHK_PARSE_REQUIRE_POL_TYPE_BIN)) {
			if (!is_binary_policy(lib->policy)) {
				fprintf(stderr, "Error: module required binary policy but was given source\n");
				return FALSE;
			}
		} else {
			fprintf(stderr, "Error: invalid policy type specification %s\n", req->value);
			return FALSE;
		}
	} else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_POL_VER)) {
		pol_ver = atoi(req->value);
		if (pol_ver < 11)
			pol_ver = POL_VER_PRE_11;
		else if (pol_ver < 15)
			pol_ver = POL_VER_12;
		else if (pol_ver < 16)
			pol_ver = POL_VER_15;
		else if (pol_ver == 16)
			pol_ver = POL_VER_16;
		else if (pol_ver == 17)
			pol_ver = POL_VER_17;
		else if (pol_ver == 18)
			pol_ver = POL_VER_18;
		else if (pol_ver > 18)
			pol_ver = POL_VER_19;
		else
			pol_ver = POL_VER_UNKNOWN;
		if (lib->policy->version < pol_ver) {
			fprintf(stderr, "Error: module requires newer policy version\n");
			return FALSE;
		}
	} else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_SELINUX)) {
#ifdef LIBSELINUX
		if (!is_selinux_enabled()) {
			fprintf(stderr, "Error: module requires selinux system\n");
			return FALSE;
		}
#else
		fprintf(stderr, "Error: module requires selinux system, but SEChecker was not built to support system checks\n");
		return FALSE
#endif
	} else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_MLS_POLICY)) {
		if (lib->policy->version != POL_VER_19MLS) {
			fprintf(stderr, "Error: module requires MLS policy\n");
			return FALSE;
		}
	} else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_MLS_SYSTEM)) {
#ifdef LIBSELINUX
		if (!is_selinux_mls_enabled() || !is_selinux_enabled()) {
			fprintf(stderr, "Error: module requires MLS enabled selinux system\n");
			return FALSE;
		}
#else
		fprintf(stderr, "Error: module requires selinux system, but SEChecker was not built to support system checks\n");
		return FALSE
#endif
	} else {
		fprintf(stderr, "Error: unrecognized requirement\n");
		return FALSE;
	}

	return TRUE;
}

bool_t sechk_lib_check_dependency(sechk_name_value_t *dep, sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;

	if (!dep || !dep->value) {
		fprintf(stderr, "Error: invalid dependency\n");
		return FALSE;
	}

	if (!lib) {
		fprintf(stderr, "Error: invalid library\n");
		return FALSE;
	}

	mod = sechk_lib_get_module(dep->value, lib);
	if (!mod) {
		fprintf(stderr, "Error: could not find dependency %s\n", dep->value);
		return FALSE;
	}

	return TRUE;
}

int sechk_lib_set_outputformat(unsigned char out, sechk_lib_t *lib)
{
	int i;
	
	if (!lib || !out)
		return -1;
	
	lib->outputformat = out;
	
	for (i = 0; i < lib->num_modules; i++)
		lib->modules[i].outputformat = out;

	return 0;
}

/* sechk_item_sev calculates the severity level of an item based on the proof */
int sechk_item_sev(sechk_item_t *item)
{
	sechk_proof_t *proof = NULL;
	int sev = SECHK_SEV_NONE;

	if (!item)
		return SECHK_SEV_NONE;

	/* the severity of an item is equal to
	 * the highest severity among its proof elements */
	for (proof = item->proof; proof; proof = proof->next)
		if (proof->severity > sev)
			sev = proof->severity;

	return sev;
}

sechk_item_t *get_sechk_item_from_result(int item_id, unsigned char item_type, sechk_result_t *res)
{
	sechk_item_t *item = NULL;

	if (!res) {
		fprintf(stderr, "Error: item requested from invalid result set\n");
		return NULL;
	}

	if (!res->num_items || !res->items) {
		fprintf(stderr, "Error: item requested from empty result set\n");
		return NULL;
	}

	if (res->item_type != item_type) {
		fprintf(stderr, "Error: type of item requested does not match result set items\n");
		return NULL;
	}

	for (item = res->items; item; item = item->next) {
		if (item->item_id == item_id)
			break;
	}

	return item;
}

sechk_proof_t *copy_sechk_proof(sechk_proof_t *orig)
{
	sechk_proof_t *copy = NULL;

	if (!orig)
		return NULL;

	copy = sechk_proof_new();
	if (!copy) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}

	copy->idx = orig->idx;
	copy->type = orig->type;
	copy->text = strdup(orig->text);
	if (!copy->text) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	copy->xml_out = NULL; /* TODO: do xml string copy here */
	copy->severity = orig->severity;
	copy->next = NULL; /* do not link to original list */

	return copy;
}

bool_t is_sechk_proof_in_item(int idx, unsigned char type, sechk_item_t *item) 
{
	sechk_proof_t *proof = NULL;

	if (!item) 
		return FALSE;

	for (proof = item->proof; proof; proof = proof->next) 
		if (proof->idx == idx && proof->type == type)
			return TRUE;

	return FALSE;
}

/* static functions */

/*
 * Parse the configuration file. */
static int sechk_lib_parse_config_file(const char *filename, sechk_lib_t *lib) 
{
	xmlTextReaderPtr reader = NULL;
	int ret;
	
        /* this initializes the XML library and checks potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used. */
	LIBXML_TEST_VERSION;
	
	reader = xmlReaderForFile(filename, NULL, 0);
	if (!reader) {
		fprintf(stderr, "Error: Could not create xmlReader.");
		goto exit_err;
	}
	
	while (1) {
		ret = xmlTextReaderRead(reader);
		if (ret == -1) {
			fprintf(stderr, "Error: Error reading xml.");
			goto exit_err;
		}
		if (ret == 0) /* no more nodes to read */
			break;
		if (sechk_lib_process_xml_node(reader, lib) != 0)
			goto exit_err;
      	}

	/* cleanup function for the XML library */
	xmlCleanupParser();
	xmlFreeTextReader(reader);
	return 0;

 exit_err:
	xmlCleanupParser();
	if (reader)
		xmlFreeTextReader(reader);
	return -1;
}

/*
 * process a single node in the xml file */
static int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t *lib)
{
	xmlChar *attrib = NULL;
	int idx;
	sechk_name_value_t *nv = NULL;
	static sechk_module_t *current_module=NULL;



	switch (xmlTextReaderNodeType(reader)) {

	case XML_ELEMENT_DECL: /* closing tags */
		if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_MODULE_TAG) == 1) {
			current_module = NULL;
		} 
		break;

	case XML_ELEMENT_NODE: /* opening tags */

		if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_SECHECKER_TAG) == 1) {
			/* parsing the <sechecker> tag */
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VERSION_ATTRIB);
			if (attrib) {
				/* TODO: add version logic */
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Warning: sechecker version is not specified in configuration file.\n");
			}

		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_MODULE_TAG) == 1) {
			/* parsing the <module> tag */
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				if ((idx = sechk_lib_get_module_indx((const char*)attrib, lib)) == -1) {
					/* set the values on a new module b/c it doesn't already exist */
					if (sechk_lib_grow_modules(lib) != 0)
						goto exit_err;
					lib->num_modules++;
					assert(lib->modules && lib->num_modules >0);
					lib->modules[lib->num_modules-1].name = strdup((const char*)attrib);
					current_module = &lib->modules[lib->num_modules-1];
				} else {
					/* set the values on the existing module */
					current_module = &lib->modules[idx];
				}
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: module name is not specified in configuration file.\n");
				goto exit_err;
			}
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_OPTION_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'option' specified outside the scope of a module.\n");
				goto exit_err;
			}
			nv = sechk_name_value_new();
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				nv->name = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: option name is not specified in configuration file.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				nv->value = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: option value is not specified in configuration file.\n");
				goto exit_err;
			}

			nv->next = current_module->options;
			current_module->options = nv;
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_REQUIRE_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'require' specified outside the scope of a module.\n");
				goto exit_err;
			}
			nv = sechk_name_value_new();
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				nv->name = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: require name is not specified in configuration file.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				nv->value = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: require value is not specified in configuration file.\n");
				goto exit_err;
			}
			nv->next = current_module->requirements;
			current_module->requirements = nv;
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_DEPENDENCY_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'dependency' specified outside the scope of a module.\n");
				goto exit_err;
			}
			nv = sechk_name_value_new();
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				nv->name = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: dependency name is not specified in configuration file.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				nv->value = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: dependency value is not specified in configuration file.\n");
				goto exit_err;
			}
			nv->next = current_module->dependencies;
			current_module->dependencies = nv;
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_OUTPUT_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'output' specified outside the scope of a module.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_SHORT) == 1) {
					current_module->outputformat = SECHK_OUT_SHORT;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_QUIET) == 1) {
					current_module->outputformat = SECHK_OUT_QUIET;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_LONG) == 1) {
					current_module->outputformat = SECHK_OUT_LONG;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_VERBOSE) == 1) {
					current_module->outputformat = SECHK_OUT_VERBOSE;
				}
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: output value is not specified in configuration file.\n");
				goto exit_err;
			}
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_HEADER_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'header' specified outside the scope of a module.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderReadString(reader);
			current_module->header = strdup(attrib);
			free(attrib);
			attrib = NULL;
			
		}
		break;
	}
	return 0;

 exit_err:
	if (nv) {
		sechk_name_value_destroy(nv);
	}
	return -1;
}

/*
 * check the size and grow appropriately - the array of modules and 
 * the boolean array of selected modules */
static int sechk_lib_grow_modules(sechk_lib_t *lib)
{
	int i;

	if (lib == NULL)
		return -1;
	/* check if we need to grow */
	if (lib->modules_size <= lib->num_modules) {
		/* first grow the modules array */
		lib->modules = (sechk_module_t*)realloc(lib->modules, sizeof(sechk_module_t) * (lib->modules_size + LIST_SZ));
		if (!lib->modules) {
			fprintf(stderr, "Error: out of memory.\n");
			return -1;
		}
		/* then grow the selection array */
		lib->module_selection = (bool_t*)realloc(lib->module_selection, sizeof(bool_t) * (lib->modules_size + LIST_SZ));

		/* initialize any newly allocated memory */
		for (i = lib->num_modules; i < lib->num_modules + LIST_SZ; i++) {
			lib->module_selection[i] = FALSE;
			memset(&lib->modules[i], 0,  sizeof(sechk_module_t));
		}
		lib->modules_size += LIST_SZ;
	}
	return 0;
}

/*
 * get the index of a module in the library by name */
static int sechk_lib_get_module_indx(const char *name, sechk_lib_t *lib)
{
	int i;
	if (lib == NULL || lib->modules == NULL)
		return -1;
	for (i=0; i < lib->num_modules; i++) {
		if (lib->modules[i].name && strcmp(name, lib->modules[i].name) == 0)
			return i;
	}
	return -1;
}
