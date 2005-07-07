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

/* xml parser tags and attributes */
#define PARSE_SECHECKER_TAG      (xmlChar*)"sechecker"
#define PARSE_MODULE_TAG         (xmlChar*)"module"
#define PARSE_OPTION_TAG         (xmlChar*)"option"
#define PARSE_VALUE_ATTRIB       (xmlChar*)"value"
#define PARSE_NAME_ATTRIB        (xmlChar*)"name"
#define PARSE_VERSION_ATTRIB     (xmlChar*)"version"

/* static methods */
static int sechk_lib_parse_config_file(const char *filename, sechk_lib_t *lib);
static int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t *lib);
static int sechk_lib_grow_modules(sechk_lib_t *lib);
static int sechk_lib_get_module_indx(const char *name, sechk_lib_t *lib);

/* 'public' methods */
sechk_lib_t *sechk_lib_new(const char *policyfilelocation, const char *fcfilelocation) 
{
	sechk_lib_t *lib = NULL;
	char *default_policy_path = NULL;
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
	/* TODO: fc file */
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
			free_fn = sechk_lib_get_module_function(lib->modules[i].name, "free", lib);
			sechk_module_free(&lib->modules[i], free_fn);
		}
		free(lib->modules);
		lib->modules_size = 0;
		lib->num_modules = 0;
	}
	if (lib->fc_entries) {
		for (i = 0; i < lib->num_fc_entries; i++)
			fscon_free(&lib->fc_entries[i]);
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

		free(module->name);
		sechk_result_free(module->result);
		sechk_name_value_free(module->options);
		sechk_name_value_free(module->requirements);
		sechk_name_value_free(module->dependencies);
	if (module->data) {
		assert(free_fn);
		free_fn(module);
	}
	sechk_fn_free(module->functions);
}

void sechk_fn_free(sechk_fn_t *fn_struct)
{
	sechk_fn_t *next_fn_struct = NULL;

	if (!fn_struct)
		return;

	while(fn_struct) {
		next_fn_struct = fn_struct->next;
		free(fn_struct->name);
		/* NEVER free (*fn_struct)->fn */
		free(fn_struct);
		fn_struct = next_fn_struct;
	}
}

void sechk_name_value_free(sechk_name_value_t *opt)
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
	if (lib->num_modules != sechk_register_get_num_modules()) {
		printf("%d\n%d\n", lib->num_modules, sechk_register_get_num_modules());
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
		init_fn = (sechk_init_fn_t)sechk_lib_get_module_function(lib->modules[i].name, "init", lib);
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
	int i, retv, success = 0;
	sechk_run_fn_t run_fn = NULL;

	for (i = 0; i < lib->num_modules; i++) {
		/* if module is "off" do not run unless requested by another module */
		if (!lib->module_selection[i])
			continue;
		assert(lib->modules[i].name);
		run_fn = (sechk_run_fn_t)sechk_lib_get_module_function(lib->modules[i].name, "run", lib);
		if (!run_fn) {
			fprintf(stderr, "Error: could not run module %s\n", lib->modules[i].name);
			return -1;
		}
		retv = run_fn(&(lib->modules[i]), lib->policy);
		if (retv) {
			fprintf(stderr, "Error: module %s failed\n", lib->modules[i].name);
			success++;
		}
	}

	return success;
}

int sechk_item_sev(sechk_item_t *item)
{
	sechk_proof_t *proof = NULL;
	int sev = SECHK_SEV_NONE;

	if (!item)
		return SECHK_SEV_NONE;

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
	sechk_name_value_t *option;
	static sechk_module_t *current_module=NULL;

	switch (xmlTextReaderNodeType(reader)) {

	case XML_ELEMENT_DECL: /* closing tags */
		if (xmlStrEqual(xmlTextReaderConstName(reader), PARSE_MODULE_TAG) == 1)
			current_module = NULL;
		break;

	case XML_ELEMENT_NODE: /* opening tags */

		if (xmlStrEqual(xmlTextReaderConstName(reader), PARSE_SECHECKER_TAG) == 1) {
			/* parsing the <sechecker> tag */
			attrib = xmlTextReaderGetAttribute(reader, PARSE_VERSION_ATTRIB);
			if (attrib) {
				/* TODO: add version logic */
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Warning: sechecker version is not specified in configuration file.\n");
			}

		} else if (xmlStrEqual(xmlTextReaderConstName(reader), PARSE_MODULE_TAG) == 1) {
			/* parsing the <module> tag */
			attrib = xmlTextReaderGetAttribute(reader, PARSE_NAME_ATTRIB);
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
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), PARSE_OPTION_TAG) == 1) {
			/* parsing the <option> tag within a module */
			option = sechk_name_value_new();
			attrib = xmlTextReaderGetAttribute(reader, PARSE_NAME_ATTRIB);
			if (attrib) {
				option->name = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: option name is not specified in configuration file.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, PARSE_VALUE_ATTRIB);
			if (attrib) {
				option->value = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: option value is not specified in configuration file.\n");
				goto exit_err;
			}
			if (!current_module) {
				fprintf(stderr, "Error: option specified outside the scope of a module.\n");
				goto exit_err;
			}
			option->next = current_module->options;
			current_module->options = option;
		}
		break;
	}
	return 0;

 exit_err:
	/* NOTE: don't free the module pointer b/c it references a index in the array */
	if (attrib)
		free(attrib);
	if (option) {
		sechk_name_value_free(option);
		free(option);
	}
	return -1;
}

/*
 * check the size and grow appropriately - the array of modules and 
 * the boolean array of selected modules */
static int sechk_lib_grow_modules(sechk_lib_t *lib)
{
	const int GROW_SIZE=1;
	int i;

	if (lib == NULL)
		return -1;
	/* check if we need to grow */
	if (lib->modules_size <= lib->num_modules) {
		/* first grow the modules array */
		lib->modules = (sechk_module_t*)realloc(lib->modules, sizeof(sechk_module_t) * (lib->modules_size + GROW_SIZE));
		if (!lib->modules) {
			fprintf(stderr, "Error: out of memory.\n");
			return -1;
		}
		/* then grow the selection array */
		lib->module_selection = (bool_t*)realloc(lib->module_selection, sizeof(bool_t) * (lib->modules_size + GROW_SIZE));

		/* initialize any newly allocated memory */
		for (i = lib->num_modules; i < lib->num_modules + GROW_SIZE; i++) {
			lib->module_selection[i] = FALSE;
			memset(&lib->modules[i], 0,  sizeof(sechk_module_t));
		}
		lib->modules_size += GROW_SIZE;
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
