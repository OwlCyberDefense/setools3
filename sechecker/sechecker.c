 /* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 * sechecker.c
 *
 */

#include "policy.h"
#include "policy-io.h"
#include "sechecker.h"
#include "util.h"

#include <stdio.h>
#include <string.h> 

sechk_lib_t *new_sechk_lib(char *policyfilelocation, char *conffilelocation, unsigned char output_override) 
{
	sechk_lib_t *lib = NULL;
	char *default_policy_path = NULL, *confpath = NULL, *confdir = NULL, *tmp = NULL;
	int retv, size;
	FILE *conffile = NULL;

	/* if conffile path is not given, check default locations */
	if (!conffilelocation) {
		confdir = find_user_config_file(".sechecker.conf");
		if (!confdir) {
			confpath = find_file("sechecker.conf");
			if (!confpath) {
				fprintf(stderr, "Error: could not find config file\n");
				goto new_lib_fail;
			}
		} else {
			confpath = (char*)calloc(1 + strlen(confdir) + strlen("/.sechecker.conf"), sizeof(char));
			if (!confpath) {
				fprintf(stderr, "Error: out of memory\n");
				goto new_lib_fail;
			}
			strcat(confpath, confdir);
			strcat(confpath, "/.sechecker.conf");
			free(confdir);
			confdir = NULL;
		}
	} else {
		confpath = strdup(conffilelocation);
	}
	
	/* open conf file */
	conffile = fopen(confpath, "r");
	if (!conffile) {
		fprintf(stderr, "Error: could not open config file (%s)\n", confpath);
		goto new_lib_fail;
	}
	free(confpath);
	confpath = NULL;

	lib = (sechk_lib_t*)calloc(1, sizeof(sechk_lib_t));
	if (!lib) {
		fprintf(stderr, "Error: out of memory\n");
		goto new_lib_fail;
	}
	lib->conf = new_sechk_conf();
	if (!(lib->conf)) {
		fprintf(stderr, "Error: out of memory\n");
		goto new_lib_fail;
	}


	/* if no policy is given, attempt to find default */
	if (!policyfilelocation) {
		retv = find_default_policy_file((POL_TYPE_SOURCE|POL_TYPE_BINARY), &default_policy_path);
		if (retv) {
			fprintf(stderr, "Error: could not find default policy\n");
			goto new_lib_fail;
		}
		retv = open_policy(default_policy_path, &(lib->policy));
		if (retv) {
			fprintf(stderr, "Error: failed opening default polciy\n");
			goto new_lib_fail;
		}
		tmp = strstr(default_policy_path, "/src/policy/policy.");
		if (!tmp) {
			tmp = strstr(default_policy_path, "/policy/policy.");
		}
		if (!tmp) {
			tmp = strstr(default_policy_path, "/policy.");
		}
		if (tmp) {
			size = strlen(default_policy_path) - strlen(tmp);
			policyfilelocation = (char*)strndup(default_policy_path, size);
		}
		lib->conf->policy_src_tree_path = policyfilelocation;
	} else {
		if (policyfilelocation[strlen(policyfilelocation)-1] == '/')
			policyfilelocation[strlen(policyfilelocation)-1] = '\0';
		default_policy_path = (char*)calloc(1+strlen(policyfilelocation)+strlen("/src/policy/policy.conf"), sizeof(char));
		if (!default_policy_path) {
			fprintf(stderr, "Error: out of memory\n");
			goto new_lib_fail;
		}
		strcat(default_policy_path, policyfilelocation);
		strcat(default_policy_path, "/src/policy/policy.conf");
		retv = open_policy(default_policy_path, &(lib->policy));
		if (retv) {
			fprintf(stderr, "Error: failed to open policy %s\n", policyfilelocation);
			goto new_lib_fail;
		}
		lib->conf->policy_src_tree_path = strdup(policyfilelocation);
	}

fprintf(stderr, "loc: %s\n", lib->conf->policy_src_tree_path);
	retv = parse_config_file(conffile, output_override, lib);
	if (retv) {
		fprintf(stderr, "Error: config file parsing failed\n");
		goto new_lib_fail;
	}

	fclose(conffile);
	free(default_policy_path);
	return lib;

new_lib_fail:
	free_sechk_lib(&lib);
	free(confdir);
	free(confpath);
	free(default_policy_path);
	if (conffile)
		fclose(conffile);
	return NULL;
}

int parse_config_file(FILE *conffile, unsigned char output_override, sechk_lib_t *lib) 
{
	if (!conffile || !lib) {
		fprintf(stderr, "parse_config_file failed: invalid parameters\n");
		return -1;
	}

	/* TODO: parse XML here */

	return 0;
}

void free_sechk_lib(sechk_lib_t **lib) 
{
	if (!lib || !(*lib))
		return;

	free_sechk_conf(&((*lib)->conf));
	free_policy(&((*lib)->policy));
	free_modules(*lib);
	free((*lib)->modules);
	free(*lib);
	*lib = NULL;
}

void free_sechk_fn(sechk_fn_t **fn_struct)
{
	sechk_fn_t *next_fn_struct = NULL;

	if (!fn_struct || !(*fn_struct))
		return;

	while(*fn_struct) {
		next_fn_struct = (*fn_struct)->next;
		free((*fn_struct)->name);
		/* NEVER free (*fn_struct)->fn */
		free(*fn_struct);
		*fn_struct = next_fn_struct;
	}
}

void free_sechk_opt(sechk_opt_t **opt)
{
	sechk_opt_t *next_opt = NULL;

	if (!opt || (*opt))
		return;

	while(*opt) {
		next_opt = (*opt)->next;
		free((*opt)->name);
		free((*opt)->value);
		free(*opt);
		*opt = next_opt;
	}
}

void free_sechk_result(sechk_result_t **res) 
{
	if (!res || !(*res))
		return;
	
	free((*res)->test_name);
	free_sechk_item(&((*res)->items));
	free(*res);
	*res = NULL;
}

void free_sechk_item(sechk_item_t **item) 
{
	sechk_item_t *next_item = NULL;

	if (!item || !(*item))
		return;

	while(*item) {
		next_item = (*item)->next;
		free_sechk_proof(&((*item)->proof));
		free(*item);
		*item = next_item;
	}
}

void free_sechk_proof(sechk_proof_t **proof) 
{
	sechk_proof_t *next_proof = NULL;

	if (!proof || !(*proof))
		return;

	while(*proof) {
		next_proof = (*proof)->next;
		free((*proof)->text);
		free((*proof)->xml_out);
		free(*proof);
		*proof = next_proof;
	}
}

void free_sechk_conf(sechk_conf_t **conf) 
{
	if (!conf || !(*conf))
		return;

	free((*conf)->selinux_config_path);
	free((*conf)->policy_src_tree_path);
	free((*conf)->module_selection);

	free(*conf);
	*conf = NULL;
}

sechk_fn_t *new_sechk_fn(void) 
{
	/* no initialization needed here */
	return (sechk_fn_t*)calloc(1, sizeof(sechk_fn_t));
}

sechk_opt_t *new_sechk_opt(void)
{
	/* no initialization needed here */
	return (sechk_opt_t*)calloc(1, sizeof(sechk_opt_t));
}

sechk_result_t *new_sechk_result(void) 
{
	/* initilization to zero is sufficient here */
	return (sechk_result_t*)calloc(1, sizeof(sechk_result_t));
}

sechk_item_t *new_sechk_item(void) 
{
	sechk_item_t *item = NULL;
	item = (sechk_item_t*)calloc(1, sizeof(sechk_item_t));
	if (!item)
		return NULL;
	item->item_id = -1;
	return item;
}

sechk_proof_t *new_sechk_proof(void) 
{
	sechk_proof_t *proof = NULL;
	proof = (sechk_proof_t*)calloc(1, sizeof(sechk_proof_t));
	if (!proof)
		return NULL;
	proof->idx = -1;
	return proof;
}

sechk_conf_t *new_sechk_conf(void) 
{
	/* zero initilization is sufficient */
	return (sechk_conf_t*)calloc(1, sizeof(sechk_conf_t));
}

int register_modules(sechk_register_fn_t *register_fns, sechk_lib_t *lib) 
{
	int i, retv;

	if (!register_fns || !lib) {
		fprintf(stderr, "Error: could not register modules\n");
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

void *get_module_function(char *module_name, char *function_name, sechk_lib_t *lib) 
{
	int i;
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!module_name || !function_name || !lib) {
		fprintf(stderr, "Error: failed to get function from module\n");
		return NULL;
	}

	/* find the correct module */
	for (i = 0; i < lib->num_modules; i++) {
		if (!lib->modules[i].name)
			continue;
		if (!strcmp(lib->modules[i].name, module_name)) {
			mod = &(lib->modules[i]);
			break;
		}
	}
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

sechk_module_t *get_module(char *module_name, sechk_lib_t *lib) 
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

int init_modules(sechk_lib_t *lib) 
{
	int i, retv;
	sechk_init_fn_t init_fn = NULL;

	for (i = 0; i < lib->num_modules; i++) {
		init_fn = (sechk_init_fn_t)get_module_function(lib->modules[i].name, "init", lib);
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

int run_modules(unsigned char run_mode, sechk_lib_t *lib) 
{
	int i, retv;
	sechk_run_fn_t run_fn = NULL;

	for (i = 0; i < lib->num_modules; i++) {
fprintf(stderr, "run %i\n", i);
		/* if module is "off" do not run unless requested by another module */
		if (!lib->conf->module_selection[i])
			continue;
		if (!(lib->modules[i].type & run_mode))
			continue;
		run_fn = (sechk_run_fn_t)get_module_function(lib->modules[i].name, "run", lib);
		if (!run_fn) {
			fprintf(stderr, "Error: could not run module %s\n", lib->modules[i].name);
			return -1;
		}
		retv = run_fn(&(lib->modules[i]), lib->policy);
		if (retv)
			return retv;
	}

	return 0;
}

void free_modules(sechk_lib_t *lib) 
{
	int i;
	sechk_free_fn_t free_fn = NULL;

	if (!lib->modules)
		return;

	for (i = 0; i < lib->num_modules; i++) {
		free_fn = (sechk_free_fn_t)get_module_function(lib->modules[i].name, "free", lib);
		if (!free_fn) {
			fprintf(stderr, "Error: could not free module %s\n", lib->modules[i].name);
			return;
		}
		free_fn(&(lib->modules[i]));
	}

	return;
}

int intlen(int n)
{
	int i = 1;
	if (i < 0) {
		i++;
		n *= -1;
	}
	while (n > 10) {
		n /= 10;
		i++;
	}
	return i;
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

	copy = new_sechk_proof();
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
