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
#include "sechk_parse.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <policy.h>
#include <policy-io.h>
#include <util.h>
#include <dirent.h>
#ifdef LIBSEFS
#include "file_contexts.h"
#endif

#ifdef LIBSELINUX
#include <selinux/selinux.h>
#endif

/* 'public' methods */
#ifdef LIBSEFS
sechk_lib_t *sechk_lib_new(const char *policyfilelocation, const char *fcfilelocation)
#else
sechk_lib_t *sechk_lib_new(const char *policyfilelocation)
#endif
{
	sechk_lib_t *lib = NULL;
	char *default_policy_path = NULL;
#ifdef LIBSEFS
	char *default_fc_path = NULL;
#endif
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

#ifdef LIBSEFS
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
#endif

exit:
	free(default_policy_path);
	free(conf_path);
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
#ifdef LIBSEFS
	if (lib->fc_entries) {
		for (i = 0; i < lib->num_fc_entries; i++)
			sefs_fc_entry_free(&lib->fc_entries[i]);
		lib->num_fc_entries = 0;
		free(lib->fc_entries);
	}
	free(lib->fc_path);
#endif
	free(lib->selinux_config_path);
	free(lib->policy_path);
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
		fprintf(stderr, "Error: the number of registered modules (%d) does not match the number of modules in the configuration file (%d).\n", sechk_register_list_get_num_modules(), lib->num_modules);
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

int sechk_lib_check_module_dependencies(sechk_lib_t *lib)
{
	int i, idx = 0;
	bool_t test = TRUE, done = FALSE, *processed = NULL;
	sechk_name_value_t *nv = NULL;

	if (!lib) {
		fprintf(stderr, "Error: invalid module library\n");
		return -1;
	}

	processed = (bool_t*)calloc(lib->num_modules, sizeof(bool_t));
	if (!processed) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}

	/* check dependencies and select dependencies to be run */
	while (!done) {
		for (i = 0; i < lib->num_modules; i++) {
			if (processed[i])
				continue;
			if (!lib->module_selection[i]) {
				processed[i] = TRUE;
				continue;
			}
			nv = lib->modules[i].dependencies;
			while (nv) {
				test = FALSE;
				test = sechk_lib_check_dependency(nv, lib);
				if (!test) {
					fprintf(stderr, "Error: dependency %s not found for %s\n", nv->name, lib->modules[i].name);
					free(processed);
					return -1;
				}
				idx = sechk_lib_get_module_idx(nv->value, lib);
				if (!lib->module_selection[idx]) {
					processed[idx] = FALSE;
					lib->module_selection[idx] = TRUE;
				}
				nv = nv->next;
			}
			processed[i] = TRUE;
		}
		for (i = 0; i < lib->num_modules; i++) {
			if (!processed[i])
				break;
		}
		if (i == lib->num_modules)
			done = TRUE;
	}
	free(processed);

	return 0;
}

int sechk_lib_check_module_requirements(sechk_lib_t *lib)
{
	int i;
	bool_t test = TRUE;
	sechk_name_value_t *nv = NULL;

	/* check requirements for all selected modules */
	for (i = 0; i < lib->num_modules; i++) {
		if (!lib->module_selection[i])
			continue;
		nv = lib->modules[i].requirements;
		while (nv) {
			test = FALSE;
			test = sechk_lib_check_requirement(nv, lib);
			if (!test) {
				fprintf(stderr, "Error: requirements not met for %s\n", lib->modules[i].name);
				return -1;
			}
			nv = nv->next;
		}
	}

	return 0;
}

int sechk_lib_init_modules(sechk_lib_t *lib)
{
	int i, retv;
	sechk_init_fn_t init_fn = NULL;

	if (lib == NULL || lib->modules == NULL)
		return -1;
	for (i = 0; i < lib->num_modules; i++) {
		if (!lib->module_selection[i])
			continue;
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

	return rc;
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
		return FALSE;
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
		return FALSE;
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
		if (lib->modules[i].outputformat) /* if outputformat=none leave as none */
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

sechk_item_t *sechk_result_get_item(int item_id, unsigned char item_type, sechk_result_t *res)
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

sechk_proof_t *sechk_proof_copy(sechk_proof_t *orig)
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

bool_t sechk_item_has_proof(int idx, unsigned char type, sechk_item_t *item) 
{
	sechk_proof_t *proof = NULL;

	if (!item) 
		return FALSE;

	for (proof = item->proof; proof; proof = proof->next) 
		if (proof->idx == idx && proof->type == type)
			return TRUE;

	return FALSE;
}

int sechk_lib_load_profile(const char *prof_name, sechk_lib_t *lib)
{
	char *profpath = NULL, *prof_filename = NULL, *path = NULL;
	int retv, i;

	if (!prof_name || !lib) {
		fprintf(stderr, "Error: invalid parameters to load profile\n");
		return -1;
	}

	/* translate profile name into filename */
	prof_filename = (char*)calloc(1 + strlen(PROF_SUBDIR) + strlen(prof_name) + strlen(".sechecker"), sizeof(char));
	if (!prof_filename) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	strcat(prof_filename, PROF_SUBDIR);
	strcat(prof_filename, prof_name);
	strcat(prof_filename, ".sechecker");

	/* find the file */
	path = find_file(prof_filename);
	if (!path) {
		fprintf(stderr, "Error: could not find profile %s.\n", prof_name);
		goto sechk_load_profile_error;
	}

	/* concatenate path and filename */
	profpath = (char*)calloc(1 + strlen(path) + strlen(prof_filename), sizeof(char));
	if (!profpath) {
		fprintf(stderr, "Error: out of memory\n");
		goto sechk_load_profile_error;
	}
	strcat(profpath, path);
	strcat(profpath, prof_filename);

	/* parse the profile */
	retv = sechk_lib_parse_profile(profpath, lib);
	if (retv) {
		fprintf(stderr, "Error: parse error in profile\n");
		goto sechk_load_profile_error;
	}

	/* turn off output for any unselected modules */
	for (i = 0; i < lib->num_modules; i++) {
		if (!lib->module_selection[i])
			lib->modules[i].outputformat = SECHK_OUT_NONE;
	}

	free(prof_filename);
	free(path);
	free(profpath);
	return 0;

sechk_load_profile_error:
	free(prof_filename);
	free(path);
	free(profpath);
	return -1;
}

/* get the index of a module in the library by name */
int sechk_lib_get_module_idx(const char *name, sechk_lib_t *lib)
{
	int i;
	if (!name || !lib || !lib->modules)
		return -1;
	for (i=0; i < lib->num_modules; i++) {
		if (lib->modules[i].name && strcmp(name, lib->modules[i].name) == 0)
			return i;
	}
	return -1;
}

int sechk_get_installed_profile_names(char ***names, int *num_profiles)
{
	int retv;
	DIR *prof_install_dir = NULL;
	struct dirent *entry = NULL;
	char *ext = NULL;

	if (!names || !num_profiles) {
		fprintf(stderr, "Error: invalid list storage pointer(s)\n");
		return -1;
	}

	assert(strlen(PROFILE_INSTALL_DIR));
	prof_install_dir = opendir(PROFILE_INSTALL_DIR);
	if (!prof_install_dir) {
		fprintf(stderr, "Error: unable to open %s\n", PROFILE_INSTALL_DIR);
		return -1;
	}

	*num_profiles = 0;
	*names = NULL;

	while ((entry = readdir(prof_install_dir))) {
		ext = strrchr(entry->d_name, '.');
		if (ext) {
			ext++;
			retv = strncmp(ext, "sechecker", 9);
			if (!retv) {
				ext--;
				(*num_profiles)++;
				*names = (char**)realloc(*names, *num_profiles * sizeof(char*));
				if (!(*names)) {
					fprintf(stderr, "Error: out of memory");
					closedir(prof_install_dir);
					return -1;
				}
				(*names)[*num_profiles - 1] = strndup(entry->d_name, (size_t)(ext - entry->d_name));
			}
		}
		entry = NULL;
	}

	closedir(prof_install_dir);
	return 0;
}
