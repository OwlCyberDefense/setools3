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
#include <errno.h>
#ifdef LIBSEFS
#include "file_contexts.h"
#endif

#ifdef LIBSELINUX
#include <selinux/selinux.h>
#endif

static const char *sechk_severities[] = { "None", "Low", "Medium", "High" };

/* this is where we define the known profiles */
static sechk_name_value_t known_profiles[] = { 
	{"development","devel-checks.sechecker"},
	{"analysis","analysis-checks.sechecker"}
};
static int num_known_profiles = 2;

/* exported functions */
sechk_lib_t *sechk_lib_new()
{
	sechk_lib_t *lib = NULL;
	int retv, i;
	const sechk_module_name_reg_t *reg_list;
	int num_known_modules = 0;

	/* allocate the new sechk_lib_t structure */
	lib = (sechk_lib_t*)calloc(1, sizeof(sechk_lib_t));
	if (!lib) {
		fprintf(stderr, "Error: out of memory\n");
		goto exit_err;
	}

	/* create the module array from the known modules in register list */
	num_known_modules = sechk_register_list_get_num_modules();
	reg_list = sechk_register_list_get_known_modules();
	for (i = 0; i < num_known_modules; i++) {
		if (sechk_lib_grow_modules(lib) != 0)
			goto exit_err;
		lib->num_modules++;
		assert(lib->modules && lib->num_modules > 0);
		lib->modules[lib->num_modules-1].name = strdup(reg_list[i].name);
	}

	/* set the default output format */
	lib->outputformat = SECHK_OUT_SHORT;

	/* register modules */
	if ((retv = sechk_lib_register_modules(reg_list, lib)) != 0)
		goto exit_err;
exit:
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

/* this function will create a new name value struct and append it to the list */
sechk_name_value_t *sechk_name_value_prepend(sechk_name_value_t *list,const char *name,const char *value)
{
	sechk_name_value_t *new_nv = NULL;
	if (!name || !value)
		return list;
	new_nv = sechk_name_value_new();
	new_nv->name = strdup(name);
	new_nv->value = strdup(value);
	new_nv->next = list;
	return new_nv;
}

/*
 * check the size and grow appropriately - the array of modules and 
 * the boolean array of selected modules */
int sechk_lib_grow_modules(sechk_lib_t *lib)
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

int sechk_lib_load_policy(const char *policyfilelocation, sechk_lib_t *lib)
{
	
	char *default_policy_path = NULL;
	int retv = -1;
	if (!lib)
		return -1;

	/* if no policy is given, attempt to find default */
	if (!policyfilelocation) {
		retv = find_default_policy_file((POL_TYPE_SOURCE|POL_TYPE_BINARY), &default_policy_path);
		if (retv) {
			fprintf(stderr, "Error: could not find default policy\n");
			return -1;
		}
		retv = open_policy(default_policy_path, &(lib->policy));
		if (retv) {
			fprintf(stderr, "Error: failed opening default policy\n");
			return -1;
		}
		lib->policy_path = strdup(default_policy_path);
		if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
			fprintf(stderr,"Using policy: %s\n",lib->policy_path);
		}
	} else {
		retv = open_policy(policyfilelocation, &(lib->policy));
		if (retv) {
			fprintf(stderr, "Error: failed opening policy %s\n", policyfilelocation);
			return -1;
		}
		lib->policy_path = strdup(policyfilelocation);
	}
	return 0;
}

#ifdef LIBSEFS
int sechk_lib_load_fc(const char *fcfilelocation, sechk_lib_t *lib)
{
	int retv = -1;
	char *default_fc_path = NULL;

	/* if no policy we can't parse the fc file */
	if (!lib->policy || !lib)
		return -1;

	/* if no file_contexts file is given attempt to find the default */
	if (!fcfilelocation) {
		retv = find_default_file_contexts_file(&default_fc_path);
		if (retv) {
			fprintf(stderr, "Warning: unable to find default file_contexts file\n");
			return -1;
		}
		retv = parse_file_contexts_file(default_fc_path, &(lib->fc_entries), &(lib->num_fc_entries), lib->policy);
		if (retv) {
			fprintf(stderr, "Warning: unable to process file_contexts file\n");
			return -1;
		} else {
			lib->fc_path = strdup(default_fc_path);
		}
		if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
			fprintf(stderr,"Using file contexts: %s\n",lib->fc_path);
		}
	} else {
		retv = parse_file_contexts_file(fcfilelocation, &(lib->fc_entries), &(lib->num_fc_entries), lib->policy);
		if (retv) {
			fprintf(stderr, "Warning: unable to process file_contexts file\n");
			return -1;
		} else {
			lib->fc_path = strdup(fcfilelocation);
		}
	}
	free(default_fc_path);

	return 0;
}
#endif


int sechk_lib_register_modules(const sechk_module_name_reg_t *register_fns, sechk_lib_t *lib) 
{
	int i, retv;
	sechk_register_fn_t fn = NULL;
	if (!register_fns || !lib) {
		fprintf(stderr, "Error: could not register modules\n");
		return -1;
	}
	if (lib->num_modules != sechk_register_list_get_num_modules()) {
		fprintf(stderr, "Error: the number of registered modules (%d) does not match the number of modules in the configuration file (%d).\n", sechk_register_list_get_num_modules(), lib->num_modules);
		return -1;
	}
	for (i = 0; i < lib->num_modules; i++) {
		fn = (sechk_register_fn_t)(register_fns[i].fn);
		retv = fn(lib);
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
				/* if we're in quiet mode then we quit on a failed requirement */
				if (lib->outputformat & (SECHK_OUT_QUIET)) {
					return -1;
					
				} else {
					/* otherwise we just disable this module and keep testing */
					printf("Error: requirements not met for %s\n", lib->modules[i].name);					
					lib->module_selection[i] = FALSE;
					break;
				}
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
	       
		if (retv < 0) {
			/* module failure */
			/* only put output failures if we are not in quiet mode */
			if (lib->outputformat & ~(SECHK_OUT_QUIET)) 
				fprintf(stderr, "Error: module %s failed\n", lib->modules[i].name);
			rc = -1;
		} else if (retv > 0) {
			/* a module looking for policy errors has found one */
			if (lib->outputformat & (SECHK_OUT_QUIET)) 
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
				/* as long as we're not in quiet mode print output */
				if (lib->outputformat & ~(SECHK_OUT_QUIET))
					fprintf(stderr, "Error: module required source policy but was given binary\n");
				return FALSE;
			}
		} else if (!strcmp(req->value, SECHK_PARSE_REQUIRE_POL_TYPE_BIN)) {
			if (!is_binary_policy(lib->policy)) {
				/* as long as we're not in quiet mode print output */
				if (lib->outputformat & ~(SECHK_OUT_QUIET))
					fprintf(stderr, "Error: module required binary policy but was given source\n");
				return FALSE;
			}
		} else {
			/* as long as we're not in quiet mode print output */
			if (lib->outputformat & ~(SECHK_OUT_QUIET))
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
			/* as long as we're not in quiet mode print output */
			if (lib->outputformat & ~(SECHK_OUT_QUIET))				
				fprintf(stderr, "Error: module requires newer policy version\n");
			return FALSE;
		}
	} else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_SELINUX)) {
#ifdef LIBSELINUX
		if (!is_selinux_enabled()) {
			/* as long as we're not in quiet mode print output */
			if (lib->outputformat & ~(SECHK_OUT_QUIET))				
				fprintf(stderr, "Error: module requires selinux system\n");
			return FALSE;
		}
#else
		/* as long as we're not in quiet mode print output */
		if (lib->outputformat & ~(SECHK_OUT_QUIET))
			fprintf(stderr, "Error: module requires selinux system, but SEChecker was not built to support system checks\n");
		return FALSE;
#endif
	} else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_MLS_POLICY)) {
		if (lib->policy->version != POL_VER_19MLS) {
			/* as long as we're not in quiet mode print output */
			if (lib->outputformat & ~(SECHK_OUT_QUIET))
				fprintf(stderr, "Error: module requires MLS policy\n");
			return FALSE;
		}
	} else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_MLS_SYSTEM)) {
#ifdef LIBSELINUX
		if (!is_selinux_mls_enabled() || !is_selinux_enabled()) {
			/* as long as we're not in quiet mode print output */
			if (lib->outputformat & ~(SECHK_OUT_QUIET))
				fprintf(stderr, "Error: module requires MLS enabled selinux system\n");
			return FALSE;
		}
#else
		/* as long as we're not in quiet mode print output */
		if (lib->outputformat & ~(SECHK_OUT_QUIET))
			fprintf(stderr, "Error: module requires selinux system, but SEChecker was not built to support system checks\n");
		return FALSE;
#endif
	} else {
		/* as long as we're not in quiet mode print output */
		if (lib->outputformat & ~(SECHK_OUT_QUIET))			
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
const char *sechk_item_sev(sechk_item_t *item)
{
	sechk_proof_t *proof = NULL;
	int sev = SECHK_SEV_NONE;

	if (item) {
		/* the severity of an item is equal to
		 * the highest severity among its proof elements */
		for (proof = item->proof; proof; proof = proof->next)
			if (proof->severity > sev)
				sev = proof->severity;
	}
	return sechk_severities[sev];

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

	/* try to find the profile in our known profiles */
	for (i = 0; i < num_known_profiles; i++) {
		if (strcmp(known_profiles[i].name,prof_name) == 0) {
			break;
		}
	}
	/* this is a known installed profile, look for it in that directory */
	if (i < num_known_profiles) {
		/* first look in the local subdir using just PROF_SUBDIR/profile */
		prof_filename = (char *)calloc(strlen(known_profiles[i].value)+4+strlen(PROF_SUBDIR),sizeof(char));
		if (!prof_filename) {
			fprintf(stderr, "Error: out of memory\n");
			return -1;
		}
		sprintf(prof_filename,"%s/%s",PROF_SUBDIR,known_profiles[i].value);		
		path = find_file(prof_filename);
		if (!path) {
			free(prof_filename);
			prof_filename = NULL;
			prof_filename = (char *)calloc(strlen(PROFILE_INSTALL_DIR)+strlen(known_profiles[i].value)+4,sizeof(char));
			if (!prof_filename) {
				fprintf(stderr, "Error: out of memory\n");
				return -1;
			}
			sprintf(prof_filename,"%s/%s",PROFILE_INSTALL_DIR,known_profiles[i].value);		
			path = find_file(prof_filename);
			if (!path) {
				fprintf(stderr,"Error: Unable to find path\n");
				goto sechk_load_profile_error;
			}
		}
		
		/* concatenate path and filename */
		profpath = (char*)calloc(3 + strlen(path) + strlen(prof_filename), sizeof(char));
		if (!profpath) {
			fprintf(stderr, "Error: out of memory\n");
			goto sechk_load_profile_error;
		}
		sprintf(profpath,"%s/%s",path,prof_filename);
		free(path);
		free(prof_filename);
		path = NULL;
		prof_filename = NULL;
	} else {
		profpath = strdup(prof_name);
	}

	/* parse the profile */
	retv = sechk_lib_parse_profile(profpath, lib);
	if (retv) {
		retv = errno;
		fprintf(stderr, "Error: could not parse profile\n");
		goto sechk_load_profile_error;
	}
	
	/* turn off output for any unselected modules */
	for (i = 0; i < lib->num_modules; i++) {
		if (!lib->module_selection[i])
			lib->modules[i].outputformat = SECHK_OUT_NONE;
	}
	
	free(profpath);
	free(prof_filename);
	free(path);
	return 0;
	
sechk_load_profile_error:
	free(profpath);
	free(prof_filename);
	free(path);
	if (retv)
		errno = retv;
	return -1;
}

int sechk_lib_module_add_option_list(sechk_module_t *module, sechk_name_value_t *options)
{
	sechk_name_value_t *cur = NULL;
	if (!module || !options)
		return -1;
	cur = options;
	while (cur->next)
		cur = cur->next;
	cur->next = module->options;
	module->options = cur;
	return 0;
}

static sechk_name_value_t *sechk_lib_del_option_list_recursive(sechk_name_value_t *cur,char *option)
{
	sechk_name_value_t *next = NULL;
	if (!cur)
		return NULL;
	if (strcmp(cur->name,option) == 0) {
		free(cur->name);
		free(cur->value);
		next = cur->next;
		free(cur);
		return sechk_lib_del_option_list_recursive(next,option);
	} else {
		cur->next = sechk_lib_del_option_list_recursive(cur->next,option);
		return cur;
	}
}

int sechk_lib_module_del_option(sechk_module_t *module,char *option)
{
	module->options = sechk_lib_del_option_list_recursive(module->options,option);
	return 0;
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

char **sechk_lib_get_profiles(int *num_profiles)
{
	char **names = NULL;
	*num_profiles = num_known_profiles;
	int i;
	if (num_known_profiles > 0) {
		names = (char **)calloc(num_known_profiles,sizeof(char *));
		for (i = 0; i < num_known_profiles; i++) 
			names[i] = strdup(known_profiles[i].name);
	}
	return names;

}
