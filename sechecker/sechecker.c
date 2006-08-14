 /* Copyright (C) 2005-2006 Tresys Technology, LLC
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
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <apol/policy.h>
#include <apol/util.h>
#ifdef LIBSEFS
#include <libsefs/file_contexts.h>
#endif

#ifdef LIBSELINUX
#include <selinux/selinux.h>
#endif

#include <qpol/policy_query.h>

static int sechk_lib_compare_sev(const char *a, const char *b)
{
	int aval, bval;
	
	if (a == NULL || b == NULL) {
		assert(FALSE);
		errno = EINVAL;
		return -1;
	}

	if (strcmp(a, SECHK_SEV_NONE) == 0)
		aval = 0;
	else if (strcmp(a, SECHK_SEV_LOW) == 0)
		aval = 1;
	else if (strcmp(a, SECHK_SEV_MED) == 0)
		aval = 2;
	else if (strcmp(a, SECHK_SEV_HIGH) == 0)
		aval = 3;
	else {
		assert(FALSE);
		errno = EINVAL;
		return -1;
	}

	if (strcmp(b, SECHK_SEV_NONE) == 0)
		bval = 0;
	else if (strcmp(b, SECHK_SEV_LOW) == 0)
		bval = 1;
	else if (strcmp(b, SECHK_SEV_MED) == 0)
		bval = 2;
	else if (strcmp(b, SECHK_SEV_HIGH) == 0)
		bval = 3;
	else {
		assert(FALSE);
		errno = EINVAL;
		return -1;
	}

	if (aval == bval)
		return 0;

	return aval < bval ? -1 : 1;
}

int sechk_lib_set_minsev(const char *minsev, sechk_lib_t *lib)
{
	if (lib == NULL || lib->policy == NULL || minsev == NULL) {
		assert(FALSE);
		errno = EINVAL;
		return -1;
	}
	
	if (strcmp(minsev, SECHK_SEV_LOW) == 0)
		lib->minsev = SECHK_SEV_LOW;
	else if (strcmp(minsev, SECHK_SEV_MED) == 0)
		lib->minsev = SECHK_SEV_MED;
	else if (strcmp(minsev, SECHK_SEV_HIGH) == 0)
		lib->minsev = SECHK_SEV_HIGH;
	else {
		ERR(lib->policy, "%s", "Invalid severity.");
		errno = EINVAL;
		return -1;
	}
	return 0;
}

sechk_module_t *sechk_module_new(void)
{
	sechk_module_t *mod = NULL;
	int error = 0;

	mod = calloc(1, sizeof(sechk_module_t));
	if (!mod)
		return NULL;

	/* create empty vectors */
	if (!(mod->options = apol_vector_create()) ||
		!(mod->requirements = apol_vector_create()) ||
		!(mod->dependencies = apol_vector_create()) ||
		!(mod->functions = apol_vector_create())) {
		error = errno;
		apol_vector_destroy(&mod->options, NULL);
		apol_vector_destroy(&mod->requirements, NULL);
		apol_vector_destroy(&mod->dependencies, NULL);
		apol_vector_destroy(&mod->functions, NULL);
		free(mod);
		errno = error;
		return NULL;
	}

	return mod;
}

sechk_lib_t *sechk_lib_new(void)
{
	sechk_lib_t *lib = NULL;
	int retv, error;
	const sechk_module_name_reg_t *reg_list;
	int num_known_modules = 0;
	size_t i = 0;
	sechk_module_t *tmp = NULL;

	/* allocate the new sechk_lib_t structure */
	lib = (sechk_lib_t*)calloc(1, sizeof(sechk_lib_t));
	if (!lib) {
		perror("Error creating module library");
		goto exit_err;
	}

	/* create the module array from the known modules in register list */
	num_known_modules = sechk_register_list_get_num_modules();
	reg_list = sechk_register_list_get_modules();
	lib->modules = apol_vector_create();
	if (!lib->modules) {
		error = errno;
		perror("Error adding modules");
		goto exit_err;
		
	}
	for (i = 0; i < num_known_modules; i++) {
		tmp = sechk_module_new();
		if (!tmp) {
			error = errno;
			perror("Error adding modules");
			goto exit_err;
		}
		tmp->name = strdup(reg_list[i].name);
		if (!tmp->name) {
			error = errno;
			perror("Error adding modules");
			goto exit_err;
		}
		if (apol_vector_append(lib->modules, tmp)) {
			error = errno;
			perror("Error adding modules");
			goto exit_err;
		}
		tmp = NULL;
	}

	/* set the default output format */
	lib->outputformat = SECHK_OUT_SHORT;
	lib->minsev = SECHK_SEV_LOW;

	/* register modules */
	if ((retv = sechk_lib_register_modules(reg_list, lib)) != 0) {
		error = errno;
		perror("Error registering modules");
		goto exit_err;
	}
exit:
	return lib;

exit_err:
	sechk_lib_destroy(&lib);
	sechk_module_free(tmp);
	errno = error;
	goto exit;
}

void sechk_lib_destroy(sechk_lib_t **lib) 
{
	if (lib == NULL)
		return;

	apol_vector_destroy(&((*lib)->modules), sechk_module_free);
	apol_policy_destroy(&((*lib)->policy));
#ifdef LIBSEFS
	apol_vector_destroy(&((*lib)->fc_entries), sefs_fc_entry_free);
	free((*lib)->fc_path);
#endif
	free((*lib)->selinux_config_path);
	free((*lib)->policy_path);
}

void sechk_module_free(void *module)
{
	sechk_module_t *mod = (sechk_module_t*)module;
	sechk_data_free_fn_t free_fn = NULL;

	if (!module)
		return;

	/* do not free describtin fields */
	sechk_result_destroy(&mod->result);
	apol_vector_destroy(&mod->options, sechk_name_value_free);
	apol_vector_destroy(&mod->requirements, sechk_name_value_free);
	apol_vector_destroy(&mod->dependencies, sechk_name_value_free);
	/* do not free severity */
	if (mod->data) {
		free_fn = sechk_lib_get_module_function(mod->name, SECHK_MOD_FN_FREE, mod->parent_lib);
		assert(free_fn);
		free_fn(mod->data);
	}
	free(mod->name);
	apol_vector_destroy(&mod->functions, sechk_fn_free);
	free(mod);
}

void sechk_fn_free(void *fn_struct)
{
	sechk_fn_t *fn = (sechk_fn_t*)fn_struct;
	if (!fn_struct)
		return;

	free(fn->name);
	/* NEVER free fn->fn */
	free(fn);
}

void sechk_name_value_free(void *nv)
{
	sechk_name_value_t *in = (sechk_name_value_t*)nv;
	if (!nv)
		return;

	free(in->name);
	free(in->value);
	free(nv);
}

void sechk_result_destroy(sechk_result_t **res) 
{
	if (!res || !(*res))
		return;

	free((*res)->test_name);
	apol_vector_destroy(&((*res)->items), sechk_item_free);
	free(*res);
	*res = NULL;
}

void sechk_item_free(void *item) 
{
	sechk_item_t *it = (sechk_item_t*)item;

	if (!item)
		return;

	apol_vector_destroy(&it->proof, sechk_proof_free);
	if (it->item_free_fn)
		it->item_free_fn(it->item);

	free(item);
}

void sechk_proof_free(void *proof) 
{
	sechk_proof_t *p = (sechk_proof_t*)proof;

	if (!proof)
		return;

	free(p->text);
	free(p->xml_out);

	if (p->elem_free_fn)
		p->elem_free_fn(p->elem);

	free(proof);
}

sechk_fn_t *sechk_fn_new(void) 
{
	/* no initialization needed here */
	return (sechk_fn_t*)calloc(1, sizeof(sechk_fn_t));
}

sechk_name_value_t *sechk_name_value_new(const char *name, const char *value)
{
	sechk_name_value_t *nv;
	int error;

	nv = (sechk_name_value_t*)calloc(1, sizeof(sechk_name_value_t));
	if (!nv)
		return NULL;
	if (name) {
		nv->name = strdup(name);
		if (!nv->name) {
			error = errno;
			goto err;
		}
	}
	if (value) {
		nv->value = strdup(value);
		if (!nv->value) {
			error = errno;
			goto err;
		}
	}

	return nv;

err:
	free(nv->name);
	free(nv);
	errno = error;
	return NULL;
}

sechk_result_t *sechk_result_new(void) 
{
	/* initilization to zero is sufficient here */
	return (sechk_result_t*)calloc(1, sizeof(sechk_result_t));
}

sechk_item_t *sechk_item_new(free_fn_t fn) 
{
	sechk_item_t *it = NULL;

	it = (sechk_item_t*)calloc(1, sizeof(sechk_item_t));
	if (!it)
		return NULL;
	it->item_free_fn = fn;

	return it;
}

sechk_proof_t *sechk_proof_new(free_fn_t fn) 
{
	sechk_proof_t *proof = NULL;
	proof = (sechk_proof_t*)calloc(1, sizeof(sechk_proof_t));
	if (!proof)
		return NULL;
	proof->type = SECHK_ITEM_NONE;
	proof->elem_free_fn = fn;
	return proof;
}

int sechk_lib_load_policy(const char *policyfilelocation, sechk_lib_t *lib)
{
	
	char *default_policy_path = NULL;
	int retv = -1;
	if (!lib)
		return -1;

	/* if no policy is given, attempt to find default */
	if (!policyfilelocation) {
		retv = qpol_find_default_policy_file((QPOL_TYPE_SOURCE|QPOL_TYPE_BINARY), &default_policy_path);
		if (retv) {
			fprintf(stderr, "Error: %s\n", qpol_find_default_policy_file_strerr(retv));
			return -1;
		}
		retv = apol_policy_open(default_policy_path, &(lib->policy), NULL);
		if (retv) {
			fprintf(stderr, "Error: failed opening default policy\n");
			return -1;
		}
		lib->policy_path = strdup(default_policy_path);
		if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
			fprintf(stderr,"Using policy: %s\n",lib->policy_path);
		}
	} else {
		retv = apol_policy_open(policyfilelocation, &(lib->policy), NULL);
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
	int retv = -1, error = 0;
	char *default_fc_path = NULL;
	int num_fc_entries = 0;

	/* if no policy we can't parse the fc file */
	if (!lib || !lib->policy) {
		errno = EINVAL;
		return -1;
	}

	/* if no file_contexts file is given attempt to find the default */
	if (!fcfilelocation) {
		retv = find_default_file_contexts_file(&default_fc_path);
		if (retv) {
			error = errno;
			ERR(lib->policy, "Warning: unable to find default file_contexts file: %s\n", strerror(error));
			errno = error;
			return 0; /* not fatal error until a module requires this to exist */
		}
		retv = parse_file_contexts_file(default_fc_path, &(lib->fc_entries), &(num_fc_entries), lib->policy);
		if (retv) {
			error = errno;
			fprintf(stderr, "Warning: unable to process file_contexts file\n");
			errno = error;
			return -1;
		} else {
			lib->fc_path = strdup(default_fc_path);
		}
		if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
			fprintf(stderr,"Using file contexts: %s\n",lib->fc_path);
		}
	} else {
		retv = parse_file_contexts_file(fcfilelocation, &(lib->fc_entries), &(num_fc_entries), lib->policy);
		if (retv) {
			error = errno;
			fprintf(stderr, "Warning: unable to process file_contexts file\n");
			errno = error;
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
	int retv, error = 0;
	size_t i;
	sechk_register_fn_t fn = NULL;
	if (!register_fns || !lib) {
		fprintf(stderr, "Error: could not register modules\n");
		errno = EINVAL;
		return -1;
	}
	if (apol_vector_get_size(lib->modules) != sechk_register_list_get_num_modules()) {
		fprintf(stderr, "Error: the number of registered modules (%d) does not match the number of modules in the configuration file (%d).\n", sechk_register_list_get_num_modules(), apol_vector_get_size(lib->modules));
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		fn = (sechk_register_fn_t)(register_fns[i].fn);
		retv = fn(lib);
		if (retv) {
			error = errno;
			fprintf(stderr, "Error: could not register module #%i\n", i);
			errno = error;
			return retv;
		}
	}
	
	return 0;
}

void *sechk_lib_get_module_function(const char *module_name, const char *function_name, const sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;
	size_t i;

	if (!module_name || !function_name || !lib) {
		fprintf(stderr, "Error: failed to get function from module\n");
		errno = EINVAL;
		return NULL;
	}

	/* find the correct module */
	mod = sechk_lib_get_module(module_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: %s: no such module\n", module_name);
		errno = ENOENT;
		return NULL;
	}

	/* find function in module */
	for (i = 0; i < apol_vector_get_size(mod->functions); i++) {
		fn_struct = apol_vector_get_element(mod->functions, i);
		if (!strcmp(fn_struct->name, function_name))
			break;
		else
			fn_struct = NULL;
	}
	if (!fn_struct) {
		fprintf(stderr, "Error: %s: no such function in module %s\n", function_name, module_name);
		errno = ENOENT;
		return NULL;
	}

	return fn_struct->fn;
}

sechk_module_t *sechk_lib_get_module(const char *module_name, const sechk_lib_t *lib) 
{
	size_t i;
	sechk_module_t *mod = NULL;
	
	if (!module_name || !lib) {
		fprintf(stderr, "Error: failed to get module\n");
		errno = EINVAL;
		return NULL;
	}

	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (!(mod->name))
			continue;
		if (!strcmp(mod->name, module_name))
			return mod;
	}
	fprintf(stderr, "Error: %s: no such module\n", module_name);
	errno = ENOENT;
	return NULL;
}

int sechk_lib_check_module_dependencies(sechk_lib_t *lib)
{
	int idx = 0;
	size_t i, j;
	bool_t test = TRUE, done = FALSE, *processed = NULL;
	sechk_name_value_t *nv = NULL;
	sechk_module_t *mod = NULL, *dep = NULL;

	if (!lib) {
		fprintf(stderr, "Error: invalid module library\n");
		errno = EINVAL;
		return -1;
	}

	processed = (bool_t*)calloc(apol_vector_get_size(lib->modules), sizeof(bool_t));
	if (!processed) {
		perror(NULL);
		return -1;
	}

	/* check dependencies and select dependencies to be run */
	while (!done) {
		for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
			if (processed[i])
				continue;
			mod = apol_vector_get_element(lib->modules, i);
			if (!mod->selected) {
				processed[i] = TRUE;
				continue;
			}
			for (j = 0; j < apol_vector_get_size(mod->dependencies); j++) {
				nv = apol_vector_get_element(mod->dependencies, j);
				test = FALSE;
				test = sechk_lib_check_dependency(nv, lib);
				if (!test) {
					ERR(lib->policy, "Error: dependency %s not found for %s\n", nv->name, mod->name);
					free(processed);
					errno = ENOENT;
					return -1;
				}
				idx = sechk_lib_get_module_idx(nv->value, lib);
				dep = apol_vector_get_element(lib->modules, idx);
				if (!dep->selected) {
					processed[idx] = FALSE;
					dep->selected = TRUE;
				}
			}
			processed[i] = TRUE;
		}
		for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
			if (!processed[i])
				break;
		}
		if (i == apol_vector_get_size(lib->modules))
			done = TRUE;
	}
	free(processed);

	return 0;
}

int sechk_lib_check_module_requirements(sechk_lib_t *lib)
{
	int retv = 0;
	size_t i, j;
	bool_t test = TRUE;
	sechk_name_value_t *nv = NULL;
	sechk_module_t *mod = NULL;

	/* check requirements for all selected modules */
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (!mod->selected)
			continue;
		for (j = 0; j < apol_vector_get_size(mod->requirements); j++) {
			nv = apol_vector_get_element(mod->requirements, j);
			test = FALSE;
			test = sechk_lib_check_requirement(nv, lib);
			if (!test) {
				/* if we're in quiet mode then we quit on a failed requirement */
				if (lib->outputformat & (SECHK_OUT_QUIET)) {
					errno = ENOTSUP;
					return -1;
				} else {
					/* otherwise we just disable this module and keep testing */
					ERR(lib->policy, "Error: requirements not met for %s\n", mod->name);	
					mod->selected = FALSE;
					retv = -1;
					break;
				}
			}
		}
	}
	return retv;
}

int sechk_lib_init_modules(sechk_lib_t *lib)
{
	int retv, error = 0;
	size_t i;
	sechk_module_t *mod = NULL;
	sechk_init_fn_t init_fn = NULL;

	if (lib == NULL || lib->modules == NULL) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (!mod->selected)
			continue;
		init_fn = (sechk_init_fn_t)sechk_lib_get_module_function(mod->name, SECHK_MOD_FN_INIT, lib);
		if (!init_fn) {
			error = errno;
			fprintf(stderr, "Error: could not initialize module %s\n", mod->name);
			errno = error;
			return -1;
		}
		retv = init_fn(mod, lib->policy);
		if (retv)
			return retv;
	}

	return 0;
}

int sechk_lib_run_modules(sechk_lib_t *lib) 
{
	int retv, num_selected = 0, rc = 0;
	size_t i;
	sechk_module_t *mod = NULL;
	sechk_run_fn_t run_fn = NULL;

	if (!lib) {
		fprintf(stderr, "Error: invalid library\n");
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (mod->selected)
			num_selected++;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		/* if module is "off" do not run */
		if (!mod->selected)
			continue;
		/* if module is below the minsev do not run unless its exactly one module */
		if (lib->minsev && sechk_lib_compare_sev(mod->severity, lib->minsev) < 0 && num_selected != 1)
			continue;
		assert(mod->name);
		run_fn = (sechk_run_fn_t)sechk_lib_get_module_function(mod->name, SECHK_MOD_FN_RUN, lib);
		if (!run_fn) {
			ERR(lib->policy, "Error: could not run module %s\n", mod->name);
			errno = ENOTSUP;
			return -1;
		}
		retv = run_fn(mod, lib->policy);
	       
		if (retv < 0) {
			/* module failure */
			/* only put output failures if we are not in quiet mode */
			if (lib->outputformat & ~(SECHK_OUT_QUIET)) 
				ERR(lib->policy, "Error: module %s failed\n", mod->name);
			rc = -1;
		} else if (retv > 0) {
			/* a module looking for policy errors has found one
			 * if in quiet mode stop since running additional
			 * modules will not change the return code */
			if (lib->outputformat & (SECHK_OUT_QUIET)) 
				return -1;
		}
	}
	return rc;
}

int sechk_lib_print_modules_report(sechk_lib_t *lib)
{
	int retv, num_selected = 0, rc = 0;
	size_t i;
	sechk_module_t *mod = NULL;
	sechk_print_output_fn_t print_fn = NULL;
	
	if (!lib) {
		fprintf(stderr, "Error: invalid library\n");
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (mod->selected)
			num_selected++;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		/* if module is "off" or its output format is quiet continue */
		if (!mod->selected || mod->outputformat & SECHK_OUT_QUIET)
			continue;
		/* if module is below the minsev do not print unless exactly one module is selected */
		if (lib->minsev && sechk_lib_compare_sev(mod->severity, lib->minsev) < 0 && num_selected != 1)
			continue;
		/* if module is the only selected one make sure output is generated */
		if (mod->outputformat == SECHK_OUT_NONE && num_selected == 1)
			mod->outputformat = SECHK_OUT_SHORT;
		assert(mod->name);
		printf("\nModule name: %s\tSeverity: %s\n%s\n", mod->name, mod->severity, mod->detailed_description);
		print_fn = (sechk_run_fn_t)sechk_lib_get_module_function(mod->name, SECHK_MOD_FN_PRINT, lib);
		if (!print_fn) {
			ERR(lib->policy, "Error: could not get print function for module %s\n", mod->name);
			errno = ENOTSUP;
			return -1;
		}
		retv = print_fn(mod, lib->policy);
		if (retv) {
			fprintf(stderr, "Error: unable to print results for module %s \n", mod->name);
			rc = -1;
		}
	}

	return rc;
}

bool_t sechk_lib_check_requirement(sechk_name_value_t *req, sechk_lib_t *lib)
{
	int pol_ver = 0;
	struct stat stat_buf;

	if (!req) {
		fprintf(stderr, "Error: invalid requirement\n");
		errno = EINVAL;
		return FALSE;
	}

	if (!lib || !lib->policy) {
		fprintf(stderr, "Error: invalid library\n");
		errno = EINVAL;
		return FALSE;
	}

	if (!strcmp(req->name, SECHK_PARSE_REQUIRE_POL_TYPE)) {
		if (!strcmp(req->value, SECHK_PARSE_REQUIRE_POL_TYPE_SRC)) {
			if (apol_policy_is_binary(lib->policy)) {
				/* as long as we're not in quiet mode print output */
				if (lib->outputformat & ~(SECHK_OUT_QUIET))
					fprintf(stderr, "Error: module required source policy but was given binary\n");
				return FALSE;
			}
		} else if (!strcmp(req->value, SECHK_PARSE_REQUIRE_POL_TYPE_BIN)) {
			if (!apol_policy_is_binary(lib->policy)) {
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
			pol_ver = 11;
		else if (pol_ver < 15)
			pol_ver = 12;
		else if (pol_ver > 18)
			pol_ver = 19;
		else
			pol_ver = 0;

		unsigned int ver; 
		if (qpol_policy_get_policy_version(lib->policy->qh, lib->policy->p, &ver) < 0) {
			ERR(lib->policy, "%s", "Unable to get policy version.");
			return FALSE;
		}
		if (ver < pol_ver) {
			/* as long as we're not in quiet mode print output */
			if (lib->outputformat & ~(SECHK_OUT_QUIET))				
				fprintf(stderr, "Error: module requires newer policy version\n");
			return FALSE;
		}
	} 
	else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_SELINUX)) {
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
		if (!qpol_policy_is_mls_enabled(lib->policy->qh, lib->policy->p)) {
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
	} else if (!strcmp(req->name, SECHK_PARSE_REQUIRE_DEF_CTX)) {
		if (stat(selinux_default_context_path(), &stat_buf) < 0) {
			/* as long as we're not in quiet mode print output */
			if (lib->outputformat & ~(SECHK_OUT_QUIET))
				fprintf(stderr, "Error: module requires a default contexts file\n");
			return FALSE;
		}

		return TRUE;
	}
	else {
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
		errno = EINVAL;
		return FALSE;
	}

	if (!lib) {
		fprintf(stderr, "Error: invalid library\n");
		errno = EINVAL;
		return FALSE;
	}

	mod = sechk_lib_get_module(dep->value, lib);
	if (!mod) {
		fprintf(stderr, "Error: could not find dependency %s\n", dep->value);
		errno = ENOENT;
		return FALSE;
	}

	return TRUE;
}

int sechk_lib_set_outputformat(unsigned char out, sechk_lib_t *lib)
{
	int i;
	sechk_module_t *mod = NULL;
	
	if (!lib || !out) {
		errno = EINVAL;
		return -1;
	}
	
	lib->outputformat = out;
	
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		mod->outputformat = out;
	}

	return 0;
}

sechk_proof_t *sechk_proof_copy(sechk_proof_t *orig)
{
	sechk_proof_t *copy = NULL;

	if (!orig)
		return NULL;

	copy = sechk_proof_new(orig->elem_free_fn);
	if (!copy) {
		fprintf(stderr, "Error: out of memory\n");
		errno = ENOMEM;
		return NULL;
	}

	copy->elem = orig->elem;
	copy->type = orig->type;
	copy->text = strdup(orig->text);
	if (!copy->text) {
		fprintf(stderr, "Error: out of memory\n");
		errno = ENOMEM;
		return NULL;
	}
	copy->xml_out = NULL; /* TODO: do xml string copy here */

	return copy;
}

int sechk_lib_load_profile(const char *prof_name, sechk_lib_t *lib)
{
	const sechk_profile_name_reg_t *profiles;
	char *profpath = NULL, *prof_filename = NULL, *path = NULL;
	int num_profiles, retv=-1, error = 0;
	size_t i;
	sechk_module_t *mod = NULL;

	if (!prof_name || !lib) {
		fprintf(stderr, "Error: invalid parameters to load profile\n");
		return -1;
	}

	/* try to find the profile in our known profiles */
	profiles = sechk_register_list_get_profiles();
	num_profiles = sechk_register_list_get_num_profiles();
	for (i = 0; i < num_profiles; i++) {
		if (strcmp(profiles[i].name, prof_name) == 0) {
			break;
		}
	}
	/* this is a known installed profile, look for it in that directory */
	if (i < num_profiles) {
		/* first look in the local subdir using just PROF_SUBDIR/profile */
		prof_filename = (char *)calloc(strlen(profiles[i].file)+4+strlen(PROF_SUBDIR), sizeof(char));
		if (!prof_filename) {
			fprintf(stderr, "Error: out of memory\n");
			errno = ENOMEM;
			return -1;
		}
		sprintf(prof_filename, "%s/%s", PROF_SUBDIR, profiles[i].file);		
		path = apol_file_find(prof_filename);
		if (!path) {
			free(prof_filename);
			prof_filename = NULL;
			prof_filename = (char *)calloc(strlen(PROFILE_INSTALL_DIR)+strlen(profiles[i].file)+4, sizeof(char));
			if (!prof_filename) {
				fprintf(stderr, "Error: out of memory\n");
				errno = ENOMEM;
				return -1;
			}
			sprintf(prof_filename, "%s/%s", PROFILE_INSTALL_DIR, profiles[i].file);		
			path = apol_file_find(prof_filename);
			if (!path) {
				fprintf(stderr, "Error: Unable to find path\n");
				error = ENOENT;
				goto sechk_load_profile_error;
			}
		}
		
		/* concatenate path and filename */
		profpath = (char*)calloc(3 + strlen(path) + strlen(prof_filename), sizeof(char));
		if (!profpath) {
			fprintf(stderr, "Error: out of memory\n");
			error = ENOMEM;
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
		error = errno;
		fprintf(stderr, "Error: could not parse profile\n");
		goto sechk_load_profile_error;
	}
	
	/* turn off output for any unselected modules */
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (!mod->selected)
			mod->outputformat = SECHK_OUT_NONE;
	}
	
	free(profpath);
	free(prof_filename);
	free(path);
	return 0;
	
sechk_load_profile_error:
	free(profpath);
	free(prof_filename);
	free(path);
	errno = error;
	return -1;
}

static int sechk_option_name_compare(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	sechk_name_value_t *in_a, *in_b;

	in_a = (sechk_name_value_t*)a;
	in_b = (sechk_name_value_t*)b;

	return strcmp(in_a->name, in_b->name);
}

int sechk_lib_module_clear_option(sechk_module_t *module, char *option)
{
	apol_vector_t *new_opts = NULL;
	sechk_name_value_t *needle = NULL, *nv = NULL, *tmp = NULL;
	int error = 0;
	size_t i = 0;

	if (!module || !option) {
		errno = EINVAL;
		return -1;
	}

	if (!(needle = sechk_name_value_new(option, NULL))) {
		error = errno;
		ERR(module->parent_lib->policy, "Error clearing option %s: %s", option, strerror(error));
		errno = error;
		return -1;
	}

	/* if not here nothing to do */
	if (apol_vector_get_index(module->options, needle, sechk_option_name_compare, NULL, &i) < 0) {
		sechk_name_value_free(needle);
		return 0;	
	}

	/* add all options of a different name to a new vector to replace the old */
	for (i = 0; i < apol_vector_get_size(module->options); i++) {
		nv = apol_vector_get_element(module->options, i);
		if (strcmp(nv->name, needle->name)) {
			if (!(tmp = sechk_name_value_new(nv->name, nv->value))) {
				error = errno;
				ERR(module->parent_lib->policy, "Error clearing option %s: %s", option, strerror(error));
				goto err;
			}
			if (apol_vector_append(new_opts, (void*)tmp)) {
				error = errno;
				ERR(module->parent_lib->policy, "Error clearing option %s: %s", option, strerror(error));
				goto err;
			}
			tmp = NULL; /* avoid double free */
		}
	}

	apol_vector_destroy(&module->options, sechk_name_value_free);
	module->options = new_opts;

	return 0;

err:
	sechk_name_value_free(tmp);
	apol_vector_destroy(&new_opts, sechk_name_value_free);
	errno = error;
	return -1;
}

/* get the index of a module in the library by name */
int sechk_lib_get_module_idx(const char *name, sechk_lib_t *lib)
{
	size_t i;
	sechk_module_t *mod = NULL;

	if (!name || !lib || !lib->modules) {
		errno = EINVAL;
		return -1;
	}
	for (i=0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (mod->name && !strcmp(name, mod->name))
			return i;
	}
	errno = ENOENT;
	return -1;
}

int sechk_proof_with_element_compare(const void *in_proof, const void *elem, void *unused __attribute__ ((unused)))
{
	const sechk_proof_t *proof = (const sechk_proof_t*)in_proof;

	if (!proof)
		return 1;

	/* explicit pointer to integer cast */
	return (int)(proof->elem - elem);
}

