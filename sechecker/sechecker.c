/**
 *  @file
 *  Implementation of the public interface for all sechecker modules
 *  and the library.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2008 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "sechecker.h"
#include "register_list.h"
#include "sechk_parse.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <apol/policy.h>
#include <apol/util.h>
#include <apol/vector.h>

#include <sefs/util.h>
#include <sefs/fcfile.hh>
#include <sefs/query.hh>

#ifdef LIBSELINUX
#include <selinux/selinux.h>
#endif

#include <qpol/policy.h>
#include <qpol/util.h>

static int sechk_lib_compare_sev(const char *a, const char *b)
{
	int aval, bval;

	if (a == NULL || b == NULL) {
		assert(false);
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
		assert(false);
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
		assert(false);
		errno = EINVAL;
		return -1;
	}

	if (aval == bval)
		return 0;

	return aval < bval ? -1 : 1;
}

int sechk_lib_set_minsev(const char *minsev, sechk_lib_t * lib)
{
	if (lib == NULL || lib->policy == NULL || minsev == NULL) {
		assert(false);
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
	if (!(mod->options = apol_vector_create(sechk_name_value_free)) ||
	    !(mod->requirements = apol_vector_create(sechk_name_value_free)) ||
	    !(mod->dependencies = apol_vector_create(sechk_name_value_free))
	    || !(mod->functions = apol_vector_create(sechk_fn_free))) {
		error = errno;
		apol_vector_destroy(&mod->options);
		apol_vector_destroy(&mod->requirements);
		apol_vector_destroy(&mod->dependencies);
		apol_vector_destroy(&mod->functions);
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
	size_t num_known_modules = 0;
	size_t i = 0;
	sechk_module_t *tmp = NULL;

	/* allocate the new sechk_lib_t structure */
	lib = (sechk_lib_t *) calloc(1, sizeof(sechk_lib_t));
	if (!lib) {
		error = errno;
		perror("Error creating module library");
		goto exit_err;
	}

	/* create the module array from the known modules in register list */
	num_known_modules = sechk_register_list_get_num_modules();
	reg_list = sechk_register_list_get_modules();
	lib->modules = apol_vector_create(sechk_module_free);
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

void sechk_lib_destroy(sechk_lib_t ** lib)
{
	if (lib == NULL || *lib == NULL)
		return;

	apol_vector_destroy(&((*lib)->modules));
	apol_policy_destroy(&((*lib)->policy));
	apol_vector_destroy(&((*lib)->fc_entries));
	free((*lib)->fc_path);
	sefs_fclist_destroy(&((*lib)->fc_file));
	free((*lib)->selinux_config_path);
	apol_policy_path_destroy(&((*lib)->policy_path));
	free(*lib);
	*lib = NULL;
}

void sechk_module_free(void *module)
{
	sechk_module_t *mod = (sechk_module_t *) module;

	if (!module)
		return;

	/* do not free describtin fields */
	sechk_result_destroy(&mod->result);
	apol_vector_destroy(&mod->options);
	apol_vector_destroy(&mod->requirements);
	apol_vector_destroy(&mod->dependencies);
	/* do not free severity */
	if (mod->data) {
		assert(mod->data_free);
		mod->data_free(mod->data);
	}
	free(mod->name);
	mod->name = NULL;
	apol_vector_destroy(&mod->functions);
	free(mod);
}

void sechk_fn_free(void *fn_struct)
{
	sechk_fn_t *fn = (sechk_fn_t *) fn_struct;
	if (!fn_struct)
		return;

	free(fn->name);
	/* NEVER free fn->fn */
	free(fn);
}

void sechk_name_value_free(void *nv)
{
	sechk_name_value_t *in = (sechk_name_value_t *) nv;
	if (!nv)
		return;

	free(in->name);
	free(in->value);
	free(nv);
}

void sechk_result_destroy(sechk_result_t ** res)
{
	if (!res || !(*res))
		return;

	free((*res)->test_name);
	apol_vector_destroy(&((*res)->items));
	free(*res);
	*res = NULL;
}

void sechk_item_free(void *item)
{
	sechk_item_t *it = (sechk_item_t *) item;

	if (!item)
		return;

	apol_vector_destroy(&it->proof);
	if (it->item_free_fn)
		it->item_free_fn(it->item);

	free(item);
}

void sechk_proof_free(void *proof)
{
	sechk_proof_t *p = (sechk_proof_t *) proof;

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
	return (sechk_fn_t *) calloc(1, sizeof(sechk_fn_t));
}

sechk_name_value_t *sechk_name_value_new(const char *name, const char *value)
{
	sechk_name_value_t *nv;
	int error;

	nv = (sechk_name_value_t *) calloc(1, sizeof(sechk_name_value_t));
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
	return (sechk_result_t *) calloc(1, sizeof(sechk_result_t));
}

sechk_item_t *sechk_item_new(free_fn_t fn)
{
	sechk_item_t *it = NULL;

	it = (sechk_item_t *) calloc(1, sizeof(sechk_item_t));
	if (!it)
		return NULL;
	it->item_free_fn = fn;

	return it;
}

sechk_proof_t *sechk_proof_new(free_fn_t fn)
{
	sechk_proof_t *proof = NULL;
	proof = (sechk_proof_t *) calloc(1, sizeof(sechk_proof_t));
	if (!proof)
		return NULL;
	proof->type = SECHK_ITEM_NONE;
	proof->elem_free_fn = fn;
	return proof;
}

int sechk_lib_load_policy(apol_policy_path_t * policy_mods, sechk_lib_t * lib)
{

	char *default_policy_path = NULL;
	int retv = -1;

	if (!lib)
		return -1;

	/* if no policy is given, attempt to find default */
	if (!policy_mods) {
		retv = qpol_default_policy_find(&default_policy_path);
		if (retv < 0) {
			fprintf(stderr, "Default policy search failed: %s\n", strerror(errno));
			return -1;
		} else if (retv != 0) {
			fprintf(stderr, "No default policy found.\n");
			return -1;
		}
		policy_mods = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, default_policy_path, NULL);
		lib->policy = apol_policy_create_from_policy_path(policy_mods, QPOL_POLICY_OPTION_MATCH_SYSTEM, NULL, NULL);
		if (lib->policy == NULL) {
			fprintf(stderr, "Error: failed opening default policy\n");
			return -1;
		}
		lib->policy_path = policy_mods;
		if (!(lib->outputformat & SECHK_OUT_QUIET)) {
			fprintf(stderr, "Using policy: %s\n", apol_policy_path_get_primary(lib->policy_path));
		}
	} else {
		lib->policy_path = policy_mods;
		lib->policy = apol_policy_create_from_policy_path(policy_mods, 0, NULL, NULL);
		if (lib->policy == NULL) {
			fprintf(stderr, "Error: failed opening policy %s\n", apol_policy_path_to_string(lib->policy_path));
			goto err;
		}
	}
	return 0;

      err:
	apol_policy_destroy(&lib->policy);
	return -1;
}

int sechk_lib_load_fc(const char *fcfilelocation, sechk_lib_t * lib)
{
	int error = 0;
	char *default_fc_path = NULL;
	sefs_fclist_t *fcfile = NULL;
	sefs_query_t *q = NULL;

	/* if no policy we can't parse the fc file */
	if (!lib || !lib->policy) {
		errno = EINVAL;
		return -1;
	}

	/* if no file_contexts file is given attempt to find the default */
	if (!fcfilelocation) {
		default_fc_path = sefs_default_file_contexts_get_path();
		if (default_fc_path == NULL) {
			error = errno;
			WARN(lib->policy, "Unable to find default file_contexts file: %s", strerror(error));
			errno = error;
			return 0;      /* not fatal error until a module requires this to exist */
		}
		if (strcmp(default_fc_path, "") == 0) {
			WARN(lib->policy, "%s", "The system has no default file_contexts file.");
			free(default_fc_path);
			errno = ENOSYS;
			return 0;      /* not fatal error until a module requires this to exist */
		}
		fcfile = sefs_fcfile_create_from_file(default_fc_path, NULL, NULL);
		q = sefs_query_create();
		lib->fc_entries = sefs_fclist_run_query(fcfile, q);
		if (!(lib->fc_entries)) {
			error = errno;
			WARN(lib->policy, "Unable to process file_contexts file %s.", default_fc_path);
			free(default_fc_path);
			errno = error;
			return -1;
		} else {
			lib->fc_path = default_fc_path;
			lib->fc_file = fcfile;
		}
		if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
			fprintf(stderr, "Using file contexts: %s\n", lib->fc_path);
		}
	} else {
		fcfile = sefs_fcfile_create_from_file(fcfilelocation, NULL, NULL);
		q = sefs_query_create();
		lib->fc_entries = sefs_fclist_run_query(fcfile, q);
		if (!(lib->fc_entries)) {
			error = errno;
			WARN(lib->policy, "Unable to process file_contexts file %s.", fcfilelocation);
			errno = error;
			return -1;
		} else {
			lib->fc_path = strdup(fcfilelocation);
			lib->fc_file = fcfile;
		}
	}
	sefs_query_destroy(&q);

	return 0;
}

int sechk_lib_register_modules(const sechk_module_name_reg_t * register_fns, sechk_lib_t * lib)
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
		fprintf(stderr,
			"Error: the number of registered modules (%zd) does not match the number of modules in the configuration file (%zd).\n",
			sechk_register_list_get_num_modules(), apol_vector_get_size(lib->modules));
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		fn = (sechk_register_fn_t) (register_fns[i].fn);
		retv = fn(lib);
		if (retv) {
			error = errno;
			fprintf(stderr, "Error: could not register module #%zd\n", i);
			errno = error;
			return retv;
		}
	}

	return 0;
}

sechk_mod_fn_t sechk_lib_get_module_function(const char *module_name, const char *function_name, const sechk_lib_t * lib)
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

sechk_module_t *sechk_lib_get_module(const char *module_name, const sechk_lib_t * lib)
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

sechk_result_t *sechk_lib_get_module_result(const char *module_name, const sechk_lib_t * lib)
{
	size_t i;
	sechk_module_t *mod = NULL;
	sechk_mod_fn_t run = NULL;

	if (!module_name || !lib) {
		fprintf(stderr, "Error: failed to get module result\n");
		errno = EINVAL;
		return NULL;
	}

	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (!(mod->name))
			continue;
		if (strcmp(mod->name, module_name))
			continue;
		if (!(mod->result)) {
			if (!(run = sechk_lib_get_module_function(module_name, SECHK_MOD_FN_RUN, lib)) ||
			    run(mod, lib->policy, NULL) < 0) {
				return NULL;	/* run or get function will set errno */
			}
		}
		return mod->result;
	}
	fprintf(stderr, "Error: %s: no such module\n", module_name);
	errno = ENOENT;
	return NULL;
}

int sechk_lib_check_module_dependencies(sechk_lib_t * lib)
{
	int idx = 0;
	size_t i, j;
	bool test = true, done = false, *processed = NULL;
	sechk_name_value_t *nv = NULL;
	sechk_module_t *mod = NULL, *dep = NULL;

	if (!lib) {
		fprintf(stderr, "Error: invalid module library\n");
		errno = EINVAL;
		return -1;
	}

	processed = (bool *) calloc(apol_vector_get_size(lib->modules), sizeof(bool));
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
				processed[i] = true;
				continue;
			}
			for (j = 0; j < apol_vector_get_size(mod->dependencies); j++) {
				nv = apol_vector_get_element(mod->dependencies, j);
				test = false;
				test = sechk_lib_check_dependency(nv, lib);
				if (!test) {
					ERR(lib->policy, "Dependency %s not found for %s.", nv->name, mod->name);
					free(processed);
					errno = ENOENT;
					return -1;
				}
				idx = sechk_lib_get_module_idx(nv->value, lib);
				dep = apol_vector_get_element(lib->modules, idx);
				if (!dep->selected) {
					processed[idx] = false;
					dep->selected = true;
				}
			}
			processed[i] = true;
		}
		for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
			if (!processed[i])
				break;
		}
		if (i == apol_vector_get_size(lib->modules))
			done = true;
	}
	free(processed);

	return 0;
}

int sechk_lib_check_module_requirements(sechk_lib_t * lib)
{
	int retv = 0;
	size_t i, j;
	bool test = true;
	sechk_name_value_t *nv = NULL;
	sechk_module_t *mod = NULL;

	/* check requirements for all selected modules */
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (!mod->selected)
			continue;
		for (j = 0; j < apol_vector_get_size(mod->requirements); j++) {
			nv = apol_vector_get_element(mod->requirements, j);
			test = false;
			test = sechk_lib_check_requirement(nv, lib);
			if (!test) {
				/* if we're in quiet mode then we quit on a failed requirement */
				if (lib->outputformat & (SECHK_OUT_QUIET)) {
					errno = ENOTSUP;
					return -1;
				} else {
					/* otherwise we just disable this module and keep testing */
					ERR(lib->policy, "Requirements not met for %s.", mod->name);
					mod->selected = false;
					retv = -1;
					break;
				}
			}
		}
	}
	return retv;
}

int sechk_lib_init_modules(sechk_lib_t * lib)
{
	int retv, error = 0;
	size_t i;
	sechk_module_t *mod = NULL;
	sechk_mod_fn_t init_fn = NULL;

	if (lib == NULL || lib->modules == NULL) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (!mod->selected)
			continue;
		init_fn = sechk_lib_get_module_function(mod->name, SECHK_MOD_FN_INIT, lib);
		if (!init_fn) {
			error = errno;
			fprintf(stderr, "Error: could not initialize module %s\n", mod->name);
			errno = error;
			return -1;
		}
		retv = init_fn(mod, lib->policy, NULL);
		if (retv)
			return retv;
	}

	return 0;
}

int sechk_lib_run_modules(sechk_lib_t * lib)
{
	int retv, num_selected = 0, rc = 0;
	size_t i;
	sechk_module_t *mod = NULL;
	sechk_mod_fn_t run_fn = NULL;

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
		run_fn = sechk_lib_get_module_function(mod->name, SECHK_MOD_FN_RUN, lib);
		if (!run_fn) {
			ERR(lib->policy, "Could not run module %s.", mod->name);
			errno = ENOTSUP;
			return -1;
		}
		retv = run_fn(mod, lib->policy, NULL);

		if (retv < 0) {
			/* module failure */
			/* only put output failures if we are not in quiet mode */
			if (lib->outputformat & ~(SECHK_OUT_QUIET))
				ERR(lib->policy, "Module %s failed.", mod->name);
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

int sechk_lib_print_modules_report(sechk_lib_t * lib)
{
	int retv, num_selected = 0, rc = 0;
	size_t i;
	sechk_module_t *mod = NULL;
	sechk_mod_fn_t print_fn = NULL;

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
		print_fn = sechk_lib_get_module_function(mod->name, SECHK_MOD_FN_PRINT, lib);
		if (!print_fn) {
			ERR(lib->policy, "Could not get print function for module %s.", mod->name);
			errno = ENOTSUP;
			return -1;
		}
		retv = print_fn(mod, lib->policy, NULL);
		if (retv) {
			fprintf(stderr, "Error: unable to print results for module %s \n", mod->name);
			rc = -1;
		}
	}

	return rc;
}

bool sechk_lib_check_requirement(sechk_name_value_t * req, sechk_lib_t * lib)
{
	struct stat stat_buf;

	if (!req) {
		fprintf(stderr, "Error: invalid requirement\n");
		errno = EINVAL;
		return false;
	}

	if (!lib || !lib->policy) {
		fprintf(stderr, "Error: invalid library\n");
		errno = EINVAL;
		return false;
	}

	if (!strcmp(req->name, SECHK_REQ_POLICY_CAP)) {
		if (!strcmp(req->value, SECHK_REQ_CAP_ATTRIB_NAMES)) {
			if (!qpol_policy_has_capability(apol_policy_get_qpol(lib->policy), QPOL_CAP_ATTRIB_NAMES)) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				}
				return false;
			}
		} else if (!strcmp(req->value, SECHK_REQ_CAP_MLS)) {
			if (!qpol_policy_has_capability(apol_policy_get_qpol(lib->policy), QPOL_CAP_MLS)) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				}
				return false;
			}
		} else if (!strcmp(req->value, SECHK_REQ_CAP_SYN_RULES)) {
			if (!qpol_policy_has_capability(apol_policy_get_qpol(lib->policy), QPOL_CAP_SYN_RULES)) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				}
				return false;
			}
		} else if (!strcmp(req->value, SECHK_REQ_CAP_RULES_LOADED)) {
			if (!qpol_policy_has_capability(apol_policy_get_qpol(lib->policy), QPOL_CAP_RULES_LOADED)) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				}
				return false;
			}
		} else if (!strcmp(req->value, SECHK_REQ_CAP_LINE_NOS)) {
			if (!qpol_policy_has_capability(apol_policy_get_qpol(lib->policy), QPOL_CAP_LINE_NUMBERS)) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				}
				return false;
			}
		} else if (!strcmp(req->value, SECHK_REQ_CAP_CONDITIONALS)) {
			if (!qpol_policy_has_capability(apol_policy_get_qpol(lib->policy), QPOL_CAP_CONDITIONALS)) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				}
				return false;
			}
		} else if (!strcmp(req->value, SECHK_REQ_CAP_MODULES)) {
			if (!qpol_policy_has_capability(apol_policy_get_qpol(lib->policy), QPOL_CAP_MODULES)) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				}
				return false;
			}
		} else {
			ERR(lib->policy, "Unknown requirement: %s, %s", req->name, req->value);
			return false;
		}
	} else if (!strcmp(req->name, SECHK_REQ_DEFAULT_CONTEXTS)) {
#ifdef LIBSELINUX
		if (stat(selinux_default_context_path(), &stat_buf) < 0) {
			if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
				ERR(lib->policy, "Requirement %s not met.", req->name);
			}
			return false;
		}
#else
		if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
			ERR(lib->policy, "Checking requirement %s: %s", req->name, strerror(ENOTSUP));
		}
		return false;
#endif
	} else if (!strcmp(req->name, SECHK_REQ_FILE_CONTEXTS)) {
		if (!lib->fc_entries || !apol_vector_get_size(lib->fc_entries)) {
			if (lib->outputformat & ~(SECHK_OUT_QUIET)) {
				ERR(lib->policy, "Requirement %s not met.", req->name);
			}
		}
	} else if (!strcmp(req->name, SECHK_REQ_SYSTEM)) {
		if (!strcmp(req->value, SECHK_REQ_SYS_SELINUX)) {
#ifdef LIBSELINUX
			if (!is_selinux_mls_enabled() || !is_selinux_enabled()) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET))
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				return false;
			}
#else
			if (lib->outputformat & ~(SECHK_OUT_QUIET))
				ERR(lib->policy, "Checking requirement %s, %s: %s", req->name, req->value, strerror(ENOTSUP));
			return false;
#endif
		} else if (!strcmp(req->value, SECHK_REQ_SYS_MLS)) {
#ifdef LIBSELINUX
			if (!is_selinux_mls_enabled() || !is_selinux_enabled()) {
				if (lib->outputformat & ~(SECHK_OUT_QUIET))
					ERR(lib->policy, "Requirement %s, %s not met.", req->name, req->value);
				return false;
			}
#else
			if (lib->outputformat & ~(SECHK_OUT_QUIET))
				ERR(lib->policy, "Checking requirement %s, %s: %s", req->name, req->value, strerror(ENOTSUP));
			return false;
#endif
		} else {
			ERR(lib->policy, "Unknown requirement: %s, %s", req->name, req->value);
			return false;
		}
	} else {
		ERR(lib->policy, "Unknown requirement: %s, %s", req->name, req->value);
		return false;
	}

	return true;
}

bool sechk_lib_check_dependency(sechk_name_value_t * dep, sechk_lib_t * lib)
{
	sechk_module_t *mod = NULL;

	if (!dep || !dep->value) {
		fprintf(stderr, "Error: invalid dependency\n");
		errno = EINVAL;
		return false;
	}

	if (!lib) {
		fprintf(stderr, "Error: invalid library\n");
		errno = EINVAL;
		return false;
	}

	mod = sechk_lib_get_module(dep->value, lib);
	if (!mod) {
		fprintf(stderr, "Error: could not find dependency %s\n", dep->value);
		errno = ENOENT;
		return false;
	}

	return true;
}

int sechk_lib_set_outputformat(unsigned char out, sechk_lib_t * lib)
{
	size_t i;
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

sechk_proof_t *sechk_proof_copy(sechk_proof_t * orig)
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
	copy->xml_out = NULL;	       /* TODO: do xml string copy here */

	return copy;
}

int sechk_lib_load_profile(const char *prof_name, sechk_lib_t * lib)
{
	const sechk_profile_name_reg_t *profiles;
	char *profpath = NULL, *prof_filename = NULL, *path = NULL;
	int retv = -1, error = 0;
	size_t num_profiles, i;
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
		prof_filename = (char *)calloc(strlen(profiles[i].file) + 4 + strlen(PROF_SUBDIR), sizeof(char));
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
			prof_filename = (char *)calloc(strlen(PROFILE_INSTALL_DIR) + strlen(profiles[i].file) + 4, sizeof(char));
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
		profpath = (char *)calloc(3 + strlen(path) + strlen(prof_filename), sizeof(char));
		if (!profpath) {
			fprintf(stderr, "Error: out of memory\n");
			error = ENOMEM;
			goto sechk_load_profile_error;
		}
		sprintf(profpath, "%s/%s", path, prof_filename);
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

	in_a = (sechk_name_value_t *) a;
	in_b = (sechk_name_value_t *) b;

	return strcmp(in_a->name, in_b->name);
}

int sechk_lib_module_clear_option(sechk_module_t * module, char *option)
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
		ERR(module->parent_lib->policy, "Clearing option %s: %s.", option, strerror(error));
		errno = error;
		return -1;
	}

	/* if not here nothing to do */
	if (apol_vector_get_index(module->options, needle, sechk_option_name_compare, NULL, &i) < 0) {
		sechk_name_value_free(needle);
		return 0;
	}

	if (!(new_opts = apol_vector_create(sechk_name_value_free))) {
		error = errno;
		ERR(module->parent_lib->policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	/* add all options of a different name to a new vector to replace the old */
	for (i = 0; i < apol_vector_get_size(module->options); i++) {
		nv = apol_vector_get_element(module->options, i);
		if (strcmp(nv->name, needle->name)) {
			if (!(tmp = sechk_name_value_new(nv->name, nv->value))) {
				error = errno;
				WARN(module->parent_lib->policy, "Clearing option %s: %s.", option, strerror(error));
				goto err;
			}
			if (apol_vector_append(new_opts, (void *)tmp)) {
				error = errno;
				WARN(module->parent_lib->policy, "Clearing option %s: %s.", option, strerror(error));
				goto err;
			}
			tmp = NULL;    /* avoid double free */
		}
	}

	sechk_name_value_free(needle);
	apol_vector_destroy(&module->options);
	module->options = new_opts;

	return 0;

      err:
	sechk_name_value_free(tmp);
	sechk_name_value_free(needle);
	apol_vector_destroy(&new_opts);
	errno = error;
	return -1;
}

/* get the index of a module in the library by name */
int sechk_lib_get_module_idx(const char *name, sechk_lib_t * lib)
{
	size_t i;
	sechk_module_t *mod = NULL;

	if (!name || !lib || !lib->modules) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(lib->modules); i++) {
		mod = apol_vector_get_element(lib->modules, i);
		if (mod->name && !strcmp(name, mod->name))
			return i;
	}
	errno = ENOENT;
	return -1;
}

int sechk_proof_with_element_compare(const void *in_proof, const void *elem, void *unused __attribute__ ((unused)))
{
	const sechk_proof_t *proof = (const sechk_proof_t *)in_proof;

	if (!proof)
		return 1;

	/* explicit pointer to integer cast */
	return (int)((char *)proof->elem - (char *)elem);
}
