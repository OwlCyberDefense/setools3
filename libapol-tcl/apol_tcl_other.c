/**
 * @file
 *
 * Miscellaneous routines that translate between apol (a Tcl/Tk
 * application) and libapol.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2002-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <tcl.h>
#include <unistd.h>

#include <apol/perm-map.h>
#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>

#include "apol_tcl_render.h"
#include "apol_tcl_components.h"
#include "apol_tcl_rules.h"
#include "apol_tcl_fc.h"
#include "apol_tcl_analysis.h"

#include <qpol/policy.h>
#include <qpol/policy_extend.h>

apol_policy_t *policydb = NULL;
qpol_policy_t *qpolicydb = NULL;

/** location of the script directory, set by Apol_GetScriptDir() */
static char *script_dir = NULL;

/** location of the help file directory, set by Apol_GetHelpDir() */
static char *help_dir = NULL;

/** severity of most recent message */
static int msg_level = INT_MAX;

/** pointer to most recent message string */
static char *message = NULL;

/** flag to indicate if a permission map has been loaded */
static int is_permmap_loaded = 0;

/**
 * Take the formated string, allocate space for it, and then write it
 * the policy's msg_callback_arg.  If there is already a string
 * stored, then append to the string if the message level is equal to
 * the previous one, overwrite the string if message level is less
 * than previous, else ignore the message.
 */
static void apol_tcl_route_handle_to_string(void *varg
					    __attribute__ ((unused)), apol_policy_t * p
					    __attribute__ ((unused)), int level, const char *fmt, va_list ap)
{
	char *s, *t;
	if (level == APOL_MSG_INFO && msg_level >= APOL_MSG_INFO) {
		/* generate an info event */
		free(message);
		message = NULL;
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(ENOMEM));
			return;
		}
		message = s;
		msg_level = level;
		Tcl_DoOneEvent(TCL_IDLE_EVENTS | TCL_DONT_WAIT);
	} else if (message == NULL || level < msg_level) {
		/* overwrite the existing stored message string with a
		 * new, higher priority message */
		free(message);
		message = NULL;
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(ENOMEM));
			return;
		}
		message = s;
		msg_level = level;
	} else if (level == msg_level) {
		/* append to existing error message */
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(ENOMEM));
			return;
		}
		if (asprintf(&t, "%s\n%s", message, s) < 0) {
			free(s);
			fprintf(stderr, "%s\n", strerror(ENOMEM));
			return;
		}
		free(s);
		free(message);
		message = t;
	}
}

void apol_tcl_clear_error(void)
{
	free(message);
	message = NULL;
	msg_level = INT_MAX;
}

void apol_tcl_write_error(Tcl_Interp * interp)
{
	if (message != NULL) {
		Tcl_Obj *obj = Tcl_NewStringObj(message, -1);
		Tcl_ResetResult(interp);
		Tcl_SetObjResult(interp, obj);
		apol_tcl_clear_error();
	}
}

int apol_tcl_string_to_level(Tcl_Interp * interp, const char *level_string, apol_mls_level_t * level)
{
	Tcl_Obj *level_obj, *sens_obj, *cats_list_obj, *cats_obj;
	const char *sens_string, *cat_string;
	qpol_level_t *sens;
	qpol_cat_t *cat;
	int num_cats, i;

	if (policydb == NULL) {
		/* no policy, so nothing to convert */
		return 1;
	}
	level_obj = Tcl_NewStringObj(level_string, -1);
	if (Tcl_ListObjIndex(interp, level_obj, 0, &sens_obj) == TCL_ERROR ||
	    Tcl_ListObjIndex(interp, level_obj, 1, &cats_list_obj) == TCL_ERROR) {
		return -1;
	}
	if (sens_obj == NULL || cats_list_obj == NULL) {
		/* no sensitivity given -- this is an error */
		ERR(policydb, "%s", "Sensitivity string did not have two elements within it.");
		return -1;
	}
	sens_string = Tcl_GetString(sens_obj);
	if (qpol_policy_get_level_by_name(qpolicydb, sens_string, &sens) < 0) {
		/* unknown sensitivity */
		return 1;
	}
	if (apol_mls_level_set_sens(policydb, level, sens_string) < 0 ||
	    Tcl_ListObjLength(interp, cats_list_obj, &num_cats) == TCL_ERROR) {
		return -1;
	}
	for (i = 0; i < num_cats; i++) {
		if (Tcl_ListObjIndex(interp, cats_list_obj, i, &cats_obj) == TCL_ERROR) {
			return -1;
		}
		cat_string = Tcl_GetString(cats_obj);
		if (qpol_policy_get_cat_by_name(qpolicydb, cat_string, &cat) < 0) {
			/* unknown category */
			return 1;
		}
		if (apol_mls_level_append_cats(policydb, level, cat_string) < 0) {
			return -1;
		}
	}
	return 0;
}

int apol_tcl_string_to_range(Tcl_Interp * interp, const char *range_string, apol_mls_range_t * range)
{
	Tcl_Obj *range_obj = NULL, *low_obj, *high_obj;
	const char *low_string, *high_string;
	apol_mls_level_t *low_level = NULL, *high_level = NULL;
	int retval = -1, list_len;

	range_obj = Tcl_NewStringObj(range_string, -1);

	/* extract low level from string and process it */
	if (Tcl_ListObjIndex(interp, range_obj, 0, &low_obj) == TCL_ERROR) {
		goto cleanup;
	}
	if (low_obj == NULL) {
		ERR(policydb, "%s", "Range string must have at least one level given.");
		goto cleanup;
	}
	low_string = Tcl_GetString(low_obj);
	if ((low_level = apol_mls_level_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if ((retval = apol_tcl_string_to_level(interp, low_string, low_level)) != 0) {
		goto cleanup;
	}
	/* for now set the high level to be the same as low level --
	 * if there really is a high level in the string then that
	 * will overwrite this entry */
	if (apol_mls_range_set_low(policydb, range, low_level) < 0 || apol_mls_range_set_high(policydb, range, low_level)) {
		goto cleanup;
	}
	low_level = NULL;
	retval = -1;

	if (Tcl_ListObjLength(interp, range_obj, &list_len) == TCL_ERROR) {
		goto cleanup;
	}
	if (list_len != 1) {
		/* extract high level and process it */
		if (Tcl_ListObjIndex(interp, range_obj, 1, &high_obj) == TCL_ERROR) {
			goto cleanup;
		}
		high_string = Tcl_GetString(high_obj);
		if ((high_level = apol_mls_level_create()) == NULL) {
			ERR(policydb, "%s", strerror(ENOMEM));
			goto cleanup;
		}
		if ((retval = apol_tcl_string_to_level(interp, high_string, high_level)) != 0 ||
		    apol_mls_range_set_high(policydb, range, high_level) < 0) {
			goto cleanup;
		}
		high_level = NULL;
	}

	retval = 0;
      cleanup:
	apol_mls_level_destroy(&low_level);
	apol_mls_level_destroy(&high_level);
	return retval;
}

int apol_tcl_string_to_range_match(Tcl_Interp * interp, const char *range_match_string, unsigned int *flags)
{
	unsigned new_flag;
	if (strcmp(range_match_string, "exact") == 0) {
		new_flag = APOL_QUERY_EXACT;
	} else if (strcmp(range_match_string, "subset") == 0) {
		new_flag = APOL_QUERY_SUB;
	} else if (strcmp(range_match_string, "superset") == 0) {
		new_flag = APOL_QUERY_SUPER;
	} else if (strcmp(range_match_string, "intersect") == 0) {
		new_flag = APOL_QUERY_INTERSECT;
	} else {
		ERR(policydb, "Invalid range match string %s.", range_match_string);
		return -1;
	}
	*flags = (*flags & ~APOL_QUERY_FLAGS) | new_flag;
	return 0;
}

int apol_tcl_string_to_context(Tcl_Interp * interp, const char *context_string, apol_context_t * context)
{
	int num_elems;
	const char **context_elem = NULL;
	const char *user, *role, *type, *range_string;
	apol_mls_range_t *range = NULL;
	int retval = -1, retval2;
	if (Tcl_SplitList(interp, context_string, &num_elems, &context_elem) == TCL_ERROR) {
		goto cleanup;
	}
	if (num_elems < 3 || num_elems > 4) {
		ERR(policydb, "Invalid Tcl context object: %s.", context_string);
		goto cleanup;
	}
	user = context_elem[0];
	role = context_elem[1];
	type = context_elem[2];
	if ((*user != '\0' && apol_context_set_user(policydb, context, user) < 0) ||
	    (*role != '\0' && apol_context_set_role(policydb, context, role) < 0) ||
	    (*type != '\0' && apol_context_set_type(policydb, context, type) < 0)) {
		goto cleanup;
	}
	if (num_elems == 4) {
		range_string = context_elem[3];
		if (*range_string != '\0') {
			if ((range = apol_mls_range_create()) == NULL) {
				ERR(policydb, "%s", strerror(ENOMEM));
				goto cleanup;
			}
			retval2 = apol_tcl_string_to_range(interp, range_string, range);
			if (retval2 != 0) {
				retval = retval2;
				goto cleanup;
			}
			if (apol_context_set_range(policydb, context, range) < 0) {
				goto cleanup;
			}
			range = NULL;
		}
	}
	retval = 0;
      cleanup:
	apol_mls_range_destroy(&range);
	if (context_elem != NULL) {
		Tcl_Free((char *)context_elem);
	}
	return retval;
}

static void apol_tcl_reset_globals(void)
{
	apol_tcl_clear_error();
	is_permmap_loaded = 0;
	qpolicydb = NULL;
}

/**
 * Get the directory where the Tcl scripts are located.  This function
 * simply returns the value of the script_dir GLOBAL variable defined
 * above if has been set previously.  Otherwise it calls
 * apol_find_file() and then returns the variable.  Someone needs to
 * call this function during or prior to running scripts that use
 * these commands.
 *
 * There is one argument, the file name of the top-level Tcl script
 * (e.g., apol.tcl) which is located according to apol_find_file().
 * The assumption is that any other Tcl script will be in the same
 * directory.
 *
 * @param argv This function takes one parameter: file to find.
 */
static int Apol_GetScriptDir(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	if (argc != 2) {
		Tcl_SetResult(interp, "Need a filename.", TCL_STATIC);
		return TCL_ERROR;
	}

	if (script_dir == NULL) {
		script_dir = apol_file_find(argv[1]);
		if (script_dir == NULL) {
			Tcl_SetResult(interp, "Problem locating Tcl startup script.", TCL_STATIC);
			return TCL_ERROR;
		}
	}
	Tcl_SetResult(interp, script_dir, TCL_STATIC);
	return TCL_OK;
}

int apol_tcl_get_startup_script(Tcl_Interp * interp, char *name)
{
	CONST char *args[2] = { NULL, name };
	return Apol_GetScriptDir(NULL, interp, 2, args);
}

/**
 * Get the directory where the help files are located.  This function
 * simply returns the value of the help_dir GLOBAL variable defined
 * above if has been set previously.  Otherwise it calls
 * apol_find_file() and then returns the variable.  Someone needs to
 * call this function during or prior to running scripts that use
 * these commands.
 *
 * @param argv This function takes one parameter: file to find.
 */
static int Apol_GetHelpDir(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	if (argc != 2) {
		Tcl_SetResult(interp, "Need a filename.", TCL_STATIC);
		return TCL_ERROR;
	}

	if (help_dir == NULL) {
		help_dir = apol_file_find(argv[1]);
		if (help_dir == NULL) {
			Tcl_SetResult(interp, "Problem locating Tcl help file.", TCL_STATIC);
			return TCL_ERROR;
		}
	}

	assert(help_dir != NULL);
	Tcl_SetResult(interp, help_dir, TCL_STATIC);
	return TCL_OK;
}

/**
 * If the current message stored withing the apol_policy_t handler is
 * an info string, then return it.  Otherwise return an empty string.
 */
static int Apol_GetInfoString(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	if (message != NULL && msg_level == APOL_MSG_INFO) {
		Tcl_SetResult(interp, message, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, "", TCL_STATIC);
	}
	return TCL_OK;
}

/**
 * Convert an apol_policy_path_t object to a Tcl string.
 */
static int apol_policy_path_to_tcl_obj(Tcl_Interp * interp, const apol_policy_path_t * path, Tcl_Obj ** obj)
{
	Tcl_Obj *path_elem[3];
	int retval = TCL_ERROR;
	switch (apol_policy_path_get_type(path)) {
	case APOL_POLICY_PATH_TYPE_MONOLITHIC:{
			path_elem[0] = Tcl_NewStringObj("monolithic", -1);
			break;
		}
	case APOL_POLICY_PATH_TYPE_MODULAR:{
			path_elem[0] = Tcl_NewStringObj("modular", -1);
			break;
		}
	default:
		Tcl_SetResult(interp, "Unknown policy type.", TCL_STATIC);
	}
	path_elem[1] = Tcl_NewStringObj(apol_policy_path_get_primary(path), -1);
	path_elem[2] = Tcl_NewListObj(0, NULL);
	if (apol_policy_path_get_type(path) == APOL_POLICY_PATH_TYPE_MODULAR) {
		const apol_vector_t *mods = apol_policy_path_get_modules(path);
		size_t i;
		for (i = 0; i < apol_vector_get_size(mods); i++) {
			const char *m = apol_vector_get_element(mods, i);
			Tcl_Obj *o = Tcl_NewStringObj(m, -1);
			if (Tcl_ListObjAppendElement(interp, path_elem[2], o) != TCL_OK) {
				goto cleanup;
			}
		}
	}
	*obj = Tcl_NewListObj(3, path_elem);
	retval = TCL_OK;
      cleanup:
	return retval;
}

/**
 * Convert a Tcl string representing a policy path into an
 * apol_policy_path_t object.
 */
static apol_policy_path_t *apol_tcl_string_to_policy_path(Tcl_Interp * interp, CONST char *p)
{
	enum apol_policy_path_type path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	CONST char *primary_path;
	CONST char **argv = NULL, **module_paths = NULL;
	apol_vector_t *modules = NULL;
	apol_policy_path_t *path = NULL;
	int argc, num_modules, retval = TCL_ERROR;

	if (Tcl_SplitList(interp, p, &argc, &argv) == TCL_ERROR) {
		goto cleanup;
	}
	if (argc < 3) {
		Tcl_SetResult(interp, strerror(EINVAL), TCL_STATIC);
		goto cleanup;
	}
	if (strcmp(argv[0], "modular") == 0) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
		if (argc >= 3) {
			if (Tcl_SplitList(interp, argv[2], &num_modules, &module_paths) == TCL_ERROR) {
				goto cleanup;
			}
			if ((modules = apol_vector_create(free)) == NULL) {
				Tcl_SetResult(interp, strerror(errno), TCL_STATIC);
				goto cleanup;
			}
			while (--num_modules >= 0) {
				char *m = NULL;
				if ((m = strdup(module_paths[num_modules])) == NULL || apol_vector_append(modules, m) < 0) {
					Tcl_SetResult(interp, strerror(errno), TCL_STATIC);
					free(m);
					goto cleanup;
				}
			}
		}
	} else if (strcmp(argv[0], "monolithic") != 0) {
		Tcl_SetResult(interp, strerror(EINVAL), TCL_STATIC);
		goto cleanup;
	}
	primary_path = argv[1];
	if ((path = apol_policy_path_create(path_type, primary_path, modules)) == NULL) {
		Tcl_SetResult(interp, strerror(errno), TCL_STATIC);
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	apol_vector_destroy(&modules);
	if (module_paths != NULL) {
		Tcl_Free((char *)module_paths);
	}
	if (retval != TCL_OK) {
		apol_policy_path_destroy(&path);
		apol_tcl_write_error(interp);
	}
	return path;
}

/**
 * Open and return a policy path, created by reading it from a policy
 * list file.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>filename containing policy list
 * </ol>
 */
static int Apol_OpenPolicyList(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	apol_policy_path_t *path = NULL;
	Tcl_Obj *result_obj;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a policy path filename.", TCL_STATIC);
		goto cleanup;
	}
	if ((path = apol_policy_path_create_from_file(argv[1])) == NULL) {
		Tcl_SetResult(interp, strerror(errno), TCL_STATIC);
		goto cleanup;
	}
	if (apol_policy_path_to_tcl_obj(interp, path, &result_obj) == TCL_ERROR) {
		goto cleanup;
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	apol_policy_path_destroy(&path);
	if (retval != TCL_OK) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Save a policy path to disk.
 *
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>policy path (3-ple of path type, primary path, and list of modules)
 *   <li>filename containing policy list
 * </ol>
 */
static int Apol_SavePolicyList(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	apol_policy_path_t *path = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (argc < 3) {
		Tcl_SetResult(interp, "Need a policy path and a filename.", TCL_STATIC);
		goto cleanup;
	}
	if ((path = apol_tcl_string_to_policy_path(interp, argv[1])) == NULL) {
		goto cleanup;
	}
	if (apol_policy_path_to_file(path, argv[2]) < 0) {
		Tcl_SetResult(interp, strerror(errno), TCL_STATIC);
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	apol_policy_path_destroy(&path);
	if (retval != TCL_OK) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Open a policy file, either source or binary, on disk.  If the file
 * was opened successfully then set the global policydb pointer to it,
 * and set its error handler to apol_tcl_route_handle_to_string().
 * Regardless of success or failure, the previously opened policy is
 * destroyed.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>a 3-ple list representing a policy path:
 *       <ol>
 *       <li>type of policy to open, one of "monolithic" or "modular"
 *       <li>path to monolithic policy or to base policy
 *       <li>(optional) if modular policy, a list of module paths
 *       </ol>
 * </ol>
 */
static int Apol_OpenPolicy(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	apol_policy_path_t *path;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a policy path.", TCL_STATIC);
		goto cleanup;
	}
	if ((path = apol_tcl_string_to_policy_path(interp, argv[1])) == NULL) {
		goto cleanup;
	}

	apol_tcl_reset_globals();

	apol_policy_destroy(&policydb);
	policydb = apol_policy_create_from_policy_path(path, 0, apol_tcl_route_handle_to_string, NULL);
	if (policydb == NULL) {
		Tcl_Obj *result_obj = Tcl_NewStringObj("Error opening policy: ", -1);
		Tcl_AppendToObj(result_obj, strerror(errno), -1);
		Tcl_SetObjResult(interp, result_obj);
		goto cleanup;
	}
	/* if not binary load syntactic rules so that line numbers may
	 * be accessed */
	qpolicydb = apol_policy_get_qpol(policydb);
	if (qpol_policy_has_capability(qpolicydb, QPOL_CAP_SYN_RULES) && qpol_policy_build_syn_rule_table(qpolicydb)) {
		Tcl_Obj *result_obj = Tcl_NewStringObj("Error loading syntactic rules: ", -1);
		Tcl_AppendToObj(result_obj, strerror(errno), -1);
		Tcl_SetObjResult(interp, result_obj);
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	apol_policy_path_destroy(&path);
	if (retval != TCL_OK) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Close the currently opened policy.  If no policy is opened then do
 * nothing.
 */
static int Apol_ClosePolicy(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	apol_tcl_reset_globals();
	apol_policy_destroy(&policydb);
	return TCL_OK;
}

/**
 * Retrieve information about a policy module file, either source or
 * binary, from disk.  This will be a 2-ple of module name and
 * version.  The policy module will be closed afterwards.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>path to the module to open
 * </ol>
 */
static int Apol_GetModuleInfo(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	qpol_module_t *module = NULL;
	char *module_name, *version, *s;
	int module_type;
	Tcl_Obj *result_obj, *objs[2];
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (argc != 2) {
		Tcl_SetResult(interp, "Need a policy module path.", TCL_STATIC);
		goto cleanup;
	}
	if ((qpol_module_create_from_file(argv[1], &module)) < 0) {
		if (asprintf(&s, "Error opening module %s: %s", argv[1], strerror(errno)) < 0) {
			fprintf(stderr, "%s", strerror(errno));
		}
		message = s;
		goto cleanup;
	}
	if (qpol_module_get_name(module, &module_name) < 0 ||
	    qpol_module_get_version(module, &version) < 0 || qpol_module_get_type(module, &module_type) < 0) {
		if (asprintf(&s, "Error reading module %s: %s", argv[1], strerror(errno)) < 0) {
			fprintf(stderr, "%s", strerror(errno));
		}
		message = s;
		goto cleanup;
	}
	if (module_type != QPOL_MODULE_OTHER) {
		if (asprintf(&s, "%s is not a loadable module.", argv[1]) < 0) {
			fprintf(stderr, "%s", strerror(errno));
		}
		message = s;
		goto cleanup;
	}
	objs[0] = Tcl_NewStringObj(module_name, -1);
	objs[1] = Tcl_NewStringObj(version, -1);
	result_obj = Tcl_NewListObj(2, objs);
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	qpol_module_destroy(&module);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Given a capability, return 1 if the currently loaded policy can do
 * that particular thing, 0 if not.
 *
 * @param argv This function takes a single capability string, which
 * is one of:
 * <ol>
 *   <li>"attribute names"
 *   <li>"conditionals"
 *   <li>"line numbers"
 *   <li>"mls"
 *   <li>"source"
 *   <li>"syntactic rules"
 * </ol>
 */
static int Apol_IsCapable(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	qpol_capability_e cap;
	int retval;
	Tcl_Obj *result_obj;
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (argc < 1) {
		Tcl_SetResult(interp, "Need a capability to check.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (strcmp(argv[1], "attribute names") == 0) {
		cap = QPOL_CAP_ATTRIB_NAMES;
	} else if (strcmp(argv[1], "conditionals") == 0) {
		cap = QPOL_CAP_CONDITIONALS;
	} else if (strcmp(argv[1], "line numbers") == 0) {
		cap = QPOL_CAP_LINE_NUMBERS;
	} else if (strcmp(argv[1], "mls") == 0) {
		cap = QPOL_CAP_MLS;
	} else if (strcmp(argv[1], "source") == 0) {
		cap = QPOL_CAP_SOURCE;
	} else if (strcmp(argv[1], "syntactic rules") == 0) {
		cap = QPOL_CAP_SYN_RULES;
	} else {
		Tcl_SetResult(interp, "Unknown capability.", TCL_STATIC);
		return TCL_ERROR;
	}
	retval = qpol_policy_has_capability(qpolicydb, cap);
	result_obj = Tcl_NewIntObj(retval);
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

/**
 * Return a string describing the currently opened policy.  The string
 * gives the policy version, if it is source or binary, and if it is
 * MLS or not.
 */
static int Apol_GetPolicyVersionString(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	char *pol_string;
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if ((pol_string = apol_policy_get_version_type_mls_str(policydb)) == NULL) {
		Tcl_SetResult(interp, strerror(ENOMEM), TCL_STATIC);
		return TCL_ERROR;
	}
	Tcl_SetResult(interp, pol_string, TCL_VOLATILE);
	free(pol_string);
	return TCL_OK;
}

/**
 * Returns the policy version number for the currently opened policy.
 * If the policy is modular, return the maximum allowed policy as per
 * libsepol.
 */
static int Apol_GetPolicyVersionNumber(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	unsigned int version;
	Tcl_Obj *version_obj;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (apol_policy_get_policy_type(policydb) != QPOL_POLICY_MODULE_BINARY) {
		if (qpol_policy_get_policy_version(qpolicydb, &version) < 0) {
			apol_tcl_write_error(interp);
			return TCL_ERROR;
		}
	} else {
		version = SEPOL_POLICY_VERSION_MAX;
	}
	version_obj = Tcl_NewIntObj(version);
	Tcl_SetObjResult(interp, version_obj);
	return TCL_OK;
}

/**
 * Appends a name and size to a stats list, conveniently in a format
 * suitable for [array set].
 *
 * @param interp Tcl interpreter object.
 * @param name Statistic key.
 * @param size Value for statistic.
 * @param result_obj Tcl object to which append.
 *
 * @return 0 on success, < 0 on error.
 */
static int append_stats(Tcl_Interp * interp, char *name, size_t size, Tcl_Obj * result_list)
{
	Tcl_Obj *stat_elem[2];
	stat_elem[0] = Tcl_NewStringObj(name, -1);
	stat_elem[1] = Tcl_NewIntObj(size);
	if (Tcl_ListObjAppendElement(interp, result_list, stat_elem[0]) != TCL_OK ||
	    Tcl_ListObjAppendElement(interp, result_list, stat_elem[1]) != TCL_OK) {
		return -1;
	}
	return 0;
}

struct policy_stat
{
	char *name;
	int (*iter_func) (qpol_policy_t * policy, qpol_iterator_t ** iter);
};

/**
 * Calculate and return statistics about the policy, in a format
 * suitable for [array set].
 */
static int Apol_GetStats(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	qpol_iterator_t *iter = NULL;
	int i, retval = TCL_ERROR;
	apol_type_query_t *type_query = NULL;
	apol_attr_query_t *attr_query = NULL;
	apol_perm_query_t *perm_query = NULL;
	apol_vector_t *v = NULL;
	size_t size;

	struct policy_stat stats[] = {
		/* components */
		{"roles", qpol_policy_get_role_iter},
		{"classes", qpol_policy_get_class_iter},
		{"common_perms", qpol_policy_get_common_iter},
		{"users", qpol_policy_get_user_iter},
		{"cond_bools", qpol_policy_get_bool_iter},

		/* rbac */
		{"roleallow", qpol_policy_get_role_allow_iter},
		{"roletrans", qpol_policy_get_role_trans_iter},

		/* mls */
		{"sens", qpol_policy_get_level_iter},
		{"cats", qpol_policy_get_cat_iter},
		{"rangetrans", qpol_policy_get_range_trans_iter},

		/* contexts */
		{"sids", qpol_policy_get_isid_iter},
		{"portcons", qpol_policy_get_portcon_iter},
		{"netifcons", qpol_policy_get_netifcon_iter},
		{"nodecons", qpol_policy_get_nodecon_iter},
		{"genfscons", qpol_policy_get_genfscon_iter},
		{"fs_uses", qpol_policy_get_fs_use_iter}
	};

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	for (i = 0; i < sizeof(stats) / sizeof(stats[0]); i++) {
		if (stats[i].iter_func(qpolicydb, &iter) < 0 ||
		    qpol_iterator_get_size(iter, &size) < 0 || append_stats(interp, stats[i].name, size, result_obj) < 0) {
			goto cleanup;
		}
		qpol_iterator_destroy(&iter);
	}

	/* the following do not have iterators that conveniently
	 * compute their sizes */

	if ((type_query = apol_type_query_create()) == NULL ||
	    (attr_query = apol_attr_query_create()) == NULL || (perm_query = apol_perm_query_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (apol_type_get_by_query(policydb, type_query, &v) < 0 ||
	    append_stats(interp, "types", apol_vector_get_size(v), result_obj) < 0) {
		goto cleanup;
	}
	apol_vector_destroy(&v);

	if (apol_attr_get_by_query(policydb, attr_query, &v) < 0 ||
	    append_stats(interp, "attribs", apol_vector_get_size(v), result_obj) < 0) {
		goto cleanup;
	}
	apol_vector_destroy(&v);

	if (apol_perm_get_by_query(policydb, perm_query, &v) < 0 ||
	    append_stats(interp, "perms", apol_vector_get_size(v), result_obj) < 0) {
		goto cleanup;
	}
	apol_vector_destroy(&v);

	if (qpol_policy_get_avrule_iter(qpolicydb,
					QPOL_RULE_ALLOW, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 || append_stats(interp, "teallow", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_avrule_iter(qpolicydb,
					QPOL_RULE_NEVERALLOW, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 || append_stats(interp, "neverallow", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_avrule_iter(qpolicydb,
					QPOL_RULE_AUDITALLOW, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 || append_stats(interp, "auditallow", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_avrule_iter(qpolicydb,
					QPOL_RULE_DONTAUDIT, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 || append_stats(interp, "dontaudit", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_terule_iter(qpolicydb,
					QPOL_RULE_TYPE_TRANS, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 || append_stats(interp, "tetrans", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_terule_iter(qpolicydb,
					QPOL_RULE_TYPE_MEMBER, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 || append_stats(interp, "temember", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_terule_iter(qpolicydb,
					QPOL_RULE_TYPE_CHANGE, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 || append_stats(interp, "techange", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	apol_type_query_destroy(&type_query);
	apol_attr_query_destroy(&attr_query);
	apol_perm_query_destroy(&perm_query);
	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&v);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Checks if a range is valid or not according to the policy.  Returns
 * 1 if valid, 0 if invalid.
 *
 * @param argv This function takes one parameter: a range (2-uple of levels).
 */
static int Apol_IsValidRange(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	apol_mls_range_t *range = NULL;
	int retval = TCL_ERROR, retval2;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a range.");
		goto cleanup;
	}
	if ((range = apol_mls_range_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	retval2 = apol_tcl_string_to_range(interp, argv[1], range);
	if (retval2 < 0) {
		goto cleanup;
	} else if (retval2 == 1) {
		Tcl_SetResult(interp, "0", TCL_STATIC);
		retval = TCL_OK;
		goto cleanup;
	}
	retval2 = apol_mls_range_validate(policydb, range);
	if (retval2 < 0) {
		goto cleanup;
	} else if (retval2 == 0) {
		Tcl_SetResult(interp, "0", TCL_STATIC);
	} else {
		Tcl_SetResult(interp, "1", TCL_STATIC);
	}
	retval = TCL_OK;
      cleanup:
	apol_mls_range_destroy(&range);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Checks if a context is partially valid or not according to the
 * policy.  Returns 1 if valid, 0 if invalid.
 */
static int Apol_IsValidPartialContext(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	apol_context_t *context = NULL;
	int retval = TCL_ERROR, retval2;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a Tcl context.");
		goto cleanup;
	}
	if ((context = apol_context_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	retval2 = apol_tcl_string_to_context(interp, argv[1], context);
	if (retval2 < 0) {
		goto cleanup;
	} else if (retval2 == 1) {
		Tcl_SetResult(interp, "0", TCL_STATIC);
		retval = TCL_OK;
		goto cleanup;
	}
	retval2 = apol_context_validate_partial(policydb, context);
	if (retval2 < 0) {
		goto cleanup;
	} else if (retval2 == 0) {
		Tcl_SetResult(interp, "0", TCL_STATIC);
	} else {
		Tcl_SetResult(interp, "1", TCL_STATIC);
	}
	retval = TCL_OK;
      cleanup:
	apol_context_destroy(&context);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Checks if the permission map has been loaded yet.  Returns 1 if so,
 * 0 if not.
 */
static int Apol_IsPermMapLoaded(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	Tcl_SetResult(interp, (policydb != NULL && is_permmap_loaded ? "1" : "0"), TCL_STATIC);
	return TCL_OK;
}

/**
 * Find the default permission map file given its base name, and
 * return a newly allocated string to the path and file.
 *
 * @param perm_map_fname Base name of permission map file.
 *
 * @return An allocated string to the fully qualified path, or NULL on
 * error.  The caller is responsible for free()ing this string
 * afterwards.
 */
static char *find_perm_map_file(const char *perm_map_fname)
{
	char *script = NULL, *var = NULL;

	if (perm_map_fname == NULL)
		return NULL;

	/* first check environment variable */
	var = getenv(APOL_ENVIRON_VAR_NAME);
	if (var != NULL) {
		if (asprintf(&script, "%s/%s", var, perm_map_fname) == -1) {
			return NULL;
		}
		if (access(script, R_OK) == 0) {
			return script;
		}
	}

	/* next try installed directory */
	free(script);
	if (asprintf(&script, "%s/%s", APOL_INSTALL_DIR, perm_map_fname) == -1) {
		return NULL;
	}
	if (access(script, R_OK) == 0) {
		return script;
	}

	/* didn't find it! */
	free(script);
	return NULL;
}

/**
 * Given a base name, determine the full path to the permission map
 * file.  If no matching file was found then return an empty string.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>base name for permission map file
 * </ol>
 */
static int Apol_GetDefault_PermMap(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	char *pmap_file;
	if (argc != 2) {
		Tcl_SetResult(interp, "Need a permission map base name.", TCL_STATIC);
		return TCL_ERROR;
	}

	pmap_file = find_perm_map_file(argv[1]);
	if (pmap_file == NULL) {
		/* There is no system default perm map. User will have
		 * to load one explicitly. */
		return TCL_OK;
	}
	Tcl_SetResult(interp, pmap_file, TCL_VOLATILE);
	free(pmap_file);
	return TCL_OK;
}

/**
 * Load a perm map from disk.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>permission map file name
 * </ol>
 */
static int Apol_LoadPermMap(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	int retval = TCL_ERROR, rt = 0;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a permission map file name.");
		goto cleanup;
	}
	if ((rt = apol_permmap_load(policydb, argv[1])) < 0) {
		goto cleanup;
	}
	is_permmap_loaded = 1;
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR || rt > 0) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Save a permission map to disk.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>permission map file name
 * </ol>
 */
static int Apol_SavePermMap(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	int retval = TCL_ERROR;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (!is_permmap_loaded) {
		ERR(policydb, "%s", "No permission map currently loaded!");
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a permission map file name.");
		goto cleanup;
	}
	if (apol_permmap_save(policydb, argv[1]) < 0) {
		goto cleanup;
	}

	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Look up a specific permission within the policy's permission map.
 * Return a Tcl string that represents that map:
 * <code>
 *   { perm_name map_type weight }
 * </code>
 *
 * @param interp Tcl interpreter object.
 * @param class_name Permission's class.
 * @param perm_name Name of permission.
 * @param Destination to create Tcl object representing mapping.
 *
 * @return 0 if permission was found, < 0 on error.
 */
static int build_tcl_perm_list(Tcl_Interp * interp, char *class_name, char *perm_name, Tcl_Obj ** obj)
{
	int map, weight;
	char *map_str;
	Tcl_Obj *perm_elem[3];

	if (apol_permmap_get(policydb, class_name, perm_name, &map, &weight) < 0) {
		return -1;
	}
	perm_elem[0] = Tcl_NewStringObj(perm_name, -1);
	switch (map) {
	case APOL_PERMMAP_READ:
		map_str = "r";
		break;
	case APOL_PERMMAP_WRITE:
		map_str = "w";
		break;
	case APOL_PERMMAP_BOTH:
		map_str = "b";
		break;
	case APOL_PERMMAP_NONE:
		map_str = "n";
		break;
	case APOL_PERMMAP_UNMAPPED:
		map_str = "u";
		break;
	default:
		map_str = "?";
	}
	perm_elem[1] = Tcl_NewStringObj(map_str, -1);
	perm_elem[2] = Tcl_NewIntObj(weight);
	*obj = Tcl_NewListObj(3, perm_elem);
	return 0;
}

/**
 * Return the currently loaded permission map as an unsorted list of
 * class entries.  Each class tuple consists of:
 * <ul>
 *   <li>class name
 *   <li>unsorted list of permission tuples
 * </ul>
 *
 * Each permission tuple consists of:
 * <ul>
 *   <li>permission name
 *   <li>mapping type, one of 'r', 'w', 'b', 'n', or 'u'
 *   <li>permission weight (an integer)
 * </ul>
 *
 * If a parameter is passed, then only the class tuple for the given
 * parameter is returned.
 */
static int Apol_GetPermMap(ClientData clientData, Tcl_Interp * interp, int argc, const char *argv[])
{
	int retval = TCL_ERROR;
	qpol_iterator_t *class_iter = NULL, *perm_iter = NULL, *common_iter = NULL;
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (!is_permmap_loaded) {
		ERR(policydb, "%s", "No permission map currently loaded!");
		goto cleanup;
	}
	if (qpol_policy_get_class_iter(qpolicydb, &class_iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(class_iter); qpol_iterator_next(class_iter)) {
		qpol_class_t *c;
		qpol_common_t *common;
		char *class_name, *perm_name;
		Tcl_Obj *class_elem[2], *class_list, *perm_list;
		if (qpol_iterator_get_item(class_iter, (void **)&c) < 0 || qpol_class_get_name(qpolicydb, c, &class_name) < 0) {
			goto cleanup;
		}
		if (argc >= 2 && strcmp(argv[1], class_name) != 0) {
			continue;
		}
		if (qpol_class_get_perm_iter(qpolicydb, c, &perm_iter) < 0 || qpol_class_get_common(qpolicydb, c, &common) < 0) {
			goto cleanup;
		}
		if (common != NULL && qpol_common_get_perm_iter(qpolicydb, common, &common_iter) < 0) {
			goto cleanup;
		}
		class_elem[0] = Tcl_NewStringObj(class_name, -1);
		class_elem[1] = Tcl_NewListObj(0, NULL);
		for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
			if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0 ||
			    build_tcl_perm_list(interp, class_name, perm_name,
						&perm_list) < 0 ||
			    Tcl_ListObjAppendElement(interp, class_elem[1], perm_list) == TCL_ERROR) {
				goto cleanup;
			}
		}
		for (; common_iter != NULL && !qpol_iterator_end(common_iter); qpol_iterator_next(common_iter)) {
			if (qpol_iterator_get_item(common_iter, (void **)&perm_name) < 0 ||
			    build_tcl_perm_list(interp, class_name, perm_name,
						&perm_list) < 0 ||
			    Tcl_ListObjAppendElement(interp, class_elem[1], perm_list) == TCL_ERROR) {
				goto cleanup;
			}
		}
		class_list = Tcl_NewListObj(2, class_elem);
		if (Tcl_ListObjAppendElement(interp, result_obj, class_list) == TCL_ERROR) {
			goto cleanup;
		}
		qpol_iterator_destroy(&perm_iter);
		qpol_iterator_destroy(&common_iter);
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&class_iter);
	qpol_iterator_destroy(&perm_iter);
	qpol_iterator_destroy(&common_iter);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Sets an individual permission mapping within the current policy.
 *
 * @param argv This function takes four parameter:
 * <ol>
 *   <li>class containing permission to change
 *   <li>name of permission to change
 *   <li>new map, one of "r", "w", "b", "n", or "u"
 *   <li>new weight, between APOL_PERMMAP_MIN_WEIGHT to
 *   APOL_PERMMAP_MAX_WEIGHT, inclusive
 * </ol>
 */
static int Apol_SetPermMap(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	int retval = TCL_ERROR, map, weight;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (!is_permmap_loaded) {
		ERR(policydb, "%s", "No permission map currently loaded!");
		goto cleanup;
	}
	if (argc != 5) {
		ERR(policydb, "%s", "Need a class, permission, new map, and new weight.");
		goto cleanup;
	}
	switch (*argv[3]) {
	case 'r':
		map = APOL_PERMMAP_READ;
		break;
	case 'w':
		map = APOL_PERMMAP_WRITE;
		break;
	case 'b':
		map = APOL_PERMMAP_BOTH;
		break;
	case 'n':
		map = APOL_PERMMAP_NONE;
		break;
	case 'u':
		map = APOL_PERMMAP_UNMAPPED;
		break;
	default:
		ERR(policydb, "Invalid perm map %s.", argv[3]);
		goto cleanup;
	}
	if (Tcl_GetInt(interp, argv[4], &weight) == TCL_ERROR) {
		goto cleanup;
	}
	if (apol_permmap_set(policydb, argv[1], argv[2], map, weight) < 0) {
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/* Package initialization */
int apol_tcl_init(Tcl_Interp * interp)
{
	Tcl_CreateCommand(interp, "apol_GetScriptDir", Apol_GetScriptDir, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetHelpDir", Apol_GetHelpDir, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetInfoString", Apol_GetInfoString, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_OpenPolicyList", Apol_OpenPolicyList, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SavePolicyList", Apol_SavePolicyList, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_OpenPolicy", Apol_OpenPolicy, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_ClosePolicy", Apol_ClosePolicy, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetModuleInfo", Apol_GetModuleInfo, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsCapable", Apol_IsCapable, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionString", Apol_GetPolicyVersionString, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionNumber", Apol_GetPolicyVersionNumber, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetStats", Apol_GetStats, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsValidRange", Apol_IsValidRange, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsValidPartialContext", Apol_IsValidPartialContext, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsPermMapLoaded", Apol_IsPermMapLoaded, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetDefault_PermMap", Apol_GetDefault_PermMap, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_LoadPermMap", Apol_LoadPermMap, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SavePermMap", Apol_SavePermMap, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPermMap", Apol_GetPermMap, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SetPermMap", Apol_SetPermMap, NULL, NULL);

	if (apol_tcl_render_init(interp) != TCL_OK ||
	    apol_tcl_components_init(interp) != TCL_OK ||
	    apol_tcl_rules_init(interp) != TCL_OK ||
	    apol_tcl_fc_init(interp) != TCL_OK || apol_tcl_analysis_init(interp) != TCL_OK) {
		return TCL_ERROR;
	}
	Tcl_PkgProvide(interp, "apol", (char *)libapol_get_version());

	return TCL_OK;
}
