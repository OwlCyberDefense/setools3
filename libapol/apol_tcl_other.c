/**
 * @file apol_tcl_other.c
 *
 * Miscellaneous routines that translate between apol (a Tcl/Tk
 * application) and libapol.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2002-2006 Tresys Technology, LLC
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

#define _GNU_SOURCE
#include <stdarg.h>
#include <string.h>
#include <tcl.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include "policy.h"
#include "policy-io.h"
#include "util.h"
#include "render.h"
#include "perm-map.h"

#include "policy-query.h"

#include "apol_tcl_render.h"
#include "apol_tcl_components.h"
#include "apol_tcl_rules.h"
#include "apol_tcl_fc.h"
#include "apol_tcl_analysis.h"
#include "policy-io.h"

#include <qpol/policy.h>

apol_policy_t *policydb = NULL;

/**
 * Take the formated string, allocate space for it, and then write it
 * the policy's msg_callback_arg.  This will first free the previous
 * contents of msg_callback_arg.
 */
static void apol_tcl_route_handle_to_string(void *varg __attribute__ ((unused)),
					    apol_policy_t *p,
					    const char *fmt, va_list ap)
{
	char *s;
	free(p->msg_callback_arg);
	p->msg_callback_arg = NULL;
	if (vasprintf(&s, fmt, ap) < 0) {
		fprintf(stderr, "Out of memory!\n");
	}
	else {
		p->msg_callback_arg = s;
	}
}

void apol_tcl_clear_error(void)
{
	if (policydb != NULL) {
		free(policydb->msg_callback_arg);
		policydb->msg_callback_arg = NULL;
	}
}

void apol_tcl_write_error(Tcl_Interp *interp)
{
	if (policydb != NULL && policydb->msg_callback_arg != NULL) {
		Tcl_Obj *obj = Tcl_NewStringObj(policydb->msg_callback_arg, -1);
		Tcl_ResetResult(interp);
		Tcl_SetObjResult(interp, obj);
		apol_tcl_clear_error();
	}
}

int apol_tcl_string_to_level(Tcl_Interp *interp, const char *level_string,
			     apol_mls_level_t *level)
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
		ERR(policydb, "Sensitivity string did not have two elements within it.", TCL_STATIC);
		return -1;
	}
	sens_string = Tcl_GetString(sens_obj);
	if (qpol_policy_get_level_by_name(policydb->qh, policydb->p,
					     sens_string, &sens) < 0) {
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
		if (qpol_policy_get_cat_by_name(policydb->qh, policydb->p,
						   cat_string, &cat) < 0) {
			/* unknown category */
			return 1;
		}
		if (apol_mls_level_append_cats(policydb, level, cat_string) < 0) {
			return -1;
		}
	}
	if (level->cats == NULL &&
	    (level->cats = apol_vector_create()) == NULL) {
		ERR(policydb, "Out of memory!");
		return -1;
	}
	return 0;
}

int apol_tcl_string_to_range(Tcl_Interp *interp, const char *range_string,
			     apol_mls_range_t *range)
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
		ERR(policydb, "Range string must have at least one level given.");
		goto cleanup;
	}
	low_string = Tcl_GetString(low_obj);
	if ((low_level = apol_mls_level_create()) == NULL) {
		ERR(policydb, "Out of memory!");
		goto cleanup;
	}
	if ((retval = apol_tcl_string_to_level(interp, low_string, low_level)) != 0) {
		goto cleanup;
	}
	/* for now set the high level to be the same as low level --
	 * if there really is a high level in the string then that
	 * will overwrite this entry */
	if (apol_mls_range_set_low(policydb, range, low_level) < 0 ||
	    apol_mls_range_set_high(policydb, range, low_level)) {
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
			Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
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

int apol_tcl_string_to_range_match(Tcl_Interp *interp, const char *range_match_string,
				   unsigned int *flags)
{
	unsigned new_flag;
	if (strcmp(range_match_string, "exact") == 0) {
		new_flag = APOL_QUERY_EXACT;
	}
	else if (strcmp(range_match_string, "subset") == 0) {
		new_flag = APOL_QUERY_SUB;
	}
	else if (strcmp(range_match_string, "superset") == 0) {
		new_flag = APOL_QUERY_SUPER;
	}
	else if (strcmp(range_match_string, "intersect") == 0) {
		new_flag = APOL_QUERY_INTERSECT;
	}
	else {
		ERR(policydb, "Invalid range match string %s.", range_match_string);
		return -1;
	}
	*flags = (*flags & ~APOL_QUERY_FLAGS) | new_flag;
	return 0;
}

int apol_tcl_string_to_context(Tcl_Interp *interp,
			       const char *context_string,
			       apol_context_t *context) {
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
				ERR(policydb, "Out of memory!");
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
		Tcl_Free((char *) context_elem);
	}
	return retval;
}

int apol_level_to_tcl_obj(Tcl_Interp *interp, apol_mls_level_t *level, Tcl_Obj **obj) {
	Tcl_Obj *level_elem[2], *cats_obj;
	size_t i;
	level_elem[0] = Tcl_NewStringObj(level->sens, -1);
	level_elem[1] = Tcl_NewListObj(0, NULL);
	for (i = 0; i < apol_vector_get_size(level->cats); i++) {
		cats_obj = Tcl_NewStringObj((char *) apol_vector_get_element(level->cats, i), -1);
		if (Tcl_ListObjAppendElement(interp, level_elem[1], cats_obj) == TCL_ERROR) {
			return -1;
		}
	}
	*obj = Tcl_NewListObj(2, level_elem);
	return 0;
}

#define APOL_TCL_PMAP_WARNINGS_SUBSET (PERMMAP_RET_UNMAPPED_PERM|PERMMAP_RET_UNMAPPED_OBJ|PERMMAP_RET_OBJ_REMMAPPED)

/**************************************************************************
 * work functions
 **************************************************************************/

static int load_perm_map_file(char *pmap_file, Tcl_Interp *interp);
static char* find_perm_map_file(char *perm_map_fname);

/* We look for the TCL files in the following order:
 * 	1. If we find apol.tcl in the cur directory, we then assume
 *	   the TCL files are there, else
 * 	2. We look for the environment variable APOL_SCRIPT_DIR and if
 * 	   exists, look for apol.tcl there, else
 *	3. We then look for in APOL_INSTALL_DIR for apol.tcl.
 * Otherwise we report an installation error. 
 */
/* global used to keep track of the script directory, set by Apol_GetScriptDir */
static char *script_dir = NULL;
 
/* global used to keep track of the help file directory, set by Apol_GetHelpDir */
static char *help_dir = NULL;

/* find the default permission map file.  This function returns a string of the files' pathname.
 */
static char* find_perm_map_file(char *perm_map_fname)
{	
	char *script, *var = NULL;
	int scriptsz;
	int rt;
			
	if(perm_map_fname == NULL)
		return NULL;
		
	/* 1. check environment variable */
	var = getenv(APOL_ENVIRON_VAR_NAME);
	if(!(var == NULL)) {
		scriptsz = strlen(var) + strlen(perm_map_fname) + 2;
		script = (char *)malloc(scriptsz);
		if(script == NULL) {
			fprintf(stderr, "out of memory");
			return NULL;
		}	
		sprintf(script, "%s/%s", var, perm_map_fname);	
		rt = access(script, R_OK);
		if(rt == 0) {
			return script;
		}
	}
	
	/* 2. installed directory */
	scriptsz = strlen(APOL_INSTALL_DIR) + strlen(perm_map_fname) + 2;
	script = (char *)malloc(scriptsz);
	if(script == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}	
	sprintf(script, "%s/%s", APOL_INSTALL_DIR, perm_map_fname);
	rt = access(script, R_OK);
	if(rt == 0) {
		return script;	
	}
	
	/* 3. Didn't find it! */
	free(script);		
	return NULL;			
}

static int load_perm_map_file(char *pmap_file, Tcl_Interp *interp)
{
	FILE *pfp;
	unsigned int m_ret;

	if(policydb == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return -1;
	}	
	if(!is_valid_str_sz(pmap_file)) {
		Tcl_AppendResult(interp, "File name string too large", (char *) NULL);
		return -1;
	} 	
	pfp = fopen(pmap_file, "r");
	if(pfp == NULL) {
		Tcl_AppendResult(interp, "Cannot open perm map file", pmap_file, (char *) NULL);
		return -1;
	}
/* FIX ME
	m_ret = load_policy_perm_mappings(policy, pfp);
*/
        m_ret = PERMMAP_RET_ERROR;
	fclose(pfp);
	if(m_ret & PERMMAP_RET_ERROR) {
		Tcl_AppendResult(interp, "ERROR loading perm mappings from file:", pmap_file, (char *) NULL);
		return -1;
	} 
	else if(m_ret & APOL_TCL_PMAP_WARNINGS_SUBSET) {
		fprintf(stdout, "There were warnings:\n");
		if(m_ret & PERMMAP_RET_UNMAPPED_PERM) 
			fprintf(stdout, "     Some permissions were unmapped.\n");
		if(m_ret & PERMMAP_RET_UNMAPPED_OBJ)
			fprintf(stdout, "     Some objects were unmapped.\n");
		if(m_ret & PERMMAP_RET_OBJ_REMMAPPED) 
			fprintf(stdout, "     Some permissions were mapped more than once.\n");
			
		return -2;
	}		
	return 0;
}

/**************************************************************************
 * TCL interface functions
 **************************************************************************/


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
int Apol_GetScriptDir(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	if(argc != 2) {
		Tcl_SetResult(interp, "Need a filename.", TCL_STATIC);
		return TCL_ERROR;
	}

	if(script_dir == NULL) {
		script_dir = apol_find_file(argv[1]);
		if(script_dir == NULL) {
			Tcl_SetResult(interp, "Problem locating Tcl startup script.", TCL_STATIC);
			return TCL_ERROR;
		}
	}
	assert(script_dir != NULL);
	Tcl_SetResult(interp, script_dir, TCL_STATIC);
	return TCL_OK;
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
static int Apol_GetHelpDir(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	if(argc != 2) {
		Tcl_SetResult(interp, "Need a filename.", TCL_STATIC);
		return TCL_ERROR;
	}

	if(help_dir == NULL) {
		help_dir = apol_find_file(argv[1]);
		if(help_dir == NULL) {
			Tcl_SetResult(interp, "Problem locating Tcl help file.", TCL_STATIC);
			return TCL_ERROR;
		}
	}

	assert(help_dir != NULL);
	Tcl_SetResult(interp, help_dir, TCL_STATIC);
	return TCL_OK;
}

/* Get the specified system default permission map pathname. */
int Apol_GetDefault_PermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char *pmap_file;	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Permission map file name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	pmap_file = find_perm_map_file(argv[1]);
	if(pmap_file == NULL) {
		/* There is no system default perm map. User will have to load one explicitly. */
		return TCL_OK;
	}
	assert(pmap_file != NULL);
	Tcl_AppendResult(interp, pmap_file, (char *) NULL);
	return TCL_OK;
}

/**
 * Open a policy file, either source or binary, on disk.  If the file
 * was opened successfully then set the global policydb pointer to it,
 * and set its error handler to apol_tcl_route_handle_to_string().
 *
 * @param argv This function takes one parameter: policy to open.
 */
static int Apol_OpenPolicy(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	if (argc != 2) {
		Tcl_SetResult(interp, "Need a policy filename.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (apol_policy_open(argv[1], &policydb)) {
		Tcl_Obj *result_obj = Tcl_NewStringObj("Error opening policy: ", -1);
		Tcl_AppendToObj(result_obj, strerror(errno), -1);
		Tcl_SetObjResult(interp, result_obj);
		return TCL_ERROR;
	}
	policydb->msg_callback_arg = NULL;
	policydb->msg_callback = apol_tcl_route_handle_to_string;

	return TCL_OK;
}

/**
 * Close the currently opened policy.  If no policy is opened then do
 * nothing.
 */
static int Apol_ClosePolicy(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	apol_policy_destroy(&policydb);
	return TCL_OK;
}

int Apol_GetVersion(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	Tcl_AppendResult(interp, (char*)libapol_get_version(), (char *) NULL);
	return TCL_OK;
}

/**
 * Returns a 2-uple describing the current policy type.  The first
 * element is says if the policy is binary or source.  The second
 * element gives if the policy is MLS or not.
 * <ol>
 *   <li>"binary" or "source"
 *   <li>"mls" or "non-mls"
 * </ol>
 */
static int Apol_GetPolicyType(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_elem[2], *result_list;
        if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	switch (policydb->policy_type) {
	case QPOL_POLICY_KERNEL_SOURCE:
		result_elem[0] = Tcl_NewStringObj("source", -1); break;
	case QPOL_POLICY_KERNEL_BINARY:
		result_elem[0] = Tcl_NewStringObj("binary", -1); break;
	default:
		result_elem[0] = Tcl_NewStringObj("unknown", -1); break;
	}
	if (qpol_policy_is_mls_enabled(policydb->qh, policydb->p)) {
		result_elem[1] = Tcl_NewStringObj("mls", -1);
	}
	else {
		result_elem[1] = Tcl_NewStringObj("non-mls", -1);
	}
	result_list = Tcl_NewListObj(2, result_elem);
	Tcl_SetObjResult(interp, result_list);
	return TCL_OK;
}

static int Apol_GetPolicyVersionString(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	char *pol_string;
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if ((pol_string = apol_get_policy_version_type_mls_str(policydb)) == NULL) {
		Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
		return TCL_ERROR;
	}
	Tcl_SetResult(interp, pol_string, TCL_VOLATILE);
	free(pol_string);
	return TCL_OK;
}

/**
 * Returns the policy version number for the currently opened policy.
 */
static int Apol_GetPolicyVersionNumber(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	unsigned int version;
	Tcl_Obj *version_obj;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (qpol_policy_get_policy_version(policydb->qh, policydb->p, &version) < 0) {
		apol_tcl_write_error(interp);
		return TCL_ERROR;
	}
	version_obj = Tcl_NewIntObj(version);
	Tcl_SetObjResult(interp, version_obj);
	return TCL_OK;
}

/**
 * Appends a name and size to a stats list, conviently in a format
 * suitable for [array set].
 *
 * @param interp Tcl interpreter object.
 * @param name Statistic key.
 * @param size Value for statistic.
 * @param result_obj Tcl object to which append.
 *
 * @return 0 on success, < 0 on error.
 */
static int append_stats(Tcl_Interp *interp, char *name, size_t size, Tcl_Obj *result_list) {
	Tcl_Obj *stat_elem[2];
	stat_elem[0] = Tcl_NewStringObj(name, -1);
	stat_elem[1] = Tcl_NewIntObj(size);
	if (Tcl_ListObjAppendElement(interp, result_list, stat_elem[0]) != TCL_OK ||
	    Tcl_ListObjAppendElement(interp, result_list, stat_elem[1]) != TCL_OK) {
		return -1;
	}
	return 0;
}

struct policy_stat {
        char *name;
        int (*iter_func)(qpol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter);
};

/**
 * Calculate and return statistics about the policy, in a format
 * suitable for [array set].
 */
static int Apol_GetStats(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj  = Tcl_NewListObj(0, NULL);
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
		if (stats[i].iter_func(policydb->qh, policydb->p, &iter) < 0 ||
		    qpol_iterator_get_size(iter, &size) < 0 ||
		    append_stats(interp, stats[i].name, size, result_obj) < 0) {
			goto cleanup;
		}
		qpol_iterator_destroy(&iter);
	}

	/* the following do not have iterators that conveniently
	 * compute their sizes */

	if ((type_query = apol_type_query_create()) == NULL ||
	    (attr_query = apol_attr_query_create()) == NULL ||
	    (perm_query = apol_perm_query_create()) == NULL) {
		ERR(policydb, "Out of memory!");
	}

	if (apol_get_type_by_query(policydb, type_query, &v) < 0 ||
	    append_stats(interp, "types", apol_vector_get_size(v), result_obj) < 0) {
		goto cleanup;
	}
	apol_vector_destroy(&v, NULL);

	if (apol_get_attr_by_query(policydb, attr_query, &v) < 0 ||
	    append_stats(interp, "attribs", apol_vector_get_size(v), result_obj) < 0) {
		goto cleanup;
	}
	apol_vector_destroy(&v, NULL);

	if (apol_get_perm_by_query(policydb, perm_query, &v) < 0 ||
	    append_stats(interp, "perms", apol_vector_get_size(v), result_obj) < 0) {
		goto cleanup;
	}
	apol_vector_destroy(&v, NULL);

	if (qpol_policy_get_avrule_iter(policydb->qh, policydb->p,
					QPOL_RULE_ALLOW, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 ||
	    append_stats(interp, "teallow", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_avrule_iter(policydb->qh, policydb->p,
					QPOL_RULE_NEVERALLOW, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 ||
	    append_stats(interp, "neverallow", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_avrule_iter(policydb->qh, policydb->p,
					QPOL_RULE_AUDITALLOW, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 ||
	    append_stats(interp, "auditallow", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_avrule_iter(policydb->qh, policydb->p,
					QPOL_RULE_DONTAUDIT, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 ||
	    append_stats(interp, "dontaudit", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_terule_iter(policydb->qh, policydb->p,
					QPOL_RULE_TYPE_TRANS, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 ||
	    append_stats(interp, "tetrans", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_terule_iter(policydb->qh, policydb->p,
					QPOL_RULE_TYPE_MEMBER, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 ||
	    append_stats(interp, "temember", size, result_obj) < 0) {
		goto cleanup;
	}
	qpol_iterator_destroy(&iter);

	if (qpol_policy_get_terule_iter(policydb->qh, policydb->p,
					QPOL_RULE_TYPE_CHANGE, &iter) < 0 ||
	    qpol_iterator_get_size(iter, &size) < 0 ||
	    append_stats(interp, "techange", size, result_obj) < 0) {
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
	apol_vector_destroy(&v, NULL);
	return retval;
}

/* Get list of permission that are associated with given list of object classes 
 *
 * 1	classes (list)
 * 2	union (bool)	indicates whether union (1) or intersection (0) desired
 *
 */
int Apol_GetPermsByClass(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
	int i, rt, num_classes, num_perms, *perms;
	bool_t p_union;
	CONST char **classes;
	char buf[128], *name;
	
	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (policydb == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	rt = Tcl_SplitList(interp, argv[1], &num_classes, &classes);
	if(rt != TCL_OK)
		return rt;
	if(num_classes < 1)  {
		Tcl_AppendResult(interp, "No object classes were provided!", (char *) NULL);
		return TCL_ERROR;
	}	
	p_union = getbool(argv[2]);
/* FIX ME
	rt = get_perm_list_by_classes(p_union, num_classes, (const char**)classes, &num_perms, &perms, policy);
*/ rt = -2;
	if(rt == -2) {
		sprintf(buf, "Error with class names (%d)", num_perms);
		Tcl_AppendResult(interp, buf, (char *) NULL);
		Tcl_Free((char *) classes);
		return TCL_ERROR;
	}
	else if(rt != 0) {
		Tcl_AppendResult(interp, "Unspecified error getting permissions", (char *) NULL);
		Tcl_Free((char *) classes);
		return TCL_ERROR;
	}
	for(i = 0; i < num_perms; i++) {
                /* FIX ME
		assert(is_valid_perm_idx(perms[i], policy));
		rt = get_perm_name(perms[i], &name, policy);
                */ rt = -1;
		if(rt != 0) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "Problem getting permission name", (char *) NULL);
			Tcl_Free((char *) classes);
			free(perms);
		}
		Tcl_AppendElement(interp, name);
		free(name);
	}
	
	free(perms);
	Tcl_Free((char *) classes);	
	return TCL_OK;
}

/**
 * Checks if a range is valid or not according to the policy.  Returns
 * 1 if valid, 0 if invalid.
 *
 * @param argv This function takes one parameter: a range (2-uple of levels).
 */
static int Apol_IsValidRange(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	apol_mls_range_t *range = NULL;
	int retval = TCL_ERROR, retval2;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "Need a range.");
		goto cleanup;
	}
	if ((range = apol_mls_range_create()) == NULL) {
		ERR(policydb, "Out of memory!");
		goto cleanup;
	}
	retval2 = apol_tcl_string_to_range(interp, argv[1], range);
	if (retval2 < 0) {
		goto cleanup;
	}
	else if (retval2 == 1) {
		Tcl_SetResult(interp, "0", TCL_STATIC);
		retval = TCL_OK;
		goto cleanup;
	}
	retval2 = apol_mls_range_validate(policydb, range);
	if (retval2 < 0) {
		goto cleanup;
	}
	else if (retval2 == 0) {
		Tcl_SetResult(interp, "0", TCL_STATIC);
	}
	else {
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
static int Apol_IsValidPartialContext(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	apol_context_t *context = NULL;
	int retval = TCL_ERROR, retval2;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "Need a Tcl context.");
		goto cleanup;
	}
	if ((context = apol_context_create()) == NULL) {
		ERR(policydb, "Out of memory!");
		goto cleanup;
	}
	retval2 = apol_tcl_string_to_context(interp, argv[1], context);
	if (retval2 < 0) {
		goto cleanup;
	}
	else if (retval2 == 1) {
		Tcl_SetResult(interp, "0", TCL_STATIC);
		retval = TCL_OK;
		goto cleanup;
	}
	retval2 = apol_context_validate_partial(policydb, context);
	if (retval2 < 0) {
		goto cleanup;
	}
	else if (retval2 == 0) {
		Tcl_SetResult(interp, "0", TCL_STATIC);
	}
	else {
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

/* 
 * Used by the GUI to check if permission mappings are loaded.
 */
int Apol_IsPermMapLoaded(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char tbuf[64];
	
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policydb == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
        /* FIX ME
	if(policy->pmap != NULL)
		sprintf(tbuf, "%d", 1);
	else
        */
		sprintf(tbuf, "%d", 0);

	Tcl_AppendElement(interp, tbuf);
	return TCL_OK;
}

/* 
 * argv[1] - policy map file name (optional) - if one is not specified then apol will search for default
 */
int Apol_LoadPermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt;
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policydb == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "File name string too large", (char *) NULL);
		return TCL_ERROR;
	}
 	rt = load_perm_map_file(argv[1], interp);
	if(rt == -1) {
		return TCL_ERROR;	
	} 
	else if (rt == -2) {
		Tcl_AppendResult(interp, "The permission map has been loaded, but there were warnings. See stdout for more information.", (char *) NULL);
		/* This is the return value we use to indicate warnings */
		return -2;
	}

	return TCL_OK;
}

/* 
 * argv[1] - file name of policy map to save to disk
 */
int Apol_SavePermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	FILE *fp;
	char tbuf[256];
	char *pmap_file; 
	int rt;
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (policydb == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
        /* FIX ME
	if(policy->pmap == NULL) {
        */
		Tcl_AppendResult(interp, "No permission map currently loaded!", (char *) NULL);
		return TCL_ERROR;
#if 0
	}
	pmap_file = argv[1];
	if(!is_valid_str_sz(pmap_file)) {
		Tcl_AppendResult(interp, "File name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	/* perm map file */
	if((fp = fopen(pmap_file, "w+")) == NULL) {
		sprintf(tbuf, "Write permission to perm map file (%s) was not permitted!", pmap_file);
		Tcl_AppendResult(interp, tbuf, (char *) NULL);
		return TCL_ERROR;
	}
	rt = write_perm_map_file(policy->pmap, policy, fp);
	if(rt != 0) {
		fclose(fp);
		Tcl_AppendResult(interp, "Problem writing the user file", (char *) NULL);
		return TCL_ERROR;
	}
	fclose(fp);
	return TCL_OK;
#endif
}

/* update permission map
 * argv[1]  pmap_tmp_file
 */
int Apol_UpdatePermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	char *pmap_tmp_file = NULL; 
	char tbuf[256];
	int rt;
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policydb == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	/* Load the temporary perm map file into memory. */
 	pmap_tmp_file = argv[1]; 		
	rt = load_perm_map_file(pmap_tmp_file, interp);
	if(rt == -1) {
		sprintf(tbuf, "Could not load permission map (%s)!", pmap_tmp_file);
		Tcl_AppendResult(interp, tbuf, (char *) NULL);
		return TCL_ERROR;	
	} 	
	return TCL_OK;
}

/* return the permission map in the form of a TCL list. The TCL list looks like this:
 *
 *	INDEX		CONTENTS
 *	0 		number of object classes (N)
 *	1		object class name1
 *	2			number of permissions (N)
 *	3				selinux perm1
 *	4				mls base perm1
 *					...
 *   		 			...
 *		     			selinux perm (N)
 *	    				mls base perm (N)
 *			...
 *			object class name (N)
 * 
 */
int Apol_GetPermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	int i, j;
	class_perm_map_t *cls;
	classes_perm_map_t *map;
	char tbuf[64];
	
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (policydb == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
        /* FIX ME
	if(policy->pmap == NULL) {
        */
		Tcl_AppendResult(interp, "No permission map currently loaded!", (char *) NULL);
		return TCL_ERROR;
#if 0
	}
	map = policy->pmap;
	/* # of classes */
	sprintf(tbuf, "%d", map->num_classes);
	Tcl_AppendElement(interp, tbuf);
	for(i = 0; i < map->num_classes; i++) {
		cls = &map->maps[i];
		Tcl_AppendElement(interp, policy->obj_classes[cls->cls_idx].name);
		/* # of class perms */
		sprintf(tbuf, "%d", cls->num_perms);
		Tcl_AppendElement(interp, tbuf);
		
		for(j = 0; j < cls->num_perms; j++) {
			Tcl_AppendElement(interp, policy->perms[cls->perm_maps[j].perm_idx]);
			if((cls->perm_maps[j].map & PERMMAP_BOTH) == PERMMAP_BOTH) {
				Tcl_AppendElement(interp, "b");
			} 
			else {
				switch(cls->perm_maps[j].map & (PERMMAP_READ|PERMMAP_WRITE|PERMMAP_NONE|PERMMAP_UNMAPPED)) {
				case PERMMAP_READ: 	Tcl_AppendElement(interp, "r");
							break;
				case PERMMAP_WRITE: 	Tcl_AppendElement(interp, "w");
							break;	
				case PERMMAP_NONE: 	Tcl_AppendElement(interp, "n");
							break;
				case PERMMAP_UNMAPPED: 	Tcl_AppendElement(interp, "u");
							break;	
				default:		Tcl_AppendElement(interp, "?");
				} 
			} 
			sprintf(tbuf, "%d", cls->perm_maps[j].weight);
			Tcl_AppendElement(interp, tbuf);
		}
	}
	return TCL_OK;
#endif
}



/* Package initialization */
int Apol_Init(Tcl_Interp *interp)
{
	Tcl_CreateCommand(interp, "apol_GetScriptDir", Apol_GetScriptDir, NULL,  NULL);
	Tcl_CreateCommand(interp, "apol_GetHelpDir", Apol_GetHelpDir, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_OpenPolicy", Apol_OpenPolicy, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_ClosePolicy", Apol_ClosePolicy, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetVersion", (Tcl_CmdProc *) Apol_GetVersion, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
        Tcl_CreateCommand(interp, "apol_GetStats", Apol_GetStats, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionString", (Tcl_CmdProc *) Apol_GetPolicyVersionString, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionNumber", Apol_GetPolicyVersionNumber, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPermsByClass", (Tcl_CmdProc *) Apol_GetPermsByClass, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_LoadPermMap", (Tcl_CmdProc *) Apol_LoadPermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_SavePermMap", (Tcl_CmdProc *) Apol_SavePermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_UpdatePermMap", (Tcl_CmdProc *) Apol_UpdatePermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPermMap", (Tcl_CmdProc *) Apol_GetPermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_IsPermMapLoaded", (Tcl_CmdProc *) Apol_IsPermMapLoaded, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetDefault_PermMap", (Tcl_CmdProc *) Apol_GetDefault_PermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_IsValidRange", Apol_IsValidRange, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsValidPartialContext", Apol_IsValidPartialContext, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyType", Apol_GetPolicyType, NULL, NULL);

        if (apol_tcl_render_init(interp) != TCL_OK ||
            apol_tcl_components_init(interp) != TCL_OK ||
            apol_tcl_rules_init(interp) != TCL_OK ||
            ap_tcl_fc_init(interp) != TCL_OK ||
            ap_tcl_analysis_init(interp) != TCL_OK) {
                return TCL_ERROR;
        }
        Tcl_PkgProvide(interp, "apol", (char*)libapol_get_version());

        return TCL_OK;
}
