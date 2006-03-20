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

#define _GNU_SOURCE
#include <stdarg.h>
#include <string.h>
#include <tcl.h>
#include <assert.h>
#include <unistd.h>
#include "policy.h"
#include "policy-io.h"
#include "util.h"
#include "render.h"
#include "perm-map.h"

#include "component-query.h"
#include "context-query.h"
#include "mls-query.h"

#include "apol_tcl_render.h"
#include "apol_tcl_components.h"
#include "apol_tcl_rules.h"
#include "apol_tcl_fc.h"
#include "apol_tcl_analysis.h"

#ifdef APOL_PERFORM_TEST
#include <time.h>
#endif

policy_t *policy; /* local global for policy DB */

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
		Tcl_SetObjResult(interp, obj);
		apol_tcl_clear_error();
	}
}

/* Takes a Tcl string representing a MLS level and converts it to an
 * ap_mls_level_t object.  Returns 0 on success, 1 if a identifier was
 * not unknown, or -1 on error. */
int ap_tcl_level_string_to_level(Tcl_Interp *interp, const char *level_string, ap_mls_level_t *level) {
        Tcl_Obj *level_obj, *sens_obj, *cats_list_obj, *cats_obj;
        const char *sens_string, *cat_string;
        int num_cats, i, cat_value;
        level->sensitivity = 0;
        level->categories = NULL;
        level->num_categories = 0;

        if (policy == NULL) {
                /* no policy, so nothing to convert */
                return 1;
        }
        level_obj = Tcl_NewStringObj(level_string, -1);
        if (Tcl_ListObjIndex(interp, level_obj, 0, &sens_obj) == TCL_ERROR) {
                return -1;
        }
        if (Tcl_ListObjIndex(interp, level_obj, 1, &cats_list_obj) == TCL_ERROR) {
                return -1;
        }
        if (sens_obj == NULL || cats_list_obj == NULL) {
                /* no sensitivity given -- this is an error */
                Tcl_SetResult(interp, "Sensivitiy string did not have two elements within it.", TCL_STATIC);
                return -1;
        }
        sens_string = Tcl_GetString(sens_obj);
        if ((level->sensitivity = get_sensitivity_idx(sens_string, policy)) < 0) {
                /* unknown sensitivity */
                return 1;
        }
        if (Tcl_ListObjLength(interp, cats_list_obj, &num_cats) == TCL_ERROR) {
                return -1;
        }
        for (i = 0; i < num_cats; i++) {
                if (Tcl_ListObjIndex(interp, cats_list_obj, i, &cats_obj) == TCL_ERROR) {
                        free(level->categories);
                        return -1;
                }
                assert(cats_obj != NULL);
                cat_string = Tcl_GetString(cats_obj);
                if ((cat_value = get_category_idx(cat_string, policy)) < 0) {
                        /* unknown category */
                        free(level->categories);
                        return 1;
                }
                if (add_i_to_a(cat_value, &(level->num_categories), &(level->categories))) {
                        Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
                        free(level->categories);
                        return -1;
                }
        }
        return 0;
}

int apol_tcl_string_to_level(Tcl_Interp *interp, const char *level_string,
			     apol_mls_level_t *level)
{
	Tcl_Obj *level_obj, *sens_obj, *cats_list_obj, *cats_obj;
	const char *sens_string, *cat_string;
	sepol_level_datum_t *sens_datum;
	sepol_cat_datum_t *cat_datum;
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
	if (sepol_policydb_get_level_by_name(policydb->sh, policydb->p,
					     sens_string, &sens_datum) < 0) {
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
		if (sepol_policydb_get_cat_by_name(policydb->sh, policydb->p,
						   cat_string, &cat_datum) < 0) {
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
		ERR(policydb, "Out of memory.");
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
			Tcl_SetResult(interp, "Out of memory.", TCL_STATIC);
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

#define APOL_TCL_PMAP_WARNINGS_SUBSET (PERMMAP_RET_UNMAPPED_PERM|PERMMAP_RET_UNMAPPED_OBJ|PERMMAP_RET_OBJ_REMMAPPED)

/**************************************************************************
 * work functions
 **************************************************************************/
 
static int load_perm_map_file(char *pmap_file, Tcl_Interp *interp);
static char* find_perm_map_file(char *perm_map_fname);
static char* find_tcl_script(char *script_name);



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
 
 
/* find the provided TCL script file according to the algorithm
 * described above.  This function returns a string of the directory.
 */
static char* find_tcl_script(char *script_name)
{
	/* This funciton has been replaced by the more generic find_file() in uitl.c */	
	return find_file(script_name);	
}

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
	
	if(policy == NULL) {
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

	m_ret = load_policy_perm_mappings(policy, pfp);
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


/* Get the directory where the TCL scripts are located.  This function
 * simply returns the value of the script_dir GLOBAL variable defined above 
 * if has been set previously.  Otherwise it calls
 * find_tcl_script() and then returns the variable.  Someone needs to call
 * this function during or prior to running scripts that use these commands.
 *
 * There is one argument, the file name of the top-level TCL script (e.g.,
 * apol.tcl) which is located according to find_tcl_script().  The presumption
 * is that any other TCL script will be in the same directory.
 */
int Apol_GetScriptDir(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	
	if(script_dir == NULL) {
		script_dir = find_tcl_script(argv[1]);
		if(script_dir == NULL) {
			Tcl_AppendResult(interp, "problem locating TCL startup script", (char *) NULL);
			return TCL_ERROR;
		}
	}
	assert(script_dir != NULL);
	Tcl_AppendResult(interp, script_dir, (char *) NULL);
	return TCL_OK;		
}

/* Get the directory where the help files are located.  This function
 * simply returns the value of the help_dir GLOBAL variable defined above 
 * if has been set previously.  Otherwise it calls
 * find_tcl_script() and then returns the variable.  Someone needs to call
 * this function during or prior to running scripts that use these commands.
 */
int Apol_GetHelpDir(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	
	if(help_dir == NULL) {
		help_dir = find_file(argv[1]);
		if(help_dir == NULL) {
			Tcl_AppendResult(interp, "problem locating help file.", (char *) NULL);
			return TCL_ERROR;
		}
	}
	assert(help_dir != NULL);
	Tcl_AppendResult(interp, help_dir, (char *) NULL);
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

/* open a policy.conf file 
 *	argv[1] - filename 
 *      argv[2] - open option for loading all or pieces of a policy.  
 *		  This option option may be one of the following:
 *	 		0 - ALL of the policy
 *			1 - Users only
 *			2 - Roles only
 *			3 - Types and attributes only
 *			4 - Booleans only
 *			5 - Classes and permissions only
 *			6 - RBAC rules only
 *			7 - TE rules only
 *			8 - Conditionals only
 *			9 - Initial SIDs only
 */
int Apol_OpenPolicy(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char tbuf[APOL_STR_SZ+64];
	unsigned int opts;
	int rt, option;
	FILE* tmp;
	
	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char*)NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "File name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	/* Make sure the provided option is an integer. */
	rt = Tcl_GetInt(interp, argv[2], &option);
	if(rt == TCL_ERROR) {
		Tcl_AppendResult(interp,"argv[2] apparently not an integer", (char *) NULL);
		return TCL_ERROR;
	}

	/* Since argv[2] is a string ending with the terminating string char, 
	 * we use the first character in our switch statement. */	
	switch(argv[2][0]) {
	case '0':
		opts = POLOPT_ALL;
		break;
	case '1':
		opts = POLOPT_USERS;
		break;
	case '2':
		opts = POLOPT_ROLES;
		break;
	case '3':
		opts = POLOPT_TYPES;
		break;
	case '4':
		opts = POLOPT_COND_BOOLS;
		break;
	case '5':
		opts = POLOPT_OBJECTS;
		break;
	case '6':
		opts = POLOPT_RBAC;
		break;
	case '7':
		opts = POLOPT_TE_POLICY;
		break;
	case '8':
		opts = POLOPT_COND_POLICY;
		break;
	case '9':
		opts = POLOPT_INITIAL_SIDS;
		break;
	default:
		Tcl_AppendResult(interp, "Invalid option:", argv[2], (char) NULL);
		return TCL_ERROR;
	}
	
	/* open_policy will actually open the file for reading - it is done here so that a
	 * descriptive error message can be returned if the file cannot be read.
	 */
	if((tmp = fopen(argv[1], "r")) == NULL) {
		Tcl_AppendResult(interp, "cannot open policy file for reading", argv[1], (char *) NULL);
		return TCL_ERROR;
	}	
	fclose(tmp);
	free_policy(&policy);
	
	rt = open_partial_policy(argv[1], opts, &policy);
	if(rt != 0) {
		free_policy(&policy);
		sprintf(tbuf, "open_policy error (%d)", rt);
		Tcl_AppendResult(interp, tbuf, (char *) NULL);
		return rt;
	}

	/******** new routine here ********/
	if (is_binary_policy(policy)) {
		if (apol_policy_open_binary(argv[1], &policydb)) {
			Tcl_SetResult(interp, "Open policy error.", TCL_STATIC);
			return TCL_ERROR;
		}
		policydb->msg_callback_arg = NULL;
		policydb->msg_callback = apol_tcl_route_handle_to_string;
	}
	return TCL_OK;
}

int Apol_ClosePolicy(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	close_policy(policy);
	policy = NULL;

        /******** new routine here ********/
	apol_policy_destroy(&policydb);
	return TCL_OK;
}

int Apol_GetVersion(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	Tcl_AppendResult(interp, (char*)libapol_get_version(), (char *) NULL);
	return TCL_OK;
}

/* Returns a 2-uple describing the current policy type.  The first
 * element is says if the policy is binary or source.  The second
 * element gives if the policy is MLS or not.
 *
 *   field 1: "binary" or "source"
 *   field 2: "mls" or "non-mls"
 */
int Apol_GetPolicyType(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(is_binary_policy(policy) )
		Tcl_AppendResult(interp, "binary", (char *) NULL);
	else
		Tcl_AppendResult(interp, "source", (char *) NULL);
	if (is_mls_policy(policy))
		Tcl_AppendElement(interp, "mls");
	else
		Tcl_AppendElement(interp, "non-mls");
	return TCL_OK;
}

/* Return flags indicating what data is in the current policy.  Following data types:
 *     	classes		object classes
 *	perms		permissions (including common perms)
 *	types		types and attributes
 *	te_rules	type enforcement rules, including allow, type_trans, audit_*, etc.
 *	roles		roles
 *	rbac		role rules
 *	users		user definitions
 */
int Apol_GetPolicyContents(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}

/* FIX: This is a place-holder function to be used by the GUI...need to have the policy.c
 * stuff control this via flags. */
	Tcl_AppendElement(interp, "classes 1");
	Tcl_AppendElement(interp, "perms 1");
	Tcl_AppendElement(interp, "types 1");
	Tcl_AppendElement(interp, "te_rules 1");
	Tcl_AppendElement(interp, "roles 1");
	Tcl_AppendElement(interp, "rbac 1");
	Tcl_AppendElement(interp, "users 1");
	return TCL_OK;	
}

int Apol_GetPolicyVersionString(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
        char *pol_string;
	if(policy == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
        if ((pol_string = get_policy_version_type_mls_str(policy)) == NULL) {
                Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
                return TCL_ERROR;
        }
	Tcl_SetResult(interp, pol_string, TCL_VOLATILE);
        free(pol_string);
	return TCL_OK;
}

/* returns the policy version number */
int Apol_GetPolicyVersionNumber(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	switch (policy->version) {
	case POL_VER_PRE_11:
		Tcl_AppendResult(interp, "10", (char *) NULL);
		break;
	case POL_VER_11:
	/* case POL_VER_12: */ /* (currently synonmous with v.11 */
		Tcl_AppendResult(interp, "12", (char *) NULL);
		break;
	case POL_VER_15:
		Tcl_AppendResult(interp, "15", (char *) NULL);
		break;
	case POL_VER_16:
		Tcl_AppendResult(interp, "16", (char *) NULL);
		break;
	case POL_VER_17:
		Tcl_AppendResult(interp, "17", (char *) NULL);
		break;
	case POL_VER_18:
		Tcl_AppendResult(interp, "18", (char *) NULL);
		break;
	case POL_VER_19:
		Tcl_AppendResult(interp, "19", (char *) NULL);
		break;
	case POL_VER_18_20:
	case POL_VER_20:
	case POL_VER_19_20:
		Tcl_AppendResult(interp, "20", (char *) NULL);
		break;
	default:
		Tcl_AppendResult(interp, "0", (char *) NULL);
		break;
	}
	return TCL_OK;
}

struct ap_policy_stat {
        const char *name;
        int num_elems;
};

/* Calculate and return statistics about the policy, in a format
 * suitable for [array set]. */
static int Apol_GetStats(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        Tcl_Obj *result_obj  = Tcl_NewListObj(0, NULL);
        int num_genfscon;
        if(policy == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
                return TCL_ERROR;
        }
        num_genfscon = ap_genfscon_get_num_paths(policy);
        {
                struct ap_policy_stat stats[] = {
                        /* components */
                        {"types", policy->num_types},
                        {"attribs", policy->num_attribs},
                        {"roles", policy->num_roles},
                        {"classes", policy->num_obj_classes},
                        {"common_perms", policy->num_common_perms},
                        {"perms", policy->num_perms},
                        {"users", policy->rule_cnt[RULE_USER]},
                        {"cond_bools", policy->num_cond_bools},

                        /* rules */
                        {"teallow", policy->rule_cnt[RULE_TE_ALLOW]},
                        {"neverallow", policy->rule_cnt[RULE_NEVERALLOW]},
                        {"auditallow", policy->rule_cnt[RULE_AUDITALLOW]},
                        {"auditdeny", policy->rule_cnt[RULE_AUDITDENY]},
                        {"dontaudit", policy->rule_cnt[RULE_DONTAUDIT]},
                        {"tetrans", policy->rule_cnt[RULE_TE_TRANS]},
                        {"temember", policy->rule_cnt[RULE_TE_MEMBER]},
                        {"techange", policy->rule_cnt[RULE_TE_CHANGE]},
                        {"clone", policy->rule_cnt[RULE_CLONE]},

                        /* rbac */
                        {"roleallow", policy->rule_cnt[RULE_ROLE_ALLOW]},
                        {"roletrans", policy->rule_cnt[RULE_ROLE_TRANS]},

                        /* mls */
                        {"sens", policy->num_sensitivities},
                        {"cats", policy->num_categories},
                        {"rangetrans", policy->num_rangetrans},

                        /* contexts */
                        {"sids", policy->num_initial_sids},
                        {"portcons", policy->num_portcon},
                        {"netifcons", policy->num_netifcon},
                        {"nodecons", policy->num_nodecon},
                        {"genfscons", num_genfscon},
                        {"fs_uses", policy->num_fs_use}
                };
                int i;
                Tcl_Obj *stat_elem[2];

                for (i = 0; i < sizeof(stats) / sizeof(stats[0]); i++) {
                        stat_elem[0] = Tcl_NewStringObj(stats[i].name, -1);
                        stat_elem[1] = Tcl_NewIntObj(stats[i].num_elems);
                        if (Tcl_ListObjAppendElement(interp, result_obj, stat_elem[0]) != TCL_OK ||
                            Tcl_ListObjAppendElement(interp, result_obj, stat_elem[1]) != TCL_OK) {
                                return TCL_ERROR;
                        }
                }
        }
		
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
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
	if(policy == NULL) {
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
	
	rt = get_perm_list_by_classes(p_union, num_classes, (const char**)classes, &num_perms, &perms, policy);
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
		assert(is_valid_perm_idx(perms[i], policy));
		rt = get_perm_name(perms[i], &name, policy);
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
 */
static int Apol_IsValidRange(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	apol_mls_range_t *range = NULL;
	int retval = TCL_ERROR, retval2;
	apol_tcl_clear_error();
	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a range.", TCL_STATIC);
		return TCL_ERROR;
	}
	if ((range = apol_mls_range_create()) == NULL) {
		Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
		return TCL_ERROR;
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
		retval = TCL_OK;
		goto cleanup;
	}
	Tcl_SetResult(interp, "1", TCL_STATIC);
	retval = TCL_OK;
 cleanup:
	apol_mls_range_destroy(&range);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}


/* Takes a Tcl string representing a context (user:role:type:range)
 * and converts it to a securite_con_t object.  If a component is
 * blank then set it to -1/NULL.  Returns 0 on success, 1 if a identifier
 * was not unknown, or -1 on error. */
static int tcl_context_string_to_context(Tcl_Interp *interp, char *context_string, security_con_t *context,
                                         ap_mls_range_t *range, ap_mls_level_t *low_level, ap_mls_level_t *high_level) {
        Tcl_Obj *context_obj, *user_obj, *role_obj, *type_obj, *range_obj;
        const char *user_string, *role_string, *type_string;
        int range_len;

        context->user = context->role = context->type = -1;
        context->range = NULL;

        if (policy == NULL) {
                return 1;
        }
        context_obj = Tcl_NewStringObj(context_string, -1);
        if (Tcl_ListObjIndex(interp, context_obj, 0, &user_obj) == TCL_ERROR ||
            user_obj == NULL) {
                return -1;
        }
        user_string = Tcl_GetString(user_obj);
        if (strcmp(user_string, "") != 0) {
                if ((context->user = get_user_idx(user_string, policy)) < 0) {
                        return 1;
                }
        }
        if (Tcl_ListObjIndex(interp, context_obj, 1, &role_obj) == TCL_ERROR ||
            role_obj == NULL) {
                return -1;
        }
        role_string = Tcl_GetString(role_obj);
        if (strcmp(role_string, "") != 0) {
                if ((context->role = get_role_idx(role_string, policy)) < 0) {
                        return 1;
                }
        }
        if (Tcl_ListObjIndex(interp, context_obj, 2, &type_obj) == TCL_ERROR ||
            type_obj == NULL) {
                return -1;
        }
        type_string = Tcl_GetString(type_obj);
        if (strcmp(type_string, "") != 0) {
                if ((context->type = get_type_idx(type_string, policy)) < 0) {
                        return 1;
                }
        }
        if (Tcl_ListObjIndex(interp, context_obj, 3, &range_obj) == TCL_ERROR ||
            range_obj == NULL ||
            Tcl_ListObjLength(interp, range_obj, &range_len) == TCL_ERROR) {
                return -1;
        }
        if (range_len != 0) {
                Tcl_Obj *low_obj, *high_obj;
                char *level_string;
                if (Tcl_ListObjIndex(interp, range_obj, 0, &low_obj) == TCL_ERROR) {
                        return -1;
                }
                level_string = Tcl_GetString(low_obj);
                if (strcmp(level_string, "{} {}") == 0) {
                        /* no real level given, so treat it as being empty */
                        return 0;
                }
                if (ap_tcl_level_string_to_level(interp, level_string, low_level)) {
                        return -1;
                }
                range->low = low_level;
                if (range_len == 1) {
                        range->high = low_level;
                }
                else {
                        if (Tcl_ListObjIndex(interp, range_obj, 1, &high_obj) == TCL_ERROR) {
                                return -1;
                        }
                        level_string = Tcl_GetString(high_obj);
                        if (strcmp(level_string, "{} {}") == 0) {
                                /* no real level given, so treat it as being empty */
                                range->high = low_level;
                                context->range = range;
                                return 0;
                        }
                        if (ap_tcl_level_string_to_level(interp, level_string, high_level)) {
                                ap_mls_level_free(low_level);
                                range->low = range->high = NULL;
                                return -1;
                        }
                        range->high = high_level;
                }
                context->range = range;
        }
        return 0;
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
	if (policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc < 2) {
		Tcl_SetResult(interp, "Need a Tcl context.", TCL_STATIC);
		return TCL_ERROR;
	}
        if ((context = apol_context_create()) == NULL) {
                Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
                return TCL_ERROR;
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
		retval = TCL_OK;
		goto cleanup;
	}
	Tcl_SetResult(interp, "1", TCL_STATIC);
        retval = TCL_OK;
 cleanup:
        apol_context_destroy(&context);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
        return retval;
}

/* Compare two contexts:
 *
 *  argv[1] - first context  (4-ple of components)
 *  argv[2] - second context (4-ple of components)
 *  argv[3] - search type  ("exact", "subset", or "superset")
 *
 * A context consists of a user, role, type, and MLS range.  The first
 * context may have empty elements that indicate not to compare that
 * region.  argv[3] is ignored if argv[1] does not give an MLS range.
 * Returns 1 if the comparison succeeds (based upon search type), 0 if
 * not.
 *   for subset, is argv[1] a subset of argv[2]
 *   for superset, is argv[1] a superset of argv[2]
 */
int Apol_CompareContexts(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
        security_con_t context1 = {0, 0, 0, NULL}, context2 = {0, 0, 0, NULL};
        ap_mls_range_t range1, range2;
        ap_mls_level_t low1, high1, low2, high2;
        int retval = TCL_ERROR;
        unsigned char range_match = 0;
        bool_t answer;

        if (argc != 4) {
		Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
                goto cleanup;
	}
	if (policy == NULL) {
                Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
                goto cleanup;
	}
        if (tcl_context_string_to_context(interp, argv[1], &context1,
                                          &range1, &low1, &high1) != 0) {
                Tcl_SetResult(interp, "Could not convert context1 to struct.", TCL_STATIC);
                goto cleanup;
        }
        if (tcl_context_string_to_context(interp, argv[2], &context2,
                                          &range2, &low2, &high2) != 0) {
                Tcl_SetResult(interp, "Could not convert context2 to struct.", TCL_STATIC);
                goto cleanup;
        }
        if (context1.range != NULL && context2.range != NULL) {
                if (strcmp(argv[3], "exact") == 0) {
                        range_match = AP_MLS_RTS_RNG_EXACT;
                }
                else if (strcmp(argv[3], "subset") == 0) {
                        range_match = AP_MLS_RTS_RNG_SUB;
                }
                else if (strcmp(argv[3], "superset") == 0) {
                        range_match = AP_MLS_RTS_RNG_SUPER;
                }
        }
        answer = match_security_context(&context2, &context1, range_match, policy);
        if (answer == TRUE) {
                Tcl_SetResult(interp, "1", TCL_STATIC);
        }
        else {
                Tcl_SetResult(interp, "0", TCL_STATIC);
        }
        retval = TCL_OK;

 cleanup:
        if (context1.range != NULL) {
                ap_mls_range_free(context1.range);
        }
        if (context2.range != NULL) {
                ap_mls_range_free(context2.range);
        }
        return retval;
}

/* Determines if a user address would be accepted by a addr/mask pair.
 *   argv[1] - user address (4-ple address)
 *   argv[2] - target address (4-ple address)
 *   argv[3] - target mask (4-ple mask)
 * Returns 1 if address is accepted, 0 if not.
 */
int Apol_CompareAddresses(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
        Tcl_Obj *user_addr_obj, *tgt_addr_obj, *tgt_mask_obj, *x, *y, *z;
        long ua, ta, tm;
        int i;

        if (argc != 4) {
		Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
                return TCL_ERROR;
        }

        user_addr_obj = Tcl_NewStringObj(argv[1], -1);
        tgt_addr_obj = Tcl_NewStringObj(argv[2], -1);
        tgt_mask_obj = Tcl_NewStringObj(argv[3], -1);
        for (i = 0; i < 4; i++) {
                if (Tcl_ListObjIndex(interp, user_addr_obj, i, &x) == TCL_ERROR ||
                    x == NULL ||
                    Tcl_GetLongFromObj(interp, x, &ua) == TCL_ERROR) {
                        Tcl_AppendResult(interp, "Invalid user address ", argv[1], NULL);
                        return TCL_ERROR;
                }
                if (Tcl_ListObjIndex(interp, tgt_addr_obj, i, &y) == TCL_ERROR ||
                    y == NULL ||
                    Tcl_GetLongFromObj(interp, y, &ta) == TCL_ERROR) {
                        Tcl_AppendResult(interp, "Invalid target address ", argv[2], NULL);
                        return TCL_ERROR;
                }
                if (Tcl_ListObjIndex(interp, tgt_mask_obj, i, &z) == TCL_ERROR ||
                    z == NULL ||
                    Tcl_GetLongFromObj(interp, z, &tm) == TCL_ERROR) {
                        Tcl_AppendResult(interp, "Invalid target mask ", argv[3], NULL);
                        return TCL_ERROR;
                }
                if ((ua & tm) != ta) {
                        Tcl_SetResult(interp, "0", TCL_STATIC);
                        return TCL_OK;
                }
        }
        Tcl_SetResult(interp, "1", TCL_STATIC);
        return TCL_OK;
}

/* Takes a string representing an address (either IPv4 or IPv6) and
 * returns a list of four signed integers representing that value. */
int Apol_ConvertStringToAddress(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
        uint32_t addr[4];
        int i;
        Tcl_Obj *addr_elem[4], *addr_obj;
        if (argc != 2) {
		Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
		return TCL_ERROR;
        }
        if (str_to_internal_ip(argv[1], addr) == -1) {
                Tcl_SetResult(interp, "Could not convert address", TCL_STATIC);
                return TCL_ERROR;
        }
        for (i = 0; i < 4; i++) {
                addr_elem[i] = Tcl_NewLongObj((long) addr[i]);
        }
        addr_obj = Tcl_NewListObj(4, addr_elem);
        Tcl_SetObjResult(interp, addr_obj);
        return TCL_OK;
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
	if(policy == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy->pmap != NULL) 
		sprintf(tbuf, "%d", 1);
	else 
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
	if(policy == NULL) {
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
	if(policy == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp, "No permission map currently loaded!", (char *) NULL);
		return TCL_ERROR;
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
	if(policy == NULL) {
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
	if(policy == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp, "No permission map currently loaded!", (char *) NULL);
		return TCL_ERROR;
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
}



/* Package initialization */
int Apol_Init(Tcl_Interp *interp) 
{
	Tcl_CreateCommand(interp, "apol_GetScriptDir", (Tcl_CmdProc *) Apol_GetScriptDir, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetHelpDir", (Tcl_CmdProc *) Apol_GetHelpDir, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_OpenPolicy", (Tcl_CmdProc *) Apol_OpenPolicy, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_ClosePolicy", (Tcl_CmdProc *) Apol_ClosePolicy, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetVersion", (Tcl_CmdProc *) Apol_GetVersion, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
        Tcl_CreateCommand(interp, "apol_GetStats", Apol_GetStats, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionString", (Tcl_CmdProc *) Apol_GetPolicyVersionString, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionNumber", (Tcl_CmdProc *) Apol_GetPolicyVersionNumber, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyContents", (Tcl_CmdProc *) Apol_GetPolicyContents, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPermsByClass", (Tcl_CmdProc *) Apol_GetPermsByClass, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_LoadPermMap", (Tcl_CmdProc *) Apol_LoadPermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_SavePermMap", (Tcl_CmdProc *) Apol_SavePermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_UpdatePermMap", (Tcl_CmdProc *) Apol_UpdatePermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPermMap", (Tcl_CmdProc *) Apol_GetPermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_IsPermMapLoaded", (Tcl_CmdProc *) Apol_IsPermMapLoaded, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetDefault_PermMap", (Tcl_CmdProc *) Apol_GetDefault_PermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_IsValidRange", Apol_IsValidRange, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsValidPartialContext", Apol_IsValidPartialContext, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_ConvertStringToAddress", (Tcl_CmdProc *) Apol_ConvertStringToAddress, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_CompareContexts", (Tcl_CmdProc *) Apol_CompareContexts, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_CompareAddresses", (Tcl_CmdProc *) Apol_CompareAddresses, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyType", (Tcl_CmdProc *) Apol_GetPolicyType, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);

        if (ap_tcl_render_init(interp) != TCL_OK ||
            ap_tcl_components_init(interp) != TCL_OK ||
            ap_tcl_rules_init(interp) != TCL_OK ||
            ap_tcl_fc_init(interp) != TCL_OK ||
            ap_tcl_analysis_init(interp) != TCL_OK) {
                return TCL_ERROR;
        }
        Tcl_PkgProvide(interp, "apol", (char*)libapol_get_version());

        return TCL_OK;
}
