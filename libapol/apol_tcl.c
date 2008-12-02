/* Copyright (C) 2002-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 *         Jason Tang (tang@jtang.org) - added flow assertion routines
 */

/* apol_tcl.c
 *
 */
 
/* The tcl functions to support the GUI using TK */

#include <stdlib.h>
#include <string.h>
#include <tcl.h>
#include <tk.h>
#include <assert.h>
#include <unistd.h>
#include <regex.h>
#include "policy.h"
#include "policy-io.h"
#include "util.h"
#include "apol_tcl.h"
#include "render.h"
#include "analysis.h"
#include "infoflow.h"
#include "perm-map.h"
#include "policy-query.h"

#ifdef LIBSEFS
#include "../libsefs/fsdata.h"
#endif

#include "flowassert.h"
#include "relabel_analysis.h"
#ifdef APOL_PERFORM_TEST
#include <time.h>
#endif

/* 
 * Several of the public C functions provided by the Tcl/Tk 8.4 libraries 
 * have had their declarations augmented with the addition of CONST modifiers 
 * on pointers. In order to support both the 8.3 and 8.4 prototype Tcl/Tk 
 * libraries, we use the internal symbol CONST84 instead of const. In this 
 * way, compiling against the 8.4 headers, will use the const-ified interfaces, 
 * but compiling against the 8.3 headers, will user the original interfaces.
 */
#ifndef CONST84
#define CONST84
#endif

extern char *rulenames[]; /* in render.c*/
policy_t *policy; /* local global for policy DB */
void* state = NULL; /* local global variable to support step-by-step transitive information flow analysis */

#ifdef LIBSEFS
sefs_filesystem_db_t *fsdata = NULL; /* local global for file context DB */
bool_t is_libsefs_builtin = TRUE;
#else
bool_t is_libsefs_builtin = FALSE;
#endif

#define APOL_TCL_PMAP_WARNINGS_SUBSET (PERMMAP_RET_UNMAPPED_PERM|PERMMAP_RET_UNMAPPED_OBJ|PERMMAP_RET_OBJ_REMMAPPED)

/**************************************************************************
 * work functions
 **************************************************************************/
 
 /* some internal prototypes */
static iflow_query_t* set_transitive_query_args(Tcl_Interp *interp, char *argv[]);
static int append_common_perm_str(bool_t do_perms, bool_t do_classes, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy);
static int append_perm_str(bool_t do_common_perms, bool_t do_classes, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy);
static int append_class_str(bool_t do_perms, bool_t do_cps, bool_t expand_cps, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy);
static int append_direct_edge_to_results(policy_t *policy, iflow_query_t* q, iflow_t *answers, Tcl_Interp *interp);
static int append_transitive_iflow_results(policy_t *policy, iflow_transitive_t* answers, Tcl_Interp *interp);
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

/* 
 * NOTE: The following are TCL specific functions for the GUI interface.  
 */
static int append_common_perm_str(bool_t do_perms, bool_t do_classes, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy)
{
	int i;
	char tbuf[APOL_STR_SZ + 64];
	
	if(idx >= policy->num_common_perms|| buf == NULL) {
		return -1;
	}	
	Tcl_DStringAppend(buf, policy->common_perms[idx].name, -1);
	if(do_perms) {
		sprintf(tbuf, "   (%d permissions)\n", policy->common_perms[idx].num_perms);
		Tcl_DStringAppend(buf, tbuf, -1);
		for(i = 0; i < policy->common_perms[idx].num_perms; i++) {
			Tcl_DStringAppend(buf, "     ", -1);
			append_perm_str(0, 0, 1, policy->common_perms[idx].perms[i], buf, policy);
		}
	}
	/* determine which classes use this common perm */
	if(do_classes) {
		Tcl_DStringAppend(buf, "\n   Object classes that use this common permission\n", -1);
		for(i = 0; i < policy->num_obj_classes; i++) {
			if(does_class_use_common_perm(i, idx, policy)) {
				Tcl_DStringAppend(buf, "     ", -1);
				append_class_str(0,0,0,1,i,buf,policy);
			}
		}
	}
	
	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);		
	return TCL_OK;
}

/* 
 * argv[1] - domain type used to start the analysis
 * argv[2] - flow direction - IN or OUT
 * argv[3] - flag (boolean value) for indicating that a list of object classes are being provided.
 * argv[4] - number of object classes that are to be included in the query.
 * argv[5] - flag (boolean value) for indicating that filter on end type(s) is being provided 
 * argv[6] - ending type regular expression 
 * argv[7] - encoded list of object class/permissions to exclude in the query
 * argv[8] - flag (boolean value) for indicating whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
 * argv[10] - flag (boolean value) whether or not to use minimum weight.
 * argv[11] - minimum weight value
 *
 * NOTE: THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! If, not it will throw an error.
 *
 */
static iflow_query_t* set_transitive_query_args(Tcl_Interp *interp, char *argv[])
{
	int num_objs, num_obj_perms, num_objs_options, obj, perm;
	int num_inter_types, type, *types = NULL;
	int i, j, rt, num, cur, sz = 0;
	char *start_type = NULL, *end_type = NULL;
	char *err, *name;
	char tbuf[64];
	CONST84 char **obj_class_perms = NULL, **inter_types = NULL;
	bool_t filter_obj_classes, filter_end_types, filter_inter_types, use_min_weight;
	regex_t reg;
	iflow_query_t *iflow_query = NULL;
	
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return NULL;
	}
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded!", (char *) NULL);
		return NULL;
	}
			
	/* Set start_type variable and guard against buffer overflows by checking string length */	
	start_type = argv[1];
	if(start_type == NULL || str_is_only_white_space(start_type)) {
		Tcl_AppendResult(interp, "empty starting type!", (char *) NULL);
		return NULL;
	}
	if(!is_valid_str_sz(start_type)) {
		Tcl_AppendResult(interp, "The provided start type string is too large.", (char *) NULL);
		return NULL;
	}
	
	filter_obj_classes = getbool(argv[3]);
	filter_end_types = getbool(argv[5]);
	filter_inter_types = getbool(argv[8]);
	use_min_weight = getbool(argv[10]);
	rt = Tcl_GetInt(interp, argv[4], &num_objs);
	if(rt == TCL_ERROR) {
		Tcl_AppendResult(interp,"argv[4] apparently not an integer", (char *) NULL);
		return NULL;
	}
	
	if(filter_obj_classes) {
		/* Second, disassemble list of object class permissions, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[7], &num_objs_options, &obj_class_perms);
		if(rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return NULL;
		}
		
		if(num_objs_options < 1) {
			Tcl_AppendResult(interp, "Must provide object class permissions.", (char *) NULL);
			Tcl_Free((char *) obj_class_perms);
			return NULL;
		}
	}
	
	if(filter_end_types) {
		if(!is_valid_str_sz(argv[6])) {
			Tcl_AppendResult(interp, "The provided end type filter string is too large.", (char *) NULL);
			return NULL;
		}	
		sz = strlen(argv[6]) + 1;
 	        end_type = (char *)malloc(sz);
	        if(end_type == NULL) {
		      fprintf(stderr, "out of memory");
		      return NULL;
		}	
		end_type = strcpy(end_type, argv[6]);
		if(end_type == NULL || str_is_only_white_space(end_type)) {
			free(end_type);
			Tcl_AppendResult(interp, "Please provide a regular expression for filtering the end types.", (char *) NULL);
			return NULL;
		}
	}
	if (filter_inter_types) {
		/* First, disassemble TCL intermediate types list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[9], &num_inter_types, &inter_types);
		if(rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return NULL;
		}
		
		if(num_inter_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least one intermediate type.", (char *) NULL);
			Tcl_Free((char *) inter_types);
			return NULL;
		}
	}			
	/* Initialize query structure */
	iflow_query = iflow_query_create();
	if (iflow_query == NULL) {
		Tcl_AppendResult(interp,"Memory error allocating query\n", (char *) NULL);
		return NULL;
	}
	
	if(strcmp(argv[2], "in") == 0) {
		iflow_query->direction = IFLOW_IN;
	}
	else if(strcmp(argv[2], "out") == 0) {
		iflow_query->direction = IFLOW_OUT;
	}
	else {
		Tcl_AppendResult(interp, "Unknown flow direction provided:", argv[2], " Must be either 'in' or 'out'.", (char *) NULL);
		iflow_query_destroy(iflow_query);
		return NULL;
	}
	
	if (use_min_weight) {
		rt = Tcl_GetInt(interp, argv[11], &iflow_query->min_weight);
		if (rt == TCL_ERROR) {
			Tcl_AppendResult(interp,"argv[11] apparently is not an integer", (char *) NULL);
			return NULL;
		}
	}

	/* Set the start type for our query */ 					
	iflow_query->start_type = get_type_idx(start_type, policy);
	if (iflow_query->start_type < 0) {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "Invalid starting type ", start_type, (char *) NULL);
		return NULL;
	}
		
	if(filter_obj_classes && obj_class_perms != NULL) {
		assert(num_objs > 0);
		cur = 0;
		/* Set the object classes permission info */
		/* Keep in mind that this is an encoded TCL list in the form 
		   "class1 num_perms perm1 ... permN ... classN num_perms perm1 ... permN" */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_class_perms[cur], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class:\n", obj_class_perms[cur], (char *) NULL);
				Tcl_Free((char *) obj_class_perms);
				iflow_query_destroy(iflow_query);
				return NULL;
			}
			/* Increment to next element, which should be the number of permissions to exclude for the class 
			 * num_obj_perms = 0 means to exclude the entire class */
			cur++;
			rt = Tcl_GetInt(interp, obj_class_perms[cur], &num_obj_perms);
			if(rt == TCL_ERROR) {
				Tcl_AppendResult(interp, "Item in obj_class_perms list apparently is not an integer\n", (char *) NULL);
				return NULL;
			}
			
			/* If this there are no permissions given then exclude the entire object class. */
			if (num_obj_perms == 0) {
				if (iflow_query_add_obj_class(iflow_query, obj) == -1) {
					Tcl_AppendResult(interp, "error adding obj\n", (char *) NULL);
					return NULL;
				}
			} else {
				for (j = 0; j < num_obj_perms; j++) {
					cur++;
					perm = get_perm_idx(obj_class_perms[cur], policy);
					if (perm < 0 || !is_valid_perm_for_obj_class(policy, obj, perm)) {
						fprintf(stderr, "Invalid object class permission\n");
						continue;
					}
					if (iflow_query_add_obj_class_perm(iflow_query, obj, perm) == -1) {
						Tcl_AppendResult(interp, "error adding perm\n", (char *) NULL);
						return NULL;
					}
				}
			} 
			cur++;
		}
		Tcl_Free((char *) obj_class_perms);
	}

	/* filter ending type(s) */
	if(filter_end_types) {	
		trim_trailing_whitespace(&end_type);
		rt = regcomp(&reg, end_type, REG_EXTENDED|REG_NOSUB);
		if(rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				Tcl_AppendResult(interp, "out of memory", (char *) NULL);
				iflow_query_destroy(iflow_query);
				return NULL;
			}
			regerror(rt, &reg, err, sz);
			regfree(&reg);
			Tcl_AppendResult(interp, err, (char *) NULL);
			free(err);
			free(end_type);
			iflow_query_destroy(iflow_query);
			return NULL;
		}
		free(end_type);
		rt = get_type_idxs_by_regex(&types, &num, &reg, FALSE, policy);
		if(rt < 0) {
			Tcl_AppendResult(interp, "Error searching types\n", (char *) NULL);
			iflow_query_destroy(iflow_query);
			return NULL;
		}
		for(i = 0; i < num; i++) {
			rt = get_type_name(types[i], &name, policy);
			if(rt < 0) {
				sprintf(tbuf, "Problem getting %dth matching type name for idx: %d", i, types[i]);
				Tcl_AppendResult(interp, tbuf, (char *) NULL);
				iflow_query_destroy(iflow_query);
				return NULL;
			}
			type = get_type_idx(name, policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				free(name);
				continue;
			}
			if (iflow_query_add_end_type(iflow_query, type) != 0) {
				free(name);
				iflow_query_destroy(iflow_query);
				Tcl_AppendResult(interp, "Error adding end type to query!\n", (char *) NULL);
				return NULL;
			}
			free(name);
		} 		
	}
	if (filter_inter_types && inter_types != NULL) {
		/* Set intermediate type info */
		for (i = 0; i < num_inter_types; i++) {
			type = get_type_idx(inter_types[i], policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				continue;
			}
			if (iflow_query_add_type(iflow_query, type) != 0) {
				iflow_query_destroy(iflow_query);
				Tcl_AppendResult(interp, "Memory error!\n", (char *) NULL);
				return NULL;
			}
		}
		Tcl_Free((char *) inter_types);
	}
	return iflow_query;		
}

static int append_perm_str(bool_t do_common_perms, bool_t do_classes, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy)
{
	int i;
	bool_t used;
	
	if(idx >= policy->num_perms|| buf == NULL) {
		return -1;
	}
	
	Tcl_DStringAppend(buf, policy->perms[idx], -1);
	if(do_classes || do_common_perms) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	/* find the classes that use this perm */
	if(do_classes) {
		used = FALSE;
		Tcl_DStringAppend(buf, "   object classes:\n", -1);
		for(i = 0; i < policy->num_obj_classes; i++) {
			if(does_class_use_perm(i, idx, policy)) {
				used = TRUE;
				Tcl_DStringAppend(buf, "        ", -1);
				append_class_str(0,0,0,1,i,buf,policy);
			}
			else if(does_class_indirectly_use_perm(i, idx, policy)) {
				used = TRUE;
				Tcl_DStringAppend(buf, "        ", -1);
				append_class_str(0,0,0,0,i,buf,policy);
				/* we "star" those included via common perm */
				Tcl_DStringAppend(buf, "*\n", -1);
			}
		}
		if(!used) {
			Tcl_DStringAppend(buf, "        <none>\n", -1);
		}
	}	
	/* find the common perms that use this perm */
	if(do_common_perms) {
		used = FALSE;
		Tcl_DStringAppend(buf, "   common permissions:\n", -1);
		for(i = 0; i < policy->num_common_perms; i++) {
			if(does_common_perm_use_perm(i, idx, policy)) {
				used = TRUE;
				Tcl_DStringAppend(buf, "        ", -1);
				append_common_perm_str(0,0,1,i,buf,policy);
			}
		}
		if(!used) {
			Tcl_DStringAppend(buf, "        <none>\n", -1);
		}
	}

	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);		
	return TCL_OK;	
}


static int append_class_str(bool_t do_perms, bool_t do_cps, bool_t expand_cps, bool_t newline, int idx, Tcl_DString *buf,
				policy_t *policy)
{
	int i, cp_idx;
	
	if(idx >= policy->num_obj_classes|| buf == NULL) {
		return -1;
	}
	
	Tcl_DStringAppend(buf, policy->obj_classes[idx].name, -1);
	
	if(do_cps || do_perms) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	/* class-specific perms */
	if(do_perms) {
		for(i = 0; i < policy->obj_classes[idx].num_u_perms; i++) {
			assert(i < policy->num_perms);
			Tcl_DStringAppend(buf, "     ", -1);
			append_perm_str(0, 0, 1, policy->obj_classes[idx].u_perms[i], buf, policy);
		}
	}
	
	/* common perms */
	if(do_cps) {
		if(policy->obj_classes[idx].common_perms >= 0) {
			cp_idx = policy->obj_classes[idx].common_perms;
			Tcl_DStringAppend(buf, "     ", -1);
			append_common_perm_str(0, 0, 0, cp_idx, buf, policy);
			Tcl_DStringAppend(buf, "  (common perm)\n", -1);
			if(expand_cps) {
				for(i = 0; i < policy->common_perms[cp_idx].num_perms; i++) {
					assert(i < policy->num_perms);
					Tcl_DStringAppend(buf, "          ", -1);
					append_perm_str(0, 0, 1, policy->common_perms[cp_idx].perms[i], buf, policy);
				}
			}
		}
	}
	
	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);		
	return TCL_OK;
}


static int append_type_str(bool_t do_attribs, bool_t do_aliases, bool_t newline, int idx, 
	policy_t *policy, Tcl_DString *buf)
{
	int j;
	char tbuf[APOL_STR_SZ + 64];
	if(idx >= policy->num_types || buf == NULL) {
		return -1;
	}

	Tcl_DStringAppend(buf, policy->types[idx].name, -1);
	
	if(do_aliases) {
		if(policy->types[idx].aliases != NULL) {
			name_item_t *ptr;
			Tcl_DStringAppend(buf, " alias {", -1);
			for(ptr = policy->types[idx].aliases; ptr != NULL; ptr = ptr->next) {
				Tcl_DStringAppend(buf, ptr->name, -1);
				if(ptr->next != NULL)
					Tcl_DStringAppend(buf, " ", -1);
			}
			Tcl_DStringAppend(buf, "} ", -1);
		}
	}
	
	if(do_attribs) {
		sprintf(tbuf, " (%d attributes)\n", policy->types[idx].num_attribs);
		Tcl_DStringAppend(buf, tbuf, -1);
		for(j = 0; j < policy->types[idx].num_attribs; j++) {
			sprintf(tbuf, "\t%s\n", policy->attribs[policy->types[idx].attribs[j]].name);
			Tcl_DStringAppend(buf, tbuf, -1);
		}
	}
	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);	

	return 0;
}

static int append_attrib_str(bool_t do_types, bool_t do_type_attribs, bool_t use_aliases, 
	bool_t newline, bool_t upper, int idx, policy_t *policy, Tcl_DString *buf)
{
	int j, k;
	char tbuf[APOL_STR_SZ+64];

	if(idx >= policy->num_attribs || buf == NULL) {
		return -1;
	}	

	if(upper) {
		Tcl_DStringAppend(buf, uppercase(policy->attribs[idx].name, tbuf), -1);
	}
	else
		Tcl_DStringAppend(buf, policy->attribs[idx].name, -1);
		
	if(do_types) {
		sprintf(tbuf, " (%d types)\n", policy->attribs[idx].num);
		Tcl_DStringAppend(buf, tbuf, -1);
		for(j = 0; j < policy->attribs[idx].num; j++) {
			Tcl_DStringAppend(buf, "\t", -1);
			Tcl_DStringAppend(buf, policy->types[policy->attribs[idx].a[j]].name, -1);
			/* aliases */
			if(use_aliases && policy->types[policy->attribs[idx].a[j]].aliases != NULL) {
				name_item_t *ptr;
				Tcl_DStringAppend(buf, ":", -1);
				for(ptr = policy->types[policy->attribs[idx].a[j]].aliases; ptr != NULL; ptr = ptr->next) {
					Tcl_DStringAppend(buf, " ", -1);
					Tcl_DStringAppend(buf, ptr->name, -1);
					if(ptr->next != NULL)
						Tcl_DStringAppend(buf, ",", -1);
				}
			}			
			if(do_type_attribs) {
				Tcl_DStringAppend(buf, " { ", -1);
				for(k = 0; k < policy->types[policy->attribs[idx].a[j]].num_attribs; k++) {
					if(strcmp(policy->attribs[idx].name, policy->attribs[policy->types[policy->attribs[idx].a[j]].attribs[k]].name) != 0)
						Tcl_DStringAppend(buf, policy->attribs[policy->types[policy->attribs[idx].a[j]].attribs[k]].name, -1);
						Tcl_DStringAppend(buf, " ", -1);
				}
				Tcl_DStringAppend(buf, "}", -1);
			}
			Tcl_DStringAppend(buf, "\n", -1);
		}
	}
	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);		

	return 0;
}

#ifdef LIBSEFS
/* This function expects an index file to be loaded already. If one is not loaded it will return an error. */
static int apol_append_type_files(int ta_idx, bool_t is_attrib, 
				  bool_t include_cxt, bool_t include_class, 
				  Tcl_DString *buf, policy_t *policy, 
				  Tcl_Interp *interp)
{
	/* Append files */
	sefs_search_keys_t search_keys;
	sefs_search_ret_t *curr;
	const char **type_strings = NULL;
	char *name = NULL, *t_buf = NULL;
	int i, num_types = 0, t_buf_sz = 0;
	int *types_indexes = NULL;
	
	if (fsdata == NULL) {
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "No Index File Loaded!", (char *) NULL);
		return -1;
	}
	assert(policy != NULL);				
	if (is_attrib) {
		if (get_attrib_types(ta_idx, &num_types, &types_indexes, policy) != 0) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "Error getting type indexes for attribute!", (char *) NULL);
			return -1;
		}
		if (types_indexes == NULL) {
			/* No types are assigned to this attribute. */
			Tcl_DStringAppend(buf, "\nFiles: None\n\n", -1);
			return 0;	
		}
	} else {
		if (add_i_to_a(ta_idx, &num_types, &types_indexes) != 0) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "Error adding type idx to array!", (char *) NULL);
			return -1;
		}
		assert(types_indexes != NULL && num_types > 0);
	}
	type_strings = (const char**)malloc(sizeof(char*) * num_types);
	if (type_strings == NULL) {
		fprintf(stderr, "Memory error.\n");
		goto err;
	}
	memset(type_strings, 0, sizeof(char*) * num_types);
	for (i = 0; i < num_types; i++) {
		if (get_type_name(types_indexes[i], &name, policy) != 0) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "Error getting type name!", (char *) NULL);
			goto err;
		}
		assert(name != NULL);
		if ((type_strings[i] = (char*)strdup((char*)name)) == NULL) {
			fprintf(stderr, "Memory error.\n");
			goto err;
		}
		free(name);
		name = NULL;
	}
	assert(type_strings != NULL);	
	free(types_indexes);
	types_indexes = NULL;
	search_keys.user = NULL;
	search_keys.path = NULL;
	search_keys.type = type_strings;
	search_keys.object_class = NULL;
	search_keys.num_type = num_types;
	search_keys.num_user = 0;
	search_keys.num_object_class = 0;
	search_keys.num_path = 0;
	search_keys.do_user_regEx = 0;
	search_keys.do_type_regEx = 0;
	search_keys.do_path_regEx = 0;

	if (sefs_filesystem_db_search(fsdata, &search_keys) != 0) {
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "File search failed\n", (char *) NULL);
		goto err;
	}
		
	curr = search_keys.search_ret;
	if (curr == NULL) {
		if (append_str(&t_buf, &t_buf_sz, "\nFiles: None\n") != 0)  {
			fprintf(stderr, "Error appending to string!\n");
			goto err;
		}
	} else {
		if (append_str(&t_buf, &t_buf_sz, "\nFiles:\n") != 0)  {
			fprintf(stderr, "Error appending to string!\n");
			goto err;
		}
		/* walk the linked list */
		while (curr) {
			/* Print "context class file_path" per newline */
			if (include_cxt && curr->context) {
				if (append_str(&t_buf, &t_buf_sz, "\t   ") != 0)  {
					fprintf(stderr, "Error appending to string!\n");
					goto err;
				}
				if (append_str(&t_buf, &t_buf_sz, curr->context) != 0)  {
					fprintf(stderr, "Error appending to string!\n");
					goto err;
				}
			}
			if (include_class && curr->object_class) {
				if (append_str(&t_buf, &t_buf_sz, "\t   ") != 0)  {
					fprintf(stderr, "Error appending to string!\n");
					goto err;
				}
				if (append_str(&t_buf, &t_buf_sz, curr->object_class) != 0)  {
					fprintf(stderr, "Error appending to string!\n");
					goto err;
				}
			}
			if (curr->path) {
				if (append_str(&t_buf, &t_buf_sz, "\t   ") != 0)  {
					fprintf(stderr, "Error appending to string!\n");
					goto err;
				}
				if (append_str(&t_buf, &t_buf_sz, curr->path) != 0)  {
					fprintf(stderr, "Error appending to string!\n");
					goto err;
				}
			}
			if (append_str(&t_buf, &t_buf_sz, "\n") != 0)  {
				fprintf(stderr, "Error appending to string!\n");
				goto err;
			}
			curr = curr->next;
		}
	}
	if (append_str(&t_buf, &t_buf_sz, "\n") != 0)  {
		fprintf(stderr, "Error appending to string!\n");
		goto err;
	}
	sefs_search_keys_ret_destroy(search_keys.search_ret);
	Tcl_DStringAppend(buf, t_buf, -1);
	
	if (type_strings != NULL) {
		for (i = 0; i < num_types; i++) {
			free((char*)type_strings[i]);
		}
		free(type_strings);
	}
	if (t_buf != NULL) free(t_buf);
	
	return 0;
err:
	if (type_strings != NULL) {
		for (i = 0; i < num_types; i++) {
			if (type_strings[i]) free((char*)type_strings[i]);
		}
		free(type_strings);
	}
	if (types_indexes != NULL) free(types_indexes);
	if (name != NULL) free(name);
	if (t_buf != NULL) free(t_buf);
	return -1;
}
#endif

/* searches using regular expressions */
static int append_all_ta_using_regex(regex_t *preg, const char *regexp, bool_t do_types, bool_t do_attribs, bool_t use_aliases,
			bool_t type_attribs, bool_t attrib_types, bool_t attrib_type_attribs, policy_t *policy,
			Tcl_DString *buf, bool_t show_files, bool_t include_cxt, bool_t include_class, 
			Tcl_Interp *interp)
{
	int i, rt;
	char tbuf[APOL_STR_SZ+64];

	if(!(do_types || do_attribs)) {
		return 0; /* nothing to do */
	}
	if(buf == NULL) {
		return -1;
	}
	
	if(do_types) {
		Tcl_DStringAppend(buf, "Type ", -1);
		if(do_attribs) {
			Tcl_DStringAppend(buf, "and Type Attribute ", -1);
		}
	}
	else {
		Tcl_DStringAppend(buf, "Type Attribute ", -1);
	}
	sprintf(tbuf, "Search using regular expressions: \'%s\'\n", regexp);
	Tcl_DStringAppend(buf, tbuf, -1);
	
	if(do_types) {
		Tcl_DStringAppend(buf, "\n\nTYPES:\n", -1);
		for (i = 0; i < policy->num_types; i++) {
			rt = regexec(preg, policy->types[i].name, 0, NULL, 0);
			if(rt == 0) {
				rt = append_type_str(type_attribs, use_aliases,1, i, policy, buf);
				if(rt != 0) {
					return -1;
				}
				if (show_files) {
#ifdef LIBSEFS
					if (apol_append_type_files(i, FALSE, include_cxt, include_class, buf, policy, interp) != 0) {
						Tcl_DStringFree(buf);
						return TCL_ERROR;
					}
#else
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "Error: You need to build apol with libsefs! Please deselect the 'Show Files' checkbutton and run the search again.", (char *) NULL);
					return TCL_ERROR;
#endif
				}	
			} else if(use_aliases) {
				name_item_t *ptr;
				for(ptr = policy->types[i].aliases; ptr != NULL; ptr = ptr->next) {
					rt = regexec(preg, ptr->name, 0, NULL, 0);
					if(rt == 0) {
						rt = append_type_str(type_attribs, use_aliases, 0, i, policy, buf);
						if(rt != 0) {
							return -1;
						}
					}
				}
			}
		}
	}
	
	if(do_attribs) {
		Tcl_DStringAppend(buf, "\n\nTYPE ATTRIBUTES:\n", -1);
		for(i = 0; i < policy->num_attribs; i++) {
			if(regexec(preg, policy->attribs[i].name, 0,NULL,0) == 0) {
				rt = append_attrib_str(attrib_types, attrib_type_attribs, use_aliases, 1, 0, i, policy, buf);
				if(rt != 0) {
					return -1;
				}
				if (show_files) {
#ifdef LIBSEFS
					if (apol_append_type_files(i, TRUE, include_cxt, include_class, buf, policy, interp) != 0) {
						Tcl_DStringFree(buf);
						return TCL_ERROR;
					}
#else
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "Error: You need to build apol with libsefs! Please deselect the 'Show Files' checkbutton and run the search again.", (char *) NULL);
					return TCL_ERROR;
#endif
				} 	
			}						
		}
	}

	return 0;
}

static int append_tt_rule(bool_t addnl, bool_t addlineno, int idx, policy_t *policy, Tcl_DString *buf) 
{
	char *rule;
	
	if(buf == NULL) {
		return -1;
	}
	
	rule = re_render_tt_rule(addlineno, idx, policy);
	if(rule == NULL)
		return -1;
	Tcl_DStringAppend(buf, rule, -1);
	free(rule);
	
	if(addnl) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	return 0;	

}

static int append_av_rule(bool_t addnl, bool_t addlineno, int idx, bool_t is_au, policy_t *policy, Tcl_DString *buf)
{ 
	char *rule;
	
	if(buf == NULL) {
		return -1;
	}
	
	rule = re_render_av_rule(addlineno, idx, is_au, policy);
	if(rule == NULL)
		return -1;
	Tcl_DStringAppend(buf, rule, -1);
	free(rule);

	if(addnl) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	return 0;
}

static int append_user_str(int idx, bool_t name_only,  policy_t *policy, Tcl_DString *buf)
{
	char *name;
	int rt;
	int i;
		
	assert(is_valid_user_idx(idx, policy));
	Tcl_DStringAppend(buf, policy->users[idx].name, -1);
	if(!name_only) {
		Tcl_DStringAppend(buf, " { ", -1);
		for(i = 0; i < policy->users[idx].num; i++) {
			rt = get_role_name(policy->users[idx].a[i], &name, policy);
			if(rt != 0) {
				return -1;
			}
			Tcl_DStringAppend(buf, name, -1);
			free(name);
			Tcl_DStringAppend(buf, " ", -1);
		}
		Tcl_DStringAppend(buf, "};", -1);
	}
	Tcl_DStringAppend(buf, "\n", -1);
	return 0;
}

static int append_direct_edge_to_results(policy_t *policy, iflow_query_t* q,
					 iflow_t *answer, Tcl_Interp *interp)
{
	int j, k, num_obj_classes = 0;
	char *rule, tbuf[BUF_SZ];
	
	/* Append number of object classes */
	for (j = 0; j < answer->num_obj_classes; j++)
		if (answer->obj_classes[j].num_rules)
			num_obj_classes++;
	sprintf(tbuf, "%d", num_obj_classes);
	Tcl_AppendElement(interp, tbuf);	
	
	for (j = 0; j < answer->num_obj_classes; j++) {
		/* if this is 0 then the obj_class is not defined for a given edge */
		if (answer->obj_classes[j].num_rules) {
			/* Indicate this is an object class we care about */
			Tcl_AppendElement(interp, "1");		
			/* Append the object class name to the TCL list */
			sprintf(tbuf, "%s", policy->obj_classes[j].name);
			Tcl_AppendElement(interp, tbuf);
						
			/* Append the number of rules */
			sprintf(tbuf, "%d", answer->obj_classes[j].num_rules);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the allow rule(s) to the TCL list */
			for (k = 0; k < answer->obj_classes[j].num_rules; k++) {
				rule = re_render_av_rule(TRUE, answer->obj_classes[j].rules[k], FALSE, policy);
				if(rule == NULL) {
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "analysis error (rendering allow rule)",  (char *) NULL);
					return -1;
				}
				Tcl_AppendElement(interp, rule);
				free(rule);
				/* Append a boolean value indicating whether this rule is enabled 
				 * for conditional policy support */
				sprintf(tbuf, "%d", policy->av_access[answer->obj_classes[j].rules[k]].enabled);
				Tcl_AppendElement(interp, tbuf);
			}			
		}
	}
	return 0;
}

static int append_transitive_iflow_rules_to_results(policy_t *policy, iflow_transitive_t* answers, iflow_path_t *cur, int path_idx, int obj_idx, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ], *rule;
	int l;
	
	/* Append the number of rules */
	sprintf(tbuf, "%d", cur->iflows[path_idx].obj_classes[obj_idx].num_rules);
	Tcl_AppendElement(interp, tbuf);
	
	/* Append the allow rule(s) to the TCL list */
	for (l = 0; l < cur->iflows[path_idx].obj_classes[obj_idx].num_rules; l++) {
		rule = re_render_av_rule(TRUE, cur->iflows[path_idx].obj_classes[obj_idx].rules[l], FALSE, policy);
		if(rule == NULL) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "analysis error (rendering allow rule)",  (char *) NULL);
			return -1;
		}
		Tcl_AppendElement(interp, rule);
		free(rule);
		/* Append a boolean value indicating whether this rule is enabled 
		 * for conditional policy support */
		sprintf(tbuf, "%d", policy->av_access[cur->iflows[path_idx].obj_classes[obj_idx].rules[l]].enabled);
		Tcl_AppendElement(interp, tbuf);
	}
	return 0;
}
static int append_transitive_iflow_objects_to_results(policy_t *policy, iflow_transitive_t *answers, iflow_path_t *cur, Tcl_Interp *interp, int j)
{
	char tbuf[BUF_SZ];
	int num_obj_classes, k, rt;
	
	/* Append the number of object classes */
	num_obj_classes = 0;
	for (k = 0; k < cur->iflows[j].num_obj_classes; k++)
		if (cur->iflows[j].obj_classes[k].num_rules)
			num_obj_classes++;
	sprintf(tbuf, "%d", num_obj_classes);
	Tcl_AppendElement(interp, tbuf);
	
	for (k = 0; k < cur->iflows[j].num_obj_classes; k++) {
		/* if 0, the obj_class is not defined for a given edge */
		if (cur->iflows[j].obj_classes[k].num_rules) {	
			/* Append the object class name */
			sprintf(tbuf, "%s", policy->obj_classes[k].name);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rules for each object */
			rt = append_transitive_iflow_rules_to_results(policy, answers, cur, j, k, interp);
			if (rt != 0) {
				return -1;	
			}
		}
	}
	return 0;
}

static int append_dta_results(policy_t *policy, domain_trans_analysis_t *dta_results, Tcl_Interp *interp)
{
	llist_node_t *x, *y;
	char *tmp, tbuf[BUF_SZ];
	int i, rt;
	trans_domain_t *t;
	entrypoint_type_t *ep;
	
	assert(dta_results != NULL);
	/* # of target types */
	sprintf(tbuf, "%d", dta_results->trans_domains->num);
	Tcl_AppendElement(interp, tbuf);
	
	/* all target types */
	for (x = dta_results->trans_domains->head; x != NULL; x = x->next) {
		t = (trans_domain_t *)x->data;
		/* target type */
		assert(dta_results->start_type == t->start_type);
		rt = get_type_name(t->trans_type, &tmp, policy);
		if (rt != 0) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "analysis error (looking up target name)", (char *) NULL);
			return TCL_ERROR;
		}
		Tcl_AppendElement(interp, tmp);
		free(tmp);
		/* # of pt rules */
		sprintf(tbuf, "%d", t->num_pt_rules);
		Tcl_AppendElement(interp, tbuf);
		/* all the pt rules */
		for (i = 0; i < t->num_pt_rules; i++) {
			tmp = re_render_av_rule(0,t->pt_rules[i], 0, policy);
			if (tmp == NULL) {
				Tcl_ResetResult(interp);
				Tcl_AppendResult(interp, "analysis error (rendering process transition rule)",  (char *) NULL);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, tmp);
			free(tmp);
			sprintf(tbuf, "%d", get_rule_lineno(t->pt_rules[i],RULE_TE_ALLOW, policy));
			Tcl_AppendElement(interp, tbuf);
			/* Append a boolean value indicating whether this rule is enabled 
			 * for conditional policy support */
			sprintf(tbuf, "%d", policy->av_access[t->pt_rules[i]].enabled);
			Tcl_AppendElement(interp, tbuf);
		}
		/* # of entrypoint file types */
		sprintf(tbuf, "%d", t->entry_types->num);
		Tcl_AppendElement(interp, tbuf);
		/* all the entrypoint file types */
		for (y = t->entry_types->head; y != NULL; y = y->next) {
			ep = (entrypoint_type_t *)y->data;
			assert(t->trans_type == ep->trans_type);
			/* file type */
			rt = get_type_name(ep->file_type, &tmp, policy);
			if (rt != 0) {
				Tcl_ResetResult(interp);
				Tcl_AppendResult(interp, "analysis error (looking up entry file name)", (char *) NULL);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, tmp);
			free(tmp);			
			/* # of file entrypoint rules */
			sprintf(tbuf, "%d", ep->num_ep_rules);
			Tcl_AppendElement(interp, tbuf);
			/* all entrypoint rules */
			for (i = 0; i < ep->num_ep_rules; i++) {
				tmp = re_render_av_rule(0, ep->ep_rules[i], 0, policy);
				if (tmp == NULL) {
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "analysis error (rendering file entrypoint rule)",  (char *) NULL);
					return TCL_ERROR;
				}
				Tcl_AppendElement(interp, tmp);
				free(tmp);
				sprintf(tbuf, "%d", get_rule_lineno(ep->ep_rules[i],RULE_TE_ALLOW, policy));
				Tcl_AppendElement(interp, tbuf);
				/* Append a boolean value indicating whether this rule is enabled 
				 * for conditional policy support */
				sprintf(tbuf, "%d", policy->av_access[ep->ep_rules[i]].enabled);
				Tcl_AppendElement(interp, tbuf);				
			}
			/* # of file execute rules */
			sprintf(tbuf, "%d", ep->num_ex_rules);
			Tcl_AppendElement(interp, tbuf);
			/* all execute rules */
			for (i = 0; i < ep->num_ex_rules; i++) {
				tmp = re_render_av_rule(0,ep->ex_rules[i], 0, policy);
				if (tmp == NULL) {
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "analysis error (rendering file execute rule)",  (char *) NULL);
					return TCL_ERROR;
				}
				Tcl_AppendElement(interp, tmp);
				free(tmp);
				sprintf(tbuf, "%d", get_rule_lineno(ep->ex_rules[i],RULE_TE_ALLOW, policy));
				Tcl_AppendElement(interp, tbuf);
				/* Append a boolean value indicating whether this rule is enabled 
				 * for conditional policy support */
				sprintf(tbuf, "%d", policy->av_access[ep->ex_rules[i]].enabled);
				Tcl_AppendElement(interp, tbuf);
			}
		}
		/* # of additional rules */
		sprintf(tbuf, "%d", t->num_other_rules);
		Tcl_AppendElement(interp, tbuf);
		/* all additional rules */
		for (i = 0; i < t->num_other_rules; i++) {
			tmp = re_render_av_rule(0, t->other_rules[i], 0, policy);
			if (tmp == NULL) {
				Tcl_ResetResult(interp);
				Tcl_AppendResult(interp, "analysis error rendering additional rules",  (char *) NULL);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, tmp);
			free(tmp);
			sprintf(tbuf, "%d", get_rule_lineno(t->other_rules[i], RULE_TE_ALLOW, policy));
			Tcl_AppendElement(interp, tbuf);
			/* Append a boolean value indicating whether this rule is enabled 
			 * for conditional policy support */
			sprintf(tbuf, "%d", policy->av_access[t->other_rules[i]].enabled);
			Tcl_AppendElement(interp, tbuf);
		}
	}
	
	return 0;
}

static int append_transitive_iflows_to_results(policy_t *policy, iflow_transitive_t* answers, iflow_path_t *cur, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ];
	int j, rt;

	/* Append the number of flows in path */
	sprintf(tbuf, "%d", cur->num_iflows);
	Tcl_AppendElement(interp, tbuf);
	for (j = 0; j < cur->num_iflows; j++) {
		/* Append the start type */
		sprintf(tbuf, "%s", policy->types[cur->iflows[j].start_type].name);
		Tcl_AppendElement(interp, tbuf);
		/* Append the end type */
		sprintf(tbuf, "%s", policy->types[cur->iflows[j].end_type].name);
		Tcl_AppendElement(interp, tbuf);
		/* Append the objects */
		rt = append_transitive_iflow_objects_to_results(policy, answers, cur, interp, j);		
		if(rt != 0)
			return -1;
	}
	return 0;
}

static int append_transitive_iflow_paths_to_results(policy_t *policy, iflow_transitive_t* answers, Tcl_Interp *interp, int end_type)
{
	char tbuf[BUF_SZ];
	int rt;
	iflow_path_t *cur;

	/* Append the number of paths for this type */
	sprintf(tbuf, "%d", answers->num_paths[end_type]);
	Tcl_AppendElement(interp, tbuf);
	for (cur = answers->paths[end_type]; cur != NULL; cur = cur->next) {
		/* Append the iflows for each path */
		rt = append_transitive_iflows_to_results(policy, answers, cur, interp);
		if (rt != 0) {
			return -1;	
		}
	}
	return 0;
}

static int append_transitive_iflow_results(policy_t *policy, iflow_transitive_t *answers, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ];
	int i, rt;
	
	/* Append the number of types */
	sprintf(tbuf, "%d", answers->num_end_types);
	Tcl_AppendElement(interp, tbuf);
		
	for (i = 0; i < answers->num_end_types; i++) {
		/* Append the type */
		sprintf(tbuf, "%s", policy->types[answers->end_types[i]].name);
		Tcl_AppendElement(interp, tbuf);
		/* Append the paths for the type */
		rt = append_transitive_iflow_paths_to_results(policy, answers, interp, i);
		if (rt != 0)
			return -1;
	}
	return 0;
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

/* 
 * NOTE: The following functions are not really TCL specific, but rather can be classed as rendering functions.
 * However, we won't worry about moving this to render.c.  
 */
 
/* append_clone_rule() - Its use is deprecated. */ 
static int append_clone_rule(bool_t addnl, bool_t addlineno, cln_item_t *item, policy_t *policy, Tcl_DString *buf) 
{
	char tbuf[APOL_STR_SZ+64];
	
	if(buf == NULL) {
		return -1;
	}
	
	Tcl_DStringAppend(buf, rulenames[RULE_CLONE], -1);
	Tcl_DStringAppend(buf, " ", -1);
	if(append_type_str(0,0, 0, item->src, policy, buf) != 0)
		return -1;	
	Tcl_DStringAppend(buf, " ", -1);		
	if(append_type_str(0,0, 0, item->tgt, policy, buf) != 0)
		return -1;
	Tcl_DStringAppend(buf, ";", -1);

	if(addlineno) {
		sprintf(tbuf, "       (%lu)", item->lineno);
		Tcl_DStringAppend(buf, tbuf, -1);
	}
	if(addnl) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	return 0;
}

static int append_role(int idx, bool_t name_only, int numperline, policy_t *policy, Tcl_DString *buf)
{
	int j;
	div_t x;	
	char tmpbuf[APOL_STR_SZ+64];
	if(numperline < 1)
		numperline = 1;
	
	Tcl_DStringAppend(buf, policy->roles[idx].name, -1);
	if(!name_only) {
		sprintf(tmpbuf, " (%d types)\n     ", policy->roles[idx].num);
		Tcl_DStringAppend(buf, tmpbuf, -1);
		for(j = 0; j < policy->roles[idx].num; j++) {
			/* control # of types per line */
			if(j != 0) {
				x = div(j, numperline);
				if(x.rem == 0) {
					sprintf(tmpbuf, "\n     ");
					Tcl_DStringAppend(buf, tmpbuf, -1);
				}
			}
			sprintf(tmpbuf, "%s  ", policy->types[policy->roles[idx].a[j]].name);
			Tcl_DStringAppend(buf, tmpbuf, -1);
		}
		Tcl_DStringAppend(buf, "\n", -1); /* extra line if we're exploding role types */	
	}
	Tcl_DStringAppend(buf, "\n", -1);
	return 0;	
}

static int append_role_allow_rule(role_allow_t *rule, policy_t *policy, Tcl_DString *buf)
{
	ta_item_t *tptr;	
	int multiple = 0;
	if(buf == NULL) {
		return -1;
	}
		
	Tcl_DStringAppend(buf, rulenames[RULE_ROLE_ALLOW], -1);

	/* source roles */
	if(rule->flags & AVFLAG_SRC_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->src_roles != NULL && rule->src_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		Tcl_DStringAppend(buf, "*", -1);
			
	for(tptr = rule->src_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	/* target roles */
	if(rule->flags & AVFLAG_TGT_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->tgt_roles != NULL && rule->tgt_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		Tcl_DStringAppend(buf, "*", -1);

	
	for(tptr = rule->tgt_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	
	Tcl_DStringAppend(buf, ";\n", -1);
		
	return 0;
}


static int append_role_trans_rule(rt_item_t *rule, policy_t *policy, Tcl_DString *buf)
{
	ta_item_t *tptr;	
	int multiple = 0;
	if(buf == NULL) {
		return -1;
	}
		
	Tcl_DStringAppend(buf, rulenames[RULE_ROLE_TRANS], -1);
	
	/* source roles */
	if(rule->flags & AVFLAG_SRC_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->src_roles != NULL && rule->src_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		Tcl_DStringAppend(buf, "*", -1);
			
	for(tptr = rule->src_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	/* target types/attributes */
	if(rule->flags & AVFLAG_TGT_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->tgt_types != NULL && rule->tgt_types->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		Tcl_DStringAppend(buf, "*", -1);

	for(tptr = rule->tgt_types; tptr != NULL; tptr = tptr->next) {
		if ((tptr->type & IDX_SUBTRACT)) {
			Tcl_DStringAppend(buf, "-", -1);
		}
		if ((tptr->type & IDX_TYPE)) {
			Tcl_DStringAppend(buf, " ", -1);
			if(append_type_str(0, 0, 0, tptr->idx, policy, buf) != 0)
				return -1;
		}
		else if ((tptr->type & IDX_ATTRIB)) {
			Tcl_DStringAppend(buf, " ", -1);
			if(append_attrib_str(0, 0, 0, 0, 0, tptr->idx, policy, buf) != 0)
				return -1;
		}			
		else {
			fprintf(stderr, "Invalid index type: %d\n", tptr->type);
			return -1;
		}
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	
	/* default role */
	Tcl_DStringAppend(buf, " ", -1);
	assert(rule->trans_role.type == IDX_ROLE);
	Tcl_DStringAppend(buf, policy->roles[rule->trans_role.idx].name, -1);
	
	Tcl_DStringAppend(buf, ";\n", -1);
		
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
	return TCL_OK;	
}

int Apol_ClosePolicy(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	close_policy(policy);
	policy = NULL;
	return TCL_OK;
}

int Apol_GetVersion(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	Tcl_AppendResult(interp, (char*)libapol_get_version(), (char *) NULL);
	return TCL_OK;
}

int Apol_GetPolicyType(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(is_binary_policy(policy) )
		Tcl_AppendResult(interp, "binary", (char *) NULL);
	else
		Tcl_AppendResult(interp, "source", (char *) NULL);
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
	if(policy == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	Tcl_AppendResult(interp, (char *)get_policy_version_name(policy->version), (char *) NULL);

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
	case POL_VER_19MLS:
		Tcl_AppendResult(interp, "19", (char *) NULL);
		break;
	case POL_VER_18_20:
	case POL_VER_20:
	case POL_VER_20MLS:
		Tcl_AppendResult(interp, "20", (char *) NULL);
		break;
	default:
		Tcl_AppendResult(interp, "0", (char *) NULL);
		break;
	}
	return TCL_OK;
}

/* return statics about the policy */
int Apol_GetStats(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char buf[128];
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	/* elements */	
	sprintf(buf, "types %d", policy->num_types);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "attribs %d", policy->num_attribs);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "roles %d", policy->num_roles);
	Tcl_AppendElement(interp, buf);
/* FIX: Rather than this type of code, we need to add TCL flags that indicate
 *      what was collected so that tcl/tk GUIs will know what to expect
 */
	sprintf(buf, "classes %d", policy->num_obj_classes);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "common_perms %d", policy->num_common_perms);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "perms %d", policy->num_perms);
	Tcl_AppendElement(interp, buf);
		
	/* rules */
	sprintf(buf, "teallow %d", policy->rule_cnt[RULE_TE_ALLOW]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "neverallow %d", policy->rule_cnt[RULE_NEVERALLOW]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "auditallow %d", policy->rule_cnt[RULE_AUDITALLOW]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "auditdeny %d", policy->rule_cnt[RULE_AUDITDENY]);
	Tcl_AppendElement(interp, buf);	
	sprintf(buf, "dontaudit %d", policy->rule_cnt[RULE_DONTAUDIT]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "tetrans %d", policy->rule_cnt[RULE_TE_TRANS]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "temember %d", policy->rule_cnt[RULE_TE_MEMBER]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "techange %d", policy->rule_cnt[RULE_TE_CHANGE]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "clone %d", policy->rule_cnt[RULE_CLONE]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "roleallow %d", policy->rule_cnt[RULE_ROLE_ALLOW]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "roletrans %d", policy->rule_cnt[RULE_ROLE_TRANS]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "users %d", policy->rule_cnt[RULE_USER]);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "sids %d", policy->num_initial_sids);
	Tcl_AppendElement(interp, buf);
	sprintf(buf, "cond_bools %d", policy->num_cond_bools);
	Tcl_AppendElement(interp, buf);
			
	return TCL_OK;
}

/* 
 * Get information about object classes, permissions, and common perms
 * args are:
 *
 * 1	do_classes	(bool)
 * 2	classes_perms 	(bool, ignored if !do_classes)
 * 3	classes_cps	(bool, ignored if !do_classes || !classes_cps)
 * 4	do_comm_perms	(bool)
 * 5	cp_perms	(bool, ignored if !do_comm_perms)
 * 6	cp_classes	(bool, ignored if !do_comm_perms)
 * 7	do_perms	(bool)
 * 8	perm_classes	(bool, ignored if !do_perms)
 * 9	perm_cps	(bool, ignored if !do_perms)
 * 10	use_srchstr	(bool, regex)
 * 11	srch_str	(string, ignored if !use_srch_str)
 *
 */
int Apol_GetClassPermInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int i, sz, rt;
	char *err;
	Tcl_DString buffer, *buf = &buffer;
	bool_t do_classes, classes_perms, classes_cps, do_common_perms, cp_perms, cp_classes, do_perms,
		perm_classes, perm_cps, use_srchstr;
	regex_t reg;
	
	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	do_classes = getbool(argv[1]);
	if(do_classes) {
		classes_perms = getbool(argv[2]);
		if(classes_perms)
			classes_cps = getbool(argv[3]);
		else
			classes_cps = FALSE;
	}
	else {
		classes_perms = FALSE;
		classes_cps = FALSE;
	}
	do_common_perms = getbool(argv[4]);
	if(do_common_perms) {
		cp_perms = getbool(argv[5]);
		cp_classes = getbool(argv[6]);
	}
	else {
		cp_perms = FALSE;
		cp_classes = FALSE;
	}
	do_perms = getbool(argv[7]);
	if(do_perms) {
		perm_classes = getbool(argv[8]);
		perm_cps = getbool(argv[9]);
	}
	else {
		perm_classes = FALSE;
		perm_cps = FALSE;
	}
	if(!do_classes && !do_common_perms && !do_perms) {
		return TCL_OK; /* nothing to do! */
	}
	use_srchstr = getbool(argv[10]);
	if(use_srchstr) {
		if(!is_valid_str_sz(argv[11])) {
			Tcl_AppendResult(interp, "Regular expression string is too large", (char *) NULL);
			return TCL_ERROR;
		}
		rt = regcomp(&reg, argv[11], REG_EXTENDED|REG_NOSUB);
		if(rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				Tcl_AppendResult(interp, "out of memory", (char *) NULL);
				return TCL_ERROR;
			}
			regerror(rt, &reg, err, sz);
			Tcl_AppendResult(interp, "Invalid regular expression:\n\n     ", (char*) NULL);
			Tcl_AppendResult(interp, argv[11], (char*) NULL);
			Tcl_AppendResult(interp, "\n\n", (char*) NULL);
			Tcl_AppendResult(interp, err, (char *) NULL);
			Tcl_DStringFree(buf);
			regfree(&reg);
			free(err);
			return TCL_ERROR;
			
		}
	}

	
	Tcl_DStringInit(buf);

	/* FIX: Here and elsewhere, need to use sorted traversal using AVL trees */	
	if(do_classes) {
		Tcl_DStringAppend(buf, "OBJECT CLASSES \n\n", -1);
		for(i = 0; i < policy->num_obj_classes; i++) {
			if(use_srchstr && (regexec(&reg, policy->obj_classes[i].name, 0,NULL,0) != 0)) {
				continue;
			}
			append_class_str(classes_perms, classes_perms, classes_cps, 1, i, buf, policy);
		}
		Tcl_DStringAppend(buf, "\n", -1);
	}
	if(do_common_perms) {
		Tcl_DStringAppend(buf, "COMMON PERMISSIONS\n\n", -1);
		for(i = 0; i < policy->num_common_perms; i++) {
			if(use_srchstr && (regexec(&reg, policy->common_perms[i].name, 0,NULL,0) != 0)) {
				continue;
			}
			append_common_perm_str(cp_perms, cp_classes, 1, i, buf, policy);
		}
		Tcl_DStringAppend(buf, "\n", -1);
	}
	if(do_perms) {
		Tcl_DStringAppend(buf, "PERMISSIONS", -1);
		if(perm_classes) {
			Tcl_DStringAppend(buf,  "  (* means class uses permission via a common permission)\n\n", -1);
		}
		else {
			Tcl_DStringAppend(buf, "\n\n", -1);
		}
		for(i = 0; i < policy->num_perms; i++) {
			if(use_srchstr && (regexec(&reg, policy->perms[i], 0,NULL,0) != 0)) {
				continue;
			}
			append_perm_str(perm_cps, perm_classes, 1, i, buf, policy);
		}
		Tcl_DStringAppend(buf, "\n", -1);
	}
	
	Tcl_DStringResult(interp, buf);
	return TCL_OK;
}


/* Given just the name of an object class, return a list of three
   items.  The first element is a list of permissions, sans any common
   permission.  The second is the class's common permission; if none
   then this element is an empty list.  The final element is the
   common permission expanded into a list; if no common permission
   then this list is empty.  If the object class does not exist at all
   then return an empty string.  All items are a 2-ple of the form
   {name index_num}. */
int Apol_GetClassPermList (ClientData clientData, Tcl_Interp *interp,
                           int objc, Tcl_Obj * CONST objv []) {
    char *objclass_name;
    Tcl_Obj *result_list_obj = NULL;
    int i;
    if (policy == NULL) {
        Tcl_SetResult (interp, "No current policy file is opened!",TCL_STATIC);
        return TCL_ERROR;
    }
    if (objc != 2) {
        Tcl_SetResult (interp, "wrong # of args", TCL_STATIC);
        return TCL_ERROR;
    }
    objclass_name = Tcl_GetString (objv [1]);
    for (i = 0; i < policy->num_obj_classes; i++) {
        if (strcmp (objclass_name, policy->obj_classes [i].name) == 0) {
            int j, k;
            Tcl_Obj *perm_list [3];
            Tcl_Obj *perm [2], *perm_elem;
            perm_list [0] = Tcl_NewListObj (0, NULL);
            perm_list [2] = Tcl_NewListObj (0, NULL);
            for (j = 0; j < policy->obj_classes [i].num_u_perms; j++) {
                int perm_index = policy->obj_classes [i].u_perms [j];
                perm [0] = Tcl_NewStringObj (policy->perms [perm_index], -1);
                perm [1] = Tcl_NewIntObj (perm_index);
                perm_elem = Tcl_NewListObj (2, perm);
                if (Tcl_ListObjAppendElement (interp, perm_list [0], perm_elem)
                    != TCL_OK) {
                    return TCL_ERROR;
                }
            }
            if (policy->obj_classes [i].common_perms >= 0) {
                int common_index = policy->obj_classes [i].common_perms;
                common_perm_t *common_perm=policy->common_perms + common_index;
                perm [0] = Tcl_NewStringObj (common_perm->name, -1);
                perm [1] = Tcl_NewIntObj (common_index);
                perm_list [1] = Tcl_NewListObj (2, perm);
                for (k = 0; k < common_perm->num_perms; k++) {
                    int class_perm_index = common_perm->perms [k];
                    perm [0] = Tcl_NewStringObj (policy->perms [class_perm_index], -1);
                    perm [1] = Tcl_NewIntObj (class_perm_index);
                    perm_elem = Tcl_NewListObj (2, perm);
                    if (Tcl_ListObjAppendElement (interp, perm_list [2],
                                                  perm_elem) != TCL_OK) {
                        return TCL_ERROR;
                    }
                }
            }
            else {
                perm_list [1] = Tcl_NewListObj (0, NULL);
            }
            result_list_obj = Tcl_NewListObj (3, perm_list);
        }
    }
    if (result_list_obj == NULL) {
        /* object class was not found */
        result_list_obj = Tcl_NewListObj (0, NULL);
    }
    Tcl_SetObjResult (interp, result_list_obj);
    return TCL_OK;
}

/* Return the common perm for a given class (or an empty string if there is none).
 * argv[1]	class
 */
int Apol_GetClassCommonPerm(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int idx, cperm_idx;
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}	
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	

	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Class name is too large", (char *) NULL);
		return TCL_ERROR;
	}
	idx = get_obj_class_idx(argv[1], policy);
	if(idx < 0) {
		char tbuf[APOL_STR_SZ+64];
		sprintf(tbuf, "%s is an invalid class name", argv[1]);
		Tcl_AppendResult(interp, tbuf, (char *) NULL);
		return TCL_ERROR;
	}
	cperm_idx = policy->obj_classes[idx].common_perms;
	if(cperm_idx < 0) {
		/* there is no common perm for the class */
		return TCL_OK;
	}
	else {
		Tcl_AppendResult(interp, policy->common_perms[cperm_idx].name, (char *) NULL);
		return TCL_OK;
	} 
}


/* get information for a single class/perm/common perm 
 * argv[1]	name
 * argv[2]	which ("class", "perm", or "common_perm")
 */
int Apol_GetSingleClassPermInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt, idx;
	char tbuf[APOL_STR_SZ+64];
	Tcl_DString buffer, *buf = &buffer;
	
	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	

	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Class/Perm name is too large", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "Which option string is too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	Tcl_DStringInit(buf);
	if(strcmp(argv[2], "class") == 0) {
		idx = get_obj_class_idx(argv[1], policy);
		if(idx < 0) {
			Tcl_DStringFree(buf);
			sprintf(tbuf, "%s is an invalid class name", argv[1]);
			Tcl_AppendResult(interp, tbuf, (char *) NULL);
			return TCL_ERROR;
		}
		rt = append_class_str(1, 1, 0, 0, idx, buf, policy);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_AppendResult(interp, "error appending class info", (char *) NULL);
			return TCL_ERROR;
		}
	}
	else if(strcmp(argv[2], "common_perm") == 0) {
		idx = get_common_perm_idx(argv[1], policy);
		if(idx < 0) {
			Tcl_DStringFree(buf);
			sprintf(tbuf, "%s is an invalid common permission name", argv[1]);
			Tcl_AppendResult(interp, tbuf, (char *) NULL);
			return TCL_ERROR;
		}
		rt = append_common_perm_str(1, 0, 0, idx, buf, policy);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_AppendResult(interp, "error appending common perm info", (char *) NULL);
			return TCL_ERROR;
		}
	}
	else if(strcmp(argv[2], "perm") == 0) {
		idx = get_perm_idx(argv[1], policy);
		if(idx < 0) {
			Tcl_DStringFree(buf);
			sprintf(tbuf, "%s is an invalid permission name", argv[1]);
			Tcl_AppendResult(interp, tbuf, (char *) NULL);
			return TCL_ERROR;
		}
		rt = append_perm_str(1,1, 0, idx, buf, policy);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_AppendResult(interp, "error appending permmission info", (char *) NULL);
			return TCL_ERROR;
		}
	}
	else {
		Tcl_DStringFree(buf);
		sprintf(tbuf, "%s is an invalid which options", argv[2]);
		Tcl_AppendResult(interp, tbuf, (char *) NULL);
		return TCL_ERROR;
	}
	
	Tcl_DStringResult(interp, buf);
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
	CONST84 char **classes;
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


/* get a list of policy resource names names. Caller may optionally provide a regular
 * expression to limit the list of returned names.
 *
 * TODO: NOTE: Currently regex option will only work for "types".
 */
/* 
 * argv[1] indicates which name list to return, possible values are:
 * 	types
 * 	attrib
 *	roles
 * 	users
 * 	classes
 *	perms
 *	common_perms
 * 	initial_sids
 * argv[2] (OPTIONAL) regular expression
 */
int Apol_GetNames(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
	int i, rt, sz, num, *idx_array;
	char *name, *err, tmpbuf[APOL_STR_SZ+64];
	bool_t use_regex = FALSE;
	regex_t reg;
	
	if(argc > 3 || argc < 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	Tcl_ResetResult(interp);
	/* handle optional regular expression */
	if(argc == 3) {
		if(strcmp("types", argv[1]) != 0) {
			Tcl_AppendResult(interp, "Regular expressions are currently only supported for types", (char *) NULL);
			return TCL_ERROR;
		} 
		use_regex = TRUE;
		if(!is_valid_str_sz(argv[2])) {
			Tcl_AppendResult(interp, "Regular expression string too large", (char *) NULL);
			return TCL_ERROR;
		}
		rt = regcomp(&reg, argv[2], REG_EXTENDED|REG_NOSUB);
		if(rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				Tcl_AppendResult(interp, "out of memory", (char *) NULL);
				return TCL_ERROR;
			}
			regerror(rt, &reg, err, sz);
			sprintf(tmpbuf, "Invalid regular expression:\n\n     %s\n\n", argv[2]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			Tcl_AppendResult(interp, err, (char *) NULL);
			free(err);
			return TCL_ERROR;
			
		}
	}
	
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(strcmp("types", argv[1]) == 0) {
		if(!use_regex) {
			for(i = 0; get_type_name(i, &name, policy) == 0; i++) {
				Tcl_AppendElement(interp, name);
				free(name);
			}
		} 
		else {
			rt = get_type_idxs_by_regex(&idx_array, &num, &reg, TRUE, policy);
			if(rt < 0) {
				Tcl_AppendResult(interp, "Error searching types\n", (char *) NULL);
				return TCL_ERROR;
			}
			for(i = 0; i < num; i++) {
				if(get_type_name(idx_array[i], &name, policy) != 0) {
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "Unexpected error getting type name\n", (char *) NULL);
					return TCL_ERROR;
				} 
				Tcl_AppendElement(interp, name);
				free(name);
			} 
			if(num > 0) 
				free(idx_array);
		} 
	}
	else if(strcmp("attribs", argv[1]) == 0) {
		for(i = 0; get_attrib_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}
	}
	else if(strcmp("roles", argv[1]) == 0) {
		for(i = 0; get_role_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}
	}
	else if(strcmp("users", argv[1]) == 0) {
		for(i = 0; get_user_name2(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}
	}
	else if(strcmp("classes", argv[1]) == 0) {
		for(i = 0; get_obj_class_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}
	}
	else if(strcmp("perms", argv[1]) == 0) {
		for(i = 0; get_perm_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}
	}
	else if(strcmp("common_perms", argv[1]) == 0) {
		for(i = 0; get_common_perm_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}		
	}
	else if(strcmp("initial_sids", argv[1]) == 0) {
		for(i = 0; get_initial_sid_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}		
	}
	else if(strcmp("cond_bools", argv[1]) == 0) {
		for(i = 0; get_cond_bool_name(i, &name, policy) == 0; i++) {
			Tcl_AppendElement(interp, name);
			free(name);
		}		
	}
	else {
		if(use_regex) 
			regfree(&reg);
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "invalid name class (types, attribs, roles, users, classes, perms, or common_perms)", (char *) NULL);
		return TCL_ERROR;
	}	
	if(use_regex) 
		regfree(&reg);
			
	return TCL_OK;
}

int Apol_SearchInitialSIDs(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char *str, *user = NULL, *role = NULL, *type = NULL;
	int *isids = NULL, num_isids;
	char tbuf[BUF_SZ];
	int sz, rt, i;
	Tcl_DString *buf, buffer; 
	
	if(argc != 4) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	
	if (!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "The provided user string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	/* Set user parameter for the query and guard against buffer overflows */
	if(!str_is_only_white_space(argv[1])) {
		sz = strlen(argv[1]) + 1;
 	        user = (char *)malloc(sz);
	        if(user == NULL) {
		      fprintf(stderr, "out of memory");
		      return TCL_ERROR;
		}	
		user = strcpy(user, argv[1]);
	}
	
	if (!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "The provided role string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	
	/* Set role parameter for the query and guard against buffer overflows */	
	if(!str_is_only_white_space(argv[2])) {
		sz = strlen(argv[2]) + 1;
 	        role = (char *)malloc(sz);
	        if(role == NULL) {
		      fprintf(stderr, "out of memory");
		      return TCL_ERROR;
		}	
		role = strcpy(role, argv[2]);
	}
	
	if (!is_valid_str_sz(argv[3])) {
		Tcl_AppendResult(interp, "The provided type string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	
	/* Set type parameter for the query and guard against buffer overflows */	
	if(!str_is_only_white_space(argv[3])) {
		sz = strlen(argv[3]) + 1;
 	        type = (char *)malloc(sz);
	        if(type == NULL) {
		      fprintf(stderr, "out of memory");
		      return TCL_ERROR;
		}	
		type = strcpy(type, argv[3]);
	}
	buf = &buffer;	

	rt = search_initial_sids_context(&isids, &num_isids, user, role, type, policy);
	if( rt != 0) {
		Tcl_AppendResult(interp, "Problem searching initial SID contexts\n", (char *) NULL);
		return TCL_ERROR;
	}
	Tcl_DStringInit(buf);
	sprintf(tbuf, "\nMatching Initial SIDs (%d):\n\n", num_isids);
	Tcl_DStringAppend(buf, tbuf, -1);
	
	for(i = 0; i < num_isids; i++) {
		sprintf(tbuf, "%-25s :      ", policy->initial_sids[isids[i]].name);
		Tcl_DStringAppend(buf, tbuf, -1);
		str = re_render_security_context(policy->initial_sids[isids[i]].scontext, policy);
		if(str == NULL) {
			Tcl_DStringFree(buf);
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "\nProblem rendering security context for", isids[i], "th initial SID.\n", (char *) NULL);
			return TCL_ERROR;
		}
		sprintf(tbuf, "%s\n", str);
		Tcl_DStringAppend(buf, tbuf, -1);
		free(str);
	}
	free(isids);
	Tcl_DStringResult(interp, buf);
								
	return TCL_OK;
}

static void apol_cond_rules_append_cond_list(cond_rule_list_t *list, bool_t include_allow, bool_t include_audit, bool_t include_tt, 
				     	     policy_t *policy, Tcl_Interp *interp)
{
	int i;
	char tbuf[BUF_SZ], *rule = NULL;
	
	if (!list) {
		/* Indicate that there are no rules, since the list is empty. */
		Tcl_AppendElement(interp, "0");
		Tcl_AppendElement(interp, "0");
		Tcl_AppendElement(interp, "0");
		return;
	}
	assert(policy != NULL);
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_av_access);
	Tcl_AppendElement(interp, tbuf);
	if (include_allow) {
		for (i = 0; i < list->num_av_access; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->av_access[list->av_access[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_av_rule(FALSE, list->av_access[i], FALSE, policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->av_access[list->av_access[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_av_audit);
	Tcl_AppendElement(interp, tbuf);
	if (include_audit) {
		for (i = 0; i < list->num_av_audit; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->av_audit[list->av_audit[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_av_rule(FALSE, list->av_audit[i], TRUE, policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->av_audit[list->av_audit[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_te_trans);
	Tcl_AppendElement(interp, tbuf);
	if (include_tt) {
		for (i = 0; i < list->num_te_trans; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->te_trans[list->te_trans[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_tt_rule(FALSE, list->te_trans[i], policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->te_trans[list->te_trans[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
}

static void apol_cond_rules_append_expr(cond_expr_t *exp, policy_t *policy, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ];
	cond_expr_t *cur;
	Tcl_DString buffer, *buf = &buffer;
	
	Tcl_DStringInit(buf);
			
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			snprintf(tbuf, sizeof(tbuf)-1, "%s ", policy->cond_bools[cur->bool].name); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_NOT:
			snprintf(tbuf, sizeof(tbuf)-1, "! "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_OR:
			snprintf(tbuf, sizeof(tbuf)-1, "|| "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_AND:
			snprintf(tbuf, sizeof(tbuf)-1, "&& "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_XOR:
			snprintf(tbuf, sizeof(tbuf)-1, "^ "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_EQ:
			snprintf(tbuf, sizeof(tbuf)-1, "== "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_NEQ:
			snprintf(tbuf, sizeof(tbuf)-1, "!= ");
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		default:
			break;
		}
	}
	/* Append the conditional expression to our tcl list */
	Tcl_AppendElement(interp, buf->string);
	Tcl_DStringFree(buf);
}

/* 
 * argv[1] boolean name
 * argv[2] use reg expression
 * argv[3] include allow rules
 * argv[4] include audit rules
 * argv[5] include type transition rules
 * argv[6] use boolean for search
 */
int Apol_SearchConditionalRules(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char *error_msg = NULL;
	bool_t regex, *exprs_b, use_bool;
	bool_t include_allow, include_audit, include_tt;
	int i;
	
	if (argc != 7) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	
	if (!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "The provided user string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	
	regex = getbool(argv[2]);
	include_allow = getbool(argv[3]);
	include_audit = getbool(argv[4]);
	include_tt = getbool(argv[5]);
	use_bool = getbool(argv[6]);
	if (use_bool && str_is_only_white_space(argv[1])) {
		Tcl_AppendResult(interp, "You umust provide a boolean!", (char *) NULL);
		return TCL_ERROR;
	}
	/* If regex is turned OFF, then validate that the boolean exists. */
	if (use_bool && !regex && get_cond_bool_idx(argv[1], policy) < 0) {
		Tcl_AppendResult(interp, "Invalid boolean name provided. You may need to turn on the regular expression option.", (char *) NULL);
		return TCL_ERROR;
	}
	exprs_b = (bool_t*)malloc(sizeof(bool_t) * policy->num_cond_exprs);
	if (!exprs_b) {
		Tcl_AppendResult(interp, "Memory error\n", (char *) NULL);
		return TCL_ERROR;
	}
	memset(exprs_b, FALSE, sizeof(bool_t) * policy->num_cond_exprs);
	
	if (search_conditional_expressions(use_bool, argv[1], regex, exprs_b, &error_msg, policy) != 0) {
		Tcl_AppendResult(interp, "Error searching conditional expressions: ", error_msg, (char *) NULL);
		free(error_msg);
		return TCL_ERROR;
	}
	for (i = 0; i < policy->num_cond_exprs; i++) {
		if (exprs_b[i]) {
			apol_cond_rules_append_expr(policy->cond_exprs[i].expr, policy, interp);
		
			apol_cond_rules_append_cond_list(policy->cond_exprs[i].true_list, 
							include_allow, include_audit, include_tt, 
							policy, interp);
			
			apol_cond_rules_append_cond_list(policy->cond_exprs[i].false_list, 
							include_allow, include_audit, include_tt, 
							policy, interp);
		}
	}
	free(exprs_b);
										
	return TCL_OK;
}

/* search and return type enforcement rules */

/* This is a newer function that replaces the legacy Apol_GetTErules() function (below).  The 
 * latter is deprecated.  This function returns the search results in a tcl list.  This list
 * is organized as follows:
 *	index		contexts
 *	0		# of returned rules
 *	1		first rule (if any)
 *	2		first rule's lineno ref into policy.co
 *	3		2nd rule (if any)
 *	4		2nd rule lineno ref
 *	n-1		last rule
 *	n		last rule's lineno ref
 *
 * arg ordering; argv[x] where x is:
 *  1		te_allow
 *  2		neverallow
 *  3		clone
 *  4		auallow
 *  5		audeny
 *  6		dontaudit
 *  7		ttrans
 *  8		tmember
 *  9		tchange
 * 10		use_1
 * 11		indirect_1
 * 12		ta1	(first type/attrib search parameter)
 * 13		which	(indicates whether ta1 is used for source, or any location
 * 14		use_2
 * 15		indirect_2
 * 16		ta2	(second type/attrib search parameter, always as target)
 * 17		use_3
 * 18		indirect_3
 * 19		ta3
 * 20		classes (list)
 * 21		perms (list)
 * 22		allow_regex (bool, indicate whether ta* are regexp or not)
 * 23		ta1_opt (indicates whether ta1 is a TYPES, ATTRIBS, or BOTH)
 * 24		ta2_opt (same for ta2; NOTE ta3 is always a TYPES)
 * 25		include only rules that are enabled by the conditional policy (boolean)
 */
int Apol_SearchTErules(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	int i, rt;
	teq_query_t query;
	teq_results_t results;
	Tcl_DString buffer, *buf = &buffer;
	char tmpbuf[APOL_STR_SZ+64];
	CONST84 char **classes, **perms;
	bool_t use_1, use_2, use_3;

	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(argc != 26) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	
	init_teq_query(&query);
	init_teq_results(&results);

	if(getbool(argv[1]))
		query.rule_select |= TEQ_ALLOW;
	if(getbool(argv[2]))
		query.rule_select |= TEQ_NEVERALLOW;
	if(getbool(argv[3]))
		query.rule_select |= TEQ_CLONE;
	if(getbool(argv[4]))
		query.rule_select |= TEQ_AUDITALLOW;
	if(getbool(argv[5]))
		query.rule_select |= TEQ_AUDITDENY;
	if(getbool(argv[6]))
		query.rule_select |= TEQ_DONTAUDIT;
	if(getbool(argv[7]))
		query.rule_select |= TEQ_TYPE_TRANS;
	if(getbool(argv[8]))
		query.rule_select |= TEQ_TYPE_MEMBER;
	if(getbool(argv[9]))
		query.rule_select |= TEQ_TYPE_CHANGE;		
	query.use_regex = getbool(argv[22]);
	query.only_enabled = getbool(argv[25]);
	
	query.ta1.indirect = getbool(argv[11]);
	query.ta2.indirect = getbool(argv[15]);
	query.ta3.indirect = getbool(argv[18]);
	

	use_1 = getbool(argv[10]);
	if(use_1) {
                if(argv[12] == NULL || str_is_only_white_space(argv[12])) {
		        Tcl_AppendResult(interp, "empty source type/attrib!", (char *) NULL);
		        return TCL_ERROR;
	        }
		if(!is_valid_str_sz(argv[12])) {
			Tcl_AppendResult(interp, "Source type/attrib string too large", (char *) NULL);
			return TCL_ERROR;
		}
		if(strcmp(argv[13], "source") == 0) 
			query.any = FALSE;
		else if(strcmp(argv[13], "either") == 0)
			query.any = TRUE;
		else {
			Tcl_AppendResult(interp, "Invalid which option for source parameter", (char *) NULL);
			return TCL_ERROR;			
		}
		
		query.ta1.ta = (char *)malloc(strlen(argv[12]) + 1);
		if(query.ta1.ta == NULL) {
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		strcpy(query.ta1.ta, argv[12]);	/* The ta string */
		
       	        if(strcmp("types", argv[23])  == 0) 
		        query.ta1.t_or_a = IDX_TYPE;
	        else if(strcmp("attribs", argv[23]) == 0) 
		        query.ta1.t_or_a = IDX_ATTRIB;
   	        else if((strcmp("both", argv[23]) == 0) ||( strcmp("either", argv[23]) == 0)) 
		        query.ta1.t_or_a = IDX_BOTH;
	        else {
		        sprintf(tmpbuf, "ta1_opt value invalid: %s", argv[23]);
 		        free_teq_query_contents(&query);
		        Tcl_AppendResult(interp, tmpbuf, (char*) NULL);
		        return TCL_ERROR;
	        }
	}
	use_2 = (getbool(argv[14]) & ! query.any);
	if(use_2) {
	        if(argv[16] == NULL || str_is_only_white_space(argv[16])) {
		        Tcl_AppendResult(interp, "empty target type/attrib!", (char *) NULL);
		        return TCL_ERROR;
	        }
		if(!is_valid_str_sz(argv[16])) {
			Tcl_AppendResult(interp, "Target type/attrib string too large", (char *) NULL);
			return TCL_ERROR;
		}
		query.ta2.ta = (char *)malloc(strlen(argv[16]) + 1);
		if(query.ta2.ta == NULL) {
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		strcpy(query.ta2.ta, argv[16]);	/* The ta string */

		if(strcmp("types", argv[24])  == 0) 
			query.ta2.t_or_a = IDX_TYPE;
		else if(strcmp("attribs", argv[24]) == 0) 
			query.ta2.t_or_a = IDX_ATTRIB;
		else if((strcmp("both", argv[24]) == 0) || ( strcmp("either", argv[24]) == 0)) 
			query.ta2.t_or_a = IDX_BOTH;
		else {
			sprintf(tmpbuf, "ta2_opt value invalid: %s", argv[24]);
			free_teq_query_contents(&query);
			Tcl_AppendResult(interp, tmpbuf, (char*) NULL);		
			return TCL_ERROR;
		}
	}
	use_3 = getbool(argv[17]) && !query.any;
	if(use_3) {
	        if(argv[19] == NULL || str_is_only_white_space(argv[19])) {
		        Tcl_AppendResult(interp, "empty default type!", (char *) NULL);
		        return TCL_ERROR;
	        }
		if(!is_valid_str_sz(argv[19])) {
			Tcl_AppendResult(interp, "Default type string too large", (char *) NULL);
			return TCL_ERROR;
		}
		query.ta3.ta = (char *)malloc(strlen(argv[19]) + 1);
		if(query.ta3.ta == NULL) {
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		strcpy(query.ta3.ta, argv[19]);	/* The ta string */
		query.ta3.t_or_a = IDX_TYPE; /* can only ever be type */
	}

	/* classes */
	rt = Tcl_SplitList(interp, argv[20], &query.num_classes, &classes);
	if(rt != TCL_OK) {
		Tcl_AppendResult(interp, "error splitting classes", (char *) NULL);
		free_teq_query_contents(&query);
		return rt;
	}
	if(query.num_classes < 1) {
		query.classes = NULL;
	}
	else {
		query.classes = (int *)malloc(sizeof(int)*query.num_classes );
		if(query.classes == NULL) {
			Tcl_Free((char *) classes);
			free_teq_query_contents(&query);
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		for(i = 0; i < query.num_classes; i++) {
			query.classes[i] = get_obj_class_idx(classes[i], policy);
			if(query.classes[i] < 0) {
				sprintf(tmpbuf, "%s is not a valid object class name", classes[i]);
				Tcl_Free((char *) classes);
				free_teq_query_contents(&query);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) classes);
	}
	/* perms */
	rt = Tcl_SplitList(interp, argv[21], &query.num_perms, &perms);
	if(rt != TCL_OK) {
		free_teq_query_contents(&query);
		Tcl_AppendResult(interp, "error splitting perms", (char *) NULL);
		return rt;
	}
	if(query.num_perms < 1) {
		query.perms = NULL;
	}
	else {
		query.perms = (int *)malloc(sizeof(int)*query.num_perms);
		if(query.perms == NULL) {
			Tcl_Free((char *) perms);
			free_teq_query_contents(&query);
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		for(i = 0; i < query.num_perms; i++) {
			query.perms[i] = get_perm_idx(perms[i], policy);
			if(query.perms[i] < 0) {
				sprintf(tmpbuf, "%s is not a permission name", perms[i]);
				Tcl_Free((char *) perms);
				free_teq_query_contents(&query);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) perms);
	}
		

	/* submit query */
	rt = search_te_rules(&query, &results, policy);
	if(rt == -1) {
		Tcl_AppendResult(interp, "Unrecoverable error when searching TE rules", (char *) NULL);
		free_teq_results_contents(&results);
		free_teq_query_contents(&query);
		return TCL_ERROR;
	}
	else if(rt == -2) {
		switch(results.err) {
		case TEQ_ERR_TA1_REGEX:
			Tcl_AppendResult(interp, "Source type string is invalid regular expression", (char *) NULL);
			break;
		case TEQ_ERR_TA2_REGEX:
			Tcl_AppendResult(interp, "Target type string is invalid regular expression", (char *) NULL);
			break;
		case TEQ_ERR_TA3_REGEX:
			Tcl_AppendResult(interp, "Default type string is invalid regular expression", (char *) NULL);
			break;
		case TEQ_ERR_TA1_INVALID:
			Tcl_AppendResult(interp, "Source is not a valid type nor attribute", (char *) NULL);
			break;
		case TEQ_ERR_TA2_INVALID:
			Tcl_AppendResult(interp, "Target is not a valid type nor attribute", (char *) NULL);
			break;
		case TEQ_ERR_TA3_INVALID:
			Tcl_AppendResult(interp, "Default is not a valid type nor attribute", (char *) NULL);
			break;
		case TEQ_ERR_TA1_STRG_SZ:
			Tcl_AppendResult(interp, "Source string is too large", (char *) NULL);
			break;
		case TEQ_ERR_TA2_STRG_SZ:
			Tcl_AppendResult(interp, "Target string is too large", (char *) NULL);
			break;
		case TEQ_ERR_TA3_STRG_SZ:
			Tcl_AppendResult(interp, "Default string is too large", (char *) NULL);
			break;
		case TEQ_ERR_INVALID_CLS_Q:
			Tcl_AppendResult(interp, "The list of classes is incoherent", (char *) NULL);
			break;
		case TEQ_ERR_INVALID_PERM_Q:
			Tcl_AppendResult(interp, "The list of permissions is incoherent", (char *) NULL);
			break;
		case TEQ_ERR_INVALID_CLS_IDX:
			Tcl_AppendResult(interp, "One of the class indicies is incorrect", (char *) NULL);
			break;
		case TEQ_ERR_INVALID_PERM_IDX:
			Tcl_AppendResult(interp, "One of the permission indicies is incorrect", (char *) NULL);
			break;
		default:
			Tcl_AppendResult(interp, "Unexpected error searching rules", (char *) NULL);
			break;
		}
		free_teq_results_contents(&results);
		free_teq_query_contents(&query);
		return TCL_ERROR;
	}
	
	
	/* render results*/
	Tcl_DStringInit(buf);
	if(results.num_av_access > 0) {
		for(i = 0; i < results.num_av_access; i++) {
			rt = append_av_rule(0, 0, results.av_access[i], FALSE, policy, buf);
			if(rt != 0) {
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				free_teq_query_contents(&query);
				free_teq_results_contents(&results);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, buf->string);
			Tcl_DStringFree(buf);
			sprintf(tmpbuf, "%lu", policy->av_access[results.av_access[i]].lineno);
			Tcl_AppendElement(interp, tmpbuf);
			
			/* Append boolean values to indicate whether this is a conditional rule 
			 * and whether it is enabled for conditional policy support */
			if (policy->av_access[results.av_access[i]].cond_expr != -1)
				Tcl_AppendElement(interp, "1");
			else 
				Tcl_AppendElement(interp, "0");
			sprintf(tmpbuf, "%d", policy->av_access[results.av_access[i]].enabled);
			Tcl_AppendElement(interp, tmpbuf);
		}
	}
	if(results.num_av_audit > 0) {
		for(i = 0; i < results.num_av_audit; i++) {
			rt = append_av_rule(0, 0, results.av_audit[i], TRUE, policy, buf);
			if(rt != 0) {
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				free_teq_query_contents(&query);
				free_teq_results_contents(&results);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, buf->string);
			Tcl_DStringFree(buf);
			sprintf(tmpbuf, "%lu", policy->av_audit[results.av_audit[i]].lineno);
			Tcl_AppendElement(interp, tmpbuf);
			/* Append boolean values to indicate whether this is a conditional rule 
			 * and whether it is enabled for conditional policy support */
			if (policy->av_audit[results.av_audit[i]].cond_expr != -1)
				Tcl_AppendElement(interp, "1");
			else 
				Tcl_AppendElement(interp, "0");
			sprintf(tmpbuf, "%d", policy->av_audit[results.av_audit[i]].enabled);
			Tcl_AppendElement(interp, tmpbuf);
		}
	}
	if(results.num_type_rules > 0) { 
		for(i = 0; i < results.num_type_rules; i++) {
			rt = append_tt_rule(0, 0, results.type_rules[i], policy, buf);
			if(rt != 0) {
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				free_teq_query_contents(&query);
				free_teq_results_contents(&results);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, buf->string);
			Tcl_DStringFree(buf);
			sprintf(tmpbuf, "%lu", policy->te_trans[results.type_rules[i]].lineno);
			Tcl_AppendElement(interp, tmpbuf);
			/* Append boolean values to indicate whether this is a conditional rule 
			 * and whether it is enabled for conditional policy support */
			if (policy->te_trans[results.type_rules[i]].cond_expr != -1)
				Tcl_AppendElement(interp, "1");
			else 
				Tcl_AppendElement(interp, "0");
			sprintf(tmpbuf, "%d", policy->te_trans[results.type_rules[i]].enabled);
			Tcl_AppendElement(interp, tmpbuf);
		}
	}
	if(results.num_clones > 0) {
		for(i = 0; i < results.num_clones; i++) {
			rt = append_clone_rule(0, 0, &(policy->clones[results.clones[i]]), policy, buf);
			if(rt != 0) {
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				free_teq_query_contents(&query);
				free_teq_results_contents(&results);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, buf->string);
			Tcl_DStringFree(buf);
			sprintf(tmpbuf, "%lu", policy->clones[results.clones[i]].lineno);
			Tcl_AppendElement(interp, tmpbuf);
			/* Append 0 to indicate this is not a conditional rule. */
			Tcl_AppendElement(interp, "0");
			/* Since the enabled flag member is only supported in access, audit and type 
			 * transition rules, always append TRUE, so the returned list can be parsed 
			 * correctly. */
			Tcl_AppendElement(interp, "1");
		}
	}
	free_teq_query_contents(&query);
	free_teq_results_contents(&results);

	return TCL_OK;	
}

/* use Apol_SearchTErules() instead of this function */
int Apol_GetTErules(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	Tcl_AppendResult(interp, "Function is no longer supported", (char *) NULL);
	return TCL_ERROR;
}

/* get information about a single role  
 * args ordering:
 * argv[1]	name of role
 * argv[2]	# of role types per line to do
 */
int Apol_GetSingleRoleInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt, idx, numperline;
	Tcl_DString *buf, buffer;
	char tmpbuf[APOL_STR_SZ +64];

	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	
	rt = Tcl_GetInt(interp, argv[2], &numperline);
	if(rt == TCL_ERROR) {
		Tcl_AppendResult(interp,"argv[2] apparently not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Role string too large", (char *) NULL);
		return TCL_ERROR;
	}
	idx = get_role_idx(argv[1], policy);
	if(idx < 0) {
		sprintf(tmpbuf, "Invalid role name (%s)", argv[1]);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;			
	}
	buf = &buffer;
	Tcl_DStringInit(buf);
	
	rt = append_role(idx, FALSE, 1, policy, buf);
	if(rt != 0){
		Tcl_DStringFree(buf);
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "error appending attributes", (char *) NULL);
		return TCL_ERROR;
	}	
	Tcl_DStringResult(interp, buf);
	return TCL_OK;	
}

/* get a list of types for a give role
 * argv[1] role name
 */
int Apol_RoleTypes(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char tmpbuf[APOL_STR_SZ+64], *name;
	int i, idx, rt;
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Role string too large", (char *) NULL);
		return TCL_ERROR;
	}
	idx = get_role_idx(argv[1], policy);
	if(idx < 0) {
		sprintf(tmpbuf, "Invalid role: %s", argv[1]);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;
	}
	assert(strcmp(argv[1], policy->roles[idx].name) == 0);
	for(i = 0; i < policy->roles[idx].num; i++) {
		rt = get_type_name(policy->roles[idx].a[i], &name, policy);
		if(rt != 0) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "Problem finding a role name", (char *) NULL);
			return TCL_ERROR;
		}
		Tcl_AppendElement(interp, name);
		free(name);
	}
	
	return TCL_OK;
}


/* get roles for a user */
int Apol_UserRoles(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char tmpbuf[APOL_STR_SZ+64], *name;
	int rt, idx, i;
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "User string too large", (char *) NULL);
		return TCL_ERROR;
	}	
	idx = get_user_idx(argv[1], policy);
	if(idx < 0) {
		sprintf(tmpbuf, "Invalid user name (%s)", argv[1]);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;		
	}
	
	for(i = 0; i < policy->users[idx].num; i++) {
		rt = get_role_name(policy->users[idx].a[i], &name, policy);
		if(rt != 0) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "error getting role name", (char *) NULL);			
			return TCL_ERROR;
		}
		Tcl_AppendElement(interp, name);
		free(name);
	}
		
	return TCL_OK;
} 

/* get a list of users that contain a given role */
/* args ordering for argv[x]:
 * 1	(bool) name_only (whether to show names only, or all role information)
 * 2	(bool) use_type (whether to only return roles that include provided type)
 * 3	(string, opt) type (type to use if use_type)
 */
int Apol_GetUsersByRole(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt, idx = -1, i;
	char tmpbuf[APOL_STR_SZ+64];
	bool_t name_only, use_role;
	Tcl_DString *buf, buffer;
	
	if(argc < 3 || argc > 4) {
		Tcl_AppendResult(interp, "apol_GetUsersByRole: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	name_only = getbool(argv[1]);
	use_role = getbool(argv[2]);
	if(use_role) {
		if(argc != 4) {
			Tcl_AppendResult(interp, "apol_GetUsersByRole: wrong # of args", (char *) NULL);
			return TCL_ERROR;
		}
		if(!is_valid_str_sz(argv[3])) {
			Tcl_AppendResult(interp, "Type string too large", (char *) NULL);
			return TCL_ERROR;
		}
		idx = get_role_idx(argv[3], policy);
		if(idx < 0) {
			sprintf(tmpbuf, "Invalid role name (%s)", argv[3]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			return TCL_ERROR;			
		}	
	}

	buf = &buffer;	
	Tcl_DStringInit(buf);
	
	for(i = 0; i < policy->num_users; i++) {
		if(!use_role || does_user_have_role(i, idx, policy)) {
			rt = append_user_str(i, name_only, policy, buf);
			if(rt != 0){
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				Tcl_AppendResult(interp, "error appending user", (char *) NULL);
				return rt;
			}	
		}
	}
	
	Tcl_DStringResult(interp, buf);
	return TCL_OK;	
}



/* Search role rules */
/* arg ordering for argv[x]:
 * 1	allow (bool)		get allow rules
 * 2	trans (bool)		get role_transition rules
 * 3	use_src (bool)		whether to search by source role
 * 4	source			the source role
 * 5	which			whether source used for source or any (if any, others ignored)
 *					possible values: "source", "any"
 * 6	use_tgt (bool)		whether to search by target role (allow) or type (trans)
 * 7	target			the target role/type
 * 8	tgt_is_role (bool) 	whther target is role (allow only) or type (trans only)
 * 9	use_default (bool) 	search using default role (trans only)
 * 10	default			the default role
 */
int Apol_GetRoleRules(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int i, rt, src_idx = -1, tgt_idx = -1, tgt_type = IDX_ROLE, dflt_idx = -1;
	Tcl_DString buffer, *buf = &buffer;
	char tmpbuf[APOL_STR_SZ+64];
	bool_t allow, trans, any = FALSE, use_src, use_tgt, tgt_is_role, use_dflt;
	rbac_bool_t src_b, tgt_b, dflt_b;
	
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(argc != 11) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}

	allow = getbool(argv[1]);
	trans = getbool(argv[2]);
	use_src = getbool(argv[3]);
	tgt_is_role = getbool(argv[8]);

	if(use_src) {
		if(strcmp(argv[5], "source") == 0)
			any = FALSE;
		else if(strcmp(argv[5], "any") == 0)
			any = TRUE;
		else {
			Tcl_AppendResult(interp, "Invalid which option for source ", (char *) NULL);
			return TCL_ERROR;			
		}
		if(!is_valid_str_sz(argv[4])) {
			Tcl_AppendResult(interp, "Source string is too large", (char *) NULL);
			return TCL_ERROR;
		}		
		src_idx = get_role_idx(argv[4], policy);
		if(src_idx < 0) {
			sprintf(tmpbuf, "Invalid source role name (%s)", argv[4]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			return TCL_ERROR;			
		}
		
	}
	use_tgt = getbool(argv[6]) && !any;
	if(use_tgt) {
		if(allow && trans) {
			Tcl_AppendResult(interp, "Invalid option, target option may only be used if EITHER allow or role_trans is selected, but not both", (char *) NULL);
			return TCL_ERROR;
		}
		if(tgt_is_role && (!allow || trans)) {
			Tcl_AppendResult(interp, "Invalid option, target option may be a ROLE when allow, and only allow, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(!tgt_is_role && (allow || !trans)) {
			Tcl_AppendResult(interp, "Invalid option, target option may be a TYPE when role_trans, and only role_trans, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(tgt_is_role) {
			if(!is_valid_str_sz(argv[7])) {
				Tcl_AppendResult(interp, "Target string is too large", (char *) NULL);
				return TCL_ERROR;
			}
			tgt_idx = get_role_idx(argv[7], policy);
			if(tgt_idx < 0) {
				sprintf(tmpbuf, "Invalid target role name (%s)", argv[7]);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;			
			}
			tgt_type = IDX_ROLE;
		}
		else {
			if(!is_valid_str_sz(argv[7])) {
				Tcl_AppendResult(interp, "Target string is too large", (char *) NULL);
				return TCL_ERROR;
			}
			tgt_idx = get_type_or_attrib_idx(argv[7], &tgt_type, policy);
			if(tgt_idx < 0) {
				sprintf(tmpbuf, "Invalid target type or attribute (%s)", argv[7]);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;			
			}
		}
		
	}
	use_dflt = getbool(argv[9]) && !any;
	if(use_dflt) {
		if(allow || !trans) {
			Tcl_AppendResult(interp, "Invalid option, default may use when role_trans, and only role_trans, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(!is_valid_str_sz(argv[10])) {
			Tcl_AppendResult(interp, "Default string is too large", (char *) NULL);
			return TCL_ERROR;
		}
		dflt_idx = get_role_idx(argv[10], policy);
		if(dflt_idx < 0) {
			sprintf(tmpbuf, "Invalid default role name (%s)", argv[10]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			return TCL_ERROR;			
		}
	}
	
	Tcl_DStringInit(buf);
	
	if(init_rbac_bool(&src_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing src rules bool", (char *) NULL);
		return TCL_ERROR;
	}
	if(init_rbac_bool(&tgt_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing tgt rules bool", (char *) NULL);
		free_rbac_bool(&src_b);	
		return TCL_ERROR;
	}
	if(init_rbac_bool(&dflt_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing default rules bool", (char *) NULL);
		free_rbac_bool(&src_b);	
		free_rbac_bool(&tgt_b);	
		return TCL_ERROR;
	}
	
	if(use_src) {
		if(match_rbac_rules(src_idx, IDX_ROLE, SRC_LIST, FALSE, tgt_is_role, &src_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching source", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
	}
	else {
		all_true_rbac_bool(&src_b, policy);
	}
	if(use_src && any) {
		if(match_rbac_rules(src_idx, IDX_ROLE, TGT_LIST, FALSE, TRUE, &tgt_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching target", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
		if(match_rbac_rules(src_idx, IDX_ROLE, DEFAULT_LIST, FALSE, TRUE, &dflt_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching default", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
	}
	else {
		
		if(use_tgt && tgt_is_role) {
			if(match_rbac_rules(tgt_idx, IDX_ROLE, TGT_LIST, FALSE, TRUE, &tgt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching target", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}
		}
		else if(use_tgt && !tgt_is_role) {
			if(match_rbac_rules(tgt_idx, tgt_type, TGT_LIST, FALSE, FALSE, &tgt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching target", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}			
		}
		else {
			all_true_rbac_bool(&tgt_b, policy);
		}
		if(use_dflt) {
			if(match_rbac_rules(dflt_idx, IDX_ROLE, DEFAULT_LIST, FALSE, FALSE, &dflt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching default", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}
		}
		else {
			all_true_rbac_bool(&dflt_b, policy);
		}
	}
	
	if(allow) {
		for(i = 0; i < policy->num_role_allow; i++) {
			if((!any && (src_b.allow[i] && tgt_b.allow[i])) ||
			   (any && (src_b.allow[i] || tgt_b.allow[i]))) {
				rt = append_role_allow_rule(&(policy->role_allow[i]), policy, buf);
				if(rt != 0) {
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending role allow rule", (char *) NULL);
					free_rbac_bool(&src_b);	
					free_rbac_bool(&tgt_b);	
					free_rbac_bool(&dflt_b);
					return TCL_ERROR;
				}
			}
		}
	}
	if(trans) {
		for(i =0; i < policy->num_role_trans; i++) {
			if((!any && (src_b.trans[i] && tgt_b.trans[i] && dflt_b.trans[i])) ||
			   (any && (src_b.trans[i] || tgt_b.trans[i] || dflt_b.trans[i]))) {
				rt = append_role_trans_rule(&(policy->role_trans[i]), policy, buf);
				if(rt != 0) {
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending role_transition rule", (char *) NULL);
					free_rbac_bool(&src_b);	
					free_rbac_bool(&tgt_b);	
					free_rbac_bool(&dflt_b);
					return TCL_ERROR;
				}
			}
		}
	}
	
	Tcl_DStringResult(interp, buf);
	free_rbac_bool(&src_b);	
	free_rbac_bool(&tgt_b);	
	free_rbac_bool(&dflt_b);				
	return TCL_OK;	
}

/* get a list of role who contain a given type */
/* args ordering for argv[x]:
 * 1	(bool) name_only (whether to show names only, or all role information)
 * 2	(bool) use_type (whether to only return roles that include provided type)
 * 3	(string, opt) type (type to use if use_type)
 */
int Apol_GetRolesByType(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int idx = -1, i, rt;
	char tmpbuf[APOL_STR_SZ+64];
	bool_t name_only, use_type;
	Tcl_DString *buf, buffer;
	
	if(argc < 3 || argc > 4) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	name_only = getbool(argv[1]);
	use_type = getbool(argv[2]);
	if(use_type) {
		if(argc != 4) {
			Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
			return TCL_ERROR;
		}
		if(!is_valid_str_sz(argv[3])) {
			Tcl_AppendResult(interp, "Type string is too large", (char *) NULL);
			return TCL_ERROR;
		}
		idx = get_type_idx(argv[3], policy);
		if(idx < 0) {
			sprintf(tmpbuf, "Invalid type name (%s)", argv[3]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			return TCL_ERROR;			
		}	
	}

	buf = &buffer;	
	Tcl_DStringInit(buf);
	
	for(i = 0; i < policy->num_roles; i++) {
		if(!use_type || does_role_use_type(i, idx, policy)) {
			rt = append_role(i, name_only, 1, policy, buf);
			if(rt != 0){
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				Tcl_AppendResult(interp, "error appending role", (char *) NULL);
				return TCL_ERROR;
			}	
		}
	}
	Tcl_DStringResult(interp, buf);
	
	return TCL_OK;	
}

/* get types for a given attribute, returns a TCL list */
/* args ordering:
 * argv[1]	attrib name
 */
int Apol_GetAttribTypesList(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int idx, j;
	char tmpbuf[APOL_STR_SZ];
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Type/attrib string is too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	idx = get_attrib_idx(argv[1], policy);
	if(idx < 0) {
		sprintf(tmpbuf, "Invalid  attribute (%s)", argv[1]);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;			
	}	
	
	for(j = 0; j < policy->attribs[idx].num; j++) {
		Tcl_AppendElement(interp, policy->types[policy->attribs[idx].a[j]].name);
	}	
	
	return TCL_OK;
}

/* get information about a single type/attrib */
/* args ordering:
 * argv[1]	(bool) name only (otherwise show all information for type/attrib
 * argv[2]	(bool) attrib type's attribs (only used if argv[3] is an attrib)
 * argv[3]	name of type/attrib to get info for
 */
int Apol_GetSingleTypeInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt, ta_idx, ta_type;
	bool_t name_only, attr_type_attribs;
	char tmpbuf[APOL_STR_SZ+64];
	Tcl_DString *buf, buffer;
	
	if(argc != 4) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	name_only = getbool(argv[1]);
	attr_type_attribs = getbool(argv[2]);
	buf = &buffer;
	
	if(!is_valid_str_sz(argv[3])) {
		Tcl_AppendResult(interp, "Type/attrib string is too large", (char *) NULL);
		return TCL_ERROR;
	}
	ta_idx = get_type_or_attrib_idx(argv[3], &ta_type, policy);
	if(ta_idx < 0) {
		sprintf(tmpbuf, "Invalid type or attribute (%s)", argv[3]);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;			
	}	
	Tcl_DStringInit(buf);
	
	if ((ta_type & IDX_SUBTRACT)) {
		Tcl_DStringAppend(buf, "-", -1);
	}
	if ((ta_type & IDX_TYPE)) {
		rt = append_type_str(!name_only, !name_only, 0, ta_idx, policy, buf);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "error appending type info", (char *) NULL);
			return TCL_ERROR;
		}		
	}
	else if ((ta_type & IDX_ATTRIB)) {
		rt = append_attrib_str(!name_only, (!name_only ? attr_type_attribs : FALSE),
			!name_only, 0, 0, ta_idx, policy, buf);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "error appending attrib info", (char *) NULL);
			return TCL_ERROR;			
		}
	}
	else {
		Tcl_DStringFree(buf);
		Tcl_AppendResult(interp, "Invalid type from get_type_or_attrib_idx()!!", (char *) NULL);
		return TCL_ERROR;			

	}
	
	Tcl_DStringResult(interp, buf);
	return TCL_OK;	
}

/* args ordering:
 * argv[1]	bool name
 * argv[2]	new value
 */
int Apol_Cond_Bool_SetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt, bool_idx;
	bool_t value;
		
	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Bool string is too large", (char *) NULL);
		return TCL_ERROR;
	}
	bool_idx = get_cond_bool_idx(argv[1], policy);
	if (bool_idx < 0) {
		Tcl_AppendResult(interp, "Error getting index value for ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}
	value = getbool(argv[2]);
	
	rt = set_cond_bool_val(bool_idx, value, policy);
	if (rt != 0) {
		Tcl_AppendResult(interp, "Error setting value for ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}
	
	rt = update_cond_expr_items(policy);
	if (rt != 0) {
		Tcl_AppendResult(interp, "Error updating conditional expressions.",  (char *)NULL);
		return TCL_ERROR;
	}	
	
	return TCL_OK;
}

/* args ordering:
 * argv[1]	bool name
 */
int Apol_Cond_Bool_GetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	bool_t bool_val;
	int rt;
	char tbuf[64];	
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Bool string is too large", (char *) NULL);
		return TCL_ERROR;
	}
		
	rt = get_cond_bool_val(argv[1], &bool_val, policy);
	if (rt < 0) {
		Tcl_AppendResult(interp, "Error getting conditional boolean value for ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}
	
	sprintf(tbuf, "%d", bool_val);	
	Tcl_AppendElement(interp, tbuf);
	
	return TCL_OK;
}

/* args ordering:
 * argv[1]	sid name
 */
int Apol_GetInitialSIDInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int idx, rt;
	char *scontext = NULL, *isid_name = NULL;
	Tcl_DString *buf, buffer;
	char tbuf[APOL_STR_SZ+64];
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "SID string is too large", (char *) NULL);
		return TCL_ERROR;
	}
	buf = &buffer;
	Tcl_DStringInit(buf);
	idx = get_initial_sid_idx(argv[1], policy);
	if(is_valid_initial_sid_idx(idx, policy)) {
		rt = get_initial_sid_name(idx, &isid_name, policy);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_AppendResult(interp, "Unexpected error getting initial SID name\n\n", (char *) NULL);
			return TCL_ERROR;
		}
		scontext = re_render_initial_sid_security_context(idx, policy);	
		sprintf(tbuf, "%s", scontext);		
		Tcl_DStringAppend(buf, tbuf, -1);
	}	
	Tcl_DStringResult(interp, buf);
	return TCL_OK;
}

/* gets information about types/attribs, based on option */
/* args ord_types
 * argv[5]	attrib_type_attribs 
 * argv[6]	use_aliases
 * argv[7]	use search string (regexp)
 * argv[8]	search string
 * argv[9]	show files
 * argv[10]	include context
 * argv[11]	include class
 */
int Apol_GetTypeInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int i, rt, sz;
	Tcl_DString *buf, buffer;
	char tmpbuf[APOL_STR_SZ+64], *err;
	regex_t reg;
	
	bool_t do_types, type_attribs, do_attribs, attrib_types, attrib_type_attribs, 
		use_aliases, use_srchstr;
	bool_t show_files, include_cxt, include_class;
	
	buf = &buffer;
	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	
	do_types = getbool(argv[1]);
	type_attribs = getbool(argv[2]);
	do_attribs = getbool(argv[3]);
	attrib_types = getbool(argv[4]);
	attrib_type_attribs = getbool(argv[5]);
	use_aliases = getbool(argv[6]);
	use_srchstr = getbool(argv[7]);
	show_files = getbool(argv[9]);
	include_cxt = getbool(argv[10]);
	include_class = getbool(argv[11]);
		
	Tcl_DStringInit(buf);	
	if(!use_srchstr) {	
		if(do_types) {
			sprintf(tmpbuf, "\n\nTYPES (%d):\n", policy->num_types);
			Tcl_DStringAppend(buf, tmpbuf, -1);
			for(i = 0; i < policy->num_types; i++) {
				sprintf(tmpbuf, "%d: ", i+1);
				Tcl_DStringAppend(buf, tmpbuf, -1);
				rt = append_type_str(type_attribs, use_aliases, 0, i, policy, buf);
				if(rt != 0) {
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending types", (char *) NULL);
					return TCL_ERROR;
				}
				if (show_files) {
#ifdef LIBSEFS
					if (apol_append_type_files(i, FALSE, include_cxt, include_class, buf, policy, interp) != 0) {
						Tcl_DStringFree(buf);
						return TCL_ERROR;
					}
#else
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "Error: You need to build apol with libsefs! Please deselect the 'Show Files' checkbutton and run the search again.", (char *) NULL);
					return TCL_ERROR;
#endif
				} else {
					Tcl_DStringAppend(buf, "\n", -1);
				}
			}
		}
		
		if(do_attribs) {
			sprintf(tmpbuf, "\n\nTYPE ATTRIBUTES (%d):\n", policy->num_attribs);
			Tcl_DStringAppend(buf, tmpbuf, -1);
			for(i = 0; i < policy->num_attribs; i++) {
				sprintf(tmpbuf, "%d: ", i+1);
				Tcl_DStringAppend(buf, tmpbuf, -1);
				rt = append_attrib_str(attrib_types, attrib_type_attribs, use_aliases, 0, 0, i,
					policy, buf);
				if(rt != 0){
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending attributes", (char *) NULL);
					return TCL_ERROR;
				}
				if (show_files) {
#ifdef LIBSEFS
					if (apol_append_type_files(i, TRUE, include_cxt, include_class, buf, policy, interp) != 0) {
						Tcl_DStringFree(buf);
						return TCL_ERROR;
					}
#else
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "Error: You need to build apol with libsefs! Please deselect the 'Show Files' checkbutton and run the search again.", (char *) NULL);
					return TCL_ERROR;
#endif
				} else {
					Tcl_DStringAppend(buf, "\n", -1);
				}
			}
		}	
	}
	else {   /* use search string; search string was provided */
		if(!is_valid_str_sz(argv[8])) {
			Tcl_AppendResult(interp, "regular expression string is too large", (char *) NULL);
			return TCL_ERROR;
		}
		rt = regcomp(&reg, argv[8], REG_EXTENDED|REG_NOSUB);
		if(rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				Tcl_AppendResult(interp, "out of memory", (char *) NULL);
				return TCL_ERROR;
			}
			regerror(rt, &reg, err, sz);
			sprintf(tmpbuf, "Invalid regular expression:\n\n     %s\n\n", argv[8]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			Tcl_AppendResult(interp, err, (char *) NULL);
			Tcl_DStringFree(buf);
			regfree(&reg);
			free(err);
			return TCL_ERROR;
			
		}
		rt = append_all_ta_using_regex(&reg, argv[8], do_types, do_attribs, use_aliases, type_attribs, 
						attrib_types, attrib_type_attribs, policy, buf,
						show_files, include_cxt, include_class, interp);
		if(rt != 0) {
			Tcl_DStringFree(buf);
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "error searching with regex", (char *) NULL);
			regfree(&reg);
			return TCL_ERROR;
		}
		regfree(&reg);
	}
	
	Tcl_DStringResult(interp, buf);
	return TCL_OK;
}

static int types_relation_append_results(types_relation_query_t *tr_query, 
					     		types_relation_results_t *tr_results,
					     		Tcl_Interp *interp, 
					     		policy_t *policy)
{
	char tbuf[BUF_SZ], *name = NULL, *rule = NULL;
	int i, j, rt;
	int rule_idx, type_idx; 
	
	assert(tr_query != NULL && tr_results != NULL);
	/* Append typeA string */
	snprintf(tbuf, sizeof(tbuf)-1, "%s", tr_query->type_name_A);
	Tcl_AppendElement(interp, tbuf);
	/* Append the number of common attributes */
	snprintf(tbuf, sizeof(tbuf)-1, "%s", tr_query->type_name_B);
	Tcl_AppendElement(interp, tbuf);
	
	/* Append the number of common attributes */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_common_attribs);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_common_attribs; i++) {
		if (get_attrib_name(tr_results->common_attribs[i], &name, policy) != 0) {
			Tcl_AppendResult(interp, "Error getting attribute name.", (char *) NULL);
			free(name);
			return TCL_ERROR;
		}
		/* Append the attribute string */
		snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
		Tcl_AppendElement(interp, tbuf);
		free(name);
	}
	/* Append the number of common roles */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_common_roles);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_common_roles; i++) {
		if (get_role_name(tr_results->common_roles[i], &name, policy) != 0) {
			Tcl_AppendResult(interp, "Error getting role name.", (char *) NULL);
			free(name);
			return TCL_ERROR;
		}
		/* Append the role string */
		snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
		Tcl_AppendElement(interp, tbuf);
		free(name);
	}
	/* Append the number of common users */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_common_users);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_common_users; i++) {
		if (get_user_name2(tr_results->common_users[i], &name, policy) != 0) {
			Tcl_AppendResult(interp, "Error getting user name.", (char *) NULL);
			free(name);
			return TCL_ERROR;
		}
		/* Append the user string */
		snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
		Tcl_AppendElement(interp, tbuf);
		free(name);
	}
	/* Append the number of type transition/change rules */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_tt_rules);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_tt_rules; i++) {
		rule = re_render_tt_rule(1, tr_results->tt_rules_results[i], policy);
		if (rule == NULL)
			return TCL_ERROR;
		Tcl_AppendElement(interp, rule);
		free(rule);
	}
	/* Append the number of allow rules */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_allow_rules);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_allow_rules; i++) {
		rule = re_render_av_rule(1, tr_results->allow_rules_results[i], 0, policy);
		if (rule == NULL)
			return TCL_ERROR;
		Tcl_AppendElement(interp, rule);
		free(rule);
	}
	
	/* Append common object type access information for type A and B */
	if (tr_results->common_obj_types_results != NULL) {
		snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->common_obj_types_results->num_objs_A);
		Tcl_AppendElement(interp, tbuf);
		for (i = 0; i < tr_results->common_obj_types_results->num_objs_A; i++) {
			type_idx = tr_results->common_obj_types_results->objs_A[i];
			if (get_type_name(type_idx, &name, policy) != 0) {
				Tcl_AppendResult(interp, "Error getting attribute name!", (char *) NULL);
				return TCL_ERROR;
			}
			snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
			Tcl_AppendElement(interp, tbuf);
			free(name);
			
			snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->typeA_access_pool->type_rules[type_idx]->num_rules);
			Tcl_AppendElement(interp, tbuf);
			for (j = 0; j < tr_results->typeA_access_pool->type_rules[type_idx]->num_rules; j++) {
				rule_idx = tr_results->typeA_access_pool->type_rules[type_idx]->rules[j];
				rule = re_render_av_rule(1, rule_idx, 0, policy);
				if (rule == NULL)
					return TCL_ERROR;
				Tcl_AppendElement(interp, rule);
				free(rule);
			}
			snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->typeB_access_pool->type_rules[type_idx]->num_rules);
			Tcl_AppendElement(interp, tbuf);
			for (j = 0; j < tr_results->typeB_access_pool->type_rules[type_idx]->num_rules; j++) {
				rule_idx = tr_results->typeB_access_pool->type_rules[type_idx]->rules[j];
				rule = re_render_av_rule(1, rule_idx, 0, policy);
				if (rule == NULL)
					return TCL_ERROR;
				Tcl_AppendElement(interp, rule);
				free(rule);
			}
		}
	} else {
		Tcl_AppendElement(interp, "0");
	}

	/* Append unique object type access information for type A */
	if (tr_results->unique_obj_types_results != NULL) {
		snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->unique_obj_types_results->num_objs_A);
		Tcl_AppendElement(interp, tbuf);
		for (i = 0; i < tr_results->unique_obj_types_results->num_objs_A; i++) {
			type_idx = tr_results->unique_obj_types_results->objs_A[i];
			if (get_type_name(type_idx, &name, policy) != 0) {
				Tcl_AppendResult(interp, "Error getting attribute name!", (char *) NULL);
				return TCL_ERROR;
			}
			snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
			Tcl_AppendElement(interp, tbuf);
			free(name);
			
			snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->typeA_access_pool->type_rules[type_idx]->num_rules);
			Tcl_AppendElement(interp, tbuf);
			for (j = 0; j < tr_results->typeA_access_pool->type_rules[type_idx]->num_rules; j++) {
				rule_idx = tr_results->typeA_access_pool->type_rules[type_idx]->rules[j];
				rule = re_render_av_rule(1, rule_idx, 0, policy);
				if (rule == NULL)
					return TCL_ERROR;
				Tcl_AppendElement(interp, rule);
				free(rule);
			}
		}	
		/* Append unique object type access information for type B */
		snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->unique_obj_types_results->num_objs_B);
		Tcl_AppendElement(interp, tbuf);
		for(i = 0; i < tr_results->unique_obj_types_results->num_objs_B; i++) {
			type_idx = tr_results->unique_obj_types_results->objs_B[i];
			if (get_type_name(type_idx, &name, policy) != 0) {
				Tcl_AppendResult(interp, "Error getting attribute name!", (char *) NULL);
				return TCL_ERROR;
			}
			snprintf(tbuf, sizeof(tbuf)-1, "%s", name);
			Tcl_AppendElement(interp, tbuf);
			free(name);
			
			snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->typeB_access_pool->type_rules[type_idx]->num_rules);
			Tcl_AppendElement(interp, tbuf);
			for (j = 0; j < tr_results->typeB_access_pool->type_rules[type_idx]->num_rules; j++) {
				rule_idx = tr_results->typeB_access_pool->type_rules[type_idx]->rules[j];
				rule = re_render_av_rule(1, rule_idx, 0, policy);
				if (rule == NULL)
					return TCL_ERROR;
				Tcl_AppendElement(interp, rule);
				free(rule);
			}
		}
	} else {
		Tcl_AppendElement(interp, "0");
		Tcl_AppendElement(interp, "0");
	}
	
	/* Append direct information flow information */
	snprintf(tbuf, sizeof(tbuf)-1, "%d", tr_results->num_dirflows);
	Tcl_AppendElement(interp, tbuf);
	for (i = 0; i < tr_results->num_dirflows; i++) {
		/* Append the ending type name to the TCL list */ 
		snprintf(tbuf, sizeof(tbuf)-1, "%s", policy->types[tr_results->direct_flow_results[i].end_type].name);
		Tcl_AppendElement(interp, tbuf);
		/* Append the direction of the information flow for each ending type to the TCL list */ 
		if (tr_results->direct_flow_results[i].direction == IFLOW_BOTH)
			Tcl_AppendElement(interp, "both");
		else if (tr_results->direct_flow_results[i].direction == IFLOW_OUT)
			Tcl_AppendElement(interp, "out");
		else
			Tcl_AppendElement(interp, "in");
		
		rt = append_direct_edge_to_results(policy, tr_query->direct_flow_query, &tr_results->direct_flow_results[i], interp);
		if (rt != 0) {
			Tcl_AppendResult(interp, "Error appending direct flow edge information!\n", (char *) NULL);
			return TCL_ERROR;
		}
	}
				
	/* Append transitive information flow information for typeA->typeB */
	if (tr_results->trans_flow_results_A_to_B != NULL) {
		rt = append_transitive_iflow_results(policy, tr_results->trans_flow_results_A_to_B, interp);
		if (rt != 0) {
			Tcl_AppendResult(interp, "Error appending transitive flow results!\n", (char *) NULL);
			return TCL_ERROR;
		} 
	} else {
		Tcl_AppendElement(interp, "0");
	}
	/* Append transitive information flow information for typeB->typeA */
	if (tr_results->trans_flow_results_B_to_A != NULL) {
		rt = append_transitive_iflow_results(policy, tr_results->trans_flow_results_B_to_A, interp);
		if (rt != 0) {
			Tcl_AppendResult(interp, "Error appending transitive flow results!\n", (char *) NULL);
			return TCL_ERROR;
		} 
	} else {
		Tcl_AppendElement(interp, "0");
	}
	
	/* Append DTA information for typeA->typeB */
	if (tr_results->dta_results_A_to_B != NULL) {
		if (append_dta_results(policy, tr_results->dta_results_A_to_B, interp) != TCL_OK) {
			Tcl_AppendResult(interp, "Error appending domain transition analysis results!", (char *) NULL);
			return TCL_ERROR;
		} 
	} else {
		Tcl_AppendElement(interp, "0");
	}
	/* Append DTA information for typeB->typeA */
	if (tr_results->dta_results_B_to_A != NULL) {
		if (append_dta_results(policy, tr_results->dta_results_B_to_A, interp) != TCL_OK) {
			Tcl_AppendResult(interp, "Error appending domain transition analysis results!", (char *) NULL);
			return TCL_ERROR;
		} 
	} else {
		Tcl_AppendElement(interp, "0");
	}
	
	return 0;
}

/* argv[18] - flag (boolean value) for indicating that a list of object classes are being provided to the DTA query.
 * argv[19] - number of object classes that are to be included in the DTA query.
 * argv[20] - list of object classes/permissions for the DTA query.
 * argv[21] - flag (boolean value) for selecting object type(s) in the DTA query.
 * argv[22] - list of object types for the DTA query.
 */
static int types_relation_get_dta_options(dta_query_t *dta_query, Tcl_Interp *interp, char *argv[], policy_t *policy)
{
	int rt, num_objs, num_objs_options, num_end_types, i, j;
	int cur, type;
	int num_obj_perms, obj, perm;
	CONST84 char **obj_class_perms, **end_types;
	bool_t filter_obj_classes, filter_end_types;
	
	assert(dta_query != NULL);		
	filter_obj_classes = getbool(argv[18]);
	filter_end_types = getbool(argv[21]);
	rt = Tcl_GetInt(interp, argv[19], &num_objs);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp, "argv[19] apparently not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	
	if(filter_obj_classes) {
		/* Second, disassemble list of object class permissions, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[20], &num_objs_options, &obj_class_perms);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}
		
		if (num_objs_options < 1) {
			Tcl_AppendResult(interp, "Must provide object class permissions.", (char *) NULL);
			Tcl_Free((char *) obj_class_perms);
			return TCL_ERROR;
		}
	}
	
	if (filter_end_types) {
		/* First, disassemble TCL intermediate types list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[22], &num_end_types, &end_types);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}
		
		if (num_end_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least one end type.", (char *) NULL);
			Tcl_Free((char *) end_types);
			return TCL_ERROR;
		}
	}		
						
	if(filter_obj_classes && obj_class_perms != NULL) {		
		assert(num_objs > 0);
		cur = 0;
		/* Set the object classes permission info */
		/* Keep in mind that this is an encoded TCL list in the form 
		 * "class1 num_perms perm1 ... permN ... classN num_perms perm1 ... permN" */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_class_perms[cur], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class:\n", obj_class_perms[cur], (char *) NULL);
				Tcl_Free((char *) obj_class_perms);
				return TCL_ERROR;
			}
			/* Increment to next element, which should be the number of specified permissions for the class */
			cur++;
			rt = Tcl_GetInt(interp, obj_class_perms[cur], &num_obj_perms);
			if (rt == TCL_ERROR) {
				Tcl_AppendResult(interp, "Item in obj_class_perms list apparently is not an integer\n", (char *) NULL);
				return TCL_ERROR;
			}
			if (num_obj_perms == 0) {
				fprintf(stderr, "No permissions for object: %s. Skipping...\n", obj_class_perms[cur - 1]);
				continue;	
			}
			
			for (j = 0; j < num_obj_perms; j++) {
				cur++;
				perm = get_perm_idx(obj_class_perms[cur], policy);
				if (perm < 0 || !is_valid_perm_for_obj_class(policy, obj, perm)) {
					fprintf(stderr, "Invalid object class permission\n");
					continue;
				}
				if (dta_query_add_obj_class_perm(dta_query, obj, perm) == -1) {
					Tcl_AppendResult(interp, "error adding perm\n", (char *) NULL);
					return TCL_ERROR;
				}
			}
			cur++;
		}
		Tcl_Free((char *) obj_class_perms);
	}

	if (filter_end_types) {
		/* Set intermediate type info */
		for (i = 0; i < num_end_types; i++) {
			type = get_type_idx(end_types[i], policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				continue;
			}
			if (dta_query_add_end_type(dta_query, type) != 0) {
				Tcl_AppendResult(interp, "Memory error!\n", (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) end_types);
	}
	
	return TCL_OK;
}

/* argv[23] - flag (boolean value) for indicating that a list of object classes are being provided to the DIF query.
 * argv[24] - object classes for DIF query (a TCL list string). At least one object class must be given or 
 * 	     an error is thrown.
 * NOTE: IF SEARCHING DIRECT FLOWS, THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! 
 * 	 If, not it will throw an error.
 */
static int types_relation_get_dirflow_options(iflow_query_t *direct_flow_query, Tcl_Interp *interp, char *argv[], policy_t *policy)
{
	int num_objs, obj;
	int i, rt;
	CONST84 char **obj_classes;
	bool_t filter_obj_classes;
	
	assert(direct_flow_query != NULL);	
	if (policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded for Direct Flow Analysis!", (char *) NULL);
		return TCL_ERROR;
	}	
	
	filter_obj_classes = getbool(argv[23]);
	if (filter_obj_classes) {
		/* First, disassemble TCL object classes list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[24], &num_objs, &obj_classes);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}
		
		if (num_objs < 1) {
			Tcl_AppendResult(interp, "Must provide at least one object class to Direct Flow query.", (char *) NULL);
			Tcl_Free((char *) obj_classes);
			return TCL_ERROR;
		}
	}
	
	if (filter_obj_classes && obj_classes != NULL) {
		/* Set the object classes info */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_classes[i], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class provided to Direct Flow query:\n", obj_classes[i], (char *) NULL);
				Tcl_Free((char *) obj_classes);
				return TCL_ERROR;
			}
			if (iflow_query_add_obj_class(direct_flow_query, obj) == -1) {
				Tcl_AppendResult(interp, "Error adding object class to direct flow query!\n", (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) obj_classes);
	} 
	
	return TCL_OK;
}

/* argv[13] - (boolean value) for indicating that a list of transitive flow object classes are being provided to the TIF query.
 * argv[14] - number of object classes that are to be included in the transitive flow query.
 * argv[15] - encoded list of object class/permissions to include in the the transitive flow query.
 * argv[16] - flag (boolean value) for indicating whether or not to include intermediate types in the 
 *	      the transitive flow query.
 * argv[17] - TCL list of intermediate types for the transitive flow analysis
 * NOTE: IF SEARCHING TRANSITIVE FLOWS, THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! 
 * 	 If, not it will throw an error.
 */
static int types_relation_get_transflow_options(iflow_query_t *trans_flow_query, Tcl_Interp *interp, char *argv[], policy_t *policy)
{
	int num_objs, num_obj_perms, num_objs_options, obj, perm;
	int num_inter_types, type;
	int i, j, rt, cur;
	CONST84 char **obj_class_perms = NULL, **inter_types = NULL;
	bool_t filter_obj_classes, filter_inter_types;
	
	assert(trans_flow_query != NULL);
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded for Transitive Flow Analysis!", (char *) NULL);
		return TCL_ERROR;
	}	
	
	filter_obj_classes = getbool(argv[13]);
	filter_inter_types = getbool(argv[16]);
	rt = Tcl_GetInt(interp, argv[14], &num_objs);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp,"argv[14] apparently not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	
	if (filter_obj_classes) {
		/* Second, disassemble list of object class permissions, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[15], &num_objs_options, &obj_class_perms);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}
		
		if (num_objs_options < 1) {
			Tcl_AppendResult(interp, "Must provide object class permissions.", (char *) NULL);
			Tcl_Free((char *) obj_class_perms);
			return TCL_ERROR;
		}
	}
	
	if (filter_inter_types) {
		/* First, disassemble TCL intermediate types list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[17], &num_inter_types, &inter_types);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}
		
		if (num_inter_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least one intermediate type.", (char *) NULL);
			Tcl_Free((char *) inter_types);
			return TCL_ERROR;
		}
	}			
	
	if (filter_obj_classes && obj_class_perms != NULL) {
		assert(num_objs > 0);
		cur = 0;
		/* Set the object classes permission info */
		/* Keep in mind that this is an encoded TCL list in the form "class1 num_perms perm1 ... permN ... classN num_perms perm1 ... permN" */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_class_perms[cur], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class:\n", obj_class_perms[cur], (char *) NULL);
				Tcl_Free((char *) obj_class_perms);
				return TCL_ERROR;
			}
			/* Increment to next element, which should be the number of permissions for the class */
			cur++;
			rt = Tcl_GetInt(interp, obj_class_perms[cur], &num_obj_perms);
			if (rt == TCL_ERROR) {
				Tcl_AppendResult(interp, "Item in obj_class_perms list apparently is not an integer\n", (char *) NULL);
				return TCL_ERROR;
			}
	
			/* If this there are no permissions given then exclude the entire object class. */
			if (num_obj_perms == 0) {
				if (iflow_query_add_obj_class(trans_flow_query, obj) == -1) {
					Tcl_AppendResult(interp, "error adding obj\n", (char *) NULL);
					return TCL_ERROR;
				}
			} else {
				for (j = 0; j < num_obj_perms; j++) {
					cur++;
					perm = get_perm_idx(obj_class_perms[cur], policy);
					if (perm < 0 || !is_valid_perm_for_obj_class(policy, obj, perm)) {
						fprintf(stderr, "Invalid object class permission\n");
						continue;
					}
					if (iflow_query_add_obj_class_perm(trans_flow_query, obj, perm) == -1) {
						Tcl_AppendResult(interp, "error adding perm\n", (char *) NULL);
						return TCL_ERROR;
					}
				}
			} 
			cur++;
		}
		Tcl_Free((char *) obj_class_perms);
	}
	if (filter_inter_types && inter_types != NULL) {
		/* Set intermediate type info */
		for (i = 0; i < num_inter_types; i++) {
			type = get_type_idx(inter_types[i], policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				continue;
			}
			if (iflow_query_add_type(trans_flow_query, type) != 0) {
				Tcl_AppendResult(interp, "Memory error!\n", (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) inter_types);
	}
	
	return TCL_OK;
}

/* 
 * Types Relationship Analysis (QUERY ARGUMENTS):
 * argv[1]  - typeA (string)
 * argv[2]  - typeB (string)
 * argv[3]  - comm_attribs_sel (boolean value)	 
 * argv[4]  - comm_roles_sel (boolean value)	
 * argv[5]  - comm_users_sel (boolean value)	
 * argv[6]  - comm_access_sel (boolean value)	
 * argv[7]  - unique_access_sel (boolean value)
 * argv[8]  - dta_sel (boolean value)		
 * argv[9]  - trans_flow_sel (boolean value)
 * argv[10] - dir_flow_sel (boolean value)
 * argv[11] - tt_rule_sel  (boolean value)
 * argv[12] - te_rules_sel (boolean value)
 *
 * argv[13] - (boolean value) for indicating that a list of transitive flow object classes are being provided to the TIF query.
 * argv[14] - number of object classes that are to be included in the transitive flow query.
 * argv[15] - encoded list of object class/permissions to include in the the transitive flow query.
 * argv[16] - flag (boolean value) for indicating whether or not to include intermediate types in the 
 *	      the transitive flow query.
 * argv[17] - TCL list of intermediate types for the transitive flow analysis
 * NOTE: IF SEARCHING TRANSITIVE FLOWS, THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! 
 * 	 If, not it will throw an error.
 *
 * argv[18] - flag (boolean value) for indicating that a list of object classes are being provided to the DTA query.
 * argv[19] - number of object classes that are to be included in the DTA query.
 * argv[20] - list of object classes/permissions for the DTA query.
 * argv[21] - flag (boolean value) for selecting object type(s) in the DTA query.
 * argv[22] - list of object types for the DTA query.
 *
 * argv[23] - flag (boolean value) for indicating that a list of object classes are being provided to the DIF query.
 * argv[24] - object classes for DIF query (a TCL list string). At least one object class must be given or 
 * 	     an error is thrown.
 * NOTE: IF SEARCHING DIRECT FLOWS, THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! 
 * 	 If, not it will throw an error.
 * 
 *
 * Types Relationship Analysis (RESULTS FORMAT):
 * 	Returns a list organized to represent the tree structure that results from a types relationship 
 * 	analysis.  The TCL list looks like the following:
 *
 *	INDEX			CONTENTS
 *	0			typeA string
 *	1			typeB string
 *	2 			Number of common attributes (Na)
 *   		3		attribute 1
 *		....
 * 		Na		attribute Na
 *	next			Number of common roles (Nr)
 * 		next		role 1
 *		...
 *		Nr		role Nr
 *	next			Number of common users (Nu)
 *		next		user 1
 *		...
 *		Nu		user Nu
 *	next			Number of type transition rules
 *		next
 *		...
 *		N		tt rule N
 *	next			Number of other allow rules
 *		next	
 *		...
 *		Np		allow rule Np
 * 	next			Number of common objects for typeA
 *		next		object 1
 *		...
 *		N		typeA common object N
 * 				Number of common object rules for typeA
 *				Number of common objects for typeB
 *				Number of common object rules for typeB
 * 	next			Number of unique objects for typeA
 * 				Number of unique object rules for typeA
 *				Number of unique objects for typeB
 *				Number of unique object rules for typeB
 *	next 			Number of Direct Information flows
 *			Follows the format for the Apol_DirectInformationFlowAnalysis()
 *	next			Number of Transitive Information flows from typeA->typeB
 *			Follows the format for the Apol_TransitiveFlowAnalysis()
 *	next			Number of Transitive Information flows from typeB->typeA
 *			Follows the format for the Apol_TransitiveFlowAnalysis()
 *	next			Number of Forward Domain Transitions from typeA->typeB
 *	next		N, # of target domain types (if none, then no other results returned)
 *	  next		name first target type (if any)
 *	  next		X, # of allow transition rules
 *	  next X*2	pt rule1, lineno1, ....
 *	  next		Y, # of entry point file types for first target type
 *	    next	first file type
 *	    next	A, # of file entrypoint rules
 *	    next A*2	ep rule 1, lineno1,....
 *	    next	B, # of file execute rules
 *	    next B*2	ex rule1, lineno1, ...
 *
 *	    next	(repeat next file type record as above Y times)
 *
 *	next		(repeat target type record N times)
 *				Number of Forward Domain Transitions from typeB->typeA
 *		Follows the preceding format.
 *
 */
int Apol_TypesRelationshipAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	types_relation_query_t *tr_query = NULL;
	types_relation_results_t *tr_results = NULL;
	int rt, i;
	bool_t option_selected;
	
	if(argc != 25) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (policy == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "TypeA string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "TypeB string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
											
	tr_query = types_relation_query_create();
	if (tr_query == NULL) {
		Tcl_AppendResult(interp, "Error creating query.", (char *) NULL);
		return TCL_ERROR;
	}
		
	tr_query->type_name_A = (char *)malloc((strlen(argv[1]) + 1) * sizeof(char));
	if (tr_query->type_name_A == NULL) {
		types_relation_query_destroy(tr_query);
		Tcl_AppendResult(interp, "out of memory", (char *) NULL);
		return TCL_ERROR;
	}
	strcpy(tr_query->type_name_A, argv[1]);	
	
	tr_query->type_name_B = (char *)malloc((strlen(argv[2]) + 1) * sizeof(char));
	if (tr_query->type_name_B == NULL) {
		types_relation_query_destroy(tr_query);
		Tcl_AppendResult(interp, "out of memory", (char *) NULL);
		return TCL_ERROR;
	}
	strcpy(tr_query->type_name_B, argv[2]);
	
	for (i = 3; i < 13; i++) {
		option_selected = getbool(argv[i]);
		if (option_selected) {
			switch(i) {
			case 3:
				tr_query->options |= TYPES_REL_COMMON_ATTRIBS;
				break;
			case 4:
				tr_query->options |= TYPES_REL_COMMON_ROLES;
				break;
			case 5:
				tr_query->options |= TYPES_REL_COMMON_USERS;
				break;
			case 6:	
				tr_query->options |= TYPES_REL_COMMON_ACCESS;
				break;	
			case 7:
				tr_query->options |= TYPES_REL_UNIQUE_ACCESS;
				break;
			case 8:
				tr_query->options |= TYPES_REL_DOMAINTRANS;
				/* Create the query structure */
				if (!tr_query->dta_query) {
					tr_query->dta_query = dta_query_create();
					if (tr_query->dta_query == NULL) {
						Tcl_AppendResult(interp, "Memory error allocating dta query.\n", 
							(char *) NULL);
						types_relation_query_destroy(tr_query);
						return TCL_ERROR;
					}
				}
				/* Gather DTA options */
				if (types_relation_get_dta_options(tr_query->dta_query, interp, argv, policy) != 0) {
					types_relation_query_destroy(tr_query);
					return TCL_ERROR;
				}
				break;
			case 9:
				tr_query->options |= TYPES_REL_TRANSFLOWS;	
				/* Create the query structure */
				if (!tr_query->trans_flow_query) {
					tr_query->trans_flow_query = iflow_query_create();
					if (tr_query->trans_flow_query == NULL) {
						Tcl_AppendResult(interp, "Memory error allocating transitive iflow query.\n",
							(char *) NULL);
						types_relation_query_destroy(tr_query);
						return TCL_ERROR;
					}
				}
				/* Gather TRANSFLOW options*/
				if (types_relation_get_transflow_options(tr_query->trans_flow_query, interp, argv, policy) != 0) {
					types_relation_query_destroy(tr_query);
					return TCL_ERROR;
				}
				break;
			case 10:
				tr_query->options |= TYPES_REL_DIRFLOWS;
				/* Create the query structure */
				if (!tr_query->direct_flow_query) {
					tr_query->direct_flow_query = iflow_query_create();
					if (tr_query->direct_flow_query == NULL) {
						Tcl_AppendResult(interp, "Memory error allocating direct iflow query.\n",
							(char *) NULL);
						types_relation_query_destroy(tr_query);
						return TCL_ERROR;
					}
				}
				/* Gather DIRFLOW options*/
				if (types_relation_get_dirflow_options(tr_query->direct_flow_query, interp, argv, policy) != 0) {
					types_relation_query_destroy(tr_query);
					return TCL_ERROR;
				}
				break;
			case 11:
				tr_query->options |= TYPES_REL_TTRULES;
				break;
			case 12:
				tr_query->options |= TYPES_REL_ALLOW_RULES;
				break;
			default:
				fprintf(stderr, "Invalid option index: %d\n", i);
			}
		}
	}
#ifdef APOL_PERFORM_TEST
		/*  test performance; it's an undocumented feature only in test builds */
		{
		clock_t start,  stop;
		double time;
		start = clock();	
		rt = types_relation_determine_relationship(tr_query, &tr_results, policy);
		stop = clock();
		time = ((double) (stop - start)) / CLOCKS_PER_SEC;
		fprintf(stdout, "\nTime to complete types relationship analysis: %f\n\n", time);
		}
#else
	/* Perform the analysis */
	rt = types_relation_determine_relationship(tr_query, &tr_results, policy);
#endif
	if (rt != 0) {	
		types_relation_query_destroy(tr_query);
		Tcl_AppendResult(interp, "Analysis error!", (char *) NULL);
		return TCL_ERROR;
	}
	if (types_relation_append_results(tr_query, tr_results, interp, policy) != TCL_OK) {
		types_relation_query_destroy(tr_query);	
		if (tr_results) types_relation_destroy_results(tr_results);
		return TCL_ERROR;
	}
	 
	types_relation_query_destroy(tr_query);	
	if (tr_results) types_relation_destroy_results(tr_results);
	
	return TCL_OK;		
}

/* 
 * argv[1] - boolean value (0 for a forward DT analysis; otherwise, reverse DT analysis)
 * argv[2] - specified domain type used to start the analysis
 * argv[3] - boolean value indicating whether to filter by access to object classes and/or specific types.
 * argv[4] - number of classes to include for the inclusive filter 
 * argv[5] - list of object classes/permissions to provide the inclusive filter
 * argv[6] - list of object types to provide the inclusive filter
 * argv[7] - boolean value indicating whether to filter by end types 
 * argv[8] - end_type regex
 *
 * Given a domain type, this function determines what new domains the given domain can transition to/from.
 * and returns those domains, as well as the entrypoint type that allows that transition and all
 * the rules that provide the required access.
 */
/* TODO: We're at the point where our simple tcl/tk interface is becoming a burden...probably time
 * to seriously consider native C GUIs, or maybe PerlTK (or at least use tcl v. 8 objects rather
 * than strings)....however, for now.....
 *
 * we return a list orgainzed to represent the tree structure that results from a domain transition
 * analysis.  The conceptual tree result looks like:
 *	source_type (provided)
 *		+ target_type1
 *			(list of rules providing source target:process transition)
 *			+ entry_file_type1
 *				(list of rules providing target file_type:file entrypoint)
 *				(list of rules providing source file_type:file execute)
 *			+ entry_file_type2
 *				(...entrypoint)
 *				(...execute)
 *			...
 *			+ entry_file_typeN
 *				...
 *		+ target_type2
 *			...
 *		...
 *		+ target_typeN
 *			...
 *
 * Since we're lazily using a tcl list to return the entire result, we take the above conceptual tree
 * and encoded it as follows:
 *	INDEX		CONTENTS
 *	0		source type name
 *	1		N, # of target domain types (if none, then no other results returned)
 *	  2		name first target type (if any)
 *	  3		X, # of process transition rules
 *	  next X*2	pt rule1, lineno1, ....
 *	  next		Y, # of entry point file types for first target type
 *	    next	first file type
 *	    next	A, # of file entrypoint rules
 *	    next A*2	ep rule 1, lineno1,....
 *	    next	B, # of file execute rules
 *	    next B*2	ex rule1, lineno1, ...
 *
 *	    next	(repeat next file type record as above Y times)
 *
 *	next		(repeat target type record N times)
 */

int Apol_DomainTransitionAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt, num_objs, num_objs_options = 0, num_end_types = 0;
	int cur, type, i, j, sz;
	int num_obj_perms, obj, perm;
	CONST84 char **obj_class_perms, **end_types;
	dta_query_t *dta_query = NULL;
	domain_trans_analysis_t *dta_results = NULL;
	char *tmp = NULL, *end_type = NULL, *err = NULL;
	regex_t reg;
	
	if (argc != 9) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
		
	if(policy == NULL) {
		Tcl_AppendResult(interp, "No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	if(!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "The provided domain type string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	
	/* Create the query structure */
	dta_query = dta_query_create();
	if (dta_query == NULL) {
		Tcl_AppendResult(interp,"Memory error allocating dta query.\n", (char *) NULL);
		goto err;
	}
	/* determine if requesting a reverse DT analysis */
	dta_query->reverse = getbool(argv[1]);
	/* Set the start type for our query */ 					
	dta_query->start_type = get_type_idx(argv[2], policy);
	if (dta_query->start_type < 0) {
		Tcl_AppendResult(interp, "Invalid starting type ", argv[2], (char *) NULL);
		goto err;
	}
	dta_query->use_object_filters = getbool(argv[3]);
	rt = Tcl_GetInt(interp, argv[4], &num_objs);
	if(rt == TCL_ERROR) {
		Tcl_AppendResult(interp,"argv[4] apparently not an integer", (char *) NULL);
		goto err;
	}
		
	if (dta_query->use_object_filters) {
		/* First, disassemble TCL intermediate types list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[6], &num_end_types, &end_types);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list of types.", (char *) NULL);
			goto err;
		}
		
		if (num_end_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least one type for the results filters.", (char *) NULL);
			Tcl_Free((char *) end_types);
			goto err;
		}
		/* Set intermediate type info */
		for (i = 0; i < num_end_types; i++) {
			type = get_type_idx(end_types[i], policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				fprintf(stderr, "Invalid type provided to results filter: %s\n", end_types[i]);
				continue;
			}
			if (dta_query_add_end_type(dta_query, type) != 0) {
				Tcl_Free((char *) end_types);
				Tcl_AppendResult(interp, "Memory error!\n", (char *) NULL);
				goto err;
			}
		}
		Tcl_Free((char *) end_types);
		
		/* Second, disassemble list of object class permissions, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[5], &num_objs_options, &obj_class_perms);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		/* NOTE: We don't bail if all class/perm are to be excluded. 
		 * The analysis will simply filter on the specified types only. */
		if (num_objs_options < 1) {
			Tcl_AppendResult(interp, "You cannot exclude all object classes in the results filters.", (char *) NULL);
			Tcl_Free((char *) obj_class_perms);
			goto err;
		} else {
			assert(num_objs > 0); /* This should not fail; if so, this will be caught */
			cur = 0;
			/* Set the object classes permission info */
			/* Keep in mind that this is an encoded TCL list in the form "class1 num_perms perm1 ... permN ... classN num_perms perm1 ... permN" */
			for (i = 0; i < num_objs; i++) {
				obj = get_obj_class_idx(obj_class_perms[cur], policy);
				if (obj < 0) {
					Tcl_AppendResult(interp, "Invalid object class:\n", obj_class_perms[cur], (char *) NULL);
					Tcl_Free((char *) obj_class_perms);
					goto err;
				}
				/* Increment to next element, which should be the number of specified permissions for the class */
				cur++;
				rt = Tcl_GetInt(interp, obj_class_perms[cur], &num_obj_perms);
				if(rt == TCL_ERROR) {
					Tcl_Free((char *) obj_class_perms);
					Tcl_AppendResult(interp, "Item in obj_class_perms list apparently is not an integer\n", (char *) NULL);
					goto err;
				}
				if (num_obj_perms == 0) {
					fprintf(stderr, "No permissions for object: %s. Skipping...\n", obj_class_perms[cur - 1]);
					continue;	
				}
				
				for (j = 0; j < num_obj_perms; j++) {
					cur++;
					perm = get_perm_idx(obj_class_perms[cur], policy);
					if (perm < 0 || !is_valid_perm_for_obj_class(policy, obj, perm)) {
						fprintf(stderr, "Invalid object class permission\n");
						continue;
					}
					if (dta_query_add_obj_class_perm(dta_query, obj, perm) == -1) {
						Tcl_Free((char *) obj_class_perms);
						Tcl_AppendResult(interp, "error adding perm\n", (char *) NULL);
						goto err;
					}
				}
				cur++;
			}
			Tcl_Free((char *) obj_class_perms);
		}
	}
	dta_query->use_endtype_filters = getbool(argv[7]);
	if (dta_query->use_endtype_filters) {
		if (str_is_only_white_space(argv[8])) {
			Tcl_AppendResult(interp, "Please provide a regular expression for filtering the end types.", (char *) NULL);
			goto err;
		}
		end_type = strdup(argv[8]);
		if (end_type == NULL) {
			Tcl_AppendResult(interp, "Out of memory.", (char *) NULL);
			goto err;
		}
	   	trim_trailing_whitespace(&end_type);
		rt = regcomp(&reg, end_type, REG_EXTENDED|REG_NOSUB);
		if (rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if ((err = (char *)malloc(++sz)) == NULL) {
				Tcl_AppendResult(interp, "Out of memory.", (char *) NULL);
				goto err;
			}
			regerror(rt, &reg, err, sz);
			regfree(&reg);
			Tcl_AppendResult(interp, err, (char *) NULL);
			free(err);
			free(end_type);
			goto err;
		}
		free(end_type);
		rt = get_type_idxs_by_regex(&dta_query->filter_types, &dta_query->num_filter_types, &reg, FALSE, policy);
		if (rt < 0) {
			Tcl_AppendResult(interp, "Error searching types\n", (char *) NULL);
			goto err;
		}
	}
								
	/* Perform the analysis */
	rt = determine_domain_trans(dta_query, &dta_results, policy);
	if (rt == -2) {
		if (dta_query->reverse) {
			Tcl_AppendResult(interp, "invalid target type name", (char *) NULL);
		} else {
			Tcl_AppendResult(interp, "invalid source type name", (char *) NULL);
		}
		goto err;
	} else if(rt < 0) {
		Tcl_AppendResult(interp, "error with domain transition anaysis", (char *) NULL);
		goto err;
	}
	dta_query_destroy(dta_query);
	
	/* source type */
	rt = get_type_name(dta_results->start_type, &tmp, policy);
	if (rt != 0) {
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "Analysis error (looking up starting type name)", (char *) NULL);
		goto err;
	}
	Tcl_AppendElement(interp, tmp);
	free(tmp);
	if (append_dta_results(policy, dta_results, interp) != TCL_OK) {
		Tcl_AppendResult(interp, "Error appending domain transition analysis results!", (char *) NULL);
		goto err;
	}
		
	free_domain_trans_analysis(dta_results);
	return TCL_OK;
err:
	if (dta_query != NULL) dta_query_destroy(dta_query);
	if (dta_results != NULL) free_domain_trans_analysis(dta_results);
	if (tmp != NULL) free(tmp);
	if (end_type != NULL) free(end_type);
	return TCL_ERROR;
}

/* 
 * argv[1] - domain type used to start the analysis
 * argv[2] - flow direction - in, out, both (Default for direct is IFLOW_EITHER; Default for transitive is IFLOW_OUT)
 * argv[3] - flag (boolean value) for indicating that a list of object classes are being provided.
 * argv[4] - object classes (a TCL list string). At least one object class must be given or an error is thrown.
 * argv[5] - flag (boolean value) for indicating that filter on end type(s) is being provided 
 * argv[6] - ending type regular expression 
 *
 * NOTE: THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! If, not it will throw an error.
 *
 * DIRECT INFORMATION FLOW RESULTS:
 * 	Returns a list organized to represent the tree structure that results from a direct information flow
 * 	analysis.  The TCL list looks like this:
 *
 *	INDEX		CONTENTS
 *	0 		starting type provided by the user.
 *	1		number of ending type answers found from query (Ne)
 *	2		ending type1
 *	3		ending type flow direction
 *		4	number of object classes for edge (No)
 *		5		object class(1) flag (0 or 1) - used to indicate if we care about this object
 *					# a flag that is 1 will be followed by the following...otherwise, the next object class flag
 *   		6 			object class name
 *		7     			number of rules (Nr)
 *	    	8				allow rule 1, lineno1,....
 *						....
 *						....
 *		next				allow rule Nr, linenoNr
 *				...	
 *				...
 *		next		object class(No) flag (currently, each iflow edge has 29 object classes)
 *			....
 *			....
 *	next		ending type Ne
 *
 */
int Apol_DirectInformationFlowAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int num_objs, type, *types, obj;
	int i, rt, num, sz = 0;
	int num_answers = 0; 
	iflow_t *answers = NULL;
	char *start_type = NULL, *end_type = NULL;
	char *err, *name;
	char tbuf[64];
	CONST84 char **obj_classes;
	bool_t filter_obj_classes, filter_end_types;
	regex_t reg;
	iflow_query_t *iflow_query = NULL;
	
	/* Handle case if ending type regular expression is specified. */ 
	if(argc != 7) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded!", (char *) NULL);
		return TCL_ERROR;
	}	
	/* Set start_type variable and guard against buffer overflows */	
	start_type = argv[1];
	if(start_type == NULL || str_is_only_white_space(start_type)) {
		Tcl_AppendResult(interp, "empty starting type!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(start_type)) {
		Tcl_AppendResult(interp, "The provided start type string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	
	filter_obj_classes = getbool(argv[3]);
	filter_end_types = getbool(argv[5]);
	if(filter_obj_classes) {
		/* First, disassemble TCL object classes list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[4], &num_objs, &obj_classes);
		if(rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			return TCL_ERROR;
		}
		
		if(num_objs < 1) {
			Tcl_AppendResult(interp, "Must provide at least one object class.", (char *) NULL);
			Tcl_Free((char *) obj_classes);
			return TCL_ERROR;
		}
	}
	
	if(filter_end_types) {       
		if(!is_valid_str_sz(argv[6])) {
			Tcl_AppendResult(interp, "The provided end type filter string is too large.", (char *) NULL);
			return TCL_ERROR;
		}	
	        sz = strlen(argv[6]) + 1;
 	        end_type = (char *)malloc(sz);
	        if(end_type == NULL) {
		      fprintf(stderr, "out of memory");
		      return TCL_ERROR;
		}	
		end_type = strcpy(end_type, argv[6]);
	        if(end_type == NULL || str_is_only_white_space(end_type)) {
			Tcl_AppendResult(interp, "Please provide a regular expression for filtering the end types.", (char *) NULL);
			return TCL_ERROR;
		}
	}	
	iflow_query = NULL;
	/* Create the query structure */
	iflow_query = iflow_query_create();
	if (iflow_query == NULL) {
		Tcl_AppendResult(interp,"Memory error allocating query\n", (char *) NULL);
		return TCL_ERROR;
	}
	
	/* Set direction of the query. */
	if(strcmp(argv[2], "in") == 0) 
		iflow_query->direction = IFLOW_IN;
	else if(strcmp(argv[2], "out") == 0) 
		iflow_query->direction = IFLOW_OUT;
	else if(strcmp(argv[2], "both") == 0) 
		iflow_query->direction = IFLOW_BOTH;
	else if(strcmp(argv[2], "either") == 0) 
		iflow_query->direction = IFLOW_EITHER;
	else {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "Unknown flow direction provided:", argv[2], (char *) NULL);
		return TCL_ERROR;
	}

	/* Set the start type for our query */ 					
	iflow_query->start_type = get_type_idx(start_type, policy);
	if (iflow_query->start_type < 0) {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "Invalid starting type ", start_type, (char *) NULL);
		return TCL_ERROR;
	}
		
	if(filter_obj_classes && obj_classes != NULL) {
		/* Set the object classes info */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_classes[i], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class:\n", obj_classes[i], (char *) NULL);
				Tcl_Free((char *) obj_classes);
				iflow_query_destroy(iflow_query);
				return TCL_ERROR;
			}
			if (iflow_query_add_obj_class(iflow_query, obj) == -1) {
				Tcl_AppendResult(interp, "error adding object class\n", (char *) NULL);
				iflow_query_destroy(iflow_query);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) obj_classes);
	} 

	/* filter ending type(s) */
	if(filter_end_types) {	
		trim_trailing_whitespace(&end_type);
		rt = regcomp(&reg, end_type, REG_EXTENDED|REG_NOSUB);
		if(rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				iflow_query_destroy(iflow_query);
				Tcl_AppendResult(interp, "out of memory", (char *) NULL);
				return TCL_ERROR;
			}
			regerror(rt, &reg, err, sz);
			regfree(&reg);
			Tcl_AppendResult(interp, err, (char *) NULL);
			free(err);
			free(end_type);
			iflow_query_destroy(iflow_query);
			return TCL_ERROR;
		}
		free(end_type);
		rt = get_type_idxs_by_regex(&types, &num, &reg, FALSE, policy);
		if(rt < 0) {
			Tcl_AppendResult(interp, "Error searching types\n", (char *) NULL);
			iflow_query_destroy(iflow_query);
			return TCL_ERROR;
		}
		for(i = 0; i < num; i++) {
			rt = get_type_name(types[i], &name, policy);
			if(rt < 0) {
				sprintf(tbuf, "Problem getting %dth matching type name for idx: %d", i, types[i]);
				Tcl_AppendResult(interp, tbuf, (char *) NULL);
				iflow_query_destroy(iflow_query);
				return TCL_ERROR;
			}
			type = get_type_idx(name, policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				free(name);
				continue;
			}
			if (iflow_query_add_end_type(iflow_query, type) != 0) {
				free(name);
				iflow_query_destroy(iflow_query);
				Tcl_AppendResult(interp, "Error adding end type to query!\n", (char *) NULL);
				return TCL_ERROR;
			}
			free(name);
		} 		
	}
	
	/* Don't run the analysis call if the user has specified to filter end types by reg exp  
	 * and we've determined in the call to set_transitive_query_args() that there are no
	 * matching end types. */	
	if (!(filter_end_types && iflow_query->num_end_types == 0)) {
		/* Initialize iflow analysis structure, which holds the results of query */									
		if (iflow_direct_flows(policy, iflow_query, &num_answers, &answers) < 0) {
			iflow_query_destroy(iflow_query);
			Tcl_AppendResult(interp, "There were errors in the information flow analysis\n", (char *) NULL);
			return TCL_ERROR;
		}
	} 

	/* Append the start type to our encoded TCL list */
	sprintf(tbuf, "%s", start_type);
	Tcl_AppendElement(interp, tbuf);
		
	if (!(filter_end_types && iflow_query->num_end_types == 0)) {
		/* Append the number of answers from the query */
		sprintf(tbuf, "%d", num_answers);
		Tcl_AppendElement(interp, tbuf);
		for (i = 0; i < num_answers; i++) {
			/* Append the ending type name to the TCL list */ 
			sprintf(tbuf, "%s", policy->types[answers[i].end_type].name);
			Tcl_AppendElement(interp, tbuf);
			/* Append the direction of the information flow for each ending type to the TCL list */ 
			if (answers[i].direction == IFLOW_BOTH)
				Tcl_AppendElement(interp, "both");
			else if (answers[i].direction == IFLOW_OUT)
				Tcl_AppendElement(interp, "out");
			else
				Tcl_AppendElement(interp, "in");
			
			rt = append_direct_edge_to_results(policy, iflow_query, &answers[i], interp);
			if (rt != 0) {
				free(answers);
				iflow_query_destroy(iflow_query);
				Tcl_AppendResult(interp, "Error appending edge information!\n", (char *) NULL);
				return TCL_ERROR;
			}
		}
		free(answers);
	} else {
		Tcl_AppendElement(interp, "0");
	}
	/* Free any reserved memory */
	iflow_query_destroy(iflow_query);

	return TCL_OK;
}

/*
 * TRANSITIVE INFORMATION FLOW RESULTS:
 * 
 * argv[1] - domain type used to start the analysis
 * argv[2] - flow direction - IN or OUT
 * argv[3] - flag (boolean value) for indicating that a list of object classes are being provided.
 * argv[4] - number of object classes that are to be included in the query.
 * argv[5] - flag (boolean value) for indicating that filter on end type(s) is being provided 
 * argv[6] - ending type regular expression 
 * argv[7] - encoded list of object class/permissions to exclude in the query
 * argv[8] - flag (boolean value) for indicatinf whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
 * argv[10] - flag (boolean value) whether or not to use minimum weight.
 * argv[11] - minimum weight value
 *
 * NOTE: THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! If, not it will throw an error.
 *
 * 	Returns a list organized to represent the tree structure that results from a transitive information flow
 * 	analysis.  The TCL list looks like this:
 *
 *	INDEX		CONTENTS
 *	0 		starting type provided by the user.
 *	1		number of answers found from query (Ne)
 *	2		type 1
 *	3			total path length for this particular type (Np)
 *		4		flow 1
 *		5			flow1 start type name
 *		6			flow1 target type name
 *		7			number of object classes for each edge (No)
 *		8			object class(1) 
 *		9     				number of rules (Nr)
 *	    	10					allow rule 1, lineno1,....
 *							....
 *							....
 *		next					allow rule Nr, linenoNr
 *					...	
 *					...
 *		next			object class(No) 
 *				....
 *				....
 *		next   		flow N
 *			....
 *			....
 *	next		type Ne
 *
 */
int Apol_TransitiveFlowAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	iflow_transitive_t *answers = NULL;
	iflow_query_t* iflow_query = NULL;
	char *start_type = NULL;
	int rt;
	char tbuf[64];
	bool_t filter_end_types;
	
	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	iflow_query = set_transitive_query_args(interp, argv);
	if (iflow_query == NULL) {
		return TCL_ERROR;
	}
	filter_end_types = getbool(argv[5]);
	/* Don't run the analysis call if the user has specified to filter end types by reg exp  
	 * and we've determined in the call to set_transitive_query_args() that there are no
	 * matching end types. */	
	if (!(filter_end_types && iflow_query->num_end_types == 0)) {
		if ((answers = iflow_transitive_flows(policy, iflow_query)) == NULL) {
			iflow_query_destroy(iflow_query);
			Tcl_AppendResult(interp, "There were errors in the information flow analysis\n", (char *) NULL);
			return TCL_ERROR;
		}
	}
	/* Append the start type to our encoded TCL list */
	rt = get_type_name(iflow_query->start_type, &start_type, policy);				
	if (rt != 0) {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "Could not get start type name. ", (char *) NULL);
		return TCL_ERROR;
	}
	sprintf(tbuf, "%s", start_type);
	Tcl_AppendElement(interp, tbuf);
	if (!(filter_end_types && iflow_query->num_end_types == 0)) {			
		rt = append_transitive_iflow_results(policy, answers, interp);
		if(rt != 0) {
			iflow_transitive_destroy(answers);
			iflow_query_destroy(iflow_query);
			Tcl_AppendResult(interp, "Error appending edge information!\n", (char *) NULL);
			return TCL_ERROR;
		}	
		iflow_transitive_destroy(answers);
	} else {
		Tcl_AppendElement(interp, "0");
	}
	iflow_query_destroy(iflow_query);
	return TCL_OK;		
}

/* argv[1] - domain type used to start the analysis
 * argv[2] - flow direction - IN or OUT
 * argv[3] - flag (boolean value) for indicating that a list of object classes are being provided.
 * argv[4] - number of object classes that are to be included in the query.
 * argv[5] - flag (boolean value) for indicating that filter on end type(s) is being provided 
 * argv[6] - ending type regular expression 
 * argv[7] - encoded list of object class/permissions to exclude in the query
 * argv[8] - flag (boolean value) for indicating whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
 * argv[10] - flag (boolean value) whether or not to use minimum weight.
 * argv[11] - minimum weight value
 */
int Apol_TransitiveFindPathsStart(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{		
	iflow_query_t* iflow_query = NULL;
	
	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	iflow_query = set_transitive_query_args(interp, argv);
	if (iflow_query == NULL) {
		return TCL_ERROR;
	}
	if(iflow_query == NULL) {
		Tcl_AppendResult(interp, "Query is empty!", (char *) NULL);
		return TCL_ERROR;
	}	
	/* Start finding additional iflow paths */
	state = iflow_find_paths_start(policy, iflow_query);	
	if (state == NULL) {
		Tcl_AppendResult(interp, "Could not start iflow paths search.", (char *) NULL);
		return TCL_ERROR;
	}
	iflow_query_destroy(iflow_query);
	return TCL_OK;
}

int Apol_TransitiveFindPathsNext(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	int num_paths;
	char tbuf[64];
		 
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded!", (char *) NULL);
		return TCL_ERROR;
	}
	if(state == NULL) {
		Tcl_AppendResult(interp,"Analysis not started!", (char *) NULL);
		return TCL_ERROR;
	}
	num_paths = iflow_find_paths_next(state);
	if (num_paths == -1) {
		iflow_find_paths_abort(state);
		Tcl_AppendResult(interp, "Error while finding additional paths.", (char *) NULL);
		return TCL_ERROR;
	} 
	sprintf(tbuf, "%d", num_paths);
	Tcl_AppendResult(interp, tbuf, (char *) NULL);
	
	return TCL_OK;		
}

int Apol_TransitiveFindPathsGetResults(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	int rt;
	iflow_transitive_t *answers = NULL;
	
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy->pmap == NULL) {
		Tcl_AppendResult(interp,"No permission map loaded!", (char *) NULL);
		return TCL_ERROR;
	}
	if(state == NULL) {
		Tcl_AppendResult(interp,"Analysis not started!", (char *) NULL);
		return TCL_ERROR;
	}
	answers = iflow_find_paths_end(state);
	if (answers == NULL) {
		iflow_find_paths_abort(state);
		Tcl_AppendResult(interp, "Error while retrieving additional paths. Results were empty.", (char *) NULL);
		return TCL_ERROR;
	} 			
	rt = append_transitive_iflow_results(policy, answers, interp);
	if(rt != 0) {
		iflow_transitive_destroy(answers);
		Tcl_AppendResult(interp, "Error while retrieving additional paths results.\n", (char *) NULL);
		return TCL_ERROR;
	}	
	iflow_transitive_destroy(answers);
	return TCL_OK;		
}

int Apol_TransitiveFindPathsAbort(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(state != NULL) {
		iflow_find_paths_abort(state);
	}
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

int Apol_IsLibsefs_BuiltIn(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char tbuf[64];
	
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (is_libsefs_builtin) 
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
 * argv[1] - file name to save 
 * argv[2] - directory to start scanning
 */
int Apol_Create_FC_Index_File(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}	
#ifndef LIBSEFS
	Tcl_AppendResult(interp, "You need to build apol with libsefs to use this feature!", (char *) NULL);
	return TCL_ERROR;
#else	
	sefs_filesystem_db_t fsdata_local;
	int rt;
	
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "File string too large", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "Directory string too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	fsdata_local.dbh = NULL;
	fsdata_local.fsdh = NULL;
	rt = sefs_filesystem_db_populate(&fsdata_local, argv[2]);
 	if (rt == -1) {
		Tcl_AppendResult(interp, "Error populating database.\n", (char *) NULL);
		return TCL_ERROR;
	} else if (rt == SEFS_NOT_A_DIR_ERROR) {
		Tcl_AppendResult(interp, "The pathname (", argv[2], ") is not a directory.\n", (char *) NULL);
		return TCL_ERROR;
	} else if (rt == SEFS_DIR_ACCESS_ERROR) {
		Tcl_AppendResult(interp, "You do not have permission to read the directory ", argv[2], ".\n", (char *) NULL);
		return TCL_ERROR;
	}
	if (sefs_filesystem_db_save(&fsdata_local, argv[1]) != 0) {
		/* Make sure the database is closed and memory freed. */
		sefs_filesystem_db_close(&fsdata_local);
		Tcl_AppendResult(interp, "Error creating index file\n", (char *) NULL);
		return TCL_ERROR;
	}
	sefs_filesystem_db_close(&fsdata_local);
	
	return TCL_OK;
#endif
}

/* 
 * argv[1] - index file to load
 */
int Apol_Load_FC_Index_File(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
#ifndef LIBSEFS
	Tcl_AppendResult(interp, "You need to build apol with libsefs to use this feature!", (char *) NULL);
	return TCL_ERROR;
#else		
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "File string too large", (char *) NULL);
		return TCL_ERROR;
	}
	if (fsdata != NULL) {
		sefs_filesystem_db_close(fsdata);
	} else {
		fsdata = (sefs_filesystem_db_t*)malloc(sizeof(sefs_filesystem_db_t));
		if (fsdata == NULL) {
			Tcl_AppendResult(interp, "Out of memory\n", (char *) NULL);
			return TCL_ERROR;
		}
		memset(fsdata, 0, sizeof(sefs_filesystem_db_t));
	}

 	if (sefs_filesystem_db_load(fsdata, argv[1]) == -1) {
 		Tcl_AppendResult(interp, "Loading of database failed.\n", (char *) NULL);
		return TCL_ERROR;
	}
	
	return TCL_OK;
#endif
}

#ifdef LIBSEFS
static void apol_search_fc_index_append_results(sefs_search_ret_t *key, Tcl_Interp *interp) 
{
	sefs_search_ret_t *curr = key;
	
	/* walk the linked list */
	while (curr) {
		if (curr->path)
			Tcl_AppendElement(interp, curr->path);
		if (curr->context)
			Tcl_AppendElement(interp, curr->context);
		if (curr->object_class)
			Tcl_AppendElement(interp, curr->object_class);
		curr = curr->next;
	}
}
#endif

/* 
 * This function expects a file context index to be loaded into memory.
 * Arguments:
 *	argv[1] - use_type [bool]
 * 	argv[2] - type [TCL list of strings]
 * 	argv[3] - use_user [bool]
 *	argv[4] - user [TCL list of strings]
 * 	argv[5] - use_class [bool]
 * 	argv[6] - object class [TCL list of strings]
 * 	argv[7] - use_path [bool]
 * 	argv[8] - path [Tcl list of strings]
 * 	argv[9] - use regular expressions for user
 * 	argv[10] - use regular expressions for type
 *	argv[11] - use regular expressions for path
 */
int Apol_Search_FC_Index_DB(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{	
	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
#ifndef LIBSEFS
	Tcl_AppendResult(interp, "You need to build apol with libsefs to use this feature!", (char *) NULL);
	return TCL_ERROR;
#else		
	int rt;
	int num_types, num_users, num_classes, num_paths;
	sefs_search_keys_t search_keys;
	CONST84 char **object_classes, **types, **users, **paths;
	
	if (fsdata == NULL) {
		Tcl_AppendResult(interp, "No Index File Loaded!", (char *) NULL);
		return TCL_ERROR;
	}
	object_classes = types = users = paths = NULL;

	search_keys.user = NULL;
	search_keys.path = NULL;
	search_keys.type = NULL;
	search_keys.object_class = NULL;
	search_keys.num_type = 0;
	search_keys.num_user = 0;
	search_keys.num_object_class = 0;
	search_keys.num_path = 0;
	
	if (getbool(argv[1])) {
		rt = Tcl_SplitList(interp, argv[2], &num_types, &types);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		
		if (num_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least 1 type.", (char *) NULL);
			goto err;
		}
		search_keys.num_type = num_types;
		search_keys.type = types;
	}
	if (getbool(argv[3])) {
		rt = Tcl_SplitList(interp, argv[4], &num_users, &users);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		
		if (num_users < 1) {
			Tcl_AppendResult(interp, "Must provide at least 1 user.", (char *) NULL);
			goto err;
		}
		search_keys.num_user = num_users;
		search_keys.user = users;
	}
	if (getbool(argv[5])) {
		rt = Tcl_SplitList(interp, argv[6], &num_classes, &object_classes);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		
		if (num_classes < 1) {
			Tcl_AppendResult(interp, "Must provide at least 1 object class.", (char *) NULL);
			goto err;
		}
		search_keys.num_object_class = num_classes;
		search_keys.object_class = object_classes;
	}
	if (getbool(argv[7])) {
		rt = Tcl_SplitList(interp, argv[8], &num_paths, &paths);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		
		if (num_paths < 1) {
			Tcl_AppendResult(interp, "Must provide at least 1 path.", (char *) NULL);
			goto err;
		}
		search_keys.num_path = num_paths;
		search_keys.path = paths;
	}

	rt = Tcl_GetInt(interp, argv[9], &search_keys.do_user_regEx);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp, "argv[9] apparently is not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	rt = Tcl_GetInt(interp, argv[10], &search_keys.do_type_regEx);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp, "argv[10] apparently is not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	rt = Tcl_GetInt(interp, argv[11], &search_keys.do_path_regEx);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp, "argv[11] apparently is not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	
	if (!search_keys.type && !search_keys.user && !search_keys.object_class && !search_keys.path) {
		Tcl_AppendResult(interp, "You must specify search criteria!", (char *) NULL);
		goto err;
	}
	
	rt = sefs_filesystem_db_search(fsdata, &search_keys);
	if (rt != 0) {
		Tcl_AppendResult(interp, "Search failed\n", (char *) NULL);
		goto err;
	}
	apol_search_fc_index_append_results(search_keys.search_ret, interp);
	sefs_search_keys_ret_destroy(search_keys.search_ret);
	if (types) Tcl_Free((char *) types);
	if (users) Tcl_Free((char *) users);
	if (object_classes) Tcl_Free((char *) object_classes);
	if (paths) Tcl_Free((char *) paths);
	return TCL_OK;
err:
	if (types) Tcl_Free((char *) types);
	if (users) Tcl_Free((char *) users);
	if (object_classes) Tcl_Free((char *) object_classes);
	if (paths) Tcl_Free((char *) paths);
	return TCL_ERROR;
#endif
}

/* 
 * No arguments, however, this function expects a file context index to be loaded into memory.
 */
int Apol_FC_Index_DB_Get_Items(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
#ifndef LIBSEFS
	Tcl_AppendResult(interp, "You need to build apol with libsefs!", (char *) NULL);
	return TCL_ERROR;
#else		
	int list_sz = 0, i, request_type;
	char **list_ret = NULL;
	
	if (fsdata == NULL) {
		Tcl_AppendResult(interp, "No Index File Loaded!", (char *) NULL);
		return TCL_ERROR;
	}
	
	if(strcmp("types", argv[1]) == 0) {
		request_type = SEFS_TYPES;
	} else if(strcmp("users", argv[1]) == 0) {
		request_type = SEFS_USERS;
	} else if(strcmp("classes", argv[1]) == 0) {
		request_type = SEFS_OBJECTCLASS;
	}  else {
		Tcl_AppendResult(interp, "Invalid option: ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}
	
 	if ((list_ret = sefs_filesystem_db_get_known(fsdata, &list_sz, request_type)) != NULL) {
		for (i = 0; i < list_sz; i++){
			Tcl_AppendElement(interp, list_ret[i]);
		}
		sefs_double_array_destroy(list_ret, list_sz);
	}

	return TCL_OK;
#endif
}

/* 
 * No arguments.
 */
int Apol_Close_FC_Index_DB(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
#ifdef LIBSEFS
	if (fsdata != NULL) {
 		sefs_filesystem_db_close(fsdata);
 		free(fsdata);
 		fsdata = NULL;
	}	
#endif
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


/* Flow Assertion Tcl <--> C interface
 * This command should be invoked from Tcl like so:
 *   apol_FlowAssertExecute assertion_contents ?abort?
 * where:
 *   assertion_contents - a Tcl string that holds the (hopefully
 *     syntactically correct) assertion file
 *
 * An optional second parameter, if set to non-zero, aborts execution
 * after the first time an assertion fails.
 *
 * If the assertion fails this function returns a list of results.
 * Each result is a 4-ple:
 *  - mode for the assertion (1 = NOFLOW, 2 = MUSTFLOW, 3 = ONLYFLOW)
 *  - line number from assertion_contents
 *  - integer result from executing (0 = VALID, 1 = FAIL, other values = error)
 *  - another list of 5-ples describing all failures found
 *      start_id   - type ID value for start of path
 *      end_id     - type ID value for end of path
 *      via_id     - type ID value of required element missing from path, or
 *                   -1 if non-applicable
 *      rule_list  - list of {line number, rule} from policy.conf that breaks
 *                   assertion
 *    * If line_list != {} then a conflict to assertion, with path
 *      beginning with rule_line.
 *    * Else if via_id >= 0 then no path was found from start_id to
 *      end_id by way of via_id.
 *    * Otherwise no path found at all from start_id to end_id.
 *    If no failures or result is an error then this is an empty list.
 */
int Apol_FlowAssertExecute (ClientData clientData, Tcl_Interp *interp,
                            int objc, Tcl_Obj * CONST objv[]) {
        char *assertion_contents;
        bool_t abort_after_first_conflict = FALSE;
        llist_t *assertion_results;
        llist_node_t *result_node;
        Tcl_Obj *result_list_obj;
    
        if (policy == NULL) {
                Tcl_SetResult (interp, "No current policy file is opened!",
                               TCL_STATIC);
                return TCL_ERROR;
        }
        if (policy->pmap == NULL) {
                Tcl_SetResult (interp, "No permission map loaded!",TCL_STATIC);
                return TCL_ERROR;
        }	
        if (objc < 2 || objc > 3) {
                Tcl_SetResult (interp, "wrong # of args", TCL_STATIC);
                return TCL_ERROR;
        }
        assertion_contents = Tcl_GetString (objv [1]);
        if (objc == 3) {
                int abort_int;
                if (Tcl_GetBooleanFromObj (NULL, objv [2], &abort_int)
                    == TCL_OK && abort_int == 1) {
                        abort_after_first_conflict = TRUE;
                }
        }
        assertion_results = execute_flow_assertion (assertion_contents, policy,
                                                   abort_after_first_conflict);
        result_list_obj = Tcl_NewListObj (0, NULL);
        for (result_node = assertion_results->head; result_node != NULL;
             result_node = result_node->next) {
                flow_assert_results_t *results =
                        (flow_assert_results_t *) result_node->data;
                Tcl_Obj *result_obj, *result_elem_obj [4];
                int i;
                result_elem_obj [0] = Tcl_NewIntObj (results->mode);
                result_elem_obj [1] = Tcl_NewLongObj ((long) results->rule_lineno);
                result_elem_obj [2] = Tcl_NewIntObj (results->assert_result);
                result_elem_obj [3] = Tcl_NewListObj (0, NULL);
                for (i = 0; i < results->num_rules; i++) {
                        flow_assert_rule_t *assert_rule = results->rules + i;
                        Tcl_Obj *rule_elem_obj [4], *rule_obj;
                        int j;
                        rule_elem_obj [0] = Tcl_NewIntObj (assert_rule->start_type);
                        rule_elem_obj [1] = Tcl_NewIntObj (assert_rule->end_type);
                        rule_elem_obj [2] = Tcl_NewIntObj (assert_rule->via_type);
                        rule_elem_obj [3] = Tcl_NewListObj (0, NULL);
                        for (j = 0; j < assert_rule->num_rules; j++) {
                                int rule_idx = assert_rule->rules [j];
                                char *rule = re_render_av_rule
                                        (FALSE, rule_idx, FALSE, policy);
                                Tcl_Obj *rule_list_elem_obj [2], *rule_list_obj;
                                rule_list_elem_obj [0] = Tcl_NewIntObj
                                        (get_rule_lineno (rule_idx, RULE_TE_ALLOW, policy));
                                rule_list_elem_obj [1] = Tcl_NewStringObj (rule, -1);
                                free (rule);
                                rule_list_obj = Tcl_NewListObj (2, rule_list_elem_obj);
                                if (Tcl_ListObjAppendElement (interp, rule_elem_obj [3], rule_list_obj) != TCL_OK) {
                                        ll_free (assertion_results, flow_assert_results_destroy);
                                        return TCL_ERROR;
                                }
                        }
                        rule_obj = Tcl_NewListObj (4, rule_elem_obj);
                        if (Tcl_ListObjAppendElement (interp, result_elem_obj [3], rule_obj)
                            != TCL_OK) {
                                ll_free (assertion_results, flow_assert_results_destroy);
                                return TCL_ERROR;
                        }
                }
                result_obj = Tcl_NewListObj (4, result_elem_obj);
                if (Tcl_ListObjAppendElement (NULL, result_list_obj,result_obj)
                    != TCL_OK) {
                        Tcl_SetResult (interp, "Out of memory", TCL_STATIC);
                        ll_free (assertion_results, flow_assert_results_destroy);
                        return TCL_ERROR;
                }
        }
        ll_free (assertion_results, flow_assert_results_destroy);
        Tcl_SetObjResult (interp, result_list_obj);
        return TCL_OK;
}

/* Generates and returns the actual results list structure for a file
   relabeling to or relabeling from query. */
static Tcl_Obj *apol_relabel_fromto_results(ap_relabel_result_t *results, int start_type, 
						policy_t *policy, bool_t do_filter, 
						int *filter_types, int num_filter_types) 
{
        Tcl_Obj *results_list_obj = Tcl_NewListObj (0, NULL);
        int i, j, k, x, rule_idx;
        Tcl_Obj *end_types_list[2];	/* Holds the end type string, (to|from|both) and a list of subject info */
        Tcl_Obj *end_type_elem;
	Tcl_Obj *obj_list[2];
	Tcl_Obj *obj_elem;
	Tcl_Obj *subj_list[3];
	Tcl_Obj *subj_elem;
	Tcl_Obj *rule_list[2];
	Tcl_Obj *rule_elem;
	char *str;
	       
        assert(results != NULL);
    
        for (i = 0; i < results->num_targets; i++) {
		if (do_filter && (find_int_in_array(results->targets[i].target_type, filter_types, num_filter_types) < 0)) 
			continue;
        	/* Append the end type */
                if (get_type_name(results->targets[i].target_type, &str, policy)) {
                	fprintf(stderr, "Could not get name for end type from policy.\n");
                        return NULL;
                }
                end_types_list[0] = Tcl_NewStringObj(str, -1); /* end type string */
                free(str);      
                end_types_list[1] = Tcl_NewListObj(0, NULL);   /* List of objects */

                for (j = 0; j < results->targets[i].num_objects; j++) {
			if (get_obj_class_name(results->targets[i].objects[j].object_class, &str, policy)) {
	                	fprintf(stderr, "Could not get name for object class from policy.\n");
        	                return NULL;
			}
			obj_list[0] = Tcl_NewStringObj(str, -1); /* object class string */
			free(str);
			obj_list[1] = Tcl_NewListObj(0, NULL); /* list of subjects */

			for (k = 0; k < results->targets[i].objects[j].num_subjects; k++) {
				switch (results->targets[i].objects[j].subjects[k].direction & (~AP_RELABEL_DIR_START)) {
				case AP_RELABEL_DIR_TO:
					subj_list[0] = Tcl_NewStringObj("to", -1);
					break;
				case AP_RELABEL_DIR_FROM:
					subj_list[0] = Tcl_NewStringObj("from", -1);
					break;
				case AP_RELABEL_DIR_BOTH:
					subj_list[0] = Tcl_NewStringObj("both", -1);
					break;
				default:
					fprintf(stderr, "Invalid direction.\n");
					return NULL;
				}
		                if (get_type_name(results->targets[i].objects[j].subjects[k].source_type, &str, policy)) {
                			fprintf(stderr, "Could not get name for source type from policy.\n");
                        		return NULL;
				}
				subj_list[1] = Tcl_NewStringObj(str, -1);
				free(str);
				subj_list[2] = Tcl_NewListObj(0, NULL);

				for (x = 0; x < results->targets[i].objects[j].subjects[k].num_rules; x++) {
					/* check that rule is either the correct direction or a starting point*/
					if (!((results->targets[i].objects[j].subjects[k].rules[x].direction & 
						results->requested_direction) || (AP_RELABEL_DIR_START &
						results->targets[i].objects[j].subjects[k].rules[x].direction) ))
						continue;

					rule_idx = results->targets[i].objects[j].subjects[k].rules[x].rule_index;
					rule_list[0] = Tcl_NewIntObj(get_rule_lineno(rule_idx, RULE_TE_ALLOW, policy));
					str = re_render_av_rule(FALSE, rule_idx, 0, policy);	
					if (str == NULL) {
						fprintf(stderr, "Error rendering rule.\n");
						return NULL;
					}
					rule_list[1] = Tcl_NewStringObj(str, -1);
					free(str);
					rule_elem = Tcl_NewListObj(2, rule_list);
					if (Tcl_ListObjAppendElement(NULL, subj_list[2], rule_elem)) {
			        		fprintf(stderr, "Tcl error while appending element to list.\n");
			                	return NULL;
					}
				}

				subj_elem = Tcl_NewListObj(3, subj_list);
				if (Tcl_ListObjAppendElement(NULL, obj_list[1], subj_elem)) {
			        	fprintf(stderr, "Tcl error while appending element to list.\n");
			                return NULL;
				}
			}

			obj_elem = Tcl_NewListObj(2, obj_list);
			if (Tcl_ListObjAppendElement(NULL, end_types_list[1], obj_elem)) {
		        	fprintf(stderr, "Tcl error while appending element to list.\n");
		                return NULL;
			}
		}

                end_type_elem = Tcl_NewListObj (2, end_types_list);
	        if (Tcl_ListObjAppendElement(NULL, results_list_obj, end_type_elem)) {
	        	fprintf(stderr, "Tcl error while appending element to list.\n");
	                return NULL;
	        }
        }
        
        return results_list_obj;
}

/* Generates and returns the actual results list structure for a file
   domain relabeling query. */
static Tcl_Obj *apol_relabel_domain_results(ap_relabel_result_t *results, int start_type, policy_t *policy,
					    bool_t do_filter, int *filter_types, int num_filter_types) {
        Tcl_Obj *results_list_obj;
        Tcl_Obj *results_list[2], *results_list_ptr;
        Tcl_Obj *item_list[2], *item_elem;
        Tcl_Obj *rule_list[2], *rule_elem;
        char *str;
        int i, j, k, type_idx;
	
	assert(results != NULL && policy != NULL);
        if (results->num_targets == 0) {
                /* no results from domain relabel analysis */
                return Tcl_NewListObj (0, NULL);
        }
        results_list[0] = Tcl_NewListObj(0, NULL);	/* FROM list */
        assert(results_list[0]);
        results_list[1] = Tcl_NewListObj(0, NULL);	/* TO list */
        assert(results_list[1]);
        
        for (i = 0; i < results->num_targets; i++) {
		results_list_ptr = results_list[0];
		if (!(results->targets[i].direction & AP_RELABEL_DIR_FROM))
			continue;
		type_idx = results->targets[i].target_type;
	        if (do_filter && (find_int_in_array(type_idx, filter_types, num_filter_types) < 0)) 
			continue;
	        if (get_type_name(type_idx, &str, policy)) {
	        	fprintf(stderr, "Could not get name for end type from policy.\n");
                        return NULL;
                }
	        item_list[0] = Tcl_NewStringObj(str, -1);	/* end_type */
	        assert(item_list[0]);
                free (str);
                item_list[1] = Tcl_NewListObj(0, NULL);		/* Rule list */
                assert(item_list[1]);
		for (j = 0; j < results->targets[i].num_objects; j++) {
			for (k  = 0; k < results->targets[i].objects[j].subjects[0].num_rules; k++) {
				if (!(AP_RELABEL_DIR_FROM & results->targets[i].objects[j].subjects[0].rules[k].direction))
					continue;
	        	        rule_list[0] = Tcl_NewIntObj(get_rule_lineno(results->targets[i].objects[j].subjects[0].rules[k].rule_index,
										 RULE_TE_ALLOW, policy));
	                	assert(rule_list[0]);
	                	str = re_render_av_rule(FALSE, results->targets[i].objects[j].subjects[0].rules[k].rule_index, 
							FALSE, policy);
	        	        if (str == NULL) 
					return NULL;
				/* Rule string */
	                	rule_list[1] = Tcl_NewStringObj(str, -1);
	                	assert(rule_list[1]);
	                	free (str);
	   		
	   			rule_elem = Tcl_NewListObj(2, rule_list);
	        		assert(rule_elem);
	                	if (Tcl_ListObjAppendElement(NULL, item_list[1], rule_elem)) {
	                		fprintf(stderr, "Tcl error while appending element to list.\n");
	                        	return NULL;
				}

			}
		}
	        item_elem = Tcl_NewListObj(2, item_list);
	        assert(item_elem);
	        if (Tcl_ListObjAppendElement(NULL, results_list_ptr, item_elem)) {
                	fprintf(stderr, "Tcl error while appending element to list.\n");
                        return NULL;
                }
                /* TCL list should look like { end_type1 rule_list end_type2 rule_list ... } */
	}
	/* repeat of above for to list*/        
        for (i = 0; i < results->num_targets; i++) {
		results_list_ptr = results_list[1];
		if (!(results->targets[i].direction & AP_RELABEL_DIR_TO))
			continue;
		type_idx = results->targets[i].target_type;
	        if (do_filter && (find_int_in_array(type_idx, filter_types, num_filter_types) < 0)) 
			continue;
	        if (get_type_name(type_idx, &str, policy)) {
	        	fprintf(stderr, "Could not get name for end type from policy.\n");
                        return NULL;
                }
	        item_list[0] = Tcl_NewStringObj(str, -1);	/* end_type */
	        assert(item_list[0]);
                free (str);
                item_list[1] = Tcl_NewListObj(0, NULL);		/* Rule list */
                assert(item_list[1]);
		for (j = 0; j < results->targets[i].num_objects; j++) {
			for (k  = 0; k < results->targets[i].objects[j].subjects[0].num_rules; k++) {
				if (!(AP_RELABEL_DIR_TO & results->targets[i].objects[j].subjects[0].rules[k].direction))
					continue;
	                	rule_list[0] = Tcl_NewIntObj(get_rule_lineno(results->targets[i].objects[j].subjects[0].rules[k].rule_index,
										 RULE_TE_ALLOW, policy));
	                	assert(rule_list[0]);
	                	str = re_render_av_rule(FALSE, results->targets[i].objects[j].subjects[0].rules[k].rule_index, 
							FALSE, policy);
	                	if (str == NULL) 
					return NULL;
				/* Rule string */
	                	rule_list[1] = Tcl_NewStringObj(str, -1);
	                	assert(rule_list[1]);
	                	free (str);
	   		
	   			rule_elem = Tcl_NewListObj(2, rule_list);
	        		assert(rule_elem);
	                	if (Tcl_ListObjAppendElement(NULL, item_list[1], rule_elem)) {
	                		fprintf(stderr, "Tcl error while appending element to list.\n");
	                        	return NULL;
				}
			}
		}
	        item_elem = Tcl_NewListObj(2, item_list);
	        assert(item_elem);
	        if (Tcl_ListObjAppendElement(NULL, results_list_ptr, item_elem)) {
                	fprintf(stderr, "Tcl error while appending element to list.\n");
                        return NULL;
                }
                /* TCL list should look like { end_type1 rule_list end_type2 rule_list ... } */
	}


        results_list_obj = Tcl_NewListObj(2, results_list);	/* Return TCL list of 2 elements { from_list to_list } */
        assert(results_list_obj);
        
        return results_list_obj;
}

/* File Relabeling Analysis Tcl<->C interface
 * objv [1] = starting type (string)
 * objv [2] = mode ("to", "from", "both", "subject")
 * objv [3] = list of object class permissions - This list is in the form...
 * objv [4] = boolean vaiue indicating whether to filter end/start types by regex
 * objv [5] = endtype regex	
 *
 * Returns a list of results.  For relabelto / relabelfrom each result
 * is a 3-ple; for domains each is a 4-ple.
 *
 * For relabelto / relabelfrom:
 *   - domain type
 *   - list of domains it can relabelto/from
 *   - list of rules for that domain type
 *
 * For domain relabeling:
 *   - domain type
 *   - list of domains it can relabel from
 *   - list of domains it can relabel to
 *   - list of rules that relabel
 *
 # Each rule is a 2-ple of the form {rule_text rule_num}
 */
int Apol_RelabelAnalysis (ClientData clientData, Tcl_Interp *interp,
                          int objc, Tcl_Obj * CONST objv[]) {
	unsigned char mode;
	unsigned char direction;
	ap_relabel_result_t results;
	char *mode_string, *end_type = NULL, *err; 
	int start_type, do_filter_types;
	Tcl_Obj *results_list_obj; 
	regex_t reg;
	int *filter_types = NULL, rt, sz, num_filter_types, i;
	CONST84 char **class_filter_names, **subj_filter_names;
	int class_filter_sz = 0, subj_filter_sz  = 0;
	int *class_filter = NULL, *subj_filter = NULL;
	                
        if (policy == NULL) {
                Tcl_SetResult (interp, "No current policy file is opened!",
                               TCL_STATIC);
                return TCL_ERROR;
        }
        if (objc < 7) {
                Tcl_SetResult (interp, "wrong # of args", TCL_STATIC);
                return TCL_ERROR;
        }
        
        start_type = get_type_idx (Tcl_GetString (objv [1]), policy);
        if (!is_valid_type (policy, start_type, 0)) {
                Tcl_SetResult (interp, "Invalid starting type name", TCL_STATIC);
                return TCL_ERROR;
        }
        mode_string = Tcl_GetString (objv [2]);
    
        if (strcmp (mode_string, "to") == 0) {
                mode = AP_RELABEL_MODE_OBJ;
		direction = AP_RELABEL_DIR_TO;
        } else if (strcmp (mode_string, "from") == 0) {
                mode = AP_RELABEL_MODE_OBJ;
		direction = AP_RELABEL_DIR_FROM;
        } else if (strcmp (mode_string, "subject") == 0) {
                mode = AP_RELABEL_MODE_SUBJ;
		direction = AP_RELABEL_DIR_BOTH;
        } else if (strcmp (mode_string, "both") == 0) {
                mode = AP_RELABEL_MODE_OBJ;
		direction = AP_RELABEL_DIR_BOTH;
        } else {
                Tcl_SetResult (interp, "Invalid relabel mode", TCL_STATIC);
                return TCL_ERROR;
        }

	rt = Tcl_SplitList(interp, Tcl_GetString(objv[3]), &class_filter_sz, &class_filter_names);
	if (rt != TCL_OK) {
		Tcl_SetResult(interp, "Error splitting TCL list.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (class_filter_sz > 0) {
		class_filter = (int*)malloc(class_filter_sz * sizeof(int));
		for (i = 0; i < class_filter_sz; i++) {
			class_filter[i] = get_obj_class_idx(class_filter_names[i], policy);
		}
	}

	rt = Tcl_SplitList(interp, Tcl_GetString(objv[4]), &subj_filter_sz, &subj_filter_names);
	if (rt != TCL_OK) {
		Tcl_SetResult(interp, "Error splitting TCL list.", TCL_STATIC);
		return TCL_ERROR;
	}
	if (subj_filter_sz > 0) {
		subj_filter = (int*)malloc(subj_filter_sz * sizeof(int));
		for (i = 0; i < subj_filter_sz; i++) {
			subj_filter[i] = get_type_idx(subj_filter_names[i], policy);
		}
	}

        if (Tcl_GetIntFromObj(interp, objv[5], &do_filter_types) != TCL_OK) {
        	 Tcl_SetResult (interp, "Error while geting integer from TCL object.", TCL_STATIC);
	         return TCL_ERROR;
	}
	end_type = Tcl_GetString(objv[6]);
        if (do_filter_types) {
        	if (str_is_only_white_space(end_type)) {
			Tcl_SetResult (interp, "Please provide a regular expression for filtering the end types.", TCL_STATIC);
			return TCL_ERROR;
		}
	   	trim_trailing_whitespace(&end_type);
		rt = regcomp(&reg, end_type, REG_EXTENDED|REG_NOSUB);
		if (rt != 0) {
			sz = regerror(rt, &reg, NULL, 0);
			if ((err = (char *)malloc(++sz)) == NULL) {
				Tcl_SetResult (interp, "Out of memory.", TCL_STATIC);
				return TCL_ERROR;
			}
			regerror(rt, &reg, err, sz);
			regfree(&reg);
			Tcl_Obj *tcl_err = Tcl_NewStringObj(err, -1);
			assert(tcl_err);
			Tcl_SetObjResult(interp, tcl_err);
			free(err);
			return TCL_ERROR;
		}
		rt = get_type_idxs_by_regex(&filter_types, &num_filter_types, &reg, FALSE, policy);
		if (rt < 0) {
			Tcl_SetResult (interp, "Error searching types\n", TCL_STATIC);
			return TCL_ERROR;
		}
	}

        /* Get the results of our query */
        if (ap_relabel_query (start_type, mode, direction, 
				subj_filter, subj_filter_sz, 
				class_filter, class_filter_sz, 
				&results, policy)) {
                free(filter_types);
		free(subj_filter);
		free(class_filter);
                ap_relabel_result_destroy (&results);
                Tcl_SetResult (interp, "Error doing analysis", TCL_STATIC);
                return TCL_ERROR;
        }
        
        switch (mode) {
        case AP_RELABEL_MODE_OBJ: {
                results_list_obj = apol_relabel_fromto_results(&results, start_type, policy, 
                						do_filter_types, filter_types, 
                						num_filter_types);
                break;
        }
        default: {
                results_list_obj = apol_relabel_domain_results(&results, start_type, policy, 
								do_filter_types, filter_types, 
								num_filter_types);
                break;
        }
        }
        free(filter_types);
       	free(subj_filter);
	free(class_filter); 
	ap_relabel_result_destroy (&results);
        if (results_list_obj == NULL) {
                Tcl_SetResult (interp, "Error processing relabeling results", TCL_STATIC);
                return TCL_ERROR;
        }
        Tcl_SetObjResult (interp, results_list_obj);
        return TCL_OK;
}


/* Package initialization */
int Apol_Init(Tcl_Interp *interp) 
{
	Tcl_CreateCommand(interp, "apol_GetScriptDir", (Tcl_CmdProc *) Apol_GetScriptDir, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_OpenPolicy", (Tcl_CmdProc *) Apol_OpenPolicy, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_ClosePolicy", (Tcl_CmdProc *) Apol_ClosePolicy, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetVersion", (Tcl_CmdProc *) Apol_GetVersion, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetNames", (Tcl_CmdProc *) Apol_GetNames, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetStats", (Tcl_CmdProc *) Apol_GetStats, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetSingleTypeInfo", (Tcl_CmdProc *) Apol_GetSingleTypeInfo, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetTypeInfo", (Tcl_CmdProc *) Apol_GetTypeInfo, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
/* Apol_GetTErules not supported, use Apol_SearchTErules */
	Tcl_CreateCommand(interp, "apol_GetTErules", (Tcl_CmdProc *) Apol_GetTErules, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_SearchTErules", (Tcl_CmdProc *) Apol_SearchTErules, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetSingleRoleInfo", (Tcl_CmdProc *) Apol_GetSingleRoleInfo, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetRolesByType", (Tcl_CmdProc *) Apol_GetRolesByType, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetRoleRules", (Tcl_CmdProc *) Apol_GetRoleRules, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_RoleTypes", (Tcl_CmdProc *) Apol_RoleTypes, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_UserRoles", (Tcl_CmdProc *) Apol_UserRoles, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetUsersByRole", (Tcl_CmdProc *) Apol_GetUsersByRole, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionString", (Tcl_CmdProc *) Apol_GetPolicyVersionString, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionNumber", (Tcl_CmdProc *) Apol_GetPolicyVersionNumber, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyContents", (Tcl_CmdProc *) Apol_GetPolicyContents, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPermsByClass", (Tcl_CmdProc *) Apol_GetPermsByClass, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetClassPermInfo", (Tcl_CmdProc *) Apol_GetClassPermInfo, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateObjCommand(interp, "apol_GetClassPermList", (Tcl_ObjCmdProc *) Apol_GetClassPermList, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetSingleClassPermInfo", (Tcl_CmdProc *) Apol_GetSingleClassPermInfo, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_DomainTransitionAnalysis", (Tcl_CmdProc *) Apol_DomainTransitionAnalysis, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetAttribTypesList", (Tcl_CmdProc *) Apol_GetAttribTypesList, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetClassCommonPerm", (Tcl_CmdProc *) Apol_GetClassCommonPerm, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_DirectInformationFlowAnalysis", (Tcl_CmdProc *) Apol_DirectInformationFlowAnalysis, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_LoadPermMap", (Tcl_CmdProc *) Apol_LoadPermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_SavePermMap", (Tcl_CmdProc *) Apol_SavePermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_UpdatePermMap", (Tcl_CmdProc *) Apol_UpdatePermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPermMap", (Tcl_CmdProc *) Apol_GetPermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_IsPermMapLoaded", (Tcl_CmdProc *) Apol_IsPermMapLoaded, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_IsLibsefs_BuiltIn", (Tcl_CmdProc *) Apol_IsLibsefs_BuiltIn, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetDefault_PermMap", (Tcl_CmdProc *) Apol_GetDefault_PermMap, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFlowAnalysis", (Tcl_CmdProc *) Apol_TransitiveFlowAnalysis, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFindPathsStart", (Tcl_CmdProc *) Apol_TransitiveFindPathsStart, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFindPathsNext", (Tcl_CmdProc *) Apol_TransitiveFindPathsNext, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFindPathsGetResults", (Tcl_CmdProc *) Apol_TransitiveFindPathsGetResults, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_TransitiveFindPathsAbort", (Tcl_CmdProc *) Apol_TransitiveFindPathsAbort, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_SearchInitialSIDs", (Tcl_CmdProc *) Apol_SearchInitialSIDs, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetInitialSIDInfo", (Tcl_CmdProc *) Apol_GetInitialSIDInfo, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_Cond_Bool_SetBoolValue", (Tcl_CmdProc *) Apol_Cond_Bool_SetBoolValue, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_Cond_Bool_GetBoolValue", (Tcl_CmdProc *) Apol_Cond_Bool_GetBoolValue, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_SearchConditionalRules", (Tcl_CmdProc *) Apol_SearchConditionalRules, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_GetPolicyType", (Tcl_CmdProc *) Apol_GetPolicyType, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_TypesRelationshipAnalysis", (Tcl_CmdProc *) Apol_TypesRelationshipAnalysis, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	
	Tcl_CreateCommand(interp, "apol_Close_FC_Index_DB", (Tcl_CmdProc *) Apol_Close_FC_Index_DB, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_Create_FC_Index_File", (Tcl_CmdProc *) Apol_Create_FC_Index_File, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_Load_FC_Index_File", (Tcl_CmdProc *) Apol_Load_FC_Index_File, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_Search_FC_Index_DB", (Tcl_CmdProc *) Apol_Search_FC_Index_DB, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "apol_FC_Index_DB_Get_Items", (Tcl_CmdProc *) Apol_FC_Index_DB_Get_Items, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateObjCommand(interp, "apol_FlowAssertExecute", (Tcl_ObjCmdProc *) Apol_FlowAssertExecute, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);	
	Tcl_CreateObjCommand(interp, "apol_RelabelAnalysis", (Tcl_ObjCmdProc *) Apol_RelabelAnalysis, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);	
	Tcl_PkgProvide(interp, "apol", (char*)libapol_get_version());

	return TCL_OK;
}
