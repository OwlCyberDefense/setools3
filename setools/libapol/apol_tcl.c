/* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
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
#include "perm-map.h"
#include "policy-query.h"

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
 * argv[7] - encoded list of object class/permissions to include in the query
 * argv[8] - flag (boolean value) for indicating whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
 *
 * NOTE: THIS FUNCTION EXPECTS PERMISSION MAPPINGS TO BE LOADED!! If, not it will throw an error.
 *
 */
static iflow_query_t* set_transitive_query_args(Tcl_Interp *interp, char *argv[])
{
	int num_objs, num_obj_perms, num_objs_options, num_inter_types, obj, type, perm, *types;
	int i, j, rt, num, cur, sz = 0;
	char *start_type = NULL, *end_type = NULL;
	char *err, *name;
	CONST84 char **obj_class_perms, **inter_types;
	char tbuf[64];
	bool_t filter_obj_classes, filter_end_types, filter_inter_types;
	regex_t reg;
	iflow_query_t* iflow_query = NULL;
	
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
			Tcl_Free((char *) obj_class_perms);
			return NULL;
		}
		
		if(num_objs_options < 1) {
			Tcl_AppendResult(interp, "Must provide object class permissions.", (char *) NULL);
			Tcl_Free((char *) obj_class_perms);
			return NULL;
		}
	}
	
	if(filter_end_types) {
		sz = strlen(argv[6]) + 1;
 	        end_type = (char *)malloc(sz);
	        if(end_type == NULL) {
		      fprintf(stderr, "out of memory");
		      return NULL;
		}	
		end_type = strcpy(end_type, argv[6]);
		if(end_type == NULL || str_is_only_white_space(end_type)) {
			Tcl_AppendResult(interp, "Please provide a regular expression for filtering the end types.", (char *) NULL);
			return NULL;
		}
		if(!is_valid_str_sz(end_type)) {
			Tcl_AppendResult(interp, "The provided end type filter string is too large.", (char *) NULL);
			return NULL;
		}	
	}
	if (filter_inter_types) {
		/* First, disassemble TCL intermediate types list, returning an array of pointers to the elements. */
		rt = Tcl_SplitList(interp, argv[9], &num_inter_types, &inter_types);
		if(rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			Tcl_Free((char *) inter_types);
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

	/* Set the start type for our query */ 					
	iflow_query->start_type = get_type_idx(start_type, policy);
	if (iflow_query->start_type < 0) {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "Invalid starting type ", start_type, (char *) NULL);
		return NULL;
	}
		
	if(filter_obj_classes && obj_class_perms != NULL) {
		int total_num_perms;
		assert(num_objs > 0);
		cur = 0;
		/* Set the object classes permission info */
		/* Keep in mind that this is an encoded TCL list in the form "class1 num_perms perm1 ... permN ... classN num_perms perm1 ... permN" */
		for (i = 0; i < num_objs; i++) {
			obj = get_obj_class_idx(obj_class_perms[cur], policy);
			if (obj < 0) {
				Tcl_AppendResult(interp, "Invalid object class:\n", obj_class_perms[cur], (char *) NULL);
				Tcl_Free((char *) obj_class_perms);
				iflow_query_destroy(iflow_query);
				return NULL;
			}
			/* Increment to next element, which should be the number of permissions for the class */
			cur++;
			rt = Tcl_GetInt(interp, obj_class_perms[cur], &num_obj_perms);
			if(rt == TCL_ERROR) {
				Tcl_AppendResult(interp, "Item in obj_class_perms list apparently is not an integer\n", (char *) NULL);
				return NULL;
			}
			total_num_perms = get_num_perms_for_obj_class(obj, policy);
			if (!total_num_perms) {
				Tcl_AppendResult(interp, "Object class without any permissions!\n", (char *) NULL);
				return NULL;
			}

			if (num_obj_perms == 0) {
				if (iflow_query_add_obj_class(iflow_query, obj) == -1) {
					Tcl_AppendResult(interp, "error adding obj\n", (char *) NULL);
					return NULL;
				}
			} else if (num_obj_perms != total_num_perms) {
				bool_t *perms_used = (bool_t*)malloc(sizeof(bool_t) * policy->num_perms);
				if (!perms_used) {
					Tcl_AppendResult(interp, "Memory error\n", (char *) NULL);
					return NULL;
				}
				memset(perms_used, FALSE, sizeof(bool_t) * policy->num_perms);

				for (j = 0; j < num_obj_perms; j++) {
					cur++;
					perm = get_perm_idx(obj_class_perms[cur], policy);
					if (perm < 0 || !is_valid_perm_for_obj_class(policy, obj, perm)) {
						fprintf(stderr, "Invalid object class permission\n");
						continue;
					}
					perms_used[perm] = TRUE;
				}
				for (j = 0; j < policy->num_perms; j++) {
					if (perms_used[j] || !is_valid_perm_for_obj_class(policy, obj, j)) {
						continue;
					}
					if (iflow_query_add_obj_class_perm(iflow_query, obj, j) == -1) {
						Tcl_AppendResult(interp, "error adding perm\n", (char *) NULL);
						return NULL;
					}
				}
				free(perms_used);
			} else {
				cur += num_obj_perms;
			}
			cur++;
		}
		Tcl_Free((char *) obj_class_perms);
	}

	/* filter ending type(s) */
	if(filter_end_types) {	
		fix_string(end_type, sz);
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
		if(iflow_query->num_end_types == 0) {
			iflow_query_destroy(iflow_query);
			Tcl_AppendResult(interp, "No end type matches found for the regular expression you specified!", (char *) NULL);
			return NULL;
		}			
	}
	if (filter_inter_types) {
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
					append_perm_str(0, 0, 1, i, buf, policy);
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
		sprintf(tbuf, " (%d types)\n", policy->attribs[idx].num_types);
		Tcl_DStringAppend(buf, tbuf, -1);
		for(j = 0; j < policy->attribs[idx].num_types; j++) {
			Tcl_DStringAppend(buf, "\t", -1);
			Tcl_DStringAppend(buf, policy->types[policy->attribs[idx].types[j]].name, -1);
			/* aliases */
			if(use_aliases && policy->types[policy->attribs[idx].types[j]].aliases != NULL) {
				name_item_t *ptr;
				Tcl_DStringAppend(buf, ":", -1);
				for(ptr = policy->types[policy->attribs[idx].types[j]].aliases; ptr != NULL; ptr = ptr->next) {
					Tcl_DStringAppend(buf, " ", -1);
					Tcl_DStringAppend(buf, ptr->name, -1);
					if(ptr->next != NULL)
						Tcl_DStringAppend(buf, ",", -1);
				}
			}			
			if(do_type_attribs) {
				Tcl_DStringAppend(buf, " { ", -1);
				for(k = 0; k < policy->types[policy->attribs[idx].types[j]].num_attribs; k++) {
					if(strcmp(policy->attribs[idx].name, policy->attribs[policy->types[policy->attribs[idx].types[j]].attribs[k]].name) != 0)
						Tcl_DStringAppend(buf, policy->attribs[policy->types[policy->attribs[idx].types[j]].attribs[k]].name, -1);
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


/* searches using regular expressions */
static int append_all_ta_using_regex(regex_t *preg, const char *regexp, bool_t do_types, bool_t do_attribs, bool_t use_aliases,
			bool_t type_attribs, bool_t attrib_types, bool_t attrib_type_attribs, policy_t *policy,
			Tcl_DString *buf)
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
		for(i = 0; i < policy->num_types; i++) {
			rt = regexec(preg, policy->types[i].name, 0, NULL, 0);
			if(rt == 0) {
				rt = append_type_str(type_attribs, use_aliases, 1, i, policy, buf);
				if(rt != 0) {
					return -1;
				}
			}
			else if(use_aliases) {
				name_item_t *ptr;
				for(ptr = policy->types[i].aliases; ptr != NULL; ptr = ptr->next) {
					rt = regexec(preg, ptr->name, 0, NULL, 0);
					if(rt == 0) {
						rt = append_type_str(type_attribs, use_aliases, 1, i, policy, buf);
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

static int append_user_str(user_item_t *user, bool_t name_only,  policy_t *policy, Tcl_DString *buf)
{
	char *name;
	ta_item_t *ptr;
	int rt;
		
	if(user == NULL || buf == NULL || policy == NULL)
		return -1;
	
	Tcl_DStringAppend(buf, user->name, -1);
	if(!name_only) {
		Tcl_DStringAppend(buf, " { ", -1);
		for(ptr = user->roles; ptr != NULL; ptr = ptr->next) {
			assert(ptr->type == IDX_ROLE);
			rt = get_role_name(ptr->idx, &name, policy);
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
	char *rule, tbuf[64];
	
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
	char tbuf[64], *rule;
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
	char tbuf[64];
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

static int append_transitive_iflows_to_results(policy_t *policy, iflow_transitive_t* answers, iflow_path_t *cur, Tcl_Interp *interp)
{
	char tbuf[64];
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
	char tbuf[64];
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

static int append_transitive_iflow_results(policy_t *policy, iflow_transitive_t* answers, Tcl_Interp *interp)
{
	char tbuf[64];
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
	else if(m_ret & PERMMAP_RET_WARNINGS) {
		fprintf(stdout, "There were warnings:\n");
		if(m_ret & PERMMAP_RET_UNMAPPED_PERM) 
			fprintf(stdout, "     Some permissions were unmapped.\n");
		if(m_ret & PERMMAP_RET_UNMAPPED_OBJ)
			fprintf(stdout, "     Some objects were unmapped.\n");
		if(m_ret & PERMMAP_RET_UNKNOWN_PERM)
			fprintf(stdout, "     Map contains unknown permissions, or permission assoicated with wrong objects.\n");
		if(m_ret & PERMMAP_RET_UNKNOWN_OBJ)
			fprintf(stdout, "     Map contains unknown objects\n");
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
		sprintf(tmpbuf, " (%d types)\n     ", policy->roles[idx].num_types);
		Tcl_DStringAppend(buf, tmpbuf, -1);
		for(j = 0; j < policy->roles[idx].num_types; j++) {
			/* control # of types per line */
			if(j != 0) {
				x = div(j, numperline);
				if(x.rem == 0) {
					sprintf(tmpbuf, "\n     ");
					Tcl_DStringAppend(buf, tmpbuf, -1);
				}
			}
			sprintf(tmpbuf, "%s  ", policy->types[policy->roles[idx].types[j]].name);
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

/* open a policy.conf file */
int Apol_OpenPolicy(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char tbuf[APOL_STR_SZ+64];
	int rt;
	FILE* tmp;
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char*)NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "File name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	/* open_policy will actually open the file for reading - it is done here so that a
	 * descriptive error message can be returned if the file cannot be read.
	 */
	if((tmp = fopen(argv[1], "r")) == NULL) {
		Tcl_AppendResult(interp, "cannot open policy file ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}	
	fclose(tmp);
	free_policy(&policy);
	rt = open_policy(argv[1], &policy);
	if(rt != 0) {
		free_policy(&policy);
		sprintf(tbuf, "open_policy error (%d)", rt);
		Tcl_AppendResult(interp, tbuf, (char *) NULL);
		return TCL_ERROR;
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
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	switch (policy->version) {
	case POL_VER_PRE_11:
		Tcl_AppendResult(interp, POL_VER_STRING_PRE_11, (char *) NULL);
		break;
	case POL_VER_11:
	/* case POL_VER_12: */ /* (currently synonmous with v.11 */
		Tcl_AppendResult(interp, POL_VER_STRING_11, (char *) NULL);
		break;
	case POL_VER_15:
		Tcl_AppendResult(interp, POL_VER_STRING_15, (char *) NULL);
		break;
	case POL_VER_16:
		Tcl_AppendResult(interp, POL_VER_STRING_16, (char *) NULL);
		break;
	default:
		Tcl_AppendResult(interp, "Unkown version", (char *) NULL);
		break;
	}
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
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
	case POL_VER_16:
		Tcl_AppendResult(interp, "16", (char *) NULL);
		break;
#endif
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
	
	if(argc > 3) {
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
	/* user list is a linked list and not an array like the other lists */
	else if(strcmp("users", argv[1]) == 0) {
		user_item_t *ptr;
		for(ptr = policy->users.head; get_user_name(ptr, &name) == 0; ptr = ptr->next) {
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
	char tbuf[64];
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
			/* Append a boolean value indicating whether this rule is enabled 
			 * for conditional policy support */
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
			/* Append a boolean value indicating whether this rule is enabled 
			 * for conditional policy support */
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
			/* Append a boolean value indicating whether this rule is enabled 
			 * for conditional policy support */
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
	for(i = 0; i < policy->roles[idx].num_types; i++) {
		rt = get_type_name(policy->roles[idx].types[i], &name, policy);
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
	user_item_t *user;
	ta_item_t *ptr;
	int rt;
	
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
	rt = get_user_by_name(argv[1], &user, policy);
	if(rt != 0) {
		sprintf(tmpbuf, "Invalid user name (%s)", argv[1]);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;		
	}
	
	for(ptr = user->roles; ptr != NULL; ptr = ptr->next) {
		assert(ptr->type == IDX_ROLE);
		rt = get_role_name(ptr->idx, &name, policy);
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
	int rt, idx = -1;
	char tmpbuf[APOL_STR_SZ+64];
	bool_t name_only, use_role;
	Tcl_DString *buf, buffer;
	user_item_t *user;
	
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
	
	for(user = get_first_user_ptr(policy); user != NULL; user = get_next_user_ptr(user)) {
		if(!use_role || does_user_have_role(user, idx, policy)) {
			rt = append_user_str(user, name_only, policy, buf);
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
	
	if(init_rbac_bool(&src_b, policy) != 0) {
		Tcl_AppendResult(interp, "error initializing src rules bool", (char *) NULL);
		return TCL_ERROR;
	}
	if(init_rbac_bool(&tgt_b, policy) != 0) {
		Tcl_AppendResult(interp, "error initializing tgt rules bool", (char *) NULL);
		free_rbac_bool(&src_b);	
		return TCL_ERROR;
	}
	if(init_rbac_bool(&dflt_b, policy) != 0) {
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
	
	for(j = 0; j < policy->attribs[idx].num_types; j++) {
		Tcl_AppendElement(interp, policy->types[policy->attribs[idx].types[j]].name);
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
	
	return TCL_OK;
}

/* args ordering:
 * argv[1]	bool name
 */
int Apol_Cond_Bool_GetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int bool_val;
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
		
	bool_val = get_cond_bool_val(argv[1], policy);
	if (bool_val < 0) {
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
 */
int Apol_GetTypeInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int i, rt, sz;
	Tcl_DString *buf, buffer;
	char tmpbuf[APOL_STR_SZ+64], *err;
	regex_t reg;
	
	bool_t do_types, type_attribs, do_attribs, attrib_types, attrib_type_attribs, 
		use_aliases, use_srchstr;

	buf = &buffer;
	if(argc != 9) {
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
		
	Tcl_DStringInit(buf);	
	if(!use_srchstr) {	
		if(do_types) {
			sprintf(tmpbuf, "\n\nTYPES (%d):\n", policy->num_types);
			Tcl_DStringAppend(buf, tmpbuf, -1);
			for(i = 0; i < policy->num_types; i++) {
				rt = append_type_str(type_attribs, use_aliases, 1, i, policy, buf);
				if(rt != 0) {
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending types", (char *) NULL);
					return TCL_ERROR;
				}
			}
		}
		
		if(do_attribs) {
			sprintf(tmpbuf, "\n\nTYPE ATTRIBUTES (%d):\n", policy->num_attribs);
			Tcl_DStringAppend(buf, tmpbuf, -1);
			for(i = 0; i < policy->num_attribs; i++) {
				sprintf(tmpbuf, "%d: ", i+1);
				Tcl_DStringAppend(buf, tmpbuf, -1);
				rt = append_attrib_str(attrib_types, attrib_type_attribs, use_aliases, 1, 0, i,
					policy, buf);
				if(rt != 0){
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending attributes", (char *) NULL);
					return TCL_ERROR;
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
		rt = append_all_ta_using_regex(&reg, argv[8], do_types, do_attribs, use_aliases, type_attribs, attrib_types, attrib_type_attribs, policy, buf);
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

/* 
 * argv[1] - boolean value (0 for a forward DT analysis; otherwise, reverse DT analysis)
 * argv[2] - specified domain type used to start the analysis
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
	domain_trans_analysis_t *dta;
	int rt;
	bool_t reverse;
	char *source_type;
	
	if(argc == 2) {
		/* determine if requesting a reverse DT analysis */
		reverse = getbool("0");
		source_type = argv[1];
	} 
	else if(argc == 3) {
		/* determine if requesting a reverse DT analysis */
		reverse = getbool(argv[1]);
		source_type = argv[2];
	}
	else {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}	
	if(!is_valid_str_sz(source_type)) {
		Tcl_AppendResult(interp, "The provided domain type string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	
	/*perform the analysis */
	rt = determine_domain_trans(reverse, source_type, &dta, policy);
	if(rt == -2) {
		if (reverse) {
			Tcl_AppendResult(interp, "invalid target type name", (char *) NULL);
		} else {
			Tcl_AppendResult(interp, "invalid source type name", (char *) NULL);
		}
		return TCL_ERROR;
	}
	else if(rt < 0) {
		Tcl_AppendResult(interp, "error with domain transition anaysis", (char *) NULL);
		return TCL_ERROR;
	}
	
	/* format the result into a tcl list (yuk!) */
	{
	llist_node_t *x, *y;
	char *tmp, tbuf[64];
	int i;
	trans_domain_t *t;
	entrypoint_type_t *ep;
	/* source type */
	rt = get_type_name(dta->start_type, &tmp, policy);
	if(rt != 0) {
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "analysis error (looking up starting type name)", (char *) NULL);
		return TCL_ERROR;
	}
	Tcl_AppendElement(interp, tmp);
	free(tmp);
	/* # of target types */
	sprintf(tbuf, "%d", dta->trans_domains->num);
	Tcl_AppendElement(interp, tbuf);
	
	/* all target types */
	for(x = dta->trans_domains->head; x != NULL; x = x->next) {
		t = (trans_domain_t *)x->data;
		/* target type */
		assert(dta->start_type == t->start_type);
		rt = get_type_name(t->trans_type, &tmp, policy);
		if(rt != 0) {
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
		for(i = 0; i < t->num_pt_rules; i++) {
			tmp = re_render_av_rule(0,t->pt_rules[i], 0, policy);
			if(tmp == NULL) {
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
		for(y = t->entry_types->head; y != NULL; y = y->next) {
			ep = (entrypoint_type_t *)y->data;
			assert(t->trans_type == ep->trans_type);
			/* file type */
			rt = get_type_name(ep->file_type, &tmp, policy);
			if(rt != 0) {
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
			for(i = 0; i < ep->num_ep_rules; i++) {
				tmp = re_render_av_rule(0, ep->ep_rules[i], 0, policy);
				if(tmp == NULL) {
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
			for(i = 0; i < ep->num_ex_rules; i++) {
				tmp = re_render_av_rule(0,ep->ex_rules[i], 0, policy);
				if(tmp == NULL) {
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
	}
	
	} /* formal result block */
	
	free_domain_trans_analysis(dta);
	return TCL_OK;

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
	iflow_query_t* iflow_query = NULL;
	
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
			Tcl_Free((char *) obj_classes);
			return TCL_ERROR;
		}
		
		if(num_objs < 1) {
			Tcl_AppendResult(interp, "Must provide at least one object class.", (char *) NULL);
			Tcl_Free((char *) obj_classes);
			return TCL_ERROR;
		}
	}
	
	if(filter_end_types) {       
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
		if(!is_valid_str_sz(end_type)) {
			Tcl_AppendResult(interp, "The provided end type filter string is too large.", (char *) NULL);
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
		fix_string(end_type, sz);
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
		if(iflow_query->num_end_types == 0) {
			iflow_query_destroy(iflow_query);
			Tcl_AppendResult(interp, "No end type matches found for the regular expression you specified!", (char *) NULL);
			return TCL_ERROR;
		}			
	}

	/* Initialize iflow analysis structure, which holds the results of query */									
	if (iflow_direct_flows(policy, iflow_query, &num_answers, &answers) < 0) {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "There were errors in the information flow analysis\n", (char *) NULL);
		return TCL_ERROR;
	}

	/* Append the start type to our encoded TCL list */
	sprintf(tbuf, "%s", start_type);
	Tcl_AppendElement(interp, tbuf);

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
 * argv[7] - encoded list of object class/permissions to include in the query
 * argv[8] - flag (boolean value) for indicatinf whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
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
	
	if(argc != 10) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	iflow_query = set_transitive_query_args(interp, argv);
	if (iflow_query == NULL) {
		return TCL_ERROR;
	}	
	if ((answers = iflow_transitive_flows(policy, iflow_query)) == NULL) {
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "There were errors in the information flow analysis\n", (char *) NULL);
		return TCL_ERROR;
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
			
	rt = append_transitive_iflow_results(policy, answers, interp);
	if(rt != 0) {
		iflow_transitive_destroy(answers);
		iflow_query_destroy(iflow_query);
		Tcl_AppendResult(interp, "Error appending edge information!\n", (char *) NULL);
		return TCL_ERROR;
	}	
	iflow_transitive_destroy(answers);
	iflow_query_destroy(iflow_query);
	return TCL_OK;		
}

/* argv[1] - domain type used to start the analysis
 * argv[2] - flow direction - IN or OUT
 * argv[3] - flag (boolean value) for indicating that a list of object classes are being provided.
 * argv[4] - number of object classes that are to be included in the query.
 * argv[5] - flag (boolean value) for indicating that filter on end type(s) is being provided 
 * argv[6] - ending type regular expression 
 * argv[7] - encoded list of object class/permissions to include in the query
 * argv[8] - flag (boolean value) for indicating whether or not to include intermediate types in the query.
 * argv[9] - TCL list of intermediate types
 */
int Apol_TransitiveFindPathsStart(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{		
	iflow_query_t* iflow_query = NULL;
	
	if(argc != 10) {
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
	if((fp = fopen(pmap_file, "w")) == NULL) {
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
		} 
	} 	
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
	
	Tcl_PkgProvide(interp, "apol", (char*)libapol_get_version());

	return TCL_OK;
}
