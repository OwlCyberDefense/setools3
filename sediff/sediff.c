/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* sediff: command line tool semanitcally differentiating two policies.
 */
 
/* libapol */
#include "util.h"
#include "sediff_rename_types.h"
#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>
#include <poldiff.h>
#include <render.h>
#include <binpol/binpol.h>
/* other */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <limits.h>
#include <unistd.h>

/* The following should be defined in the make environment */
#ifndef SEDIFF_VERSION_NUM
	#define SEDIFF_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004,2005 Tresys Technology, LLC"
#define SEDIFF_GUI_PROG	"sediffx"

char *p1_file, *p2_file;

static int print_rtrans_diffs(FILE *fp, ap_single_rtrans_diff_t *diff, policy_t *p_old, policy_t *p_new);

static struct option const longopts[] =
{
  {"classes", no_argument, NULL, 'c'},
  {"types", no_argument, NULL, 't'},
  {"attributes", no_argument, NULL, 'a'},
  {"roles", no_argument, NULL, 'r'},
  {"users", no_argument, NULL, 'u'},
  {"booleans", no_argument, NULL, 'b'},
  {"initialsids", no_argument, NULL, 'i'},
  {"terules", no_argument, NULL, 'T'},
  {"roleallows", no_argument, NULL, 'A'},
  {"roletrans", no_argument, NULL, 'R'},
  {"conds", no_argument, NULL, 'C'},
  {"stats", no_argument, NULL, 's'},
  {"gui", no_argument, NULL, 'X'},
  {"quiet", no_argument, NULL, 'q'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};
 
void usage(const char *program_name, int brief)
{
	printf("%s (sediff ver. %s)\n\n", COPYRIGHT_INFO, SEDIFF_VERSION_NUM);
	printf("Usage: %s [OPTIONS] POLICY1 POLICY2\n", program_name);
	printf("Usage: %s -X [POLICY1 POLICY2]\n",program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n"
"Semantically differentiate two policies.  The policies can be either source\n"
"or binary policy files, version 15 or later.  By default, all supported\n"
"policy elements are examined.  The following diff options are available:\n"
"  -c, --classes    object class and permission definitions\n"
"  -t, --types      type definitions\n"
"  -a, --attributes attribute definitions\n"
"  -r, --roles      role definitions\n"
"  -u, --users      user definitions\n"
"  -b, --booleans   boolean definitions and default values\n"
"  -T, --terules    type enforcement rules\n"
"  -R, --roletrans   role transition rules\n"
"  -A, --roleallows  role allow rules\n"  
"  -C, --conds      conditionals and their rules\n\n"
"  -X, --gui        launch the sediff gtk gui\n"
"  -q, --quiet      only print different definitions\n"
"  -s, --stats      print useful policy statics\n"
"  -h, --help       display this help and exit\n"
"  -v, --version    output version information and exit\n\n"
, stdout);
	return;
}

static bool_t fn_is_binpol(const char *fn)
{
	FILE *fp;
	bool_t rt;
	
	if(fn == NULL)
		return FALSE;
	fp = fopen(fn, "r");
	if(fp == NULL)
		return FALSE;
	if(ap_is_file_binpol(fp)) 
		rt = TRUE;
	else
		rt = FALSE;
	fclose(fp);
	return rt;
}

static int fn_binpol_ver(const char *fn)
{
	FILE *fp;
	int rt;
	
	if(fn == NULL)
		return -1;
	fp = fopen(fn, "r");
	if(fp == NULL)
		return FALSE;
	if(!ap_is_file_binpol(fp)) 
		rt = -1;
	else 
		rt = ap_binpol_version(fp);
	fclose(fp);
	return rt;
}


const char *policy_type(policy_t *p)
{
	return(is_binary_policy(p) ? "binary" : "source");
}


static int print_diff_stats(FILE *fp, ap_single_view_diff_t *svd)
{
	if (fp == NULL || svd == NULL)
		return -1;
	fprintf(fp,"Total Differences:\n\tClasses %d \n\tCommon Permissions %d\n\tPermissions %d \n "
		"\tTypes %d \n\tAttributes %d \n\tRoles %d\n\tUsers %d  \n\tBooleans %d"
		" \n\tRole Allows %d\n\tRole Trans: %d\n\tTE Rules %d  \n\tConditionals %d  \n",
		svd->classes->num_add+svd->classes->num_rem+svd->classes->num_chg,
		svd->common_perms->num_add+svd->common_perms->num_rem+svd->common_perms->num_chg,
		svd->perms->num_add+svd->perms->num_rem,
		svd->types->num_add+svd->types->num_rem+svd->types->num_chg,
		svd->attribs->num_add+svd->attribs->num_rem+svd->attribs->num_chg+svd->attribs->num_chg_add+
		svd->attribs->num_chg_rem,
		svd->roles->num_add+svd->roles->num_rem+svd->roles->num_chg+svd->roles->num_chg_add+
		svd->roles->num_chg_rem,
		svd->users->num_add+svd->users->num_rem+svd->users->num_chg,
		svd->bools->num_add+svd->bools->num_rem+svd->bools->num_chg,
		svd->rallows->num_add+svd->rallows->num_rem+svd->rallows->num_chg,
		svd->rtrans->num_add+svd->rtrans->num_rem+svd->rtrans->num_chg+
		svd->rtrans->num_add_type+svd->rtrans->num_rem_type,
		svd->te->num_add+svd->te->num_rem+svd->te->num_chg+
		svd->te->num_add_type+svd->te->num_rem_type,
		svd->conds->num_add+svd->conds->num_rem+svd->conds->num_chg);
	return 0;
}

typedef int(*get_iad_name_fn_t)(int idx, char **name, policy_t *policy);

static int print_iad_type_chg_elements(FILE *fp,ap_single_iad_chg_t *asic
				       ,policy_t *p_add,policy_t *p_rem,char *adescrp,get_iad_name_fn_t get_a_name)
{
	int i;
	char *tmp;
	int rt;

	for (i=0; i < asic->num_add;i++) {
		rt = (*get_a_name)(asic->add[i], &tmp, p_add);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, asic->add[i]);
			return -1;
		}
		fprintf(fp, "\t\t\t+ %s\n", tmp);
		free(tmp);
	}
	for (i=0; i < asic->num_rem;i++) {
		rt = (*get_a_name)(asic->rem[i], &tmp, p_rem);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, asic->rem[i]);
			return -1;
		}
		fprintf(fp, "\t\t\t- %s\n", tmp);
		free(tmp);
	}

	return 0;
}


static int print_iad_elements(FILE *fp,
			     int_a_diff_t *diff,policy_t *policy,bool_t added,
			     char *adescrp,get_iad_name_fn_t get_a_name)
{
	int i;
	char *tmp;
	int rt;
	for (i = 0; i < diff->numa; i++) {
		rt = (*get_a_name)(diff->a[i], &tmp, policy);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, diff->a[i]);
			return -1;
		}
		if (added)
			fprintf(fp, "\t\t\t+ %s\n", tmp);
		else
		        fprintf(fp, "\t\t\t- %s\n", tmp);
		free(tmp);
	}
	return 0;
}

/* given the role name(name) this will find all rules with name as the source
   in both policies and print out those rules concatenating the targets together 
   for easier reading */
static int print_rallow_rules(FILE *fp,policy_t *p1,policy_t *p2,char *name,
			      char *adescrp)
{
	rbac_bool_t rb, rb2;
	int rt,idx1,idx2,i;
	char *rname = NULL;
	int num_found;


	/* find index of both roles in policies */
	idx1 = get_role_idx(name,p1);
	if (idx1 < 0)
		return -1;
	idx2 = get_role_idx(name, p2);
	if (idx2 < 0)
		return -1;

	if (init_rbac_bool(&rb, p1, TRUE) != 0) 
		goto print_rallow_keys_error;
	
	if (init_rbac_bool(&rb2, p2, TRUE) != 0) 
		goto print_rallow_keys_error;
	

	/* find all target roles that have that role in the source of a role allow rule */
	rt = match_rbac_roles(idx1, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb, &num_found, p1);
	if (rt < 0) 
		return -1;
	rt = match_rbac_roles(idx2, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb2, &num_found, p2);
	if (rt < 0) {
		free_rbac_bool(&rb);
		return -1;
	}
	/* print that stuff out */
	fprintf(fp,"\t\t* Policy 1: allow %s { ",name);
	for (i = 0; i < p1->num_roles; i++) {
		if (!rb.allow[i])
			continue;
		rt = get_role_name(i,&rname,p1);
		if (rt < 0)
			goto print_rallow_keys_error;
		fprintf(fp,"%s ",rname);
		free(rname);
		rname = NULL;		
	}
	fprintf(fp,"}\n");

	fprintf(fp,"\t\t* Policy 2: allow %s { ",name);
	for (i = 0; i < p2->num_roles; i++) {
		if (!rb2.allow[i])
			continue;
		rt = get_role_name(i,&rname,p2);
		if (rt < 0)
			goto print_rallow_keys_error;
		fprintf(fp,"%s ",rname);
		free(rname);
		rname = NULL;		
	}
	fprintf(fp,"}\n");

	free_rbac_bool(&rb);
	free_rbac_bool(&rb2);
	return 0;
 print_rallow_keys_error:
	if (rname)
		free(rname);
	free_rbac_bool(&rb);
	free_rbac_bool(&rb2);
	return -1;



}

static int print_rallow_element(FILE *fp,int_a_diff_t *diff,policy_t *policy,bool_t added,
				char *adescrp,get_iad_name_fn_t get_a_name)
{
	int i;
	char *tmp;
	int rt;
	for (i = 0; i < diff->numa; i++) {
		rt = (*get_a_name)(diff->a[i], &tmp, policy);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, diff->a[i]);
			return -1;
		}
		fprintf(fp, " %s", tmp);
		free(tmp);
	}
	fprintf(fp, " }\n");
	return 0;
}


/* print out a difference, in this case we consider everything in the p1 diff to be removed
   and everything in the p2 to be added, and everything in both to be changed*/
static int print_iad(FILE *fp, int id, ap_single_iad_diff_t *siad,policy_t *p_old,policy_t *p_new)
{
	get_iad_name_fn_t get_name, get_a_name;
	char *name, *descrp = NULL, *adescrp = NULL;
	bool_t type_chg = FALSE;
	int rt,i;

/* now we want stats at all times even if emtpy list 	
  if(iad_p1 == NULL && iad_p2 == NULL ) 
		return 0;  indicates an empty list */

	if(fp == NULL || siad == NULL || (p_old == NULL && p_new == NULL ) 
	   || !(id & (IDX_TYPE|IDX_ATTRIB|IDX_ROLE|IDX_USER|IDX_OBJ_CLASS|IDX_COMMON_PERM|IDX_ROLE)))
		return -1;

	switch(id) {
	case IDX_ROLE|IDX_PERM:
		get_name = &get_role_name;
		get_a_name = &get_role_name;
		descrp = "Role Allows";
		adescrp = "Role Allows";
		break;
	case IDX_TYPE:
		get_name = &get_type_name;
		get_a_name = &get_attrib_name;
		descrp = "Types";
		adescrp = "Attributes";
		break;
	case IDX_ATTRIB:
		get_name = &get_attrib_name;
		get_a_name = &get_type_name;
		descrp = "Attributes";
		adescrp = "Types";
		type_chg = TRUE;
		break;
	case IDX_ROLE:
		get_name = &get_role_name;
		get_a_name = &get_type_name;
		descrp = "Roles";
		adescrp = "Types";
		type_chg = TRUE;
		break;
	case IDX_USER:
		get_name = &get_user_name2;
		get_a_name = &get_role_name;
		descrp = "Users";
		adescrp = "Roles";
		break;
	case IDX_OBJ_CLASS:
		get_name = &get_obj_class_name;
		get_a_name = &get_perm_name;
		descrp = "Classes";
		adescrp = "Permissions";
		break;
	case IDX_COMMON_PERM:
		get_name = &get_common_perm_name;
		get_a_name = &get_perm_name;
		descrp = "Common Permissions";
		adescrp = "Permissions";
		break;
	default:
		assert(0); /* shouldn't get here */
		return -1; 
		break;
	}

	if (type_chg == TRUE)
		fprintf(fp,"%s (%d Added, %d Removed, %d Changed, %d Changed New Type,"
			" %d Changed Missing Type)\n",descrp,siad->num_add,siad->num_rem,siad->num_chg,
			siad->num_chg_add,siad->num_chg_rem);
	else
		fprintf(fp,"%s (%d Added, %d Removed, %d Changed)\n"
			,descrp,siad->num_add,siad->num_rem,siad->num_chg);

	/* First goes adds */
	fprintf(fp, "\tAdded %s: %d\n",descrp,siad->num_add);
	for (i=0; i<siad->num_add; i++) {
		rt = (*get_name)(siad->add[i]->idx, &name, p_new);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for %s %d\n", descrp, siad->add[i]->idx);
			return -1;
		}
		fprintf(fp, "\t\t+ %s\n", name);
		free(name);
	}

	/* removes */
	fprintf(fp, "\tRemoved %s: %d\n",descrp,siad->num_rem);
	for (i=0; i<siad->num_rem; i++) {	       
		rt = (*get_name)(siad->rem[i]->idx, &name, p_old);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for %s %d\n", descrp, siad->rem[i]->idx);
			return -1;
		}
		fprintf(fp, "\t\t- %s\n", name);
		free(name);

	}

	if (!((siad->id & IDX_ROLE) | (siad->id & IDX_ATTRIB))) {
		fprintf(fp, "\tChanged %s: %d\n",descrp,siad->num_chg);
		for (i=0; i < siad->num_chg; i++) {
			if (siad->chg[i].p1_idx >= 0)
				rt = (*get_name)(siad->chg[i].p1_idx, &name, p_old);			
			else
				rt = (*get_name)(siad->chg[i].p2_idx, &name, p_new);
			if (rt < 0)
				return -1;
			if (siad->chg[i].rem_iad != NULL && siad->chg[i].add_iad != NULL) {
				fprintf(fp, "\t\t* %s (%d Added, %d Removed %s)\n", name,
						siad->chg[i].add_iad->numa,siad->chg[i].rem_iad->numa, adescrp);
				rt = print_iad_elements(fp,siad->chg[i].add_iad,p_new,TRUE,adescrp,get_a_name);
				if (rt < 0)
					return -1;
				rt = print_iad_elements(fp,siad->chg[i].rem_iad,p_old,FALSE,adescrp,get_a_name);
				if (rt < 0)
					return -1;

			} else if (siad->chg[i].rem_iad != NULL) {
				fprintf(fp, "\t\t* %s (%d Removed %s)\n", name, siad->chg[i].rem_iad->numa, adescrp);
				rt = print_iad_elements(fp,siad->chg[i].rem_iad,p_old,FALSE,adescrp,get_a_name);
				if (rt < 0)
					return -1;

			} else {
				fprintf(fp, "\t\t* %s (%d Added %s)\n", name, siad->chg[i].add_iad->numa, adescrp);
				rt = print_iad_elements(fp,siad->chg[i].add_iad,p_new,TRUE,adescrp,get_a_name);		 
				if (rt < 0)
					return -1;
			}			
			free(name);

		}
	} else if (((siad->id & IDX_ROLE) | (siad->id & IDX_ATTRIB))) {
		fprintf(fp, "\tChanged %s: %d\n",descrp,siad->num_chg);
		for (i=0; i < siad->num_chg; i++) {
			if (siad->chg[i].p1_idx >= 0)
				rt = (*get_name)(siad->chg[i].p1_idx, &name, p_old);			
			else
				rt = (*get_name)(siad->chg[i].p2_idx, &name, p_new);
			fprintf(fp, "\t\t* %s (%d Added, %d Removed %s)\n", name,
					siad->chg[i].num_add,siad->chg[i].num_rem, adescrp);
			print_iad_type_chg_elements(fp,&(siad->chg[i]),
						    p_new,p_old,adescrp,get_a_name);

			free(name);
		}
	}
	if (type_chg == TRUE) {
		fprintf(fp, "\tChanged, New Type %s: %d\n",descrp,siad->num_chg_add);
		for (i=0; i < siad->num_chg_add; i++) {
			rt = (*get_name)(siad->chg_add[i].p2_idx, &name, p_new);			

			fprintf(fp, "\t\t* %s (%d Added, %d Removed %s)\n", name,
					siad->chg_add[i].num_add,siad->chg_add[i].num_rem, adescrp);
			print_iad_type_chg_elements(fp,&(siad->chg_add[i]),
						    p_new,p_old,adescrp,get_a_name);

			free(name);
		}
	}
	if (type_chg == TRUE) {
		fprintf(fp, "\tChanged, Removed Type %s: %d\n",descrp,siad->num_chg_rem);
		for (i=0; i < siad->num_chg_rem; i++) {
			rt = (*get_name)(siad->chg_rem[i].p1_idx, &name, p_old);			
			fprintf(fp, "\t\t* %s (%d Added, %d Removed %s)\n", name,
					siad->chg_rem[i].num_add,siad->chg_rem[i].num_rem, adescrp);
			print_iad_type_chg_elements(fp,&(siad->chg_rem[i]),
						    p_new,p_old,adescrp,get_a_name);
			free(name);

		}
	}

	return 0;
}

/* print out a difference, in this case we consider everything in the p1 diff to be removed
   and everything in the p2 to be added, and everything in both to be changed*/
static int print_rallow(FILE *fp, int id, ap_single_iad_diff_t *siad,
		     policy_t *p1, policy_t *p2)
{
	get_iad_name_fn_t get_name, get_a_name;
	char *name, *descrp = NULL, *adescrp = NULL;
	int rt,i;
	

/* now we want stats at all times even if emtpy list 	
  if(iad_p1 == NULL && iad_p2 == NULL ) 
		return 0;  indicates an empty list */

	if(fp == NULL || (p1 == NULL && p2 == NULL ) || !(id & (IDX_TYPE|IDX_ATTRIB|IDX_ROLE|IDX_USER|IDX_OBJ_CLASS|IDX_COMMON_PERM|IDX_ROLE)))
		return -1;
	
	switch(id) {
	case IDX_ROLE|IDX_PERM:
		get_name = &get_role_name;
		get_a_name = &get_role_name;
		descrp = "Role Allows";
		adescrp = "Role Allows";
		break;
	default:
		assert(0); /* shouldn't get here */
		return -1; 
		break;
	}
	
	fprintf(fp,"%s (%d Added, %d Removed, %d Changed)\n"
		,descrp,siad->num_add,siad->num_rem,siad->num_chg);


	/* First goes adds */
	fprintf(fp, "\tAdded %s: %d\n",descrp,siad->num_add);
	for (i=0; i<siad->num_add; i++) {
		rt = (*get_name)(siad->add[i]->idx, &name, p2);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for %s %d\n", descrp, siad->add[i]->idx);
			return -1;
		}
		fprintf(fp, "\t\t+ allow %s {", name);
		rt = print_rallow_element(fp,siad->add[i],p2,TRUE,adescrp,get_a_name);
		if (rt < 0)
			goto print_rallow_error;
		free(name);
	}

	/* removes */
	fprintf(fp, "\tRemoved %s: %d\n",descrp,siad->num_rem);
	for (i=0; i<siad->num_rem; i++) {	       
		rt = (*get_name)(siad->rem[i]->idx, &name, p1);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for %s %d\n", descrp, siad->rem[i]->idx);
			return -1;
		}
		fprintf(fp, "\t\t- %s {", name);
		rt = print_rallow_element(fp,siad->rem[i],p1,FALSE,adescrp,get_a_name);
		free(name);

	}

	/* Changes */
	fprintf(fp, "\tChanged %s: %d\n",descrp,siad->num_chg);
	for (i=0; i < siad->num_chg; i++) {
		if (siad->chg[i].p1_idx >= 0)
			rt = (*get_name)(siad->chg[i].p1_idx, &name, p1);			
		else
			rt = (*get_name)(siad->chg[i].p2_idx, &name, p2);
		if (rt < 0)
			return -1;
		if (siad->chg[i].rem_iad != NULL && siad->chg[i].add_iad != NULL) {
			rt = print_rallow_rules(fp,p1,p2,name,adescrp);
			rt = print_iad_elements(fp,siad->chg[i].add_iad,p2,TRUE,adescrp,get_a_name);
			if (rt < 0)
				return -1;
			rt = print_iad_elements(fp,siad->chg[i].rem_iad,p1,FALSE,adescrp,get_a_name);
			if (rt < 0)
				return -1;
			
		} else if (siad->chg[i].rem_iad != NULL) {
			rt = print_rallow_rules(fp,p1,p2,name,adescrp);
			rt = print_iad_elements(fp,siad->chg[i].rem_iad,p1,FALSE,adescrp,get_a_name);
			if (rt < 0)
				return -1;
			
		} else {
			rt = print_rallow_rules(fp,p1,p2,name,adescrp);
			rt = print_iad_elements(fp,siad->chg[i].add_iad,p2,TRUE,adescrp,get_a_name);		 
			if (rt < 0)
				return -1;
		}			
		free(name);

	}

	return 0;

	/*handle memory before we quit from an error */
 print_rallow_error:
	return -1;

}

static int print_type_diffs(FILE *fp, ap_single_view_diff_t *svd)
{
	int rt;
	if(svd == NULL || fp == NULL)
		return -1;

	rt = print_iad(fp, IDX_TYPE, svd->types,svd->diff->p1,svd->diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing types.\n");
		return -1;
	}
	return 0;
}

static int print_attrib_diffs(FILE *fp, ap_single_view_diff_t *svd)
{
	int rt;
	
	if(svd == NULL || fp == NULL)
		return -1;
	
	rt = print_iad(fp, IDX_ATTRIB, svd->attribs,svd->diff->p1,svd->diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing attributes for p1.\n");
		return -1;
	}
	return 0;
}

static int print_role_diffs(FILE *fp, ap_single_view_diff_t *svd)
{
	int rt;
	
	if(svd == NULL || fp == NULL)
		return -1;
	
	rt = print_iad(fp, IDX_ROLE, svd->roles,svd->diff->p1,svd->diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing roles for p1.\n");
		return -1;
	}
	return 0;
}

static int print_rallows_diffs(FILE *fp, ap_single_iad_diff_t *siad,policy_t *p1,policy_t *p2)
{
	int rt;
	
	if(siad == NULL || fp == NULL || p1 == NULL || p2 == NULL)
		return -1;
	
	rt = print_rallow(fp, IDX_ROLE|IDX_PERM, siad,p1,p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing roles for p1.\n");
		return -1;
	}
	return 0;
}

static int print_user_diffs(FILE *fp, ap_single_view_diff_t *svd)
{
	int rt;
	if(svd == NULL || fp == NULL)
		return -1;

	rt = print_iad(fp, IDX_USER, svd->users,svd->diff->p1,svd->diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing users for p1.\n");
		return -1;
	}
	return 0;
}

static int print_rtrans_diffs(FILE *fp, ap_single_rtrans_diff_t *srd, policy_t *policy_old, policy_t *policy_new)
{
	char *srole = NULL,*trole = NULL,*type = NULL, *trole2 = NULL;
	int rt,i;

	if(srd == NULL || fp == NULL)
		return -1;

	fprintf(fp, "Role Transitions (%d Added, %d Added New Type, %d Removed, %d Removed Missing Type"
			", %d Changed)\n",srd->num_add,srd->num_add_type,srd->num_rem,srd->num_rem_type,srd->num_chg);

	/* added rtrans */
	/* Put added header on */
	fprintf(fp, "\tAdded Role Transitions: %d\n",srd->num_add);
	for (i = 0; i < srd->num_add;i++) {
		rt = get_role_name(srd->add[i]->rs_idx,&srole,policy_new);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_type_name(srd->add[i]->t_idx,&type,policy_new);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_role_name(srd->add[i]->rt_idx,&trole,policy_new);
		if (rt < 0)
			goto print_rtrans_error;
		fprintf(fp,"\t\t+ role_transition %s %s %s\n",srole,type,trole);
		free(srole);
		free(type);
		free(trole);
		
	}
	
	/* added types */
	/* Put added header on */
	fprintf(fp, "\tAdded Role Transitions, New Type: %d\n",srd->num_add_type);
	for (i = 0; i < srd->num_add_type;i++) {
		rt = get_role_name(srd->add_type[i]->rs_idx,&srole,policy_new);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_type_name(srd->add_type[i]->t_idx,&type,policy_new);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_role_name(srd->add_type[i]->rt_idx,&trole,policy_new);
		if (rt < 0)
			goto print_rtrans_error;
		fprintf(fp,"\t\t+ role_transition %s %s %s\n",srole,type,trole);
		free(srole);
		free(type);
		free(trole);			
	}

	/* removes */
	/* Put changed header on */
	fprintf(fp, "\tRemoved Role Transitions: %d\n",srd->num_rem);
	for (i = 0; i < srd->num_rem;i++) {
		rt = get_role_name(srd->rem[i]->rs_idx,&srole,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_type_name(srd->rem[i]->t_idx,&type,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_role_name(srd->rem[i]->rt_idx,&trole,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		fprintf(fp,"\t\t- role_transition %s %s %s\n",srole,type,trole);

		free(srole);
		free(type);
		free(trole);   			
	}

	/* removed types */
	/* Put changed header on */
	fprintf(fp, "\tRemoved Role Transitions, Removed Type: %d\n",srd->num_rem_type);
	for (i = 0; i < srd->num_rem_type;i++) {
		rt = get_role_name(srd->rem_type[i]->rs_idx,&srole,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_type_name(srd->rem_type[i]->t_idx,&type,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_role_name(srd->rem_type[i]->rt_idx,&trole,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		fprintf(fp,"\t\t- role_transition %s %s %s\n",srole,type,trole);

		free(srole);
		free(type);
		free(trole);
	}


	/* Changed rtrans */
	/* Put changed header on */
	fprintf(fp, "\tChanged Role Transitions: %d\n",srd->num_chg);
	for (i = 0; i < srd->num_chg;i++) {
		rt = get_role_name(srd->chg_rem[i]->rs_idx,&srole,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_type_name(srd->chg_rem[i]->t_idx,&type,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_role_name(srd->chg_rem[i]->rt_idx,&trole,policy_old);
		if (rt < 0)
			goto print_rtrans_error;
		rt = get_role_name(srd->chg_add[i]->rt_idx,&trole2,policy_new);
		if (rt < 0)
			goto print_rtrans_error;
		
		fprintf(fp,"\t\t* role_transition %s %s\n",srole,type);
		fprintf(fp,"\t\t\t+ %s\n",trole2);
		fprintf(fp,"\t\t\t- %s\n",trole);
		free(srole);
		free(type);
		free(trole);
		free(trole2);		
	}


	return 0;

	/*handle memory before we quit from an error */
 print_rtrans_error:
	return -1;

}

static int print_boolean_diffs(FILE *fp, ap_single_bool_diff_t *sbd, policy_t *policy_old, policy_t *policy_new)
{
	int rt,i;
	char *name = NULL;
	bool_t state;

	if(sbd == NULL || policy_new == NULL || policy_old == NULL || fp == NULL)
		return -1;

	fprintf(fp, "Booleans (%d Added, %d Removed, %d Changed)\n",sbd->num_add,
			sbd->num_rem, sbd->num_chg);

	/* added booleans */
	fprintf(fp, "\tAdded Booleans: %d\n",sbd->num_add);
	for (i = 0;i < sbd->num_add;i++) {
		rt = get_cond_bool_name(sbd->add[i]->idx, &name, policy_new);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for boolean %d\n", sbd->add[i]->idx);
			return -1;
		}
		fprintf(fp, "\t\t+ %s\n", name);
		free(name);		
	}

	/* removed booleans */
	/* removed booleans header */
	fprintf(fp, "\tRemoved Booleans: %d\n",sbd->num_rem);
	for (i = 0;i < sbd->num_rem;i++) {
		rt = get_cond_bool_name(sbd->rem[i]->idx, &name, policy_old);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for boolean %d\n", sbd->rem[i]->idx);
			return -1;
		}
		fprintf(fp, "\t\t- %s\n", name);
		free(name);				
	}

	/* Changed booleans */
	/* Changed Booleans header */
	fprintf(fp, "\tChanged Booleans: %d\n",sbd->num_chg);
	for (i = 0;i < sbd->num_chg;i++) {
		rt = get_cond_bool_name(sbd->chg[i]->idx, &name, policy_old);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for boolean %d\n", sbd->chg[i]->idx);
			return -1;
		}
		fprintf(fp, "\t\t* %s (changed", name);
		rt = get_cond_bool_default_val_idx(sbd->chg[i]->idx, &state, policy_old);
		if (rt < 0) {
			fprintf(stderr, "Problem getting boolean state for %s\n", name);
			free(name);
			return -1;
		}
		fprintf(fp, " from %s to %s)\n", (state ? "TRUE" : "FALSE"), (state ? "FALSE" : "TRUE") );
		free(name);    						      
	}
	return 0;
}

static int print_classes_diffs(FILE *fp, ap_single_view_diff_t *svd)
{
	int rt;
	if(svd == NULL || fp == NULL)
		return -1;
		
	rt = print_iad(fp, IDX_OBJ_CLASS, svd->classes,svd->diff->p1,svd->diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing classes for p1.\n");
		return -1;
	}
	return 0;	
}

static int print_common_perms_diffs(FILE *fp, ap_single_view_diff_t *svd)
{
	int rt;
	if(svd == NULL || fp == NULL)
		return -1;
		
	rt = print_iad(fp, IDX_COMMON_PERM, svd->common_perms,svd->diff->p1,svd->diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing common permissions for p1.\n");
		return -1;
	}
	return 0;	
}

static int print_perms_diffs(FILE *fp, ap_single_perm_diff_t *spd, policy_t *policy_old, policy_t *policy_new)
{
	int rt, i;
	char *name;
	
	if(spd == NULL || fp == NULL)
		return -1;
		

	fprintf(fp, "Permissions (%d Added, %d Removed)\n",spd->num_add,
			spd->num_rem);

	/* added */
	fprintf(fp,"\tAdded Permissions: %d\n",spd->num_add);
	for (i = 0; i < spd->num_add; i++) {
		rt = get_perm_name(spd->add[i], &name, policy_new);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d\n", spd->add[i]);
			return -1;
		}
		fprintf(fp, "\t\t+ %s\n", name);
		free(name);
	}
	/* removed */
	fprintf(fp,"\tRemoved Permissions: %d\n",spd->num_rem);
	for (i = 0; i < spd->num_rem; i++) {
		rt = get_perm_name(spd->rem[i], &name, policy_old);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d\n", spd->rem[i]);
			return -1;
		}
		fprintf(fp, "\t\t- %s\n", name);
		free(name);		
	}
	return 0;	
}

static int print_te_rule(FILE *fp,avh_node_t *cur, policy_t *policy, const char *string,
			 bool_t show_cond)
{
	char *rule = NULL, *cond = NULL;

       	if (cur == NULL || policy == NULL) {
		return -1; 

	}
	/* print the rule */
	rule = re_render_avh_rule(cur, policy); 
	if (rule == NULL) { 
		return -1;
	} 
	if (show_cond && cur->flags & AVH_FLAG_COND) {
		cond = re_render_avh_rule_cond_state(cur,policy);	
		fprintf(fp,"%s%s%s",cond == NULL ? " " : cond,string,rule);
	}
	else if (!show_cond && cur->flags & AVH_FLAG_COND) {
		fprintf(fp," \t\t%s%s",string,rule);
	}
	else
		fprintf(fp, " %s%s",string,rule);
	free(rule); 
	if (cond != NULL) {
		free(cond);
		cond = NULL;
	}
	
	/* get the line # */
	rule = re_render_avh_rule_linenos(cur, policy); 
	if (rule != NULL) { 
		fprintf(fp,"(%s)", is_binary_policy(policy) ? "" : rule);
		free(rule); 
	} 


	if (show_cond && cur->flags & AVH_FLAG_COND) {
		rule = re_render_avh_rule_cond_expr(cur,policy);
		fprintf(fp,"%s",rule);
		free(rule);
	}	
	fprintf(fp,"\n");

	return 0;
}

static int print_te_diffs(FILE *fp, ap_single_te_diff_t *sted,policy_t *policy1,policy_t *policy2,
		   bool_t showconds)
{
	int i,j;
	avh_node_t *diffcur1 = NULL;
	avh_node_t *diffcur2 = NULL;
	char *name = NULL;
	
	if(sted == NULL || fp == NULL) 
		goto print_te_error;
	

	if (showconds == TRUE) {
		fprintf(fp, "TE Rules (%d Added, %d Added New Type, %d Removed, %d Removed Missing Type,"
				" %d Changed)\n",sted->num_add,sted->num_add_type,sted->num_rem,sted->num_rem_type,sted->num_chg);

	}

	/* adds */
	fprintf(fp, "\t%sAdded TE Rules: %d\n",showconds ? "" : "\t\t",sted->num_add);
	for (i = 0; i < sted->num_add; i++) {
		print_te_rule(fp,sted->add[i],policy2,"\t\t+ ",showconds);
	}
	
	/* are we printing adds that have new types */
	fprintf(fp, "\t%sAdded TE Rules because of new type: %d\n",showconds ? "" : "\t\t",sted->num_add_type);
	for (i = 0; i < sted->num_add_type; i++) {
		print_te_rule(fp,sted->add_type[i],policy2,"\t\t+ ",showconds);
	}
	
	/* removes */
	fprintf(fp, "\t%sRemoved TE Rules: %d\n",showconds ? "" : "\t\t", sted->num_rem);
	for (i = 0; i < sted->num_rem; i++) {
		print_te_rule(fp,sted->rem[i],policy1,"\t\t- ",showconds);	
	}
	/* removes that have a missing type */	
	fprintf(fp, "\t%sRemoved TE Rules because of missing type: %d\n",showconds ? "" : "\t\t", sted->num_rem_type);
	for (i = 0; i < sted->num_rem_type; i++) {
		print_te_rule(fp,sted->rem_type[i],policy1,"\t\t- ",showconds);	
	}	
	/* changes */
	fprintf(fp, "\t%sChanged TE Rules: %d\n",showconds ? "" : "\t\t",sted->num_chg);
	for (i = 0; i < sted->num_chg; i++) {
		print_te_rule(fp,sted->chg[i].rem,policy1,"\t*Policy1: ",showconds);	
		print_te_rule(fp,sted->chg[i].add,policy2,"\t*Policy2: ",showconds);	
		/* now print the diffs */
		diffcur1 = sted->chg[i].rem_diff;
		diffcur2 = sted->chg[i].add_diff;
		if (diffcur1 != NULL) {
			if (diffcur1->key.rule_type <= RULE_MAX_AV) {
				for (j = 0 ; j < diffcur1->num_data; j++) {
					if (get_perm_name(diffcur1->data[j],&name,policy1) == 0) {
						fprintf(fp,"\t\t%s- %s\n",showconds ? "" : "\t\t",name);
						free(name);
					} else
						goto print_te_error;
				}
			} else {
				if (diffcur1->num_data == 1) {
					if (get_type_name(diffcur1->data[0],&name,policy1) == 0) {
						fprintf(fp,"\t\t%s- %s\n",showconds ? "" : "\t\t",name);
						free(name);
					} else
						goto print_te_error;
				}
			}
		} 
		if (diffcur2) {
			if (diffcur2->key.rule_type <= RULE_MAX_AV) {
				for (j = 0 ; j < diffcur2->num_data; j++) {
					if (get_perm_name(diffcur2->data[j],&name,policy2) == 0) {
						fprintf(fp,"\t\t%s+ %s\n",showconds ? "" : "\t\t",name);
						free(name);
					} else
						goto print_te_error;
				}
				
			} else {
				if (diffcur2->num_data == 1) {
					if (get_type_name(diffcur2->data[0],&name,policy2) == 0) {
						fprintf(fp,"\t\t%s+ %s\n",showconds ? "" : "\t\t",name);
						free(name);
					} else
						goto print_te_error;
				}
			}
		}
		
	}

       	return 0;

	/*handle memory before we quit from an error */
 print_te_error:
	printf("there was a te printing error");
	return -1;

}

static int print_cond_diffs(FILE *fp, ap_single_cond_diff_t *scd, policy_t *policy_old, policy_t *policy_new)
{
	char *rule = NULL;
	int i;

	if(scd == NULL || fp == NULL || policy_old == NULL || policy_new == NULL) {
		goto print_cond_error;
	}

	fprintf(fp, "Conditionals (%d Added, %d Removed, %d Changed)\n", scd->num_add,scd->num_rem,
			scd->num_chg);
	/* print the header */
	fprintf(fp, "\tAdded Conditionals: %d\n",scd->num_add);
	for (i = 0;i < scd->num_add;i++) {
		/* print the conditional */
		rule = re_render_cond_expr(scd->add[i].idx,policy_new);
		fprintf(fp,"\t+%s\n",rule);
		free(rule);
		fprintf(fp,"\t\tTRUE list:\n");	    		
		print_te_diffs(fp, scd->add[i].true_list, policy_old,policy_new,FALSE);
		fprintf(fp,"\t\tFALSE list:\n");	    		
		print_te_diffs(fp, scd->add[i].false_list, policy_old,policy_new,FALSE);
	}
	fprintf(fp, "\tRemoved Conditionals: %d\n",scd->num_rem);
	for (i = 0;i < scd->num_rem;i++) {
		/* print the conditional */
		rule = re_render_cond_expr(scd->rem[i].idx,policy_old);
		fprintf(fp,"\t-%s\n",rule);
		free(rule);		
		fprintf(fp,"\t\tTRUE list:\n");	    		
		print_te_diffs(fp, scd->rem[i].true_list, policy_old,policy_new,FALSE);
		fprintf(fp,"\t\tFALSE list:\n");	    		
		print_te_diffs(fp, scd->rem[i].false_list, policy_old,policy_new,FALSE);
	}
	/* changes */
	fprintf(fp, "\tChanged Conditionals: %d\n",scd->num_chg);
	for (i = 0;i < scd->num_chg;i++) {
		/* print the conditional */
		rule = re_render_cond_expr(scd->chg[i].idx,policy_old);
		fprintf(fp,"\t*%s\n",rule);
		free(rule);
		fprintf(fp,"\t\tTRUE list:\n");	    				
		print_te_diffs(fp, scd->chg[i].true_list, policy_old,policy_new,FALSE);
		fprintf(fp,"\t\tFALSE list:\n");	    		
		print_te_diffs(fp, scd->chg[i].false_list, policy_old,policy_new,FALSE);		
	}
       	return 0;

	/*handle memory before we quit from an error */
 print_cond_error:
	return -1;
}



int main (int argc, char **argv)
{
	int classes, types, roles, users, all, stats, attributes, rallows, rtrans;
	int optc, isids, conds, terules, rbac, bools, rt,gui, quiet;
	policy_t *p1 = NULL, *p2 = NULL;
	char *p1_file = NULL, *p2_file = NULL;
	apol_diff_result_t *diff = NULL;
	ap_single_view_diff_t *svd = NULL;
	unsigned int opts = POLOPT_NONE;
	char prog_path[PATH_MAX];
	int ret_code = 0;
	
	attributes = rallows = rtrans = classes = types = roles = users = bools = all = stats = isids = conds = terules = rbac = gui = quiet = 0;
	while ((optc = getopt_long (argc, argv, "qXaActrubiTRCshv", longopts, NULL)) != -1)  {
		switch (optc) {
		case 0:
	  		break;
		case 'X': /* gui */
			gui = 1;
			break;
	  	case 'c': /* classes */
	  		opts |= POLOPT_OBJECTS;
	  		classes = 1;
	  		break;
	  	case 't': /* types */
	  		opts |= POLOPT_TYPES;
	  		types = 1;
	  		break;
	  	case 'a': /* attributes */
	  		opts |= POLOPT_TYPES;
	  		attributes = 1;
	  		break;
	  	case 'r': /* roles */
	  		opts |= POLOPT_ROLES;
	  		roles = 1;
	  		break;
	  	case 'u': /* users */
	  		opts |= POLOPT_USERS;
	  		users = 1;
	  		break;
	  	case 'b': /* conditional booleans */
	  		opts |= POLOPT_COND_BOOLS;
	  		bools = 1;
	  		break;
	  	case 'i': /* initial SIDs */
	  		opts |= POLOPT_INITIAL_SIDS;
	  		isids = 0; /* not supported as yet */
	  		printf("Warning: Initial SIDs not currently supported and will be ignored. \n");
	  		break;
	  	case 's': /* stats */
	  		opts = POLOPT_ALL;
	  		stats = 1;
	  		break;
	  	case 'T': /* te rules */
	  		opts |= POLOPT_TE_POLICY;
	  		terules = 1;
	  		break;
	  	case 'R': /* role trans */
	  		opts |= POLOPT_RBAC;
	  		rtrans = 1;
	  		break;
	  	case 'A': /* role allows */
	  		opts |= POLOPT_RBAC;
	  		rallows = 1;
	  		break;
	  	case 'C': /* conditionals */
	  		opts |= POLOPT_COND_POLICY;
			opts |= POLOPT_AV_RULES;
			conds = 1;
	  		break;
	  	case 'h': /* help */
	  		usage(argv[0], 0);
	  		exit(0);
	  		break;
	  	case 'v': /* version */
	  		printf("\n%s (sediff ver. %s)\n\n", COPYRIGHT_INFO, SEDIFF_VERSION_NUM);
	  		exit(0);
	  		break;
		case 'q': /* quite */
			quiet = 1;
			break;
	  	default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}

	/* if no options, then show stats */
	if(classes + bools + types + roles + users + isids + terules + rbac + conds + stats + attributes + terules + rallows + rtrans < 1) {
		opts = POLOPT_ALL;
		all = 1;
	}
	if (gui == 0 && (argc - optind > 2 || argc - optind < 1)) {
		usage(argv[0], 1);
		exit(1);
	}
	/* are we going to use the gui */
	else if (gui == 1) {
		snprintf(prog_path, PATH_MAX, "./%s", SEDIFF_GUI_PROG);
		/* launch the gui with no arguments */
		if (argc - optind == 0 ) {
			rt = access(prog_path, X_OK);
			if (rt == 0) {
				rt = execvp(prog_path,argv);
			} else {
				rt = execvp(SEDIFF_GUI_PROG,argv);
			}


		}
		/* launch the gui with file args */
		else if (argc - optind == 2) {
			rt = access(prog_path, X_OK);
			if (rt == 0) {
				rt = execvp(prog_path,argv);
			} else {
				rt = execvp(prog_path,argv);
			}			
		}
		if (argc - optind != 0 && argc - optind != 2) {
			usage(argv[0], 1);
			exit(1);
		}
		exit(1);
	}

	else {
		p1_file = argv[optind++];
		p2_file = argv[optind];
	}

	/* attempt to open the policies */
	if(fn_is_binpol(p1_file) && fn_binpol_ver(p1_file) < 15) {
		printf("Policy 1:  Binary policies are only supported for version 15 or higer.\n");
		exit(1);
	}
	if(fn_is_binpol(p2_file) && fn_binpol_ver(p2_file) < 15 ) {
		printf("Policy 2:  Binary policies are only supported for version 15 or higer.\n");
		exit(1);
	}
	rt = open_partial_policy(p1_file, opts, &p1);
	if(rt != 0) {
		printf("Problem opening first policy file: %s\n", p1_file);
		exit(1);
	}
	if(get_policy_version_id(p1) < POL_VER_12) {
		printf("Policy 1:  Unsupport version: Supported versions are Source (12 and higher), Binary (15 and higher).\n");
		exit(1);
	}
	rt = open_partial_policy(p2_file, opts, &p2);
	if(rt != 0) {
		printf("Problem opening second policy file: %s\n", p2_file);
		exit(1);
	}
	if(get_policy_version_id(p2) < POL_VER_12 ) {
		printf("Policy 2:  Unsupport version: Supported versions are Source (12 and higher), Binary (15 and higher).\n");
		exit(1);
	}

	printf("Calculating difference, this might take a while\n");
	svd = ap_single_view_diff_new(opts, p1, p2, NULL);
	if (svd == NULL) {
		printf("Problem differentiating policies\n");
		exit(1);
	}
	diff = svd->diff;
	
	printf("Difference between policy 1 and policy 2: \n");
	printf("   p1 (%6s, ver: %s): %s\n", policy_type(svd->diff->p1), get_policy_version_name(svd->diff->p1->version), p1_file);
	printf("   p2 (%6s, ver: %s): %s\n\n", policy_type(svd->diff->p2), get_policy_version_name(svd->diff->p2->version), p2_file);
	
	if(classes || all)  {
		if (!(quiet && (diff->diff1->num_classes == 0 && diff->diff2->num_classes == 0))) {
			print_classes_diffs(stdout, svd);
			printf("\n");
		}
		if (!(quiet && (diff->diff1->num_perms == 0 && diff->diff2->num_perms == 0))) {
			print_perms_diffs(stdout, svd->perms,svd->diff->p1,svd->diff->p2);
			printf("\n");
		}
		if (!(quiet && (diff->diff1->num_common_perms == 0 && diff->diff2->num_common_perms == 0))) {
			print_common_perms_diffs(stdout, svd);
			printf("\n");
		}
	}
	if(types || all) {
		if (!(quiet && (diff->diff1->num_types == 0 && diff->diff2->num_types == 0))) {
			print_type_diffs(stdout, svd);
			printf("\n");
		}
	}
	if (attributes || all) {
		if (!(quiet && (diff->diff1->num_attribs == 0 && diff->diff2->num_attribs == 0))) {
			if(!apol_is_bindiff(diff)) {
				print_attrib_diffs(stdout, svd);
				printf("\n");
			}
		}
	}
	if((roles || all) && !(quiet && (diff->diff1->num_roles == 0 && diff->diff2->num_roles == 0))) {
		print_role_diffs(stdout, svd);
		printf("\n");
	}
	if((users || all) && !(quiet && (diff->diff1->num_users == 0 && diff->diff2->num_users == 0))) {
		print_user_diffs(stdout, svd);
		printf("\n");
	}
	if((bools || all) && !(quiet && (diff->diff1->num_booleans == 0 && diff->diff2->num_booleans == 0))) {
		print_boolean_diffs(stdout, svd->bools,svd->diff->p1,svd->diff->p2);
		printf("\n");
	}
	if((rallows || all) && !(quiet && (diff->diff1->num_role_allow == 0 && diff->diff2->num_role_allow == 0))){
		print_rallows_diffs(stdout, svd->rallows, svd->diff->p1, svd->diff->p2);
		printf("\n");
	}
	if((rtrans || all) && !(quiet && (diff->diff1->num_role_trans == 0 && diff->diff2->num_role_trans == 0))) {
		print_rtrans_diffs(stdout, svd->rtrans, svd->diff->p1, svd->diff->p2);
		printf("\n");
	}
	if((terules || all) && !(quiet && (diff->diff1->te.num == 0 && diff->diff2->te.num == 0))) {
		print_te_diffs(stdout, svd->te, svd->diff->p1, svd->diff->p2, TRUE);
		printf("\n");
	}
	if((conds || all) && !(quiet && (diff->diff1->num_cond_exprs == 0 && diff->diff2->num_cond_exprs == 0))) {
		print_cond_diffs(stdout, svd->conds, svd->diff->p1, svd->diff->p2);
		printf("\n");
	} 
	if((stats || all) && !quiet) {
		print_diff_stats(stdout, svd);
		printf("\n");
	}

	if (ap_single_view_diff_get_num_diffs(svd) > 0)
		ret_code = 1;
	ap_single_view_diff_destroy(svd);
	close_policy(p1);
	close_policy(p2);
	exit(ret_code);
}

