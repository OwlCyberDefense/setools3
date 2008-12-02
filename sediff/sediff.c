/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* sediff: command line tool semanitcally differentiating two policies.
 */
 
/* libapol */
#include <policy.h>
#include <policy-io.h>
#include <poldiff.h>
#include <render.h>
#include <binpol/binpol.h>
/* other */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#define _GNU_SOURCE
#include <getopt.h>

/* The following should be defined in the make environment */
#ifndef SEDIFF_VERSION_NUM
	#define SEDIFF_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004 Tresys Technology, LLC"

char *p1_file, *p2_file;

static struct option const longopts[] =
{
  {"classes", no_argument, NULL, 'c'},
  {"types", no_argument, NULL, 't'},
  {"roles", no_argument, NULL, 'r'},
  {"users", no_argument, NULL, 'u'},
  {"booleans", no_argument, NULL, 'b'},
  {"initialsids", no_argument, NULL, 'i'},
  {"terules", no_argument, NULL, 'T'},
  {"rbacrules", no_argument, NULL, 'R'},
  {"conds", no_argument, NULL, 'C'},
  {"stats", no_argument, NULL, 's'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};
 
void usage(const char *program_name, int brief)
{
	printf("%s (sediff ver. %s)\n\n", COPYRIGHT_INFO, SEDIFF_VERSION_NUM);
	printf("Usage: %s [OPTIONS] POLICY1 POLICY2\n", program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Semantically differentiate two policies.  The policies can be either source\n\
or binary policy files, version 15 or later.  By default, all supported\n\
policy elements are examined.  The following diff options are available:\n\
  -c, --classes    object class and permission definitions\n\
  -t, --types      type and attribute definitions\n\
  -r, --roles      role definitions\n\
  -u, --users      user definitions\n\
  -b, --booleans   boolean definitions and default values\n\
  -i, --initialsids initial SIDs (not currently supported)\n\
  -T, --terules    type enforcement rules\n\
  -R, --rbacrules  role rules\n\
  -C, --conds      conditionals and their rules\n\
 ", stdout);
	fputs("\n\
  -s, --stats      print useful policy statics\n\
  -h, --help       display this help and exit\n\
  -v, --version    output version information and exit\n\n\
", stdout);
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


int print_diff_stats(FILE *fp, apol_diff_result_t *diff)
{
	return 0;
}

typedef int(*get_iad_name_fn_t)(int idx, char **name, policy_t *policy);

int print_iad(FILE *fp, int_a_diff_t *iad, int id, policy_t *p)
{
	get_iad_name_fn_t get_name, get_a_name;
	char *name, *descrp = NULL, *adescrp = NULL;
	bool_t missing;
	int rt, i;
	int_a_diff_t *t;
	
	if(iad == NULL)
		return 0; /* indicates an empty list */
	
	if(fp == NULL || p == NULL || !(id & (IDX_TYPE|IDX_ATTRIB|IDX_ROLE|IDX_USER|IDX_OBJ_CLASS|IDX_COMMON_PERM|IDX_ROLE)))
		return -1;
	
	switch(id) {
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
		break;
	case IDX_ROLE|IDX_PERM:
		get_name = &get_role_name;
		get_a_name = &get_role_name;
		descrp = "Roles";
		adescrp = "Roles";
		break;
	case IDX_ROLE:
		get_name = &get_role_name;
		get_a_name = &get_type_name;
		descrp = "Roles";
		adescrp = "Types";
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
	for(t = iad; t != NULL; t = t->next) {
		missing = (t->a == NULL);
		rt = (*get_name)(t->idx, &name, p);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
			return -1;
		}
		fprintf(fp, "   %s (%s", name, (missing ? "missing" : "changed"));
		if(!missing)
			fprintf(fp, ", %d missing %s)\n", t->numa, adescrp);
		else
			fprintf(fp, ")\n");
		free(name);
		
		if(!missing) {
			/* do members not present in other policy */
			for(i = 0; i < t->numa; i++) {
				rt = (*get_a_name)(t->a[i], &name, p);
				if(rt < 0) {
					fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, t->a[i]);
					return -1;
				}
				fprintf(fp, "        %s\n", name);
				free(name);
			}
		}
		
	}
	
	return 0;
}

int print_type_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;

	fprintf(fp, "%d different TYPES in policy 1.\n", diff->diff1->num_types);
	rt = print_iad(fp, diff->diff1->types, IDX_TYPE, diff->p1);
	if(rt < 0) {
		fprintf(stderr, "Problem printing types for p1.\n");
		return -1;
	}
	fprintf(fp, "%d different TYPES in policy 2.\n", diff->diff2->num_types);
	rt = print_iad(fp, diff->diff2->types, IDX_TYPE, diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing types for p2.\n");
		return -1;
	}
	return 0;
}

int print_attrib_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	
	if(diff == NULL || fp == NULL)
		return -1;
	if(diff->bindiff)
		return 0; /* no attribs in a binary diff */
	
	fprintf(fp, "%d different ATTRIBS in policy 1.\n", diff->diff1->num_attribs);
	rt = print_iad(fp, diff->diff1->attribs, IDX_ATTRIB, diff->p1);
	if(rt < 0) {
		fprintf(stderr, "Problem printing attributes for p1.\n");
		return -1;
	}
	fprintf(fp, "%d different ATTRIBS in policy 2.\n", diff->diff2->num_attribs);
	rt = print_iad(fp, diff->diff2->attribs, IDX_ATTRIB, diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing attributes for p2.\n");
		return -1;
	}
	
	return 0;
}

int print_role_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	
	if(diff == NULL || fp == NULL)
		return -1;
	
	fprintf(fp, "%d different ROLES in policy 1.\n", diff->diff1->num_roles);
	rt = print_iad(fp, diff->diff1->roles, IDX_ROLE, diff->p1);
	if(rt < 0){
		fprintf(stderr, "Problem printing roles for p1.\n");
		return -1;
	}
	fprintf(fp, "%d different ROLES in policy 2.\n", diff->diff2->num_roles);
	rt = print_iad(fp, diff->diff2->roles, IDX_ROLE, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing roles for p2.\n");
		return -1;
	}
	
	return 0;
}

int print_rbac_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	
	if(diff == NULL || fp == NULL)
		return -1;
	
	fprintf(fp, "%d different ROLE ALLOWS in policy 1.\n", diff->diff1->num_role_allow);
	rt = print_iad(fp, diff->diff1->role_allow, IDX_ROLE|IDX_PERM, diff->p1);
	if(rt < 0){
		fprintf(stderr, "Problem printing roles for p1.\n");
		return -1;
	}
	fprintf(fp, "%d different ROLE ALLOWS in policy 2.\n", diff->diff2->num_role_allow);
	rt = print_iad(fp, diff->diff2->role_allow, IDX_ROLE|IDX_PERM, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing roles for p2.\n");
		return -1;
	}
	
	return 0;
}

int print_user_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;

	fprintf(fp, "%d different USERS in policy 1.\n", diff->diff1->num_users);
	rt = print_iad(fp, diff->diff1->users, IDX_USER, diff->p1);
	if(rt < 0){
		fprintf(stderr, "Problem printing users for p1.\n");
		return -1;
	}
	fprintf(fp, "%d different USERS in policy 2.\n", diff->diff2->num_users);
	rt = print_iad(fp, diff->diff2->users, IDX_USER, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing users for p2.\n");
		return -1;
	}
	return 0;
}

int print_boolean_diff(FILE *fp, bool_diff_t *bools, policy_t *p)
{
	bool_diff_t *t;
	int rt;
	char *name;
	bool_t state;
	
	if(bools == NULL)
		return 0; /* empty list */
	
	if(fp == NULL || p == NULL)
		return -1;
	
	for(t = bools; t != NULL; t = t->next) {
		rt = get_cond_bool_name(t->idx, &name, p);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
			return -1;
		}
		fprintf(fp, "   %s (%s", name, (t->state_diff ? "changed" : "missing"));
		if(t->state_diff) {
			rt = get_cond_bool_default_val_idx(t->idx, &state, p);
			if(rt < 0) {
				fprintf(stderr, "Problem getting boolean state for %s\n", name);
				free(name);
				return -1;
			}
			fprintf(fp, " from %s to %s)\n", (state ? "TRUE" : "FALSE"), (state ? "FALSE" : "TRUE") );
		}
		else
			fprintf(fp, ")\n");
		free(name);
	}
	
	return 0;
}

int print_boolean_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;
	
	fprintf(fp, "%d different BOOLEANS in policy 1.\n", diff->diff1->num_booleans);
	rt = print_boolean_diff(fp, diff->diff1->booleans, diff->p1);
	if(rt < 0){
		fprintf(stderr, "Problem printing booleans for p1.\n");
		return -1;
	}
	fprintf(fp, "%d different BOOLEANS in policy 2.\n", diff->diff2->num_booleans);
	rt = print_boolean_diff(fp, diff->diff2->booleans, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing booleans for p2.\n");
		return -1;
	}
	
	return 0;
}

int print_classes_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;
		

	fprintf(fp, "%d different CLASSES in policy 1.\n", diff->diff1->num_classes);
	rt = print_iad(fp, diff->diff1->classes, IDX_OBJ_CLASS, diff->p1);
	if(rt < 0){
		fprintf(stderr, "Problem printing classes for p1.\n");
		return -1;
	}
	fprintf(fp, "%d different CLASSES in policy 2.\n", diff->diff2->num_classes);
	rt = print_iad(fp, diff->diff2->classes, IDX_OBJ_CLASS, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing classes for p2.\n");
		return -1;
	}
	return 0;	
}

int print_common_perms_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;
		

	fprintf(fp, "%d different COMMON PERMISSIONS in policy 1.\n", diff->diff1->num_common_perms);
	rt = print_iad(fp, diff->diff1->common_perms, IDX_COMMON_PERM, diff->p1);
	if(rt < 0) {
		fprintf(stderr, "Problem printing common permissions for p1.\n");
		return -1;
	}
	
	fprintf(fp, "%d different COMMON PERMISSIONS in policy 2.\n", diff->diff2->num_common_perms);
	rt = print_iad(fp, diff->diff2->common_perms, IDX_COMMON_PERM, diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing common permissions for p2.\n");
		return -1;
	}
	return 0;	
}

int print_perms_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt, i;
	char *name;
	
	if(diff == NULL || fp == NULL)
		return -1;
		
	fprintf(fp, "%d different PERMISSIONS in policy 1.\n", diff->diff1->num_perms);
	for(i = 0; i < diff->diff1->num_perms; i++) {
		rt = get_perm_name(diff->diff1->perms[i], &name, diff->p1);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d in p1\n", diff->diff1->perms[i]);
			return -1;
		}
		fprintf(fp, "   %s (missing)\n", name);
		free(name);
	}
	
	fprintf(fp, "%d different PERMISSIONS in policy 2.\n", diff->diff2->num_perms);
	for(i = 0; i < diff->diff2->num_perms; i++) {
		rt = get_perm_name(diff->diff2->perms[i], &name, diff->p2);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d in p2\n", diff->diff2->perms[i]);
			return -1;
		}
		fprintf(fp, "   %s (missing)\n", name);
		free(name);
	}
	
	return 0;	
}

int print_te_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int i;
	avh_node_t *cur;
	char *rule;
	
	if(diff == NULL || fp == NULL)
		return -1;
	fprintf(fp, "%d different TE RULES in policy 1.\n", diff->diff1->te.num);
	for(i = 0; i < AVH_SIZE; i++) {
		for(cur = diff->diff1->te.tab[i]; cur != NULL; cur = cur->next) {
			rule = re_render_avh_rule_cond_state(cur, diff->p1);
			if(rule == NULL) {
				assert(0);
				return -1;
			}
			fprintf(fp, "   %s", rule);
			free(rule);
			
			rule = re_render_avh_rule(cur, diff->p1);
			if(rule == NULL) {
				assert(0);
				return -1;
			}
			fprintf(fp, "   %s", rule);
			free(rule);
			
			if(cur->flags & AVH_FLAG_COND) {
				fprintf(fp, " (cond = %d)", cur->cond_expr);
			}
			
			rule = re_render_avh_rule_linenos(cur, diff->p1);
			if(rule != NULL) {
				fprintf(fp, " (");
				fprintf(fp, "%s", rule);
				fprintf(fp, ")");
				free(rule);
			}
			fprintf(fp, "\n");
		}
	}
	
	fprintf(fp, "%d different TE RULES in policy 2.\n", diff->diff2->te.num);
	for(i = 0; i < AVH_SIZE; i++) {
		for(cur = diff->diff2->te.tab[i]; cur != NULL; cur = cur->next) {
			rule = re_render_avh_rule_cond_state(cur, diff->p2);
			if(rule == NULL) {
				assert(0);
				return -1;
			}
			fprintf(fp, "   %s", rule);
			free(rule);
			
			rule = re_render_avh_rule(cur, diff->p2);
			if(rule == NULL) {
				assert(0);
				return -1;
			}
			fprintf(fp, "   %s", rule);
			free(rule);
			
			if(cur->flags & AVH_FLAG_COND) {
				fprintf(fp, " (cond = %d)", cur->cond_expr);
			}
			
			rule = re_render_avh_rule_linenos(cur, diff->p2);
			if(rule != NULL) {
				fprintf(fp, " (");
				fprintf(fp, "%s", rule);
				fprintf(fp, ")");
				free(rule);
			}
			fprintf(fp, "\n");
		}
	}	
	
	
	return 0;
}


int main (int argc, char **argv)
{
	int classes, types, roles, users, all, stats, optc, isids, conds, terules, rbac, bools, rt;
	policy_t *p1, *p2;
	char *p1_file, *p2_file;
	apol_diff_result_t *diff;
	unsigned int opts = POLOPT_NONE;
	
	classes = types = roles = users = bools = all = stats = isids = conds = terules = rbac = 0;
	while ((optc = getopt_long (argc, argv, "ctrubiTRCshv", longopts, NULL)) != -1)  {
		switch (optc) {
		case 0:
	  		break;
	  	case 'c': /* classes */
	  		opts |= POLOPT_OBJECTS;
	  		classes = 1;
	  		break;
	  	case 't': /* types */
	  		opts |= POLOPT_TYPES;
	  		types = 1;
	  		break;
	  	case 'r': /* roles */
	  		opts |= POLOPT_ROLES;
	  		roles = 1;
	  		break;
	  	case 'u': /* users */
	  		opts = POLOPT_USERS;
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
	  	case 'R': /* rbac */
	  		opts |= POLOPT_RBAC;
	  		rbac = 1;
	  		break;
	  	case 'C': /* conditionals */
	  		opts |= POLOPT_COND_POLICY;
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
	  	default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}
	/* if no options, then show stats */
	if(classes + bools + types + roles + users + isids + terules + rbac + conds + stats < 1) {
		opts = POLOPT_ALL;
		all = 1;
	}
	if (argc - optind > 2 || argc - optind < 1) {
		usage(argv[0], 1);
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
	if(get_policy_version_id(p1) < POL_VER_12 ) {
		printf("Policy 1:  Unsupport version: Supported versions are Source (12 and higher), Binary (15 and higher).\n");
		exit(1);
	}

	/* diff and display requested info */
	diff = apol_diff_policies(opts, p1, p2);
	if(diff == NULL) {
		printf("Problem differentiating policies\n");
		exit(1);
	}
	
	printf("Difference between policy 1 and policy 2: \n");
	printf("   p1 (%6s, ver: %2d): %s\n", policy_type(diff->p1), get_policy_version_num(diff->p1), p1_file);
	printf("   p2 (%6s, ver: %2d): %s\n\n", policy_type(diff->p2), get_policy_version_num(diff->p2), p2_file);
	
	if(types || all) {
		print_type_diffs(stdout, diff);
		printf("\n");
		print_attrib_diffs(stdout, diff);
		if(!apol_is_bindiff(diff))
			printf("\n");
	}
	if(roles || all) {
		print_role_diffs(stdout, diff);
		printf("\n");
	}
	if(users || all) {
		print_user_diffs(stdout, diff);
		printf("\n");
	}
	if(bools || all) {
		print_boolean_diffs(stdout, diff);
		printf("\n");
	}
	if(classes || all) {
		print_classes_diffs(stdout, diff);
		printf("\n");
		print_perms_diffs(stdout, diff);
		printf("\n");
		print_common_perms_diffs(stdout, diff);
		printf("\n");
	}
	if(terules || all) {
		print_te_diffs(stdout, diff);
		printf("\n");
	}
	if(rbac || all) {
		print_rbac_diffs(stdout, diff);
		printf("\n");
	}

	apol_free_diff_result(1, diff);
	exit(0);
}

