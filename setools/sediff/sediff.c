/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* sediff: command line tool semanitcally differentiating two policies.
 */
 
/* libapol */
#include "util.h"
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
#include <limits.h>
#include <unistd.h>

/* The following should be defined in the make environment */
#ifndef SEDIFF_VERSION_NUM
	#define SEDIFF_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004 Tresys Technology, LLC"
#define SEDIFF_GUI_PROG	"sediffx"

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
  {"gui", no_argument, NULL, 'X'},
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
  -X, --gui        launch the sediff gtk gui\n\
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
	if (fp == NULL || diff == NULL)
		return -1;
	fprintf(fp,"Total Differences:\n\tClasses & Permissions %d \n "
		"\tTypes %d \n\tAttributes %d \n\tRoles %d  \n\tUsers %d  \n\tBooleans %d"
		" \n\tTE Rules %d  \n\tRbac %d  \n",
		(diff->diff1->num_classes + diff->diff1->num_common_perms + diff->diff1->num_perms +
		 diff->diff2->num_classes + diff->diff2->num_common_perms + diff->diff2->num_perms),
		(diff->diff1->num_types + diff->diff2->num_types),
		(diff->diff1->num_attribs + diff->diff2->num_attribs),
		(diff->diff1->num_roles + diff->diff2->num_roles),
		(diff->diff1->num_users + diff->diff2->num_users),
		(diff->diff1->num_booleans + diff->diff2->num_booleans),
		(diff->diff1->te.num + diff->diff2->te.num),
		(diff->diff1->num_role_allow + diff->diff2->num_role_allow));
	return 0;
}

typedef int(*get_iad_name_fn_t)(int idx, char **name, policy_t *policy);

static int print_iad_element(char **string,int *string_sz,
			     int_a_diff_t *diff,policy_t *policy,bool_t added,
			     char *adescrp,get_iad_name_fn_t get_a_name)
{
	int i;
	char *tmp;
	int rt;
	char tbuf[APOL_STR_SZ+64];
	for (i = 0; i < diff->numa; i++) {
		rt = (*get_a_name)(diff->a[i], &tmp, policy);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, diff->a[i]);
			return -1;
		}
		if (added)
			sprintf(tbuf, "\t\t\t+ %s\n", tmp);
		else
		        sprintf(tbuf, "\t\t\t- %s\n", tmp);
		append_str(string,string_sz,tbuf);		
		free(tmp);
	}
	return 0;
}



/* print out a difference, in this case we consider everything in the p1 diff to be removed
   and everything in the p2 to be added, and everything in both to be changed*/
int print_iad(FILE *fp, int id, int_a_diff_t *iad_p1, int_a_diff_t *iad_p2,
		     policy_t *p1, policy_t *p2)
{
	get_iad_name_fn_t get_name, get_a_name;
	char *name, *descrp = NULL, *adescrp = NULL, *name2 = NULL;
	char *changed_buf = NULL, *added_buf = NULL, *removed_buf = NULL;
	int changed_sz = 0, removed_sz = 0, added_sz = 0;
	int num_removed = 0, num_added = 0, num_changed = 0;
	bool_t missing;
	int rt;
	int_a_diff_t *t = NULL, *u = NULL;
	char tbuf[APOL_STR_SZ+64];
	



/* now we want stats at all times even if emtpy list 	
  if(iad_p1 == NULL && iad_p2 == NULL ) 
		return 0;  indicates an empty list */

	if(fp == NULL || (p1 == NULL && p2 == NULL ) || !(id & (IDX_TYPE|IDX_ATTRIB|IDX_ROLE|IDX_USER|IDX_OBJ_CLASS|IDX_COMMON_PERM|IDX_ROLE)))
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
		descrp = "Role Allows";
		adescrp = "Role Allows";
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

	append_str(&added_buf,&added_sz,"\n");
	append_str(&changed_buf,&changed_sz,"\n");
	append_str(&removed_buf,&removed_sz,"\n");

	/* Handle only removed items */
	if (iad_p1 != NULL) {
		for (t = iad_p1; t != NULL; t = t->next) {
			rt = (*get_name)(t->idx, &name, p1);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
				goto print_iad_error;
			}
			missing = (t->a == NULL);
			if (missing){
				num_removed += 1;
				sprintf(tbuf, "\t\t- %s\n", name);
				append_str(&removed_buf,&removed_sz,tbuf);			     				 
			}
		}
		free(name);
	}

	/* Handle added items */
	/* Looking for items that are not in the old policy, hence indicating it was ADDED */
	if (iad_p2 != NULL) {
		/* Here we only take care of added items */
		for (t = iad_p2; t != NULL; t = t->next) {
			rt = (*get_name)(t->idx, &name, p2);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
				goto print_iad_error;
			}
			missing = (t->a == NULL);
			/* This means that the item exists only in the new policy */
			if (missing) {
				num_added += 1;
				sprintf(tbuf, "\t\t+ %s\n", name);
				append_str(&added_buf,&added_sz,tbuf);
			}	
			free(name);
		}
	}

	/* Handle Changed Items */
	if (iad_p2 != NULL) {
		t = iad_p2;
		/* did we remove anything ? */
		if (iad_p1 != NULL) {
			u = iad_p1;
			while (u != NULL || t != NULL) {
				/* do we still have items on both lists */
				if (t != NULL && u != NULL) {
					rt = (*get_name)(t->idx, &name, p2);
					if (rt < 0) {
						fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
						goto print_iad_error;
					}
					rt = (*get_name)(u->idx, &name2, p1);
					if (rt < 0) {
						fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
						goto print_iad_error;
					}
					rt = strcmp(name,name2);
					/* do both items have the same name(i.e. are they the same) */
					if (rt == 0){
						/* if the item is not missing, which would mean its in both policies */
						missing = (t->a == NULL);
						if (!missing) {
							num_changed +=1 ;
							sprintf(tbuf, "\t\t* %s (%d Added, %d Removed %s)\n", name,t->numa,u->numa, adescrp);
							append_str(&changed_buf,&changed_sz,tbuf);
							rt = print_iad_element(&changed_buf,&changed_sz,t,p2,TRUE,adescrp,get_a_name);
							if (rt < 0)
								goto print_iad_error;
							rt = print_iad_element(&changed_buf,&changed_sz,u,p1,FALSE,adescrp,get_a_name);
							if (rt < 0)
								goto print_iad_error;
						}
						u = u->next;
						t = t->next;
					}
					/* new goes first */
					else if ( rt < 0 ) {
						missing = (t->a == NULL);
						if (!missing) {
							num_changed +=1 ;
							sprintf(tbuf, "\t\t* %s (%d Added %s)\n", name, t->numa, adescrp);
							append_str(&changed_buf,&changed_sz,tbuf);
							rt = print_iad_element(&changed_buf,&changed_sz,t,p2,TRUE,adescrp,get_a_name);
							if (rt < 0)
								goto print_iad_error;
						}
						t = t->next;
					}
					/* old goes first */
					else {
						missing = (u->a == NULL);
						/* This means that the item exists in the new policy, so we indicate whether it has been changed. */
						if (!missing) {
							num_changed +=1 ;
							sprintf(tbuf, "\t\t* %s (%d Removed %s)\n", name2, u->numa, adescrp);
							append_str(&changed_buf,&changed_sz,tbuf);
							rt = print_iad_element(&changed_buf,&changed_sz,u,p1,FALSE,adescrp,get_a_name);
							if (rt < 0)
								goto print_iad_error;
						}						
						u = u->next;
					}					
					
				}
				/* do we only have additions left? */
				else if (t != NULL) {
					rt = (*get_name)(t->idx, &name, p2);
					if (rt < 0) {
						fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
						goto print_iad_error;
					}
					missing = (t->a == NULL);
					if (!missing) {
						num_changed +=1 ;
						sprintf(tbuf, "\t\t* %s (%d Added %s)\n", name, t->numa, adescrp);
						append_str(&changed_buf,&changed_sz,tbuf);
						rt = print_iad_element(&changed_buf,&changed_sz,t,p2,TRUE,adescrp,get_a_name);
						if (rt < 0)
							goto print_iad_error;
					}
					free(name);
					t = t->next;
				}
				/* do we only have removes left? */
				else {
					rt = (*get_name)(u->idx, &name, p1);
					if (rt < 0) {
						fprintf(stderr, "Problem getting name for %s %d\n", descrp, u->idx);
						goto print_iad_error;
					}
					missing = (u->a == NULL);
					/* This means that the item exists in the new policy, so we indicate whether it has been changed. */
					if (!missing) {
						num_changed +=1 ;
						sprintf(tbuf, "\t\t* %s (%d Removed %s)\n", name, u->numa, adescrp);
						append_str(&changed_buf,&changed_sz,tbuf);
						rt = print_iad_element(&changed_buf,&changed_sz,u,p1,FALSE,adescrp,get_a_name);
						if (rt < 0)
							goto print_iad_error;
					}
					free(name);
					u = u->next;
				}
			}
		}
		/* we have no removes just put in additions */
	        else {
			for (t = iad_p2; t != NULL; t = t->next) {
				rt = (*get_name)(t->idx, &name, p2);
				if (rt < 0) {
					fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
					goto print_iad_error;
				}
				missing = (t->a == NULL);
				if (!missing) {
					num_changed +=1 ;
					sprintf(tbuf, "\t\t* %s (%d Added %s)\n", name, t->numa, adescrp);
					append_str(&changed_buf,&changed_sz,tbuf);
					rt = print_iad_element(&changed_buf,&changed_sz,t,p2,TRUE,adescrp,get_a_name);
					if (rt < 0)
						goto print_iad_error;

				}
			}

		}
			
	}
	/* did we only remove  ? */
	else if (iad_p1 != NULL) {
		for (u = iad_p1; u != NULL; u = u->next) {
			rt = (*get_name)(u->idx, &name, p1);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, u->idx);
				goto print_iad_error;
			}
			missing = (u->a == NULL);
			/* This means that the item exists in the new policy, so we indicate whether it has been changed.  */
			if (!missing) {
				num_changed +=1 ;
				sprintf(tbuf, "\t\t* %s (%d Removed %s)\n", name, u->numa, adescrp);
				append_str(&changed_buf,&changed_sz,tbuf);
				rt = print_iad_element(&changed_buf,&changed_sz,u,p1,FALSE,adescrp,get_a_name);
				if (rt < 0)
					goto print_iad_error;

			}
			free(name);
		}

	}

	fprintf(fp,"%s (%d Added, %d Removed, %d Changed)\n"
		"\tAdded %s: %d%s"
		"\tRemoved %s: %d%s"
		"\tChanged %s: %d%s",
		descrp,num_added,num_removed,num_changed,
		descrp,num_added,added_buf,
		descrp,num_removed,removed_buf,
		descrp,num_changed,changed_buf);
	/* now print to the file */
	if (changed_buf)
		free(changed_buf);
	if (added_buf)
		free(added_buf);
	if (removed_buf)
		free(removed_buf);
	return 0;

	/*handle memory before we quit from an error */
 print_iad_error:
	if (changed_buf)
		free(changed_buf);
	if (added_buf)
		free(added_buf);
	if (removed_buf)
		free(removed_buf);
	return -1;

}



int print_type_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;

	rt = print_iad(fp, IDX_TYPE, diff->diff1->types, diff->diff2->types,  diff->p1, diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing types.\n");
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
	
	rt = print_iad(fp, IDX_ATTRIB, diff->diff1->attribs, diff->diff2->attribs, diff->p1, diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing attributes for p1.\n");
		return -1;
	}
	return 0;
}

int print_role_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	
	if(diff == NULL || fp == NULL)
		return -1;
	
	rt = print_iad(fp, IDX_ROLE, diff->diff1->roles,diff->diff2->roles, diff->p1, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing roles for p1.\n");
		return -1;
	}
	return 0;
}

int print_rbac_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	
	if(diff == NULL || fp == NULL)
		return -1;
	
	rt = print_iad(fp, IDX_ROLE|IDX_PERM, diff->diff1->role_allow,diff->diff2->role_allow, 
		       diff->p1, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing roles for p1.\n");
		return -1;
	}
	
	return 0;
}

int print_user_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;

	rt = print_iad(fp, IDX_USER, diff->diff1->users, diff->diff2->users, diff->p1, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing users for p1.\n");
		return -1;
	}
	return 0;
}

int print_boolean_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	bool_diff_t *t;
	char tbuf[APOL_STR_SZ+64];
	int num_changed = 0, num_removed = 0, num_added = 0;
	int changed_sz = 0, added_sz = 0, removed_sz = 0;
	char *changed_buf = NULL, *added_buf = NULL, *removed_buf = NULL;
	char *name = NULL;

	if(diff == NULL || fp == NULL)
		return -1;

	bool_diff_t *bools_removed = diff->diff1->booleans;
	bool_diff_t *bools_added = diff->diff2->booleans;
	bool_t state;

	append_str(&added_buf,&added_sz,"\n");
	append_str(&changed_buf,&changed_sz,"\n");
	append_str(&removed_buf,&removed_sz,"\n");



	/* Changed booleans */
	if (bools_removed != NULL) {
		for (t = bools_removed; t != NULL; t = t->next) {
			rt = get_cond_bool_name(t->idx, &name, diff->p1);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
				goto print_boolean_error;
			}
			if (t->state_diff) {
				num_changed += 1;
				sprintf(tbuf,"\t\t* %s (changed",name);
				append_str(&changed_buf,&changed_sz,tbuf);
				rt = get_cond_bool_default_val_idx(t->idx, &state, diff->p1);
				if (rt < 0) {
					fprintf(stderr, "Problem getting boolean state for %s\n", name);
					free(name);
					goto print_boolean_error;
				}
				sprintf(tbuf, " from %s to %s)\n", (state ? "TRUE" : "FALSE"), (state ? "FALSE" : "TRUE") );
				append_str(&changed_buf,&changed_sz,tbuf);
			}
			free(name);
		}
	}
	/* removed booleans */
	if (bools_removed != NULL) {
		for (t = bools_removed; t != NULL; t = t->next) {
			rt = get_cond_bool_name(t->idx, &name, diff->p1);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
				goto print_boolean_error;
			}
			if (!t->state_diff) {
				num_removed += 1;
				sprintf(tbuf, "\t\t- %s\n", name);
				append_str(&removed_buf,&removed_sz,tbuf);
			}
			free(name);
		}
	}
	/* added booleans */
	if (bools_added != NULL) {
		for (t = bools_added; t != NULL; t = t->next) {
			rt = get_cond_bool_name(t->idx, &name, diff->p2);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
				goto print_boolean_error;
			}
			if (!t->state_diff) {
				num_added += 1;
				sprintf(tbuf,  "\t\t+ %s\n", name);
				append_str(&added_buf,&added_sz,tbuf);
			}
			free(name);
		}
	}
	
	fprintf(fp, "Booleans (%d Added, %d Removed, %d Changed)\n",num_added,num_removed,num_changed);
	fprintf(fp,"\tAdded Booleans: %d%s"
		"\tRemoved Booleans: %d%s"
		"\tChanged Booleans: %d%s",
		num_added,added_buf,
		num_removed,removed_buf,
		num_changed,changed_buf);

	if (changed_buf)
		free(changed_buf);
	if (added_buf)
		free(added_buf);
	if (removed_buf)
		free(removed_buf);
	return 0;

	/*handle memory before we quit from an error */
 print_boolean_error:
	if (changed_buf)
		free(changed_buf);
	if (added_buf)
		free(added_buf);
	if (removed_buf)
		free(removed_buf);
	return -1;
}

int print_classes_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;
		
	rt = print_iad(fp, IDX_OBJ_CLASS, diff->diff1->classes, diff->diff2->classes, diff->p1, diff->p2);
	if(rt < 0){
		fprintf(stderr, "Problem printing classes for p1.\n");
		return -1;
	}
	return 0;	
}

int print_common_perms_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int rt;
	if(diff == NULL || fp == NULL)
		return -1;
		
	rt = print_iad(fp, IDX_COMMON_PERM, diff->diff1->common_perms, diff->diff2->common_perms, diff->p1, diff->p2);
	if(rt < 0) {
		fprintf(stderr, "Problem printing common permissions for p1.\n");
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
		
	fprintf(fp, "Permissions (%d Added, %d Removed)\n",diff->diff2->num_perms,diff->diff1->num_perms);
	fprintf(fp, "\tAdded Permissions: %d\n", diff->diff2->num_perms);
	for(i = 0; i < diff->diff2->num_perms; i++) {
		rt = get_perm_name(diff->diff2->perms[i], &name, diff->p2);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d in p2\n", diff->diff2->perms[i]);
			return -1;
		}
		fprintf(fp, "\t\t+ %s\n", name);
		free(name);
	}


	fprintf(fp, "\tRemoved Permissions: %d\n", diff->diff1->num_perms);
	for(i = 0; i < diff->diff1->num_perms; i++) {
		rt = get_perm_name(diff->diff1->perms[i], &name, diff->p1);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d in p1\n", diff->diff1->perms[i]);
			return -1;
		}
		fprintf(fp, "\t\t- %s\n", name);
		free(name);
	}
	return 0;	
}

static int print_te_rule(avh_node_t *cur, policy_t *policy, const char *string,
			 char **buf, int *sz)
{
	char *rule = NULL, *cond = NULL;
	/* this is kludgy but trying to get speed */
	char tbuf[APOL_STR_SZ*10];
	
	if (cur == NULL || policy == NULL) {
		return -1; 

	}
	if (cur->flags & AVH_FLAG_COND) {
		cond = re_render_avh_rule_cond_state(cur,policy);
	}
	/* print the rule */
	rule = re_render_avh_rule(cur, policy); 
	if (rule == NULL) { 
		return -1;
	} 
	sprintf(tbuf,"%s%s%s",cond == NULL ? " " : cond,string,rule);
	append_str(buf,sz,tbuf);
	free(rule); 
	if (cond != NULL) {
		free(cond);
		cond = NULL;
	}
	
	/* get the line # */
	rule = re_render_avh_rule_linenos(cur, policy); 
	if (rule != NULL) { 
		sprintf(tbuf,"(%s)", is_binary_policy(policy) ? "" : rule);
		append_str(buf,sz,tbuf);
		free(rule); 
	} 

	if (cur->flags & AVH_FLAG_COND && !is_binary_policy(policy)) {
		if (get_cond_bool_name(cur->cond_expr,&rule,policy) < 0) {
			return -1;
		}
		sprintf(tbuf," [ %s ] ",rule);
		append_str(buf,sz,tbuf);
		free(rule);
	}	
	append_str(buf,sz,"\n");
	return 0;
}

int print_te_diffs(FILE *fp, apol_diff_result_t *diff)
{
	int i,j;
	avh_node_t *cur = NULL;
	avh_node_t *cur2 = NULL;
	avh_node_t *diffcur1 = NULL;
	avh_node_t *diffcur2 = NULL;
	avh_key_t p2key,p1key;
	char *cond = NULL, *name=NULL;;
	int num_changed = 0, num_removed = 0, num_added = 0;
	int changed_sz = 0, added_sz = 0, removed_sz = 0;
	char *changed_buf = NULL, *added_buf = NULL, *removed_buf = NULL;
	apol_diff_t *diff1 = NULL, *diff2 = NULL;
	policy_t *policy1 = NULL, *policy2 = NULL;
	bool_t inverse;
	char tbuf[APOL_STR_SZ*10];
	
	if(diff == NULL || fp == NULL)
		goto print_te_error;

	diff1 = diff->diff1;
	diff2 = diff->diff2;
	policy1 = diff->p1;
	policy2 = diff->p2;

	append_str(&added_buf,&added_sz,"\n");
	append_str(&removed_buf,&removed_sz,"\n");
	append_str(&changed_buf,&changed_sz,"\n");

 	/* find removed */
 	for (i = 0; i < AVH_SIZE; i++) { 
 		for (diffcur1 = diff1->te.tab[i];diffcur1 != NULL; diffcur1 = diffcur1->next) { 
			cond = NULL;
 			/* make the p2 key */
 			make_p2_key(&diffcur1->key,&p2key,policy1,policy2); 
			/* search for the key/cond in p2, at this point we do not want to print out changes */
			cur2 = avh_find_first_node(&policy2->avh, &p2key);
			while (cur2 != NULL && does_cond_match(cur2,policy2,diffcur1,policy1,&inverse) == FALSE)
				cur2 = avh_find_next_node(cur2);
			/* is this key in policy 2? */
			if (cur2 != NULL) {
				/* now check to see if its in diff2 */
				diffcur2 = avh_find_first_node(&diff2->te, &p2key);
				while (diffcur2 != NULL && does_cond_match(diffcur1,policy1,diffcur2,policy2,&inverse) == FALSE)
					diffcur2 = avh_find_next_node(diffcur2);
				/* if diffcur2 == NULL then this rule is a changed rule 
				   with diffs in diff1 only, if its in diff2 we'll find it when
				   we loop through the diff2 struct later
				*/
				if (diffcur2 == NULL) {
					num_changed += 1;
					/* find the complete rule in p1 for printing out changes */
					cur = avh_find_first_node(&policy1->avh, &diffcur1->key);
					while (cur != NULL && does_cond_match(cur,policy1,diffcur1,policy1,&inverse) == FALSE)
						cur = avh_find_next_node(cur);					     
					if (print_te_rule(cur,policy1,"\t\t* Policy 1: ",&changed_buf,&changed_sz) < 0)
						goto print_te_error;
					if (print_te_rule(cur2,policy2,"\t\t* Policy 2: ",&changed_buf,&changed_sz) < 0)
						goto print_te_error;
					if (diffcur1->key.rule_type <= RULE_MAX_AV) {
						for (j = 0 ; j < diffcur1->num_data; j++) {
							if (get_perm_name(diffcur1->data[j],&name,policy1) == 0) {
								sprintf(tbuf," \t\t\t- %s\n",name);
								append_str(&changed_buf,&changed_sz,tbuf);
								free(name);
							}
						}
					}
					else {
						if (diffcur1->num_data == 1) {
							if (get_type_name(diffcur1->data[0],&name,policy1) == 0) {
								sprintf(tbuf," \t\t\t- %s\n",name);
								append_str(&changed_buf,&changed_sz,tbuf);
								free(name);
							}
						}
					}

				}

			}
			/* if the key is not in policy 2 at all */
			else if (!cur2) {
				/* update the number removed */
				num_removed += 1;
				if (print_te_rule(diffcur1,policy1,"\t\t- ",&removed_buf,&removed_sz) < 0)
					goto print_te_error;

 			} 
 		} 
 	} 
	/* find added and changed rules*/
	for (i = 0; i < AVH_SIZE; i++) {
		for (diffcur2 = diff2->te.tab[i];diffcur2 != NULL; diffcur2 = diffcur2->next) {

			/* make the p1 key */
			make_p2_key(&diffcur2->key,&p1key,policy2,policy1);

			/* now loop through policy 1 and find not only matching key but also matching 
			   conditional */			
			cur = avh_find_first_node(&policy1->avh, &p1key);
			while (cur != NULL && does_cond_match(cur,policy1,diffcur2,policy2,&inverse) == FALSE)
				cur = avh_find_next_node(cur);

			/* if the key was in policy1 this is a changed rule*/
			if (cur != NULL) {
				num_changed += 1;
				/* find the complete rule in policy 2 */
				cur2 = avh_find_first_node(&policy2->avh, &diffcur2->key);
				while (cur2 != NULL && does_cond_match(cur2,policy2,diffcur2,policy2,&inverse) == FALSE)
					cur2 = avh_find_next_node(cur2);
				if (cur2 == NULL)
					goto print_te_error;

				/* now that we have found the node in policy1 we know that the current
				   p2 node is at least in both, now we look in the p1 diff to see
				   if there were any changes in p1 */
				diffcur1 = avh_find_first_node(&diff1->te, &p1key);
				while (diffcur1 != NULL && does_cond_match(diffcur1,policy1,diffcur2,policy2,&inverse) == FALSE)
					diffcur1 = avh_find_next_node(diffcur1);

				if (print_te_rule(cur,policy1,"\t\t* Policy 1: ",&changed_buf,&changed_sz) < 0)
					goto print_te_error;
				if (print_te_rule(cur2,policy2,"\t\t* Policy 2: ",&changed_buf,&changed_sz) < 0)
					goto print_te_error;

				/* now print the diffs */
				if (diffcur2->key.rule_type <= RULE_MAX_AV) {
					for (j = 0 ; j < diffcur2->num_data; j++) {
						if (get_perm_name(diffcur2->data[j],&name,policy2) == 0) {
							sprintf(tbuf," \t\t\t+ %s\n",name);
							append_str(&changed_buf,&changed_sz,tbuf);
							free(name);
						}
					}
					if (diffcur1 != NULL) {
						for (j = 0 ; j < diffcur1->num_data; j++) {
							if (get_perm_name(diffcur1->data[j],&name,policy1) == 0) {
								sprintf(tbuf," \t\t\t- %s\n",name);
								append_str(&changed_buf,&changed_sz,tbuf);
								free(name);
							}
						}
					}
				}
				else {
					if (diffcur2->num_data == 1) {
						if (get_type_name(diffcur2->data[0],&name,policy2) == 0) {
							sprintf(tbuf," \t\t\t+ %s\n",name);
							append_str(&changed_buf,&changed_sz,tbuf);
							free(name);
						}
					}
					if (diffcur1 != NULL) {
						if(diffcur1->num_data == 1) {
							if (get_type_name(diffcur1->data[0],&name,policy1) == 0) {
								sprintf(tbuf," \t\t\t- %s\n",name);
								append_str(&changed_buf,&changed_sz,tbuf);
								free(name);
							}
						}
					}
				}
				append_str(&changed_buf,&changed_sz,"\n");
			}
			/* if the key is only in diff2 */
			else if (cur == NULL) {
				num_added += 1;
				if(print_te_rule(diffcur2,policy2,"\t\t+ ",&added_buf,&added_sz) < 0)
					goto print_te_error;

			}
		}
	}
	fprintf(fp,"TE Rules (%d Added, %d Removed, %d Changed)\n",
		num_added,num_removed,num_changed);
	fprintf(fp,"\tAdded TE Rules %d:%s"
		"\tRemoved TE Rules %d:%s"
		"\tChanged TE Rules %d:%s",
		num_added,added_buf,num_removed,removed_buf,num_changed,changed_buf);

	if (changed_buf)
		free(changed_buf);
	if (added_buf)
		free(added_buf);
	if (removed_buf)
		free(removed_buf);
       	return 0;

	/*handle memory before we quit from an error */
 print_te_error:
	printf("there was a te printing error");
	if (changed_buf)
		free(changed_buf);
	if (added_buf)
		free(added_buf);
	if (removed_buf)
		free(removed_buf);
	return -1;

}


int main (int argc, char **argv)
{
	int classes, types, roles, users, all, stats, optc, isids, conds, terules, rbac, bools, rt,gui;
	policy_t *p1, *p2;
	char *p1_file, *p2_file;
	apol_diff_result_t *diff;
	unsigned int opts = POLOPT_NONE;
	char prog_path[PATH_MAX];

	
	classes = types = roles = users = bools = all = stats = isids = conds = terules = rbac = gui = 0;
	while ((optc = getopt_long (argc, argv, "XctrubiTRCshv", longopts, NULL)) != -1)  {
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
				rt = execvp(prog_path,NULL);
			} else {
				rt = execvp(SEDIFF_GUI_PROG,NULL);
			}


		}
		/* launch the gui with file args */
		else if (argc - optind == 2) {
			rt = access(prog_path, X_OK);
			if (rt == 0) {
				rt = execvp(prog_path,&argv[optind]);
			} else {
				rt = execvp(SEDIFF_GUI_PROG,&argv[optind]);
			}			
		}
		if (argc - optind != 0 && argc - optind != 2) {
			usage(argv[0], 1);
			exit(1);
		}
		exit(1);
		/* otherwise execlp() won't ever return! */
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
	if(stats || all) {
		print_diff_stats(stdout, diff);
		printf("\n");
	}

	apol_free_diff_result(1, diff);
	exit(0);
}

