 /* Copyright (C) 2001-2002 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* apolicy */

/* Functions to search through policy for desired information */

#include "util.h"
#include "policy.h"
#include "analyze.h"
#include "clone.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

extern char *rulenames[]; /* in policy.c*/


int print_policy_summary(policy_t *policy, FILE *fp)
{
	if(policy == NULL) {
		fprintf(stderr, "Error: printf_policy_summary give an invalid policy pointer\n");
		return -1;
	}
	fprintf(fp, "\nPolicy Summary\n\n");
	fprintf(fp, "Types: %d, Type Attributes: %d\n", policy->num_types, policy->num_attribs);
	fprintf(fp, "Type Enforcement Rules (%d rules total)\n", (policy->rule_cnt[RULE_TE_ALLOW] + policy->rule_cnt[RULE_NEVERALLOW] +
			policy->rule_cnt[RULE_AUDITALLOW] + policy->rule_cnt[RULE_AUDITDENY] + policy->rule_cnt[RULE_NOTIFY] +
			policy->rule_cnt[RULE_TE_TRANS] + policy->rule_cnt[RULE_TE_MEMBER] + policy->rule_cnt[RULE_TE_CHANGE] +
			policy->rule_cnt[RULE_CLONE]));
	fprintf(fp, "  AV Rules     TE Allow:   %4d     NeverAllow:  %4d\n", policy->rule_cnt[RULE_TE_ALLOW], policy->rule_cnt[RULE_NEVERALLOW]);
	fprintf(fp, "               AuditAllow: %4d     AuditDeny:   %4d      Notify:      %4d\n", policy->rule_cnt[RULE_AUDITALLOW], policy->rule_cnt[RULE_AUDITDENY], policy->rule_cnt[RULE_NOTIFY]);
	fprintf(fp, "  TT Rules     Type Trans: %4d     Type Member: %4d      Type Change  %4d\n", policy->rule_cnt[RULE_TE_TRANS], policy->rule_cnt[RULE_TE_MEMBER], policy->rule_cnt[RULE_TE_CHANGE]);
	fprintf(fp, "  Clone Rules  Clone:      %4d\n", policy->rule_cnt[RULE_CLONE]);
	fprintf(fp, "\n");
	fprintf(fp, "Roles: %d\n", policy->num_roles);
	fprintf(fp, "Role-based Access Control Rules (%d rules total)\n", policy->rule_cnt[RULE_ROLE_ALLOW]); 
	fprintf(fp, "  Role Allow:    %4d        Role Trans:   TBD       Role Dominance:   TBD\n", policy->rule_cnt[RULE_ROLE_ALLOW]);
	return 0;
}


int print_type(bool_t do_attribs, bool_t do_aliases, bool_t newline, int idx, policy_t *policy, FILE *fp)
{
	int j;
	if(idx >= policy->num_types) {
		fprintf(stderr, "Error: print_type given index (%d) larger than num_types (%d)\n", idx, policy->num_types);
		return -1;
	}
	fprintf(fp, "%s", policy->types[idx].name);
	
	if(do_aliases) {
		if(policy->types[idx].aliases != NULL) {
			name_item_t *ptr;
			fprintf(fp, ":");
			for(ptr = policy->types[idx].aliases; ptr != NULL; ptr = ptr->next) {
				fprintf(fp, "%s", ptr->name);
				if(ptr->next != NULL)
					fprintf(fp, ",");
			}
		}
	}
	
	if(do_attribs) {
		fprintf(fp, " (%d attributes)\n", policy->types[idx].num_attribs);
		for(j = 0; j < policy->types[idx].num_attribs; j++) {
			fprintf(fp, "\t%s\n", policy->attribs[policy->types[idx].attribs[j]].name);
		}
	}
	if(newline)
		fprintf(fp, "\n");	
	return 0;
}

int print_attrib(bool_t do_types, bool_t do_type_attribs, bool_t newline, bool_t upper, int idx, policy_t *policy, FILE *fp)
{
	int j, k;
	if(idx >= policy->num_attribs) {
		fprintf(stderr, "Error: print_attrib given index (%d) larger than num_attribs (%d)\n", idx, policy->num_attribs);
		return -1;
	}	
	if(upper) {
		char temp[BUF_SZ];
		fprintf(fp, "%s", uppercase(policy->attribs[idx].name, temp));
	}
	else
		fprintf(fp, "%s", policy->attribs[idx].name);
	if(do_types) {
		fprintf(fp, " (%d types)\n", policy->attribs[idx].num_types);
		for(j = 0; j < policy->attribs[idx].num_types; j++) {
			fprintf(fp, "\t%s", policy->types[policy->attribs[idx].types[j]].name);
			/* aliases */
			if(policy->types[policy->attribs[idx].types[j]].aliases != NULL) {
				name_item_t *ptr;
				fprintf(fp, ":");
				for(ptr = policy->types[policy->attribs[idx].types[j]].aliases; ptr != NULL; ptr = ptr->next) {
					fprintf(fp, " %s", ptr->name);
					if(ptr->next != NULL)
						fprintf(fp, ",");
				}
			}			
			if(do_type_attribs) {
				fprintf(fp, " { ");
				for(k = 0; k < policy->types[policy->attribs[idx].types[j]].num_attribs; k++) {
					if(strcasecmp(policy->attribs[idx].name, policy->attribs[policy->types[policy->attribs[idx].types[j]].attribs[k]].name) != 0)
						fprintf(fp, "%s ", policy->attribs[policy->types[policy->attribs[idx].types[j]].attribs[k]].name);
				}
				fprintf(fp, "}");
			}
			fprintf(fp, "\n");
		}
	}
	if(newline)
		fprintf(fp, "\n");		
	return 0;	
}

static bool_t type_contains_attrib(int type_idx, int attrib_idx, policy_t *policy)
{
	int i;
	
	if(policy == NULL || type_idx >= policy->num_types )
		return 0;
	for(i = 0; i < policy->types[type_idx].num_attribs; i++) {
		if(attrib_idx == policy->types[type_idx].attribs[i])
			return 1;
	}
	return 0;
}


/* find and print all types that contain a given attribute */
int find_types_by_two_attribs(int idx1, int idx2, bool_t full_info, policy_t *policy, FILE *fp)
{
	int i;
	
	fprintf(fp, "All TYPES that have the following two attributes: ");
	if(print_attrib(0,0,0,1, idx1, policy, fp) != 0)
		return -1;
	fprintf(fp, " & ");
	if(print_attrib(0,0,1,1, idx2, policy, fp) != 0)
		return -1;
	fprintf(fp, "\n");

	for(i = 0; i < policy->num_types; i++) {
		if(type_contains_attrib(i, idx1, policy) && type_contains_attrib(i, idx2, policy)) {
			if(full_info){
				if(print_type(1, 1, 1, i, policy, fp) != 0)
					return -1;
			}
			else {
				if(print_type(0, 1, 1, i, policy, fp) != 0)
					return -1;
			}
		}
	}	
	return 0;
}

int find_ta_using_substring(char *str,
			bool_t do_types, 
			bool_t do_attribs, 
			bool_t use_aliases,
			bool_t full_info, 
			policy_t *policy,
			FILE *fp
			)
{
	int i;
	
	if(!(do_types || do_attribs))
		return -1;
	
	if(do_types) {
		fprintf(fp, "\n\nType ");
		if(do_attribs) {
			fprintf(fp, "and Type Attribute ");
		}
	}
	else {
		fprintf(fp, "\n\nType Attribute ");
	}
	fprintf(fp, "names containing the substring: %s\n", str);
	
	if(do_types) {
		fprintf(fp, "\n\nTYPES:\n");
		for(i = 0; i < policy->num_types; i++) {
			if(strstr(policy->types[i].name, str) != NULL) {
				print_type(full_info, 1, 1, i, policy, fp);
			}
			else if(use_aliases) {
				name_item_t *ptr;
				for(ptr = policy->types[i].aliases; ptr != NULL; ptr = ptr->next) {
					if(strstr(ptr->name, str) != NULL)
						print_type(full_info, 1, 1, i, policy, fp);
				}
			}		
		}
	}
	
	if(do_attribs) {
		fprintf(fp, "\n\nTYPE ATTRIBUTES:\n");
		for(i = 0; i < policy->num_attribs; i++) {
			if(strstr(policy->attribs[i].name, str) != NULL) {
				print_attrib(full_info, 1, 1, 0, i, policy, fp);
			}						
		}
	}
	
	return 0;
}


/* print all types and attribs base on options selected */
int print_type_analysis(bool_t do_types, 	/* print types?*/
			bool_t type_attribs,	/* print types' attributes?, ignore if types=0 */
			bool_t do_attribs,	/* print attributes? */
			bool_t attrib_types, 	/* print attrib's types?, ignore if attribs=0 */
			bool_t attrib_type_attribs, /* for attrib's type?, include other attribs; ignore if attribs = 0*/
			policy_t *policy,
			FILE *fp)
{
	int i;
	
	if(do_types) {
		fprintf(fp, "\n\nTYPES (%d):\n", policy->num_types);
		for(i = 0; i < policy->num_types; i++) {
			fprintf(fp, "%d: ", i+1);
			print_type(type_attribs, 1, 1, i, policy, fp);
		}
	}
	
	if(do_attribs) {
		fprintf(fp, "\n\nTYPE ATTRIBUTES (%d):\n", policy->num_attribs);
		for(i = 0; i < policy->num_attribs; i++) {
			fprintf(fp, "%d: ", i+1);
			print_attrib(attrib_types, attrib_type_attribs, 1, 0, i, policy, fp);
		}
	}	
	return 0;
}

static int print_role(bool_t		do_types,
		int		numperline,
		bool_t		newline,
		int		idx,
		policy_t	*policy,
		FILE		*fp)
{
	bool_t no_nl = 0;
	int j;

	if(idx >= policy->num_roles) {
		fprintf(stderr, "Error: print_roles given index (%d) larger than num_roles (%d)\n", idx, policy->num_roles);
		return -1;
	}	
	if(numperline < 1)
		no_nl = 1;	
	
	fprintf(fp, "%s", policy->roles[idx].name);
	if(do_types) {
		div_t x;
		fprintf(fp, " (%d types)\n     ", policy->roles[idx].num_types);
		for(j = 0; j < policy->roles[idx].num_types; j++) {
			/* control # of types per line */
			if(!no_nl && j != 0) {
				x = div(j, numperline);
				if(x.rem == 0) {
					fprintf(fp, "\n     ");
				}
			}
			fprintf(fp, "%s  ", policy->types[policy->roles[idx].types[j]].name);
		}	
	}
	
	if(newline)
		fprintf(fp, "\n");	
	return 0;
	
}


int print_roles(bool_t 		do_types,	/* print role types? */
		int		numperline,	/* number of types to print per line */
		policy_t 	*policy,
		FILE 		*fp)
{
	int i, rt;

	fprintf(fp, "\n\nROLES (%d):\n", policy->num_roles);
	for(i = 0; i < policy->num_roles; i++) {
		fprintf(fp, "%d: ", i+1);
		rt = print_role(do_types, numperline, 1, i, policy, fp);
		if(rt !=0 )
			return rt;
	}
	return 0;
}


int print_role_allow_rule(role_allow_t *rule, policy_t *policy, FILE *fp)
{
	ta_item_t *tptr;	
	int multiple = 0;
	
	fprintf(fp, "%s", rulenames[RULE_ROLE_ALLOW]);

	/* source roles */
	if(rule->flags & AVFLAG_SRC_TILDA) 
		fprintf(fp, " ~");
	else
		fprintf(fp, " ");
	if(rule->src_roles != NULL && rule->src_roles->next != NULL) {
		multiple = 1;
		fprintf(fp, "{");
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		fprintf(fp, "*");
	
	for(tptr = rule->src_roles; tptr != NULL; tptr = tptr->next) {
		if(tptr->type != IDX_ROLE) {
			fprintf(stderr, "Invalid role type: %d\n", tptr->type);
			return -1;			
		}
		fprintf(fp, " ");
		if(print_role(0, 0, 0, tptr->idx, policy, fp) != 0) {
			return -1;
		}
	}
	if(multiple) {
		fprintf(fp, " }");
		multiple = 0;
	}

	/* tgt roles */
	if(rule->flags & AVFLAG_TGT_TILDA) 
		fprintf(fp, " ~");
	else
		fprintf(fp, " ");
	if(rule->tgt_roles != NULL && rule->tgt_roles->next != NULL) {
		multiple = 1;
		fprintf(fp, "{");
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		fprintf(fp, "*");
	
	for(tptr = rule->tgt_roles; tptr != NULL; tptr = tptr->next) {
		if(tptr->type != IDX_ROLE) {
			fprintf(stderr, "Invalid role type: %d\n", tptr->type);
			return -1;			
		}
		fprintf(fp, " ");
		if(print_role(0, 0, 0, tptr->idx, policy, fp) != 0) {
			return -1;
		}
	}
	if(multiple) {
		fprintf(fp, " }");
		multiple = 0;
	}
	
	
	fprintf(fp, ";\n");
	
	return 0;
}


int print_role_allow_rules(policy_t *policy, FILE *fp)
{
	int i;
	fprintf(fp, "\n\nRole Allow Rules (%d rules)\n", policy->num_role_allow);	
	for(i = 0; i < policy->num_role_allow; i++) {
		fprintf(fp, "%d: ", i+1);
		print_role_allow_rule(&(policy->role_allow[i]), policy, fp);
	}
	return 0;
}


						
static int print_name_list(name_item_t *list, 
					bool_t iscls,		/* 1 if list is classes, 0 if not (i.e., permissions) */
					unsigned char flags, /* from av_item_t object */
					FILE *fp)
{
	name_item_t *ptr;
	int multiple = 0;

	if(flags & (iscls ? AVFLAG_CLS_TILDA : AVFLAG_PERM_TILDA)) 
		fprintf(fp, " ~");
	else
		fprintf(fp, " ");
	if(list != NULL && list->next != NULL) {
		multiple = 1;
		fprintf(fp, "{ ");
	}
	if(flags & (iscls ? AVFLAG_CLS_STAR : AVFLAG_PERM_STAR))
		fprintf(fp, "* ");	
		
	for(ptr = list; ptr != NULL; ptr = ptr->next) {
		fprintf(fp, "%s ", ptr->name);
	}
	
	if(multiple) {
		fprintf(fp, "}");
	}
	return 0;	
}

int print_clone_rule(cln_item_t *rule, policy_t *policy, FILE *fp)
{
	int rt;
	fprintf(fp, "%s ", rulenames[RULE_CLONE]);
	rt = print_type(0,0,0, rule->src, policy, fp);
	if(rt != 0)
		return rt;
	fprintf(fp, " ");
	rt = print_type(0,0,0, rule->tgt, policy, fp);
	if(rt != 0)
		return rt;	
	printf("\n");
	return 0;
}


int print_clone_rules(policy_t *policy, FILE *fp)
{
	cln_item_t *ptr;
	int rt, i;

	fprintf(fp, "\n\nClone Rules (%d rules)\n", policy->rule_cnt[RULE_CLONE]);
	for(ptr = policy->clones, i = 1; ptr != NULL; ptr = ptr->next, i++) {
		fprintf(fp, "%d: ", i);
		rt = print_clone_rule(ptr, policy, fp);
		if(rt != 0)
			return rt;
	}
	return 0;
}

int print_av_rule(av_item_t *item, policy_t *policy, FILE *fp) 
{
	ta_item_t *tptr;	
	int multiple = 0;
	
	fprintf(fp, "%s", rulenames[item->type]);
	
	/* source types */
	if(item->flags & AVFLAG_SRC_TILDA) 
		fprintf(fp, " ~");
	else
		fprintf(fp, " ");
	if(item->src_types != NULL && item->src_types->next != NULL) {
		multiple = 1;
		fprintf(fp, "{");
	}
	if(item->flags & AVFLAG_SRC_STAR)
		fprintf(fp, "*");
	
	for(tptr = item->src_types; tptr != NULL; tptr = tptr->next) {
		if(tptr->type == IDX_TYPE) {
			fprintf(fp, " ");
			if(print_type(0, 0, 0, tptr->idx, policy, fp) != 0)
				return -1;
		}
		else if(tptr->type == IDX_ATTRIB) {
			fprintf(fp, " ");
			if(print_attrib(0, 0, 0, 1, tptr->idx, policy, fp) != 0)
				return -1;
		}			
		else {
			fprintf(stderr, "Invalid index type: %d\n", tptr->type);
			return -1;
		}
	}
	if(multiple) {
		fprintf(fp, " }");
		multiple = 0;
	}
	
	/* tgt types */
	if(item->flags & AVFLAG_TGT_TILDA) 
		fprintf(fp, " ~");
	else
		fprintf(fp, " ");
	if(item->tgt_types != NULL && item->tgt_types->next != NULL) {
		multiple = 1;
		fprintf(fp, "{");
	}
	if(item->flags & AVFLAG_TGT_STAR)
		fprintf(fp, "*");
	
	for(tptr = item->tgt_types; tptr != NULL; tptr = tptr->next) {
		if(tptr->type == IDX_TYPE) {
			fprintf(fp, " ");
			if(print_type(0,0, 0, tptr->idx, policy, fp) != 0)
				return -1;
		}
		else if(tptr->type == IDX_ATTRIB) {
			fprintf(fp, " ");
			if(print_attrib(0, 0, 0, 1, tptr->idx, policy, fp) != 0)
				return -1;
		}			
		else {
			fprintf(stderr, "Invalid index type: %d\n", tptr->type);
			return -1;
		}
	}
	if(multiple) {
		fprintf(fp, " }");
		multiple = 0;
	}
	fprintf(fp, " :");
	
	/* classes */
	if(print_name_list(item->classes, 1, item->flags, fp) != 0)
		return -1;
		
	/* permissions */
	if(print_name_list(item->perms, 0, item->flags, fp) != 0)
		return -1;
				
	fprintf(fp, "\n");
	return 0;
}

int print_tt_rule(tt_item_t *item, policy_t *policy, FILE *fp)
{
	ta_item_t *tptr;	
	int multiple = 0;
	
	fprintf(fp, "%s", rulenames[item->type]);

	/* source types */
	if(item->flags & AVFLAG_SRC_TILDA) 
		fprintf(fp, " ~");
	else
		fprintf(fp, " ");
	if(item->src_types != NULL && item->src_types->next != NULL) {
		multiple = 1;
		fprintf(fp, "{");
	}
	if(item->flags & AVFLAG_SRC_STAR)
		fprintf(fp, "*");
	
	for(tptr = item->src_types; tptr != NULL; tptr = tptr->next) {
		if(tptr->type == IDX_TYPE) {
			fprintf(fp, " ");
			if(print_type(0, 0, 0, tptr->idx, policy, fp) != 0)
				return -1;
		}
		else if(tptr->type == IDX_ATTRIB) {
			fprintf(fp, " ");
			if(print_attrib(0, 0, 0, 1, tptr->idx, policy, fp) != 0)
				return -1;
		}			
		else {
			fprintf(stderr, "Invalid index type: %d\n", tptr->type);
			return -1;
		}
	}
	if(multiple) {
		fprintf(fp, " }");
		multiple = 0;
	}

	/* tgt types */
	if(item->flags & AVFLAG_TGT_TILDA) 
		fprintf(fp, " ~");
	else
		fprintf(fp, " ");
	if(item->tgt_types != NULL && item->tgt_types->next != NULL) {
		multiple = 1;
		fprintf(fp, "{");
	}
	if(item->flags & AVFLAG_TGT_STAR)
		fprintf(fp, "*");
	
	for(tptr = item->tgt_types; tptr != NULL; tptr = tptr->next) {
		if(tptr->type == IDX_TYPE) {
			fprintf(fp, " ");
			if(print_type(0, 0, 0, tptr->idx, policy, fp) != 0)
				return -1;
		}
		else if(tptr->type == IDX_ATTRIB) {
			fprintf(fp, " ");
			if(print_attrib(0, 0, 0, 1, tptr->idx, policy, fp) != 0)
				return -1;
		}			
		else {
			fprintf(stderr, "Invalid index type: %d\n", tptr->type);
			return -1;
		}
	}
	if(multiple) {
		fprintf(fp, " }");
		multiple = 0;
	}
	fprintf(fp, " :");
	
	/* classes */
	if(print_name_list(item->classes, 1, item->flags, fp) != 0)
		return -1;
		
	/* default type */
	if(item->dflt_type.type == IDX_TYPE) {
		fprintf(fp, " ");
		if(print_type(0, 0, 1, item->dflt_type.idx, policy, fp) != 0)
			return -1;
	}
	else if(item->dflt_type.type == IDX_ATTRIB) {
		fprintf(fp, " ");
		if(print_attrib(0, 0, 1, 1, item->dflt_type.idx, policy, fp) != 0)
			return -1;
	}			
	else {
		fprintf(stderr, "Invalid index type: %d\n", item->dflt_type.type);
		return -1;
	}	
	
	return 0;
}


int print_av_rules(	bool_t access,		/* print access rules (allow, neverallow) */
			bool_t audit,		/* printf audit rules (audit[allow|deny], notify */
			policy_t *policy,
			FILE *fp
			)
{
	int i;
	if(access) {
		fprintf(fp, "\n\nTE Access Rules (%d rules)\n", policy->num_av_access);
		for(i = 0; i < policy->num_av_access; i++) {
			fprintf(fp, "%d: ", i+1);
			print_av_rule(&(policy->av_access[i]), policy, fp);
		}
	}
	if(audit) {
		fprintf(fp, "\n\nTE Audit Rules (%d rules)\n", policy->num_av_audit);
		for(i = 0; i < policy->num_av_audit; i++) {
			fprintf(fp, "%d: ", i+1);
			print_av_rule(&(policy->av_audit[i]), policy, fp);
		}
	}	
	return 0;	
}

int print_tt_rules(policy_t *policy, FILE *fp)
{
	int i;
	fprintf(fp, "\n\nType Transition|Member|Change Rules (%d rules)\n", policy->num_te_trans);	
	for(i = 0; i < policy->num_te_trans; i++) {
		fprintf(fp, "%d: ", i+1);
		print_tt_rule(&(policy->te_trans[i]), policy, fp);
	}
	return 0;
}



/* top-level find function for a single type  as either source or target */
int find_te_rules(int idx,				/* idx of type/attribute*/
                  int type,				/* whether a type or attribute */
                  bool_t  include_audit, 	/* if set, also include av_audit rules */
                  bool_t  do_indirect,
                  policy_t *policy,
                  FILE *fp
                  ) 		
{
	int i;
	rules_bool_t rules_b;
	
	if(init_rules_bool(include_audit, &rules_b, policy) != 0)
		return -1;
		
	if(match_te_rules(idx, type, include_audit, BOTH_LISTS, do_indirect, &rules_b, policy) != 0) {
		free_rules_bool(&rules_b);
		return -1;
	}
	
	
	/* print the results */
	if(type == IDX_TYPE) {
		fprintf(fp, "\n\nRules involving the following TYPE: ");
		print_type(0,1, 1, idx, policy, fp);
		fprintf(fp, "\n");
	}
	else if(type == IDX_TYPE) {
		fprintf(fp, "\n\nRules involving the following TYPE ATTRIBUTE: ");
		print_attrib(0,0,1,0, idx, policy, fp);
		fprintf(fp, "\n");
	}
	else {
		fprintf(fp, "\n\nInvalid Index type (%d), neither Type nor Atrtribute!\n", type);
	}
		
	fprintf(fp, "\nAV Access Rules  (%d)\n", rules_b.ac_cnt);
	for(i = 0; i < policy->num_av_access && rules_b.ac_cnt > 0; i++) {
		if(rules_b.access[i]) {
			rules_b.ac_cnt--;
			fprintf(fp, "%d: ", i+1);			
			print_av_rule(&(policy->av_access[i]), policy, fp);
		}
	}
	if(include_audit) {	
		fprintf(fp, "\n\nAV Audit Rules(%d)\n", rules_b.au_cnt);
		for(i = 0; i < policy->num_av_audit && rules_b.au_cnt > 0; i++) {
			if(rules_b.audit[i]) {
				rules_b.au_cnt--;
				fprintf(fp, "%d: ", i+1);			
				print_av_rule(&(policy->av_audit[i]), policy, fp);
			}
		}	
	}
	fprintf(fp, "\n\nType Transition Rules (%d)\n", rules_b.tt_cnt);
	for(i = 0; i < policy->num_te_trans && rules_b.tt_cnt > 0; i++) {
		if(rules_b.ttrules[i]) {
			rules_b.tt_cnt--;
			fprintf(fp, "%d: ", i+1);
			print_tt_rule(&(policy->te_trans[i]), policy, fp);
		}
	}
	
	free_rules_bool(&rules_b);	
	return 0;
}

/* This function allows two types/attribs to be provided, but specified as either
 * src or target.  Either src_idx or tgt_idx may be -1, which means that only src
 * (or tgt) is being used to search by.  Both src and tgt idx's cannot be -1.  If
 * both are >=0, then only rules that have both src and tgt in their respective fields
 * will match */
/* FIX: deal with clone rules */
int find_te_rules_by_src_tgt(int src_idx,				
                  			int src_type,			
                  			int tgt_idx,				
                  			int tgt_type,			
                  			bool_t  include_audit, 	
                  			bool_t  do_indirect, 
                  			policy_t *policy,
                  			FILE *fp
                  			) 
{
	int i;
	
	rules_bool_t rules_src, rules_tgt;
	if(src_idx < 0 && tgt_idx < 0)
		goto err_return;
	
	if(init_rules_bool(include_audit, &rules_src, policy) != 0)
		goto err_return;
	if(init_rules_bool(include_audit, &rules_tgt, policy) != 0)
		goto err_return;
		
	if(src_idx >= 0) {
		if(match_te_rules(src_idx, src_type, include_audit, SRC_LIST, do_indirect, &rules_src, policy) != 0) 
			goto err_return;
	}
	else {
		all_true_rules_bool(&rules_src, policy);
	}
	
	if(tgt_idx >= 0) {
		if(match_te_rules(tgt_idx, tgt_type, include_audit, TGT_LIST, do_indirect, &rules_tgt, policy) != 0) 
			goto err_return;
	}
	else {
		all_true_rules_bool(&rules_tgt, policy);
	}
	
	/* print the results */

	if(src_idx >= 0 && tgt_idx >= 0)
		fprintf(fp, "\n\nRules involving the following two types or type attributes: \n\n");
	else if (src_idx < 0)
		fprintf(fp, "\n\nRules involving the following TARGET type or type attribute: \n\n");
	else
		fprintf(fp, "\n\nRules involving the following SOURCE type or type attribute: \n\n");
		
	if(src_idx >= 0) {
		if(src_type == IDX_TYPE) {
			fprintf(fp, "SOURCE is a TYPE: ");
			print_type(0, 1, 1, src_idx, policy, fp);
		}
		else if(src_type == IDX_ATTRIB) {
			fprintf(fp, "SOURCE is a TYPE ATTRIBUTE: ");
			print_attrib(0, 0, 1, 0, src_idx, policy, fp);
		}	
		else {
			fprintf(fp, "Invalid source type (%d), neither Type nor Attribute\n", src_type);
		}
	}
	
	if(tgt_idx >= 0) {
		if(tgt_type == IDX_TYPE ){
			fprintf(fp, "TARGET is a TYPE: ");
			print_type(0, 1, 1, tgt_idx, policy, fp);
		}
		else if(tgt_type == IDX_ATTRIB) {
			fprintf(fp, "TARGET is a TYPE ATTRIBUTE: ");
			print_attrib(0, 0, 1, 0, tgt_idx, policy, fp);
		}
		else {
			fprintf(fp, "Invalid target type (%d), neither Type nor Attribute\n", tgt_type);
		}
	}
		
	fprintf(fp, "\nAV Access Rules\n");
	for(i = 0; i < policy->num_av_access ; i++) {
		if(rules_src.access[i] && rules_tgt.access[i]) {
			fprintf(fp, "%d: ", i+1);			
			print_av_rule(&(policy->av_access[i]), policy, fp);
		}
	}
	if(include_audit) {	
		fprintf(fp, "\n\nAV Audit Rules\n");
		for(i = 0; i < policy->num_av_audit; i++) {
			if(rules_src.audit[i] && rules_tgt.audit[i]) {
				fprintf(fp, "%d: ", i+1);			
				print_av_rule(&(policy->av_audit[i]), policy, fp);
			}
		}	
	}
	fprintf(fp, "\n\nType Transition Rules\n");
	for(i = 0; i < policy->num_te_trans; i++) {
		if(rules_src.ttrules[i] && rules_tgt.ttrules[i]) {
			fprintf(fp, "%d: ", i+1);
			print_tt_rule(&(policy->te_trans[i]), policy, fp);
		}
	}
	
	free_rules_bool(&rules_src);	
	free_rules_bool(&rules_tgt);
	return 0;
	
err_return:
	free_rules_bool(&rules_src);	
	free_rules_bool(&rules_tgt);
	return -1;
}	

/* find & display cloned rules for a given type */
int find_cloned_rules(int idx,				/* idx of type being cloned*/
                  bool_t  include_audit, 	/* if set, also include av_audit rules */
                  policy_t *policy,
                  FILE *fp
                  ) 		
{
	int i;
	rules_bool_t rules_b;
	
	if(init_rules_bool(include_audit, &rules_b, policy) != 0)
		return -1;
		
	if(match_cloned_rules(idx, include_audit, &rules_b, policy) != 0) {
		free_rules_bool(&rules_b);
		return -1;
	}
	/* print the results */
	
	fprintf(fp, "\n\nRules CLONED for the following type: ");
	print_type(0,1, 1, idx, policy, fp);
	fprintf(fp, "\n");
		
	fprintf(fp, "\nAV Access Rules  (%d)\n", rules_b.ac_cnt);
	for(i = 0; i < policy->num_av_access && rules_b.ac_cnt > 0; i++) {
		if(rules_b.access[i]) {
			rules_b.ac_cnt--;
			fprintf(fp, "%d: ", i+1);			
			print_av_rule(&(policy->av_access[i]), policy, fp);
		}
	}
	if(include_audit) {	
		fprintf(fp, "\n\nAV Audit Rules(%d)\n", rules_b.au_cnt);
		for(i = 0; i < policy->num_av_audit && rules_b.au_cnt > 0; i++) {
			if(rules_b.audit[i]) {
				rules_b.au_cnt--;
				fprintf(fp, "%d: ", i+1);			
				print_av_rule(&(policy->av_audit[i]), policy, fp);
			}
		}	
	}
	fprintf(fp, "\n\nType Transition Rules (%d)\n", rules_b.tt_cnt);
	for(i = 0; i < policy->num_te_trans && rules_b.tt_cnt > 0; i++) {
		if(rules_b.ttrules[i]) {
			rules_b.tt_cnt--;
			fprintf(fp, "%d: ", i+1);
			print_tt_rule(&(policy->te_trans[i]), policy, fp);
		}
	}
	
	free_rules_bool(&rules_b);	
	return 0;
}

