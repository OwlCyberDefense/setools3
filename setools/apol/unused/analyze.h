/* Copyright (C) 2001-2002 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* apolicy */

#ifndef _APOLICY_ANALYZE_H_
#define _APOLICY_ANALYZE_H_

#include "policy.h"
#include<stdio.h>


int print_av_rule(av_item_t *item, policy_t *policy, FILE *fp);
int print_av_rules(bool_t access, bool_t audit, policy_t *policy, FILE *fp);
int print_type(bool_t do_attribs, bool_t do_aliases, bool_t newline, int idx, policy_t *policy, FILE *fp);
int print_attrib(bool_t do_types, bool_t do_type_attribs, bool_t newline, bool_t upper, int idx, policy_t *policy, FILE *fp);
int print_type_analysis(bool_t do_types, bool_t type_attribs, bool_t do_attribs, bool_t attrib_types, 
			bool_t attrib_type_attribs, policy_t *policy, 	FILE *fp);
int print_policy_summary(policy_t *policy, FILE *fp);
int print_roles(bool_t do_types, int numperline,policy_t *policy, FILE *fp);
int print_role_allow_rules(policy_t *policy, FILE *fp);
int find_te_rules(int idx, int type, bool_t  include_audit, bool_t do_indirect, policy_t *policy, FILE *fp);
int print_tt_rules(policy_t *policy, FILE *fp);
int print_clone_rules(policy_t *policy, FILE *fp); 
int find_te_rules_by_src_tgt(int src_idx,int src_type,int tgt_idx,int tgt_type,bool_t include_audit,bool_t do_indirect,policy_t *policy,FILE *fp);
int find_types_by_two_attribs(int idx1, int idx2, bool_t full_info, policy_t *policy, FILE *fp);
int find_cloned_rules(int idx, bool_t include_audit, policy_t *policy, FILE *fp); 
int find_ta_using_substring(char *str, bool_t do_types, bool_t do_attribs, bool_t use_aliases, bool_t full_info, policy_t *policy, FILE *fp);		

#endif /*_APOLICY_ANALYZE_H_ */
