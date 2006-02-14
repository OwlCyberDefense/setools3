/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* policy-query.h
 *
 * policy query/search functions
 */
#ifndef _APOLICY_POLICY_QUERY_H_
#define _APOLICY_POLICY_QUERY_H_

#include <regex.h>
#include <errno.h>
#include "policy.h"


typedef struct srch_type {
	bool_t	indirect;	/* include matches for assoicated attributes (if type) */	
	/* NOTE: Since the search can take a regex or type/attrib, we must have the 
	 * ta specified as a string rather than an idx */
	char	*ta;		/* type/attrib string, NULL if unused, can be regex*/
	int	t_or_a	;	/* Used only for regex searches, can be IDX_TYPE, IDX_ATTRIB, or IDX_BOTH */
} srch_type_t;

typedef struct teq_query {
	#define TEQ_NONE	0x0
	#define	TEQ_ALLOW	0x00000001
	#define	TEQ_NEVERALLOW	0x00000002
	#define	TEQ_AUDITALLOW	0x00000004
	#define TEQ_DONTAUDIT	0x00000008
	#define TEQ_AUDITDENY	0x00000008	/* same as dontaudit */
	#define TEQ_CLONE	0x00000010
	#define TEQ_TYPE_TRANS	0x00000020
	#define TEQ_TYPE_MEMBER	0x00000040
	#define TEQ_TYPE_CHANGE	0x00000080
	#define TEQ_AV_ACCESS	(TEQ_ALLOW|TEQ_NEVERALLOW)
	#define	TEQ_AV_AUDIT	(TEQ_AUDITALLOW|TEQ_DONTAUDIT)
	#define	TEQ_TYPE	(TEQ_TYPE_TRANS|TEQ_TYPE_MEMBER|TEQ_TYPE_CHANGE)
	#define TEQ_ALL		(TEQ_AV_ACCESS|TEQ_AV_AUDIT|TEQ_TYPE)
	unsigned int	rule_select;		/* indicate which rules to include */
	bool_t		any;			/* if true, than use ta1 for any and ignore ta2-3 */
	bool_t		use_regex;		/* if true, ta* are regex */
	bool_t		only_enabled; 		/* include only rules that are enabled by the conditional policy */
	srch_type_t	ta1;			/* */
	srch_type_t	ta2;			/* */
	srch_type_t	ta3;			/* */
	int		*classes;		/* array of class indexes */
	int		num_classes;
	int		*perms;			/* array of permission indexes */
	int		num_perms;
	char		*bool_name;			/* name of conditional boolean (or regex if use_regex) */
} teq_query_t;

/* set of arrays of rule indicies matching search query */
typedef struct teq_results {
	int		*av_access;		/* rule indicies */
	int		*av_access_lineno;	/* line #s for each entry in av_access */
	int		num_av_access;
	int		*av_audit;		/* rule indicies */
	int		*av_audit_lineno;	/* line #s for each entry in av_audit */
	int		num_av_audit;
	int		*type_rules;		/* rule indicies */
	int		*type_lineno;		/* line #s for each entry in type_rules */
	int		num_type_rules;
	int		*clones;		/* rule indicies */
	int		*clones_lineno;		/* line #s for each entry in type_rules */
	int		num_clones;
	#define TEQ_ERR_TA1_REGEX	1	/* invalid regex in q->ta1 */
	#define TEQ_ERR_TA2_REGEX	2	/* invalid regex in q->ta2 */
	#define TEQ_ERR_TA3_REGEX	3	/* invalid regex in q->ta3 */
	#define TEQ_ERR_TA1_INVALID	4	/* invalid non-regex type/attrib in q->ta1 */
	#define TEQ_ERR_TA2_INVALID	5	/* invalid non-regex type/attrib in q->ta2 */
	#define TEQ_ERR_TA3_INVALID	6	/* invalid non-regex type in q->ta3 */
	#define TEQ_ERR_TA1_STRG_SZ	7	/* q->ta1 string too large */
	#define TEQ_ERR_TA2_STRG_SZ	8	/* q->ta2 string too large */
	#define TEQ_ERR_TA3_STRG_SZ	9	/* q->ta3 string too large */
	#define TEQ_ERR_INVALID_CLS_Q	10	/* the classes query does not make sense */
	#define TEQ_ERR_INVALID_PERM_Q	11	/* the permissions query does not make sense */
	#define TEQ_ERR_INVALID_CLS_IDX	12	/* a class indx is not valid */
	#define TEQ_ERR_INVALID_PERM_IDX 13	/* a perm indx is not valid */
	int		err;		/* error type*/
	char		*errmsg;	/* used to communicate error messsage (optional) */
} teq_results_t;

typedef struct rtrans_query {
	srch_type_t src;
	srch_type_t tgt;
	ap_mls_range_t		*range;  		/* filter range */
	bool_t				use_regex;		/* if true, ta* are regex */
	unsigned int		search_type;
} rtrans_query_t;

/* set of arrays of rule indicies matching search query and error message */
typedef struct rtrans_results {
	int*	range_rules;		/* rule indicies */
	int		num_range_rules;
	int		err;		/* error type*/
	char*	errmsg;	/* used to communicate error messsage (optional) */
	#define RTRANS_ERR_REGCOMP	1	/* invalid regex for src input*/
	#define RTRANS_ERR_SRC_INVALID  2	/* unknown source */
	#define RTRANS_ERR_TGT_INVALID  3	/* unknown target */
} rtrans_results_t;


/* macros */
#define is_ta_used(ta_src_type) (ta_src_type.ta != NULL)

/* prototypes */
int free_teq_query_contents(teq_query_t *q);
int free_teq_results_contents(teq_results_t *r);
bool_t validate_te_query(teq_query_t *q);
int init_teq_results(teq_results_t *r);
int init_teq_query(teq_query_t *q);
int init_rtrans_query(rtrans_query_t *q);
int init_rtrans_results(rtrans_results_t *r);
int free_rtrans_results_contents(rtrans_results_t *r);

int match_rbac_rules(int idx, int type, unsigned char whichlist, bool_t do_indirect,bool_t tgt_is_role, rbac_bool_t *b, policy_t *policy);
int match_rbac_roles(int idx, int type, unsigned char whichlist, bool_t	do_indirect, bool_t tgt_is_role, rbac_bool_t *b,int *num_matched, policy_t *policy);
int match_te_rules(bool_t allow_regex, regex_t *preg, int ta_opt,int idx, int idx_type, bool_t include_audit, unsigned char whichlists,	
	bool_t do_indirect, bool_t only_enabled, rules_bool_t *rules_b, policy_t *policy);
int search_te_rules(teq_query_t *q, teq_results_t *r, policy_t *policy);
int search_range_transition_rules(rtrans_query_t* query, rtrans_results_t* results, policy_t* policy);
bool_t match_rbac_role_ta(int rs_idx,int ta_idx, int *rt_idx,policy_t *policy);

	
int search_conditional_expressions(bool_t use_bool, char *bool, bool_t allow_regex, bool_t *exprs_b, char **error_msg, policy_t *policy);
int match_cond_rules(rules_bool_t *rules_b, bool_t *exprs_b, bool_t include_audit, policy_t *policy);
int policy_query_add_type(int **end_types, int *num_end_types, int end_type);
#endif /*_APOLICY_POLICY_QUERY_H_*/


