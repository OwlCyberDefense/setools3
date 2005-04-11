/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * poldiff.h
 *
 * Support for semantically diff'ing two policies 
 */

#ifndef _APOLICY_POLDIFF_H_
#define _APOLICY_POLDIFF_H_
#include "policy.h"
#include "semantic/avhash.h"


typedef struct int_a_diff {
	int	idx;
	char    *str_id; /* this is the string id so we can sort them in the gui*/
	int	numa; 	/* is NULL, then the entire component is not in the other policy. */
	int	*a;	/* types (roles/attribs), roles (users), perms (class/common perm),
			 * attribs (types)
			 * not associated with this idx in the other policy; if this */
	bool_t  missing; /* used by rallows, and possibly more in future to tell if this item is missing
			    from the other policy */
	struct int_a_diff *next;
} int_a_diff_t;


typedef struct ap_rtrans_diff {
	int rs_idx;    /* the idx of the role source */
	int t_idx;      /* the idx of the type */
	int rt_idx;   /* the idx of role target */
	bool_t missing; /* is the trans key not in the other policy */
	struct ap_rtrans_diff *next;
} ap_rtrans_diff_t;

typedef struct bool_diff {
	int	idx;
	bool_t	state_diff;	/* if TRUE, then the boolean exists in both policies, but
				 * the default state is different; if FALSE, then the bool
				 * does not exist in the other policy */
	struct bool_diff *next;
} bool_diff_t;

typedef struct ap_cond_expr_diff {
	int idx;                       /* index of conditional in policy */
	bool_t missing;                /* if the conditional is missing in other policy */
	avh_node_t **true_list_diffs;  /* the list of true list differences */
	avh_node_t **false_list_diffs; /* the list of false list differences */
	int num_true_list_diffs;       /* number in true list diff */
	int num_false_list_diffs;      /* number in false list diff */
	struct ap_cond_expr_diff *next;/* the next cond expr diff */
} ap_cond_expr_diff_t;

/* Contains those components of a policy that are not contained in another policy
 * This is one side of the differences between the two policies.  The policies
 * used for the diff must be assoicated separately.
 *
 * All the references (e.g., contexts) are with repsect to the assoicated policy */
typedef struct apol_diff {
	int		num_types;
	int		num_attribs;
	int		num_roles;
	int		num_users;
	int		num_classes;
	int		num_common_perms;
	int		num_perms;
	int		num_booleans;
	int		num_role_allow;
	int		num_role_trans;
	int             num_cond_exprs;
	int_a_diff_t	*types;	
	int_a_diff_t	*attribs;
	int_a_diff_t	*roles;
	int_a_diff_t	*users;
	int_a_diff_t	*classes;	/* classes and/or perm mapping */
	int_a_diff_t	*common_perms;	/* common perms and/or perm mapping */
	int		*perms;		/* any type of missing individual perm */
	bool_diff_t	*booleans;
	int_a_diff_t	*role_allow;   /* rbac differences */
       	ap_rtrans_diff_t   *role_trans;	/* role transitions */
	avh_t		te;		/* hash table contains missing TE rule semantics */
	ap_cond_expr_diff_t *cond_exprs; /* the conditional exprs diff */
} apol_diff_t;

typedef struct apol_diff_result {
	policy_t	*p1;	/* First policy */
	policy_t	*p2;	/* Second policy */
	bool_t		bindiff; /* indicates wither one p1/p2 is binary */
	apol_diff_t	*diff1;	/* p1's stuff not in p2 */
	apol_diff_t	*diff2; /* p2's stuff not in p1 */
} apol_diff_result_t;


#define apol_is_bindiff(adr) (adr != NULL ? adr->bindiff : FALSE)

void apol_free_diff_result(bool_t close_pols, apol_diff_result_t *adr);
apol_diff_result_t *apol_diff_policies(unsigned int opts, policy_t *p1, policy_t *p2);
int make_p2_key(avh_key_t *p1key, avh_key_t *p2key, policy_t *p1, policy_t *p2);
bool_t does_cond_match(avh_node_t *n1, policy_t *p1, avh_node_t *n2, policy_t *p2, bool_t *inverse);
ap_cond_expr_diff_t *find_cdiff_in_policy(ap_cond_expr_diff_t *cond_expr_diff,apol_diff_t *diff2,policy_t *p1,policy_t *p2);
#endif /* _APOLICY_POLDIFF_H_ */


