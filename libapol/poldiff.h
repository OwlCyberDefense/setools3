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


#define AP_SRC_TYPE   1
#define AP_TGT_TYPE   2
#define AP_OCLASS     3
#define AP_SRC_ROLE   4
#define AP_TGT_ROLE   5
#define AP_EXEC_TYPE  6

typedef struct ap_diff_rename {
	int *p1;       /* policy 1 items */
	int *p2;       /* equivalent policy 2 items */
	int num_items; /* the number of equivalent items */
	int sz;        /* the array sizes */
} ap_diff_rename_t;

ap_diff_rename_t *ap_diff_rename_new();
void ap_diff_rename_free(ap_diff_rename_t *rename);
int ap_diff_rename_add(int p1_type, int p2_type, policy_t *p1, policy_t *p2, ap_diff_rename_t *rename);
int ap_diff_rename_remove(int p1, int p2, ap_diff_rename_t *rename);

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


typedef struct ap_single_iad_chg {
        int *add;               /* the array of added sub items used for roles/attribs 
				 because they have to deal with changes because of types*/
        int *rem;               /* the array of removed sub items used for roles/attribs 
				 because they have to deal with changes because of types*/
        int_a_diff_t *add_iad; /* the arr of added sub items for all other items */
        int_a_diff_t *rem_iad; /* the arr of removed sub items for all other items */
        int num_add;            /* should be one */
        int num_rem;            /* should be one */
        int p1_idx;             /* the p1 idx of the base thing */
} ap_single_iad_chg_t;

/* this is used for types/roles/attribs/rallows/perms/oclasses/users 
   all of these are currently stored as iads*/
typedef struct ap_single_iad_diff {
        unsigned int type;               /* this indicates what kind of thing this is, type, attrib, etc */
        int_a_diff_t **add;     /* the array of added iad elements */
        int_a_diff_t **rem;     /* the array of removed iad elements */
        ap_single_iad_chg_t *chg;      /* the array of changed structs */
        ap_single_iad_chg_t *chg_add;  /* the array of changed because of added type */
        ap_single_iad_chg_t *chg_rem;  /* the array of changed because of a removed type */
        int num_add;            /* the number of added iads */
        int num_rem;            /* the number of removed iads */
        int num_chg;            /* the number of changed */
        int num_chg_add;        /* the number of changed because of added type */
        int num_chg_rem;        /* the number of changed because of removed type */
} ap_single_iad_diff_t;

/* single view of booleans just keep a arrays of 
   added/removed/changed bool_diff_t structs */
typedef struct ap_single_bool_diff {
        bool_diff_t **add;   /* the array of added boolean  */
        bool_diff_t **rem;   /* the array of changed booleans */
        bool_diff_t **chg;   /* all these are p1 idxs can just check state in p1 to see what state change was  */
        int num_add;         /* the number of added booleans */
        int num_rem;         /* the number of removed booleans */
        int num_chg;          /* the number of changed booleans */
} ap_single_bool_diff_t;

/* This structure represents a single view of a role transition difference */
typedef struct ap_single_rtrans_diff {
        ap_rtrans_diff_t **add;      /* an array of added rtrans */
        ap_rtrans_diff_t **rem;      /* an array of removed rtrans */
        ap_rtrans_diff_t **chg_add;      /* an array of changed rtrans */
	ap_rtrans_diff_t **chg_rem;
        ap_rtrans_diff_t **add_type; /* the rules added because of a new type */
        ap_rtrans_diff_t **rem_type; /* the rules removed because of a removed type */
        int num_add;                 /* the number of added rtrans */
        int num_rem;                 /* the number of removed rtrans */
        int num_chg;                  /* the number of changed rtrans */
        int num_add_type;            /* the number of rtrans added because of an added type */
        int num_rem_type;            /* the number of trans removed because of an removed type */
        int sort_key;              /* bit mask telling us sorting directions 1 is asc, 0 is desc */
} ap_single_rtrans_diff_t;

/* the structure represents a single TE rule change needed for output, it contains links to the 
   complete rules in p1 and p2 as well as links to the added/removed perms in d1/d2 */
typedef struct ap_single_te_chg {
        avh_node_t *add;       /* p2 full rule --idx into p2 hash*/
        avh_node_t *rem;       /* p1 full rule --idx into p1 hash*/
        avh_node_t *add_diff;  /* d2 added perms --idx into d2 hash*/
        avh_node_t *rem_diff;  /* d1 removed perms --idx into d1 hash*/
} ap_single_te_chg_t;

/* this structure represents a single view of the te rules differences */
typedef struct ap_single_te_diff {
        avh_node_t **add;                  /* added te rules --idx into p2 diff hash */
        avh_node_t **rem;                  /* removed te rules --idx into p1 diff hash */
        ap_single_te_chg_t *chg;           /* changed te rules */
        avh_node_t **add_type;             /* added te rules because of added type */ 
        avh_node_t **rem_type;             /* removed te rules because of removed type */
        int num_add;
        int num_rem;
        int num_chg;
        int num_add_type;
        int num_rem_type;
        int sort_key;    /* bit mask telling us sorting directions 1 is asc, 0 is desc */
} ap_single_te_diff_t;


/* for conds just use the structs already in poldiff to handle it
for adds just put in "pointer indexes" to p2 diff to only added
conds, and visa versa for removed and p1.  To deal with changes
make two pointer index arrays (of the same length) that match up
conds by index, i.e. the pointers at index 0 both point to the same
cond if one of the index pointers is null we know its a change because
of only a remove or an add */
typedef struct ap_single_cond_diff {
        ap_cond_expr_diff_t **add;        /* the added conditonals */
        ap_cond_expr_diff_t **rem;        /* removed conditionals */
        ap_cond_expr_diff_t **chg_add;    /* array of added parts of changed conditionals */
        ap_cond_expr_diff_t **chg_rem;    /* array of removed parts of changed conditionals */
        int num_add;
        int num_rem;
        int num_chg_add;
        int num_chg_rem;
} ap_single_cond_diff_t;

typedef struct ap_single_perm_diff {
	int *add;
	int *rem;
	int num_add;
	int num_rem;
} ap_single_perm_diff_t;


typedef struct ap_single_view {
	ap_single_iad_diff_t *types;         /* single view of the type differences */
	ap_single_iad_diff_t *roles;         /* single view of the role differences */
	ap_single_iad_diff_t *users;         /* single view of the user differences */
	ap_single_iad_diff_t *attribs;       /* single view of the attribute differences */
	ap_single_iad_diff_t *classes;       /* single view of the object class differences */
	ap_single_perm_diff_t *perms;         /* single view of the permissions differences */
	ap_single_iad_diff_t *common_perms;  /* single view of the common permissions differences */
	ap_single_iad_diff_t *rallows;       /* single view of the role allow differences */
	ap_single_bool_diff_t *bools;        /* single view of the boolean differences */
	ap_single_rtrans_diff_t *rtrans; /* single view of the role transition differences */
	ap_single_te_diff_t *te;         /* single view of the TE rule differences */
	ap_single_cond_diff_t *conds;    /* single view of the conditional differences */
} ap_single_view_diff_t;

/* for perms we just need the ints stored in d1/d2 */
typedef struct apol_diff_result {
	policy_t        *p1;	/* First policy */
	policy_t	*p2;	/* Second policy */
	bool_t		bindiff; /* indicates wither one p1/p2 is binary */
	apol_diff_t	*diff1;	/* p1's stuff not in p2 */
	apol_diff_t	*diff2; /* p2's stuff not in p1 */
} apol_diff_result_t;


#define apol_is_bindiff(adr) (adr != NULL ? adr->bindiff : FALSE)

void apol_free_diff_result(bool_t close_pols, apol_diff_result_t *adr);
apol_diff_result_t *apol_diff_policies(unsigned int opts, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types);
int make_p2_key(avh_key_t *p1key, avh_key_t *p2key, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types);
bool_t does_cond_match(avh_node_t *n1, policy_t *p1, avh_node_t *n2, policy_t *p2, bool_t *inverse);
ap_cond_expr_diff_t *find_cdiff_in_policy(ap_cond_expr_diff_t *cond_expr_diff,apol_diff_t *diff2,policy_t *p1,policy_t *p2,bool_t *inverse);
int find_cond_in_policy(int p1_idx,policy_t *p1,policy_t *p2,bool_t noinverse);
#endif /* _APOLICY_POLDIFF_H_ */


