/* Copyright (C) 2001-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* policy.h
 *
 * analysis policy database support header 
 *
 * Our policy database (see below) is completly different
 * than that used by checkpolicy/SS; we're trying to analyze from
 * policy.conf "up" to higher abstractions.
 */

#ifndef _APOLICY_POLICY_H_
#define _APOLICY_POLICY_H_

#include "cond.h"
#include "avl-util.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <regex.h>

#define LIST_SZ 100	/* alloc size for all list arrays...
			 * dynamically grow in this increments as necesary */


/* policy options used for opening a policy; controls which part of the
 * policy were loaded. 
 */
#define POLOPT_NONE		0x0
#define	POLOPT_CLASSES		0x00000001	/* object classes  */
#define POLOPT_PERMS		0x00000002	/* types and type attributes */
#define POLOPT_TYPES		0x00000004	/* role declarations */
#define POLOPT_ROLES		0x00000008	/* user declarations */
#define POLOPT_USERS		0x00000010	/* TE allow rules */
#define POLOPT_TE_ALLOW		0x00000020	/* neverallow rules */
#define POLOPT_TE_NEVERALLOW	0x00000040
#define POLOPT_TE_AUDITALLOW	0x00000080	/* includes old auditdeny rules */
#define POLOPT_TE_DONTAUDIT	0x00000100	/* type_transition rules */
#define POLOPT_TE_TRANS		0x00000200
#define POLOPT_TE_MEMBER	0x00000400
#define POLOPT_TE_CHANGE	0x00000800	/* all role rules (allow, old trans)*/
#define POLOPT_ROLE_RULES	0x00001000	/* conditional boolean definitions */
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
#define POLOPT_COND_BOOLS	0x00002000	/* conditional expression definitions */
#define POLOPT_COND_EXPR	0x00004000	/* conditional expression definitions */
#define POLOPT_COND_TE_RULES	0x00008000	/* conditional TE rules */
#endif
#define POLOPT_INITIAL_SIDS	0x00010000	/* initial SIDs and their context */
#define POLOPT_OTHER		0x10000000	/* Everything else not covered above. */

#define POLOPT_OBJECTS		(POLOPT_CLASSES|POLOPT_PERMS)
#define POLOPT_AV_RULES		(POLOPT_TE_ALLOW|POLOPT_TE_NEVERALLOW|POLOPT_TE_AUDITALLOW|POLOPT_TE_DONTAUDIT)
#define POLOPT_TYPE_RULES	(POLOPT_TE_TRANS|POLOPT_TE_MEMBER|POLOPT_TE_CHANGE)
#define POLOPT_TE_RULES		(POLOPT_AV_RULES|POLOPT_TYPE_RULES)
#define POLOPT_TE_POLICY	(POLOPT_TE_RULES|POLOPT_TYPES)
#define POLOPT_RBAC		(POLOPT_ROLES|POLOPT_ROLE_RULES)
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
#define POLOPT_UNCOND_TE_RULES	(POLOPT_TE_RULES)
#define POLOPT_COND_POLICY	(POLOPT_COND_BOOLS|POLOPT_COND_EXPR|POLOPT_COND_TE_RULES)
#define POLOPT_ALL		(POLOPT_INITIAL_SIDS|POLOPT_OBJECTS|POLOPT_TE_POLICY|POLOPT_RBAC|POLOPT_USERS|POLOPT_COND_POLICY|POLOPT_OTHER)
#else
#define POLOPT_ALL		(POLOPT_INITIAL_SIDS|POLOPT_OBJECTS|POLOPT_TE_POLICY|POLOPT_RBAC|POLOPT_USERS|POLOPT_OTHER)
#endif
/* The following define which pass of the parser the components are collected.  We
 * don't include all the options (like POLOPT_OTHER), but rather only those that 
 * apol currently makes use of (or will in the near future) */
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
#define PLOPT_PASS_1		(POLOPT_OBJECTS|POLOPT_TYPES|POLOPT_COND_BOOLS)
#define PLOPT_PASS_2		(POLOPT_RBAC|POLOPT_USERS|POLOPT_TE_RULES|POLOPT_COND_EXPR|POLOPT_COND_TE_RULES)
#else
#define PLOPT_PASS_1		(POLOPT_OBJECTS|POLOPT_TYPES)
#define PLOPT_PASS_2		(POLOPT_ROLES|POLOPT_ROLE_RULES|POLOPT_USERS|POLOPT_TE_RULES)
#endif

/* NOTE:Rather than implement a structure like a hash table, or 
 * better yet "borrow" the policydb from the SE Linux  source,
 * we instead are using these simplier, albiet more limited
 * unsorted dynamic arrays.  This of course means that searches 
 * and insertions are more slow, but in general we're only
 * trying to analyze a policy.conf file, and not build an efficient
 * runtime policy DB.  So we can live with the performance
 * issues in trade for being able to incrementally build analysis
 * capabilities and to focus on our need to analyze a policy rather
 * than enforce it.
 */
 
/* for when we just store lists of name strings*/
typedef struct name_item {
	char			*name;	/* string */
	struct name_item	*next;
} name_item_t;



/* IDs for ta_item */
#define IDX_INVALID		0
#define IDX_TYPE		1
#define IDX_ATTRIB		2
#define IDX_ROLE		3
#define IDX_PERM		4
#define IDX_COMMON_PERM		5
#define IDX_OBJ_CLASS		6
#define IDX_MAX			6
#define IDX_BOTH		-1	/* reserve as special indicator for regex rule searches  */

/* type, attribute, role, perm , common perm list item */
typedef struct ta_item {
	int	type;	/* ID above */
	int	idx;	/* into appropriate list array*/
	struct 	ta_item	*next;
} ta_item_t;

/* AVL tree list type ids */
#define	AVL_TYPES		0	/* the type array */
#define AVL_ATTRIBS		1	/* the attrib array */
#define AVL_CLASSES		2	/* object classes */
#define AVL_PERMS		3	/* permissions */
#define AVL_INITIAL_SIDS	4	/* initial SID contexts */
#define	AVL_NUM_TREES		5	/* # of avl trees supported */

/* type decalaration */
typedef struct type_item {
	char		*name;
	name_item_t	*aliases;
	int		num_attribs;
	int		*attribs;  /* dynamic array of attrib indicies*/
} type_item_t;

/* attributes and their associated types */
typedef struct attrib_item {
	char	*name; 
	int	num_types;
	int	*types;  /* dynamic array of type indicies*/
} attrib_item_t;

/* NOTE: the role declaration structure looks identical to the  attrib
 * delcation structure.  So rather than rebuild functions that do the 
 * same thing, we will use attrib_item_t also for role declations. */
 
/* FIX: At some point for code clarity, should make the attrib/role
 * functions have more generic names...very low priority! */
typedef attrib_item_t role_item_t;

typedef struct common_perm {
	char	*name;
	int	num_perms;
	int	*perms;		 /* dynamic array of idx's into perm array */
} common_perm_t;

/* Object class and permissions */
typedef struct obj_class {
	char	*name;
	int	common_perms;	/* there may be only one of these */
	int	num_u_perms;
	int	*u_perms;
} obj_class_t;


/* user statements; linked list */
typedef struct user_item {
	char			*name;
	ta_item_t		*roles;
	struct user_item	*next;
	void 			*data;	/* generic pointer used by libseuser; ignored in apol */
} user_item_t;

typedef struct user_list {
	user_item_t	*head;
	user_item_t	*tail;
} user_list_t;


typedef struct security_context {
	user_item_t	*user;	/* Note, unfortunately we don't have idx's for users. 
				 * Never free user from this structure; this is just a
				 * pointer to the real user record */
	int		role;
	int		type;
} security_context_t;

/* IDs of rules */
#define RULE_TE_ALLOW		0 	/*AV rule */
#define RULE_AUDITALLOW		1	/*AV rule */
#define RULE_AUDITDENY		2	/*AV rule */
/* removed NOTIFY and replaced with DONTAUDIT  Jul 2002 */
#define RULE_NOTIFY		3	/*AV rule */
#define RULE_DONTAUDIT		3	/*replaces NOTIFY */
#define RULE_NEVERALLOW		4	/*AV rule */
#define RULE_MAX_AV		4   	/*end of AV rule types */
#define RULE_TE_TRANS		5   	/*TT rule (type transition|change|member) */
#define RULE_TE_MEMBER		6   	/*TT rule */
#define RULE_TE_CHANGE		7	/*TT rule */
#define RULE_CLONE		8	/*clone rule */
#define RULE_ROLE_ALLOW		9	/* Role allow */
#define RULE_ROLE_TRANS		10	/* Role transition */
#define RULE_USER		11	/* User role definition */
#define RULE_MAX		12	/* # of rule IDs defined (1+last rule)*/



/* flags used to indicate '~' and '*' */
/* used for both AV and TT rules */
#define AVFLAG_NONE		0x00
#define AVFLAG_SRC_TILDA	0x01
#define AVFLAG_SRC_STAR		0x02
#define AVFLAG_TGT_TILDA	0x04
#define AVFLAG_TGT_STAR		0x08
#define AVFLAG_CLS_TILDA	0x10
#define AVFLAG_CLS_STAR		0x20
#define AVFLAG_PERM_TILDA	0x40
#define AVFLAG_PERM_STAR	0x80

/* a structure for a AV rule*/
typedef struct av_item {
 	int		type;		/* rule type; av rule IDs defined above */
 	unsigned char	flags;		/* where we handle '~' and '*' */
 	unsigned long	lineno;		/* line # from policy.conf */
 	ta_item_t	*src_types;	/* the domain types/attribs */
 	ta_item_t	*tgt_types;	/* the object types/attribs */
	ta_item_t	*classes;
	ta_item_t	*perms;
} av_item_t; 	

/* structure for a type transition (member, change) rule */
typedef struct tt_item {
	int		type;		/* rule type; av rule IDs defined above */
	unsigned char	flags;		/* use AV* flags above, only need SRC, TGT, & CLS */
 	unsigned long	lineno;		/* line # from policy.conf */
	ta_item_t	*src_types;	/* the domain types/attribs */
 	ta_item_t	*tgt_types;	/* the object types/attribs */
	ta_item_t	*classes;
	ta_item_t	dflt_type;	/* the default type; only one of these */	
} tt_item_t;

/* a role allow rule; dynamic arrays */
typedef struct role_allow_item {
	unsigned char	flags;		/* use AV* flags above, only need SRC & TGT */	
 	unsigned long	lineno;		/* line # from policy.conf */
	ta_item_t	*src_roles;	
	ta_item_t	*tgt_roles;
} role_allow_t;

/* role transition rule; dynamic array */
typedef struct rt_item {
	unsigned char	flags;		/* use AV* flags for src and tgt */
 	unsigned long	lineno;		/* line # from policy.conf */
	ta_item_t	*src_roles;
	ta_item_t	*tgt_types;	
	ta_item_t	trans_role;	/* role to transition to */
} rt_item_t;	

/* clone rule structure; we store the rule and then resolve its semanitcs as necessary */
typedef struct cln_item {
 	unsigned long	lineno;		/* line # from policy.conf */
	int		src;		/* idx of src tpye...must be a type (not a type attribute) */
	int		tgt;		/* idx of target type... "             "          " */
	struct cln_item *next;
} cln_item_t;




/* initial SIDs and their context */
typedef struct initial_sid {
	char			*name;
	security_context_t 	*scontext;
} initial_sid_t;

/* type alias array
 * TODO: see comments in add_alias() in policy.c */
typedef struct alias_item {
	char			*name;
	int			type;	/* assoicated type */
} alias_item_t;

/* IDs for DYNAMIC array only  (e.g., clones is not a dynamic array, but rather a linked list*/
#define POL_LIST_TYPE		0
#define POL_LIST_ATTRIB		1
#define POL_LIST_AV_ACC 	2
#define POL_LIST_AV_AU		3
#define POL_LIST_TE_TRANS	4
#define POL_LIST_ROLES		5
#define POL_LIST_ROLE_ALLOW	6
#define POL_LIST_ROLE_TRANS	7
#define POL_LIST_PERMS		8
#define POL_LIST_COMMON_PERMS	9
#define POL_LIST_OBJ_CLASSES	10
#define POL_LIST_ALIAS		11
#define POL_LIST_INITIAL_SIDS	12
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
#define POL_LIST_COND_BOOLS	13
#define POL_LIST_COND_EXPRS	14
#define POL_NUM_LISTS		15
#else
#define POL_NUM_LISTS		13
#endif

/* These are our weak indicators of which version of policy we're using.
 * The syntax and semantics of a policy are in great flux, and many changes
 * are being implemented.  We're trying to use this with older and new 
 * policies, so we try to keep some degree of backwards compatability.
 * During parsning we try to infer which version we have and set this
 * indicator accordingly.
 */
#define POL_VER_UNKNOWN		0
#define POL_VER_PREJUL2002	1	/* all versions befor the Jul
						 * 2002 changes */
#define POL_VER_PRE_11		1	/* same as POL_VER_PREJUL2002 */

#define POL_VER_JUL2002		2	/* all version after Jul 2002 until next date */
#define POL_VER_11		2	/* same as POL_VER_JUL2002 */
#define POL_VER_12		2	/* same as POL_VER_JUL2002; no apparent syntax changes b/w 11 and 12 */
#define POL_VER_15		3	/* somewhere between v 12 and 15! */
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
#define	POL_VER_16		4	/* conditional policy extensions */
#define POL_VER_COND		4	/* same */
#define	POL_VER_MAX		4
#else
#define POL_VER_MAX		3
#endif

#define POL_VER_STRING_PRE_11 	"prior to v. 11"
#define POL_VER_STRING_11	"v.11 -- v.12"
#define POL_VER_STRING_15	"v.13 -- v.15"
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
#define POL_VER_STRING_16	"v.16"
#endif

/**************************************/
/* This is an actual policy data base */
typedef struct policy {
	int	version;		/* weak indicator of policy version, see comments above */
	unsigned int opts;		/* indicates which parts of the policy are included in this policy */
	int	num_types;		/* array current ptr */
	int	num_attribs;		/* " " */
	int	num_av_access;		/* " " */
	int	num_av_audit;		/* " " */
	int	num_te_trans;		/* " " */
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
	int	num_cond_bools;		/* " " */
	int	num_cond_exprs;		/* " " */
#endif
	int	num_roles;		/* " " */
	int	num_role_allow;		/* " " */
	int	num_role_trans;		/* " " */
	int 	num_perms;		/* " " */
	int	num_common_perms;
	int	num_obj_classes;
	int	num_aliases;
	int	num_initial_sids;
	int 	rule_cnt[RULE_MAX];	/* statics on # of various rules */
	int	list_sz[POL_NUM_LISTS]; /* keep track of dynamic array sizes */

/* AVL trees */
	avl_tree_t	tree[AVL_NUM_TREES];	/* AVL tree heads */

/* the lists */
/* Permissions and Object Classes */
	char		**perms;	/* defined access permissions (ARRAY) */
	common_perm_t	*common_perms;	/* associates of perms (ARRAY) */
	obj_class_t	*obj_classes;	/* define objects and their perms (ARRAY) */
/* Type Enforcement Rules */
	type_item_t 	*types;    	/* defined types and their attribs (ARRAY)*/
	alias_item_t	*aliases;	/* separate index into type aliases (ARRAY) */
	attrib_item_t 	*attribs;	/* defined attribs and their types (ARRAY)*/
	av_item_t	*av_access;	/* allow and neverallow rules; we expect lots of these (ARRAY)*/
	av_item_t	*av_audit;	/* audit and notify rules (ARRAY)*/
	tt_item_t	*te_trans;	/* type transition|member|change rules (ARRAY)*/
	cln_item_t	*clones;	/* clone rules (LLIST) */
/* Misc. Policy */
	initial_sid_t	*initial_sids;	/* initial SIDs and their context (ARRAY) */
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
/* Conditional Policy */
	cond_bool_t	*cond_bools;	/* conditional policy booleans (ARRAY) */
	cond_expr_item_t *cond_exprs;	/* conditional expressions (ARRAY) */
#endif
/* Role-based access control rules */
	role_item_t	*roles;		/* roles (ARRAY)*/
	role_allow_t	*role_allow;	/* role allow rules (ARRAY) */
	rt_item_t	*role_trans;	/* role transition rules (ARRAY) */
/* User rules */
/* TODO: We probably need to re-work user into an ARRAY like most of the other lists to allow 
 *	 for growth in the number of users and make everything consistent.  Unfortunately, we
 *	 already have a large investment in code that uses the linked list!! */
	user_list_t	users;		/* users (LLIST) */
/* Permissions map (which is used for information flow analysis) */
	struct classes_perm_map *pmap;	/* see perm-map.h */
} policy_t;


/* used for whichlist arguments */
#define SRC_LIST	0x0001
#define TGT_LIST	0x0002
#define BOTH_LISTS 	0x0003 /* both src and tgt */
#define DEFAULT_LIST	0x0004 /* this is the THIRD type/role for the "transitions" rules only */
#define ALL_LISTS	0x0007 /* all lists */



/* 
 * exported prototypes and macros 
 */

/* General */
int init_policy( policy_t **policy_ptr);
int free_policy(policy_t **policy_ptr);
int set_policy_version(int ver, policy_t *policy);

/* DB updates/additions/changes */
#define add_common_perm_to_class(cls_idx, cp_idx, policy) ((is_valid_obj_class_idx(cls_idx, policy) && is_valid_common_perm_idx(cp_idx, policy)) ? policy->obj_classes[cls_idx].common_perms = cp_idx: -1 )

int add_type(char *type, policy_t *policy);
int add_alias(int type_idx, char *alias, policy_t *policy);
int add_attrib_to_type(int type_idx, char *token, policy_t *policy);
int insert_ta_item(ta_item_t *newitem, ta_item_t **list);
int append_user(user_item_t *newuser, user_list_t *list);
int add_name(char *name, name_item_t **list);
int add_clone_rule(int src, int tgt,  unsigned long lineno, policy_t *policy);
int add_attrib(bool_t with_type, int type_idx, policy_t *policy, char *attrib);
int add_type_to_role(int type_idx, int role_idx, policy_t *policy);
int add_class(char *classname, policy_t *policy);
int add_perm_to_class(int cls_idx, int p_idx, policy_t *policy);
int add_common_perm(char *name, policy_t *policy);
int add_perm_to_common(int comm_perm_idx, int perm_idx, policy_t *policy);
int add_perm(char *perm, policy_t *policy);

/* Object Classes */
#define num_obj_classes(policy) (policy != NULL ? policy->num_obj_classes : -1)
#define is_valid_obj_class_idx(idx, policy) (policy != NULL && (idx >= 0 && idx < policy->num_obj_classes))
#define does_class_use_common_perm(cls_idx, cp_idx, policy)  ((is_valid_obj_class_idx(cls_idx,policy) && is_valid_common_perm_idx(cp_idx,policy)) ? (cp_idx == policy->obj_classes[cls_idx].common_perms) : FALSE)
#define num_of_class_perms(cls_idx, policy) (is_valid_obj_class_idx(cls_idx,policy) ? \
	policy->obj_classes[cls_idx].num_u_perms + \
	(is_valid_common_perm_idx(policy->obj_classes[cls_idx].common_perms, policy) ? \
	policy->common_perms[policy->obj_classes[cls_idx].common_perms].num_perms : 0 ) \
	: -1 )
	
int get_obj_class_name(int idx, char **name, policy_t *policy);
int get_obj_class_idx(const char *name, policy_t *policy);
int get_num_perms_for_obj_class(int clss_idx, policy_t *policy);
int get_obj_class_common_perm_idx(int cls_idx,  policy_t *policy);
int get_obj_class_perm_idx(int cls_idx, int idx, policy_t *policy);
int get_obj_class_perms(int obj_class, int *num_perms, int **perms, policy_t *policy);


/* Permissions */
#define is_valid_perm_idx(idx, policy) (policy != NULL  && (idx >= 0 && idx < policy->num_perms))
#define is_valid_common_perm_idx(idx, policy) (idx >= 0 && idx < policy->num_common_perms)
bool_t is_valid_perm_for_obj_class(policy_t *policy, int class, int perm);

int get_common_perm_name(int idx, char **name, policy_t *policy);
int get_common_perm_perm_name(int cp_idx, int *p_idx, char **name, policy_t *policy);
int get_common_perm_idx(const char *name, policy_t *policy);
int get_perm_name(int idx, char **name, policy_t *policy);
int get_perm_idx(const char *name, policy_t *policy);
bool_t does_common_perm_use_perm(int cp_idx, int perm_idx, policy_t *policy);
bool_t does_class_use_perm(int cls_idx, int perm_idx, policy_t *policy);
int get_perm_list_by_classes(bool_t union_flag, int num_classes, const char **classes, int *num_perms, int **perms, policy_t *policy);
bool_t does_class_indirectly_use_perm(int cls_idx, int perm_idx, policy_t *policy);


/* Initial SIDs */
#define is_valid_initial_sid_idx(idx, policy) (policy != NULL && (idx >= 0 && idx < policy->num_initial_sids))
#define num_initial_sids(policy) (policy != NULL ? policy->num_initial_sids : -1)
int add_initial_sid(char *name, policy_t *policy);
int get_initial_sid_idx(const char *name, policy_t *policy);
int add_initial_sid_context(int idx, security_context_t *scontext, policy_t *policy);
int get_initial_sid_name(int idx, char **name, policy_t *policy);
int search_initial_sids_context(int **isids, int *num_isids, const char *user, const char *role, const char *type, policy_t *policy);

/* Types and attributes */
#define num_types(policy) (policy != NULL ? policy->num_types : -1)
#define num_attribs(policy) (policy->num_attribs)
#define is_valid_attrib_idx(idx, policy) (policy != NULL && (idx >= 0 && idx < policy->num_attribs))
#define is_valid_type_idx(idx, policy) (policy != NULL && (idx >= 0 && idx < policy->num_types))

bool_t is_valid_type(policy_t *policy, int type, bool_t self_allowed);
bool_t is_valid_obj_class(policy_t *policy, int obj_class);
int add_type(char *type, policy_t *policy);
int add_alias(int type_idx, char *alias, policy_t *policy);
int add_attrib_to_type(int type_idx, char *token, policy_t *policy);
int init_policy( policy_t **policy_ptr);
int free_policy(policy_t **policy_ptr);

int get_type_idx(const char *name, policy_t *policy);
int get_type_idx_by_alias_name(const char *alias, policy_t *policy);
int get_attrib_idx(const  char *name, policy_t *policy);
int get_type_or_attrib_idx(const char *name, int *idx_type, policy_t *policy);
int get_type_name(int idx, char **name, policy_t *policy);
int get_attrib_name(int idx, char **name, policy_t *policy);
int get_type_attribs(int type, int *num_attribs, int **attribs, policy_t *policy);
int get_attrib_types(int attrib, int *num_types, int **types, policy_t *policy);


/* users */
#define get_first_user_ptr(policy) ((policy != NULL) ? policy->users.head : NULL)
#define get_next_user_ptr(user) ((user != NULL) ? user->next : NULL)
#define get_user_name_ptr(user) ((user != NULL) ? user->name : NULL)
#define get_user_first_role_ptr(user) ((user != NULL) ? user->roles : NULL)
#define get_user_next_role_ptr(role) ((role != NULL) ? role->next : NULL)
#define num_users(policy) (policy != NULL ? policy->rule_cnt[RULE_USER] : -1)

int free_user(user_item_t *ptr);
int get_user_name(user_item_t *user, char **name);
bool_t does_user_exists(const char *name, policy_t *policy);
int get_user_by_name(const char *name, user_item_t **user, policy_t *policy);
bool_t does_user_have_role(user_item_t *user, int role, policy_t *policy);


/* roles */
#define is_valid_role_idx(idx, policy) (policy != NULL && (idx >= 0 && idx < policy->num_roles))
#define num_roles(policy) (policy != NULL ? policy->num_roles : -1)
#define get_role_types(role, num_types, types, policy) get_attrib_types(role, num_types, types, policy)

int add_role(char *role, policy_t *policy);
int get_role_name(int idx, char **name, policy_t *policy);
int get_role_idx(const char *name, policy_t *policy);
bool_t does_role_use_type(int role, int type, policy_t *policy);
bool_t is_role_in_list(int role, ta_item_t *list);


/* TE rules */
/* if rule_type == 1, then access rules, otherwise audit rules */
#define is_valid_av_rule_idx(idx, rule_type, policy) (idx >= 0 && ( (rule_type == 1) ? idx < policy->num_av_access : idx < policy->num_av_audit) )
#define is_valid_tt_rule_idx(idx, policy) (idx >= 0 && idx < policy->num_te_trans)

int extract_types_from_te_rule(int rule_idx, int rule_type, unsigned char whichlist, int **types, int *num_types, policy_t *policy);
int extract_obj_classes_from_te_rule(int rule_idx, int rule_type, int **obj_classes, int *num_obj_classes, policy_t *policy);
int extract_perms_from_te_rule(int rule_idx, int rule_type, int **perms, int *num_perms, policy_t *policy);
bool_t does_av_rule_idx_use_type(int rule_idx, unsigned char rule_type, int type_idx, int ta_type, 
		unsigned char whichlist, bool_t do_indirect, policy_t *policy);
bool_t does_av_rule_use_type(int idx, int type, unsigned char whichlist, bool_t do_indirect, 
	av_item_t *rule, int *cnt, policy_t *policy);
bool_t does_tt_rule_use_type(int idx, int type, unsigned char whichlist, bool_t do_indirect, tt_item_t *rule, int *cnt, policy_t *policy);
bool_t does_av_rule_use_classes(int rule_idx, int rule_type, int *cls_idxs, int num_cls_idxs, policy_t *policy);
bool_t does_av_rule_use_perms(int rule_idx, int rule_type, int *perm_idxs, int num_perm_idxs, policy_t *policy);
bool_t does_tt_rule_use_classes(int rule_idx, int *cls_idxs, int num_cls_idxs, policy_t *policy);

/* Role rules */
bool_t does_role_trans_use_role(int idx, unsigned char whichlist, bool_t do_indirect, rt_item_t *rule, int *cnt);
bool_t does_role_allow_use_role(int src, unsigned char whichlist,  bool_t do_indirect, role_allow_t *rule, int *cnt);
bool_t does_role_trans_use_ta(int idx, int type, bool_t do_indirect, rt_item_t *rule, int *cnt, policy_t *policy);


/* misc */

bool_t does_clone_rule_use_type(int idx, int type, unsigned char whichlist, cln_item_t *rule,
	int *cnt, policy_t *policy);
int get_rule_lineno(int rule_idx, int rule_type, policy_t *policy);
int get_ta_item_name(ta_item_t *ta, char **name, policy_t *policy);

/**************/
/* these are INTERNAL functions only; allow direct access to type/attrib name string
 * stored within the policy db.  They are expoerted only for use by other internal
 * policy db modules.
 *
 * THE CALLER SHOULD NOT FREE OR OTHERWISE MODIFY THE RETURNED STRING!!!!
 */
int _get_attrib_name_ptr(int idx, char **name, policy_t *policy);
int _get_type_name_ptr(int idx, char **name, policy_t *policy);


#endif /*_APOLICY_POLICY_H_*/


