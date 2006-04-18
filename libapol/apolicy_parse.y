/* Copyright (C) 2001-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */
 
/* skeleton and structure "borrowed" from SE Linux module\selinux_plug\ss\policy.parse.y */
/* nearly all the logic is new and specific to policy analysis */

/* Keeping track of policy version.  We try to maintain some backwards 
 * comptability so that we can use this libaray with old and new policies.
 * This is difficult since changes are occuring regular to the syntax!
 * Below is our record of the versions we track, and what we think distinguishes them.
 * This is not a complete version determiner; just key issues.
 *
 * Policy Version 19 (POL_VER_19)
 * 	Added MLS satements for constraints
 *
 * Policy Version 18 (POL_VER_18)
 *	Added new netlink permission
 *
 * Policy Version 17 (POL_VER_17)
 *	Added support for IPv6
 *
 * Policy Version 16 (POL_VER_16):
 *	Added conditional policy syntax
 *		if-else statement
 *		bool declarations
 *
 * Policy Version 15 (POL_VER_15):
 *	Added FSUSEXATTR 
 *
 * Pre Jul 2002 (POL_VER_11 & POL_VER_12):
 *
 * 	devfs_context syntax
 * 	clone rule
 * 	notify rule (though never used and we don't keep it around)
 * 	fs_context without FSCON keyword
 * 	port context without PORTCON keyword
 * 	net if context without NETIFCON keyword
 * 	node context without NODECON keyword
 *	type attributes wihtout ATTRIBUTE keyword
 *
 * As of Jul 2002:
 *
 *	Type Attributes declared via ATTRIBUTE keyword
 *	clone rule not supported
 *	notify rule not supported
 *	added dontaudit rule
 * 	fs_uses added
 * 	gen_fs (GENFSCON) added; devfs_context removed
 *	PORTCON, FSCON, NETIFCON, and NODECON added, and previous
 *		formats removed
 *
 */

%{

#include <stdio.h>
#include "queue.h"
#include "policy.h"
#include "cond.h"
#include <assert.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

queue_t id_queue = 0;
unsigned int pass;

/* our GLOBAL policy structure */
policy_t *parse_policy = NULL;

typedef struct opt_stack {
	ap_optional_t *opt;
	struct opt_stack *next;
} opt_stack_t;

static opt_stack_t *optional_stack = NULL;

/* this is for passing around a rule (used in the conditional
 * policy support.
 */
typedef struct rule_desc {
	int rule_type;
	int idx;
} rule_desc_t;

/* used to signify non-error but empty return */
static rule_desc_t dummy_rule_desc;
static cond_expr_t dummy_cond_expr;

extern char yytext[];
extern int yywarn(char *msg);
extern int yyerror(char *msg);
extern int yystate(void);
extern int yyleave_state(void);
extern int yyenter_decl(void);
extern int yyenter_require(void);
extern int yyenter_ignore(void);
extern int yyenter_accept(void);
extern int yybegin_initial(void);
extern int yyis_decl(void);
static char errormsg[255];
extern unsigned long policydb_lineno;

int yylex(void);

static int insert_separator(int push);
static int insert_id(char *id,int push);
static int define_class(void);
static int define_initial_sid(void);
static int define_common_perms(void);
static int define_av_perms(int inherits);
static int define_sens(void);
static int define_dominance(void);
static int define_category(void);
static int define_level(void);
static int define_attrib(void);
static int define_typeattribute(void);
static int define_typealias(void);
static int define_type(int alias);
static int define_compute_type(int rule_type);
static int define_te_clone(void);
static int define_te_avtab(int rule_type);
static int define_role_types(void);
static ap_role_t *merge_roles_dom(ap_role_t *r1, ap_role_t *r2);
static ap_role_t *define_role_dom(ap_role_t *r);
static int define_role_trans(void);
static int define_role_allow(void);
static int define_constraint(bool_t is_mls, ap_constraint_expr_t *expr);
static int define_mls(void);
static int mls_valid(void);
static int define_validatetrans(bool_t is_mls, ap_constraint_expr_t *expr);
static int define_range_trans(void);
static ap_constraint_expr_t *define_cexpr(__u32 expr_type, __u32 arg1, __u32 arg2);
static int define_user(void);
static security_con_t *parse_security_context(int dontsave);
static int define_initial_sid_context(void);
static int define_devfs_context(int has_type);
static int define_fs_context(int ver);
static int define_port_context(int ver, int low, int high);
static int define_netif_context(int ver);
static int define_ipv4_node_context(int ver, __u32 addr, __u32 mask);
static uint32_t *parse_ipv6_addr(char *addr_str);
static int define_ipv6_node_context(int ver);
static int define_fs_use(int behavior, int ver);
static int define_genfs_context(int has_type);
static int define_nfs_context(void);
static int define_bool(void);
static int define_conditional(cond_expr_t *expr, cond_rule_list_t *t_list, cond_rule_list_t *f_list);
static cond_expr_t *define_cond_expr(__u32 expr_type, void *arg1, void *arg2);
static cond_rule_list_t *define_cond_pol_list(cond_rule_list_t *list, rule_desc_t *rule);
static rule_desc_t *define_cond_compute_type(int rule_type);
static rule_desc_t *define_cond_te_avtab(int rule_type);
static ap_mls_level_t *parse_mls_level(int dontsave);
static ap_mls_range_t *parse_mls_range(int dontsave);
static int begin_optional(void);
static int begin_optional_else(void);
static int end_optional(void);
static int end_optional_else(void);
static int optional_end_main(void);
static int begin_require(void);
static int add_require(int type);
static int push_optional(ap_optional_t *opt);
%}

%union {
	int sval;
	unsigned int val;
	unsigned int *valptr;
	void *ptr;
}

%type <ptr> cond_expr cond_expr_prim cond_pol_list
%type <ptr> cond_allow_def cond_auditallow_def cond_auditdeny_def cond_dontaudit_def
%type <ptr> cond_transition_def cond_te_avtab_def cond_rule_def
%type <ptr> role_def roles
%type <sval> cexpr_prim op roleop mls_cexpr mls_trans_cexpr require_decl_def
%type <sval> trans_prim mls_prim trans_cexpr_prim mls_cexpr_prim mls_trans_cexpr_prim
%type <val> ipv4_addr_def number

%token PATH
%token CLONE
%token COMMON
%token CLASS
%token CONSTRAIN
%token VALIDATETRANS
%token MLSCONSTRAIN
%token MLSVALIDATETRANS
%token INHERITS
%token SID
%token ROLE
%token ROLES
%token TYPEATTRIBUTE
%token TYPEALIAS
%token TYPE
%token TYPES
%token ALIAS
%token ATTRIBUTE
%token BOOL
%token IF
%token DECLIF
%token ELSE
%token TYPE_TRANSITION
%token TYPE_MEMBER
%token TYPE_CHANGE
%token ROLE_TRANSITION
%token SENSITIVITY
%token DOMINANCE
%token DOM DOMBY INCOMP
%token CATEGORY
%token LEVEL
%token RANGE
%token RANGE_TRANSITION
%token USER
%token NEVERALLOW
%token ALLOW
%token AUDITALLOW
%token AUDITDENY
%token DONTAUDIT
%token SOURCE
%token TARGET
%token SAMEUSER
%token FSCON PORTCON NETIFCON NODECON 
%token FSUSEPSID FSUSETASK FSUSETRANS FSUSEXATTR
%token GENFSCON
%token U1 U2 R1 R2 T1 T2 U3 R3 T3 L1 L2 H1 H2 
%token NOT AND OR XOR
%token CTRUE CFALSE
%token IDENTIFIER
%token NUMBER
%token EQUALS
%token NOTEQUAL
%token IPV6_ADDR
%token REQUIRE
%token OPTIONAL

%left OR
%left XOR
%left AND
%right NOT
%left EQUALS NOTEQUAL

%nonassoc LOWER_THAN_ELSE
%nonassoc ELSE
%%
policy			: classes initial_sids access_vectors 
			  opt_mls te_rbac users opt_constraints 
			  initial_sid_contexts  
			  policy_version_contexts
			| optionals
			;
classes			: class_def 
			| classes class_def
			;
class_def		: CLASS identifier
			{if (define_class()) return -1;}
			;
initial_sids 		: initial_sid_def 
			| initial_sids initial_sid_def
			;
initial_sid_def		: SID identifier
                        {if (define_initial_sid()) return -1;}
			;
access_vectors		: opt_common_perms av_perms
			;
/* added Jul 2002 */
opt_common_perms        : common_perms
                        |
                        ;
common_perms		: common_perms_def
			| common_perms common_perms_def
			;
common_perms_def	: COMMON identifier '{' identifier_list '}'
			{if (define_common_perms()) return -1;}
			;
av_perms		: av_perms_def
			| av_perms av_perms_def
			;
av_perms_def		: CLASS identifier '{' identifier_list '}'
			{if (define_av_perms(FALSE)) return -1;}
                        | CLASS identifier INHERITS identifier 
			{if (define_av_perms(TRUE)) return -1;}
                        | CLASS identifier INHERITS identifier '{' identifier_list '}'
			{if (define_av_perms(TRUE)) return -1;}
			;
opt_mls			: mls
                        | 
			;
mls			: sensitivities dominance opt_categories 
			levels opt_old_commons opt_mls_constraints
			;
opt_old_commons		: old_common_def
			|
			;
old_common_def		: COMMON identifier
			{ yyerror("Old (pre-v.19) MLS not supported."); return EOLDMLS; }
			;
sensitivities	 	: sensitivity_def 
			| sensitivities sensitivity_def
			;
sensitivity_def		: SENSITIVITY identifier alias_def ';'
			{if (define_sens()) return -1;}
			| SENSITIVITY identifier ';'
			{if (define_sens()) return -1;}
	                ;
alias_def		: ALIAS names
			;
dominance		: DOMINANCE '{' identifier_list '}' 
			{if (define_dominance()) return -1;}
			;
/* added Jul 2002 */
opt_categories          : categories
                        |
                        ;
categories 		: category_def 
			| categories category_def
			;
category_def		: CATEGORY identifier alias_def ';'
			{if (define_category()) return -1;}
			| CATEGORY identifier ';'
			{if (define_category()) return -1;}
			;
levels	 		: level_def 
			| levels level_def
			;
level_def		: LEVEL identifier ':' id_comma_list ';'
			{if (define_level()) return -1;}
			| LEVEL identifier ';' 
			{if (define_level()) return -1;}
			| LEVEL identifier ':' identifier '.' { if (insert_id(".", 0)) return -1; } identifier ';'
			{if (define_level()) return -1;} 
			;
te_rbac			: te_rbac_decl
			| te_rbac te_rbac_decl
			;
te_rbac_decl		: te_decl
			| rbac_decl
			| range_trans_decl
			| optional_block
			| ';'
                        ;
range_trans_decl	:range_transition_def
			;
rbac_decl		: role_type_def
                        | role_dominance
                        | role_trans_def
 			| role_allow_def
			;
			/* added July 2002; we make optional for backwards compatability */
			/* added optional conditional language stuff */
te_decl			: attribute_def
			| cond_def
			| type_def
			| typeattribute_def
			| typealias_def
                        | transition_def
                        | te_avtab_def
                        /* removed July 2002; remain for backward compatability */
			| te_clone_def
			;
/*  added July 2002 */
attribute_def           : ATTRIBUTE identifier ';'
                        { if (define_attrib()) return -1;}
                        ;
                        
/* support for conditional policy language extensions */
cond_def		: bool_def
			| cond_stmt_def
			;
bool_def                : BOOL identifier bool_val ';'
                        {if (define_bool()) return -1;}
                        ;
bool_val                : CTRUE
 			{ if (insert_id("T",0)) return -1; }
                        | CFALSE
			{ if (insert_id("F",0)) return -1; }
                        ;
cond_stmt_def           : IF cond_expr '{' cond_pol_list '}' %prec LOWER_THAN_ELSE
                        { if (define_conditional((cond_expr_t*)$2, (cond_rule_list_t*)$4, (cond_rule_list_t*)NULL) < 0) return -1; }
                        | IF cond_expr '{' cond_pol_list '}' cond_stmt_else_def cond_pol_list '}'
                        { if (define_conditional((cond_expr_t*)$2, (cond_rule_list_t*)$4, (cond_rule_list_t*)$7) < 0 ) return -1;  }
                        ;
cond_stmt_else_def	: ELSE '{'
			{ yybegin_initial();}
			;
cond_expr               : '(' cond_expr ')'
			{ $$ = $2;}
			| NOT cond_expr
			{ $$ = define_cond_expr(COND_NOT, $2, NULL);
			  if ($$ == NULL) return -1; }
			| cond_expr AND cond_expr
			{ $$ = define_cond_expr(COND_AND, $1, $3);
			  if ($$ == NULL) return -1; }
			| cond_expr OR cond_expr
			{ $$ = define_cond_expr(COND_OR, $1, $3);
			  if ($$ == NULL) return -1; }
			| cond_expr XOR cond_expr
			{ $$ = define_cond_expr(COND_XOR, $1, $3);
			  if ($$ == NULL) return -1; }
			| cond_expr EQUALS cond_expr
			{ $$ = define_cond_expr(COND_EQ, $1, $3);
			  if ($$ == NULL) return -1; }
			| cond_expr NOTEQUAL cond_expr
			{ $$ = define_cond_expr(COND_NEQ, $1, $3);
			  if ($$ == NULL) return -1; }
			| cond_expr_prim
			{ $$ = $1; }
			;
cond_expr_prim          : identifier
                        { $$ = define_cond_expr(COND_BOOL, NULL, NULL);
			  if ($$ == NULL) return -1; }
                        ;
cond_pol_list           : /* empty */
                        { $$ = (cond_rule_list_t*)NULL; }
                        | cond_pol_list cond_rule_def 
                        { $$ = define_cond_pol_list((cond_rule_list_t*)$1, (rule_desc_t*)$2);
			  if ($$ == 0) return -1; }
			;
cond_rule_def           : cond_transition_def
                        { $$ = $1;
			  if ($$ == NULL) return -1; }
                        | cond_te_avtab_def
                        { $$ = $1;
			  if ($$ == NULL) return -1; }
			| require_block
			{$$ = NULL;}
                        ;
cond_transition_def	: TYPE_TRANSITION names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(RULE_TE_TRANS) ;
                          if ($$ == 0) return -1;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(RULE_TE_MEMBER) ;
                          if ($$ ==  0) return -1;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(RULE_TE_CHANGE) ;
                          if ($$ ==  0) return -1;}
    			;
cond_te_avtab_def	: cond_allow_def
                          { $$ = $1; }
			| cond_auditallow_def
			  { $$ = $1; }
			| cond_auditdeny_def
			  { $$ = $1; }
			| cond_dontaudit_def
			  { $$ = $1; }
			;
cond_allow_def		: ALLOW names names ':' names names  ';'
			{ $$ = define_cond_te_avtab(RULE_TE_ALLOW) ;
                          if ($$ == 0) return -1; }
		        ;
cond_auditallow_def	: AUDITALLOW names names ':' names names ';'
			{ $$ = define_cond_te_avtab(RULE_AUDITALLOW) ;
                          if ($$ == 0) return -1; }
		        ;
cond_auditdeny_def	: AUDITDENY names names ':' names names ';'
			{ $$ = define_cond_te_avtab(RULE_AUDITDENY) ;
                          if ($$ == 0) return -1; }
		        ;
cond_dontaudit_def	: DONTAUDIT names names ':' names names ';'
			{ $$ = define_cond_te_avtab(RULE_DONTAUDIT);
                          if ($$ == 0) return -1; }
                        ;


/* removed July 2002; remain for backward compatability */
te_clone_def            : CLONE identifier identifier ';'
			{if (define_te_clone()) return -1;}
			;
type_def		: TYPE identifier alias_def opt_attr_list ';'
                        {if (define_type(1)) return -1;}
	                | TYPE identifier opt_attr_list ';'
                        {if (define_type(0)) return -1;}
    			;
/* added jan 2005 */
typeattribute_def	: TYPEATTRIBUTE identifier id_comma_list ';'
			{if (define_typeattribute()) return -1; }
			;
/* added feb 2004 */			
typealias_def		: TYPEALIAS identifier alias_def ';'
			{if (define_typealias()) return -1;}
			;
opt_attr_list           : ',' id_comma_list
			| 
			;
transition_def		: TYPE_TRANSITION names names ':' names identifier ';'
                        {if (define_compute_type(RULE_TE_TRANS)) return -1;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        {if (define_compute_type(RULE_TE_MEMBER)) return -1;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        {if (define_compute_type(RULE_TE_CHANGE)) return -1;}
    			;
range_transition_def	:  RANGE_TRANSITION names names mls_range_def ';'
			{ if (define_range_trans() | define_mls()) return -1; }
			;
te_avtab_def		: allow_def
			| auditallow_def
			| auditdeny_def
			/* Jul 2002, removed notify and added dontaudit */
			| dontaudit_def
			| neverallow_def
			;
allow_def		: ALLOW names names ':' names names  ';'
			{if (define_te_avtab(RULE_TE_ALLOW)) return -1; }
		        ;
auditallow_def		: AUDITALLOW names names ':' names names ';'
			{if (define_te_avtab(RULE_AUDITALLOW)) return -1; }
		        ;
auditdeny_def		: AUDITDENY names names ':' names names ';'
			{if (define_te_avtab(RULE_AUDITDENY)) return -1; }
		        ;
/* Jul 2002, removed notify and added dontaudit */
dontaudit_def		: DONTAUDIT names names ':' names names ';'
			{if (define_te_avtab(RULE_DONTAUDIT)) return -1; }
		        ;
neverallow_def		: NEVERALLOW names names ':' names names  ';'
			{if (define_te_avtab(RULE_NEVERALLOW)) return -1; }
		        ;
role_type_def		: ROLE identifier ';'
			{if (define_role_types()) return -1;}
			| ROLE identifier TYPES names ';'
			{if (define_role_types()) return -1;}
                        ;
role_dominance		: DOMINANCE '{' roles '}'
			;
role_trans_def		: ROLE_TRANSITION names names identifier ';'
			{if (define_role_trans()) return -1; }
			;
role_allow_def		: ALLOW names names ';'
			{if (define_role_allow()) return -1; }
			;
roles			: role_def
			{ $$ = $1; }
			| roles role_def
			{ $$ = merge_roles_dom((ap_role_t*)$1, (ap_role_t*)$2); if ($$ == 0) return -1;}
			;
role_def		: ROLE identifier_push ';'
                        {$$ = define_role_dom(NULL); if ($$ == 0) return -1;}
			| ROLE identifier_push '{' roles '}'
                        {$$ = define_role_dom((ap_role_t*)$4); if ($$ == 0) return -1;}
			;
/* added July 2002; made constraints optional */
opt_constraints         : constraints
                        |
                        ;
opt_mls_constraints	: mls_constraints
			|
			;

constraints		: constraint_def 
			| constraints constraint_def
			| validatetrans_def
			| constraints validatetrans_def
			;
mls_constraints		: mls_constraint_def 
			| mls_constraints mls_constraint_def
			| mlsvalidatetrans_def
			| mls_constraints mlsvalidatetrans_def
			;
constraint_def		: CONSTRAIN names names mls_cexpr ';'
			{ if (define_constraint(FALSE, (ap_constraint_expr_t *)$4)) return -1; }
			;
mls_constraint_def	: MLSCONSTRAIN names names mls_cexpr ';'
			{ if (define_mls() | define_constraint(TRUE, (ap_constraint_expr_t *)$4)) return -1; } 
			;
validatetrans_def	: VALIDATETRANS names mls_trans_cexpr ';'
			{ if (define_validatetrans(FALSE, (ap_constraint_expr_t *)$3)) return -1; }
			;
mlsvalidatetrans_def	: MLSVALIDATETRANS names mls_trans_cexpr ';'
			{ if (define_mls() | define_validatetrans(TRUE, (ap_constraint_expr_t *)$3)) return -1; }
			;
mls_cexpr		: '(' mls_cexpr ')'
			{ $$ = $2; }
			| NOT mls_cexpr
			{ $$ = (int) define_cexpr(AP_CEXPR_NOT, $2, 0);
			  if ($$ == 0) return -1; }
			| mls_cexpr AND mls_cexpr
			{ $$ = (int) define_cexpr(AP_CEXPR_AND, $1, $3);
			  if ($$ == 0) return -1; }
			| mls_cexpr OR mls_cexpr
			{ $$ = (int) define_cexpr(AP_CEXPR_OR, $1, $3);
			  if ($$ == 0) return -1; }
			| mls_cexpr_prim
			{ $$ = $1; }
			;
mls_trans_cexpr		: '(' mls_trans_cexpr ')'
			{ $$ = $2; }
			| NOT mls_trans_cexpr
			{ $$ = (int) define_cexpr(AP_CEXPR_NOT, $2, 0);
			  if ($$ == 0) return -1; }
			| mls_trans_cexpr AND mls_trans_cexpr
			{ $$ = (int) define_cexpr(AP_CEXPR_AND, $1, $3);
			  if ($$ == 0) return -1; }
			| mls_trans_cexpr OR mls_trans_cexpr
			{ $$ = (int) define_cexpr(AP_CEXPR_OR, $1, $3);
			  if ($$ == 0) return -1; }
			| mls_trans_cexpr_prim
			{ $$ = $1; }
			;
cexpr_prim		: U1 op U2
			{ $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_USER, $2);
			  if ($$ == 0) return -1; }
			| R1 roleop R2
			{ $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| T1 op T2
			{ $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_TYPE, $2);
			  if ($$ == 0) return -1; }
			| U1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_USER, $2);
			  if ($$ == 0) return -1; }
			| U2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_USER | AP_CEXPR_TARGET, $2);
			  if ($$ == 0) return -1; }
			| R1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| R2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_ROLE | AP_CEXPR_TARGET, $2);
			  if ($$ == 0) return -1; }
			| T1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_TYPE, $2);
			  if ($$ == 0) return -1; }
			| T2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_TYPE | AP_CEXPR_TARGET, $2);
			  if ($$ == 0) return -1; }
			| SAMEUSER
			{ $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_USER, AP_CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| SOURCE ROLE { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_ROLE, AP_CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| TARGET ROLE { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_ROLE | AP_CEXPR_TARGET, AP_CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| ROLE roleop
			{ $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| SOURCE TYPE { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_TYPE, AP_CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| TARGET TYPE { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_TYPE | AP_CEXPR_TARGET, AP_CEXPR_EQ);
			  if ($$ == 0) return -1; }
			;
trans_prim		: U3 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_USER | AP_CEXPR_XTARGET, $2);
			  if ($$ == 0) return -1; }
			| R3 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_ROLE | AP_CEXPR_XTARGET, $2);
			  if ($$ == 0) return -1; }
			| T3 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = (int) define_cexpr(AP_CEXPR_NAMES, AP_CEXPR_TYPE | AP_CEXPR_XTARGET, $2);
			  if ($$ == 0) return -1; }
			;
mls_prim		: L1 roleop L2
			{ if (!mls_valid()) YYABORT;
			  $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_MLS_LOW1_LOW2, $2);
			  if ($$ == 0) return -1; }
			| L1 roleop H2
			{ if (!mls_valid()) YYABORT;
			  $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_MLS_LOW1_HIGH2, $2);
			  if ($$ == 0) return -1; }
			| H1 roleop L2
			{ if (!mls_valid()) YYABORT;
			  $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_MLS_HIGH1_LOW2, $2);
			  if ($$ == 0) return -1; }
			| H1 roleop H2
			{ if (!mls_valid()) YYABORT;
			  $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_MLS_HIGH1_HIGH2, $2);
			  if ($$ == 0) return -1; }
			| L1 roleop H1
			{ if (!mls_valid()) YYABORT;
			  $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_MLS_LOW1_HIGH1, $2);
			  if ($$ == 0) return -1; }
			| L2 roleop H2
			{ if (!mls_valid()) YYABORT;
			  $$ = (int) define_cexpr(AP_CEXPR_ATTR, AP_CEXPR_MLS_LOW2_HIGH2, $2);
			  if ($$ == 0) return -1; }
			;
trans_cexpr_prim	: trans_prim
			{ $$ = $1; }
			| cexpr_prim
			{ $$ = $1; }
			;
mls_cexpr_prim		: mls_prim
			{ $$ = $1; }
			| cexpr_prim
			{ $$ = $1; }
			;
mls_trans_cexpr_prim	: trans_cexpr_prim
			{ $$ = $1; }
			| mls_prim
			{ $$ = $1; }
			;
op			: EQUALS
			{ $$ = AP_CEXPR_EQ; }
			| NOTEQUAL
			{ $$ = AP_CEXPR_NEQ; }
			;
roleop			: op 
			{ $$ = $1; }
			| DOM
			{ $$ = AP_CEXPR_DOM; }
			| DOMBY
			{ $$ = AP_CEXPR_DOMBY; }
			| INCOMP
			{ $$ = AP_CEXPR_INCOMP; }
			;
users			: user_def
			| users user_def
			;
user_id			: identifier
			;
user_def		: USER user_id ROLES names opt_mls_components ';'
	                {if (define_user()) return -1;}
			;
opt_mls_components	: LEVEL mls_level_def RANGE user_range 
			{ if (!mls_valid()) YYABORT; }
			| 
			;
user_range		: mls_range_def
			;
initial_sid_contexts	: initial_sid_context_def
			| initial_sid_contexts initial_sid_context_def
			;
initial_sid_context_def	: SID identifier security_context_def
			{if (define_initial_sid_context()) return -1;}
			;

/* added Jul 2002 to maintain backwards compatabililty with previous
 * policy versions 
 *
 * current distinctions are:
 * pre_jul_2002		policy versions prior to version 11
 * jul_2002		policy version 11 or later
 */			
policy_version_contexts	: version_jul_2002
			| versions_pre_jul_2002
			;

version_jul_2002	: opt_fs_contexts_11 fs_uses opt_genfs_contexts 
				net_contexts_11
			;
			
versions_pre_jul_2002	: fs_contexts_pre11
			  opt_devfs_contexts { /* this is a new policy component added in the
			                      May 2002 release of SE Linux.  We are making this
			                      optional so that apolicy will (for now at least)
			                      work wih older policies as well as newer ones */ }
			  net_contexts_pre11
			;


/* added Jul 2002 */
fs_uses                 : fs_use_def
                        | fs_uses fs_use_def
                        ;
/* added Jul 2002 */
/* changed Jul 2003; added FSUSEXATTR */
fs_use_def              : FSUSEPSID identifier ';' 
                        {if (define_fs_use(AP_FS_USE_PSID, POL_VER_JUL2002)) return -1;}
                        | FSUSEXATTR identifier security_context_def ';'
                        {if (define_fs_use(AP_FS_USE_XATTR, POL_VER_15)) return -1;}
                        | FSUSETASK identifier security_context_def ';'
                        {if (define_fs_use(AP_FS_USE_TASK, POL_VER_JUL2002)) return -1;}
                        | FSUSETRANS identifier security_context_def ';'
                        {if (define_fs_use(AP_FS_USE_TRANS, POL_VER_JUL2002)) return -1;}
                        ; 
/* added Jul 2002 */                       
opt_genfs_contexts      : genfs_contexts
                        | 
                        ;
/* added Jul 2002 */ 
genfs_contexts	        : genfs_context_def
			| genfs_contexts genfs_context_def
			;
/* added Jul 2002 */ 
genfs_context_def	: GENFSCON identifier path '-' identifier security_context_def
			{if (define_genfs_context(1)) return -1;}
			| GENFSCON identifier path '-' '-' {insert_id("-", 0);} security_context_def
			{if (define_genfs_context(1)) return -1;}
                        | GENFSCON identifier path security_context_def
			{if (define_genfs_context(0)) return -1;}
			;


/* added Jul 2002 */
opt_fs_contexts_11      : fs_contexts_11 
                        |
                        ;
fs_contexts_11		: fs_context_def_11
			| fs_contexts_11 fs_context_def_11
			;
			
fs_contexts_pre11	: fs_context_def_pre11
			| fs_contexts_pre11 fs_context_def_pre11
			;
/* changed Jul 2002, added FSCON keyword */
fs_context_def_11	: FSCON number number security_context_def security_context_def
			{if (define_fs_context(POL_VER_JUL2002)) return -1;}
			;
/* removed Jul 2002, keep for backward compatability */
fs_context_def_pre11	: number number security_context_def security_context_def
			{if (define_fs_context(POL_VER_PREJUL2002)) return -1;}
			;

/* net_context versions */
net_contexts_11		: opt_port_contexts_11 opt_netif_contexts_11 opt_node_contexts_11 
			;
net_contexts_pre11	: port_contexts_pre11 netif_contexts_pre11 node_contexts_pre11 opt_nfs_contexts
			;

/* added Jul 2002 */
opt_port_contexts_11  	: port_contexts_11
                        |
                        ;
port_contexts_11	: port_context_def_11
			| port_contexts_11 port_context_def_11
			;
			
/* changed Jul 2002 to add PORTCON keyword */
port_context_def_11	: PORTCON identifier number security_context_def
			{if (define_port_context(POL_VER_JUL2002, $3, $3)) return -1;}
			| PORTCON identifier number '-' number security_context_def
			{if (define_port_context(POL_VER_JUL2002, $3, $5)) return -1;}
			;
/* removed in Jul 2002; keep to allow old form for backwards compatability */
port_contexts_pre11	: port_context_def_pre11
			| port_contexts_pre11 port_context_def_pre11
			;
port_context_def_pre11	: identifier number security_context_def
			{if (define_port_context(POL_VER_PREJUL2002, $2, $2)) return -1;}
			| identifier number '-' number security_context_def
			{if (define_port_context(POL_VER_PREJUL2002, $2, $4)) return -1;}
			;
/* added Jul 2002 */
opt_netif_contexts_11   : netif_contexts_11
                        |
                        ;
/* changed Jul 2002 to add NETIFCON keyword */
netif_contexts_11	: netif_context_def_11
			| netif_contexts_11 netif_context_def_11
			;
netif_context_def_11	: NETIFCON identifier security_context_def security_context_def
			{if (define_netif_context(POL_VER_JUL2002)) return -1;} 
			;
/* removed in Jul 2002; keep to allow old form for backwards compatability */
netif_contexts_pre11	: netif_context_def_pre11
			| netif_contexts_pre11 netif_context_def_pre11 
			;
netif_context_def_pre11	: identifier security_context_def security_context_def
			{if (define_netif_context(POL_VER_PREJUL2002)) return -1;}
			;
/* added Jul 2002 */
opt_node_contexts_11   	: node_contexts_11 
                        |
                        ;
node_contexts_11	: node_context_def_11
			| node_contexts_11 node_context_def_11
			;
/* changed Jul 2002 to add NODECON keyword (v 11) or later version changes (e.g., 17 w/ IPv6) */
node_context_def_11	: NODECON ipv4_addr_def ipv4_addr_def security_context_def
			{if (define_ipv4_node_context(POL_VER_JUL2002, $2, $3)) return -1;}
			| NODECON ipv6_addr ipv6_addr security_context_def
			{if (define_ipv6_node_context(POL_VER_17)) return -1;}
 			;
/* Jul 2002, allow for old form for backwards compatability */
node_contexts_pre11	: node_context_def_pre11
			| node_contexts_pre11 node_context_def_pre11 
			;
/* removed in Jul 2002; keep to allow old form for backwards compatability */
node_context_def_pre11	: ipv4_addr_def ipv4_addr_def security_context_def
			{if (define_ipv4_node_context(POL_VER_PREJUL2002, $1, $2)) return -1;}
			;
/* all NFS remove Jul 2002 */
opt_nfs_contexts        : nfs_contexts
                        |
                        ;
nfs_contexts		: nfs_context_def
			| nfs_contexts nfs_context_def
			;
nfs_context_def	        : ipv4_addr_def ipv4_addr_def security_context_def security_context_def
			{if (define_nfs_context()) return -1;}
			;

/* removed Jul 2002 */
opt_devfs_contexts	: devfs_contexts
			|
			;
/* removed Jul 2002 */
devfs_contexts		: devfs_context_def 
			| devfs_contexts devfs_context_def
			;
/* removed Jul 2002 */
devfs_context_def	: path '-' identifier security_context_def
			{if (define_devfs_context(1)) return -1;}
                        | path security_context_def
			{if (define_devfs_context(0)) return -1;}
			;
ipv4_addr_def		: number '.' number '.' number '.' number
			{
				unsigned int address = 0;
				address |= ($1 & 0xff);
				address = address << 8;
				address |= ($3 & 0xff);
				address = address << 8;
				address |= ($5 & 0xff);
				address = address << 8;
				address |= ($7 & 0xff);
				$$ = address;
			}
			;	
ipv6_addr		: IPV6_ADDR
			{ if (insert_id(yytext,0)) return -1; }
			;
security_context_def	: user_id ':' identifier ':' identifier opt_mls_range_def
	                ;
opt_mls_range_def	: ':' mls_range_def
			|	
			;
mls_range_def		: mls_level_def '-' mls_level_def
			{if (insert_separator(0)) return -1;}
	                | mls_level_def
			{if (insert_separator(0)) return -1;}
	                ;
mls_level_def		: identifier ':' id_comma_list
			{if (insert_separator(0)) return -1;}
	                | identifier 
			{if (insert_separator(0)) return -1;}
			| identifier ':' identifier '.' { if (insert_id(".", 0)) return -1; } identifier
			{ if (insert_separator(0)) return -1; }
			;
optionals : optionals optional_block
			| optionals optional_stray_else %prec LOWER_THAN_ELSE
			| /* empty */
			;
optional_stray_else 	: optional_stray_else_def '}'
			{yyleave_state();}
			;
optional_stray_else_def: ELSE '{'
			{yyenter_ignore();}
			;
optional_block		: optional_block_main optional_else
			{end_optional();}
			;
optional_block_main	: optional_decl avrules_block '}'
			{optional_end_main();}
			;
optional_decl		: OPTIONAL '{' 
			{begin_optional();}
			;
optional_else		: optional_else_decl avrules_block '}'
			{end_optional_else();}
			| %prec LOWER_THAN_ELSE /* empty */
			;
optional_else_decl	: ELSE '{'
			{begin_optional_else();}
			;
avrules_block		: avrule_decls avrule_user_defs
			;
avrule_decls            : avrule_decls avrule_decl
                        | /* empty */
                        ;
avrule_decl             : rbac_decl
                        | te_decl
			| if_decl
			| optional_stray_else %prec LOWER_THAN_ELSE
                        | require_block
			| identifier {free(queue_remove(id_queue));}
			| optional_block
			| ':'
                        | ';'
                        ;
if_decl			: if_decl_header avrule_decls '}'
			{yyleave_state();}
			if_decl_else
			;	
if_decl_header		: DECLIF '{'
			{yyenter_decl();}
			;
if_decl_else		: if_decl_else_header avrule_decls '}'
			{yyleave_state();}
			| %prec LOWER_THAN_ELSE /* empty */
			;
if_decl_else_header	: ELSE '{'
			{yyenter_decl();}
			;
require_block           : require_header require_list '}'
			{yyleave_state();}
                        ;
require_header		: REQUIRE '{'
			{begin_require();}
			;
require_list            : require_list require_decl
                        | /* empty */
                        ;
require_decl            : require_class ';'
                        | require_decl_def require_id_list ';'
			{ add_require($1);}
                        ;
require_class           : CLASS identifier names
			{ add_require(IDX_OBJ_CLASS); }
			;
require_decl_def	: ROLE { $$ = IDX_ROLE; }
			| TYPE { $$ = IDX_TYPE; }
			| ATTRIBUTE { $$ = IDX_ATTRIB; }
			| USER { $$ = IDX_USER; }
			| BOOL { $$ = IDX_BOOLEAN; }
			;
require_id_list		: identifier
			| require_id_list ',' identifier
			;
avrule_user_defs        : user_def avrule_user_defs
                        | /* empty */
                        ;
id_comma_list           : identifier
			| id_comma_list ',' identifier
			;
tilde			: '~'
			;
asterisk		: '*'
                        ;
exclude                 : '-'

/* Jul 2002 nesting logic changed slightly */			;
names           	: identifier
			{ if (insert_separator(0)) return -1; }
			| nested_id_set
			{ if (insert_separator(0)) return -1; }
			| asterisk
                        { if (insert_id("*", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
			| tilde identifier
                        { if (insert_id("~", 0)) return -1;
			  if (insert_separator(0)) return -1; }
                        | identifier exclude { if (insert_id("-", 0)) return -1; } identifier
                        { if (insert_separator(0)) return -1; }
			| tilde nested_id_set
	 		{ if (insert_id("~", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
			;
tilde_push              : tilde
                        { if (insert_id("~", 1)) return -1; }
			;
asterisk_push           : asterisk
                        { if (insert_id("*", 1)) return -1; }
			;
names_push		: identifier_push
			| '{' identifier_list_push '}'
			| asterisk_push
			| tilde_push identifier_push
			| tilde_push '{' identifier_list_push '}'
			;
identifier_list_push	: identifier_push
			| identifier_list_push identifier_push
			;
identifier_push		: IDENTIFIER
			{ if (insert_id(yytext, 1)) return -1; }
			;
identifier_list		: identifier
			| identifier_list identifier
			;
/* added Jul 2002*/
nested_id_set           : '{' nested_id_list '}'
                        ;
nested_id_list          : nested_id_element | nested_id_list nested_id_element
                        ;
nested_id_element       : identifier | '-' { if (insert_id("-", 0)) return -1; } identifier | nested_id_set
			;
/* end add */
identifier		: IDENTIFIER
			{ if (insert_id(yytext,0)) return -1; }
			;
path     		: PATH
			{ if (insert_id(yytext,0)) return -1; }
			;
number			: NUMBER 
			{ $$ = strtoul(yytext,NULL,0); }
			;
%%
static int insert_separator(int push)
{
	int error;

	if (push)
		error = queue_push(id_queue, 0);
	else
		error = queue_insert(id_queue, 0);

	if (error) {
		yyerror("queue overflow");
		return -1;
	}
	return 0;
}

static int insert_id(char *id, int push)
{
	char *newid = 0;
	int error;

	newid = (char *) malloc(strlen(id) + 1);
	if (!newid) {
		yyerror("out of memory");
		return -1;
	}
	strcpy(newid, id);
	if (push)
		error = queue_push(id_queue, (queue_element_t) newid);
	else
		error = queue_insert(id_queue, (queue_element_t) newid);

	if (error) {
		yyerror("queue overflow");
		free(newid);
		return -1;
	}
	return 0;
}

/* added with Jul 2002 policy changes; allows for explicit declarations of type attributes */
static int define_attrib(void)
{
	char *id;
	int rt;
	
	rt = set_policy_version(POL_VER_JUL2002, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	if (pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_TYPES))) {
		free(queue_remove(id_queue));
		return 0;
	}

	if (pass > 2 && yyis_decl()) {
		add_name(queue_remove(id_queue), &(parse_policy->optionals->attribs));
		return 0;
	}

	id = queue_remove(id_queue);
	/* check whether already exists */
	rt = get_attrib_idx(id, parse_policy);
	if(rt >=0){
		snprintf(errormsg, sizeof(errormsg), "duplicate attribute decalaration (%s)\n", id);
		yyerror(errormsg);
		return -1;
	}
	if(!is_valid_str_sz(id)) {
		snprintf(errormsg,sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
		yyerror(errormsg);
		return -1;
	}
	rt = add_attrib(FALSE, 0, parse_policy, id);
	if(rt == -1) {
		yyerror("Error adding attribute via ATTRIBUTE keyword");
		return -1;
	}
	free(id);
	return 0;
}
	

static int define_type(int alias)
{
	char *id;
	int idx;

	if (pass == 2 ||(pass == 1 && !(parse_policy->opts & POLOPT_TYPES))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		/* change in 2002031409 version for alias syntax */
		if (alias) {
			while ((id = queue_remove(id_queue))) 
				free(id);
		}
		return 0;
	}

	if (pass > 2 && yyis_decl()) {
		add_name(queue_remove(id_queue), &(parse_policy->optionals->types));
		while ((id = queue_remove(id_queue))) 
			free(id);
		if (alias) {
			while ((id = queue_remove(id_queue))) 
				free(id);
		}
		return 0;
	}

	/* add the new type */
	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for type definition?");
		return -1;
	}
	if(!is_valid_str_sz(id)) {
		snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
		yyerror(errormsg);
		return -1;
	}
	idx = add_type(id, parse_policy);
	if(idx == -2) {
		snprintf(errormsg, sizeof(errormsg), "duplicate type decalaration (%s)\n", id);
		yyerror(errormsg);
		return -1;
	}
	else if(idx < 0)
		return -1;	
			
	/* aliases */
	if (alias) { 
		while ((id = queue_remove(id_queue))) {
			if(!is_valid_str_sz(id)) {
				snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
				yyerror(errormsg);
				return -1;
			}
			if(add_alias(idx, id, parse_policy) != 0) {
				snprintf(errormsg, sizeof(errormsg), "failed add_name for alias %s\n", id);
				yyerror(errormsg);
				return -1;			
			}
			free(id); /* add_alias() makes its owm copy of the string */
		}
	}
	
	/*  attribs */
	while ((id = queue_remove(id_queue))) {
		if(!is_valid_str_sz(id)) {
			snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
			yyerror(errormsg);
			return -1;
		}
		if(add_attrib_to_type(idx, id, parse_policy) != 0)
			return -1;
	}
	return 0;
}	

static int define_typeattribute(void)
{
	char *id;
	int rt, idx, idx_type;
	
	if (pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_TYPES)) || (pass > 2 && yyis_decl())) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}
	
	rt = set_policy_version(POL_VER_18_20, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	
	id = (char*)queue_remove(id_queue);
	if (!id) {
		yyerror("type name required for typeattribute declaration");
		return -1;
	}
	idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
	if (idx < 0) {
		snprintf(errormsg, sizeof(errormsg), "unknown type %s in typeattribute definitition.", id);
		yyerror(errormsg);
		return -1;
	}
	if (idx_type != IDX_TYPE) {
		snprintf(errormsg, sizeof(errormsg), "%s is not a type. Illegal typeattribute definitition.", id);
		yyerror(errormsg);
		return -1;
	}
	
	while ((id = queue_remove(id_queue))) {
		if(!is_valid_str_sz(id)) {
			snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
			yyerror(errormsg);
			return -1;
		}
		if(add_attrib_to_type(idx, id, parse_policy) != 0)
			return -1;
	}
	return 0;
}

static int define_typealias(void)
{
	char *id;
	int idx, idx_type;
	
	if (pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_TYPES)) || (pass > 2 && yyis_decl()) ) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}
	
	id = (char*)queue_remove(id_queue);
	if (!id) {
		yyerror("type name required for typealias declaration");
		return -1;
	}
	idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
	if (idx < 0) {
		snprintf(errormsg, sizeof(errormsg), "unknown type %s in typealias definitition.", id);
		yyerror(errormsg);
		return -1;
	}
	if (idx_type != IDX_TYPE) {
		snprintf(errormsg, sizeof(errormsg), "%s is not a type. Illegal typealias definitition.", id);
		yyerror(errormsg);
		return -1;
	}
	while ((id = queue_remove(id_queue))) {
		if(!is_valid_str_sz(id)) {
			snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
			yyerror(errormsg);
			return -1;
		}
		if(add_alias(idx, id, parse_policy) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed add_alias for alias %s\n", id);
			yyerror(errormsg);
			return -1;			
		}
	}
	return 0;
}

/* add a rule to the provided av rule list */
static int add_avrule(int type, av_item_t **rlist, int *list_num, bool_t enabled) {
	int idx, idx_type;
	char *id;
	av_item_t *item;
	ta_item_t *titem;
	bool_t subtract;
		
	item = add_new_av_rule(type, parse_policy);
	if(item == NULL) {
		yyerror("Problem adding AV rule to policy database");
		return -1;
	}
	
	item->type = type;
	item->lineno = policydb_lineno;
	item->enabled = enabled;

	/* source (domain) types/attribs */
	subtract = FALSE;
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			item->flags |= AVFLAG_SRC_STAR;
			free(id);
			continue;
		}
		if(strcmp(id, "-") == 0) {
			subtract = TRUE;
			free(id);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			item->flags |= AVFLAG_SRC_TILDA;
			free(id);
			continue;
		}
		idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is neither a type nor type attribute", id);
			yyerror(errormsg);
			return -1;				
		}
		titem = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = idx_type;
		if (subtract) {
			titem->type |= IDX_SUBTRACT;
			subtract = FALSE;
		}
		titem->idx = idx;
		if(insert_ta_item(titem, &(item->src_types)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for source type id %s", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}
	
	/* target object types/attribs */
	subtract = FALSE;
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			item->flags |= AVFLAG_TGT_STAR;
			free(id);
			continue;
		}
		if(strcmp(id, "-") == 0) {
			subtract = TRUE;
			free(id);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			item->flags |= AVFLAG_TGT_TILDA;
			free(id);
			continue;
		}	
		idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is neither a type or type attribute", id);
			yyerror(errormsg);
			return -1;				
		}
		titem = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = idx_type;
		if (subtract) {
			titem->type |= IDX_SUBTRACT;
			subtract = FALSE;
		}
		titem->idx = idx;
		if(insert_ta_item(titem, &(item->tgt_types)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for target type id %s", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}		
	/* object classes */
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			yyerror("'*' operator cannot be applied to object classes");
			return -1;
		}
		if(strcmp(id, "~") == 0) {
			yyerror("'~' operator cannot be applied to object classes");
			return -1;
		}
		idx = get_obj_class_idx(id, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is not a valid object class name", id);
			yyerror(errormsg);
			return -1;
		}
		titem = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = IDX_OBJ_CLASS;
		titem->idx = idx;
		if(insert_ta_item(titem, &(item->classes)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for classes id %s", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}
	
	/* permissions */
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			item->flags |= AVFLAG_PERM_STAR;
			free(id);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			item->flags |= AVFLAG_PERM_TILDA;
			free(id);
			continue;
		}
		idx = get_perm_idx(id, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is not a valid permission name", id);
			yyerror(errormsg);
			return -1;
		}
		titem = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = IDX_PERM;
		titem->idx = idx;
		if(insert_ta_item(titem, &(item->perms)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for classes id %s", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}	
	return *list_num - 1;
}

/* store av rules */
static int define_te_avtab(int rule_type)
{
	int rt;
	char *id;

	if (pass == 1 || (pass > 2 && yyis_decl())) {
		goto skip_avtab_rule;
	}

	switch(rule_type) {
	case RULE_TE_ALLOW:
		if(!(parse_policy->opts & POLOPT_TE_ALLOW))
			goto skip_avtab_rule;
		rt = add_avrule(rule_type, &(parse_policy->av_access), &(parse_policy->num_av_access), TRUE);
		break;
	case RULE_NEVERALLOW:
		if(!(parse_policy->opts & POLOPT_TE_NEVERALLOW))
			goto skip_avtab_rule;
		rt = add_avrule(rule_type, &(parse_policy->av_access), &(parse_policy->num_av_access), TRUE);
		break;
	
	/* Jul 2002, added RULE_DONTAUDIT, which replaces RULE_NOTIFY */
	case RULE_DONTAUDIT:
		rt = set_policy_version(POL_VER_JUL2002, parse_policy);
		if(rt != 0) {
			yyerror("error setting policy version");
			return -1;
		}
		/* fall thru */
	case RULE_AUDITDENY:
		if(!(parse_policy->opts & POLOPT_TE_DONTAUDIT))
			goto skip_avtab_rule;
		rt = add_avrule(rule_type, &(parse_policy->av_audit), &(parse_policy->num_av_audit), TRUE);
		break;
	case RULE_AUDITALLOW:
		if(!(parse_policy->opts & POLOPT_TE_AUDITALLOW))
			goto skip_avtab_rule;
		rt = add_avrule(rule_type, &(parse_policy->av_audit), &(parse_policy->num_av_audit), TRUE);
		break;
	
	default:
		snprintf(errormsg, sizeof(errormsg), "Invalid AV type (%d)", rule_type);
		yyerror(errormsg);
		return -1;
	}
	if(rt < 0) 
		return rt;
	return 0;
skip_avtab_rule:
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	return 0;
}	

/* add a new type transition rule */
static int add_ttrule(int rule_type, bool_t enabled)
{
	int idx, idx_type;
	char *id;
	tt_item_t *item;
	ta_item_t *titem;
	bool_t subtract;
		
	item = add_new_tt_rule(rule_type, parse_policy);
	if(item == NULL) {
		yyerror("Problem adding TT rule to policy database");
		return -1;
	}
	
	item->type = rule_type;
	item->cond_expr = -1;
	item->lineno = policydb_lineno;
	item->enabled = enabled;
	
	/* source (domain) types/attribs */
	subtract = FALSE;
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			item->flags |= AVFLAG_SRC_STAR;
			free(id);
			continue;
		}
		if (strcmp(id, "-") == 0) {
			subtract = TRUE;
			free(id);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			item->flags |= AVFLAG_SRC_TILDA;
			free(id);
			continue;
		}

		idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is neither a type or type attribute", id);
			yyerror(errormsg);
			return -1;				
		}
		titem = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = idx_type;
		if (subtract) {
			titem->type |= IDX_SUBTRACT;
			subtract = FALSE;
		}
		titem->idx = idx;
		if(insert_ta_item(titem, &(item->src_types)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for source type id %s\n", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}
	
	/* target object types/attribs */
	subtract = FALSE;
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			item->flags |= AVFLAG_TGT_STAR;
			free(id);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			item->flags |= AVFLAG_TGT_TILDA;
			free(id);
			continue;
		}
		if (strcmp(id, "-") == 0) {
			subtract = TRUE;
			free(id);
			continue;
		}

		idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is neither a type or type attribute", id);
			yyerror(errormsg);
			return -1;				
		}
		titem = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = idx_type;
		if (subtract) {
			titem->type |= IDX_SUBTRACT;
			subtract = FALSE;
		}
		titem->idx = idx;
		if(insert_ta_item(titem, &(item->tgt_types)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for target type id %s\n", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}		
	
	/* object classes */
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			yyerror("'*' operator cannot be applied to object classes");
			return -1;
		}

		if(strcmp(id, "~") == 0) {
			yyerror("'~' operator cannot be applied to object classes");
			return -1;
		}

		idx = get_obj_class_idx(id, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is not a valid object class name", id);
			yyerror(errormsg);
			return -1;
		}
		titem = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = IDX_OBJ_CLASS;
		titem->idx = idx;
		if(insert_ta_item(titem, &(item->classes)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for classes id %s", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}
	
	/* default type */	
	id = queue_remove(id_queue);
	idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
	if(idx < 0 || idx_type != IDX_TYPE) {
		snprintf(errormsg, sizeof(errormsg), "default type %s is NOT a defined type.", id);
		yyerror(errormsg);
		return -1;				
	}
	item->dflt_type.type = idx_type;
	item->dflt_type.idx = idx;
	free(id);	

	return parse_policy->num_te_trans - 1;
}


/* put type transition (change, member) rules in policy object */
static int define_compute_type(int rule_type)
{
	char *id;
	int rt;
	
	if (pass == 1 || (pass > 2 && yyis_decl())) {
		goto skip_tt_rule;
	}

	switch(rule_type) {
	case RULE_TE_TRANS:
		if(!(parse_policy->opts & POLOPT_TE_TRANS))
			goto skip_tt_rule;
		break;	
	case RULE_TE_MEMBER:
		if(!(parse_policy->opts & POLOPT_TE_MEMBER))
			goto skip_tt_rule;
		break;
	case RULE_TE_CHANGE:
		if(!(parse_policy->opts & POLOPT_TE_CHANGE))
			goto skip_tt_rule;
		break;
	default:
		snprintf(errormsg, sizeof(errormsg), "Invalid type transition|member|change rule type (%d)", rule_type);
		yyerror(errormsg);
		return -1;
	}
	rt = add_ttrule(rule_type, TRUE);
	if(rt < 0) 
		return rt;
		
	return 0;
	
skip_tt_rule:
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	id = queue_remove(id_queue);
	free(id);
	return 0;	
}

/* capture clone rule; we won't actually clone rules but keep the actual CLONE statements 
 * and resolve clones when needed */
/* pre Jul 2002 only */
static int define_te_clone(void)
{
	char *id;
	int  src, tgt, rt;

	if (pass == 1 || (pass > 2 && yyis_decl())) {
		id = queue_remove(id_queue);
		free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}
	id = queue_remove(id_queue);
	src = get_type_idx(id, parse_policy);
	if(src < 0) {
		snprintf(errormsg, sizeof(errormsg), "Invalid source type (%s)", id);
		yyerror(errormsg);
		return -1;
	}
	free(id);
	
	id = queue_remove(id_queue);
	tgt = get_type_idx(id, parse_policy);
	if(tgt < 0) {
		snprintf(errormsg, sizeof(errormsg), "Invalid target type (%s)", id);
		yyerror(errormsg);
		return -1;
	}
	free(id);	
	
	rt = add_clone_rule(src, tgt, policydb_lineno, parse_policy);
	if(rt != 0) return rt;
	
	(parse_policy->rule_cnt[RULE_CLONE])++;

	rt= set_policy_version(POL_VER_PREJUL2002, parse_policy);
	if (rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	return 0;	
}


static int define_role_types(void)
{
	char *id, *or_name;
	int role_idx, idx, idx_type, rt, i;
	bool_t tilde_found = FALSE, subtract = FALSE;
	int *list_types = NULL, *tmp = NULL, *subtracted = NULL; 
	int num_list_types = 0, num_tmp = 0, num_subtracted = 0;

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_ROLES))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	if (pass > 2 && yyis_decl()) {
		add_name(queue_remove(id_queue), &(parse_policy->optionals->roles));
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no role name for role definition?");
		return -1;
	}
	if(!is_valid_str_sz(id) ) {
		snprintf(errormsg, sizeof(errormsg), "string \"%s\" is too large", id);
		yyerror(errormsg);
		return -1;
	}
	
	/* If this is the first role to be added, then add the hard-coded
	 * default object role "object_r" as it will not show up in the policy */
	if(parse_policy->num_roles < 1) {
		or_name = (char *)malloc(strlen(OBJECT_R_NAME) + 1);
		strcpy(or_name, OBJECT_R_NAME);
		role_idx = add_role(or_name, parse_policy);
		if(role_idx < 0) {
			yyerror("Problem adding object role object_r to policy");
			free(id);
			return -1;
		}
		assert(role_idx == 0);
	}
	
	/* if the role already exists, we'll just add the new type, otherwise
	 * we create new role */
	role_idx = get_role_idx(id, parse_policy);
	if(role_idx < 0) {
		role_idx = add_role(id, parse_policy);
		/* don't free id if we added it; the add_role type uses the memory */
		if(role_idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "Problem adding role %s to policy", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
	}
	else {
		/* get rid of the role name if it alrady exists */
		free(id);
	}
	/* add the types or attributes */	
	while ((id = queue_remove(id_queue))) {
		if (!strcmp(id, "*")) {
			/* skip type 0 it is "self" */
			for (i = 1; i < parse_policy->num_types; i++) {
				rt = add_type_to_role(i, role_idx, parse_policy);
				if(rt != 0)
					return rt;
			}
			free(id);
			break;
		}
		if (!strcmp(id, "~")) {
			tilde_found = TRUE;
			free(id);
			continue;
		} 
		if (!strcmp(id, "-")) {
			subtract = TRUE;
			free(id);
			continue;
		}
		idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "Invalid type or attribute name (%s) in role definition", id);
			yyerror(errormsg);
			return -1;
		}
		if (idx_type == IDX_ATTRIB) {
			rt = get_attrib_types(idx, &num_tmp, &tmp, parse_policy);
			if (rt != 0) {
				free(tmp);
				return rt;
			}
			for (i = 0; i < num_tmp; i++) {
				if (subtract) {
					rt = add_i_to_a(tmp[i], &num_subtracted, &subtracted);
					if (rt != 0)
						return rt;
				} else {
					rt = add_i_to_a(tmp[i], &num_list_types, &list_types);
					if (rt != 0)
						return rt;
				}
			}
			subtract = FALSE;
			free(tmp);
			tmp = NULL;
			num_tmp = 0;
		} else {
			if (subtract) {
				rt = add_i_to_a(idx, &num_subtracted, &subtracted);
				if (rt != 0)
					return rt;
				subtract = FALSE;
			} else {
				rt = add_i_to_a(idx, &num_list_types, &list_types);
				if (rt != 0)
					return rt;
			}
		}
		free(id);	
	}
	for (i = 0; i < num_list_types; i++) {
		if (find_int_in_array(list_types[i], subtracted, num_subtracted) == -1) {
			rt = add_i_to_a(list_types[i], &num_tmp, &tmp);
			if (rt != 0)
				return rt;
		}
	}
	if (tilde_found) {
		/* skip type 0 it is "self" */
		for (i = 1; i < parse_policy->num_types; i++) {
			if (find_int_in_array(i, tmp, num_tmp) == -1) {
				rt = add_type_to_role(i, role_idx, parse_policy);
				if (rt != 0) {
					snprintf(errormsg, sizeof(errormsg), "error adding types to role (%s)", parse_policy->roles[role_idx].name);
					yyerror(errormsg);
					return rt;
				}
			}
		}
	} else {
		for (i = 0; i < num_tmp; i++) {
			rt = add_type_to_role(tmp[i], role_idx, parse_policy);
			if (rt != 0) {
				snprintf(errormsg, sizeof(errormsg), "error adding types to role (%s)", parse_policy->roles[role_idx].name);
				yyerror(errormsg);
				return rt;
			}
		}
	}

	free(tmp);
	free(list_types);
	free(subtracted);
	return 0;
}


static int define_role_allow(void)
{
	char *id;
	int idx;
	ta_item_t *role = NULL;
	role_allow_t *rule = NULL;
	
	if(pass == 1 || (pass == 2 && !(parse_policy-> opts & POLOPT_ROLE_RULES)) || (pass > 2 && yyis_decl())) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}
	
	if(parse_policy->num_role_allow >= parse_policy->list_sz[POL_LIST_ROLE_ALLOW]) {
		/* grow the dynamic array */
		role_allow_t * ptr;		
		ptr = (role_allow_t *)realloc(parse_policy->role_allow, (LIST_SZ+parse_policy->list_sz[POL_LIST_ROLE_ALLOW]) * sizeof(role_allow_t));
		if(ptr == NULL) {
			yyerror("out of memory\n");
			return -1;
		}
		parse_policy->role_allow = ptr;
		parse_policy->list_sz[POL_LIST_ROLE_ALLOW] += LIST_SZ;
	}	
	rule = &(parse_policy->role_allow[parse_policy->num_role_allow]);
	memset(rule, 0, sizeof(role_allow_t));
	rule->lineno = policydb_lineno;
	
	/* source roles*/
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			rule->flags |= AVFLAG_SRC_STAR;
			free(id);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			rule->flags |= AVFLAG_SRC_TILDA;
			free(id);
			continue;
		}
		idx = get_role_idx(id, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is an invalid role attribute", id);
			yyerror(errormsg);
			free(id);
			return -1;				
		}
		role = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(role == NULL) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		role->type = IDX_ROLE;
		role->idx = idx;
		if(insert_ta_item(role, &(rule->src_roles)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for source rule id %s\n", id);
			yyerror(errormsg);
			free(id);
			free(role);
			return -1;
		}
		free(id);
	}
	
	/* target role */
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			rule->flags |= AVFLAG_TGT_STAR;
			free(id);
			free(role);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			rule->flags |= AVFLAG_TGT_TILDA;
			free(id);
			continue;
		}	
		idx = get_role_idx(id, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is not a valid role", id);
			yyerror(errormsg);
			free(id);
			return -1;				
		}
		role = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(role == NULL) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		role->type = IDX_ROLE;
		role->idx = idx;
		if(insert_ta_item(role, &(rule->tgt_roles)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for target role id %s\n", id);
			yyerror(errormsg);
			free(id);
			free(role);
			return -1;
		}
		free(id);
	}
	
	(parse_policy->num_role_allow)++;	
	(parse_policy->rule_cnt[RULE_ROLE_ALLOW])++;		
	return 0;
}


static int define_role_trans(void)
{
	char *id;
	int idx, idx_type;
	rt_item_t *rule;
	ta_item_t *role = NULL, *type = NULL;
	bool_t subtract = FALSE;
	
	if(pass == 1 || (pass == 2 && !(parse_policy-> opts & POLOPT_ROLE_RULES)) || (pass > 2 && yyis_decl())) {
		while ((id = queue_remove(id_queue))) 
			free(id);			/* src roles */
		while ((id = queue_remove(id_queue))) 
			free(id);			/* tgt types */
		id = queue_remove(id_queue);
		free(id);				/* trans. role */
		return 0;
	}

	if(parse_policy->num_role_trans >= parse_policy->list_sz[POL_LIST_ROLE_TRANS]) {
		/* grow the dynamic array */
		rt_item_t *ptr;		
		ptr = (rt_item_t *)realloc(parse_policy->role_trans, 
			(LIST_SZ+parse_policy->list_sz[POL_LIST_ROLE_TRANS]) * sizeof(rt_item_t));
		if(ptr == NULL) {
			yyerror("out of memory\n");
			return -1;
		}
		parse_policy->role_trans = ptr;
		parse_policy->list_sz[POL_LIST_ROLE_TRANS] += LIST_SZ;
	}	
	rule = &(parse_policy->role_trans[parse_policy->num_role_trans]);
	memset(rule, 0, sizeof(rt_item_t));	
	rule->lineno = policydb_lineno;
	
	/* source ROLES*/
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			rule->flags |= AVFLAG_SRC_STAR;
			free(id);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			rule->flags |= AVFLAG_SRC_TILDA;
			free(id);
			continue;
		}
		idx = get_role_idx(id, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is an invalid role name", id);
			yyerror(errormsg);
			free(id);
			return -1;				
		}
		role = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(role == NULL) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		role->type = IDX_ROLE;
		role->idx = idx;
		if(insert_ta_item(role, &(rule->src_roles)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for source rule id %s\n", id);
			yyerror(errormsg);
			free(role);
			free(id);
			return -1;
		}
		free(id);
	}
	
	/* target TYPES/ATTRIBS */
	while ((id = queue_remove(id_queue))) {
		if(strcmp(id, "*") == 0) {
			rule->flags |= AVFLAG_TGT_STAR;
			free(id);
			continue;
		}
		if (strcmp(id, "-") == 0) {
			subtract = TRUE;
			free(id);
			continue;
		}
		if(strcmp(id, "~") == 0) {
			rule->flags |= AVFLAG_TGT_TILDA;
			free(id);
			continue;
		}
		idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is neither a type or type attribute", id);
			yyerror(errormsg);
			free(id);
			free(role);
			return -1;				
		}
		type = (ta_item_t *)malloc(sizeof(ta_item_t));
		if(type == NULL) {
			yyerror("out of memory");
			free(id);
			free(role);
			return -1;
		}
		type->type = idx_type;
		if (subtract) {
			type->type |= IDX_SUBTRACT;
			subtract = FALSE;
		}
		type->idx = idx;
		if(insert_ta_item(type, &(rule->tgt_types)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for target type %s\n", id);
			yyerror(errormsg);
			free(id);
			free(role);
			free(type);
			return -1;
		}
		free(id);
	}	
	
	/* transition role */
	id = queue_remove(id_queue);
	rule->trans_role.idx = get_role_idx(id, parse_policy);
	rule->trans_role.type = IDX_ROLE;
	if(rule->trans_role.idx < 0) {
		snprintf(errormsg, sizeof(errormsg), "%s is an invalid role name", id);
		yyerror(errormsg);
		free(role);
		free(type);
		free(id);
		return -1;				
	}
	free(id);	
	(parse_policy->num_role_trans)++;	
	(parse_policy->rule_cnt[RULE_ROLE_TRANS])++;			
	return 0;
}


/* users list */

static int define_user(void)
{
	char *id;
	int idx, ridx, rt, i;
	bool_t existing, tilde = FALSE;
	int *tmp = NULL, num_tmp = 0;
	ap_mls_level_t *lvl = NULL;
	ap_mls_range_t *rng = NULL;

	if(pass == 1 || (pass == 2 && !(parse_policy-> opts & POLOPT_USERS))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		if (is_mls_policy(parse_policy)) {
			parse_mls_level(1);
			parse_mls_range(1);
		}
		return 0;
	}

	if (pass > 2 && yyis_decl()) {
		add_name(queue_remove(id_queue), &(parse_policy->optionals->users));
		while ((id = queue_remove(id_queue))) 
			free(id);
		if (is_mls_policy(parse_policy)) {
			parse_mls_level(1);
			parse_mls_range(1);
		}
		return 0;
	}
	
	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no user name for user definition?");
		return -1;
	}
	if(!is_valid_str_sz(id)) {
		snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
		yyerror(errormsg);
		return -1;
	}
	/* check if existing user; if so treat as union of roles */
	idx = get_user_idx(id, parse_policy);
	if(idx >= 0) {
		/* existing; ptr now points to existing user record */
		existing = TRUE;
		free(id);
	}
	else {
		/* new user */
		existing = FALSE;
		idx = add_user(id, parse_policy);
		if(idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "problem adding user \"%s\" to policy", id);
			yyerror(errormsg);
			return -1;
		}
		/* don't free id (user name)*/
	}
		
	while((id = queue_remove(id_queue))) {
		if (!strcmp("*", id)) {
			for (i = 0; i < parse_policy->num_roles; i++) {
				rt = add_i_to_a(i, &num_tmp, &tmp);
				if (rt != 0)
					return -1;
			}
			free(id);
			break;
		}
		if (!strcmp("~", id)) {
			tilde = TRUE;
			free(id);
			continue;
		}
		ridx = get_role_idx(id, parse_policy);
		if(ridx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is an invalid role name", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		rt = add_i_to_a(ridx, &num_tmp, &tmp);
		if (rt != 0)
			return -1;
		free(id);		 
	}
	if (tilde) {
		for (i = 0; i < parse_policy->num_roles; i++) {
			if (find_int_in_array(i, tmp, num_tmp) == -1) {
				rt = add_role_to_user(i, idx, parse_policy);
				if(rt != 0) {
					yyerror("problem inserting role in user");
					return -1;
				}
			}
		}
	} else {
		for (i = 0; i < num_tmp; i++) {
			rt = add_role_to_user(tmp[i], idx, parse_policy);
			if(rt != 0) {
				yyerror("problem inserting role in user");
				return -1;
			}
		}
	}
	

	/* MLS level/range definitions*/
	if (is_mls_policy(parse_policy)) {
		lvl = parse_mls_level(0);
		if (!lvl){
			yyerror("no default level for user?");
			return -1;
		}
		rng = parse_mls_range(0);
		if (!rng) {
			yyerror("no range for user?");
			return -1;
		}
		if (parse_policy->users[idx].dflt_level) /* currently over-write if multiple */
			ap_mls_level_free(parse_policy->users[idx].dflt_level);
		parse_policy->users[idx].dflt_level = lvl;
		if (parse_policy->users[idx].range) /* currently over-write if multiple */
			ap_mls_range_free(parse_policy->users[idx].range);
		parse_policy->users[idx].range = rng;
	}

	id = queue_remove(id_queue);

	free(tmp);
	return 0;
}

/* class definitions */

static int define_class(void)
{
	char *id = 0;
	int idx;
	
	if(pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_CLASSES))) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}
	
	/* add class name */
	id = queue_remove(id_queue);
	if(!id) {
		yyerror("no class name for class definitions\n");
		return -1;
	}
	if(!is_valid_str_sz(id)) {
		snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
		yyerror(errormsg);
		return -1;
	}
	idx = add_class(id, parse_policy);
	if(idx == -2) {
		snprintf(errormsg, sizeof(errormsg), "duplicate class decalaration (%s)\n", id);
		yyerror(errormsg);
		return -1;
	}
	else if(idx < 0) 
		return -1;
	
	return 0;
}

/* object permissions permissions */
static int define_av_perms(int inherits)
{
	char *id;
	int cls_idx, cp_idx, p_idx, rt;
	char *tname = NULL;
	if(pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_CLASSES)) || 
		(pass == 1 && !(parse_policy->opts & POLOPT_PERMS))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}
	id = queue_remove(id_queue);
	if(!id) {
		yyerror("no class name for permission definition");
		return -1;
	}
	cls_idx = get_obj_class_idx(id, parse_policy);
	if(cls_idx < 0) {
		snprintf(errormsg, sizeof(errormsg), "%s is not a valid object class name", id);
		yyerror(errormsg);
		return -1;
	}
	free(id);
	if (inherits) {
		id = (char *) queue_remove(id_queue);
		if (!id) {
			yyerror("no inherits name for access vector definition?");
			return -1;
		}
		cp_idx = get_common_perm_idx(id, parse_policy);
		if(cp_idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is not a valid object class name", id);
			yyerror(errormsg);
			return -1;
		}
		tname = id; /* temporarily keep around for check below */
		rt = add_common_perm_to_class(cls_idx, cp_idx, parse_policy);
		if( rt <  0) {
			yyerror("problem adding common perm idx to class");
			return -1;
		}		
	} 
	/* class-specific permissions */
	while ((id = queue_remove(id_queue))) {
		p_idx = add_perm(id, parse_policy);
		if(p_idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "problem adding permisions %s", id);
			yyerror(errormsg);
			return -1;
		}
		/* this check straight from checkpolicy; not sure necessary ??? */
		if (inherits) {
			/*
			 * Class-specific permissions and 
			 * common permissions exist in the same
			 * name space.
			 */
			
			if(strcasecmp(id, tname) == 0) {
				snprintf(errormsg, sizeof(errormsg), "class-specific permission (%s) conflicts with common permission", id);
				yyerror(errormsg);
				return -1;
			}
		}
		if(!is_valid_str_sz(id)) {
			snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
			yyerror(errormsg);
			return -1;
		}
		rt = add_perm_to_class(cls_idx, p_idx, parse_policy);
		if(rt != 0) {
			snprintf(errormsg, sizeof(errormsg), "problem adding permission (%s) to object class", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);		
	}
	if(inherits) 
		free(tname); /* no longer need common name */
	
	
	return 0;
}


/* common permissions */
static int define_common_perms(void)
{
	char *id = 0;
	int idx, permidx, rt;
	
	if (pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_PERMS))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}
	
	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no common name for common perm definition?");
		return -1;
	}
	
	/* add new common perm */
	if(!is_valid_str_sz(id)) {
		snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
		yyerror(errormsg);
		return -1;
	}
	idx = add_common_perm(id, parse_policy);
	if(idx == -2) {
		snprintf(errormsg, sizeof(errormsg), "Duplicate common permission name (%s)", id);
		yyerror(errormsg);
		return -1;
	}
	else if(idx < 0)
		return -1; /* other err */
	
	/* add permissions to common perm */
	while ((id = queue_remove(id_queue))) {	
		if(!is_valid_str_sz(id)) {
			snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
			yyerror(errormsg);
			return -1;
		}
		permidx = add_perm(id, parse_policy);
		if(permidx < 0) {
			free(id); /* add_perm() allocates its own memory */
			snprintf(errormsg, sizeof(errormsg), "Problem adding permission name (%s)", id);
			yyerror(errormsg);
			return -1;
		}
		free(id); /* add_perm() allocates its own memory */
		rt = add_perm_to_common(idx, permidx, parse_policy);
		/* Note: a -2 return (already exists) is fine here */
		if(rt == -1 ) {
			yyerror("Problem adding permission idx to common permission");
			return -1;
		}
	}
	return 0;
}

static ap_role_t *merge_roles_dom(ap_role_t *r1, ap_role_t *r2)
{
	ap_role_t *new = NULL;
	int i, retv;

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_ROLES))) {
		return (ap_role_t*)1; /* any non-NULL value */
	}

	new = (ap_role_t*)calloc(1, sizeof(ap_role_t));
	if (!new) {
		yyerror("out of memory");
		return NULL;
	}

	/* r1 types */
	for (i = 0; i < r1->num_types; i++) {
		retv = add_i_to_a(r1->types[i], &(new->num_types), &(new->types));
		if (retv) {
			yyerror("error merging roles");
			goto fail;
		}
	}

	/* r2 types */
	for (i = 0; i < r2->num_types; i++) {
		if (find_int_in_array(r2->types[i], new->types, new->num_types) == -1) {
			retv = add_i_to_a(r2->types[i], &(new->num_types), &(new->types));
			if (retv) {
				yyerror("error merging roles");
				goto fail;
			}
		}
	}

	/* r1 dom roles */
	for (i = 0; i < r1->num_dom_roles; i++) {
		retv = add_i_to_a(r1->dom_roles[i], &(new->num_dom_roles), &(new->dom_roles));
		if (retv) {
			yyerror("error merging roles");
			goto fail;
		}
	}

	/* r2 dom roles */
	for (i = 0; i < r2->num_dom_roles; i++) {
		if (find_int_in_array(r2->dom_roles[i], new->dom_roles, new->num_dom_roles) == -1) {
			retv = add_i_to_a(r2->dom_roles[i], &(new->num_dom_roles), &(new->dom_roles));
			if (retv) {
				yyerror("error merging roles");
				goto fail;
			}
		}
	}


	/* if r1 has no name it is temporary; free it */
	if (!r1->name) {
		free(r1->types);
		free(r1->dom_roles);
		free(r1);
	}

	return new;

fail:
	free(new->types);
	free(new->dom_roles);
	free(new);
	return NULL;
}

static ap_role_t* define_role_dom(ap_role_t *r)
{
	char *id;
	int idx, i, retv, j;
	ap_role_t *role = NULL;
	
	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_ROLES))) {
		id = queue_remove(id_queue);
		free(id);
		return (ap_role_t*)1; /* any non-NULL value */
	}
	
	/* pass 2 */
	/* if the role already exists, we'll just add the new types, otherwise
	 * we create new role */
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("no role name for role dominance?");
		return NULL;
	}

	idx = get_role_idx(id, parse_policy);
	if(idx < 0) {
		/* new role identifier;*/
		if(!is_valid_str_sz(id) ) {
			snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
			yyerror(errormsg);
			return NULL;
		}
		idx = add_role(id, parse_policy);
		if(idx < 0)
			return NULL;
	}
	else {
		/* already exists; */
		free(id);
	}

	role = &(parse_policy->roles[idx]);

	if (r) {
		for (i = 0; i < r->num_types; i++) {
			if (find_int_in_array(r->types[i], role->types, role->num_types) == -1) {
				retv = add_i_to_a(r->types[i], &(role->num_types), &(role->types));
				if (retv) {
					yyerror("error adding types to dominant role");
					return NULL;
				}
			}
		}
		for (i = 0; i < r->num_dom_roles; i++) {
			if (find_int_in_array(r->dom_roles[i], role->dom_roles, role->num_dom_roles) == -1) {
				retv = add_i_to_a(r->dom_roles[i], &(role->num_dom_roles), &(role->dom_roles));
				if (retv) {
					yyerror("error adding dominated roles to dominant role");
					return NULL;
				}
			}
		}

		/* propagate to roles dominating this one */
		for (j = 0; j < parse_policy->num_roles; j ++) {
			if (j == idx)
				continue; /* do not process self */
			if (find_int_in_array(idx, parse_policy->roles[j].dom_roles, parse_policy->roles[j].num_dom_roles) != -1) {
				for (i = 0; i < role->num_types; i++) {
					if (find_int_in_array(role->types[i], parse_policy->roles[j].types, parse_policy->roles[j].num_types) == -1) {
						retv = add_i_to_a(role->types[i], &(parse_policy->roles[j].num_types), &(parse_policy->roles[j].types));
						if (retv) {
							yyerror("error propagating dominance");
							return NULL;
						}
					}
				}
				for (i = 0; i < role->num_dom_roles; i++) {
					if (find_int_in_array(role->dom_roles[i], parse_policy->roles[j].dom_roles, parse_policy->roles[j].num_dom_roles) == -1) {
						retv = add_i_to_a(role->dom_roles[i], &(parse_policy->roles[j].num_dom_roles), &(parse_policy->roles[j].dom_roles));
						if (retv) {
							yyerror("error propagating dominance");
							return NULL;
						}
					}
				}
			}
		}

	}
		
	return role; 
}


static int define_bool(void)
{
	char *id, *name;
	bool_t state;
	int rt;
	
	rt = set_policy_version(POL_VER_COND, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	
	if (!(parse_policy->opts & POLOPT_COND_BOOLS) || pass == 2) {
		while ((id = (char*)queue_remove(id_queue)))
			free(id);
		return 0;
	}
	
	if (pass > 2 && yyis_decl()) {
		add_name(queue_remove(id_queue), &(parse_policy->optionals->bools));
		while ((id = (char*)queue_remove(id_queue)))
			free(id);
		return 0;
	}

	name = (char*)queue_remove(id_queue);
	if (!name) {
		yyerror("No name for boolean declaration");
		return -1;
	}
	
	id = (char*)queue_remove(id_queue);
	if (!id) {
		yyerror("No value for boolean declaration");
		return -1;
	}
	
	if (strcmp(id, "T") == 0)
		state = TRUE;
	else
		state = FALSE;
	free(id);
	
	rt = add_cond_bool(name, state, parse_policy);
	if (rt == -2) {
		snprintf(errormsg, sizeof(errormsg), "Boolean %s already exists", name);
		yyerror(errormsg);
		return -1;
	} else if (rt < 0) {
		yyerror("Error adding boolean");
		return -1;
	}
	
	return 0;
}

/* search through the policy for a matching conditional expression
 * returns -1 if non or found
 * returns the index of the cond_expr_item_t if found.
 */
static int find_matching_cond_expr(cond_expr_t *expr, policy_t *policy)
{
	int i;
	
	for (i = 0; i < policy->num_cond_exprs; i++) {
		if (cond_exprs_equal(expr, policy->cond_exprs[i].expr))
			return i;
	}
	return -1;
}

static int cond_rule_add_helper(int **list, int *list_len, int *add, int add_len)
{
	int i;
	
	if (!add)
		return 0;
		
	if (!*list) {
		/* Copy the pointer of the incoming true|false list into our cond_expr_item_t list member */
		*list = add;
		return 0;
	}
	
	for (i = 0; i < add_len; i++) {
		/* we probably don't need to do this checking, but it is better to be safe */
		if (find_int_in_array(add[i], *list, *list_len) == -1) {
			if (add_i_to_a(add[i], list_len, list) == -1)
				return -1;
		}
	}
	
	return 0;
}

static int define_conditional(cond_expr_t *expr, cond_rule_list_t *t_list, cond_rule_list_t *f_list)
{
	int idx, rt;
	cond_expr_item_t *cur = NULL;
	
	rt = set_policy_version(POL_VER_COND, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	
	if (pass == 1 || (pass > 2 && yyis_decl()))
		return 0;
	
	if (expr == &dummy_cond_expr) {
		yyerror("Received invalid expression in define_conditional");
		return -1;
	}
	
	idx = find_matching_cond_expr(expr, parse_policy);
	
	/* found matching expressions - add the rules to this expression. */
	if (idx != -1) {
		cond_free_expr(expr);
		cur = &parse_policy->cond_exprs[idx];
		if (t_list) {
			if (!cur->true_list) {
				cur->true_list = t_list;
			} else {
				if (cond_rule_add_helper(&cur->true_list->av_access, &cur->true_list->num_av_access,
					t_list->av_access, t_list->num_av_access) == -1)
						return -1;
				if (cond_rule_add_helper(&cur->true_list->av_audit, &cur->true_list->num_av_audit,
					t_list->av_audit, t_list->num_av_audit) == -1)
						return -1;
				if (cond_rule_add_helper(&cur->true_list->te_trans, &cur->true_list->num_te_trans,
					t_list->te_trans, t_list->num_te_trans) == -1)
						return -1;
			}	
			add_cond_expr_item_helper(idx, TRUE, t_list, parse_policy);
		}
		if (f_list) {
			if (!cur->false_list) {
				cur->false_list = f_list;
			} else {
				if (cond_rule_add_helper(&cur->false_list->av_access, &cur->false_list->num_av_access,
					f_list->av_access, f_list->num_av_access) == -1)
						return -1;
				if (cond_rule_add_helper(&cur->false_list->av_audit, &cur->false_list->num_av_audit,
					f_list->av_audit, f_list->num_av_audit) == -1)
						return -1;
				if (cond_rule_add_helper(&cur->false_list->te_trans, &cur->false_list->num_te_trans,
					f_list->te_trans, f_list->num_te_trans) == -1)
						return -1;
			}
			add_cond_expr_item_helper(idx, FALSE, f_list, parse_policy);
		}
	} else {
		if (add_cond_expr_item(expr, t_list, f_list, parse_policy) < 0) {
			yyerror("Error adding conditional expression item to the policy");
			return -1;
		}
	}
	
	if (update_cond_expr_items(parse_policy) != 0)
		return -1;
        
	return 0;
}

static cond_expr_t *define_cond_expr(__u32 expr_type, void *arg1, void *arg2)
{
	char *id;
	cond_expr_t *expr, *e1 = NULL, *e2;
	int bool_var;
	
	if (pass == 1 || (pass > 2 && yyis_decl())) {
		if (expr_type == COND_BOOL) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return &dummy_cond_expr;
	}
	
	if (!(parse_policy->opts & POLOPT_COND_BOOLS)) {
		return &dummy_cond_expr;
	}
	
	/* create a new expression struct */
	expr = malloc(sizeof(struct cond_expr));
	if (!expr) {
		yyerror("out of memory");
		return NULL;
	}
	memset(expr, 0, sizeof(cond_expr_t));
	expr->expr_type = expr_type;
	
	/* create the type asked for */
	switch (expr_type) {
	case COND_NOT:
		e1 = NULL;
		e2 = (struct cond_expr *) arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal conditional NOT expression");
			free(expr);
			return NULL;
		}
		e1->next = expr;
		return (struct cond_expr *) arg1;
	case COND_AND:
	case COND_OR:
	case COND_XOR:
	case COND_EQ:
	case COND_NEQ:
		e1 = NULL;
		e2 = (struct cond_expr *) arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal left side of conditional binary op expression");
			free(expr);
			return NULL;
		}
		e1->next = (struct cond_expr *) arg2;

		e1 = NULL;
		e2 = (struct cond_expr *) arg2;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal right side of conditional binary op expression");
			free(expr);
			return NULL ;
		}
		e1->next = expr;
		return (struct cond_expr *) arg1;
	case COND_BOOL:
		id = (char *) queue_remove(id_queue) ;
		if (!id) {
			yyerror("bad conditional; expected boolean id");
			free(id);
			free(expr);
			return NULL;
		}
		
		bool_var = get_cond_bool_idx(id, parse_policy);
		
		if (bool_var < 0) {
			snprintf(errormsg, sizeof(errormsg), "unknown boolean %s in conditional expression", id);
			yyerror(errormsg);
			free(expr);
			free(id);
			return NULL ;
		}
		expr->bool = bool_var;
                free(id);
		return expr;
	default:
		yyerror("illegal conditional expression");
		return NULL;
	}
}

/* collect the type lists */
static cond_rule_list_t *define_cond_pol_list(cond_rule_list_t *list, rule_desc_t *rule)
{
	cond_rule_list_t *rl;
	
	if (pass == 1 || (pass > 2 && yyis_decl()))
		return (cond_rule_list_t*)1;
		
	if (!list) {
		rl = (cond_rule_list_t*)malloc(sizeof(cond_rule_list_t));
		if (!rl) {
			yyerror("Memory error");
			free(rule);
			return NULL;
		}
		memset(rl, 0, sizeof(cond_rule_list_t));
	} else {
		rl = list;
	}
	
	if (!rule || rule == &dummy_rule_desc)
		return rl;
	
	switch (rule->rule_type) {
	case RULE_TE_ALLOW:
	case RULE_NEVERALLOW:
		if (add_i_to_a(rule->idx, &rl->num_av_access, &rl->av_access) != 0) {
			yyerror("Memory error");
			free(rule);
			return NULL;
		}
		break;
	case RULE_DONTAUDIT:
	case RULE_AUDITDENY:
	case RULE_AUDITALLOW:
		if (add_i_to_a(rule->idx, &rl->num_av_audit, &rl->av_audit) != 0) {
			yyerror("Memory error");
			free(rule);
			return NULL;
		}
		break;
	case RULE_TE_TRANS:
	case RULE_TE_MEMBER:
	case RULE_TE_CHANGE:
		if (add_i_to_a(rule->idx, &rl->num_te_trans, &rl->te_trans) != 0) {
			yyerror("Memory error");
			free(rule);
			return NULL;
		}
		break;
	default:
		yyerror("Internal error: invalid type description.");
		free(rule);
		return NULL;
	}
	
	free(rule);
	return rl;
}

static rule_desc_t *define_cond_compute_type(int rule_type)
{
	char *id;
	int rt;
	rule_desc_t *rule;
	
	if (pass == 1 || (pass > 2 && yyis_decl()))
		goto skip_tt_rule;
		
	if (!(parse_policy->opts & POLOPT_COND_TE_RULES))
		goto skip_tt_rule;
				
	rule = (rule_desc_t*)malloc(sizeof(rule_desc_t));
	if (!rule) {
		yyerror("Memory error");
		return NULL;
	}
	memset(rule, 0, sizeof(rule_desc_t));
	
	switch(rule_type) {
	case RULE_TE_TRANS:
	case RULE_TE_MEMBER:
	case RULE_TE_CHANGE:
		break;
	default:
		snprintf(errormsg, sizeof(errormsg), "Invalid type transition|member|change rule type (%d)", rule_type);
		yyerror(errormsg);
		return NULL;
	}
	rt = add_ttrule(rule_type, TRUE);
	if(rt < 0) 
		return NULL;
		
	rule->rule_type = rule_type;
	rule->idx = rt;
		
	return rule;
	
skip_tt_rule:
	/* TODO: Currently an empty stub */	
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	id = queue_remove(id_queue);
	free(id);
	return &dummy_rule_desc;
}

static rule_desc_t *define_cond_te_avtab(int rule_type)
{
	char *id;
        int rt;
	rule_desc_t *rule;
	        
	if (pass == 1 || (pass > 2 && yyis_decl())) {
		goto skip_avtab_rule;
	}
	
	if(!(parse_policy->opts & POLOPT_COND_TE_RULES))
                goto skip_avtab_rule;	
	
	rule = (rule_desc_t*)malloc(sizeof(rule_desc_t));
	if (!rule) {
		yyerror("Memory error");
		return NULL;
	}
	memset(rule, 0, sizeof(rule_desc_t));
	
	switch(rule_type) {
	case RULE_TE_ALLOW:
		rt = add_avrule(rule_type, &(parse_policy->av_access), &(parse_policy->num_av_access), TRUE);
		break;
	case RULE_NEVERALLOW:
		rt = add_avrule(rule_type, &(parse_policy->av_access), &(parse_policy->num_av_access), TRUE);
		break;
	
	/* Jul 2002, added RULE_DONTAUDIT, which replaces RULE_NOTIFY */
	case RULE_DONTAUDIT:
		rt = set_policy_version(POL_VER_JUL2002, parse_policy);
		if(rt != 0) {
			yyerror("error setting policy version");
			return NULL;
		}
		/* fall thru */
	case RULE_AUDITDENY:
		rt = add_avrule(rule_type, &(parse_policy->av_audit), &(parse_policy->num_av_audit), TRUE);
		break;
	case RULE_AUDITALLOW:
		rt = add_avrule(rule_type, &(parse_policy->av_audit), &(parse_policy->num_av_audit), TRUE);
		break;
	default:
		snprintf(errormsg, sizeof(errormsg), "Invalid AV type (%d)", rule_type);
		yyerror(errormsg);
		return NULL;
	}
	if (rt < 0) 
		return NULL;
	
	rule->rule_type = rule_type;
	rule->idx = rt;
	
	return rule;

skip_avtab_rule:                
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	while ((id = queue_remove(id_queue))) 
		free(id);
	return &dummy_rule_desc; /* 0 (i.e., NULL) is fail */
}


static int define_initial_sid(void)
{
	char *id = 0;
	int idx;
	__u32 sid;
	
	if (pass == 2 ||(pass == 1 && !(parse_policy->opts & POLOPT_INITIAL_SIDS))) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}
	
	/* add initial SID name; context will be added in define_initial_sid_context() */
	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no name for SID definition?");
		free(id);
		return -1;
	}
	if(!is_valid_str_sz(id)) {
		snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	sid = num_initial_sids(parse_policy)+1;	/* from the src parse, the enxt SID # is always the
						 * number of SIDs plus one (SIDs start from 1) */
	idx = add_initial_sid2(id, sid, parse_policy);
	/*idx = add_initial_sid(id, parse_policy);*/
	if(idx == -2) {
		snprintf(errormsg, sizeof(errormsg), "duplicate initial SID decalaration (%s)\n", id);
		yyerror(errormsg);
		return -1;
	}
	else if(idx < 0)
		return -1;
		
	return 0;
}

static ap_mls_level_t *parse_mls_level(int dontsave)
{
	char *id, *id_2nd;
	int rt, sens, i;
	int *cats = NULL, num_cats = 0;
	ap_mls_level_t *lvl = NULL;

	if (dontsave) {
		while ((id = queue_remove(id_queue))) {
			free(id);
		}
		return NULL; /* not an error here */
	}

	id = queue_remove(id_queue);
	sens = get_sensitivity_idx(id, parse_policy);
	if (sens < 0) {
		yyerror("invalid sensitivity in level definition");
		return NULL;
	}
	free(id);

	while ((id = queue_remove(id_queue))) {
		if (!strcmp(id, ".")) {
			free(id);
			if (num_cats == 0) {
				yyerror("no starting category for category range in level definition?");
				return NULL;
			}
			id = queue_remove(id_queue);
			if (!id) {
				yyerror("incomplete category range in level definition");
				return NULL;
			}
			rt = get_category_idx(id, parse_policy);
			if (rt < 0) {
				snprintf(errormsg, sizeof(errormsg), "undefined category %s in level definition", id);
				yyerror(errormsg);
				return NULL;
			}
			i = cats[num_cats-1];
			if (i >= rt) {
				yyerror("invalid category range in level definition");
				return NULL;
			}
			i++; /* do not add i twice */
			for (/* i already initialized */; i <= rt; i++) {
				if (add_i_to_a(i, &num_cats, &cats)) {
					yyerror("out of memory");
					return NULL;
				}
			}
			free(id);
		} else if ((id_2nd = strchr(id, '.'))) {
			*(id_2nd++) = '\0';
			i = get_category_idx(id, parse_policy);
			if (i < 0) {
				snprintf(errormsg, sizeof(errormsg), "undefined category %s in level definition", id);
				yyerror(errormsg);
				return NULL;
			}
			rt = get_category_idx(id_2nd, parse_policy);
			if (rt < 0) {
				snprintf(errormsg, sizeof(errormsg), "undefined category %s in level definition", id_2nd);
				yyerror(errormsg);
				return NULL;
			}
			if (i >= rt) {
				yyerror("invalid category range in level definition");
				return NULL;
			}
			for (/* i already initialized */; i <= rt; i++) {
				if (add_i_to_a(i, &num_cats, &cats)) {
					yyerror("out of memory");
					return NULL;
				}
			}
			free(id);
			id_2nd = NULL;
		} else {
			i = get_category_idx(id, parse_policy);
			free(id);
			if (i < 0) {
				snprintf(errormsg, sizeof(errormsg), "undefined category %s in level definition", id);
				yyerror(errormsg);
				return NULL;
			}
			if (add_i_to_a(i, &num_cats, &cats)) {
				yyerror("out of memory");
				return NULL;
			}
		}	
	}

	lvl = (ap_mls_level_t*)calloc(1, sizeof(ap_mls_level_t));
	if (!lvl) {
		free(cats);
		yyerror("out of memory");
		return NULL;
	}

	lvl->sensitivity = sens;
	lvl->categories = cats;
	lvl->num_categories = num_cats;

	return lvl;
}

static ap_mls_range_t *parse_mls_range(int dontsave)
{
	ap_mls_level_t *low = NULL, *high = NULL;
	ap_mls_range_t  *rng = NULL;
	char *id;

	if (dontsave) {
		parse_mls_level(dontsave);
		id = queue_head(id_queue);
		if (id) { /* id is null then one level */
			parse_mls_level(dontsave);
		}
		return NULL; /* not an error here */
	}

	low = parse_mls_level(dontsave);
	if (!low) {
		yyerror("error parsing MLS range low level");
		return NULL;
	}

	id = queue_head(id_queue);
	if (id) { /* id is null then one level */
		high = parse_mls_level(dontsave);
	} else {
		high = low;
	}
	if (!high) {
		yyerror("error parsing MLS range high level");
		return NULL;
	}

	rng = (ap_mls_range_t*)calloc(1, sizeof(ap_mls_range_t));
	if (!rng) {
		if (high != low)
			ap_mls_level_free(high);
		ap_mls_level_free(low);
		yyerror("out of memory");
		return NULL;
	}

	rng->low = low;
	rng->high = high;

	return rng;
}

/* If dontsave, then just clear the queue and return NULL (the return
 * should be ignored in this case).  Otherwise, allocate a context
 * structure and return it, or NULL for error
 */
static security_con_t *parse_security_context(int dontsave)
{
	char *id;
	int rt;
	security_con_t *scontext;
	
	if (pass == 1 || dontsave) {
		id = queue_remove(id_queue);  /* user  */
		free(id);
		id = queue_remove(id_queue);  /* role  */
		free(id);
		id = queue_remove(id_queue);  /* type  */
		free(id);
		if (is_mls_policy(parse_policy)) {
			parse_mls_range(1);
		}
		id = queue_head(id_queue);
		if (!id)
			id = queue_remove(id_queue);
		return NULL; /* In this case this is not an error */
	}
	
	scontext = (security_con_t *)malloc(sizeof(security_con_t));
	if(scontext == NULL) {
		yyerror("out of memory");
		return NULL;
	}
	memset(scontext, 0, sizeof(security_con_t));
	/* user */
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("Security context missing user?");
		free(scontext);
		return NULL;
	}
	rt = get_user_idx(id, parse_policy);
	if(rt < 0) {
		snprintf(errormsg, sizeof(errormsg), "User %s is not defined in policy.", id);
		yyerror(errormsg);
		free(id);
		free(scontext);
		return NULL;
	}
	free(id);
	scontext->user = rt;
	
	/* role */
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("Security context missing role?");
		free(scontext);
		return NULL;
	}			
	rt = get_role_idx(id, parse_policy);
	if(rt < 0) {
		snprintf(errormsg, sizeof(errormsg), "Role %s is not defined in policy.", id);
		yyerror(errormsg);
		free(id);
		free(scontext);
		return NULL;
	}
	free(id);
	scontext->role = rt;
	
	/* type */
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("Security context missing type?");
		free(scontext);
		return NULL;
	}			
	rt = get_type_idx(id, parse_policy);
	if(rt < 0) {
		snprintf(errormsg, sizeof(errormsg), "Type %s is not defined in policy.", id);
		yyerror(errormsg);
		free(id);
		free(scontext);
		return NULL;
	}
	free(id);
	scontext->type = rt;	
	
	if (is_mls_policy(parse_policy)) {
		scontext->range = parse_mls_range(0);
	}
	id = queue_head(id_queue);
	if (!id)
		id = queue_remove(id_queue);

	if (!validate_security_context(scontext, parse_policy)) {
		yyerror("Context not valid");
		security_con_destroy(scontext);
		return NULL;
	}

	return scontext;
}


static int define_initial_sid_context(void)
{
	char *id;
	int idx;
	security_con_t *scontext;

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_INITIAL_SIDS))){
		id = (char *) queue_remove(id_queue); 
		parse_security_context(1);
		free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID context definition?");
		return -1;
	}
	if(!is_valid_str_sz(id)) {
		snprintf(errormsg, sizeof(errormsg), "string \"%s\" exceeds APOL_SZ_SIZE", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	idx = get_initial_sid_idx(id, parse_policy);
	if(idx < 0) {
		snprintf(errormsg, sizeof(errormsg), "%s is not a valid initial SID name", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	free(id);
	scontext = parse_security_context(0);
	if(scontext == NULL) 
		return -1;
	if(add_initial_sid_context(idx, scontext, parse_policy) != 0) {
		yyerror("problem adding security context to Initial SID");
		return -1;
	}		
	
	return 0;
}

/************************************************************************
 *
 * Until we decide to include these additional statments in the analysis
 * policy database, all we do is free the various ids.  
 *
 ************************************************************************/



static int define_sens(void)
{
	char *id, *name = NULL;
	int rt;
	name_item_t *aliases = NULL;

	rt = set_policy_version(POL_VER_19_20, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	if (pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_MLS_COMP))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	name = queue_remove(id_queue);
	if (!name) {
		yyerror("no name for sensitivity?");
		return -1;
	}

	while ( (id = queue_remove(id_queue)) ) {
		rt = add_name(id, &aliases);
		if (rt) {
			free_name_list(aliases);
			yyerror("error adding alias to sensitivity");
			return -1;
		}
	}

	rt = add_sensitivity(name, aliases, parse_policy);
	if (rt) {
		free(name);
		free_name_list(aliases);
		yyerror("error adding sensitivity to policy");
		return -1;
	}

	return 0;
}

static int define_dominance(void)
{
	char *id;
	int rt, i = 0;

	if (pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_MLS_COMP))) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	rt = set_policy_version(POL_VER_19_20, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	parse_policy->mls_dominance = (int*)malloc(parse_policy->num_sensitivities * sizeof(int));
	if (!parse_policy->mls_dominance) {
		yyerror("out of memory");
		return -1;
	}
	for (i = 0; i < parse_policy->num_sensitivities; i++)
		parse_policy->mls_dominance[i] = -1;

	i = 0;
	while ((id = queue_remove(id_queue))) {
		rt = get_sensitivity_idx(id, parse_policy);
		if (rt < 0) {
			yyerror("undefined sensitivity in dominance definition");
			return -1;
		}
		if (i >= parse_policy->num_sensitivities) {
			yyerror("too many sensitivities in dominance definition?");
			return -1;
		}
		if (find_int_in_array(rt, parse_policy->mls_dominance, parse_policy->num_sensitivities) != -1) {
			yyerror("duplicate sensitivity in  dominance definition");
			return -1;
		}

		parse_policy->mls_dominance[i] = rt;

		i++;
		free(id);
	}

	if (i != parse_policy->num_sensitivities) {
		yyerror("all sensitivities must be specified in dominance definition");
		return -1;
	}

	return 0;
}

static int define_category(void)
{
	char *id, *name = NULL;
	int rt;
	name_item_t *aliases = NULL;

	rt = set_policy_version(POL_VER_19_20, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	if (pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_MLS_COMP))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	name = queue_remove(id_queue);
	if (!name) {
		yyerror("no name for category?");
		return -1;
	}

	while ( (id = queue_remove(id_queue)) ) {
		rt = add_name(id, &aliases);
		if (rt) {
			free_name_list(aliases);
			yyerror("error adding alias to category");
			return -1;
		}
	}

	rt = add_category(name, parse_policy->num_categories, aliases, parse_policy);
	if (rt) {
		free(name);
		free_name_list(aliases);
		yyerror("error adding category to policy");
		return -1;
	}

	return 0;
}

static int define_level(void)
{
	int rt;
	ap_mls_level_t *lvl = NULL;

	rt = set_policy_version(POL_VER_19_20, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	if (pass == 2 || (pass == 1 && !(parse_policy->opts & POLOPT_MLS_COMP))) {
		parse_mls_level(1);
		return 0;
	}

	lvl = parse_mls_level(0);
	if (!lvl) {
		yyerror("error parsing level");
		return -1;
	}
	
	rt = add_mls_level(lvl->sensitivity, lvl->categories, lvl->num_categories, parse_policy);
	free(lvl); /* only free the container its internal memory is used by parse_policy*/
	if (rt) {
		yyerror("error adding level to the policy");
		return -1;
	}

	return 0;
}

static int define_constraint(bool_t is_mls, ap_constraint_expr_t *expr)
{
	char *id;
	ta_item_t *classes = NULL, *perms = NULL, *item = NULL;
	int idx, rt;

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_CONSTRAIN))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	while ((id = queue_remove(id_queue))) {
		idx = get_obj_class_idx(id, parse_policy);
		free(id);
		if (idx == -1) {
			yyerror("invalid object class");
			ap_constraint_expr_destroy(expr);
			free_ta_list(classes);
			return -1;
		}
		item = (ta_item_t*)calloc(1, sizeof(ta_item_t));
		if (!item) {
			free_ta_list(classes);
			ap_constraint_expr_destroy(expr);
			yyerror("out of memory");
			return -1;
		}
		item->idx = idx;
		item->type = IDX_OBJ_CLASS;
		rt = insert_ta_item(item, &classes);
		if (rt) {
			free(item);
			free_ta_list(classes);
			ap_constraint_expr_destroy(expr);
			yyerror("out of memory");
			return -1;
		}
		item = NULL;
	}

	while ((id = queue_remove(id_queue))) {
		idx = get_perm_idx(id, parse_policy);
		free(id);
		if (idx == -1) {
			yyerror("invalid permission");
			ap_constraint_expr_destroy(expr);
			free_ta_list(classes);
			free_ta_list(perms);
			return -1;
		}
		item = (ta_item_t*)calloc(1, sizeof(ta_item_t));
		if (!item) {
			free_ta_list(classes);
			free_ta_list(perms);
			ap_constraint_expr_destroy(expr);
			yyerror("out of memory");
			return -1;
		}
		item->idx = idx;
		item->type = IDX_PERM;
		rt = insert_ta_item(item, &perms);
		if (rt) {
			free(item);
			free_ta_list(classes);
			free_ta_list(perms);
			ap_constraint_expr_destroy(expr);
			yyerror("out of memory");
			return -1;
		}
		item = NULL;
	}

	rt = add_constraint(is_mls, classes, perms, expr, policydb_lineno, parse_policy);
	if (rt) {
		free_ta_list(classes);
		free_ta_list(perms);
		ap_constraint_expr_destroy(expr);
		yyerror("error adding constraint to policy");
		return -1;
	}

	return 0;
}

static int define_mls(void)
{
	int rt;

	rt = set_policy_version(POL_VER_19_20, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	parse_policy->mls = TRUE;

	return 0;
}

static int mls_valid(void)
{
	if (parse_policy->version >= POL_VER_MLS) {
		return 1;
	} else {
		yyerror("MLS detected in non-MLS policy");
		return 0;
	}
}

static int define_validatetrans(bool_t is_mls, ap_constraint_expr_t *expr)
{
	char *id;
	ta_item_t *classes = NULL, *item = NULL;
	int idx, rt;

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_CONSTRAIN))) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	while ((id = queue_remove(id_queue))) {
		idx = get_obj_class_idx(id, parse_policy);
		free(id);
		if (idx == -1) {
			yyerror("invalid object class");
			ap_constraint_expr_destroy(expr);
			free_ta_list(classes);
			return -1;
		}
		item = (ta_item_t*)calloc(1, sizeof(ta_item_t));
		if (!item) {
			free_ta_list(classes);
			ap_constraint_expr_destroy(expr);
			yyerror("out of memory");
			return -1;
		}
		item->idx = idx;
		item->type = IDX_OBJ_CLASS;
		rt = insert_ta_item(item, &classes);
		if (rt) {
			free(item);
			free_ta_list(classes);
			ap_constraint_expr_destroy(expr);
			yyerror("out of memory");
			return -1;
		}
		item = NULL;
	}

	rt = add_validatetrans(is_mls, classes, expr, policydb_lineno, parse_policy);
	if (rt) {
		free_ta_list(classes);
		ap_constraint_expr_destroy(expr);
		yyerror("error adding validatetrans to policy");
		return -1;
	}

	return 0;
}

static int define_range_trans(void)
{
	char *id;
	int rt, l, idx, idx_type;
	ap_rangetrans_t *new_rngtr = NULL;
	bool_t subtract;
	ta_item_t *titem = NULL;
	ap_mls_range_t *range = NULL;

	rt = set_policy_version(POL_VER_19_20, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_RANGETRANS)) || (pass > 2 && yyis_decl()))  {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		id = queue_remove(id_queue); 
		free(id); 
		for (l = 0; l < 2; l++) {
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
			id = queue_remove(id_queue);
			if (!id)
				break;
			free(id); 
		}
	return 0;
	}

	new_rngtr = add_new_rangetrans(parse_policy);
	if (new_rngtr == NULL) {
		yyerror("Problem adding rangetrans to policy");
		return -1;
	}
	
	new_rngtr->lineno = policydb_lineno;

	/*read source (domain) */
	subtract = FALSE;
	while ((id = queue_remove(id_queue))) {
		if (strcmp(id, "*") == 0) {
			new_rngtr->flags |= AVFLAG_SRC_STAR;
			free(id);
			continue;
		}
		if (strcmp(id, "-") == 0) {
			subtract = TRUE;
			free(id);
			continue;
		}
		if (strcmp(id, "~") == 0) {
			new_rngtr->flags |= AVFLAG_SRC_TILDA;
			free(id);
			continue;
		}
		idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
		if (idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is neither a type nor type attribute", id);
			yyerror(errormsg);
			return -1;
		}
		titem = (ta_item_t*)malloc(sizeof(ta_item_t));
		if (titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = idx_type;
		if (subtract) {
			titem->type |= IDX_SUBTRACT;
			subtract = FALSE;
		}
		titem->idx = idx;
		if (insert_ta_item(titem, &(new_rngtr->src_types)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for source type id %s", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}

	/* read target (executable) types */
	subtract = FALSE;
	while ((id = queue_remove(id_queue))) {
		if (strcmp(id, "*") == 0) {
			new_rngtr->flags |= AVFLAG_TGT_STAR;
			free(id);
			continue;
		}
		if (strcmp(id, "-") == 0) {
			subtract = TRUE;
			free(id);
			continue;
		}
		if (strcmp(id, "~") == 0) {
			new_rngtr->flags |= AVFLAG_TGT_TILDA;
			free(id);
			continue;
		}
		idx = get_type_or_attrib_idx(id, &idx_type, parse_policy);
		if (idx < 0) {
			snprintf(errormsg, sizeof(errormsg), "%s is neither a type nor type attribute", id);
			yyerror(errormsg);
			return -1;
		}
		titem = (ta_item_t*)malloc(sizeof(ta_item_t));
		if (titem == NULL) {
			yyerror("out of memory");
			return -1;
		}
		titem->type = idx_type;
		if (subtract) {
			titem->type |= IDX_SUBTRACT;
			subtract = FALSE;
		}
		titem->idx = idx;
		if (insert_ta_item(titem, &(new_rngtr->tgt_types)) != 0) {
			snprintf(errormsg, sizeof(errormsg), "failed ta_item insetion for target type id %s", id);
			yyerror(errormsg);
			return -1;
		}
		free(id);
	}

	/* read range */

	range = parse_mls_range(0);
	if (range == NULL) {
		yyerror("error parsing range");
		return -1;
	}

	new_rngtr->range = range;

	id = queue_remove(id_queue);
	if (id != NULL) {
		yyerror("extra identifiers after rangetrans?");
		return -1;
	}

	return 0;
}

static ap_constraint_expr_t *
 define_cexpr(__u32 expr_type, __u32 arg1, __u32 arg2)
{
	char *id;
	ap_constraint_expr_t *expr = NULL, *tmp_expr1 = NULL, *tmp_expr2 = NULL;
	ta_item_t *item = NULL;
	bool_t subtract = FALSE;

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_CONSTRAIN))) {
		if (expr_type == AP_CEXPR_NAMES) {
			while ((id = queue_remove(id_queue))) 
				free(id);
		}
		return (ap_constraint_expr_t *)1; /* any non-NULL value */
	}

	expr = (ap_constraint_expr_t *)calloc(1, sizeof(ap_constraint_expr_t));
	if (!expr) {
		yyerror("out of memory");
		return NULL;
	}

	expr->expr_type = expr_type;

	switch(expr_type) {
	case AP_CEXPR_NOT:
		tmp_expr1 = NULL;
		tmp_expr2 = (ap_constraint_expr_t *)arg1;
		while (tmp_expr2) {
			tmp_expr1 = tmp_expr2;
			tmp_expr2 = tmp_expr2->next;
		}
		if (!tmp_expr1 || tmp_expr1->next) {
			yyerror("invalid constraint expression");
			free(expr);
			return NULL;
		}
		tmp_expr1->next = expr;
		return (ap_constraint_expr_t *)arg1;
		break;
	case AP_CEXPR_AND:
	case AP_CEXPR_OR:
		tmp_expr1 = NULL;
		tmp_expr2 = (ap_constraint_expr_t *)arg1;
		while (tmp_expr2) {
			tmp_expr1 = tmp_expr2;
			tmp_expr2 = tmp_expr2->next;
		}
		if (!tmp_expr1 || tmp_expr1->next) {
			yyerror("invalid constraint expression");
			free(expr);
			return NULL;
		}
		tmp_expr1->next = (ap_constraint_expr_t *)arg2;

		tmp_expr1 = NULL;
		tmp_expr2 = (ap_constraint_expr_t *)arg2;
		while (tmp_expr2) {
			tmp_expr1 = tmp_expr2;
			tmp_expr2 = tmp_expr2->next;
		}
		if (!tmp_expr1 || tmp_expr1->next) {
			yyerror("invalid constraint expression");
			free(expr);
			return NULL;
		}
		tmp_expr1->next = expr;
		return (ap_constraint_expr_t *)arg1;
		break;
	case AP_CEXPR_ATTR:
		expr->attr = arg1;
		expr->op = arg2;
		return expr;
		break;
	case AP_CEXPR_NAMES:
		expr->attr = arg1;
		expr->op = arg2;
		while ((id = (char *) queue_remove(id_queue))) {
			item = (ta_item_t*)calloc(1, sizeof(ta_item_t));
			if (!item) {
				yyerror("out of memory");
				free(expr);
				return NULL;
			}
			if (expr->attr & AP_CEXPR_USER) {
				item->type = IDX_USER;
				item->idx = get_user_idx(id, parse_policy);
				if (item->idx == -1) {
					yyerror("invalid user");
					free(item);
					free(expr);
					return NULL;
				}
				if (insert_ta_item(item, &(expr->names))) {
					yyerror("failed adding user");
					free(expr);
					return NULL;
				}
			} else if(expr->attr & AP_CEXPR_ROLE) {
				item->type = IDX_ROLE;
				item->idx = get_role_idx(id, parse_policy);
				if (item->idx == -1) {
					yyerror("invalid role");
					free(item);
					free(expr);
					return NULL;
				}
				if (insert_ta_item(item, &(expr->names))) {
					yyerror("failed adding role");
					free(expr);
					return NULL;
				}
			} else if (expr->attr & AP_CEXPR_TYPE) {
				if (!strcmp(id, "*")) {
					expr->name_flags |= AP_CEXPR_STAR;
					free(id);
					free(item);
					continue;
				} else if (!strcmp(id, "~")) {
					expr->name_flags |= AP_CEXPR_TILDA;
					free(id);
					free(item);
					continue;
				} else if (!strcmp(id, "-")) {
					subtract = TRUE;
					free(id);
					free(item);
					continue;
				} else {
					item->idx = get_type_or_attrib_idx(id, &(item->type), parse_policy);
					if (item->idx == -1) {
						yyerror("invalid type/attribute");
						free(item);
						free(expr);
						return NULL;
					}
					if (subtract) {
						subtract = FALSE;
						item->type |= IDX_SUBTRACT;
					}
					if (insert_ta_item(item, &(expr->names))) {
						yyerror("failed adding type/attribute");
						free(expr);
						return NULL;
					}
				}
			} else {
				yyerror("invalid constraint expression");
				free(expr);
				return NULL;
			}
		}
		break;
	default:
		yyerror("invalid constraint expression");
		free(expr);
		return NULL;
		break;
	}

	return expr;
}




static int define_fs_context(int ver)
{
	int rt;
	
	rt = set_policy_version(ver, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	parse_security_context(1);
	parse_security_context(1);
	return 0;
}

static int define_port_context(int ver, int low, int high)
{
	char *id;
	security_con_t *context;
	int rt, protocol = 0;
	
	rt = set_policy_version(ver, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	id = (char *) queue_remove(id_queue);

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_OCONTEXT))) {
		free(id);
		parse_security_context(1);
	} else {
		if (!strcmp(id, "tcp"))
			protocol = AP_TCP_PROTO;
		else if (!strcmp(id, "udp"))
			protocol = AP_UDP_PROTO;
		else if (!strcmp(id, "esp"))
			protocol = AP_ESP_PROTO;
		else {
			yyerror("unrecognized protocol");
			return -1;
		}

		context = parse_security_context(0);

		rt = add_portcon(protocol, low, high, context, parse_policy);
		if (rt) {
			yyerror("error adding portcon to policy");
			return -1;
		}

	}

	return 0;
}

static int define_netif_context(int ver)
{
	int rt;
	char *id;
	security_con_t *devcon, *pktcon;

	rt = set_policy_version(ver, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_OCONTEXT))) {
		free(queue_remove(id_queue));
		parse_security_context(1);
		parse_security_context(1);
		return 0;
	} else {
		id = queue_remove(id_queue);
		if (!id) {
			yyerror("no interface for netifcon?");
			return -1;
		}
		devcon = parse_security_context(0);
		pktcon = parse_security_context(0);
	}

	rt = add_netifcon(id, devcon, pktcon, parse_policy);
	if (rt) {
		yyerror("error adding netifcon to policy");
		return -1;
	}

	return 0;
}

static int define_ipv4_node_context(int ver, __u32 addr, __u32 mask)
{
	int rt;
	uint32_t address[4], netmask[4];
	security_con_t *context = NULL;

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_OCONTEXT))) {
		parse_security_context(1);
		return 0;
	}

	rt = set_policy_version(ver, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		free(address);
		free(netmask);
		return -1;
	}

	context = parse_security_context(0);
	address[3] = addr;
	address[0] = address[1] = address[2] = 0;
	netmask[3] = mask;
	netmask[0] = netmask[1] = netmask[2] = 0;
	rt = add_nodecon(AP_IPV4, address, netmask, context, parse_policy);
	if (rt) {
		yyerror("error adding nodecon to policy");
		security_con_destroy(context);
		return -1;
	}

	return 0;
}

static uint32_t *parse_ipv6_addr(char *addr_str)
{
	int rt, i;
	uint32_t *address = NULL;
	struct in6_addr addr;

	if (!addr_str) {
		yyerror("invalid IPv6 address");
		return NULL;
	}

	address = (uint32_t *)calloc(4, sizeof(uint32_t));
	if (!address){
		yyerror("out of memory");
		return NULL;
	}

	rt = inet_pton(AF_INET6, addr_str, &addr);
	if (rt < 1) {
		yyerror("error processing IPv6 address");
		return NULL;
	}

	for (i = 0; i < 16; i++) {
		address[i/4] |= ((uint32_t)addr.s6_addr[i] << (8 * (3 - i%4)));
	}

	return address;
}

static int define_ipv6_node_context(int ver)
{
	int rt;
	uint32_t *address = NULL, *netmask = NULL;
	security_con_t *context = NULL;
	char *id = NULL;

	rt = set_policy_version(ver, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_OCONTEXT))) {
		free(queue_remove(id_queue));
		free(queue_remove(id_queue));
		parse_security_context(1);
		return 0;
	}
	id = queue_remove(id_queue);
	address = parse_ipv6_addr(id);
	if (!address) {
		return -1; /* error reported from above function */
	}
	id = queue_remove(id_queue);
	netmask = parse_ipv6_addr(id);
	if (!netmask) {
		free(address);
		return -1; /* error reported from above function */
	}
	context = parse_security_context(0);
	rt = add_nodecon(AP_IPV6, address, netmask, context, parse_policy);
	free(address);
	free(netmask);
	if (rt) {
		yyerror("error adding nodecon to policy");
		security_con_destroy(context);
		return -1;
	}

	return 0;	
}

/* removed Jul 2002 */
static int define_devfs_context(int has_type)
{
	int rt;
	
	rt = set_policy_version(POL_VER_PREJUL2002, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	free(queue_remove(id_queue));
	if (has_type)
		free(queue_remove(id_queue));
	parse_security_context(1);
	return 0;
}
/* removed Jul 2002 */

static int define_nfs_context(void)
{
	int rt;
	
	rt = set_policy_version(POL_VER_PREJUL2002, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}
	parse_security_context(1);
	return 0;
}

/* added Jul 2002 */
/* changed Jul 2003; added FSUSEXATTR */
static int define_fs_use(int behavior, int ver)
{
	int rt;
	char *id = NULL;
	security_con_t *context = NULL;
	
	rt = set_policy_version(ver, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_OCONTEXT))) {
	id = (char*) queue_remove(id_queue);
	free(id);
	if(behavior != AP_FS_USE_PSID)
		parse_security_context(1);
	return 0;
	}

	id = (char*) queue_remove(id_queue);
	if (!id) {
		yyerror("no name for filesystem in fs_use statement?");
		return -1;
	}
	if(behavior != AP_FS_USE_PSID) {
		context = parse_security_context(0);
		if (!context) {
			yyerror("missing or invalid context for fs_use statement");
			return -1;
		}
	}

	rt = add_fs_use(behavior, id, context, parse_policy);
	if (rt != 0) {
		yyerror("error adding fs_use statement to policy");
		return -1;
	}

	return 0;
}

/* added Jul 2002 */
static int define_genfs_context_helper(char *fstype, int has_type)
{
	int rt, idx, type=-1;
	char *id = NULL, *tmp = NULL;
	security_con_t *context;

	rt = set_policy_version(POL_VER_JUL2002, parse_policy);
	if(rt != 0) {
		yyerror("error setting policy version");
		return -1;
	}

	if (pass == 1 || (pass == 2 && !(parse_policy->opts & POLOPT_OCONTEXT))) {
		free(fstype);
		free(queue_remove(id_queue));
		if (has_type)
			free(queue_remove(id_queue));
		parse_security_context(1);
		return 0;
	}

	if (!fstype) {
		yyerror("no name for filesystem type?");
		return -1;
	}

	idx = ap_genfscon_get_idx(fstype, parse_policy);
	if (idx == -1) {
		rt = add_genfscon(fstype, parse_policy);
		if (rt) {
			yyerror("error adding genfscon to policy");
			return -1;
		}
		idx = parse_policy->num_genfscon - 1;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("no path for genfscon?");
		return -1;
	}

	if (has_type) {
		tmp = queue_remove(id_queue);
		switch (tmp[0]) {
		case 'b':
			type = FILETYPE_BLK;
			break;
		case 'c':
			type = FILETYPE_CHR;
			break;
		case 'd':
			type = FILETYPE_DIR;
			break;
		case 'l':
			type = FILETYPE_LNK;
			break;
		case 'p':
			type = FILETYPE_FIFO;
			break;
		case 's':
			type = FILETYPE_SOCK;
			break;
		case '-':
			type = FILETYPE_REG;
			break;
		default:
			yyerror("invalid filetype in genfscon");
			break;
		}
		free(tmp);
	} else {
		type = FILETYPE_ANY;
	}

	context = parse_security_context(0);
	if (!context) {
		yyerror("invalid context for genfscon");
		return -1;
	}

	rt = add_path_to_genfscon(&(parse_policy->genfscon[idx]), id, type, context);
	if (rt) {
		yyerror("error adding path to genfscon");
		return -1;
	}

	return 0;
}

/* added Jul 2002 */
static int define_genfs_context(int has_type)
{
	return define_genfs_context_helper(queue_remove(id_queue), has_type);
}

/* Optional processing */
/* A Brief Explanation:
 * Optionals are handled by adding start states to the scanner to
 * enable conditional parsing of sections of the policy
 * Optionals are skipped during pass one, and also skipped in pass 2. 
 * If any skipped optionals were found, a third pass is made in the declaration
 * state; this state reads the require statements and changes the meaning
 * of symbol declarations to add them to the optional's symbol list rather
 * than the policy. After this step, requirements are resolved and a fourth 
 * pass is made to take the main blocks of optionals for which all requirements
 * are met. This process of resolve and reparse is repeated until no new 
 * optionals are taken at which point a final pass is make to take the 
 * else blocks of the remaining optionals. During all passes > 2 lines
 * outside an optional block are ignored. */
static int begin_optional(void)
{
	ap_optional_t *opt = NULL;

	parse_policy->has_optionals = TRUE;

	if (pass < 3) {
		yyenter_ignore();
	} else {
		if ((opt=ap_optional_get_by_lineno(policydb_lineno, parse_policy))) {
			if (opt->status & (OPTIONAL_STATUS_UNDECIDED|OPTIONAL_STATUS_TAKE_ELSE|OPTIONAL_STATUS_FINISHED)) {
				yyenter_ignore();
			} else {
				yyenter_accept();
			}
		} else {
			if (!optional_stack || !optional_stack->opt || optional_stack->opt->status == OPTIONAL_STATUS_TAKE_MAIN) {
				opt = calloc(1, sizeof(ap_optional_t));
				if (!opt)
					return -1;
				ap_optional_init(opt);
				opt->next = parse_policy->optionals;
				parse_policy->optionals = opt;
				opt->lineno = policydb_lineno;
				yyenter_decl();
			} else {
				/* do not create yet */
				yyenter_ignore();
			} 
		}
	}

	push_optional(opt);
	return 0;
}

static int begin_optional_else(void)
{
	if (optional_stack && optional_stack->opt && optional_stack->opt->status == OPTIONAL_STATUS_TAKE_ELSE) {
		yyenter_accept();
		optional_stack->opt->status = OPTIONAL_STATUS_FINISHED;
	} else
		yyenter_ignore();
	return 0;
}

static int optional_end_main(void)
{
	if (optional_stack && optional_stack->opt && optional_stack->opt->status == OPTIONAL_STATUS_TAKE_MAIN)
		optional_stack->opt->status = OPTIONAL_STATUS_FINISHED;

	yyleave_state();
	return 0;
}

static int end_optional_else(void)
{
	yyleave_state();
	return 0;
}

static int end_optional(void)
{
	opt_stack_t *tmp = optional_stack;

	if (tmp) {
		optional_stack = optional_stack->next;
		free(tmp);
	}
	return 0;
}

static int add_require(int type)
{
	ap_require_t *req = NULL;
	char *id = NULL;

	if (pass >= 3) {
		if (type == IDX_OBJ_CLASS) {
			req = calloc(1, sizeof(ap_require_t));
			if (!req) 
				return -1;
			ap_require_init(req);
			req->name = queue_remove(id_queue);
			req->type = type;
			req->next = parse_policy->optionals->requires;
			parse_policy->optionals->requires = req;
			if (add_require(IDX_PERM))
				return -1;
		} else {
			while((id = queue_remove(id_queue))) {
				req = calloc(1, sizeof(ap_require_t));
				if (!req) 
					return -1;
				ap_require_init(req);
				req->name = id;
				req->type = type;
				if (type == IDX_PERM) {
					req->next = parse_policy->optionals->requires->perms;
					parse_policy->optionals->requires->perms = req;
				} else {
					req->next = parse_policy->optionals->requires;
					parse_policy->optionals->requires = req;
				}
			}
		}
	} else {
		while((id = queue_remove(id_queue)))
			free(id);
	}

	return 0;
}

static int push_optional(ap_optional_t *opt)
{
	opt_stack_t *tmp = NULL;

	tmp = calloc(1, sizeof(opt_stack_t));
	if (!tmp)
		return -1;
	tmp->opt = opt;
	tmp->next = optional_stack;
	optional_stack = tmp;

	return 0;
}

static int begin_require(void)
{
	if (optional_stack && optional_stack->opt->status & (OPTIONAL_STATUS_FINISHED|OPTIONAL_STATUS_TAKE_MAIN))
		yyenter_ignore();
	else
		yyenter_require();
	return 0;
}

