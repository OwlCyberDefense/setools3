 /* Copyright (C) 2001-2003, Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* util.h */

/* Utility functions */

#ifndef _APOLICY_UTIL_H_
#define _APOLICY_UTIL_H_

#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <stdint.h>

/* The following should be defined in the make environment */
#ifndef LIBAPOL_VERSION_STRING
	#define LIBAPOL_VERSION_STRING "UNKNOWN"
#endif

/* use 8k line size */
#define LINE_SZ 8192
#define BUF_SZ 240
/* HACK! checkpolicy doesn't appear to enforce a string size limit; but for simplicity
 * we're going to fail for any single string over APOL_STR_SZ.  We primarily need this
 * to simplify the string-intensive apol TCL commands.
 */
#define APOL_STR_SZ 128
#define is_valid_str_sz(str) (strlen(str) < APOL_STR_SZ)

#define APOL_ENVIRON_VAR_NAME "APOL_INSTALL_DIR"

/* structs defined in policy.h */
struct policy;
struct ta_item;

#undef FALSE
#define FALSE   0
#undef TRUE
#define TRUE	1
typedef unsigned char bool_t;


/* generic link list structures */
typedef struct llist_node {
	void 			*data;	/* data of any type or structure */
	struct llist_node	*prev;
	struct llist_node	*next;
} llist_node_t;

typedef struct llist {
	int		num;
	llist_node_t	*head;
	llist_node_t	*tail;
} llist_t;

/* structure used internally for passing TE rule match booleans */
typedef struct rules_bool {
	bool_t *access;		/* AV access rules */
	bool_t *audit;		/* AV audit rules; can be optional */
	bool_t *ttrules;	/* Type transition rules */
	bool_t *clone;		/* clone rules */
	int ac_cnt;
	int au_cnt;
	int tt_cnt;
	int cln_cnt;
} rules_bool_t;

/* structure used internally for matching RBAC rules */
typedef struct rbac_bool {
	bool_t *allow;		/* RBAC allow */
	bool_t *trans;		/* RBAC role_transition */
	int a_cnt;
	int t_cnt;
} rbac_bool_t;

/* prototypes */
const char* libapol_get_version(void);
char* find_file(const char *file_name);
char* find_user_config_file(const char *file_name);
bool_t getbool(const char *str);
int trim_string(char **str);
int trim_leading_whitespace(char **str);
void trim_trailing_whitespace(char **str);
llist_t *ll_new(void);
void ll_free(llist_t *ll, void(*free_data)(void *));
llist_node_t *ll_node_free(llist_node_t *n, void(*free_data)(void *));
int ll_unlink_node(llist_t *ll, llist_node_t *n);
int ll_insert_data(llist_t *ll, llist_node_t *n, void *data);
int ll_append_data(llist_t *ll, void *data);
int init_rules_bool(bool_t include_audit, rules_bool_t *rules_b, struct policy *policy);
int init_rbac_bool(rbac_bool_t *b, struct policy *policy, bool_t roles);
int rbac_bool_or_eq(rbac_bool_t *b1, rbac_bool_t *b2, struct policy *policy);
int rbac_bool_and_eq(rbac_bool_t *b1, rbac_bool_t *b2, struct policy *policy);
int all_true_rules_bool(rules_bool_t *rules_b, struct policy *policy);
int all_false_rules_bool(rules_bool_t *rules_b, struct policy *policy);
int all_true_rbac_bool(rbac_bool_t *b, struct policy *policy);
int all_false_rbac_bool(rbac_bool_t *b, struct policy *policy);
int free_rules_bool(rules_bool_t *rules_b);
int free_rbac_bool(rbac_bool_t *b);
char* uppercase(const char *instr, char *outstr);

int add_i_to_a(int i, int *cnt, int **a);
int add_uint_to_a(uint32_t i, uint32_t *cnt, uint32_t **a);
int find_int_in_array(int i, const int *a, int a_sz);
int add_int_to_array(int i, int *a, int num, int a_sz);
int copy_int_array(int **dest, int *src, int len);
int int_compare(const void *aptr, const void *bptr);

bool_t is_name_in_list(const char *name, struct ta_item *list, struct policy *policy);
unsigned char str_is_only_white_space(const char *str);
int get_type_idxs_by_regex(int **types, int *num, regex_t *preg, bool_t include_self, struct policy *policy);
char *get_config_var(const char *var, FILE *fp);
char **get_config_var_list(const char *var, FILE *file, int *list_sz);
char *config_var_list_to_string(const char **list, int size);
unsigned char str_token_is_not_valid(const char *str);
int append_str(char **tgt, int *tgt_sz, const char *str);
int read_file_to_buffer(const char *fname, char **buf, int *len);
int str_to_internal_ip(const char *str, uint32_t ip[4]);

#endif /*_APOLICY_UTIL_H_*/


/******************** new stuff here ********************/

/**
 * @file util.h
 *
 * Miscellaneous, uncategorized functions for libapol.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _APOL_UTIL_H_
#define _APOL_UTIL_H_

/**
 * Given a portcon protocol, return a read-only string that describes
 * that protocol.
 *
 * @param protocol Portcon protocol, one of IPPROTO_TCP or IPPROTO_UDP
 * from netinet/in.h.
 *
 * @return A string that describes the protocol, or NULL if the
 * protocol is invalid.  <b>Do not free() this string.</b>
 */
extern const char *apol_protocol_to_str(uint8_t protocol);

/**
 * Given a string representing and IP value (mask or address, IPv4 or
 * IPv6), write to an array that value in the same bit order that
 * sepol uses.  If the IP was in IPv4 format, only write to the first
 * element and zero the remainder.
 *
 * @param str A string representing and IP value, either in IPv4 or
 * IPv6 format.
 * @param ip Array to which write converted value.
 *
 * @return SEPOL_IPV4 if the string is in IPv4 format, SEPOL_IPV6 if
 * in IPv6, < 0 on error.
 */
extern int apol_str_to_internal_ip(const char *str, uint32_t ip[4]);

/**
 * Given a genfscon object class, return a read-only string that
 * describes that class.
 *
 * @param objclass Object class, one of SEPOL_CLASS_BLK_FILE,
 * SEPOL_CLASS_CHR_FILE, etc.
 *
 * @return A string that describes the object class, or NULL if the
 * object class is invalid.  <b>Do not free() this string.</b>
 */
extern const char *apol_objclass_to_str(uint32_t objclass);

/**
 * Given a fs_use behavior type, return a read-only string that
 * describes that fs_use behavior.
 *
 * @param filetype File type, one of SEPOL_FS_USE_PSID,
 * SEPOL_FS_USE_XATTR, etc.
 *
 * @return A string that describes the behavior, or NULL if the
 * behavior is invalid.  <b>Do not free() this string.</b>
 */
extern const char *apol_fs_use_behavior_to_str(uint32_t behavior);

/**
 * Given a fs_use behavior string, return its numeric value.
 *
 * @param filetype File type, one of "fs_use_psid", "fs_use_xattr",
 * etc.
 *
 * @return A numeric representation for the behavior, one of
 * SEPOL_FS_USE_PSID, SEPOL_FS_USE_XATTR, etc, or < 0 if the string is
 * invalid.
 */
extern int apol_str_to_fs_use_behavior(const char *behavior);

#endif
