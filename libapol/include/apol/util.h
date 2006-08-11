/**
 * @file util.h
 *
 * Miscellaneous, uncategorized functions for libapol.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2001-2006 Tresys Technology, LLC
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

#ifndef APOL_UTIL_H
#define APOL_UTIL_H

#include <config.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* use 8k line size */
#define APOL_LINE_SZ 8192

#define APOL_ENVIRON_VAR_NAME "APOL_INSTALL_DIR"

#undef FALSE
#define FALSE   0
#undef TRUE
#define TRUE	1
typedef unsigned char bool_t;

/**
 * Return an inmutable string describing this library's version.
 *
 * @return String describing this library.
 */
extern const char* libapol_get_version(void);

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
 * qpol uses.  If the IP was in IPv4 format, only write to the first
 * element and zero the remainder.
 *
 * @param str A string representing and IP value, either in IPv4 or
 * IPv6 format.
 * @param ip Array to which write converted value.
 *
 * @return QPOL_IPV4 if the string is in IPv4 format, QPOL_IPV6 if
 * in IPv6, < 0 on error.
 */
extern int apol_str_to_internal_ip(const char *str, uint32_t ip[4]);

/**
 * Given a genfscon object class, return a read-only string that
 * describes that class.
 *
 * @param objclass Object class, one of QPOL_CLASS_BLK_FILE,
 * QPOL_CLASS_CHR_FILE, etc.
 *
 * @return A string that describes the object class, or NULL if the
 * object class is invalid.  <b>Do not free() this string.</b>
 */
extern const char *apol_objclass_to_str(uint32_t objclass);

/**
 * Given a fs_use behavior type, return a read-only string that
 * describes that fs_use behavior.
 *
 * @param behavior A fs_use behavior, one of QPOL_FS_USE_PSID,
 * QPOL_FS_USE_XATTR, etc.
 *
 * @return A string that describes the behavior, or NULL if the
 * behavior is invalid.  <b>Do not free() this string.</b>
 */
extern const char *apol_fs_use_behavior_to_str(uint32_t behavior);

/**
 * Given a fs_use behavior string, return its numeric value.
 *
 * @param behavior A fs_use behavior, one of "fs_use_psid",
 * "fs_use_xattr", etc.
 *
 * @return A numeric representation for the behavior, one of
 * QPOL_FS_USE_PSID, QPOL_FS_USE_XATTR, etc, or < 0 if the string is
 * invalid.
 */
extern int apol_str_to_fs_use_behavior(const char *behavior);

/**
 * Given a rule type, return a read-only string that describes that
 * rule.
 *
 * @param rule_type A policy rule type, one of QPOL_RULE_ALLOW,
 * QPOL_RULE_TYPE_CHANGE, etc.
 *
 * @return A string that describes the rule, or NULL if the rule_type
 * is invalid.  <b>Do not free() this string.</b>
 */
extern const char *apol_rule_type_to_str(uint32_t rule_type);

/**
 * Given a conditional expression type, return a read-only string that
 * describes that operator.
 *
 * @param expr_type An expression type, one of QPOL_COND_EXPR_BOOL,
 * QPOL_COND_EXPR_NOT, etc.
 *
 * @return A string that describes the expression, or NULL if the
 * expr_type is invalid.  <b>Do not free() this string.</b>
 */
extern const char *apol_cond_expr_type_to_str(uint32_t expr_type);

/**
 * Given a file name, search and return that file's path on the
 * running system.  First search the present working directory, then
 * the directory at APOL_INSTALL_DIR (an environment variable), then
 * apol's install dir.
 *
 * @param file_name File to find.
 *
 * @return File's path, or NULL if not found.  Caller must free() this
 * string afterwards.
 */
extern char* apol_file_find(const char *file_name);

/**
 * Given a file name for a user configuration, search and return that
 * file's path in the user's home directory.
 *
 * @param file_name File to find.
 *
 * @return File's path, or NULL if not found.  Caller must free() this
 * string afterwards.
 */
extern char* apol_file_find_user_config(const char *file_name);

/**
 * Given a file name, read the file's contents into a newly allocated
 * buffer.  The caller must free() this buffer afterwards.
 *
 * @param fname Name of file to read.
 * @param buf Reference to a newly allocated buffer.
 * @param len Reference to the number of bytes read.
 *
 * @return 0 on success, < 0 on error.
 */
extern int apol_file_read_to_buffer(const char *fname, char **buf, size_t *len);
/**
 * Given a file pointer into a config file, read and return the value
 * for the given config var.  The caller must free() the returned
 * string afterwards.
 *
 * @param var Name of configuration variable to obtain.
 * @param fp An open file pointer into a configuration file.  This
 * function will not maintain the pointer's current location.
 *
 * @return A newly allocated string containing the variable's value,
 * or NULL if not found or error.
 */
extern char *apol_config_get_var(const char *var, FILE *fp);

/**
 * Given a file pointer into a config file, read and return a list of
 * values associated with the given config var.  The variable's value
 * is expected to be a ':' separated string.  The caller must free()
 * the returned array of strings afterwards, as well as the pointer
 * itself.
 *
 * @param var Name of configuration variable to obtain.
 * @param fp An open file pointer into a configuration file.  This
 * function will not maintain the pointer's current location.
 * @param list_sz Reference to the number of elements within the
 * returned array.
 *
 * @return A newly allocated array of strings containing the
 * variable's values, or NULL if not found or error.
 */
extern char **apol_config_get_varlist(const char *var, FILE *file, size_t *list_sz);

/**
 * Given a list of configuration variables, as returned by
 * apol_config_list(), allocate and return a string that joins the
 * list using ':' as the separator.  The caller is responsible for
 * free()ing the string afterwards.
 *
 * @param list Array of strings.
 * @param size Number of elements within the list.
 *
 * @return An allocated concatenated string, or NULL upon error.
 */
extern char *apol_config_varlist_to_str(const char **list, size_t size);

/**
 * Given a dynamically allocated string, allocate a new string with
 * both starting and trailing whitespace characters removed.  The
 * caller is responsible for free()ing the resulting pointer.  The
 * original string will be free()d by this function.
 *
 * @param str Reference to a dynamically allocated string.
 *
 * @return 0 on success, < 0 on out of memory.
 */
extern int apol_str_trim(char **str);

/**
 * Append a string to an existing dynamic mutable string, expanding
 * the target string if necessary.  The caller must free() the target
 * string.  If tgt is NULL then initially allocate the resulting
 * string.
 *
 * @param tgt Reference to a string to modify, or NULL to create a new
 * string.
 * @param tgt_sz Number of bytes allocated to tgt.
 * @param str String to append.
 *
 * @return 0 on success, < 0 on out of memory or error.
 */
extern int apol_str_append(char **tgt, size_t *tgt_sz, const char *str);

/**
 * Test whether a given string is only white space.
 *
 * @param str String to test.
 * @return 1 if string is either NULL or only whitespace, 0 otherwise.
 */
extern int apol_str_is_only_white_space(const char *str);

/**
 * Wrapper around strcmp for use in vector comparison functions.
 *
 * @param a String to compare.
 * @param b The other string to compare.
 * @param unused Not used. (exists to match expected function signature)
 *
 * @return Less than, equal to, or greater than 0 if string a is found
 * to be less than, identical to, or greater than string b
 * respectively.
 */
extern int apol_str_strcmp(const void *a, const void *b, void *unused __attribute__ ((unused)) );

#endif
