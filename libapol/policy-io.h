/* Copyright (C) 2001-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com
 */

/* policy-io.c
 *
 * Policy I/O functions */

#ifndef _APOLICY_POLICYIO_H_
#define _APOLICY_POLICYIO_H_

#include "policy.h"

/* LIBAPOL_DEFAULT_POLICY should be defined in the make environment */
#ifndef LIBAPOL_DEFAULT_POLICY
	#define LIBAPOL_DEFAULT_POLICY "/etc/security/selinux/src/policy/policy.conf"
#endif

/* * Return codes for find_default_policy_file() function. */
#define FIND_DEFAULT_SUCCESS 			0
#define GENERAL_ERROR	 			-1
#define BIN_POL_FILE_DOES_NOT_EXIST 		-2
#define SRC_POL_FILE_DOES_NOT_EXIST 		-3
#define BOTH_POL_FILE_DO_NOT_EXIST 		-4
#define POLICY_INSTALL_DIR_DOES_NOT_EXIST	-5
#define INVALID_SEARCH_OPTIONS			-6

int close_policy(policy_t *policy);
int open_policy(const char* filename, policy_t **policy);
int open_partial_policy(const char* filename, unsigned int options, policy_t **policy);
unsigned int validate_policy_options(unsigned int options);
int find_default_policy_file(unsigned int search_opt, char **policy_file_path);
const char* find_default_policy_file_strerr(int err);

#endif   



