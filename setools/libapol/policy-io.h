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

#define	SEARCH_BINARY 1
#define SEARCH_SOURCE 2
#define SEARCH_BOTH 3

int close_policy(policy_t *policy);
int open_policy(const char* filename, policy_t **policy);
int open_partial_policy(const char* filename, unsigned int options, policy_t **policy);
unsigned int validate_policy_options(unsigned int options);
int find_default_policy_file(int search_opt, char *policy_file_path);
const char* decode_find_default_policy_file_err(int err);

#endif   



