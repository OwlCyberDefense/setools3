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

int close_policy(policy_t *policy);
int open_policy(const char* filename, policy_t **policy);
int open_partial_policy(const char* filename, unsigned int options, policy_t **policy);
unsigned int validate_policy_options(unsigned int options);

#endif   



