 /* Copyright (C) 2001 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* apolicy 
 *
 * Functions to resolve clone rules dynamically */
#ifndef _APOLICY_CLONE_H_
#define _APOLICY_CLONE_H_

#include "policy.h"
#include "util.h"
 
int match_cloned_rules(int idx, bool_t include_audit, rules_bool_t *rules_b,policy_t *policy );

#endif
