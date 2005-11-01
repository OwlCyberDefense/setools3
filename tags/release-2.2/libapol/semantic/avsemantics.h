/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * avsemantics.h
 *
 * Support for semantically examining the TE rules for a policy
 * via a hash table.
 */
#ifndef _APOLICY_AVSEMANTICS_H_
#define _APOLICY_AVSEMANTICS_H_
#include "avhash.h"
#include "../policy.h"

bool_t avh_is_enabled(avh_node_t *node, policy_t *p);
int avh_build_hashtab(policy_t *p);

#endif /* _APOLICY_AVSEMANTICS_H_ */

