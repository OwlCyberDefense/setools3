/* Copyright (C) 2002 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com
 */

/* policy-avl.h
 *
 * AVL binary tree functions that are aware of the policy database structure.
 */

#ifndef _APOLICY_POLICY_ALV_H_
#define _APOLICY_POLICY_ALV_H_

#include "policy.h"

int init_avl_trees(policy_t *policy);
int free_avl_trees(policy_t *policy);

#endif /*_APOLICY_POLICY_ALV_H_ */

