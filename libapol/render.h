 /* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* render.h */

/* Utility functions to render aspects of a policy into strings */

#ifndef _APOLICY_RENDER_H_
#define _APOLICY_RENDER_H__

#include <stdlib.h>
#include "policy.h"

char *re_render_av_rule(bool_t addlineno, int idx, bool_t is_au, policy_t *policy) ;
char *re_render_tt_rule(bool_t addlineno, int idx, policy_t *policy) ;
char *re_render_security_context(const security_con_t *context,policy_t *policy);
char *re_render_initial_sid_security_context(int idx, policy_t *policy);
char *re_render_avh_rule(avh_node_t *node, policy_t *p);
char *re_render_avh_rule_cond_state(avh_node_t *node, policy_t *p);
char *re_render_avh_rule_linenos(avh_node_t *node, policy_t *p);
char * re_render_avh_rule_enabled_state(avh_node_t *node, policy_t *p);
char *re_render_avh_rule_cond_expr(avh_node_t *node, policy_t *p);
char *re_render_cond_expr(int idx,policy_t *p);
#endif /*_APOLICY_RENDER_H_*/
