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
char *re_render_security_context(const security_context_t *context,policy_t *policy);
char *re_render_initial_sid_security_context(int idx, policy_t *policy);

#endif /*_APOLICY_RENDER_H_*/
