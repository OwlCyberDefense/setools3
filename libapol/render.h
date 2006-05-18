#ifndef _APOLICY_RENDER_H_
#define _APOLICY_RENDER_H_

#include <stdlib.h>
#include "policy.h"

char *re_render_av_rule(bool_t addlineno, int idx, bool_t is_au, policy_t *policy) ;
char *re_render_tt_rule(bool_t addlineno, int idx, policy_t *policy);
char *re_render_role_trans(bool_t addlineno, int idx, policy_t *policy);
char *re_render_role_allow(bool_t addlineno, int idx, policy_t *policy);
char *re_render_security_context(const security_con_t *context,policy_t *policy);
char *re_render_initial_sid_security_context(int idx, policy_t *policy);
char *re_render_avh_rule(avh_node_t *node, policy_t *p);
char *re_render_avh_rule_cond_state(avh_node_t *node, policy_t *p);
char *re_render_avh_rule_linenos(avh_node_t *node, policy_t *p);
char *re_render_avh_rule_cond_expr(avh_node_t *node, policy_t *p);
char *re_render_cond_expr(int idx,policy_t *p);
char *re_render_fs_use(ap_fs_use_t *fsuse, policy_t *policy);
char *re_render_portcon(ap_portcon_t *portcon, policy_t *policy);
char *re_render_netifcon(ap_netifcon_t *netifcon, policy_t *policy);
char *re_render_nodecon(ap_nodecon_t *nodecon, policy_t *policy);
char *re_render_genfscon(ap_genfscon_t *genfscon, policy_t *policy);
char *re_render_cexpr(ap_constraint_expr_t *expr, policy_t *policy);
char *re_render_constraint(bool_t addlineno, ap_constraint_t *constraint, policy_t *policy);
#define re_render_validatetrans(addlineno, vtrx, policy) re_render_constraint(addlineno, vtrx, policy)
char *re_render_mls_level(ap_mls_level_t *level, policy_t *policy);
char *re_render_mls_range(ap_mls_range_t *range, policy_t *policy);
char *re_render_rangetrans(bool_t addlineno, int idx, policy_t *policy);

/******************** new stuff below ********************/

/**
 * @file render.h
 *
 * Public interfaces that renders things.  Unless otherwise stated,
 * all functions return a newly allocated string, which the caller is
 * responsible for free()ing afterwards.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 * @author David Windsor dwindsor@tresys.com
 *
 * Copyright (C) 2003-2006 Tresys Technology, LLC
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

/* QPOL */
#include <qpol/policy_query.h>
#include "mls-query.h"
#include "vector.h"
/**
 * Given an IPv4 address (or mask) in qpol byte order, allocate and
 * return a string representing that address.
 *
 * @param policydb Reference to a policy, for reporting errors
 * @param addr Address (or mask) to render.
 *
 * @return A newly allocated string, which the caller must free.
 * Returns NULL on error.
 */
char *re_render_ipv4_addr(apol_policy_t *policydb, uint32_t addr);

/**
 * Given an IPv6 address (or mask) in qpol byte order, allocate and
 * return a string representing that address.
 *
 * @param policydb Reference to a policy, for reporting errors
 * @param addr Address (or mask) to render.
 *
 * @return A newly allocated string, which the caller must free.
 * Returns NULL on error.
 */
char *re_render_ipv6_addr(apol_policy_t *policydb, uint32_t addr[4]);

/**
 * Creates a string containing the textual representation of
 * a security context.
 * @param policydb Reference to a policy.
 * @param context Reference to the security context to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
char *re_render_security_context2(apol_policy_t *policydb, qpol_context_t *context);

/**
 * Creates a string containing the textual representation of
 * a portcon type.
 * @param policydb Reference to a policy.
 * @param portcon Reference to the portcon statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
char *re_render_portcon2(apol_policy_t *policydb, qpol_portcon_t *portcon);

/**
 * Creates a string containing the textual representation of
 * a netifcon type.
 * @param policydb Reference to a policy.
 * @param netifcon Reference to the netifcon statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
char *re_render_netifcon2(apol_policy_t *policydb, qpol_netifcon_t *netifcon);

/**
 * Creates a string containing the textual representation of
 * a nodecon type.
 * @param policydb Reference to a policy.
 * @param nodecon Reference to the nodecon statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
char *re_render_nodecon2(apol_policy_t *policydb, qpol_nodecon_t *nodecon);

/**
 * Creates a string containing the textual representation of
 * a genfscon type.
 * @param policydb Reference to a policy.
 * @param genfscon Reference to the genfscon statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
char *re_render_genfscon2(apol_policy_t *policydb, qpol_genfscon_t *genfscon);

/**
 * Creates a string containing the textual representation of
 * a fs_use type.
 * @param policydb Reference to a policy.
 * @param fsuse Reference to the fs_use statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
char *re_render_fs_use2(apol_policy_t *policydb, qpol_fs_use_t *fsuse);

#endif /*_APOLICY_RENDER_H_*/
