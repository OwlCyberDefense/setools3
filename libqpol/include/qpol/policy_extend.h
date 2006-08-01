/**
 *  @file policy-extend.h
 *  Public interface for loading and using an extended
 *  policy image. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#ifndef QPOL_POLICY_EXTEND_H
#define QPOL_POLICY_EXTEND_H

#include <qpol/policy.h>
#include <qpol/iterator.h>

typedef struct qpol_extended_image qpol_extended_image_t;

/**
 *  Create an extended image for a policy. This function modifies the policydb
 *  by adding additional records and information about attributes, initial sids
 *  and other components not normally written to a binary policy file.
 *  @param handle Error handler for the policydb.
 *  @param policy The policy for which the extended image should be created.
 *  @return Returns 0 on success and < 0 on failure. If the call fails,
 *  errno will be set; the state of the policy is not guaranteed to be stable
 *  if this call fails.
 */
extern int qpol_policy_extend(qpol_handle_t *handle, qpol_policy_t *policy);

extern void qpol_extended_image_destroy(qpol_extended_image_t **ext);

/* forward declarations: see avrule_query.h and terule_query.h */
struct qpol_avrule;
struct qpol_terule;

extern int qpol_avrule_get_syn_avrule_iter(qpol_handle_t *handle, qpol_policy_t *policy, struct qpol_avrule *rule, qpol_iterator_t **iter);
extern int qpol_terule_get_syn_terule_iter(qpol_handle_t *handle, qpol_policy_t *policy, struct qpol_terule *rule, qpol_iterator_t **iter);

#endif /* QPOL_POLICY_EXTEND_H */

