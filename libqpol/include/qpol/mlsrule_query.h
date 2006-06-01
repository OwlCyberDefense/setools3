/**
 *  @file mlsrule_query.h
 *  Defines the public interface for searching and iterating over 
 *  range transition rules. 
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

#ifndef QPOL_MLSRULE_QUERY_H
#define QPOL_MLSRULE_QUERY_H

#include <qpol/policy.h>
#include <qpol/policy_query.h>

typedef struct qpol_range_trans qpol_range_trans_t;

/**
 *  Get an iterator over all range transition rules in a policy.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which to get the av rules.
 *  @param iter Iterator over items of type qpol_range_trans_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
extern int qpol_policy_get_range_trans_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter);

/**
 *  Get the source type from a range transition rule.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the source type.
 *  @param source Pointer in which to store the source type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source will be NULL.
 */
extern int qpol_range_trans_get_source_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_range_trans_t *rule, qpol_type_t **source);

/**
 *  Get the target type from a range transition rule.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the target type.
 *  @param target Pointer in which to store the target type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target will be NULL.
 */
extern int qpol_range_trans_get_target_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_range_trans_t *rule, qpol_type_t **target);

/**
 *  Get the range from a range transition rule.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the range.
 *  @param range Pointer in which to store the range.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *range will be NULL.
 */
extern int qpol_range_trans_get_range(qpol_handle_t *handle, qpol_policy_t *policy, qpol_range_trans_t *rule, qpol_mls_range_t **range);

#endif /* QPOL_MLSRULE_QUERY_H */
