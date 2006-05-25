 /**
 *  @file avrule_query.h
 *  Defines the public interface for searching and iterating over avrules. 
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

#ifndef QPOL_AVRULE_QUERRY_H
#define QPOL_AVRULE_QUERRY_H

#include <qpol/policy.h>

typedef struct qpol_avrule qpol_avrule_t;

/* rule type defines (values copied from "sepol/policydb/policydb.h") */
#define QPOL_RULE_ALLOW         1
#define QPOL_RULE_NEVERALLOW  128
#define QPOL_RULE_AUDITALLOW    2
#define QPOL_RULE_DONTAUDIT     8
#define QPOL_RULE_TYPE_TRANS   16
#define QPOL_RULE_TYPE_CHANGE  64
#define QPOL_RULE_TYPE_MEMBER  32

/**
 *  Get an iterator over all av rules in a policy of a rule type
 *  in rule_type_mask.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which to get the av rules.
 *  @param rule_type_mask Bitwise or'ed set of QPOL_RULE_* values.
 *  It is an error to specify any of QPOL_RULE_TYPE_* in the mask.
 *  @param iter Iterator over items of type qpol_avrule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
extern int qpol_get_avrule_iter(qpol_handle_t *handle, qpol_policy_t *policy, uint32_t rule_type_mask, qpol_iterator_t **iter);

/**
 *  Get the source type from an av rule.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the source type.
 *  @param source Pointer in which to store the source type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source will be NULL.
 */
extern int qpol_avrule_get_source_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, qpol_type_t **source);

/**
 *  Get the target type from an av rule.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the target type.
 *  @param target Pointer in which to store the target type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target will be NULL.
 */
extern int qpol_avrule_get_target_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, qpol_type_t **target);

/**
 *  Get the object class from an av rule.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the object class.
 *  @param obj_class Pointer in which to store the object class.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *obj_class will be NULL.
 */
extern int qpol_avrule_get_object_class(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, qpol_class_t **obj_class);

/**
 *  Get an iterator over the permissions in an av rule.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the permissions.
 *  @param perms Iterator over items of type char* returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *perms will be NULL.
 */
extern int qpol_avrule_get_perm_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, qpol_iterator_t **perms);

/**
 *  Get the rule type value for an av rule.
 *  @param handle Error handler for the policy database.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the rule type.
 *  @param rule_type Integer in which to store the rule type value.
 *  The value will be one of the QPOL_RULE_* values above.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *rule_type will be 0.
 */
extern int qpol_avrule_get_rule_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, uint32_t *rule_type);

#endif 
