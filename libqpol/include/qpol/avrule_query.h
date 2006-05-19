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
 *  @param rule_type_mask Bitwise or'ed set of SEPOL_RULE_* values.
 *  It is an error to specify any of SEPOL_RULE_TYPE_* in the mask.
 *  @param iter Iterator over items of type sepol_av_rule_datum_t returned.
 *  The caller is responsible for calling sepol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
extern int qpol_get_avrule_iter(sepol_handle_t *handle, qpol_policy_t *policy, uint32_t rule_type_mask, qpol_iterator_t **iter);

#endif 
