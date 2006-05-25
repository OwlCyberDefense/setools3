/**
 *  @file nodecon_query.h
 *  Defines the public interface for searching and iterating over nodecon statements.
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

#ifndef QPOL_NODECON_QUERY_H
#define QPOL_NODECON_QUERY_H

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

#define QPOL_IPV4 0
#define QPOL_IPV6 1

typedef struct qpol_nodecon qpol_nodecon_t;

/**
 *  Get a single nodecon statement by address, mask and protocol.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy from which to get the nodecon statement.
 *  @param addr The IP address of the node, if IPv4 only addr[0] is used.
 *  @param mask The net mask of the node, if IPv4 only mask[0] is used.
 *  @param protocol The protocol used in the address and mask;
 *  set to QPOL_IPV4 for IPv4 and QPOL_IPV6 for IPv6.
 *  @param ocon Pointer in which to store the statement returned.
 *  The caller should call free() to free memory used by this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *ocon will be NULL.
 */
extern int qpol_policy_get_nodecon_by_node(qpol_handle_t *handle, qpol_policy_t *policy, uint32_t addr[4], uint32_t mask[4], unsigned char protocol, qpol_nodecon_t **ocon);

/**
 *  Get an iterator for the nodecon statements in a policy.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_nodecon_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy 
 *  to free memory used by this iterator. The caller must also call free()
 *  on items returned by qpol_iterator_get_item() when using this iterator.
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails, 
 *  errno will be set and *iter will be NULL.
 */
extern int qpol_policy_get_nodecon_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter);

/**
 *  Get the IP address from a nodecon statement. Sets protocol to indicate
 *  the number of integers used by the array.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy associated with the nodecon statement.
 *  @param ocon The nodecon statement from which to get the IP address.
 *  @param mask Pointer to be set to the byte array of the IP address;
 *  the caller should not free this pointer. The number of integers
 *  in this array is 1 if IPv4 and 4 if IPv6.
 *  @param protocol Pointer to be set to the protocol value; this
 *  will be set to QPOL_IPV4 for IPv4 and QPOL_IPV6 for IPv6.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set, addr will be NULL, and protocol will be 0.
 */
int qpol_nodecon_get_addr(qpol_handle_t *handle, qpol_policy_t *policy, qpol_nodecon_t *ocon, uint32_t **addr, unsigned char *protocol);

/**
 *  Get the net mask from a nodecon statement. Sets protocol to indicate
 *  the number of integers used by the array.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy associated with the nodecon statement.
 *  @param ocon The nodecon statement from which to get the net mask.
 *  @param mask Pointer to be set to the byte array of the net mask;
 *  the caller should not free this pointer. The number of integers
 *  in this array is 1 if IPv4 and 4 if IPv6.
 *  @param protocol Pointer to be set to the protocol value; this
 *  will be set to QPOL_IPV4 for IPv4 and QPOL_IPV6 for IPv6.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set, mask will be NULL, and protocol will be 0.
 */
int qpol_nodecon_get_mask(qpol_handle_t *handle, qpol_policy_t *policy, qpol_nodecon_t *ocon, uint32_t **mask, unsigned char *protocol);

/**
 *  Get the protocol from a nodecon statement.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy associated with the nodecon statement.
 *  @param ocon The nodecon statement from which to get the protocol.
 *  @param protocol Pointer to be set to the protocol value; this
 *  will be set to QPOL_IPV4 for IPv4 and QPOL_IPV6 for IPv6.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and protocol will be 0.
 */
int qpol_nodecon_get_protocol(qpol_handle_t *handle, qpol_policy_t *policy, qpol_nodecon_t *ocon, unsigned char *protocol);

/**
 *  Get the context from a nodecon statement.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy associated with the nodecon statement.
 *  @param ocon The nodecon statement from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
extern int qpol_nodecon_get_context(qpol_handle_t *handle, qpol_policy_t *policy, qpol_nodecon_t *ocon, qpol_context_t **context);

#endif /* QPOL_NODECON_QUERY_H */

