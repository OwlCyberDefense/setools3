/**
 *  @file
 *
 *  Public interface to a seaudit_sort.  This represents an abstract
 *  object that specifies how to sort messages within a particular
 *  seaudit_model.  The caller obtains a specific sort object and
 *  appends it to a model via seaudit_model_append_sort(); the caller
 *  cannot get a "generic" sort object.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#ifndef SEAUDIT_SORT_H
#define SEAUDIT_SORT_H

#ifdef  __cplusplus
extern "C"
{
#endif

	typedef struct seaudit_sort seaudit_sort_t;

/**
 * Create a new sort object, initialized with the data from an
 * existing sort.  The new sort will not be attached to any model.
 *
 * @param sort Sort to clone.
 *
 * @return A cloned sort object, or NULL upon error.  The caller is
 * responsible for calling seaudit_sort_destroy() afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_create_from_sort(const seaudit_sort_t * sort);

/**
 * Destroy the referenced seaudit_sort object.
 *
 * @param sort Sort object to destroy.  The pointer will be set to
 * NULL afterwards.  (If pointer is already NULL then do nothing.)
 */
	extern void seaudit_sort_destroy(seaudit_sort_t ** sort);

/**
 * Instruct a model to sort messages by message type: boolean changes,
 * then avc denies, then avc allows, then policy load messages.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_message_type(const int direction);

/**
 * Instruct a model to sort messages by chronological order.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_date(const int direction);

/**
 * Instruct a model to sort messages by host name, alphabetically.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_host(const int direction);

/**
 * Instruct a model to sort AVC messages by permissions,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_permission(const int direction);

/**
 * Instruct a model to sort AVC messages by source context's user,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_source_user(const int direction);

/**
 * Instruct a model to sort AVC messages by source context's role,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_source_role(const int direction);

/**
 * Instruct a model to sort AVC messages by source context's type,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_source_type(const int direction);

/**
 * Instruct a model to sort AVC messages by target context's user,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_target_user(const int direction);

/**
 * Instruct a model to sort AVC messages by target context's role,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_target_role(const int direction);

/**
 * Instruct a model to sort AVC messages by target context's type,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_target_type(const int direction);

/**
 * Instruct a model to sort AVC messages by object class,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_object_class(const int direction);

/**
 * Instruct a model to sort AVC messages by the executable,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_executable(const int direction);

/**
 * Instruct a model to sort AVC messages by the command,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_command(const int direction);

/**
 * Instruct a model to sort AVC messages by the name, alphabetically.
 * Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_name(const int direction);

/**
 * Instruct a model to sort AVC messages by the path, alphabetically.
 * Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_path(const int direction);

/**
 * Instruct a model to sort AVC messages by the device, alphabetically.
 * Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_device(const int direction);

/**
 * Instruct a model to sort AVC messages by the object's inode.
 * Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_inode(const int direction);

/**
 * Instruct a model to sort AVC messages by the process ID.  Non-AVC
 * messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_pid(const int direction);

/**
 * Instruct a model to sort AVC messages by the port number.  Non-AVC
 * messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_port(const int direction);

/**
 * Instruct a model to sort AVC messages by local address,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_laddr(const int direction);

/**
 * Instruct a model to sort AVC messages by the local port number.
 * Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_lport(const int direction);

/**
 * Instruct a model to sort AVC messages by foreign address,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_faddr(const int direction);

/**
 * Instruct a model to sort AVC messages by the foreign port number.
 * Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_fport(const int direction);

/**
 * Instruct a model to sort AVC messages by source address,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_saddr(const int direction);

/**
 * Instruct a model to sort AVC messages by the source port number.
 * Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_sport(const int direction);

/**
 * Instruct a model to sort AVC messages by destination address,
 * alphabetically.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_daddr(const int direction);

/**
 * Instruct a model to sort AVC messages by the destination port
 * number.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_dport(const int direction);

/**
 * Instruct a model to sort AVC messages by the IPC call's key.
 * Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_key(const int direction);

/**
 * Instruct a model to sort AVC messages by the process capability
 * value.  Non-AVC messages will be placed below AVC ones.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
	extern seaudit_sort_t *seaudit_sort_by_cap(const int direction);

#ifdef  __cplusplus
}
#endif

#endif
