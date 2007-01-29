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
	extern seaudit_sort_t *seaudit_sort_by_message_type(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_date(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_host(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_permission(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_source_user(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_source_role(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_source_type(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_target_user(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_target_role(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_target_type(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_object_class(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_executable(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_command(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_path(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_device(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_inode(int direction);

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
	extern seaudit_sort_t *seaudit_sort_by_pid(int direction);

#ifdef  __cplusplus
}
#endif

#endif
