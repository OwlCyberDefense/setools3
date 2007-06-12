/**
 *  @file
 *  Public interface for a single AVC log message.  This is a subclass
 *  of seaudit_message.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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

#ifndef SEAUDIT_AVC_MESSAGE_H
#define SEAUDIT_AVC_MESSAGE_H

#include <apol/vector.h>

#ifdef  __cplusplus
extern "C"
{
#endif

	typedef struct seaudit_avc_message seaudit_avc_message_t;

/**
 * AVC messages may be either a granted (i.e., an allow) or a denied.
 */
	typedef enum seaudit_avc_message_type
	{
		SEAUDIT_AVC_UNKNOWN = 0,
		SEAUDIT_AVC_DENIED,
		SEAUDIT_AVC_GRANTED
	} seaudit_avc_message_type_e;

/**
 * Return the type of avc message this is, either a granted (i.e., an
 * allow) or a denied.
 *
 * @param avc AVC message to check.
 *
 * @return One of SEAUDIT_AVC_DENIED or SEAUDIT_AVC_GRANTED, or
 * SEAUDIT_AVC_UNKNOWN upon error or if unknown.
 */
	extern seaudit_avc_message_type_e seaudit_avc_message_get_message_type(const seaudit_avc_message_t * avc);

/**
 * Return the avc message's timestamp, measured in nanoseconds.
 *
 * @param avc AVC message to check.
 *
 * @return Timestamp, in nanoseconds, or 0 upon error or if unknown.
 */
	extern long seaudit_avc_message_get_timestamp_nano(const seaudit_avc_message_t * avc);

/**
 * Return the source context's user of an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Source user, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_source_user(const seaudit_avc_message_t * avc);

/**
 * Return the source context's role of an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Source role, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_source_role(const seaudit_avc_message_t * avc);

/**
 * Return the source context's target of an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Source target, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_source_type(const seaudit_avc_message_t * avc);

/**
 * Return the target context's user of an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Target user, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_target_user(const seaudit_avc_message_t * avc);

/**
 * Return the target context's role of an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Target role, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_target_role(const seaudit_avc_message_t * avc);

/**
 * Return the target context's target of an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Target type, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_target_type(const seaudit_avc_message_t * avc);

/**
 * Return the object class from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Object class, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_object_class(const seaudit_avc_message_t * avc);

/**
 * Return a vector of permissions (type char *) from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Vector of permission strings, or NULL upon error or if
 * unknown.  Do not modify the vector in any way.
 */
	extern const apol_vector_t *seaudit_avc_message_get_perm(const seaudit_avc_message_t * avc);

/**
 * Return the executable and path from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Executable string, or NULL upon error or if unknown.  Do
 * not free() this string.
 */
	extern const char *seaudit_avc_message_get_exe(const seaudit_avc_message_t * avc);

/**
 * Return the command from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Command, or NULL upon error or if unknown.  Do not free()
 * this string.
 */
	extern const char *seaudit_avc_message_get_comm(const seaudit_avc_message_t * avc);

/**
 * Return the name from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Name, or NULL upon error or if unknown.  Do not free() this
 * string.
 */
	extern const char *seaudit_avc_message_get_name(const seaudit_avc_message_t * avc);

/**
 * Return the process ID from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Process's PID, or 0 upon error or if unknown.
 */
	extern unsigned int seaudit_avc_message_get_pid(const seaudit_avc_message_t * avc);

/**
 * Return the inode from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Process's PID, or 0 upon error or if unknown.
 */
	extern unsigned long seaudit_avc_message_get_inode(const seaudit_avc_message_t * avc);

/**
 * Return the path of the object from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Object's path, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_path(const seaudit_avc_message_t * avc);

/**
 * Return the device for the object from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Object's device, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_dev(const seaudit_avc_message_t * avc);

/**
 * Return the network interface for the object from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Network interface, or NULL upon error or if unknown.  Do
 * not free() this string.
 */
	extern const char *seaudit_avc_message_get_netif(const seaudit_avc_message_t * avc);

/**
 * Return the local address from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Local address, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_laddr(const seaudit_avc_message_t * avc);

/**
 * Return the local port from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Local port, or 0 upon error or if unknown.
 */
	extern int seaudit_avc_message_get_lport(const seaudit_avc_message_t * avc);

/**
 * Return the foreign address from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Foreign address, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_faddr(const seaudit_avc_message_t * avc);

/**
 * Return the foreign port from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Foreign port, or 0 upon error or if unknown.
 */
	extern int seaudit_avc_message_get_fport(const seaudit_avc_message_t * avc);

/**
 * Return the source address from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Source address, or NULL upon error or if unknown.  Do not
 * free() this string.
 */
	extern const char *seaudit_avc_message_get_saddr(const seaudit_avc_message_t * avc);

/**
 * Return the source port from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Source port, or 0 upon error or if unknown.
 */
	extern int seaudit_avc_message_get_sport(const seaudit_avc_message_t * avc);

/**
 * Return the destination address from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Destination address, or NULL upon error or if unknown.  Do
 * not free() this string.
 */
	extern const char *seaudit_avc_message_get_daddr(const seaudit_avc_message_t * avc);

/**
 * Return the destination port from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Destination port, or 0 upon error or if unknown.
 */
	extern int seaudit_avc_message_get_dport(const seaudit_avc_message_t * avc);

/**
 * Return the IPC key from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Key, or -1 upon error or if unknown.
 */
	extern int seaudit_avc_message_get_key(const seaudit_avc_message_t * avc);

/**
 * Return the process capability from an avc message.
 *
 * @param avc AVC message to check.
 *
 * @return Capability, or -1 upon error or if unknown.
 */
	extern int seaudit_avc_message_get_cap(const seaudit_avc_message_t * avc);

#ifdef  __cplusplus
}
#endif

#endif
