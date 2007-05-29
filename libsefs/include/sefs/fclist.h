/**
 *  @file
 *  Defines the public interface for the file context list abstract object.
 *  A user must call a constructor for one of sefs_fcfile_t, sefs_db_t, or
 *  sefs_filesystem_t to create a sefs_fclist_t object.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#ifndef SEFS_FCLIST_H
#define SEFS_FCLIST_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <stdarg.h>
#include <stdbool.h>

#include <apol/policy.h>

	typedef struct sefs_fclist sefs_fclist_t;

	typedef void (*sefs_callback_fn_t) (void *varg, sefs_fclist_t * fclist, int level, const char *fmt, va_list argp);

/**
 * Possible types of fclist for use with sefs_fclist_get_data().
 */
	typedef enum sefs_fclist_type
	{
		SEFS_FCLIST_TYPE_NONE = 0,	/*!< Not an actual type, used for error conditions */
		SEFS_FCLIST_TYPE_FILESYSTEM,	/*!< get_data returns sefs_filesystem_t, a representation of a file system */
		SEFS_FCLIST_TYPE_FCFILE,	/*!< get_data returns sefs_fcfile_t, a representation of a collection of file_context files */
		SEFS_FCLIST_TYPE_DB    /*!< get_data returns sefs_db_t, a representation of a database of file system contexts */
	} sefs_fclist_type_e;

/**
 * Deallocate all memory associated with the referenced fclist object,
 * and then set it to NULL.  This function does nothing if the fclist
 * object is already NULL.
 * @param Reference to a fclist object to destroy.
 */
	void sefs_fclist_destroy(sefs_fclist_t ** fclist);

/**
 * Get the type of fclist object represented by \a fclist.
 * @param fclist Fclist object from which to get the type.
 * @return The type of fclist object or SEFS_FCLIST_TYPE_NONE on error.
 */
	sefs_fclist_type_e sefs_fclist_get_type(sefs_fclist_t * fclist);

/**
 * Get a pointer to the data specific to the type of fclist object as
 * returned by sefs_fclist_get_type().
 * @param fclist Fclist object from which to get the representation
 * specific data.
 * @return A pointer to the representation specific data, or NULL on error.
 */
	void *sefs_fclist_get_data(sefs_fclist_t * fclist);

/**
 * Determine if the contexts in the fclist contain MLS fields.
 * @param fclist Fclist object to test for MLS.
 * @return \a true if MLS fields are present and \a false otherwise
 */
	bool sefs_fclist_get_is_mls(sefs_fclist_t * fclist);

/**
 * Associate a policy with the fclist.  This is needed to resolve
 * attributes and MLS ranges in queries.  If a policy is already
 * associated, then calling this function removes that previous
 * association.
 * @param fclist Fclist with which to associate the policy.
 * @param policy Policy to associate with \a fclist. If NULL,
 * remove any policy association. While \a policy is associated
 * with \a fclist the caller should not destroy \a policy.
 * @see sefs_query_set_type()
 * @see sefs_query_set_range()
 */
	void sefs_fclist_associate_policy(sefs_fclist_t * fclist, apol_policy_t * policy);

#define SEFS_MSG_ERR  1		       /*!< Message describes a fatal error. */
#define SEFS_MSG_WARN 2		       /*!< Message is issued as a warning but does not represent a fatal error. */
#define SEFS_MSG_INFO 3		       /*!< Message is issued for inormational reasons and does not represent an atypical state. */

/**
 * Write a message to the callback stored within a fclist error handler.
 * If the msg_callback field is empty, then the default message callback
 * will be used.
 * @param fclist Error reporting handler. If NULL, then write message to
 * stderr.
 * @param level Severity of message, one of SEFS_MSG_*.
 * @param fmt Format string to print, using syntax of printf(3).
 */
	void sefs_handle_msg(sefs_fclist_t * fclist, int level, const char *fmt, ...);

	__attribute__ ((format(printf, 3, 4)))
	void sefs_handle_msg(sefs_fclist_t * fclist, int level, const char *fmt, ...);

//TODO: move protected functions below to internal header

/**
 * Invoke a sefs_fclist_t's callback for an error, passing it a format string
 * and arguments.
 */
#define ERR(f, format, ...) sefs_handle_msg(f, format, __VA_ARGS__)

/**
 * Invoke a sefs_fclist_t's callback for a warning, passing it a format string
 * and arguments.
 */
#define WARN(f, format, ...) sefs_handle_msg(f, format, __VA_ARGS__)

/**
 * Invoke a sefs_fclist's callback for an informational message,
 * passing it a format string and arguments.
 */
#define INFO(f, format, ...) sefs_handle_msg(f, format, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_FCLIST_H */
