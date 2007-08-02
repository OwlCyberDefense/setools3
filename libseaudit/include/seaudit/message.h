/**
 *  @file
 *  Public interface for a single seaudit log message.  Note that this
 *  is an abstract class.
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

#ifndef SEAUDIT_MESSAGE_H
#define SEAUDIT_MESSAGE_H

#ifdef  __cplusplus
extern "C"
{
#endif

#include <time.h>

	typedef struct seaudit_message seaudit_message_t;

/**
 * This enum defines the different types of audit messages this
 * library will handle.  Message types are put in alphabetical order
 * to make msg_field_compare() in sort.c easier.
 */
	typedef enum seaudit_message_type
	{
		SEAUDIT_MESSAGE_TYPE_INVALID = 0,
		/** BOOL is the message that results when changing
		    booleans in a conditional policy. */
		SEAUDIT_MESSAGE_TYPE_BOOL,
		/** AVC is a standard 'allowed' or 'denied' type
		    message. */
		SEAUDIT_MESSAGE_TYPE_AVC,
		/** LOAD is the message that results when a policy is
		    loaded into the system. */
		SEAUDIT_MESSAGE_TYPE_LOAD
	} seaudit_message_type_e;

/**
 * Get a pointer to a message's specific data.  This returns a void
 * pointer; the caller must cast it to one of seaudit_avc_message_t,
 * seaudit_bool_message_t, or seaudit_load_message_t.  Use the
 * returned value from the second parameter to determine which type
 * this message really is.
 *
 * @param msg Message from which to get data.
 * @param type Reference to the message specific type.
 *
 * @return Pointer to message's specific type, or NULL upon error.
 */
	extern void *seaudit_message_get_data(const seaudit_message_t * msg, seaudit_message_type_e * type);

/**
 * Return the time that this audit message was generated.
 *
 * @param msg Message from which to get its time.
 *
 * @return Time of the message.  Treat the contents of this struct as
 * const.
 *
 * @see localtime(3)
 */
	extern const struct tm *seaudit_message_get_time(const seaudit_message_t * msg);

/**
 * Return the name of the host that generated this audit message.
 *
 * @param msg Message from which to get its time.
 *
 * @return Host of the message.  Do not modify this string.
 */
	extern const char *seaudit_message_get_host(const seaudit_message_t * msg);

/**
 * Given a message, allocate and return a string that approximates the
 * message as it had appeared within the original log file.
 *
 * @param msg Message to convert.
 *
 * @return String representation for message, or NULL upon error.  The
 * caller is responsible for free()ing the string afterwards.
 */
	extern char *seaudit_message_to_string(const seaudit_message_t * msg);

/**
 * Given a message, allocate and return a string, formatted in HTML,
 * that approximates the message as it had appeared within the
 * original log file.
 *
 * @param msg Message to convert.
 *
 * @return HTML String representation for message, or NULL upon error.
 * The caller is responsible for free()ing the string afterwards.
 */
	extern char *seaudit_message_to_string_html(const seaudit_message_t * msg);

/**
 * Given a message, allocate and return a string that gives
 * miscellaneous (i.e., uncategorized) information about the message.
 * To get the more important values you will need to use more specific
 * accessor methods.
 *
 * @param msg Message from which to get miscellaneous information.
 *
 * @return Miscellaneous message string representation, or NULL upon
 * error.  The caller is responsible for free()ing the string
 * afterwards.
 */
	extern char *seaudit_message_to_misc_string(const seaudit_message_t * msg);

#ifdef  __cplusplus
}
#endif

#endif
