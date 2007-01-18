/**
 *  @file
 *  Public interface to a seaudit_filter_t.  A filter is used to
 *  modify the list of messages returned from a seaudit_model_t.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#ifndef SEAUDIT_FILTER_H
#define SEAUDIT_FILTER_H

#ifdef  __cplusplus
extern "C"
{
#endif

#include <seaudit/avc_message.h>

#include <apol/vector.h>
#include <stdio.h>
#include <time.h>

	typedef struct seaudit_filter seaudit_filter_t;

/**
 * By default, all criteria of a filter must be met for a message to
 * be accepted.  This behavior can be changed such that a message is
 * accepted if any of the criteria pass.
 */
	typedef enum seaudit_filter_match
	{
		SEAUDIT_FILTER_MATCH_ALL = 0,
		SEAUDIT_FILTER_MATCH_ANY
	} seaudit_filter_match_e;

/**
 * By default, only messages accepted by filters will be shown by the
 * model.  This behavior can be changed such that filters are used to
 * select messages to hide.
 */
	typedef enum seaudit_filter_visible
	{
		SEAUDIT_FILTER_VISIBLE_SHOW = 0,
		SEAUDIT_FILTER_VISIBLE_HIDE
	} seaudit_filter_visible_e;

/**
 * When specifying a date/time for the filter, one must also give how
 * to match the date and time.
 */
	typedef enum seaudit_filter_date_match
	{
		SEAUDIT_FILTER_DATE_MATCH_BEFORE = 0,
		SEAUDIT_FILTER_DATE_MATCH_AFTER,
		SEAUDIT_FILTER_DATE_MATCH_BETWEEN
	} seaudit_filter_date_match_e;

/**
 * Create a new filter object.  The default matching behavior is to
 * accept all messages.
 *
 * @param name Name for the filter; the string will be duplicated.  If
 * NULL then the filter will be assigned a default name.
 *
 * @return A newly allocated filter.  The caller is responsible for
 * calling seaudit_filter_destroy() afterwards.
 */
	extern seaudit_filter_t *seaudit_filter_create(const char *name);

/**
 * Create a new filter object, initialized with the data from an
 * existing filter.  This will do a deep copy of the original filter.
 * The new filter will not be attached to any model.
 *
 * @param filter Filter to clone.
 *
 * @return A cloned filter, or NULL upon error.  The caller is
 * responsible for calling seaudit_filter_destroy() afterwards.
 */
	extern seaudit_filter_t *seaudit_filter_create_from_filter(const seaudit_filter_t * filter);

/**
 * Create and return a vector of filters (type seaudit_filter_t),
 * initialized from the contents of a XML configuration file.
 *
 * @param filename File containing one or more filter data.
 *
 * @return Vector of filters created from that file, or NULL upon
 * error.  The caller is responsible for apol_vector_destroy(),
 * passing seaudit_filter_destroy() as the second parameter.
 *
 * @see seaudit_filter_save_to_file()
 */
	extern apol_vector_t *seaudit_filter_create_from_file(const char *filename);

/**
 * Destroy the referenced seaudit_filter_t object.
 *
 * @param filter Filter object to destroy.  The pointer will be set to
 * NULL afterwards.  (If pointer is already NULL then do nothing.)
 */
	extern void seaudit_filter_destroy(seaudit_filter_t ** filter);

/**
 * Save to disk, in XML format, the given filter's values.  This
 * includes the filter's criteria.
 *
 * @param filter Filter to save.
 * @param filename Name of the file to write.  If the file already
 * exists it will be overwritten.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see seaudit_filter_create_from_file()
 */
	extern int seaudit_filter_save_to_file(seaudit_filter_t * filter, const char *filename);

/**
 * Set a filter to accept a message if all criteria are met (default
 * behavior) or if any criterion is met.
 *
 * @param filter Filter to modify.
 * @param match Matching behavior if filter has multiple criteria.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_match(seaudit_filter_t * filter, seaudit_filter_match_e match);

/**
 * Get the current match value for a filter.
 *
 * @param filter Filter containing match value.
 *
 * @return One of SEAUDIT_FILTER_MATCH_ALL or SEAUDIT_FILTER_MATCH_ANY.
 */
	extern seaudit_filter_match_e seaudit_filter_get_match(seaudit_filter_t * filter);

/**
 * Set the name of this filter, overwriting any previous name.
 *
 * @param filter Filter to modify.
 * @param name New name for this filter.  This function will duplicate
 * the string.  If this is NULL then clear the existing name.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_name(seaudit_filter_t * filter, const char *name);

/**
 * Get the name of this filter.
 *
 * @param filter Filter from which to get name.
 *
 * @return Name of the filter, or NULL if no name has been set.  Do
 * not free() or otherwise modify this string.
 */
	extern char *seaudit_filter_get_name(seaudit_filter_t * filter);

/**
 * Set the description of this filter, overwriting any previous
 * description.
 *
 * @param filter Filter to modify.
 * @param desc New description for this filter.  This function will
 * duplicate the string.  If this is NULL then clear the existing
 * description.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_description(seaudit_filter_t * filter, const char *desc);

/**
 * Get the description of this filter.
 *
 * @param filter Filter from which to get description.
 *
 * @return Description of the filter, or NULL if no description has
 * been set.  Do not free() or otherwise modify this string.
 */
	extern char *seaudit_filter_get_description(seaudit_filter_t * filter);

/**
 * Set the list of source users.  A message is accepted if its source
 * user is within this list.  The filter will duplicate the vector and
 * the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of strings, or NULL to clear current settings.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_source_user(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of source users for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
	extern apol_vector_t *seaudit_filter_get_source_user(seaudit_filter_t * filter);

/**
 * Set the list of source roles.  A message is accepted if its source
 * role is within this list.  The filter will duplicate the vector and
 * the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of strings, or NULL to clear current settings.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_source_role(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of source roles for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
	extern apol_vector_t *seaudit_filter_get_source_role(seaudit_filter_t * filter);

/**
 * Set the list of source types.  A message is accepted if its source
 * type is within this list.  The filter will duplicate the vector and
 * the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of strings, or NULL to clear current settings.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_source_type(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of source types for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
	extern apol_vector_t *seaudit_filter_get_source_type(seaudit_filter_t * filter);

/**
 * Set the list of target users.  A message is accepted if its target
 * user is within this list.  The filter will duplicate the vector and
 * the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of strings, or NULL to clear current settings.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_target_user(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of target users for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
	extern apol_vector_t *seaudit_filter_get_target_user(seaudit_filter_t * filter);

/**
 * Set the list of target roles.  A message is accepted if its target
 * role is within this list.  The filter will duplicate the vector and
 * the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of strings, or NULL to clear current settings.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_target_role(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of target roles for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
	extern apol_vector_t *seaudit_filter_get_target_role(seaudit_filter_t * filter);

/**
 * Set the list of target types.  A message is accepted if its target
 * type is within this list.  The filter will duplicate the vector and
 * the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of strings, or NULL to clear current settings.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_target_type(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of target types for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
	extern apol_vector_t *seaudit_filter_get_target_type(seaudit_filter_t * filter);

/**
 * Set the list of target object classes.  A message is accepted if
 * its target class is within this list.  The filter will duplicate
 * the vector and the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of strings, or NULL to clear current settings.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_target_class(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of target object classes for a filter.
 * This will be a vector of strings.  Treat the vector and its
 * contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
	extern apol_vector_t *seaudit_filter_get_target_class(seaudit_filter_t * filter);

/**
 * Set the executable criterion, as a glob expression.  A message is
 * accepted if its executable matches this expression.
 *
 * @param filter Filter to modify.
 * @param exe Glob expression for executable.  This function will
 * duplicate the string.  If this is NULL then clear the existing
 * executable.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_executable(seaudit_filter_t * filter, const char *exe);

/**
 * Return the current executable for a filter.  Treat this string as
 * const.
 *
 * @param filter Filter to get value.
 *
 * @return Glob expression for executable, or NULL if none set.
 */
	extern char *seaudit_filter_get_executable(seaudit_filter_t * filter);

/**
 * Set the host criterion, as a glob expression.  A message is
 * accepted if its host matches this expression.
 *
 * @param filter Filter to modify.
 * @param host Glob expression for host.  This function will duplicate
 * the string.  If this is NULL then clear the existing host.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_host(seaudit_filter_t * filter, const char *host);

/**
 * Return the current host for a filter.  Treat this string as const.
 *
 * @param filter Filter to get value.
 *
 * @return Glob expression for host, or NULL if none set.
 */
	extern char *seaudit_filter_get_host(seaudit_filter_t * filter);

/**
 * Set the path criterion, as a glob expression.  A message is
 * accepted if its path matches this expression.
 *
 * @param filter Filter to modify.
 * @param path Glob expression for path.  This function will duplicate
 * the string.  If this is NULL then clear the existing path.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_path(seaudit_filter_t * filter, const char *path);

/**
 * Return the current path for a filter.  Treat this string as const.
 *
 * @param filter Filter to get value.
 *
 * @return Glob expression for path, or NULL if none set.
 */
	extern char *seaudit_filter_get_path(seaudit_filter_t * filter);

/**
 * Set the command criterion, as a glob expression.  A message is
 * accepted if its command matches this expression.
 *
 * @param filter Filter to modify.
 * @param command Glob expression for command.  This function will
 * duplicate the string.  If this is NULL then clear the existing
 * command.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_command(seaudit_filter_t * filter, const char *command);

/**
 * Return the current command for a filter.  Treat this string as const.
 *
 * @param filter Filter to get value.
 *
 * @return Glob expression for command, or NULL if none set.
 */
	extern char *seaudit_filter_get_command(seaudit_filter_t * filter);

/**
 * Set the IP address criterion, as a glob expression.  A message is
 * accepted if any of its IP addresses (saddr, daddr, faddr, or laddr)
 * matches this expression.
 *
 * @param filter Filter to modify.
 * @param ipaddr Glob expression for IP address.  This function will
 * duplicate the string.  If this is NULL then clear the existing
 * address.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_ipaddress(seaudit_filter_t * filter, const char *ipaddr);

/**
 * Return the current IP address for a filter.  Treat this string as
 * const.
 *
 * @param filter Filter to get value.
 *
 * @return Glob expression for address, or NULL if none set.
 */
	extern char *seaudit_filter_get_ipaddress(seaudit_filter_t * filter);

/**
 * Set the port criterion.  A message is accepted if any of its ports
 * (port, source, dest, fport, or lport) matches this port.
 *
 * @param filter Filter to modify.
 * @param port Port criterion.  If this is zero or negative then clear
 * the existing port.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_port(seaudit_filter_t * filter, const int port);

/**
 * Return the current port for a filter.
 *
 * @param filter Filter to get value.
 *
 * @return Current port criterion, or 0 if none set.
 */
	extern int seaudit_filter_get_port(seaudit_filter_t * filter);

/**
 * Set the network interface criterion.  A message is accepted if its
 * interface matches exactly with this string.
 *
 * @param filter Filter to modify.
 * @param netif Network interface criterion.  This function will
 * duplicate the string.  If this is NULL then clear the existing
 * criterion.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_netif(seaudit_filter_t * filter, const char *netif);

/**
 * Return the current network interface for a filter.  Treat this
 * string as const.
 *
 * @param filter Filter to get value.
 *
 * @return String for netif, or NULL if none set.
 */
	extern char *seaudit_filter_get_netif(seaudit_filter_t * filter);

/**
 * Set the type of AVC criterion.  A message is accepted if it matches
 * this value exactly.  If the message type is not SEAUDIT_AVC_UNKNOWN
 * and the message is not an AVC then it will be rejected.
 *
 * @param filter Filter to modify.
 * @param message_type One of SEAUDIT_AVC_DENIED, SEAUDIT_AVC_GRANTED,
 * SEAUDIT_AVC_UNKNOWN.  If SEAUDIT_AVC_UNKNOWN then unset this
 * criterion.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_message_type(seaudit_filter_t * filter, const seaudit_avc_message_type_e message_type);

/**
 * Return the current message type for a filter.
 *
 * @param filter Filter to get value.
 *
 * @return Type of AVC message to filter, or SEAUDIT_AVC_UNKNOWN if
 * none set.
 */
	extern seaudit_avc_message_type_e seaudit_filter_get_message_type(seaudit_filter_t * filter);

/**
 * Set the date/time criterion.  A message is accepted if its
 * date/time falls within the allowable range.
 *
 * @param filter Filter to modify.
 * @param start Starting time.  This structure will be duplicated.  If
 * NULL, then do not filter by dates.
 * @param end Ending time.  This structure will be duplicated.  It
 * will be ignored (and hence may be NULL) if date_match is not
 * SEAUDIT_FILTER_DATE_MATCH_BETWEEN.
 * @param date_match How to match dates, either ones falling before
 * start, ones falling after start, or ones between start and end.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_filter_set_date(seaudit_filter_t * filter, const struct tm *start, const struct tm *end,
					   seaudit_filter_date_match_e match);

/**
 * Return the current date/time for a filter.  Note that if no
 * date/time has been set then both reference pointers will be set to
 * NULL (match will be set to an invalid value).
 *
 * @param filter Filter to get value.
 * @param start Pointer to location to store starting time.  Do not
 * free() or otherwise modify this pointer.
 * @param end Pointer to location to store ending time.  Do not free()
 * or otherwise modify this pointer.  If match is not
 * SEAUDIT_FILTER_DATE_MATCH_BETWEEN then the contents of this
 * structure are invalid.
 * @param date_match Pointer to location to set date matching option.
 */
	extern void seaudit_filter_get_date(seaudit_filter_t * filter, struct tm **start, struct tm **end,
					    seaudit_filter_date_match_e * match);

#ifdef  __cplusplus
}
#endif

#endif
