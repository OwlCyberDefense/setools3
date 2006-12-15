/**
 *  @file preferences.h
 *  Declaration of the current user's preferences for the seaudit
 *  application.
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

#ifndef PREFERENCES_H
#define PREFERENCES_H

#include <apol/policy-path.h>
#include <apol/vector.h>

typedef struct preferences preferences_t;

/* n.b.: OTHER_FIELD must be the last entry in this enumeration, for
   message_view stops processing after that token */
typedef enum preference_field
{
	HOST_FIELD, MESSAGE_FIELD, DATE_FIELD,
	SUSER_FIELD, SROLE_FIELD, STYPE_FIELD,
	TUSER_FIELD, TROLE_FIELD, TTYPE_FIELD,
	OBJCLASS_FIELD, PERM_FIELD,
	EXECUTABLE_FIELD, COMMAND_FIELD,
	PID_FIELD, INODE_FIELD, PATH_FIELD, OTHER_FIELD
} preference_field_e;

/**
 * Allocate and return a preferences object.  This function will first
 * initialize the object using the user's configuration file.  If that
 * is not readable then the system-wide configuration is attempted.
 * It is not an error if both files are not available.
 *
 * @return An initialized preferences object, or NULL upon error.  The
 * caller must call preferences_destroy() afterwards.
 */
preferences_t *preferences_create(void);

/**
 * Destroy a preferences object, and all memory associated with it.
 * Does nothing if the pointer is already NULL.
 *
 * @param prefs Reference to a preferences object to destroy.  This
 * will be set to NULL afterwards.
 */
void preferences_destroy(preferences_t ** prefs);

/**
 * Write the preferences object to the user's configuration file,
 * overwriting any existing file.
 *
 * @param prefs Preference object to write.
 *
 * @return 0 if successfully written, < 0 upon error.
 */
int preferences_write_to_conf_file(preferences_t * prefs);

/**
 * Return the visibility of the column with the given preference id.
 *
 * @param prefs Preference object to query.
 * @param id Preferences column identifier.
 *
 * @return Non-zero if the column is set to be visible, zero if not.
 */
int preferences_is_column_visible(preferences_t * prefs, preference_field_e id);

/**
 * Set the visibility of a column with the given preference id.  Note
 * that this will <b>not</b> update any message_view_t.
 *
 * @param prefs Preference object to query.
 * @param id Preferences column identifier.
 * @param visible If non-zero then set column visible, zero to hide.
 *
 * @see message_view_update_visible_columns needs to be called if
 * column visibilities are changed.
 */
void preferences_set_column_visible(preferences_t * prefs, preference_field_e id, int visible);

/**
 * Set the filename for the preferred audit log file.  Unless
 * overridden by the command line, this log file will be opened when
 * seaudit is launched.
 *
 * @param prefs Preference object to modify.
 * @param log Path to the log file.  The string will be duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int preferences_set_log(preferences_t * prefs, const char *log);

/**
 * Get the filename for the preferred log file from the preferences
 * object.
 *
 * @param prefs Preference object to query.
 *
 * @return Filename for the log file.  Do not modify this string.
 */
char *preferences_get_log(preferences_t * prefs);

/**
 * Set the filename for the preferred policy.  Unless overridden by the
 * command line, this policy will be opened when seaudit is launched.
 *
 * @param prefs Preference object to modify.
 * @param policy Path to the policy file.  The string will be
 * duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int preferences_set_policy(preferences_t * prefs, const char *policy);

/**
 * Get the filename for the preferred policy from the preferences object.
 *
 * @param prefs Preference object to query.
 *
 * @return Filename for the policy.  Do not modify this string.
 */
char *preferences_get_policy(preferences_t * prefs);

/**
 * Set the default report filename.
 *
 * @param prefs Preference object to modify.
 * @param report Path to the report.  The string will be duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int preferences_set_report(preferences_t * prefs, const char *report);

/**
 * Get the default report filename.
 *
 * @param prefs Preference object to query.
 *
 * @return Filename for the report.  Do not modify this string.
 */
char *preferences_get_report(preferences_t * prefs);

/**
 * Set the default stylesheet filename.
 *
 * @param prefs Preference object to modify.
 * @param stylesheet Path to the stylesheet.  The string will be
 * duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int preferences_set_stylesheet(preferences_t * prefs, const char *stylesheet);

/**
 * Get the default stylesheet filename.
 *
 * @param prefs Preference object to query.
 *
 * @return Filename for the stylesheet.  Do not modify this string.
 */
char *preferences_get_stylesheet(preferences_t * prefs);

/**
 * Set the default real-time setting for opened log files.  If startup
 * is non-zero, then the real-time monitor will be enabled for new log
 * files.
 *
 * @param prefs Preferences object to modify.
 * @param startup If non-zero, then enable real-time by default.
 */
void preferences_set_real_time_at_startup(preferences_t * prefs, int startup);

/**
 * Get the default value for real-time monitoring.
 *
 * @param prefs Preference object to query.
 *
 * @return Non-zero if opened logs should be monitored.
 */
int preferences_get_real_time_at_startup(preferences_t * prefs);

/**
 * Set the time interval (in milliseconds) for polling the log file
 * during real-time monitoring.
 *
 * @param prefs Preferences object to modify.
 * @param interval Polling interval in milliseconds.
 */
void preferences_set_real_time_interval(preferences_t * prefs, int interval);

/**
 * Get the time interval (in milliseconds) when performing real-time
 * monitoring.
 *
 * @param prefs Preference object to query.
 *
 * @return Time interval in milliseconds.
 */
int preferences_get_real_time_interval(preferences_t * prefs);

/**
 * Add a filename to the recently opened log files list.  If the name
 * is already in the list then do nothing.  Otherwise append the name
 * to the end of the list.  If the list grows too large then remove
 * the oldest entry.
 *
 * @param prefs Preference object to modify.
 * @param log Path to the most recently opened log.  The string will
 * be duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int preferences_add_recent_log(preferences_t * prefs, const char *log);

/**
 * Return a vector of recently loaded log files (type char *), with
 * the oldest file first.  Note that the vector may be empty.
 *
 * @param prefs Preferences object to query.
 *
 * @return Vector of paths.  Treat this vector as const.
 */
apol_vector_t *preferences_get_recent_logs(preferences_t * prefs);

/**
 * Add a policy path to the recently opened policy files list.  If the
 * name is already in the list then do nothing.  Otherwise append the
 * name to the end of the list.  If the list grows too large then
 * remove the oldest entry.
 *
 * @param prefs Preference object to modify.
 * @param policy Path to the most recently opened policy.  The path
 * will be duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int preferences_add_recent_policy(preferences_t * prefs, const apol_policy_path_t * policy);

/**
 * Return a vector of recently loaded policy files (type
 * apol_policy_path_t *), with the oldest file first.  Note that the
 * vector may be empty.
 *
 * @param prefs Preferences object to query.
 *
 * @return Vector of paths.  Treat this vector as const.
 */
apol_vector_t *preferences_get_recent_policies(preferences_t * prefs);

#endif
