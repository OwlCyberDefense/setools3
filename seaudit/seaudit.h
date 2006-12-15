/**
 *  @file seaudit.h
 *  Declaration of the main driver class for seaudit.
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

#ifndef SEAUDIT_H
#define SEAUDIT_H

#include "preferences.h"
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <seaudit/log.h>
#include <stdio.h>
#include <time.h>

typedef struct seaudit seaudit_t;

#define COPYRIGHT_INFO "Copyright (c) 2003-2007 Tresys Technology, LLC"

/**
 * Retrieve the preferences object associated with the seaudit object.
 *
 * @param s seaudit object to query.
 *
 * @return Pointer to a preferences object.  Do not free() this pointer.
 */
preferences_t *seaudit_get_prefs(seaudit_t * s);

/**
 * Set the currently loaded policy for seaudit.  This will also update
 * the preferences object's recently loaded policies.
 *
 * @param s seaudit object to modify.
 * @param policy New policy file for seaudit.  If NULL then seaudit
 * has no policy opened.  Afterwards seaudit takes ownership of the
 * policy.
 * @param path If policy is not NULL, then add this path to the most
 * recently used policy files.
 */
void seaudit_set_policy(seaudit_t * s, apol_policy_t * policy, apol_policy_path_t * path);

/**
 * Retrieve the currently loaded policy.
 *
 * @param s seaudit object to query.
 *
 * @return Pointer to an apol policy, or NULL if none loaded.  Treat
 * this as a const pointer.
 */
apol_policy_t *seaudit_get_policy(seaudit_t * s);

/**
 * Return the path to the currently loaded policy.  If the current
 * policy is modular then this returns the base policy's path.
 *
 * @param s seaudit object to query.
 *
 * @return Path of policy, or NULL if none loaded.  Treat this as a
 * const pointer.
 */
apol_policy_path_t *seaudit_get_policy_path(seaudit_t * s);

/**
 * Set the currently loaded log for seaudit.  This will also update
 * the preferences object's recently loaded files.
 *
 * @param s seaudit object to modify.
 * @param log New log file for seaudit.  If NULL then seaudit has no
 * log files opened.  Afterwards seaudit takes ownership of the log.
 * @param f File handler that was used to open the log.  Afterwards
 * seaudit takes ownership of this handler.
 * @param filename If log is not NULL, then add this filename to the
 * most recently used files.
 */
void seaudit_set_log(seaudit_t * s, seaudit_log_t * log, FILE * f, const char *filename);

/**
 * Command seaudit to (re)parse its log file.
 *
 * @param s seaudit object containing the log.
 *
 * @return 0 if log parsed cleanly, < 0 upon errors, or > 0 if there
 * were warnings.
 */
int seaudit_parse_log(seaudit_t * s);

/**
 * Retrieve the currently loaded log file.
 *
 * @param s seaudit object to query.
 *
 * @return Pointer to a libseaudit log, or NULL if none loaded.  Treat
 * this as a const pointer.
 */
seaudit_log_t *seaudit_get_log(seaudit_t * s);

/**
 * Return the path to the currently loaded log file.
 *
 * @param s seaudit object to query.
 *
 * @return Path of log file, or NULL if none loaded.  Treat this as a
 * const pointer.
 */
char *seaudit_get_log_path(seaudit_t * s);

/**
 * Return a vector of strings corresponding to all users found within
 * currently opened log files.  The vector will be sorted
 * alphabetically.
 *
 * @param s seaudit object to query.
 *
 * @return Vector of sorted users, or NULL if no log is loaded.  The
 * caller must call apol_vector_destroy() upon the return value,
 * passing NULL as the second parameter.
 */
apol_vector_t *seaudit_get_log_users(seaudit_t * s);

/**
 * Return a vector of strings corresponding to all roles found within
 * currently opened log files.  The vector will be sorted
 * alphabetically.
 *
 * @param s seaudit object to query.
 *
 * @return Vector of sorted roles, or NULL if no log is loaded.  The
 * caller must call apol_vector_destroy() upon the return value,
 * passing NULL as the second parameter.
 */
apol_vector_t *seaudit_get_log_roles(seaudit_t * s);

/**
 * Return a vector of strings corresponding to all types found within
 * currently opened log files.  The vector will be sorted
 * alphabetically.
 *
 * @param s seaudit object to query.
 *
 * @return Vector of sorted types, or NULL if no log is loaded.  The
 * caller must call apol_vector_destroy() upon the return value,
 * passing NULL as the second parameter.
 */
apol_vector_t *seaudit_get_log_types(seaudit_t * s);

/**
 * Return a vector of strings corresponding to all object classes
 * found within currently opened log file.  The vector will be sorted
 * alphabetically.
 *
 * @param s seaudit object to query.
 *
 * @return Vector of sorted classes, or NULL if no log is loaded.  The
 * caller must call apol_vector_destroy() upon the return value,
 * passing NULL as the second parameter.
 */
apol_vector_t *seaudit_get_log_classes(seaudit_t * s);

/**
 * Return the number of messages in the current log.
 *
 * @param s seaudit object to query.
 *
 * @return Number of log messages, or 0 if no log is opened.
 */
size_t seaudit_get_num_log_messages(seaudit_t * s);

/**
 * Return the time stamp for the first message in the currently opened
 * log.
 *
 * @param s seaudit object to query.
 *
 * @return Time of the first log message, or NULL if no log is opened.
 * Treat this as a const pointer.
 */
struct tm *seaudit_get_log_first(seaudit_t * s);

/**
 * Return the time stamp for the last message in the currently opened
 * log.
 *
 * @param s seaudit object to query.
 *
 * @return Time of the last log message, or NULL if no log is opened.
 * Treat this as a const pointer.
 */
struct tm *seaudit_get_log_last(seaudit_t * s);

#endif
