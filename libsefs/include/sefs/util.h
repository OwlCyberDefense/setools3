/**
 * @file
 *
 * Miscellaneous, uncategorized functions for libsefs.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#ifndef SEFS_UTIL_H
#define SEFS_UTIL_H

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * Return an immutable string describing this library's version.
 *
 * @return String describing this library.
 */
	extern const char *libsefs_get_version(void);

/**
 * Return the name (path + filename) of the file_contexts file for the
 * currently running SELinux system.  If the system is not running
 * SELinux then return an empty string ("").
 *
 * @return The name of the default file_contexts file (if system is
 * running SELinux), an empty string (if not SELinux), or NULL upon
 * error.  The caller must free() the string afterwards.
 */
	extern char *sefs_default_file_contexts_get_path(void);

#ifdef	__cplusplus
}
#endif

#endif
