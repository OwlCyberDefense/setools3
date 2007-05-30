/**
 *  @file
 *  Additional declarations for use solely by libsefs.
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

#ifndef SEFS_INTERNAL_HH
#define SEFS_INTERNAL_HH

#include <apol/bst.h>
#include <sefs/fclist.hh>

/**
 * Invoke a sefs_fclist_t's callback for an error, passing it a format
 * string and arguments.
 */
#define SEFS_ERR(format, ...) handleMsg(SEFS_MSG_ERR, format, __VA_ARGS__)

/**
 * Invoke a sefs_fclist_t's callback for a warning, passing it a
 * format string and arguments.
 */
#define SEFS_WARN(format, ...) handleMsg(SEFS_MSG_WARN, format, __VA_ARGS__)

/**
 * Invoke a sefs_fclist's callback for an informational message,
 * passing it a format string and arguments.
 */
#define SEFS_INFO(format, ...) handleMsg(SEFS_MSG_INFO, format, __VA_ARGS__)

#endif
