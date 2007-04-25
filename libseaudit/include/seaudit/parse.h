/**
 *  @file
 *  Public interface for parsing an audit log.
 *
 *  @author Meggan Whalen mwhalen@tresys.com
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

#ifndef SEAUDIT_PARSE_H
#define SEAUDIT_PARSE_H

#ifdef  __cplusplus
extern "C"
{
#endif

#include "log.h"
#include <stdio.h>

/**
 * Parse the file specified by syslog and put all selinux audit
 * messages into the log.  It is assumed that log will be created
 * before this function.  If the log already has messages, new
 * messages will be appended to it.  Afterwards all models watching
 * this log will be notified of the changes.
 *
 * @param log Audit log to which append messages.
 * @param syslog Handler to an opened file containing audit messages.
 *
 * @return 0 on success, > 0 on warnings, < 0 on error and errno will
 * be set.
 */
	extern int seaudit_log_parse(seaudit_log_t * log, FILE * syslog);

/**
 * Parse a string buffer representing a syslog (or just lines from it)
 * and put all selinux audit messages into the log.  It is assumed
 * that log will be created before this function.  If the log already
 * has messages, new messages will be appended to it.  Afterwards all
 * models watching this log will be notified of the changes.
 *
 * @param log Audit log to which append messages.
 * @param buffer Buffer containing SELinux audit messages.
 * @param bufsize Number of bytes in the buffer.
 *
 * @return 0 on success, > 0 on warnings, < 0 on error and errno will
 * be set.
 */
	extern int seaudit_log_parse_buffer(seaudit_log_t * log, const char *buffer, const size_t bufsize);

#ifdef  __cplusplus
}
#endif

#endif
