/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mbrown@tresys.com
 * Date: October 3, 2003
 *
 * This file contains the parsing definitions
 *
 * parse.h
 */

#ifndef LIBAUDIT_PARSE_H
#define LIBAUDIT_PARSE_H


#include "auditlog.h"
#define PARSE_MEMORY_ERROR -2
#define PARSE_NO_SELINUX_ERROR -4
#define PARSE_SUCCESS 0
#define PARSE_INVALID_MSG_WARN 2 /* message NOT added to audit log */
#define PARSE_MALFORMED_MSG_WARN 3 /* message added to audit log anyway */
#define PARSE_BOTH_MSG_WARN 4 /* invalid and malformed messages found in log */


#define PARSE_MEMORY_ERROR_MSG "Memory error while parsing the log!"
#define PARSE_NO_SELINUX_ERROR_MSG "No SELinux messages found in log!"
#define PARSE_SUCCESS_MSG "Parse success!"
#define PARSE_INVALID_MSG_WARN_MSG "Warning! One or more invalid messages found in audit log.  See help file for more information."
#define PARSE_MALFORMED_MSG_WARN_MSG "Warning! One or more malformed messages found in audit log.  See help file for more information."
#define PARSE_BOTH_MSG_WARN_MSG "Warning! Invalid and malformed messages found in audit log.  See help file for more information."

int parse_audit(FILE *syslog, audit_log_t *log, bool_t do_filter);
/* parses the file specified by syslog and puts all selinux audit messages into log 
   it is assumed that log will be created before this function
*/


#endif









