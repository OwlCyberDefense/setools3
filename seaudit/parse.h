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
#define PARSE_FILE_OPEN_ERROR -3
#define PARSE_NO_SELINUX_ERROR -4
#define PARSE_SUCCESS 0
#define PARSE_INVALID_MSG_WARN 2 /* message NOT added to audit log */
#define PARSE_MALFORMED_MSG_WARN 3 /* message added to audit log anyway */

int parse_audit(char *syslog, audit_log_t *log);
/* parses the file specified by syslog and puts all selinux audit messages into log 
   it is assumed that log will be created before this function
*/


#endif









