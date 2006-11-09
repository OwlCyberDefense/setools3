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

#ifdef	__cplusplus
extern "C" {
#endif

#include "auditlog.h"
#define	PARSE_RET_SUCCESS		0x00000001	/* success, no warnings nor errors */
#define PARSE_RET_MEMORY_ERROR		0x00000002	/* general error */
#define PARSE_RET_EOF_ERROR            	0x00000004	/* file was eof */
#define PARSE_RET_NO_SELINUX_ERROR   	0x00000008	/* no selinux messages found */
#define PARSE_RET_INVALID_MSG_WARN	0x00000010	/* invalid message, but added to audit log anyway */
#define PARSE_REACHED_END_OF_MSG	0x00000020	/* we reached the end of the message before gathering all information */
#define LOAD_POLICY_FALSE_POS		0x00000040	/* indicates that the message is not a load message although has 'security:' string */
#define LOAD_POLICY_NEXT_LINE 		0x00000080	/* indicates that we've parsed the first line of a load message */

#define PARSE_MEMORY_ERROR_MSG "Memory error while parsing the log!"
#define PARSE_NO_SELINUX_ERROR_MSG "No SELinux messages found in log!"
#define PARSE_SUCCESS_MSG "Parse success!"
#define PARSE_INVALID_MSG_WARN_MSG "Warning! One or more invalid messages found in audit log.  See help file for more information."

unsigned int parse_audit(FILE * syslog, audit_log_t * log);
/* parses the file specified by syslog and puts all selinux audit messages into log 
   it is assumed that log will be created before this function
*/

#ifdef	__cplusplus
}
#endif

#endif
