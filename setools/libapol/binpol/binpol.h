/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * Support from binary policies in libapol 
 */
 
#ifndef _APOLICY_BINPOL_H_
#define _APOLICY_BINPOL_H_

#include "../policy.h"


bool_t ap_is_file_binpol(FILE *fp);
int ap_binpol_version(FILE *fp);
int ap_read_binpol_file(FILE *fp, unsigned int options, policy_t *policy);

#endif
