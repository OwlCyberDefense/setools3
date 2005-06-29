/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */ 

#ifndef FILE_CONTEXTS_H
#define FILE_CONTEXTS_H

#include "policy.h"
#include <stdio.h>

int parse_file_contexts_file(char *fc_path, fscon_t **contexts, int *num_contexts, policy_t *policy);

#endif /* FILE_CONTEXTS_H */

