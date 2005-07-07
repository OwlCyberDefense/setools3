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

/* general file contexts structure */
typedef struct fscon {
	char		*path;		/* the path for genfs_context, regexp for file_context */
	char		*fstype;	/* only used in genfs_context */
	int		filetype;	/* the type of file, block, char etc */
	security_con_t 	*context;  
} fscon_t; 

int parse_file_contexts_file(const char *fc_path, fscon_t **contexts, int *num_contexts, policy_t *policy);
void fscon_free(fscon_t *fscon);

#endif /* FILE_CONTEXTS_H */

