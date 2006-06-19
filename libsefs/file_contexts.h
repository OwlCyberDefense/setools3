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
typedef struct sefs_fc_entry {
	char		*path;		/* the path for genfs_context, regexp for file_context */
	int		filetype;	/* the type of file, block, char etc */
//	security_con_t 	*context;  //FIXME
} sefs_fc_entry_t; 

int parse_file_contexts_file(const char *fc_path, sefs_fc_entry_t **contexts, int *num_contexts, policy_t *policy);
void sefs_fc_entry_free(sefs_fc_entry_t *fc_entry);
int find_default_file_contexts_file(char **path);

#endif /* FILE_CONTEXTS_H */

