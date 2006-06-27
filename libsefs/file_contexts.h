/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/*
 * Author: jmowery@tresys.com
 *
 */

#ifndef FILE_CONTEXTS_H
#define FILE_CONTEXTS_H

/* libapol */
#include <../libapol/policy.h>
#include <../libapol/policy-io.h>
#include <render.h>
#include "../libapol/vector.h"
#include "policy-query.h"

/* libqpol */
#include <../libqpol/include/qpol/policy_query.h>

#include <stdio.h>

/* file type IDs */
#define FILETYPE_NONE 0  /* none */
/* the following values must correspond to libsepol flask.h */
#define FILETYPE_REG  6  /* Regular file */
#define FILETYPE_DIR  7  /* Directory */
#define FILETYPE_LNK  9  /* Symbolic link */
#define FILETYPE_CHR  10 /* Character device */
#define FILETYPE_BLK  11 /* Block device */
#define FILETYPE_SOCK 12 /* Socket */
#define FILETYPE_FIFO 13 /* FIFO */
#define FILETYPE_ANY  14 /* any type */

/* general file contexts structure */
typedef struct security_context {
        qpol_user_t     	*user;
        qpol_role_t     	*role;
        qpol_type_t     	*type;
        qpol_mls_range_t	*range;
} security_con_t;

typedef struct sefs_fc_entry {
	char		*path;		/* the path for genfs_context, regexp for file_context */
	int		filetype;	/* the type of file, block, char etc */
	security_con_t 	*context; 
} sefs_fc_entry_t; 

int parse_file_contexts_file(const char *fc_path, apol_vector_t **contexts, int *num_contexts, apol_policy_t *policy);
void sefs_fc_entry_free(void *fc);
int find_default_file_contexts_file(char **path);

#endif /* FILE_CONTEXTS_H */

