/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#define _GNU_SOURCE

#include <config.h>

#include "file_contexts.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef LIBSELINUX
#include <selinux/selinux.h>
#endif

/* libapol */
#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/vector.h>

/* libqpol */
#include <qpol/policy_query.h>


/* for some reason we have to define this here to remove compile warnings */
ssize_t getline(char **lineptr, size_t *n, FILE *stream);

/**
 ** parse_file_contexts_file returns the number of contexts as well as an apol vector containing the contexts
 **
 **/

int parse_file_contexts_file(const char *fc_path, apol_vector_t **contexts, int *num_contexts, apol_policy_t *policy) 
{ 
	char *line = NULL, *tmp = NULL, *context = NULL;
	size_t line_len = 0;
	int i = 0, error, retv, j;
	FILE *fc_file = NULL;

	if (!fc_path || !contexts || !num_contexts || !policy)
		return -1;

	fc_file = fopen(fc_path, "r");
	if (!fc_file) {
		ERR(policy, "unable to open file %s\n", fc_path);
		return -1;
	}

	if ( !(*contexts = apol_vector_create()) ){
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                return -1;
	}
	/* Create a fr entry and fill with data from the policy */
	while (!feof(fc_file)) {
		sefs_fc_entry_t *fc_entry = (sefs_fc_entry_t *)malloc(1*sizeof(sefs_fc_entry_t));
		tmp = NULL;
		if (!(*contexts)) {
	                error = errno;
        	        ERR(policy, "Error: %s\n", strerror(error));
			goto failure;
		}
		retv = getline(&line, &line_len, fc_file);
		if (retv == -1) {
			if (feof(fc_file)) {
				break;
			} else {
				ERR(policy, "%s", "Error reading file.");
				goto failure;
			}
		}
		if (line[0] == '#') {
			free(line);
			line = NULL;
			continue;
		}
		line_len = strlen(line);
		for (j = 0; j < line_len; j++) {
			if (isspace(line[j]) || line[j] == ':')
				line[j] = '\0';
			else if (!tmp) {
				tmp = line + j;
			}
		}
		j = (int)(tmp - line);
		if (!tmp) {
			free(line);
			line = NULL;
			continue;
		}

		if ( !(fc_entry->path = strdup(tmp)) ) {
	                error = errno;
	                ERR(policy, "Error: %s\n", strerror(error));
			goto failure;
		}

		j += (strlen(tmp) + 1);

		if (tmp - line > line_len) {
			goto failure; /* you have walked off the end */
		}

		for (; j < line_len; j++) {
			if (line[j]) {
				tmp = line + j;
				break;
			} 
		}
		if (tmp - line > line_len) {
			goto failure; /* you have walked off the end */
		}
		if (tmp[0] == '-') {
			switch (tmp[1]) {
			case '-':
				fc_entry->filetype = FILETYPE_REG;
				break;
			case 'd':
				fc_entry->filetype = FILETYPE_DIR;
				break;
			case 'c':
				fc_entry->filetype = FILETYPE_CHR;
				break;
			case 'b':
				fc_entry->filetype = FILETYPE_BLK;
				break;
			case 'p':
				fc_entry->filetype = FILETYPE_FIFO;
				break;
			case 'l':
				fc_entry->filetype = FILETYPE_LNK;
				break;
			case 's':
				 fc_entry->filetype = FILETYPE_SOCK;
				break;
			default:
				ERR(policy, "%s", "Invalid file_contexts format.");
				goto failure;
				break;
			}
			j += 3;
			tmp += 3;
		} else {
			fc_entry->filetype = FILETYPE_ANY;
		}

		for(;j < line_len; j++) {
			if (line[j]) {
				tmp = line + j;
				break;
			} 
		}
		if (tmp - line > line_len) {
			goto failure; /* you have walked off the end */
		}

		if (strcmp(tmp, "<<none>>")) {
			/* Create a context */
			fc_entry->context = (security_con_t*)malloc(1*sizeof(security_con_t));	
			for (; j < line_len; j++) {
				if (line[j]) {
					tmp = line + j;
					break;
				} 
			}
			if (tmp - line > line_len) {
				goto failure; 
			}
			context = strdup(tmp);
			if (!context) {
	                        error = errno;
        	                ERR(policy, "Error: %s\n", strerror(error));
                	        goto failure;
			}
			/* Get data on the user from the policy file and save it in the context */
			fc_entry->context->user = NULL;
			if ( !(fc_entry->context->user = strdup(context)) ) {
	                        error = errno;
        	                ERR(policy, "Error: %s\n", strerror(error));
                	        goto failure;
			}
			context = NULL;
			j += (strlen(tmp) + 1);

			for (; j < line_len; j++) {
				if (line[j]) {
					tmp = line + j;
					break;
				} 
			}
			if (tmp - line > line_len) {
				goto failure;
			}
			context = strdup(tmp);
			if (!context) {
		                error = errno;
                		ERR(policy, "Error: %s\n", strerror(error));
				goto failure;
			}
			/* Get data on the role from the policy file and save it in the context */
			fc_entry->context->role = NULL;
			if ( !(fc_entry->context->role = strdup(context)) ) {
                        	error = errno;
	                        ERR(policy, "Error: %s\n", strerror(error));
        	                goto failure;
			}
			context = NULL;
			j += (strlen(tmp) + 1);

			for (; j < line_len; j++) {
				if (line[j]) {
					tmp = line + j;
					break;
				} 
			}
			if (tmp - line > line_len) {
				goto failure;
			}
			context = strdup(tmp);
			if (!context) {
		                error = errno;
		                ERR(policy, "Error: %s\n", strerror(error));
				goto failure;
			}  
			/* Get data on the type from the policy file and save it in the context */
			fc_entry->context->type = NULL;
			if ( !(fc_entry->context->type = strdup(context)) ) {
	                        error = errno;
        	                ERR(policy, "Error: %s\n", strerror(error));
                	        goto failure;
			}
		} else {
			fc_entry->context = NULL;
		}	
		free(line);
		line = NULL;
		free(context);
		context = NULL;
		i++;
		if ( apol_vector_append(*contexts, (void *)fc_entry ) < 0 ) {
	                error = errno;
        	        ERR(policy, "Error: %s\n", strerror(error));
			goto failure;
		}
	}
	*num_contexts = i;
	fclose(fc_file);
	return 0;
failure:
	free(line);
	free(context);
	fclose(fc_file);
	return -1;
}

void sefs_fc_entry_free(void *fc)
{
	sefs_fc_entry_t *fc_entry = (sefs_fc_entry_t*)fc;
	if (!fc_entry)
		return;
	fc_entry->path = NULL;
	fc_entry->context = NULL;
}

int find_default_file_contexts_file(char **path)
{
	*path = NULL;
#ifdef LIBSELINUX
	*path = strdup(selinux_file_context_path());
	return 0;
#else
	return -1;
#endif
}
