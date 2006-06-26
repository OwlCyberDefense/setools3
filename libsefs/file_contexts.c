/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#define _GNU_SOURCE

#include "file_contexts.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LIBSELINUX
#include <selinux/selinux.h>
#endif

/* libapol */
#include <../libapol/policy.h>
#include <../libapol/policy-io.h>
#include <render.h>
#include "../libapol/vector.h"
#include "policy-query.h"

/* libqpol */
#include <../libqpol/include/qpol/policy_query.h>


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
	int i = 0, retv, j;
	FILE *fc_file = NULL;

	if (!fc_path || !contexts || !num_contexts || !policy)
		return -1;

	fc_file = fopen(fc_path, "r");
	if (!fc_file) {
		fprintf(stderr, "unable to open file %s\n", fc_path);
		return -1;
	}

	/* Create a fc entry and fill with data from the policy */
	while (!feof(fc_file)) {
		sefs_fc_entry_t *fc_entry = (sefs_fc_entry_t *)malloc(1*sizeof(sefs_fc_entry_t));
		tmp = NULL;
		apol_vector_append(*contexts, (void *)fc_entry ); 
		if (!(*contexts)) {
			fprintf(stderr, "out of memory\n");
			goto failure;
		}
		retv = getline(&line, &line_len, fc_file);
		if (retv == -1) {
			if (feof(fc_file)) {
				break;
			} else {
				fprintf(stderr, "error reading file\n");
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

		fc_entry->path = strdup(tmp);

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
				fprintf(stderr, "invalid file_contexts format\n");
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
			fc_entry->context = (security_con_t*)malloc(1 * sizeof(security_con_t));
			if (!((fc_entry->context))) {
				fprintf(stderr, "out of memory\n");
				goto failure;
			}
			for (; j < line_len; j++) {
				if (line[j]) {
					tmp = line + j;
					break;
				} 
			}
			if (tmp - line > line_len) {
				goto failure; 
			}
			free(context);
			context = strdup(tmp);
			if (!context) {
				fprintf(stderr, "out of memory\n");
				goto failure;
			}
			/* Get data on the user from the policy file and save it in the context */
			qpol_policy_get_user_by_name(policy->qh, policy->p, context, &fc_entry->context->user);
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
			free(context);
			context = strdup(tmp);
			if (!context) {
				fprintf(stderr, "out of memory\n");
				goto failure;
			}
			/* Get data on the role from the policy file and save it in the context */
			qpol_policy_get_role_by_name(policy->qh, policy->p, context, &fc_entry->context->role);
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
			free(context);
			context = strdup(tmp);
			if (!context) {
				fprintf(stderr, "out of memory\n");
				goto failure;
			}  
			/* Get data on the type from the policy file and save it in the context */
			qpol_policy_get_type_by_name(policy->qh, policy->p, context, &fc_entry->context->type);
		
		} else {
			fc_entry->context = NULL;
		}	

		free(line);
		line = NULL;
		free(context);
		context = NULL;
		i++;
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

void sefs_fc_entry_free(sefs_fc_entry_t *fc_entry)
{
	if (!fc_entry)
		return;
	free(fc_entry->path);
	fc_entry->path = NULL;
	free(fc_entry->context);
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
