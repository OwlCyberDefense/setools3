/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */ 

#include "file_contexts.h"
#include "policy.h"
#include <ctype.h>
#define _GNU_SOURCE
#include <stdio.h>

#ifdef LIBSELINUX
#include <selinux/selinux.h>
#endif

/* for some reason we have to define this here to remove compile warnings */
ssize_t getline(char **lineptr, size_t *n, FILE *stream);

int parse_file_contexts_file(const char *fc_path, sefs_fc_entry_t **contexts, int *num_contexts, policy_t *policy) 
{
	int array_sz = 0; /* actual size of array */
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

	while (!feof(fc_file)) {
		tmp = NULL;
		if (i+1 > array_sz) {
			array_sz += LIST_SZ;
			*contexts = (sefs_fc_entry_t*)realloc(*contexts, array_sz * sizeof(sefs_fc_entry_t));
			if (!(*contexts)) {
				fprintf(stderr, "out of memory\n");
				goto failure;
			}
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

		(*contexts)[i].path = strdup(tmp);

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
				(*contexts)[i].filetype = FILETYPE_REG;
				break;
			case 'd':
				(*contexts)[i].filetype = FILETYPE_DIR;
				break;
			case 'c':
				(*contexts)[i].filetype = FILETYPE_CHR;
				break;
			case 'b':
				(*contexts)[i].filetype = FILETYPE_BLK;
				break;
			case 'p':
				(*contexts)[i].filetype = FILETYPE_FIFO;
				break;
			case 'l':
				(*contexts)[i].filetype = FILETYPE_LNK;
				break;
			case 's':
				 (*contexts)[i].filetype = FILETYPE_SOCK;
				break;
			default:
				fprintf(stderr, "invalid file_contexts format\n");
				goto failure;
				break;
			}
			j += 3;
			tmp += 3;
		} else {
			(*contexts)[i].filetype = FILETYPE_ANY;
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
			(*contexts)[i].context = (security_con_t*)malloc(1 * sizeof(security_con_t));
			if (!((*contexts)[i].context)) {
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
				goto failure; /* you have walked off the end */
			}
			free(context);
			context = strdup(tmp);
			if (!context) {
				fprintf(stderr, "out of memory\n");
				goto failure;
			}
			(*contexts)[i].context->user = get_user_idx(context, policy);
			j += (strlen(tmp) + 1);

			for (; j < line_len; j++) {
				if (line[j]) {
					tmp = line + j;
					break;
				} 
			}
			if (tmp - line > line_len) {
				goto failure; /* you have walked off the end */
			}
			free(context);
			context = strdup(tmp);
			if (!context) {
				fprintf(stderr, "out of memory\n");
				goto failure;
			}
			(*contexts)[i].context->role = get_role_idx(context, policy);
			j += (strlen(tmp) + 1);

			for (; j < line_len; j++) {
				if (line[j]) {
					tmp = line + j;
					break;
				} 
			}
			if (tmp - line > line_len) {
				goto failure; /* you have walked off the end */
			}
			free(context);
			context = strdup(tmp);
			if (!context) {
				fprintf(stderr, "out of memory\n");
				goto failure;
			}
			(*contexts)[i].context->type = get_type_idx(context, policy);
		
		} else {
			(*contexts)[i].context = NULL;
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
