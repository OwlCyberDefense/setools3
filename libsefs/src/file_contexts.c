/**
 * @file file_contexts.c
 *
 * Public interface for loading and parsing the default file_contexts
 * file.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include <sefs/file_contexts.h>
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

int sefs_fc_entry_parse_file_contexts(apol_policy_t * p, const char *fc_path, apol_vector_t ** contexts)
{
	char *line = NULL, *tmp = NULL;
	size_t line_len = 0;
	int i = 0, error = 0, retv, j;
	FILE *fc_file = NULL;
	sefs_fc_entry_t *fc_entry = NULL;

	if (!contexts)
		*contexts = NULL;

	if (!fc_path || !contexts || !p)
		return -1;

	fc_file = fopen(fc_path, "r");
	if (!fc_file) {
		error = errno;
		ERR(p, "Unable to open file %s", fc_path);
		goto failure;
	}

	if (!(*contexts = apol_vector_create())) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto failure;
	}
	/* Create a fc entry and fill with data from the policy */
	while (!feof(fc_file)) {
		fc_entry = (sefs_fc_entry_t *) calloc(1, sizeof(sefs_fc_entry_t));
		tmp = NULL;
		if (!(*contexts)) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto failure;
		}
		retv = getline(&line, &line_len, fc_file);
		if (retv == -1) {
			if (feof(fc_file)) {
				break;
			} else {
				error = errno;
				ERR(p, "%s", strerror(error));
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

		if (!(fc_entry->path = strdup(tmp))) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto failure;
		}

		j += (strlen(tmp) + 1);

		if (tmp - line > line_len) {
			goto failure;  /* you have walked off the end */
		}

		for (; j < line_len; j++) {
			if (line[j]) {
				tmp = line + j;
				break;
			}
		}
		if (tmp - line > line_len) {
			goto failure;  /* you have walked off the end */
		}
		if (tmp[0] == '-') {
			switch (tmp[1]) {
			case '-':
				fc_entry->filetype = SEFS_FILETYPE_REG;
				break;
			case 'd':
				fc_entry->filetype = SEFS_FILETYPE_DIR;
				break;
			case 'c':
				fc_entry->filetype = SEFS_FILETYPE_CHR;
				break;
			case 'b':
				fc_entry->filetype = SEFS_FILETYPE_BLK;
				break;
			case 'p':
				fc_entry->filetype = SEFS_FILETYPE_FIFO;
				break;
			case 'l':
				fc_entry->filetype = SEFS_FILETYPE_LNK;
				break;
			case 's':
				fc_entry->filetype = SEFS_FILETYPE_SOCK;
				break;
			default:
				error = EINVAL;
				ERR(p, "%s", "Invalid file_contexts format.");
				goto failure;
				break;
			}
			j += 3;
			tmp += 3;
		} else {
			fc_entry->filetype = SEFS_FILETYPE_ANY;
		}

		for (; j < line_len; j++) {
			if (line[j]) {
				tmp = line + j;
				break;
			}
		}
		if (tmp - line > line_len) {
			goto failure;  /* you have walked off the end */
		}

		if (strcmp(tmp, "<<none>>")) {
			/* Create a context */
			fc_entry->context = calloc(1, sizeof(sefs_security_con_t));
			if (!fc_entry->context) {
				error = errno;
				ERR(p, "%s", strerror(error));
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
			/* Get data on the user from the policy file
			 * and save it in the context */
			fc_entry->context->user = NULL;
			if (!(fc_entry->context->user = strdup(tmp))) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto failure;
			}
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
			/* Get data on the role from the policy file
			 * and save it in the context */
			fc_entry->context->role = NULL;
			if (!(fc_entry->context->role = strdup(tmp))) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto failure;
			}
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
			/* Get data on the type from the policy file
			 * and save it in the context */
			fc_entry->context->type = NULL;
			if (!(fc_entry->context->type = strdup(tmp))) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto failure;
			}
		} else {
			fc_entry->context = NULL;
		}
		free(line);
		line = NULL;
		i++;
		if (apol_vector_append(*contexts, (void *)fc_entry) < 0) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto failure;
		}
		fc_entry = NULL;
	}
	free(fc_entry);		       /* free uninitialized one created just before eof */
	free(line);
	fclose(fc_file);
	return 0;
      failure:
	apol_vector_destroy(contexts, sefs_fc_entry_free);
	free(line);
	if (fc_file)
		fclose(fc_file);
	errno = error;
	return -1;
}

void sefs_fc_entry_free(void *fc)
{
	sefs_fc_entry_t *fc_entry = (sefs_fc_entry_t *) fc;
	if (!fc_entry)
		return;
	free(fc_entry->path);
	if (fc_entry->context) {
		free(fc_entry->context->user);
		free(fc_entry->context->role);
		free(fc_entry->context->type);
		free(fc_entry->context->range);
		free(fc_entry->context);
	}
	free(fc);
}

int sefs_fc_find_default_file_contexts(char **path)
{
	*path = NULL;
#ifdef LIBSELINUX
	*path = strdup(selinux_file_context_path());
	if (*path == NULL)
		return -1;
	return 0;
#else
	errno = ENOSYS;
	return -1;
#endif
}
