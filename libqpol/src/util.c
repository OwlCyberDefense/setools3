/**
 * @file
 *
 * Implementation of utility functions.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#include "qpol_internal.h"

#include <qpol/util.h>

#include <glob.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <selinux/selinux.h>

const char *libqpol_get_version(void)
{
	return LIBQPOL_VERSION_STRING;
}

static int search_policy_source_file(char **path)
{
	if (asprintf(path, "%s/src/policy/policy.conf", selinux_policy_root()) < 0) {
		*path = NULL;
		return -1;
	}
	if (access(*path, R_OK) < 0) {
		free(*path);
		*path = NULL;
		return 1;
	}
	return 0;
}

static int is_binpol_valid(const char *policy_fname, const int version)
{
	FILE *policy_fp = NULL;
	int ret_version;

	policy_fp = fopen(policy_fname, "r");
	if (policy_fp == NULL) {
		return 0;
	}
	if (!qpol_is_file_binpol(policy_fp)) {
		fclose(policy_fp);
		return 0;
	}
	ret_version = qpol_binpol_version(policy_fp);
	fclose(policy_fp);
	return (ret_version == version);
}

static int search_for_policyfile_with_ver(const char *binary_path, const int version, char **path)
{
	glob_t glob_buf;
	struct stat fs;
	int rt;
	size_t i;
	char *pattern = NULL;

	*path = NULL;
	/* Call glob() to get a list of filenames matching pattern. */
	if (asprintf(&pattern, "%s.*", binary_path) < 0) {
		return -1;
	}
	glob_buf.gl_offs = 1;
	glob_buf.gl_pathc = 0;
	rt = glob(pattern, GLOB_DOOFFS, NULL, &glob_buf);
	free(pattern);
	if (rt != 0 && rt != GLOB_NOMATCH) {
		errno = EIO;
		return -1;
	}
	for (i = 0; i < glob_buf.gl_pathc; i++) {
		char *p = glob_buf.gl_pathv[i + glob_buf.gl_offs];
		if (stat(p, &fs) != 0) {
			globfree(&glob_buf);
			return -1;
		}
		if (S_ISDIR(fs.st_mode))
			continue;
		if (is_binpol_valid(p, version)) {
			if ((*path = strdup(p)) == NULL) {
				globfree(&glob_buf);
				return -1;
			}
			globfree(&glob_buf);
			return 1;
		}
	}
	globfree(&glob_buf);
	return 0;
}

static int search_for_policyfile_with_highest_ver(const char *binary_path, char **path)
{
	glob_t glob_buf;
	struct stat fs;
	int rt;
	size_t i;
	char *pattern = NULL;

	*path = NULL;
	/* Call glob() to get a list of filenames matching pattern. */
	if (asprintf(&pattern, "%s.*", binary_path) < 0) {
		return -1;
	}
	glob_buf.gl_offs = 1;
	glob_buf.gl_pathc = 0;
	rt = glob(pattern, GLOB_DOOFFS, NULL, &glob_buf);
	free(pattern);
	if (rt != 0 && rt != GLOB_NOMATCH) {
		errno = EIO;
		return -1;
	}

	for (i = 0; i < glob_buf.gl_pathc; i++) {
		char *p = glob_buf.gl_pathv[i + glob_buf.gl_offs];
		if (stat(*path, &fs) != 0) {
			globfree(&glob_buf);
			free(*path);
			*path = NULL;
			return -1;
		}
		if (S_ISDIR(fs.st_mode))
			continue;

		/* define "latest" version as lexigraphical order */
		if (*path != NULL) {
			if (strcmp(p, *path) > 0) {
				free(*path);
			} else {
				continue;
			}
		}

		if ((*path = strdup(p)) == NULL) {
			globfree(&glob_buf);
			return -1;
		}
	}

	globfree(&glob_buf);
	if (*path != NULL) {
		return 1;
	}
	return 0;
}

static int search_binary_policy_file(char **path)
{
	const char *bin_path;
	if ((bin_path = selinux_binary_policy_path()) == NULL) {
		*path = NULL;
		return -1;
	}
#ifdef LIBSELINUX
	int current_version, rt;
	/* try loading a binary policy that matches the system's
	 * currently loaded policy */
	if ((current_version = security_policyvers()) < 0 || asprintf(path, "%s.%d", bin_path, current_version) < 0) {
		*path = NULL;
		return -1;
	}
	/* make sure the actual binary policy version matches the
	 * policy version.  If it does not, then search the policy
	 * install directory for a binary file of the correct
	 * version. */
	if (is_binpol_valid(*path, current_version)) {
		return 0;
	}
	free(*path);
	if ((rt = search_for_policyfile_with_ver(bin_path, current_version, path)) != 0) {
		return rt;
	}
#endif

	/* if a valid binary policy file has not yet been found, try
	 * the highest version */
	return search_for_policyfile_with_highest_ver(bin_path, path);
}

int qpol_default_policy_find(char **path)
{
	int rt;
	if (path == NULL) {
		errno = EINVAL;
		return -1;
	}
	*path = NULL;
	/* Try default source policy first as a source policy contains
	 * more useful information. */
	if ((rt = search_policy_source_file(path)) <= 0) {
		return rt;
	}
	/* Try a binary policy */
	return search_binary_policy_file(path);
}
