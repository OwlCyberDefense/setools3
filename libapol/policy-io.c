#include <config.h>

#include "policy.h"
#include "util.h"
#include "stdio.h"
#include "queue.h"
#include "policy-io.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <glob.h>
#include <string.h>
#ifdef APOL_PERFORM_TEST
#include <time.h>
#endif
#ifdef LIBSELINUX
#include <limits.h>
#include <selinux/selinux.h>
#endif

#ifndef LIBAPOL_POLICY_INSTALL_DIR
	#define LIBAPOL_POLICY_INSTALL_DIR "/etc/security/selinux"
#endif

#ifndef LIBAPOL_SELINUX_DIR
	#define LIBAPOL_SELINUX_DIR "/selinux"
#endif

#define POLICY_VER_FILE_NAME "policyvers"
#define BIN_POLICY_ROOTNAME  "policy."

/* Error TEXT definitions for decoding the above error definitions. */
#define TEXT_BIN_POL_FILE_DOES_NOT_EXIST	"Could not locate a default binary policy file.\n"
#define TEXT_SRC_POL_FILE_DOES_NOT_EXIST	"Could not locate default source policy file.\n"
#define TEXT_BOTH_POL_FILE_DO_NOT_EXIST		"Could not locate a default source policy or binary file.\n"
#define TEXT_POLICY_INSTALL_DIR_DOES_NOT_EXIST	"The default policy install directory does not exist.\n"
#define TEXT_READ_POLICY_FILE_ERROR		"Cannot read default policy file.\n"
#define TEXT_INVALID_SEARCH_OPTIONS		"Invalid search options provided to find_default_policy_file().\n"
#define TEXT_GENERAL_ERROR_TEXT			"Error in find_default_policy_file().\n"

/* externs mostly with yacc parser */
extern policy_t *parse_policy; /* parser using a global policy which we must set here */
extern unsigned int policydb_lineno;
extern queue_t id_queue;
extern FILE *yyin;
extern int yyparse(void);
extern void yyrestart(FILE *);
extern unsigned int pass;
extern int yydebug;

/* returns an error string based on a return error */
const char* find_default_policy_file_strerr(int err)
{
	switch(err) {
	case BIN_POL_FILE_DOES_NOT_EXIST:
		return TEXT_BIN_POL_FILE_DOES_NOT_EXIST;
	case SRC_POL_FILE_DOES_NOT_EXIST:
		return TEXT_SRC_POL_FILE_DOES_NOT_EXIST;
	case POLICY_INSTALL_DIR_DOES_NOT_EXIST:
		return TEXT_POLICY_INSTALL_DIR_DOES_NOT_EXIST;
	case BOTH_POL_FILE_DO_NOT_EXIST:
		return TEXT_BOTH_POL_FILE_DO_NOT_EXIST;
	case INVALID_SEARCH_OPTIONS:
		return TEXT_INVALID_SEARCH_OPTIONS;
	default:
		return TEXT_GENERAL_ERROR_TEXT;
	}
}

static bool_t is_binpol_valid(const char *policy_fname, const char *version)
{
//FIXME
	return TRUE;
}

static int search_for_policyfile_with_ver(const char *binpol_install_dir, char **policy_path_tmp, const char *version)
{
	glob_t glob_buf;
	struct stat fstat;
	int len, i, num_matches = 0, rt;
	char *pattern = NULL;
	
	assert(binpol_install_dir != NULL && policy_path_tmp && version != NULL);
	/* a. allocate pattern string to use for our call to glob() */
	len = strlen(binpol_install_dir) + strlen(BIN_POLICY_ROOTNAME) + 2;
     	if((pattern = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	} 
	sprintf(pattern, "%s/%s*", binpol_install_dir, BIN_POLICY_ROOTNAME);
	
	/* Call glob() to get a list of filenames matching pattern. */
	glob_buf.gl_offs = 1;
	glob_buf.gl_pathc = 0;
	rt = glob(pattern, GLOB_DOOFFS, NULL, &glob_buf);
	if (rt != 0 && rt != GLOB_NOMATCH) {
		fprintf(stderr, "Error globbing %s for %s*", binpol_install_dir, BIN_POLICY_ROOTNAME);
		perror("search_for_policyfile_with_ver");
		return GENERAL_ERROR;
	}
	num_matches = glob_buf.gl_pathc;
	for (i = 0; i < num_matches; i++) {
		if (stat(glob_buf.gl_pathv[i], &fstat) != 0) {
			globfree(&glob_buf);
			free(pattern);
			perror("search_for_policyfile_with_ver");
			return GENERAL_ERROR;
		}
		/* skip directories */
		if (S_ISDIR(fstat.st_mode))
			continue;
		if (is_binpol_valid(glob_buf.gl_pathv[i], version)) {
			len = strlen(glob_buf.gl_pathv[i]) + 1;
		     	if((*policy_path_tmp = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
				fprintf(stderr, "out of memory\n");
				globfree(&glob_buf);
				free(pattern);
				return GENERAL_ERROR;
			} 
			strcpy(*policy_path_tmp, glob_buf.gl_pathv[i]);
		}			
	}
	free(pattern);
	globfree(&glob_buf);
	return 0;
}

static int search_for_policyfile_with_highest_ver(const char *binpol_install_dir, char **policy_path_tmp)
{
	glob_t glob_buf;
	struct stat fstat;
	int len, i, num_matches = 0, rt;
	char *pattern = NULL;
	
	assert(binpol_install_dir != NULL && policy_path_tmp);
	/* a. allocate pattern string */
	len = strlen(binpol_install_dir) + strlen(BIN_POLICY_ROOTNAME) + 2;
     	if((pattern = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	} 
	sprintf(pattern, "%s/%s*", binpol_install_dir, BIN_POLICY_ROOTNAME);
	glob_buf.gl_offs = 0;
	glob_buf.gl_pathc = 0;
	/* Call glob() to get a list of filenames matching pattern */
	rt = glob(pattern, GLOB_DOOFFS, NULL, &glob_buf);
	if (rt != 0 && rt != GLOB_NOMATCH) {
		fprintf(stderr, "Error globbing %s for %s*", binpol_install_dir, BIN_POLICY_ROOTNAME);
		perror("search_for_policyfile_with_highest_ver");
		return GENERAL_ERROR;
	}
	num_matches = glob_buf.gl_pathc;
	for (i = 0; i < num_matches; i++) {
		if (stat(glob_buf.gl_pathv[i], &fstat) != 0) {
			globfree(&glob_buf);
			free(pattern);
			perror("search_for_policyfile_with_highest_ver");
			return GENERAL_ERROR;
		}
		/* skip directories */
		if (S_ISDIR(fstat.st_mode))
			continue;

		if (*policy_path_tmp != NULL && strcmp(glob_buf.gl_pathv[i], *policy_path_tmp) > 0) {
			free(*policy_path_tmp);
			*policy_path_tmp = NULL;
		} else if (*policy_path_tmp != NULL) {
			continue;
		}
		len = strlen(glob_buf.gl_pathv[i]) + 1;
	     	if((*policy_path_tmp = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
			fprintf(stderr, "out of memory\n");
			globfree(&glob_buf);
			free(pattern);
			return GENERAL_ERROR;
		} 
		strcpy(*policy_path_tmp, glob_buf.gl_pathv[i]);
	}
	free(pattern);
	globfree(&glob_buf);
	
	return 0;
}

static int search_binary_policy_file(char **policy_file_path)
{
#ifdef LIBSELINUX
	int ver;
#else
	int len;
	char *policy_version_file = NULL;
#endif	
	int rt = 0;
	char *version = NULL, *policy_path_tmp = NULL;
	bool_t is_valid;

     	/* A. Get the path for the currently loaded policy version. */
#ifdef LIBSELINUX
	/* Get the version number */
	ver = security_policyvers();
	if (ver < 0) {
		fprintf(stderr, "Error getting policy version.\n");
		return GENERAL_ERROR;
	}
	/* Store the version number into string */
	if ((version = (char *)malloc(sizeof(char) * LINE_SZ)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	}
	snprintf(version, LINE_SZ - 1, "%d", ver);
	assert(version);
	if ((policy_path_tmp = (char *)malloc(sizeof(char) * PATH_MAX)) == NULL) {
		fprintf(stderr, "out of memory\n");
		free(version);
		return GENERAL_ERROR;
	}
	snprintf(policy_path_tmp, PATH_MAX - 1, "%s%s%s", selinux_binary_policy_path(), 
		"." , version);
#else	
     	len = strlen(LIBAPOL_SELINUX_DIR) + strlen(POLICY_VER_FILE_NAME) + 1;
     	if((policy_version_file = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	} 
	sprintf(policy_version_file, "%s/%s", LIBAPOL_SELINUX_DIR, POLICY_VER_FILE_NAME);
	rt = access(policy_version_file, F_OK);
	if (rt == 0) {
	     	/* Read in the loaded policy version number. */
		rt = read_file_to_buffer(policy_version_file, &version, &len);
		free(policy_version_file);
		if (rt == 0) {
			len = strlen(LIBAPOL_POLICY_INSTALL_DIR) + strlen(BIN_POLICY_ROOTNAME) + strlen(version) + 2;
		     	if((policy_path_tmp = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
		     		if (version) free(version);
				fprintf(stderr, "out of memory\n");
				return GENERAL_ERROR;
			} 
			sprintf(policy_path_tmp, "%s/%s%s", LIBAPOL_POLICY_INSTALL_DIR, BIN_POLICY_ROOTNAME, version);
		} else {
			/* Cannot read policy_vers file, so proceed to step B. */
			if (version) free(version);
		}
	} else {
		free(policy_version_file);
	}
#endif
	assert(policy_path_tmp);
	/* B. make sure the actual binary policy version matches the policy version. 
	 * If it does not, then search the policy install directory for a binary file 
	 * of the correct version. */
	is_valid = is_binpol_valid(policy_path_tmp, version);
     	if (!is_valid) {
     		free(policy_path_tmp);
     		policy_path_tmp = NULL;
#ifdef LIBSELINUX
		rt = search_for_policyfile_with_ver(selinux_binary_policy_path(), &policy_path_tmp, version);
#else
     		rt = search_for_policyfile_with_ver(LIBAPOL_POLICY_INSTALL_DIR, &policy_path_tmp, version);
#endif
     	}
     	if (version) free(version);
     	if (rt == GENERAL_ERROR)
     		return GENERAL_ERROR;		
		
	/* C. If we have not found a valid binary policy file,  
	 * then try to use the highest version we find. */
	if (!policy_path_tmp) {
#ifdef LIBSELINUX
		rt = search_for_policyfile_with_highest_ver(selinux_binary_policy_path(), &policy_path_tmp);
#else
		rt = search_for_policyfile_with_highest_ver(LIBAPOL_POLICY_INSTALL_DIR, &policy_path_tmp);
#endif
		if (rt == GENERAL_ERROR)
     			return GENERAL_ERROR;
     	}
	/* If the following case is true, then we were not able to locate a binary 
	 * policy within the policy install dir */
	if (!policy_path_tmp) {
		return BIN_POL_FILE_DOES_NOT_EXIST;
	} 
	/* D. Set the policy file path */
     	if((*policy_file_path = (char *)malloc(sizeof(char) * (strlen(policy_path_tmp)+1))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	} 
	strcpy(*policy_file_path, policy_path_tmp);
	free(policy_path_tmp);
	assert(*policy_file_path);
	
	return FIND_DEFAULT_SUCCESS;
}

static int search_policy_src_file(char **policy_file_path)
{	
	int rt;
	char *path = NULL;
	
	/* Check if the default policy source file exists. */
#ifdef LIBSELINUX
	if ((path = (char *)malloc(sizeof(char) * PATH_MAX)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	}
	snprintf(path, PATH_MAX - 1, "%s/src/policy.conf", 
		 selinux_policy_root());
#else	
	if ((path = (char *)malloc(sizeof(char) * (strlen(LIBAPOL_DEFAULT_POLICY) + 1))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	}
	strcpy(path, LIBAPOL_DEFAULT_POLICY);
#endif
	assert(path != NULL);
	rt = access(path, F_OK);
	if (rt != 0) {
		free(path);
		return SRC_POL_FILE_DOES_NOT_EXIST;
     	}
     	if ((*policy_file_path = (char *)malloc(sizeof(char) * (strlen(path)+1))) == NULL) {
		fprintf(stderr, "out of memory\n");
		free(path);
		return GENERAL_ERROR;
	}
	strcpy(*policy_file_path, path);
	free(path);
	
	return FIND_DEFAULT_SUCCESS;
}

/* Find the default policy file given a policy type. 
 * This function takes 2 arguments: 
 * 	1. a pointer to a buffer to store the policy file path.
 *	2. search_opt - bitmask of policy type(s) (see policy.h) 
 *
 * Return codes defined in policy-io.h.
 *
 */
int find_default_policy_file(unsigned int search_opt, char **policy_file_path)
{
	int rt, src_not_found = 0;
	
	assert(policy_file_path != NULL);
	
	/* Try default source policy first as a source  
	 * policy contains more useful information. */
	if (search_opt & POL_TYPE_SOURCE) {
		rt = search_policy_src_file(policy_file_path);
		if (rt == FIND_DEFAULT_SUCCESS) {
	     		return FIND_DEFAULT_SUCCESS;	
	     	}
	     	/* Only continue if a source policy couldn't be found. */
	     	if (rt != SRC_POL_FILE_DOES_NOT_EXIST) {
	     		return rt;	
	     	}  
	     	src_not_found = 1;
	}
	
	/* Try a binary policy */
        if (search_opt & POL_TYPE_BINARY) {
	     	rt = search_binary_policy_file(policy_file_path);
	     	if (rt == BIN_POL_FILE_DOES_NOT_EXIST && src_not_found) {
	     		return BOTH_POL_FILE_DO_NOT_EXIST;	
	     	} 
	     	return rt;	
	} 
	/* Only get here if invalid search options was provided. */
	return INVALID_SEARCH_OPTIONS;
}

/******************** new policy reading below ********************/

/**
 * @file policy-io.c
 *
 * Implementation of policy loading routines.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2001-2006 Tresys Technology, LLC
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <qpol/policy_extend.h>

#include "policy.h"
#include "policy-io.h"
#include "perm-map.h"

__attribute__ ((format (printf, 3, 4)))
static void qpol_handle_route_to_callback(void *varg, qpol_handle_t *handle,
					  const char *fmt, ...)
{
	apol_policy_t *p = (apol_policy_t *) varg;
	va_list ap;
	va_start(ap, fmt);
	if (p != NULL && p->msg_callback != NULL) {
		p->msg_callback(p->msg_callback_arg, p, fmt, ap);
	}
	va_end(ap);
}

static void apol_handle_default_callback(void *varg __attribute__ ((unused)),
					 apol_policy_t *p __attribute__ ((unused)),
					 const char *fmt, va_list ap)
{
	 vfprintf(stderr, fmt, ap);
	 fprintf(stderr, "\n");
}

int apol_policy_open(const char *path, apol_policy_t **policy)
{
	int policy_type;
	if (!path || !policy) {
		errno = EINVAL;
		return -1;
	}

	if (policy)
		*policy = NULL;

	if (!(*policy = calloc(1, sizeof(apol_policy_t)))) {
		fprintf(stderr, "Out of memory!\n");
		return -1; /* errno set by calloc */
	}
	(*policy)->msg_callback = apol_handle_default_callback;
	(*policy)->msg_callback_arg = (*policy);

        policy_type = qpol_open_policy_from_file(path, &((*policy)->p), &((*policy)->qh), qpol_handle_route_to_callback, (*policy));
        if (policy_type < 0) {
		ERR(*policy, "Unable to open policy at %s.", path);
		apol_policy_destroy(policy);
		return -1; /* qpol sets errno */
        }
        (*policy)->policy_type = policy_type;
	return 0;
}

void apol_policy_destroy(apol_policy_t **policy)
{
	if (policy != NULL && *policy != NULL) {
		qpol_close_policy(&((*policy)->p));
		qpol_handle_destroy(&((*policy)->qh));
		apol_permmap_destroy(&(*policy)->pmap);
		free(*policy);
		*policy = NULL;
	}
}
