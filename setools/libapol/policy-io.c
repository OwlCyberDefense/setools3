/* Copyright (C) 2001-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com
 */

/* policy-io.c
 *
 * Policy I/O functions 
 */
 
#include "policy.h"
#include "util.h"
#include "stdio.h"
#include "queue.h"
#include "binpol/binpol.h"
#include "policy-io.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <glob.h>
#ifdef APOL_PERFORM_TEST
#include <time.h>
#endif

#ifndef LIBAPOL_POLICY_INSTALL_DIR
	#define LIBAPOL_POLICY_INSTALL_DIR "/etc/security/selinux"
#endif

#ifndef LIBAPOL_SELINUX_DIR
	#define LIBAPOL_SELINUX_DIR "/selinux"
#endif

#define POLICY_VER_FILE_NAME "policyvers"

/* Error TEXT definitions for decoding the above error definitions. */
#define TEXT_BIN_POL_FILE_DOES_NOT_EXIST	"Could not locate a default binary policy file.\n"
#define TEXT_SRC_POL_FILE_DOES_NOT_EXIST	"Could not locate default source policy file.\n"
#define TEXT_NOT_SELINUX_AWARE			"This is not an selinux system.\n"
#define TEXT_READ_POLICY_FILE_ERROR		"Cannot read default policy file.\n"
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

/* returns an error string based on a return error from seuser_label_home_dir() */
const char* find_default_policy_file_strerr(int err)
{
	switch(err) {
	case BIN_POL_FILE_DOES_NOT_EXIST:
		return TEXT_BIN_POL_FILE_DOES_NOT_EXIST;
	case SRC_POL_FILE_DOES_NOT_EXIST:
		return TEXT_SRC_POL_FILE_DOES_NOT_EXIST;
	case NOT_SELINUX_AWARE:
		return TEXT_NOT_SELINUX_AWARE;
	default:
		return TEXT_GENERAL_ERROR_TEXT;
	}
}

static bool_t is_binpol_valid(const char *policy_fname, const char *version)
{
	FILE *policy_fp = NULL;
	int ret_version;
	
	assert(policy_fname != NULL && version != NULL);
	policy_fp = fopen(policy_fname, "r");
	if (policy_fp == NULL) {
		fprintf(stderr, "Could not open policy %s!\n", policy_fname);
		fclose(policy_fp);
		return FALSE;
	}
	if(!ap_is_file_binpol(policy_fp)) {
		fclose(policy_fp);
		return FALSE;
	}
	ret_version = ap_binpol_version(policy_fp);
	fclose(policy_fp);
	if (ret_version != atoi(version))
		return FALSE;
	
     	return TRUE;
}

static int search_for_policyfile_with_ver(const char *binpol_install_dir, char **policy_path_tmp, const char *version)
{
	glob_t glob_buf;
	struct stat fstat;
	int len, i, num_matches = 0;
	char *pattern = NULL;
	
	assert(binpol_install_dir != NULL && policy_path_tmp && version != NULL);
	/* a. allocate pattern string to use for our call to glob() */
	len = strlen(binpol_install_dir) + strlen("policy.*") + 1;
     	if((pattern = (char *)malloc(len+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	} 
	sprintf(pattern, "%s/policy.*", binpol_install_dir);
	
	/* Call glob() to get a list of filenames matching pattern. We glob for 'policy.*' */
	glob_buf.gl_offs = 1;
	if (glob(pattern, GLOB_DOOFFS, NULL, &glob_buf) != 0) {
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
		     	if((*policy_path_tmp = (char *)malloc(len+1)) == NULL) {
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
	int len, i, num_matches = 0;
	char *pattern = NULL;
	
	assert(binpol_install_dir != NULL && policy_path_tmp);
	/* a. allocate pattern string */
	len = strlen(binpol_install_dir) + strlen("policy.*") + 1;
     	if((pattern = (char *)malloc(len+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	} 
	sprintf(pattern, "%s/policy.*", binpol_install_dir);
	glob_buf.gl_offs = 0;
	/* Call glob() to get a list of filenames matching pattern */
	if (glob(pattern, GLOB_DOOFFS, NULL, &glob_buf) != 0) {
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
	     	if((*policy_path_tmp = (char *)malloc(len+1)) == NULL) {
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
	int rt, len;
	char *version = NULL, *policy_version_file = NULL, *policy_path_tmp = NULL;
	bool_t is_valid;
		
     	/* a. Check /selinux/policyvers for the currently loaded policy version */
     	len = strlen(LIBAPOL_SELINUX_DIR) + strlen(POLICY_VER_FILE_NAME) + 1;
     	if((policy_version_file = (char *)malloc(len+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	} 
	sprintf(policy_version_file, "%s/%s", LIBAPOL_SELINUX_DIR, POLICY_VER_FILE_NAME);
	rt = access(policy_version_file, F_OK);
	if (rt == 0) {
	     	/* 1. Read in the loaded policy version number. */
		rt = read_file_to_buffer(policy_version_file, &version, &len);
		free(policy_version_file);
		if (rt == 0) {
			/* 2. See if policy.VERSION exists in the policy install directory. */
			len = strlen(LIBAPOL_POLICY_INSTALL_DIR) + strlen("policy.") + strlen(version) + 1;
		     	if((policy_path_tmp = (char *)malloc(len+1)) == NULL) {
		     		if (version) free(version);
				fprintf(stderr, "out of memory\n");
				return GENERAL_ERROR;
			} 
			sprintf(policy_path_tmp, "%s/policy.%s", LIBAPOL_POLICY_INSTALL_DIR, version);
			
			/* 3. make sure the actual binary policy version matches the policy version from  /selinux/policyvers. 
			 * If it does not, then search the policy install directory for a binary file of the correct version. */
			is_valid = is_binpol_valid(policy_path_tmp, version);
		     	if (!is_valid) {
		     		free(policy_path_tmp);
		     		policy_path_tmp = NULL;
		     		rt = search_for_policyfile_with_ver(LIBAPOL_POLICY_INSTALL_DIR, &policy_path_tmp, version);
		     	}
		     	if (version) free(version);
		     	if (rt == GENERAL_ERROR)
		     		return GENERAL_ERROR;
		} else {
			/* Cannot read policy_vers file, so move on an step b. */
			if (version) free(version);
		}
	} else {
		free(policy_version_file);
	}
		
	/* b. If we have not found a valid binary policy file, then try to use the highest version we find */
	if (!policy_path_tmp) {
		rt = search_for_policyfile_with_highest_ver(LIBAPOL_POLICY_INSTALL_DIR, &policy_path_tmp);
		if (rt == GENERAL_ERROR)
     			return GENERAL_ERROR;
     	}
	/* c. If the following case is true, then we were not able to locate a binary policy within the policy install dir */
	if (!policy_path_tmp) {
		return BIN_POL_FILE_DOES_NOT_EXIST;
	} 
	/* d. Set the policy file path */
     	if((*policy_file_path = (char *)malloc(strlen(policy_path_tmp)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	} 
	strcpy(*policy_file_path, policy_path_tmp);
	free(policy_path_tmp);
	return FIND_DEFAULT_SUCCESS;
}

static int search_policy_src_file(char **policy_file_path)
{	
	int rt;
	
	/* Check if the default policy source file exists. */
	rt = access(LIBAPOL_DEFAULT_POLICY, F_OK);
	if (rt != 0) {
		return SRC_POL_FILE_DOES_NOT_EXIST;
     	}
     	if((*policy_file_path = (char *)malloc(strlen(LIBAPOL_DEFAULT_POLICY)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	}
	strcpy(*policy_file_path, LIBAPOL_DEFAULT_POLICY);

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
	int rt;
	
	assert(policy_file_path != NULL);

	/* See if selinux-aware. */ 
	rt = access(LIBAPOL_POLICY_INSTALL_DIR, F_OK);
	if (rt != 0) {
		return NOT_SELINUX_AWARE;
     	}    
	/* Try a binary policy */
        if (search_opt & POL_TYPE_BINARY) {
	     	rt = search_binary_policy_file(policy_file_path);
	     	if (rt == FIND_DEFAULT_SUCCESS) {
	     		return FIND_DEFAULT_SUCCESS;	
	     	}
	     	/* Only continue if a binary policy couldn't be found. */
	     	if (rt != BIN_POL_FILE_DOES_NOT_EXIST) {
	     		return rt;	
	     	}  	
	} 
	/* Try default source policy */
	if (search_opt & POL_TYPE_SOURCE) {
		rt = search_policy_src_file(policy_file_path);
		if (rt != FIND_DEFAULT_SUCCESS) {
	     		return rt;
	     	}
	}
	return rt;
}

int close_policy(policy_t *policy)
{
	return free_policy(&policy);
}

static int read_policy(policy_t *policy)
{
	/*yydebug = 1; */
	parse_policy = policy; /* setting the parser's global parse policy */
	/* assumed yyin is opened to policy file */
	id_queue = queue_create();
	if (!id_queue) {
		fprintf(stderr, "out of memory\n");
		queue_destroy(id_queue);
		return -1;
	}
	policydb_lineno = 1;
	pass = 1;
	if (yyparse()) {
		fprintf(stderr, "error(s) encountered while parsing configuration (first pass, line: %d)\n", policydb_lineno);
		queue_destroy(id_queue);
		rewind(yyin);
		yyrestart(yyin);	
		return -1;
	}
	
	/* If we don't need anything from pass 2, just return and save the time */
	if(!(policy->opts & PLOPT_PASS_2 )) {
		queue_destroy(id_queue);
		return 0;
	}
		
	policydb_lineno = 1;
	pass = 2;
	rewind(yyin);
	yyrestart(yyin);	
	if (yyparse()) {
		fprintf(stderr, "error(s) encountered while parsing configuration (second pass, line: %d)\n", policydb_lineno);
		queue_destroy(id_queue);
		rewind(yyin);
		yyrestart(yyin);	
		return -1;
	}
		
	queue_destroy(id_queue);
	return 0;		
}

/* checks for acceptable combinations, and adjusts the mask accordingly */
unsigned int validate_policy_options(unsigned int options)
{
	unsigned int opts = options;

	/* always include the basic conditional pieces */
	opts |= (POLOPT_COND_BOOLS|POLOPT_COND_EXPR);

	/* NOTE: The order of these is important */	
	if(POLOPT_TE_RULES & opts)
		opts |= (POLOPT_OBJECTS|POLOPT_TYPES);
	if(POLOPT_PERMS & opts)
		opts |= POLOPT_CLASSES;
	if(POLOPT_ROLE_RULES & opts)
		opts |= (POLOPT_TYPES|POLOPT_ROLES|POLOPT_CLASSES);
	if(POLOPT_USERS & opts)
		opts |= POLOPT_ROLES;
	if(POLOPT_ROLES & opts)
		opts |= POLOPT_TYPES;
	if(POLOPT_INITIAL_SIDS & opts)
		opts |= (POLOPT_TYPES|POLOPT_ROLES|POLOPT_USERS);
	if(POLOPT_OBJECTS & opts)
		opts |= POLOPT_OBJECTS;
	
	return opts;
}

/* returns:
 *  0	success
 *  1	invalid options combination
 * -1	general error
 */
int open_partial_policy(const char* filename, unsigned int options, policy_t **policy)
{
	int rt;
	unsigned int opts;
	
	opts = validate_policy_options(options);
	
	if(policy == NULL)
		return -1;
	*policy = NULL;
	rt = init_policy(policy);
	if(rt != 0) {
		fprintf(stderr, "error initializing policy\n");
		return -1;
	}
	(*policy)->opts = opts;
	yyin = fopen(filename, "r");
	if (yyin == NULL) {
		fprintf(stderr, "Could not open policy %s!\n", filename);
		return -1;
	}
	if(ap_is_file_binpol(yyin)) {
		rt = ap_read_binpol_file(yyin, opts, *policy);
		if(rt != 0) {
			fclose(yyin);
			return rt;
		}
	}
	else {
	
#ifdef APOL_PERFORM_TEST
	/*  test policy load performance; it's an undocumented feature only in test builds */
		{
		clock_t start,  stop;
		double time;
		start = clock();	
		rt = read_policy(*policy);
		stop = clock();
		time = ((double) (stop - start)) / CLOCKS_PER_SEC;
		fprintf(stdout, "\nTime to load policy %s: %f\n\n", filename, time);
		}
#else
		rt = read_policy(*policy);
#endif
		if(rt != 0) {
			fprintf(stderr, "error reading policy\n");
			fclose(yyin);
			return -1;	
		}
	}
	fclose(yyin);
	return 0;
}

/* opens the entire policy */
int open_policy(const char* filename, policy_t **policy)
{
	return open_partial_policy(filename, POLOPT_ALL, policy);
}

