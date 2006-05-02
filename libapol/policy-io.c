/* Copyright (C) 2001-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com
 * Modified: don.patterson@tresys.com - added default policy search implementation.
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
	FILE *policy_fp = NULL;
	int ret_version;
	
	assert(policy_fname != NULL && version != NULL);
	policy_fp = fopen(policy_fname, "r");
	if (policy_fp == NULL) {
		fprintf(stderr, "Could not open policy %s!\n", policy_fname);
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

int close_policy(policy_t *policy)
{
	return free_policy(&policy);
}

/* external functions from the parser to handle start state changes 
 * for each pass (initial for passes 1 &2 and optonly for all other passes) */
extern int yybegin_optonly(void);
extern int yybegin_initial(void);

static int resolve_optionals(policy_t *policy)
{
	int changed = 0;
	ap_optional_t *opt = NULL;

	for (opt=policy->optionals; opt; opt = opt->next) {
		if (opt->status != OPTIONAL_STATUS_UNDECIDED)
			continue;
		if(ap_optional_check_requires(opt, policy) > 0) {
			changed = 1;
			opt->status = OPTIONAL_STATUS_TAKE_MAIN;
		}
	}

	return changed;
}

static void take_else(policy_t *policy)
{
	ap_optional_t *opt = NULL;

	for (opt = policy->optionals; opt; opt = opt->next)
		if (opt->status == OPTIONAL_STATUS_UNDECIDED)
			opt->status = OPTIONAL_STATUS_TAKE_ELSE;
}

static int reparse(policy_t *policy)
{
	int rt;
	policydb_lineno = 1;
		pass++;
		rewind(yyin);
		yyrestart(yyin);	
		if ((rt = yyparse())) {
			fprintf(stderr, "error(s) encountered while parsing configuration (fourth+ pass, line: %d)\n", policydb_lineno);
			queue_destroy(id_queue);
			rewind(yyin);
			yyrestart(yyin);	
			return rt;
		}
	return 0;
}

static int read_policy(policy_t *policy)
{
	int rt, i, changed = 0;
	ap_mls_level_t *lvl = NULL;
	
	policy->policy_type = POL_TYPE_SOURCE;
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
	yybegin_initial();
	if ((rt = yyparse())) {
		fprintf(stderr, "error(s) encountered while parsing configuration (first pass, line: %d)\n", policydb_lineno);
		queue_destroy(id_queue);
		rewind(yyin);
		yyrestart(yyin);	
		return rt;
	}
	
	/* If we don't need anything from pass 2, just return and save the time */
	if(!(policy->opts & PLOPT_PASS_2)) {
		queue_destroy(id_queue);
		return 0;
	}
		
	policydb_lineno = 1;
	pass = 2;
	rewind(yyin);
	yyrestart(yyin);	
	if ((rt = yyparse())) {
		fprintf(stderr, "error(s) encountered while parsing configuration (second pass, line: %d)\n", policydb_lineno);
		queue_destroy(id_queue);
		rewind(yyin);
		yyrestart(yyin);	
		return rt;
	}

	if(policy->has_optionals) {
		policydb_lineno = 1;
		pass = 3;
		rewind(yyin);
		yyrestart(yyin);	
		yybegin_optonly();
		if ((rt = yyparse())) {
			fprintf(stderr, "error(s) encountered while parsing configuration (third pass, line: %d)\n", policydb_lineno);
			queue_destroy(id_queue);
			rewind(yyin);
			yyrestart(yyin);	
			return rt;
		}

		/* Pass 4+ */
		do {
			changed = resolve_optionals(policy);
			if((rt=reparse(policy)))
				return rt;
		} while (changed);
		take_else(policy);
		reparse(policy);
	}

	queue_destroy(id_queue);
	/* Kludge; now check for policy version 18 but special permission defined (i.e., if
	 * nlmsg_write or nlmsg_write are defined as permissions, than the version is at least
	 * 18.  No where else do we check for version 18 in source policies! */
	#define OPEN_PERM_CHECK_18 "nlmsg_write"
	rt = get_perm_idx(OPEN_PERM_CHECK_18, policy);
	if(rt >= 0) { /* permission does exists; at least a version 18 policy */
		rt = set_policy_version(POL_VER_18_20, policy);
		if(rt < 0) {
			fprintf(stderr, "error setting policy version to version 18.\n");
			return -1;
		}
	}

	/* ensure all sensitivities have a level if not
	 * do what checkpolicy does: create one with an
	 * empty category list */
	if (is_mls_policy(policy)) {
		for (i = 0; i < policy->num_sensitivities; i++) {
			if (!(lvl = ap_mls_sensitivity_get_level(i, policy))) {
				if (add_mls_level(i, NULL, 0, policy)) {
					fprintf(stderr, "error adding implicit level for sensitivity %s\n", policy->sensitivities[i].name);
					return -1;
				}
			}
		}
	}

	return 0;		
}

/* checks for acceptable combinations, and adjusts the mask accordingly */
unsigned int validate_policy_options(unsigned int options)
{
	unsigned int opts = options;

	/* always include the basic conditional pieces */
	opts |= (POLOPT_COND_BOOLS|POLOPT_COND_EXPR);

	/* NOTE: The order of these is important */
	if(POLOPT_COND_TE_RULES & opts)
		opts |= POLOPT_TYPES|POLOPT_OBJECTS;	
	if(POLOPT_TE_RULES & opts)
		opts |= (POLOPT_OBJECTS|POLOPT_TYPES);
	if(POLOPT_PERMS & opts)
		opts |= POLOPT_CLASSES;
	if(POLOPT_ROLE_RULES & opts)
		opts |= (POLOPT_TYPES|POLOPT_ROLES|POLOPT_CLASSES);
	if(POLOPT_USERS & opts)
		opts |= (POLOPT_ROLES|POLOPT_MLS_COMP);
	if(POLOPT_ROLES & opts)
		opts |= POLOPT_TYPES;
	if(POLOPT_INITIAL_SIDS & opts)
		opts |= (POLOPT_TYPES|POLOPT_ROLES|POLOPT_USERS|POLOPT_MLS_COMP);
	if(POLOPT_OCONTEXT & opts)
		opts |= (POLOPT_TYPES|POLOPT_ROLES|POLOPT_USERS|POLOPT_MLS_COMP);
	if(POLOPT_OBJECTS & opts)
		opts |= POLOPT_OBJECTS;
	if(POLOPT_CONSTRAIN & opts)
		opts |= POLOPT_SYMBOLS;
	if(POLOPT_RANGETRANS & opts)
		opts |= (POLOPT_MLS_COMP|POLOPT_TYPES);
	
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
	struct stat buf;

	/* To support optionals and the transition to 3.0 disable opening 
	 * only part of a policy .*/	
	/*	opts = validate_policy_options(options);*/
	opts = POLOPT_ALL;
	
	if(policy == NULL)
		return -1;
	*policy = NULL;
	rt = init_policy(policy);
	if(rt != 0) {
		fprintf(stderr, "error initializing policy\n");
		return -1;
	}
	(*policy)->opts = opts;
	rt = stat(filename, &buf);
	if (rt < 0) {
		fprintf(stderr, "Could not open policy %s!\n",filename);
		return -1;
	} else {
		/* ensure this is a regular file ie. not a directory, blk_file etc. */
		if (!S_ISREG(buf.st_mode)) {
			fprintf(stderr, "Could not open policy %s, not a regular file!\n", filename);
			return -1;
		}
	}
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
			return rt;	
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

/******************** new policy reading below ********************/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sepol/policydb_extend.h>

#include "policy.h"
#include "policy-io.h"

__attribute__ ((format (printf, 3, 4)))
static void sepol_handle_route_to_callback(void *varg, sepol_handle_t *handle,
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

int apol_policy_open_binary(const char *path,
			    apol_policy_t **policy)
{
	int retv = 0;
	FILE *infile = NULL;
	sepol_policy_file_t *pfile = NULL;

	if ((*policy = calloc(1, sizeof(**policy))) == NULL) {
		fprintf(stderr, "Out of memory!\n");
		return -1;
	}
	(*policy)->msg_callback = apol_handle_default_callback;
	(*policy)->msg_callback_arg = (*policy);

	(*policy)->sh = sepol_handle_create();
	if ((*policy)->sh == NULL) {
		ERR(*policy, "Error creating sepol policy handle.\n");
		return -1;
	}
	sepol_handle_set_callback((*policy)->sh, sepol_handle_route_to_callback, (*policy));

	retv = sepol_policydb_create(&(*policy)->p);
	if (retv) {
		ERR(*policy, "Error creating policy database.\n");
		goto open_policy_error;
	}

	retv = sepol_policy_file_create(&pfile);
	if (retv) {
		ERR(*policy, "Error creating policy file.\n");
		goto open_policy_error;
	}

	infile = fopen(path, "rb");
	if (!infile) {
		ERR(*policy, "Error: unable to open %s: ", path); /* no new line */
		perror(NULL);
		goto open_policy_error;
	}

	sepol_policy_file_set_fp(pfile, infile);
	sepol_policy_file_set_handle(pfile, (*policy)->sh);

	retv = sepol_policydb_read((*policy)->p, pfile);
	if (retv) {
		goto open_policy_error;
	}

	if (sepol_policydb_extend((*policy)->sh, (*policy)->p, NULL)) {
		goto open_policy_error;
	}

open_policy_done:
	sepol_policy_file_free(pfile);
	pfile = NULL;
	fclose(infile);

	return retv;

open_policy_error:
	apol_policy_destroy(policy);
	goto open_policy_done;
}

void apol_policy_destroy(apol_policy_t **policy)
{
	if (policy != NULL && *policy != NULL) {
		sepol_policydb_free((*policy)->p);
		sepol_handle_destroy((*policy)->sh);
		free(*policy);
		*policy = NULL;
	}
}
