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
#include <assert.h>
#ifdef APOL_PERFORM_TEST
#include <time.h>
#endif

#ifndef LIBAPOL_POLICY_INSTALL_DIR
	#define LIBAPOL_POLICY_INSTALL_DIR "/etc/security/selinux"
#endif

#ifndef LIBAPOL_SELINUX_DIR
	#define LIBAPOL_SELINUX_DIR "/selinux"
#endif

/* Defines for find_default_policy_file() function. */
#define GENERAL_ERROR	 		-1
#define POLICY_FILE_DOES_NOT_EXIST 	-2
#define POLICY_VER_FILE_DOES_NOT_EXIST	-3
#define NOT_SELINUX_AWARE		-4
#define READ_POLICY_VER_FILE_ERROR	-5

/* Error TEXT definitions for decoding the above error definitions. */
#define TEXT_POLICY_FILE_DOES_NOT_EXIST		"Policy file(s) does not exist.\n"
#define TEXT_POLICY_VER_FILE_DOES_NOT_EXIST	"Selinux policy version file does not exist.\n"
#define TEXT_NOT_SELINUX_AWARE			"This is not an selinux system.\n"
#define TEXT_READ_POLICY_VER_FILE_ERROR		"Cannot read selinux policy version file.\n"
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
const char* decode_find_default_policy_file_err(int err)
{
	switch(err) {
	case POLICY_FILE_DOES_NOT_EXIST:
		return TEXT_POLICY_FILE_DOES_NOT_EXIST;
	case POLICY_VER_FILE_DOES_NOT_EXIST:
		return TEXT_POLICY_VER_FILE_DOES_NOT_EXIST;
	case NOT_SELINUX_AWARE:
		return TEXT_NOT_SELINUX_AWARE;
	case READ_POLICY_VER_FILE_ERROR:
		return TEXT_READ_POLICY_VER_FILE_ERROR;
	default:
		return TEXT_GENERAL_ERROR_TEXT;
	}
}

static int search_binary_policy_file(char *policy_file_path)
{
	int rt, len;
	char *version = NULL;
	char policy_version_file[BUF_SZ], buf[BUF_SZ];
	
     	/* a. Check /selinux/policyvers for the currently loaded policy version */ 
     	snprintf(policy_version_file, BUF_SZ-1, "%s/policyvers", LIBAPOL_SELINUX_DIR);
	rt = access(policy_version_file, F_OK);
	if (rt != 0) {
		return POLICY_VER_FILE_DOES_NOT_EXIST;
     	}
     	
     	/* b. Read in the loaded policy version number. */
	rt = read_file_to_buffer(policy_version_file, &version, &len);
	if (rt != 0) {
		if (version)
			free(version);
		return READ_POLICY_VER_FILE_ERROR;
	}
	/* c. See if policy.VERSION exists in the policy install directory. */
	snprintf(buf, sizeof(buf)-1, "%s/policy.%s", LIBAPOL_POLICY_INSTALL_DIR, version);
	rt = access(buf, R_OK);
	if (rt != 0) {
		return POLICY_FILE_DOES_NOT_EXIST;
     	}
	free(version);
	snprintf(policy_file_path, BUF_SZ-1, "%s", buf);
	return 0;
}

static int search_policy_src_file(char *policy_file_path)
{	
	int rt;
	
	/* Check if the default policy source file exists. */
	rt = access(LIBAPOL_DEFAULT_POLICY, F_OK);
	if (rt != 0) {
		return POLICY_FILE_DOES_NOT_EXIST;
     	}
	snprintf(policy_file_path, BUF_SZ-1, "%s", LIBAPOL_DEFAULT_POLICY);

	return 0;
}

/* Find the installed policy file using our built-in search order. 
 * This function returns a file path string. This function takes 
 * 2 arguments: 
 *
 * 	1. a pointer to a buffer to store the policy file path
 *	2. search option:
 * 		a. SEARCH_BINARY - search binary policy file.
 *		b. SEARCH_SOURCE - search for default policy source file.
 *		c. SEARCH_BOTH - search for binary first and if this doesn't
 *		   exist, search for the default policy source file defined in
 *		   libapol.
 */
int find_default_policy_file(int search_opt, char *policy_file_path)
{
	int rt;
	
	assert(search_opt > 0 && search_opt <= 3 && policy_file_path != NULL);

	/* 1. See if selinux-aware. */ 
	rt = access(LIBAPOL_POLICY_INSTALL_DIR, F_OK);
	if (rt != 0) {
		return NOT_SELINUX_AWARE;
     	}    

        switch (search_opt) {
     	case SEARCH_BINARY:
	     	rt = search_binary_policy_file(policy_file_path);
	     	if (rt != 0) {
	     		return rt;
	     	}
		break;
	case SEARCH_SOURCE:
		rt = search_policy_src_file(policy_file_path);
		if (rt != 0) {
	     		return rt;
	     	}
		break;
	case SEARCH_BOTH: 
		/* Search for binary policy file FIRST. */
		rt = search_binary_policy_file(policy_file_path);
		if (rt != 0) {
			if (rt == POLICY_FILE_DOES_NOT_EXIST || rt == POLICY_VER_FILE_DOES_NOT_EXIST) {
		     		rt = search_policy_src_file(policy_file_path);
				if (rt != 0) {
			     		return rt;
			     	}	
			} else 
				return rt;
	     	} 
		break;
	default: 
		fprintf(stderr, "Invalid search option provided to find_default_policy_file()\n");
		return GENERAL_ERROR;
	}
	return 0;
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

