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
#ifdef APOL_PERFORM_TEST
#include <time.h>
#endif

/* externs mostly with yacc parser */
extern policy_t *parse_policy; /* parser using a global policy which we must set here */
extern unsigned int policydb_lineno;
extern queue_t id_queue;
extern FILE *yyin;
extern int yyparse(void);
extern void yyrestart(FILE *);
extern unsigned int pass;
extern int yydebug;

int close_policy(policy_t *policy)
{
	return free_policy(&policy);
}

static int read_policy(policy_t *policy)
{
	//yydebug = 1;
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
		fprintf(stderr, "Could not open policy!\n");
		return -1;
	}
	
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
	fclose(yyin);
	return 0;
}

/* opens the entire policy */
int open_policy(const char* filename, policy_t **policy)
{
	return open_partial_policy(filename, POLOPT_ALL, policy);
}

