/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* sesearch.c: command line tool to search TE rules.
 */
 
/* libapol */
#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>
#include <render.h>

/* other */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#define _GNU_SOURCE
#include <getopt.h>

/* The following should be defined in the make environment */
#ifndef SESEARCH_VERSION_NUM
	#define SESEARCH_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2003-2004 Tresys Technology, LLC"

char policy_file[BUF_SZ];

static struct option const longopts[] =
{
  {"source", required_argument, NULL, 's'},
  {"target", required_argument, NULL, 't'},
  {"class", required_argument, NULL, 'c'},
  {"perms", required_argument, NULL, 'p'},
  {"defaultto", required_argument, NULL, 'd'},
  {"allow", no_argument, NULL, 'A'},
  {"neverallow", no_argument, NULL, 'N'},
  {"audit", no_argument, NULL, 'U'},
  {"type", no_argument, NULL, 'T'},
  {"all", no_argument, NULL, 'a'},
  {"lineno", no_argument, NULL, 'l'},
  {"indirect", no_argument, NULL, 'i'},
  {"noregex", no_argument, NULL, 'n'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};

void usage(const char *program_name, int brief)
{
	printf("%s (sesearch ver. %s)\n\n", COPYRIGHT_INFO, SESEARCH_VERSION_NUM);
	printf("Usage: %s [OPTIONS] [POLICY_FILE]\n", program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Search Type Enforcement rules in an SELinux policy.\n\
  -s NAME, --source NAME  find rules with NAME type/attrib (regex) as source\n\
  -t NAME, --target NAME  find rules with NAME type/attrib (regex) as target\n\
  -c NAME, --class NAME   find rules with NAME as the object class\n\
  -p P1[,P2,...] --perms P1[,P2...]\n\
                         find rules with the specified permissions\n\
", stdout);
	fputs("\
  --allow                search for allow rules only \n\
  --neverallow           search for neverallow rules only\n\
  --audit                search for auditallow and dontaudit rules only\n\
  --type                 search for type_trans and type_change rules only\n\
", stdout);
	fputs("\
  -i, --indirect         indirect; also search for the type's attributes\n\
  -n, --noregex          do not use regular expression to match type/attributes\n\
  -a, --all              show all rules regardless of type, class, or perms\n\
  -l, --lineno           include line # in policy.conf for each rule\n\n\
  -d[POLICYTYPE], --defaultto[=POLICYTYPE] \n\
  			 default to policy type (POLICYTYPE=source|binary)\n\
  -h, --help             display this help and exit\n\
  -v, --version          output version information and exit\n\
", stdout);
  	fputs("\n\
If none of -s, -t, -c, -p are specified, then all rules are shown\n\
You specify -a (--all), or one of more of --allow, --neverallow, \n\
--audit, or --type.\
\n\n\
For -d, if no POLICY_FILE is provided, sesearch will attempt to use the \n\
specified system default policy type. Without the -d option, if no \n\
POLICY_FILE is provided, sesearch will attempt to use the installed \n\
binary policy and if this cannot be found, it will attempt to \n\
use the default source policy:\n\
", stdout);
	printf("      %s\n\n", LIBAPOL_DEFAULT_POLICY);

	return;
}


int main (int argc, char **argv)
{
	int i, rt, optc, cls, idx, *perms, num_perms;
	bool_t all, lineno, indirect, allow, nallow, audit, type, useregex;
	unsigned int open_opts = 0;
	policy_t *policy;
	char *src_name, *tgt_name, *class_name, *permlist, *tok, *rule;
	teq_query_t q;
	teq_results_t r;
	bool_t try_binary = FALSE, try_source = FALSE;
	
	all = lineno = allow = nallow = audit = type = indirect = FALSE;
	useregex = TRUE;
	cls = -1;
	num_perms = 0;
	perms = NULL;
	src_name = tgt_name = class_name = permlist = NULL;
	
	open_opts = POLOPT_TE_POLICY | POLOPT_OBJECTS;
	
	while ((optc = getopt_long (argc, argv, "s:t:c:p:d:alhvni", longopts, NULL)) != -1)  {
		switch (optc) {
		case 0:
	  		break;
	  	case 's': /* source */
	  		if(optarg == 0) {
	  			usage(argv[0], 1);
	  			printf("Missing source type/attribute for -s (--source)\n");
	  			exit(1);
	  		}
	  		src_name = strdup(optarg);
	  		if (!src_name) {
	  			fprintf(stderr, "Memory error!\n");
	  			exit(1);	
	  		}
	  		break;
	  	case 't': /* target */
	  		if(optarg == 0) {
	  			usage(argv[0], 1);
	  			printf("Missing target type/attribute for -t (--target)\n");
	  			exit(1);
	  		}
	  		tgt_name = strdup(optarg);
	  		if (!tgt_name) {
	  			fprintf(stderr, "Memory error!\n");
	  			exit(1);	
	  		}
	  		break;
	  	case 'c': /* class */
	  		if(optarg == 0) {
	  			usage(argv[0], 1);
	  			printf("Missing object class for -c (--class)\\n");
	  			exit(1);
	  		}
	  		class_name = strdup(optarg);
	  		if (!class_name) {
	  			fprintf(stderr, "Memory error!\n");
	  			exit(1);	
	  		}
	  		break;
	  	case 'p': /* permissions */
	  		if(optarg == 0) {
	  			usage(argv[0], 1);
	  			printf("Missing permissions for -p (--perms)\n\n");
	  			exit(1);
	  		}
	  		permlist = strdup(optarg);
	  		if (!permlist) {
	  			fprintf(stderr, "Memory error!\n");
	  			exit(1);	
	  		}
	  		break;
	  	case 'd': /* default to policy type */
	  		if(optarg != 0) {
	 			if (strcasecmp("source", optarg) == 0) 
	  				try_source = TRUE;
	  			else if (strcasecmp("binary", optarg) == 0) 
	  				try_binary = TRUE;
	  		}
	  		break;
	  	case 'i': /* indirect search */
	  		indirect = TRUE;
	  		break;
	  	case 'n': /* no regex */
	  		useregex = FALSE;
	  		break;
	  	case 'A': /* allow */
	  		allow = TRUE;
	  		break;
	  	case 'N': /* neverallow */
	  		nallow = TRUE;
	  		break;
	  	case 'U': /* audit */
	  		audit = TRUE;
	  		break;
	  	case 'T': /* type */
	  		type = TRUE;
	  		break;
	  	case 'a': /* all */
	  		all = TRUE;
	  		open_opts = POLOPT_ALL;
	  		break;
	  	case 'l': /* lineno */
	  		lineno = TRUE;
	  		break;
	  	case 'h': /* help */
	  		usage(argv[0], 0);
	  		exit(0);
	  	case 'v': /* version */
	  		printf("\n%s (sesearch ver. %s)\n\n", COPYRIGHT_INFO, SESEARCH_VERSION_NUM);
	  		exit(0);
	  	default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}
	if(!(allow || nallow || audit || type || all )) {
		usage(argv[0], 1);
		printf("Either -a (--all), or one of --allow, --type, --audit, or\n     --type mustbe specified\n\n");
		exit(1);
	}
		
	if (argc - optind > 1) {
		usage(argv[0], 1);
		exit(1);
	} else if(argc - optind < 1) {
		if (try_binary) {
			rt = find_default_policy_file(SEARCH_BINARY, policy_file);
		} else if (try_source) {
			rt = find_default_policy_file(SEARCH_SOURCE, policy_file);
		} else {
			rt = find_default_policy_file(SEARCH_BOTH, policy_file);
		}
		if (rt != 0) {
			printf("Error while searching for default policy: %s\n", decode_find_default_policy_file_err(rt));
			exit(1);
		}
	} else 
		snprintf(policy_file, sizeof(policy_file)-1, "%s", argv[optind]);

	/* attempt to open the policy */
	rt = open_partial_policy(policy_file, open_opts, &policy);
	if(rt != 0)
		exit(1);
	
	/* form query */
	init_teq_query(&q);
	
	if(permlist != NULL) {
		for(tok = strtok(permlist, ","); tok != NULL; tok = strtok(NULL, ",")) {
			idx = get_perm_idx(tok, policy);
			if(idx < 0) {
				printf("Permission name (%s) is not a valid permission\n", tok);
				close_policy(policy);
				exit(1);
			}
			add_i_to_a(idx, &num_perms, &perms);
		}
		free(permlist);
	}
	
	if(all) 
		q.rule_select = TEQ_ALL;
	else {
		q.rule_select = TEQ_NONE;
		if(allow)
			q.rule_select |= TEQ_ALLOW;
		if(nallow)
			q.rule_select |= TEQ_NEVERALLOW;
		if(audit)
			q.rule_select |= TEQ_AV_AUDIT;
		if(type)
			q.rule_select |= TEQ_TYPE;
	}
	q.use_regex = useregex;
	q.any = FALSE;
	q.ta1.indirect = q.ta2.indirect = indirect;
	q.ta1.t_or_a = q.ta2.t_or_a = IDX_BOTH;
	q.ta1.ta = src_name;
	q.ta2.ta = tgt_name;
	q.num_perms = num_perms;
	q.perms = perms;
	
	if(class_name != NULL) {
		cls = get_obj_class_idx(class_name, policy);
		if(cls < 0) {
			printf("Invalid class name: %s\n", class_name);
			free_teq_query_contents(&q);
			exit(1);
		}
		q.classes = &cls;
		q.num_classes = 1;
	}

	
	/* display requested info */
	init_teq_results(&r);
	rt = search_te_rules(&q, &r, policy);
	if(rt == -1) {
		printf("Unexpected error (-1) searching rules\n");
		free_teq_query_contents(&q);
		free_teq_results_contents(&r);
		close_policy(policy);
		exit(1);
	}
	else if(rt == -2) {
		switch(r.err) {
		case TEQ_ERR_TA1_REGEX:
			printf("%s\n", r.errmsg);
			break;
		case TEQ_ERR_TA2_REGEX:
			printf("%s\n", r.errmsg);
			break;
		case TEQ_ERR_TA3_REGEX:
			printf("%s\n", r.errmsg);
			break;
		case TEQ_ERR_TA1_INVALID:
			printf("Source is not a valid type nor attribute\n");
			break;
		case TEQ_ERR_TA2_INVALID:
			printf("Target is not a valid type nor attribute\n");
			break;
		case TEQ_ERR_TA3_INVALID:
			printf("Default is not a valid type nor attribute\n");
			break;
		case TEQ_ERR_TA1_STRG_SZ:
			printf("Source string is too large\n");
			break;
		case TEQ_ERR_TA2_STRG_SZ:
			printf("Target string is too large\n");
			break;
		case TEQ_ERR_TA3_STRG_SZ:
			printf("Default string is too large\n");
			break;
		case TEQ_ERR_INVALID_CLS_Q:
			printf("The list of classes is incoherent\n");
			break;
		case TEQ_ERR_INVALID_PERM_Q:
			printf("The list of permissions is incoherent\n");
			break;
		case TEQ_ERR_INVALID_CLS_IDX:
			printf("One of the class indicies is incorrect\n");
			break;
		case TEQ_ERR_INVALID_PERM_IDX:
			printf("One of the permission indicies is incorrect\n");
			break;
		default:
			printf("Unexpected error (-2) searching rules\n");
			break;
		}
		free_teq_query_contents(&q);
		free_teq_results_contents(&r);
		close_policy(policy);
		exit(1);
	}
	printf("\n%d Rules match your search criteria\n", r.num_av_access+r.num_av_audit+r.num_type_rules);
	if(r.num_av_access > 0) {
		for(i = 0; i < r.num_av_access; i++) {
			rule = re_render_av_rule(FALSE, r.av_access[i], FALSE, policy);
			assert(rule);
			if(lineno)
				printf("[%6d]  ", r.av_access_lineno[i]);
			printf("%s\n", rule);
			free(rule);

		}
	}
	if(r.num_av_audit > 0) {
		for(i = 0; i < r.num_av_audit; i++) {
			rule = re_render_av_rule(FALSE, r.av_audit[i], TRUE, policy);
			assert(rule);
			if(lineno)
				printf("[%6d]  ", r.av_audit_lineno[i]);
			printf("%s\n", rule);
			free(rule);

		}
	}
	if(r.num_type_rules > 0) { 
		for(i = 0; i < r.num_type_rules; i++) {
			rule = re_render_tt_rule(FALSE, r.type_rules[i], policy);
			assert(rule);
			if(lineno)
				printf("[%6d]  ", r.type_lineno[i]);
			printf("%s\n", rule);
			free(rule);

		}
	}

	free_teq_query_contents(&q);
	free_teq_results_contents(&r);
	close_policy(policy);
	exit(0);
}


