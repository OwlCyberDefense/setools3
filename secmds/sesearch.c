/* Copyright (C) 2003-2005 Tresys Technology, LLC
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

#define COPYRIGHT_INFO "Copyright (C) 2003-2005 Tresys Technology, LLC"

char *policy_file = NULL;

static struct option const longopts[] =
{
  {"source", required_argument, NULL, 's'},
  {"target", required_argument, NULL, 't'},
  {"class", required_argument, NULL, 'c'},
  {"perms", required_argument, NULL, 'p'},
  {"boolean", required_argument, NULL, 'b'},
  {"allow", no_argument, NULL, 'A'},
  {"neverallow", no_argument, NULL, 'N'},
  {"audit", no_argument, NULL, 'U'},
  {"type", no_argument, NULL, 'T'},
  {"all", no_argument, NULL, 'a'},
  {"lineno", no_argument, NULL, 'l'},
  {"show_cond", no_argument, NULL, 'C'},
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
  -b NAME, --boolean NAME find conditional rules with NAME in the expression\n\
", stdout);
	fputs("\
  --allow                 search for allow rules only \n\
  --neverallow            search for neverallow rules only\n\
  --audit                 search for auditallow and dontaudit rules only\n\
  --type                  search for type_trans and type_change rules only\n\
", stdout);
	fputs("\
  -i, --indirect          indirect; also search for the type's attributes\n\
  -n, --noregex           do not use regular expression to match type/attributes\n\
  -a, --all               show all rules regardless of type, class, or perms\n\
  -l, --lineno            include line # in policy.conf for each rule.\n\
  			  This option is ignored if using a binary policy.\n\
  -C, --show_cond         show conditional expression for conditional rules\n\
  -h, --help              display this help and exit\n\
  -v, --version           output version information and exit\n\
", stdout);
  	fputs("\n\
If none of -s, -t, -c, -p -b are specified, then all rules are shown\n\
You must specify -a (--all), or one of more of --allow, --neverallow, \n\
--audit, or --type.\
\n\n\
The default source policy, or if that is unavailable the default binary\n\
 policy, will be opened if no policy file name is provided.\n", stdout);
	return;
}


int main (int argc, char **argv)
{
	int i, rt, optc, cls, idx, *perms, num_perms;
	bool_t all, lineno, indirect, allow, nallow, audit, type, useregex, show_cond;
	unsigned int open_opts = 0;
	policy_t *policy;
	char *src_name, *tgt_name, *class_name, *permlist, *tok, *rule, *bool_name, *cond_expr;
	teq_query_t q;
	teq_results_t r;
	unsigned int search_opts = 0;
	
	all = lineno = allow = nallow = audit = type = indirect = show_cond = FALSE;
	useregex = TRUE;
	cls = -1;
	num_perms = 0;
	perms = NULL;
	src_name = tgt_name = class_name = permlist = bool_name = NULL;
	
	open_opts = POLOPT_TE_POLICY | POLOPT_OBJECTS;
	
	while ((optc = getopt_long (argc, argv, "s:t:c:p:b:d:alChvni0:", longopts, NULL)) != -1)  {
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
	  			printf("Missing object class for -c (--class)\n");
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
	  			printf("Missing permissions for -p (--perms)\n");
	  			exit(1);
	  		}
	  		permlist = strdup(optarg);
	  		if (!permlist) {
	  			fprintf(stderr, "Memory error!\n");
	  			exit(1);	
	  		}
	  		break;
		case 'b':
	  		if(optarg == 0) {
	  			usage(argv[0], 1);
	  			printf("Missing boolean for -b (--boolean)\n");
	  			exit(1);
	  		}
	  		bool_name = strdup(optarg);
	  		if (!bool_name) {
	  			fprintf(stderr, "Memory error!\n");
	  			exit(1);	
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
		case 'C':
			show_cond = TRUE;
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
	if (!search_opts)
		search_opts = (POL_TYPE_SOURCE | POL_TYPE_BINARY);
		
	if (argc - optind > 1) {
		usage(argv[0], 1);
		exit(1);
	} else if(argc - optind < 1) {
		rt = find_default_policy_file(search_opts, &policy_file);
		if (rt != FIND_DEFAULT_SUCCESS) {
			printf("Default policy search failed: %s\n", find_default_policy_file_strerr(rt));
			exit(1);
		}
	} else 
		policy_file = argv[optind];

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
	q.bool_name = bool_name;
	
	if(class_name != NULL) {
		q.classes = (int *)malloc(sizeof(int)*1);
		if (q.classes == NULL) {
			printf("out of memory\n");
			free_teq_query_contents(&q);
			exit(1);
		}
		q.classes[0] = get_obj_class_idx(class_name, policy);
		if (q.classes[0] < 0) {
			printf("Invalid class name: %s\n", class_name);
			free_teq_query_contents(&q);
			exit(1);
		}
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
			if(show_cond && policy->av_access[r.av_access[i]].cond_expr != -1)
				printf("%c  ", policy->av_access[r.av_access[i]].cond_list?'T':'F');
			else if (show_cond)
				printf("   ");
			if(lineno && !is_binary_policy(policy))
				printf("[%7d]  ", r.av_access_lineno[i]);
			printf("%s", rule);
			free(rule);
			if(show_cond && policy->av_access[r.av_access[i]].cond_expr != -1) {
				printf(" %s", (cond_expr = re_render_cond_expr(policy->av_access[r.av_access[i]].cond_expr, policy)));
				free(cond_expr);
			}
			printf("\n");

		}
	}
	if(r.num_av_audit > 0) {
		for(i = 0; i < r.num_av_audit; i++) {
			rule = re_render_av_rule(FALSE, r.av_audit[i], TRUE, policy);
			assert(rule);
			if(show_cond && policy->av_audit[r.av_audit[i]].cond_expr != -1)
				printf("%c  ", policy->av_audit[r.av_audit[i]].cond_list?'T':'F');
			else if (show_cond)
				printf("   ");
			if(lineno && !is_binary_policy(policy))
				printf("[%7d]  ", r.av_audit_lineno[i]);
			printf("%s", rule);
			free(rule);
			if(show_cond && policy->av_audit[r.av_audit[i]].cond_expr != -1) {
				printf(" %s", (cond_expr = re_render_cond_expr(policy->av_audit[r.av_audit[i]].cond_expr, policy)));
				free(cond_expr);
			}
			printf("\n");
		}
	}
	if(r.num_type_rules > 0) { 
		for(i = 0; i < r.num_type_rules; i++) {
			rule = re_render_tt_rule(FALSE, r.type_rules[i], policy);
			assert(rule);
			if (show_cond && policy->te_trans[r.type_rules[i]].cond_expr != -1)
				printf("%c  ", policy->te_trans[r.type_rules[i]].cond_list?'T':'F');
			else if (show_cond)
				printf("   ");
			if(lineno && !is_binary_policy(policy))
				printf("[%7d]  ", r.type_lineno[i]);
			printf("%s", rule);
			free(rule);
			if (show_cond && policy->te_trans[r.type_rules[i]].cond_expr != -1) {
				printf(" %s", (cond_expr = re_render_cond_expr(policy->te_trans[r.type_rules[i]].cond_expr, policy)));
			}
			printf("\n");
		}
	}

	free_teq_query_contents(&q);
	free_teq_results_contents(&r);
	close_policy(policy);
	exit(0);
}


