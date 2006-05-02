/* Copyright (C) 2003-2006 Tresys Technology, LLC
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

#define COPYRIGHT_INFO "Copyright (C) 2003-2006 Tresys Technology, LLC"

char *policy_file = NULL;

static struct option const longopts[] =
{
  {"source", required_argument, NULL, 's'},
  {"target", required_argument, NULL, 't'},
  {"role_source", required_argument, NULL, 'r'},
  {"role_target", required_argument, NULL, 'g'},
  {"class", required_argument, NULL, 'c'},
  {"perms", required_argument, NULL, 'p'},
  {"boolean", required_argument, NULL, 'b'},
  {"allow", no_argument, NULL, 'A'},
  {"neverallow", no_argument, NULL, 'N'},
  {"audit", no_argument, NULL, 'U'},
  {"rangetrans", no_argument, NULL, 'R'},
  {"all", no_argument, NULL, 'a'},
  {"type", no_argument, NULL, 'T'},
  {"role_allow", no_argument, NULL, 'L'},
  {"role_trans", no_argument, NULL, 'o'},
  {"lineno", no_argument, NULL, 'l'},
  {"show_cond", no_argument, NULL, 'C'},
  {"indirect", no_argument, NULL, 'i'},
  {"noregex", no_argument, NULL, 'n'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};

typedef struct options {
	char *src_name;
	char *tgt_name;
	char *src_role_name;
	char *tgt_role_name;
	char *class_name;
	char *permlist;
	char *bool_name;
	bool_t all;
	bool_t lineno;
	bool_t indirect;
	bool_t allow;
	bool_t nallow;
	bool_t audit;
	bool_t type;
	bool_t rtrans;
	bool_t role_allow;
	bool_t role_trans;
	bool_t useregex;
	bool_t show_cond;
} options_t;

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
  --role_source NAME      find rules with NAME role (regex) as source\n\
  --role_target NAME      find rules with NAME role (regex) as target\n\
  -c NAME, --class NAME   find rules with NAME as the object class\n\
  -p P1[,P2,...] --perms P1[,P2...]\n\
                          find rules with the specified permissions\n\
  -b NAME, --boolean NAME find conditional rules with NAME in the expression\n\
", stdout);
	fputs("\
  --allow                 search for allow rules\n\
  --neverallow            search for neverallow rules\n\
  --audit                 search for auditallow and dontaudit rules\n\
  --type                  search for type_trans and type_change rules\n\
  --rangetrans            search for range transition rules\n\
  --role_allow            search for role allow rules\n\
  --role_trans            search for role transition rules\n\
  -a, --all               show all rules regardless of type, class, or perms\n\
", stdout);
	fputs("\
  -i, --indirect          indirect; also search for the type's attributes\n\
  -n, --noregex           do not use regular expression to match type/attributes\n\
  -l, --lineno            include line # in policy.conf for each rule.\n\
  			  This option is ignored if using a binary policy.\n\
  -C, --show_cond         show conditional expression for conditional rules\n\
  -h, --help              display this help and exit\n\
  -v, --version           output version information and exit\n\
", stdout);
  	fputs("\n\
If none of -s, -t, -c, -p, -b, --role_source, or --role_target\n\
are specified, then all rules are shown.\n\
You must specify -a (--all), or one of more of --allow, --neverallow, \n\
--audit, --rangetrans, --role_allow, --role_trans or --type.\n\
\n\
The default source policy, or if that is unavailable the default binary\n\
policy, will be opened if no policy file name is provided.\n", stdout);
	return;
}

static int perform_te_query(options_t *cmd_opts, teq_results_t *r, policy_t *policy)
{
	teq_query_t q;
	char *tok, *rule, *cond_expr;
	int rt, idx, *perms, num_perms;

	num_perms = 0;
	perms = NULL;
	tok = rule = cond_expr =  NULL;

	/* form query */
	init_teq_query(&q);
	
	if(cmd_opts->permlist != NULL) {
		for(tok = strtok(cmd_opts->permlist, ","); tok != NULL; tok = strtok(NULL, ",")) {
			idx = get_perm_idx(tok, policy);
			if(idx < 0) {
				printf("Permission name (%s) is not a valid permission\n", tok);
				close_policy(policy);
				return -1;
			}
			add_i_to_a(idx, &num_perms, &perms);
		}
		free(cmd_opts->permlist);
	}
	
	if(cmd_opts->all) 
		q.rule_select = TEQ_ALL;
	else {
		q.rule_select = TEQ_NONE;
		if(cmd_opts->allow)
			q.rule_select |= TEQ_ALLOW;
		if(cmd_opts->nallow)
			q.rule_select |= TEQ_NEVERALLOW;
		if(cmd_opts->audit)
			q.rule_select |= TEQ_AV_AUDIT;
		if(cmd_opts->type)
			q.rule_select |= TEQ_TYPE;
	}
	q.use_regex = cmd_opts->useregex;
	q.any = FALSE;
	q.ta1.indirect = q.ta2.indirect = cmd_opts->indirect;
	q.ta1.t_or_a = q.ta2.t_or_a = IDX_BOTH;
	q.ta1.ta = cmd_opts->src_name;
	q.ta2.ta = cmd_opts->tgt_name;
	q.num_perms = num_perms;
	q.perms = perms;
	q.bool_name = cmd_opts->bool_name;
	
	if(cmd_opts->class_name != NULL) {
		q.classes = (int *)malloc(sizeof(int)*1);
		if (q.classes == NULL) {
			printf("out of memory\n");
			return -1;
		}
		q.classes[0] = get_obj_class_idx(cmd_opts->class_name, policy);
		if (q.classes[0] < 0) {
			printf("Invalid class name: %s\n", cmd_opts->class_name);
			return -1;
		}
		q.num_classes = 1;
	}

	/* display requested info */
	rt = search_te_rules(&q, r, policy);
	if(rt == -1) {
		printf("Unexpected error (-1) searching rules\n");
		return -1;
	}
	else if(rt == -2) {
		switch(r->err) {
		case TEQ_ERR_TA1_REGEX:
			printf("%s\n", r->errmsg);
			break;
		case TEQ_ERR_TA2_REGEX:
			printf("%s\n", r->errmsg);
			break;
		case TEQ_ERR_TA3_REGEX:
			printf("%s\n", r->errmsg);
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
		return -1;
	}
	return 0;
}


static int perform_rtrans_query(options_t* cmd_opts, rtrans_results_t* rtrans_results, 
	policy_t *policy)
{
    int rt = 0;
    rtrans_query_t query;

    init_rtrans_query(&query);

    query.src.indirect = cmd_opts->indirect;
    query.src.ta = cmd_opts->src_name;
    query.src.t_or_a = IDX_BOTH;

    query.tgt.indirect = cmd_opts->indirect;
    query.tgt.ta = cmd_opts->tgt_name;
    query.tgt.t_or_a = IDX_BOTH;

    query.use_regex = cmd_opts->useregex;

    query.range = 0;

    if (cmd_opts->src_name) {
        query.search_type |= AP_MLS_RTS_SRC_TYPE;
    }

    if (cmd_opts->tgt_name) {
        query.search_type |= AP_MLS_RTS_TGT_TYPE;
    }

    /* TODO: add mls range types and set the high and low of the range */
    rt = search_range_transition_rules(&query, rtrans_results, policy);
    if (rt != 0) {
        if(rt == -1) {
            printf("Unexpected error (-1) searching rules\n");
        }
        else if( rt == -2) {
            printf("%s\n", rtrans_results->errmsg);
        }
    }

    return rt;
}

static int perform_rbac_query(options_t *cmd_opts, rbac_results_t *rbac_results, policy_t *policy)
{
	int retv = 0, error = 0;
	rbac_query_t *query = NULL;

	if (!cmd_opts || !rbac_results || !policy) {
		errno = EINVAL;
		return -1;
	}

	query = calloc(1, sizeof(rbac_query_t));
	init_rbac_query(query);

	if (cmd_opts->src_role_name) {
		query->src = strdup(cmd_opts->src_role_name);
		if (!query->src) {
			error = errno;
			goto err;
		}
	}

	if (cmd_opts->tgt_role_name) {
		query->tgt_role = strdup(cmd_opts->tgt_role_name);
		if (!query->tgt_role) {
			error = errno;
			goto err;
		}
	}

	if (cmd_opts->tgt_name) {
		query->tgt_ta = strdup(cmd_opts->tgt_name);
		if (!query->tgt_ta) {
			error = errno;
			goto err;
		}
	}

	query->use_regex = cmd_opts->useregex;
	query->indirect = cmd_opts->indirect;

	if (cmd_opts->role_allow || cmd_opts->all)
		query->rule_select |= RBACQ_RALLOW;

	if (cmd_opts->role_trans || cmd_opts->all)
		query->rule_select |= RBACQ_RTRANS;

	retv = search_rbac_rules(query, rbac_results, policy);
	if (retv < 0) {
		error = errno;
		fprintf(stderr, "Error during rbac search: %s\n", rbac_results->errmsg);
		goto err;
	}

	free_rbac_query(query);
	free(query);

	return 0;

err:
	free_rbac_query(query);
	free(query);
	errno = error;
	return -1;
}

static void print_teq_results(options_t *cmd_opts, teq_results_t *r, 
			policy_t *policy)
{
	int i;
	char *rule, *cond_expr;
	bool_t print_line_no = cmd_opts->lineno && !is_binary_policy(policy);
	if(r->num_av_access > 0) {
		for(i = 0; i < r->num_av_access; i++) {
			rule = re_render_av_rule(print_line_no, r->av_access[i], FALSE, policy);
			assert(rule);
			if(cmd_opts->show_cond && policy->av_access[r->av_access[i]].cond_expr != -1)
				printf("%c  ", policy->av_access[r->av_access[i]].cond_list?'T':'F');
			else if (cmd_opts->show_cond)
				printf("   ");
			printf("%s", rule);
			free(rule);
			if(cmd_opts->show_cond && policy->av_access[r->av_access[i]].cond_expr != -1) {
				printf(" %s", (cond_expr = re_render_cond_expr(policy->av_access[r->av_access[i]].cond_expr, policy)));
				free(cond_expr);
			}
			printf("\n");

		}
	}
	if(r->num_av_audit > 0) {
		for(i = 0; i < r->num_av_audit; i++) {
			rule = re_render_av_rule(print_line_no, r->av_audit[i], TRUE, policy);
			assert(rule);
			if(cmd_opts->show_cond && policy->av_audit[r->av_audit[i]].cond_expr != -1)
				printf("%c  ", policy->av_audit[r->av_audit[i]].cond_list?'T':'F');
			else if (cmd_opts->show_cond)
				printf("   ");
			printf("%s", rule);
			free(rule);
			if(cmd_opts->show_cond && policy->av_audit[r->av_audit[i]].cond_expr != -1) {
				printf(" %s", (cond_expr = re_render_cond_expr(policy->av_audit[r->av_audit[i]].cond_expr, policy)));
				free(cond_expr);
			}
			printf("\n");
		}
	}
	if(r->num_type_rules > 0) { 
		for(i = 0; i < r->num_type_rules; i++) {
			rule = re_render_tt_rule(print_line_no, r->type_rules[i], policy);
			assert(rule);
			if (cmd_opts->show_cond && policy->te_trans[r->type_rules[i]].cond_expr != -1)
				printf("%c  ", policy->te_trans[r->type_rules[i]].cond_list?'T':'F');
			else if (cmd_opts->show_cond)
				printf("   ");
			printf("%s", rule);
			free(rule);
			if (cmd_opts->show_cond && policy->te_trans[r->type_rules[i]].cond_expr != -1) {
				printf(" %s", (cond_expr = re_render_cond_expr(policy->te_trans[r->type_rules[i]].cond_expr, policy)));
			}
			printf("\n");
		}
	}
}

static void print_rtrans_results(options_t *cmd_opts, 
				rtrans_results_t* rtrans_results, policy_t *policy)
{
	int i;
	char *rule;

	if(rtrans_results->num_range_rules > 0) {
		for(i = 0; i < rtrans_results->num_range_rules; i++) {
			rule = re_render_rangetrans((cmd_opts->lineno && !is_binary_policy(policy)), rtrans_results->range_rules[i], policy);
			assert(rule);
			if (cmd_opts->show_cond)
				printf("   %s\n", rule);
			else
				printf("%s\n", rule);
			free(rule);
		}
	}
}

static void print_rbac_results(options_t *cmd_opts, rbac_results_t *rbac_results, policy_t *policy)
{
	int i;
	char *rule = NULL;

	if (!cmd_opts || !rbac_results || !policy)
		return;

	if (rbac_results->err) {
		fprintf(stderr, "%s\n", rbac_results->errmsg);
		return;
	}

	for (i = 0; i < rbac_results->num_role_allows && (cmd_opts->role_allow || cmd_opts->all); i++) {
		rule = re_render_role_allow((cmd_opts->lineno && !is_binary_policy(policy)), rbac_results->role_allows[i], policy);
		assert(rule);
		printf("%s\n", rule);
		free(rule);
	}

	for (i = 0; i < rbac_results->num_role_trans && (cmd_opts->role_trans || cmd_opts->all); i++) {
		rule = re_render_role_trans((cmd_opts->lineno && !is_binary_policy(policy)), rbac_results->role_trans[i], policy);
		assert(rule);
		printf("%s\n", rule);
		free(rule);
	}
}

int main (int argc, char **argv)
{
	options_t cmd_opts;
	int optc, rt;
		
	bool_t tesearch, rtrans_search, rbac_search;
	unsigned int open_opts = 0;
	policy_t *policy;
	teq_results_t teq_results;
	unsigned int search_opts = 0;
	
	cmd_opts.all = cmd_opts.lineno = cmd_opts.allow = FALSE;
	cmd_opts.nallow = cmd_opts.audit = cmd_opts.type = FALSE;
	cmd_opts.rtrans = cmd_opts.indirect = cmd_opts.show_cond = FALSE;
	cmd_opts.useregex = TRUE;
	cmd_opts.role_allow = cmd_opts.role_trans = FALSE;
	cmd_opts.src_name = cmd_opts.tgt_name = cmd_opts.class_name = NULL;
	cmd_opts.permlist = cmd_opts.bool_name = cmd_opts.src_role_name = NULL;
	cmd_opts.tgt_role_name = NULL;
	
	tesearch = rtrans_search = rbac_search = FALSE;

	open_opts = POLOPT_TE_POLICY | POLOPT_OBJECTS;
	
	while ((optc = getopt_long (argc, argv, "s:t:r:g:c:p:b:ANURaTLolCinhv0", longopts, NULL)) != -1)  {
		switch (optc) {
		case 0:
	  		break;
	  	case 's': /* source */
	  		if(optarg == 0) {
	  			usage(argv[0], 1);
	  			printf("Missing source type/attribute for -s (--source)\n");
	  			exit(1);
	  		}
	  		cmd_opts.src_name = strdup(optarg);
	  		if (!cmd_opts.src_name) {
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
	  		cmd_opts.tgt_name = strdup(optarg);
	  		if (!cmd_opts.tgt_name) {
	  			fprintf(stderr, "Memory error!\n");
		  		exit(1);	
			}
	  		break;
		case 'r':
	  		if(optarg == 0) {
	  			usage(argv[0], 1);
	  			printf("Missing source role for --role_source\n");
	  			exit(1);
	  		}
  			cmd_opts.src_role_name = strdup(optarg);
  			if (!cmd_opts.src_role_name) {
  				fprintf(stderr, "Memory error!\n");
	  			exit(1);	
	  		}
			break;
		case 'g':
	  		if(optarg == 0) {
	  			usage(argv[0], 1);
	  			printf("Missing target role for --role_target\n");
	  			exit(1);
	  		}
  			cmd_opts.tgt_role_name = strdup(optarg);
  			if (!cmd_opts.tgt_role_name) {
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
	  		cmd_opts.class_name = strdup(optarg);
	  		if (!cmd_opts.class_name) {
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
	  		cmd_opts.permlist = strdup(optarg);
	  		if (!cmd_opts.permlist) {
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
	  		cmd_opts.bool_name = strdup(optarg);
	  		if (!cmd_opts.bool_name) {
	  			fprintf(stderr, "Memory error!\n");
	  			exit(1);	
	  		}
			break;
	  	case 'i': /* indirect search */
	  		cmd_opts.indirect = TRUE;
	  		break;
	  	case 'n': /* no regex */
	  		cmd_opts.useregex = FALSE;
	  		break;
	  	case 'A': /* allow */
	  		cmd_opts.allow = TRUE;
	  		break;
	  	case 'N': /* neverallow */
	  		cmd_opts.nallow = TRUE;
	  		break;
	  	case 'U': /* audit */
	  		cmd_opts.audit = TRUE;
	  		break;
	  	case 'T': /* type */
	  		cmd_opts.type = TRUE;
	  		break;
	  	case 'R': /* range transition */
	  		cmd_opts.rtrans = TRUE;
			open_opts |= POLOPT_RANGETRANS;
	  		break;
		case 'L':
			cmd_opts.role_allow = TRUE;
			open_opts |= POLOPT_RBAC;
			break;
		case 'o':
			cmd_opts.role_trans = TRUE;
			open_opts |= POLOPT_RBAC;
			break;
	  	case 'a': /* all */
	  		cmd_opts.all = TRUE;
	  		open_opts = POLOPT_ALL;
	  		break;
	  	case 'l': /* lineno */
	  		cmd_opts.lineno = TRUE;
	  		break;
		case 'C':
			cmd_opts.show_cond = TRUE;
			open_opts |= POLOPT_COND_POLICY;
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
 
	if(!(cmd_opts.allow || cmd_opts.nallow || cmd_opts.audit || cmd_opts.role_allow ||
			cmd_opts.type || cmd_opts.rtrans || cmd_opts.role_trans || cmd_opts.all)) {
		usage(argv[0], 1);
		printf("One of -a (--all), --allow, --neverallow, --audit, --rangetrans, "
               "--type, --role_allow, or --role_trans mustbe specified\n\n");
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

	if (cmd_opts.all){
		tesearch = TRUE;
		rtrans_search = TRUE;
		rbac_search = TRUE;
	}
	else{
		if (cmd_opts.allow || cmd_opts.nallow || cmd_opts.audit || 
			cmd_opts.type){
			tesearch = TRUE;
		}
		if (cmd_opts.rtrans) {
			rtrans_search = TRUE;
		}
		if (cmd_opts.role_allow || cmd_opts.role_trans) {
			rbac_search = TRUE;
		}
	}

	init_teq_results(&teq_results);

	if (tesearch){
		rt = perform_te_query(&cmd_opts, &teq_results, policy);
		if (rt < 0){
			free_teq_results_contents(&teq_results);
			close_policy(policy);
			exit(1);
		}
	}

	rtrans_results_t rtrans_results;
	init_rtrans_results(&rtrans_results);
	if (rtrans_search) {
		rt = perform_rtrans_query(&cmd_opts, &rtrans_results, 
                   policy);
		if (rt < 0){
			free_rtrans_results_contents(&rtrans_results);
			close_policy(policy);
			exit(1);
		}
	}

	rbac_results_t rbac_results;
	init_rbac_results (&rbac_results);
	if (rbac_search) {
		rt = perform_rbac_query(&cmd_opts, &rbac_results, policy);
		if (rt < 0) {
			free_rbac_results(&rbac_results);
			close_policy(policy);
			exit(1);
		}
	}

	printf("\n%d Rules match your search criteria\n", 
			teq_results.num_av_access + teq_results.num_av_audit +
			teq_results.num_type_rules + rtrans_results.num_range_rules + 
			rbac_results.num_role_allows + rbac_results.num_role_trans);
	print_teq_results(&cmd_opts, &teq_results, policy);
	print_rtrans_results(&cmd_opts, &rtrans_results, policy);
	print_rbac_results(&cmd_opts, &rbac_results,  policy);
	printf("\n\n");

	/* cleanup */
	free_teq_results_contents(&teq_results);
	free_rtrans_results_contents(&rtrans_results);
	free_rbac_results(&rbac_results);
	close_policy(policy);
	free(cmd_opts.src_name);
	free(cmd_opts.tgt_name);
	free(cmd_opts.class_name);
	free(cmd_opts.permlist);
	free(cmd_opts.bool_name);
	free(cmd_opts.src_role_name);
	free(cmd_opts.tgt_role_name);
	exit(0);
}


