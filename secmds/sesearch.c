/**
 *  @file
 *  Command line tool to search TE rules.
 *
 *  @author Frank Mayer  mayerf@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

/* libapol */
#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>
#include <apol/vector.h>

/* libqpol*/
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include <qpol/syn_rule_query.h>
#include <qpol/util.h>

/* other */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2006 Tresys Technology, LLC"

char *policy_file = NULL;

static struct option const longopts[] = {
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
	{"semantic", no_argument, NULL, 'S'},
	{"show_cond", no_argument, NULL, 'C'},
	{"indirect", no_argument, NULL, 'i'},
	{"noregex", no_argument, NULL, 'n'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

typedef struct options
{
	char *src_name;
	char *tgt_name;
	char *src_role_name;
	char *tgt_role_name;
	char *class_name;
	char *permlist;
	char *bool_name;
	bool_t all;
	bool_t lineno;
	bool_t semantic;
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
	apol_vector_t *perm_vector;
} options_t;

void usage(const char *program_name, int brief)
{
	printf("%s (sesearch ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
	printf("Usage: %s [OPTIONS] RULE_TYPE [EXPESSION] [POLICY ...]\n", program_name);
	if (brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Search the rules in a SELinux policy.\n\
", stdout);
	fputs("RULE_TYPE must be one or more of the following:\n\
  --allow                 search for allow rules\n\
  --neverallow            search for neverallow rules\n\
  --audit                 search for auditallow and dontaudit rules\n\
  --type                  search for type_trans, type_member, and type_change\n\
  --rangetrans            search for range transition rules\n\
  --role_allow            search for role allow rules\n\
  --role_trans            search for role transition rules\n\
  -a, --all               show all rules regardless of type, class, or perms\n\
", stdout);
	fputs("EXPRESSION options:\n\
  -s NAME, --source=NAME  find rules with type/attribute NAME (regex) as source\n\
  -t NAME, --target=NAME  find rules with type/attribute NAME (regex) as target\n\
  --role_source=NAME      find rules with role NAME (regex) as source\n\
  --role_target=NAME      find rules with role NAME (regex) as target\n\
  -c NAME, --class=NAME   find rules with class NAME as the object class\n\
  -p P1[,P2,...] --perms=P1[,P2...]\n\
                          find rules with the specified permissions\n\
  -b NAME, --boolean=NAME find conditional rules with NAME in the expression\n\
", stdout);
	fputs("Other options:\n\
  -i, --indirect          also search for the type's attributes\n\
  -n, --noregex           do not use regular expression matching\n\
  -l, --lineno            show line number for each rule if available\n\
  --semantic              search rules semantically instead of syntactically\n\
  -C, --show_cond         show conditional expression for conditional rules\n\
  -h, --help              print this help text and exit\n\
  -v, --version           print version information and exit\n\
", stdout);
	fputs("\n\
If no expression is specified, then all rules are shown.\n\
\n\
The default source policy, or if that is unavailable the default binary\n\
policy, will be opened if no policy is provided.\n", stdout);
	return;
}

static int perform_av_query(apol_policy_t * policy, options_t * opt, apol_vector_t ** v)
{
	apol_avrule_query_t *avq = NULL;
	unsigned int rules = 0;
	int error = 0;
	char *tmp = NULL, *tok = NULL, *s = NULL;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->all && !opt->allow && !opt->nallow && !opt->audit) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	avq = apol_avrule_query_create();
	if (!avq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	if (opt->allow || opt->all)
		rules |= QPOL_RULE_ALLOW;
	if (opt->nallow || opt->all)
		rules |= QPOL_RULE_NEVERALLOW;
	if (opt->audit || opt->all)
		rules |= (QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT);
	apol_avrule_query_set_rules(policy, avq, rules);

	apol_avrule_query_set_regex(policy, avq, opt->useregex);
	if (opt->src_name)
		apol_avrule_query_set_source(policy, avq, opt->src_name, opt->indirect);
	if (opt->tgt_name)
		apol_avrule_query_set_target(policy, avq, opt->tgt_name, opt->indirect);
	if (opt->bool_name)
		apol_avrule_query_set_bool(policy, avq, opt->bool_name);
	if (opt->class_name) {
		if (apol_avrule_query_append_class(policy, avq, opt->class_name)) {
			error = errno;
			goto err;
		}
	}
	if (opt->permlist) {
		tmp = strdup(opt->permlist);
		for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
			if (apol_avrule_query_append_perm(policy, avq, tok)) {
				error = errno;
				goto err;
			}
			if ((s = strdup(tok)) == NULL || apol_vector_append(opt->perm_vector, s) < 0) {
				error = errno;
				goto err;
			}
			s = NULL;
		}
		free(tmp);
	}

	if (!(opt->semantic) && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (apol_syn_avrule_get_by_query(policy, avq, v)) {
			error = errno;
			goto err;
		}
	} else {
		if (apol_avrule_get_by_query(policy, avq, v)) {
			error = errno;
			goto err;
		}
	}

	apol_avrule_query_destroy(&avq);
	return 0;

      err:
	apol_vector_destroy(v, NULL);
	apol_avrule_query_destroy(&avq);
	free(tmp);
	free(s);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_syn_av_results(apol_policy_t * policy, options_t * opt, apol_vector_t * v)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	apol_vector_t *syn_list = NULL;
	qpol_syn_avrule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	qpol_cond_t *cond = NULL;
	uint32_t enabled = 0, is_true = 0;
	unsigned long lineno = 0;

	if (!policy || !v)
		return;

	syn_list = v;
	if (!(num_rules = apol_vector_get_size(syn_list)))
		goto cleanup;

	fprintf(stdout, "Found %zd syntactic av rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		rule = apol_vector_get_element(syn_list, i);
		enable_char = branch_char = ' ';
		if (opt->show_cond) {
			if (qpol_syn_avrule_get_cond(q, rule, &cond))
				goto cleanup;
			if (cond) {
				if (qpol_syn_avrule_get_is_enabled(q, rule, &enabled) < 0 || qpol_cond_eval(q, cond, &is_true) < 0)
					goto cleanup;
				tmp = apol_cond_expr_render(policy, cond);
				enable_char = (enabled ? 'E' : 'D');
				branch_char = ((is_true && enabled) || (!is_true && !enabled) ? 'T' : 'F');
				asprintf(&expr, "[ %s ]", tmp);
				free(tmp);
				tmp = NULL;
				if (!expr)
					goto cleanup;
			}
		}
		if (!(rule_str = apol_syn_avrule_render(policy, rule)))
			goto cleanup;
		if (opt->lineno) {
			if (qpol_syn_avrule_get_lineno(q, rule, &lineno))
				goto cleanup;
			fprintf(stdout, "%c%c [%7lu] %s %s\n", enable_char, branch_char, lineno, rule_str, expr ? expr : "");
		} else {
			fprintf(stdout, "%c%c %s %s\n", enable_char, branch_char, rule_str, expr ? expr : "");
		}
		free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}

      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
}

static void print_av_results(apol_policy_t * policy, options_t * opt, apol_vector_t * v)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	qpol_avrule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	qpol_iterator_t *iter = NULL;
	qpol_cond_t *cond = NULL;
	uint32_t enabled = 0, list = 0;

	if (!policy || !v)
		return;

	if (!(num_rules = apol_vector_get_size(v)))
		return;

	fprintf(stdout, "Found %zd semantic av rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		enable_char = branch_char = ' ';
		if (!(rule = (qpol_avrule_t *) apol_vector_get_element(v, i)))
			goto cleanup;
		if (opt->show_cond) {
			if (qpol_avrule_get_cond(q, rule, &cond))
				goto cleanup;
			if (qpol_avrule_get_is_enabled(q, rule, &enabled))
				goto cleanup;
			if (cond) {
				if (qpol_avrule_get_which_list(q, rule, &list))
					goto cleanup;
				tmp = apol_cond_expr_render(policy, cond);
				qpol_iterator_destroy(&iter);
				enable_char = (enabled ? 'E' : 'D');
				branch_char = (list ? 'T' : 'F');
				asprintf(&expr, "[ %s ]", tmp);
				free(tmp);
				tmp = NULL;
				if (!expr)
					goto cleanup;
			}
		}
		if (!(rule_str = apol_avrule_render(policy, rule)))
			goto cleanup;
		fprintf(stdout, "%c%c %s %s\n", enable_char, branch_char, rule_str, expr ? expr : "");
		free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}

      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
}

static int perform_te_query(apol_policy_t * policy, options_t * opt, apol_vector_t ** v)
{
	apol_terule_query_t *teq = NULL;
	unsigned int rules = 0;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (opt->all || opt->type) {
		rules = (QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER);
	} else {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	teq = apol_terule_query_create();
	if (!teq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_terule_query_set_rules(policy, teq, rules);
	apol_terule_query_set_regex(policy, teq, opt->useregex);
	if (opt->src_name)
		apol_terule_query_set_source(policy, teq, opt->src_name, opt->indirect);
	if (opt->tgt_name)
		apol_terule_query_set_target(policy, teq, opt->tgt_name, opt->indirect);
	if (opt->bool_name)
		apol_terule_query_set_bool(policy, teq, opt->bool_name);
	if (opt->class_name) {
		if (apol_terule_query_append_class(policy, teq, opt->class_name)) {
			error = errno;
			goto err;
		}
	}

	if (!(opt->semantic) && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (apol_syn_terule_get_by_query(policy, teq, v)) {
			error = errno;
			goto err;
		}
	} else {
		if (apol_terule_get_by_query(policy, teq, v)) {
			error = errno;
			goto err;
		}
	}

	apol_terule_query_destroy(&teq);
	return 0;

      err:
	apol_vector_destroy(v, NULL);
	apol_terule_query_destroy(&teq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_syn_te_results(apol_policy_t * policy, options_t * opt, apol_vector_t * v)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	apol_vector_t *syn_list = NULL;
	qpol_syn_terule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	qpol_cond_t *cond = NULL;
	uint32_t enabled = 0, is_true = 0;
	unsigned long lineno = 0;

	if (!policy || !v)
		return;

	syn_list = v;
	if (!(num_rules = apol_vector_get_size(syn_list)))
		goto cleanup;

	fprintf(stdout, "Found %zd syntactic te rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		rule = apol_vector_get_element(syn_list, i);
		enable_char = branch_char = ' ';
		if (opt->show_cond) {
			if (qpol_syn_terule_get_cond(q, rule, &cond))
				goto cleanup;
			if (cond) {
				if (qpol_syn_terule_get_is_enabled(q, rule, &enabled) < 0 || qpol_cond_eval(q, cond, &is_true) < 0)
					goto cleanup;
				tmp = apol_cond_expr_render(policy, cond);
				enable_char = (enabled ? 'E' : 'D');
				branch_char = ((is_true && enabled) || (!is_true && !enabled) ? 'T' : 'F');
				asprintf(&expr, "[ %s ]", tmp);
				free(tmp);
				tmp = NULL;
				if (!expr)
					break;
			}
		}
		if (!(rule_str = apol_syn_terule_render(policy, rule)))
			goto cleanup;
		if (opt->lineno) {
			if (qpol_syn_terule_get_lineno(q, rule, &lineno))
				goto cleanup;
			fprintf(stdout, "%c%c [%7lu] %s %s\n", enable_char, branch_char, lineno, rule_str, expr ? expr : "");
		} else {
			fprintf(stdout, "%c%c %s %s\n", enable_char, branch_char, rule_str, expr ? expr : "");
		}
		free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}

      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
}

static void print_te_results(apol_policy_t * policy, options_t * opt, apol_vector_t * v)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	qpol_terule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	qpol_iterator_t *iter = NULL;
	qpol_cond_t *cond = NULL;
	uint32_t enabled = 0, list = 0;

	if (!policy || !v)
		goto cleanup;

	if (!(num_rules = apol_vector_get_size(v)))
		goto cleanup;

	fprintf(stdout, "Found %zd semantic te rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		enable_char = branch_char = ' ';
		if (!(rule = (qpol_terule_t *) apol_vector_get_element(v, i)))
			goto cleanup;
		if (opt->show_cond) {
			if (qpol_terule_get_cond(q, rule, &cond))
				goto cleanup;
			if (qpol_terule_get_is_enabled(q, rule, &enabled))
				goto cleanup;
			if (cond) {
				if (qpol_terule_get_which_list(q, rule, &list))
					goto cleanup;
				if (qpol_cond_get_expr_node_iter(q, cond, &iter))
					goto cleanup;
				tmp = apol_cond_expr_render(policy, cond);
				qpol_iterator_destroy(&iter);
				enable_char = (enabled ? 'E' : 'D');
				branch_char = (list ? 'T' : 'F');
				asprintf(&expr, "[ %s ]", tmp);
				free(tmp);
				tmp = NULL;
				if (!expr)
					goto cleanup;
			}
		}
		if (!(rule_str = apol_terule_render(policy, rule)))
			goto cleanup;
		fprintf(stdout, "%c%c %s %s\n", enable_char, branch_char, rule_str, expr ? expr : "");
		free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}

      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
}

static int perform_ra_query(apol_policy_t * policy, options_t * opt, apol_vector_t ** v)
{
	apol_role_allow_query_t *raq = NULL;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->role_allow && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	raq = apol_role_allow_query_create();
	if (!raq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_role_allow_query_set_regex(policy, raq, opt->useregex);
	if (opt->src_role_name) {
		if (apol_role_allow_query_set_source(policy, raq, opt->src_role_name)) {
			error = errno;
			goto err;
		}
	}
	if (opt->tgt_role_name)
		if (apol_role_allow_query_set_target(policy, raq, opt->tgt_role_name)) {
			error = errno;
			goto err;
		}

	if (apol_role_allow_get_by_query(policy, raq, v)) {
		error = errno;
		goto err;
	}

	apol_role_allow_query_destroy(&raq);
	return 0;

      err:
	apol_vector_destroy(v, NULL);
	apol_role_allow_query_destroy(&raq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_ra_results(apol_policy_t * policy, options_t * opt, apol_vector_t * v)
{
	size_t i, num_rules = 0;
	qpol_role_allow_t *rule = NULL;
	char *tmp = NULL;

	if (!policy || !v)
		return;

	if (!(num_rules = apol_vector_get_size(v)))
		return;

	fprintf(stdout, "Found %zd role allow rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		if (!(rule = (qpol_role_allow_t *) apol_vector_get_element(v, i)))
			break;
		if (!(tmp = apol_role_allow_render(policy, rule)))
			break;
		fprintf(stdout, "   %s\n", tmp);
		free(tmp);
		tmp = NULL;
	}
}

static int perform_rt_query(apol_policy_t * policy, options_t * opt, apol_vector_t ** v)
{
	apol_role_trans_query_t *rtq = NULL;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->role_trans && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	rtq = apol_role_trans_query_create();
	if (!rtq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_role_trans_query_set_regex(policy, rtq, opt->useregex);
	if (opt->src_role_name) {
		if (apol_role_trans_query_set_source(policy, rtq, opt->src_role_name)) {
			error = errno;
			goto err;
		}
	}
	if (opt->tgt_name) {
		if (apol_role_trans_query_set_target(policy, rtq, opt->tgt_name, opt->indirect)) {
			error = errno;
			goto err;
		}
	}

	if (apol_role_trans_get_by_query(policy, rtq, v)) {
		error = errno;
		goto err;
	}

	apol_role_trans_query_destroy(&rtq);
	return 0;

      err:
	apol_vector_destroy(v, NULL);
	apol_role_trans_query_destroy(&rtq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_rt_results(apol_policy_t * policy, options_t * opt, apol_vector_t * v)
{
	size_t i, num_rules = 0;
	qpol_role_trans_t *rule = NULL;
	char *tmp = NULL;

	if (!policy || !v)
		return;

	if (!(num_rules = apol_vector_get_size(v)))
		return;

	fprintf(stdout, "Found %zd role_transition rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		if (!(rule = (qpol_role_trans_t *) apol_vector_get_element(v, i)))
			break;
		if (!(tmp = apol_role_trans_render(policy, rule)))
			break;
		fprintf(stdout, "   %s\n", tmp);
		free(tmp);
		tmp = NULL;
	}
}

static int perform_range_query(apol_policy_t * policy, options_t * opt, apol_vector_t ** v)
{
	apol_range_trans_query_t *rtq = NULL;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->rtrans && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	rtq = apol_range_trans_query_create();
	if (!rtq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_range_trans_query_set_regex(policy, rtq, opt->useregex);
	if (opt->src_name) {
		if (apol_range_trans_query_set_source(policy, rtq, opt->src_name, opt->indirect)) {
			error = errno;
			goto err;
		}
	}
	if (opt->tgt_name) {
		if (apol_range_trans_query_set_target(policy, rtq, opt->tgt_name, opt->indirect)) {
			error = errno;
			goto err;
		}
	}

	if (apol_range_trans_get_by_query(policy, rtq, v)) {
		error = errno;
		goto err;
	}

	apol_range_trans_query_destroy(&rtq);
	return 0;

      err:
	apol_vector_destroy(v, NULL);
	apol_range_trans_query_destroy(&rtq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_range_results(apol_policy_t * policy, options_t * opt, apol_vector_t * v)
{
	size_t i, num_rules = 0;
	qpol_range_trans_t *rule = NULL;
	char *tmp = NULL;

	if (!policy || !v)
		return;

	if (!(num_rules = apol_vector_get_size(v)))
		return;

	fprintf(stdout, "Found %zd range_transition rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		if (!(rule = (qpol_range_trans_t *) apol_vector_get_element(v, i)))
			break;
		if (!(tmp = apol_range_trans_render(policy, rule)))
			break;
		fprintf(stdout, "   %s\n", tmp);
		free(tmp);
		tmp = NULL;
	}
}

int main(int argc, char **argv)
{
	options_t cmd_opts;
	int optc, rt;

	apol_policy_t *policy = NULL;
	apol_vector_t *v = NULL;
	apol_policy_path_t *pol_path = NULL;
	apol_vector_t *mod_paths = NULL;
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;

	cmd_opts.all = cmd_opts.lineno = cmd_opts.allow = FALSE;
	cmd_opts.nallow = cmd_opts.audit = cmd_opts.type = FALSE;
	cmd_opts.rtrans = cmd_opts.indirect = cmd_opts.show_cond = FALSE;
	cmd_opts.useregex = TRUE;
	cmd_opts.role_allow = cmd_opts.role_trans = cmd_opts.semantic = FALSE;
	cmd_opts.src_name = cmd_opts.tgt_name = cmd_opts.class_name = NULL;
	cmd_opts.permlist = cmd_opts.bool_name = cmd_opts.src_role_name = NULL;
	cmd_opts.tgt_role_name = NULL;
	cmd_opts.perm_vector = NULL;

	while ((optc = getopt_long(argc, argv, "s:t:r:g:c:p:b:ANURaTLolCinhv0", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 's':	       /* source */
			if (optarg == 0) {
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
		case 't':	       /* target */
			if (optarg == 0) {
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
			if (optarg == 0) {
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
			if (optarg == 0) {
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
		case 'c':	       /* class */
			if (optarg == 0) {
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
		case 'p':	       /* permissions */
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing permissions for -p (--perms)\n");
				exit(1);
			}
			cmd_opts.permlist = strdup(optarg);
			cmd_opts.perm_vector = apol_vector_create();
			if (!cmd_opts.permlist || !cmd_opts.perm_vector) {
				fprintf(stderr, "%s", strerror(ENOMEM));
				exit(1);
			}
			break;
		case 'b':
			if (optarg == 0) {
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
		case 'i':	       /* indirect search */
			cmd_opts.indirect = TRUE;
			break;
		case 'n':	       /* no regex */
			cmd_opts.useregex = FALSE;
			break;
		case 'A':	       /* allow */
			cmd_opts.allow = TRUE;
			break;
		case 'N':	       /* neverallow */
			cmd_opts.nallow = TRUE;
			break;
		case 'U':	       /* audit */
			cmd_opts.audit = TRUE;
			break;
		case 'T':	       /* type */
			cmd_opts.type = TRUE;
			break;
		case 'R':	       /* range transition */
			cmd_opts.rtrans = TRUE;
			break;
		case 'L':
			cmd_opts.role_allow = TRUE;
			break;
		case 'o':
			cmd_opts.role_trans = TRUE;
			break;
		case 'a':	       /* all */
			cmd_opts.all = TRUE;
			break;
		case 'l':	       /* lineno */
			cmd_opts.lineno = TRUE;
			break;
		case 'S':	       /* semantic */
			cmd_opts.semantic = TRUE;
			break;
		case 'C':
			cmd_opts.show_cond = TRUE;
			break;
		case 'h':	       /* help */
			usage(argv[0], 0);
			exit(0);
		case 'v':	       /* version */
			printf("\n%s (sesearch ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	if (!(cmd_opts.allow || cmd_opts.nallow || cmd_opts.audit || cmd_opts.role_allow ||
	      cmd_opts.type || cmd_opts.rtrans || cmd_opts.role_trans || cmd_opts.all)) {
		usage(argv[0], 1);
		printf("One of -a (--all), --allow, --neverallow, --audit, --rangetrans, "
		       "--type, --role_allow, or --role_trans mustbe specified\n\n");
		exit(1);
	}

	if (argc - optind < 1) {
		rt = qpol_default_policy_find(&policy_file);
		if (rt < 0) {
			fprintf(stderr, "Default policy search failed: %s\n", strerror(errno));
			exit(1);
		} else if (rt != 0) {
			fprintf(stderr, "No default policy found.\n");
			exit(1);
		}
	} else {
		policy_file = argv[optind];
		optind++;
	}

	if (argc - optind > 0) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
		if (!(mod_paths = apol_vector_create())) {
			ERR(policy, "%s", strerror(ENOMEM));
			exit(1);
		}
		for (; argc - optind; optind++) {
			char *tmp = NULL;
			if (!(tmp = strdup(argv[optind]))) {
				ERR(policy, "Error loading module %s", argv[optind]);
				free(policy_file);
				apol_vector_destroy(&mod_paths, free);
				exit(1);
			}
			if (apol_vector_append(mod_paths, (void *)tmp)) {
				ERR(policy, "Error loading module %s", argv[optind]);
				apol_vector_destroy(&mod_paths, free);
				free(policy_file);
				free(tmp);
				exit(1);
			}
		}
	}

	pol_path = apol_policy_path_create(path_type, policy_file, mod_paths);
	if (!pol_path) {
		ERR(policy, "%s", strerror(ENOMEM));
		free(policy_file);
		apol_vector_destroy(&mod_paths, free);
		exit(1);
	}
	apol_vector_destroy(&mod_paths, free);

	policy = apol_policy_create_from_policy_path(pol_path, 0, NULL, NULL);
	if (!policy) {
		ERR(policy, "%s", strerror(errno));
		free(policy_file);
		apol_policy_path_destroy(&pol_path);
		exit(1);
	}

	if (!cmd_opts.semantic && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (qpol_policy_build_syn_rule_table(apol_policy_get_qpol(policy))) {
			apol_policy_destroy(&policy);
			exit(1);
		}
	}

	/* if syntactic rules are not available always do semantic search */
	if (!qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		cmd_opts.semantic = 1;
	}

	/* supress line numbers if doing semantic search or not available */
	if (cmd_opts.semantic || !qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_LINE_NUMBERS)) {
		cmd_opts.lineno = 0;
	}

	if (perform_av_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		if (!cmd_opts.semantic && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES))
			print_syn_av_results(policy, &cmd_opts, v);
		else
			print_av_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v, NULL);

	if (perform_te_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		if (!cmd_opts.semantic && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES))
			print_syn_te_results(policy, &cmd_opts, v);
		else
			print_te_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v, NULL);

	if (perform_ra_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		print_ra_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v, NULL);

	if (perform_rt_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		print_rt_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v, NULL);

	if (perform_range_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		print_range_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v, NULL);
	rt = 0;

      cleanup:
	apol_policy_destroy(&policy);
	apol_policy_path_destroy(&pol_path);
	free(cmd_opts.src_name);
	free(cmd_opts.tgt_name);
	free(cmd_opts.class_name);
	free(cmd_opts.permlist);
	free(cmd_opts.bool_name);
	free(cmd_opts.src_role_name);
	free(cmd_opts.tgt_role_name);
	apol_vector_destroy(&cmd_opts.perm_vector, free);
	exit(rt);
}
