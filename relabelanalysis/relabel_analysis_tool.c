/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Jeremy A. Mowery jmowery@tresys.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>
#include <util.h>
#include <render.h>

#include "relabel_analysis.h"

#define RELABEL_ANALYSIS_TOOL_VERSION_INFO "v1.0"

static struct option const longopts[] = 
{
	{"start", 	required_argument,	NULL, 's'},
	{"mode", 	required_argument,	NULL, 'm'},
	{"policy",	required_argument, 	NULL, 'p'},
	{"trans", 	optional_argument,  	NULL, 't'},
	{"trans_steps", required_argument,	NULL, 'x'},
	{"filter", 	required_argument, 	NULL, 'f'},
	{"output",	required_argument,	NULL, 'o'},
	{"help", 	no_argument,		NULL, 'h'},
	{"version", 	no_argument, 		NULL, 'v'},
	{"rules",	required_argument,	NULL, 'r'},
	{NULL, 0, NULL, 0}
};

void usage(const char *argv0, int long_version)
{
	printf("usage:\n%s -s <start type> -m \"to\"|\"from\"|\"both\"|\"domain\" [options]\n", argv0);
	if (long_version){
		printf("\n"
"Required Arguments:\n"
"   -s, --start <start type>   starting type for analysis\n"
"   -m, --mode  <mode string>  mode of analysis\n\n"
"Mode Strings:\n"
"   to        list types which can be relabeled to starting type\n"
"   from      list types which can be relabeled from starting type\n"
"   both      list types as with both to and from mode\n"
"   subject   list all types to and from which starting type can relabel\n\n"
"Additional Options:\n"
"   -p, --policy <policy file> specify the policy file to load\n"
"   -f, --filter <filter file> specify a filter file to use\n"
"   -o, --output <output file> create an output file\n"
"   -h, --help                 display this message\n"
"   -v, --version              display version information\n\n"
"Transitive Analysis Options (currently not available)\n"
"   -t, --trans [trans target] include type transition for multi-step relabeling\n"
"   -x, --trans_steps <int n>  analyze paths upto at most n steps\n\n"
"Output of rules\n"
"   -r, --rules <int n>        sets display level of rules\n"
"                              0 = off (only list types), 1 = list types & paths\n"
"                              2 = only one way (if bi-directional), \n"
"                              3 = all (default)\n\n"
);
	} else {
		printf("try %s --help for more information.\n", argv0);
	}
};

int apol_parse_filter_file(FILE *infile, relabel_filter_t *filter, policy_t *policy)
{
        char str [300], *object, *perm, *s;
        int retv;

        if (!infile){
                fprintf(stderr, "bad filter file\n");
                return -1;
        }

        if (!filter || !policy){
                fprintf(stderr, "bad parameter\n");
                return -1;
        }

        while (!feof(infile)){
                bzero(str, sizeof (str));
                fgets(str, sizeof (str), infile);

                /* trim starting whitespace */
                for (object = str; isspace (*object); object++)
                        ;
                if (*object == '\0' || *object == '#')
                        continue;

                /* find actual permission */
                if ((perm = strchr (object, ':')) == NULL) {
                        fprintf(stderr, "invalid line format \n");
                        return -1;
                }
                *perm = '\0';
                perm++;
                while (isspace (*perm)) {
                        perm++;
                }

                /* trim trailing whitespace for both variables */
                for (s = object; *s != '\0'; s++) {
                        if (isspace (*(s + 1))) {
                                *(s + 1) = '\0';
                        }
                }
                for (s = perm; *s != '\0'; s++) {
                        if (isspace (*(s + 1))) {
                                *(s + 1) = '\0';
                        }
                }

                /* double check that something remains for both object
                 * and permission */
                if (strlen (object) == 0 || strlen (perm) == 0) {
                        fprintf(stderr,"BAKA!\n");
                        return -42;
                }

                retv = apol_fill_filter_set (object, perm, filter, policy);
                if (retv)
                        return retv;
        }
	return 0;
};

bool_t is_relabel_result_empty(relabel_result_t *res)
{
	bool_t retv = 1;
	int i, temp = 0;

	if (res->num_subjects)
		for (i = 0; i < res->num_types; i++)
			temp += res->num_subjects[i];
	
	if (temp) retv = 0;

	return retv;
};

/* rules_lvl 0=none 1=only directions 2=to or from only not back 3=all*/
void print_relabel_result(relabel_set_t *sets, relabel_result_t *res, relabel_filter_t *filter, int start_type, policy_t *policy, FILE *out, int rules_lvl)
{
	int i, j, k, x, retv, dummy = 0, where, list = 0, skip_filter;
	char *str = NULL, *str2 = NULL, *str3 = NULL;
	
	if (filter)
		skip_filter = 0;
	else
		skip_filter = 1;

	if (res->mode->mode == MODE_DOM){
		retv = get_type_name(start_type, &str, policy);
		if (retv) { 
			fprintf(stderr, "out of memory\n");
			return;
		}
		fprintf(out ,"%s can relabel from:\n", str);
		free(str);
		str = NULL;
		for(i = 0; i < res->set->num_types; i++) {
			if (res->set->types[i].list == TOLIST)
				continue;
			retv = get_type_name(res->set->types[i].type, &str, policy);
			if (retv) {
				fprintf(stderr, "out of memory\n");
				return;
			}
			fprintf(out, "%s %s\n", (i&&rules_lvl)?"\n ":" ",  str);
			free(str);
			str = NULL;
			dummy++;
			for (j = 0; j < res->set->types[i].num_rules; j++) {
				if (rules_lvl > 1) 
					fprintf(out, "    %s\n", re_render_av_rule((is_binary_policy(policy))?0:1, res->set->types[i].rules[j], 0, policy));
			}
		}
		if (!dummy)
			fprintf(out, "  <none>\n");

		retv = get_type_name(start_type, &str, policy);
		if (retv) { 
			fprintf(stderr, "out of memory\n");
			return;
		}
		fprintf(out ,"\n%s can relabel to:\n", str);
		free(str);
		str = NULL;
		dummy = 0;
		for(i = 0; i < res->set->num_types; i++) {
			if (res->set->types[i].type == FROMLIST)
				continue;
			retv = get_type_name(res->set->types[i].type, &str, policy);
			if (retv) {
				fprintf(stderr, "out of memory\n");
				return;
			}
			fprintf(out, "%s %s\n", (i&&rules_lvl)?"\n ":" ", str);
			free(str);
			str = NULL;
			dummy++;
			for (j = 0; j < res->set->types[i].num_rules; j++) {
				if (rules_lvl > 1) 
					fprintf(out, "    %s\n", re_render_av_rule((is_binary_policy(policy))?0:1, res->set->types[i].rules[j], 0, policy));
			}
		}
		if (!dummy)
			fprintf(out, "   <none>\n");
	} else {
		if (str2) {
			free(str2);
			str2 = NULL;
		}
		retv = get_type_name(start_type, &str2, policy);
		if (retv) {
			fprintf(stderr, "out of memory\n");
			return;
		}
		if (res->mode->mode == MODE_FROM) {
			list = TOLIST;
			fprintf(out, "The following types can be relabeled from %s:\n", str2);
		} else if (res->mode->mode == MODE_TO) {
			list = FROMLIST;
			fprintf(out, "The following types can be relabeled to %s:\n", str2);
		} else if (res->mode->mode == MODE_BOTH) {
			list = BOTHLIST;
			fprintf(out, "Type %s can be relabeled to/from:\n", str2);
		}
		for (i = 0; i < res->num_types; i++) {
			if (str) {
				free(str);
				str = NULL;
			}
			retv = get_type_name(res->types[i], &str, policy);
			if (retv) {
				fprintf(stderr, "out of memory\n");
				return;
			}
			fprintf(out, "%s %s\n", (i&&rules_lvl)?"\n ":" ", str);
			for (j = 0; j < res->num_subjects[i]; j++) {
				if (str3) {
					free(str3);
					str3 = NULL;
				}
				retv = get_type_name(res->subjects[i][j], &str3, policy);
				if (retv) {
					fprintf(stderr, "out of memory\n");
					return;
				}
				where = apol_where_is_type_in_list(&(sets[res->subjects[i][j]]), res->types[i], list);
				if (where == NOTHERE) {
					fprintf(stderr, "fatal internal error\n");
					return;
				}
				if (sets[res->subjects[i][j]].types[where].list == TOLIST) {
					if (rules_lvl > 0) 
						fprintf(out, "    %s -> %s by %s\n", str2, str, str3);
				} else if (sets[res->subjects[i][j]].types[where].list == FROMLIST) {
					if (rules_lvl > 0)
						fprintf(out, "    %s <- %s by %s\n", str2, str, str3);
				} else if (sets[res->subjects[i][j]].types[where].list == BOTHLIST) {
					if (rules_lvl > 0)
						fprintf(out, "    %s <-> %s by %s\n", str2, str, str3);
				} else {
					fprintf(stderr, "something is foobar .list=%i i=%i j=%i where=%i\n", sets[res->subjects[i][j]].types[where].list, i, j, where);
					return;
				}
				for (k = 0; k < sets[res->subjects[i][j]].types[where].num_rules; k++) {
					if (rules_lvl > 1) {
						if (skip_filter) {
							fprintf(out, "      %s\n", re_render_av_rule((is_binary_policy(policy))?0:1, sets[res->subjects[i][j]].types[where].rules[k], 0, policy));
						} else {
							for (x = 0; x < filter->num_perm_sets; x++) {
								dummy = 0;
								if (does_av_rule_use_classes(sets[res->subjects[i][j]].types[where].rules[k], 1, &(filter->perm_sets[x].obj_class), 1, policy))
									dummy = 1;
								if (dummy) 
									break;
							}
							if (dummy)
								fprintf(out, "      %s\n", re_render_av_rule((is_binary_policy(policy))?0:1, sets[res->subjects[i][j]].types[where].rules[k], 0, policy));
						}
					}
				}
				if (sets[res->subjects[i][j]].types[where].list == BOTHLIST) {
					where = apol_where_is_type_in_list(&(sets[res->subjects[i][j]]), start_type, ANYLIST);
					if (where == NOTHERE) {
						fprintf(stderr, "fatal internal error\n");
						return;
					}
					for (k = 0; k < sets[res->subjects[i][j]].types[where].num_rules; k++) {
						if (rules_lvl > 2) {
							if (skip_filter) {
								fprintf(out, "      %s\n", re_render_av_rule((is_binary_policy(policy))?0:1, sets[res->subjects[i][j]].types[where].rules[k], 0, policy));
							} else {
								for (x = 0; x < filter->num_perm_sets; x++) {
									dummy = 0;
									if (does_av_rule_use_classes(sets[res->subjects[i][j]].types[where].rules[k], 1, &(filter->perm_sets[x].obj_class), 1, policy))
										dummy = 1;
									if (dummy) 
										break;
								}
								if (dummy)
									fprintf(out, "      %s\n", re_render_av_rule((is_binary_policy(policy))?0:1, sets[res->subjects[i][j]].types[where].rules[k], 0, policy));
							}
						}
					}
				}
			}
		}
	}

};

int main (int argc, char** argv)
{
	policy_t *policy = NULL;
	relabel_set_t *sets = NULL;
	relabel_result_t *res = NULL;
	relabel_filter_t *filter= NULL;
	relabel_mode_t *mode = NULL;

	char *policy_filename = NULL;
	char *output_filename = NULL;
	char *filter_filename = NULL;
	char *start_type_name = NULL;
	char *trans_type_name = NULL;
	char *dummy = NULL;

	FILE *out;
	FILE *filter_file;

	int retv, optc, start_type, rules_lvl = 100;

	if (!( dummy = (char*)calloc(2000, sizeof(char)) )) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	if (!( mode = (relabel_mode_t*)malloc(1 * sizeof(relabel_mode_t)) )) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	retv = apol_relabel_mode_init(mode);
	if (retv)
		return -1;


	while ( (optc = getopt_long(argc, argv, "s:m:p:t::x:f:o:hvr:", longopts, NULL)) != -1 ) {
		switch (optc) {
		case 's':
			start_type_name = optarg;
			break;
		case 'm':
			if(!strcmp(optarg, "to")) mode->mode = MODE_TO;
			else if (!strcmp(optarg, "from")) mode->mode = MODE_FROM;
			else if (!strcmp(optarg, "both")) mode->mode = MODE_BOTH;
			else if (!strcmp(optarg, "subject")) mode->mode = MODE_DOM;
			break;
		case 'p':
			policy_filename = optarg;
			break;
		case 't':
			trans_type_name = optarg;
			mode->transitive = 1;
			break;
		case 'x':
			mode->trans_steps = atoi(optarg);
			break;
		case 'f':
			filter_filename = optarg;
			mode->filter = 1;
			break;
		case 'o':
			output_filename = optarg;
			break;
		case 'h':
			usage(argv[0], 1);
			exit(0);
			break;
		case 'v':
			printf("relabel analysis tool %s version: %s\n", argv[0], RELABEL_ANALYSIS_TOOL_VERSION_INFO);
			exit(0);
			break;
		case 'r':
			rules_lvl = atoi(optarg);
			break;
		default:
			break;
		}
	}

	if (!start_type_name || !(mode->mode)) {
		usage(argv[0], 0);
		exit(1);
	}

	if (!policy_filename) {
		retv = find_default_policy_file(POL_TYPE_BINARY|POL_TYPE_SOURCE, &dummy);
		if (!dummy || retv) {
			fprintf(stderr, "error opening default policy\n");
			return retv;
		}
		policy_filename = dummy;
	}
	
	if (!output_filename) {
		out = stdout;
	} else {
		out = fopen(output_filename, "w");
		if (!out) {
			fprintf(stderr,"unable to open %s for writing\n", output_filename);
			exit(1);
		}
	}

	fprintf(out, "Relabel Analysis for %s\n", start_type_name);

	if (filter_filename) {
		filter_file = fopen(filter_filename, "r");
		if (!filter_file) {
			fprintf(stderr, "unable to open %s for reading\n", filter_filename);
			exit(1);
		}
		if (!( filter = (relabel_filter_t*)malloc(1 * sizeof(relabel_filter_t)) )) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		retv = apol_relabel_filter_init(filter);
		if (retv) 
			return -1;

	}

	if (mode->transitive /* XXX FIXME */) { 
		fprintf(stderr, "transitive analysis not yet available\n");
		exit(1);
	}

	if (mode->trans_steps) {
		fprintf(stderr, "transitive analysis not yet available\n");
		exit(1);
	}

	if (!( res = (relabel_result_t*)malloc(1 * sizeof(relabel_result_t)) )) {
		fprintf(stderr, "unable to allocate result collector memory\n");
		exit(1);
	}
	retv = apol_relabel_result_init(res);
	if (retv) {
		fprintf(stderr, "unable to initialize result collector\n");
		exit(retv);
	}

	if (open_policy(policy_filename, &policy)) {
		fprintf(stderr, "unable to open policy file: %s\n", policy_filename);
		exit(1);
	}

	start_type = get_type_idx(start_type_name, policy);
	if (!is_valid_type(policy, start_type, 0)) { 
		fprintf(stderr, "invalid type\n");
		return -1;
	}

	retv = apol_do_relabel_analysis(&sets, policy);
	if (retv) { 
		fprintf(stderr," fill relabel sets error %i\n", retv);
		return retv;
	}

	if (filter_filename) {
		retv = apol_parse_filter_file(filter_file, filter, policy);
		if (retv) {
			fprintf(stderr,"fill filter sets error %i\n", retv);
 			return retv;
		}
		fclose(filter_file);
	}
	
	retv = apol_query_relabel_analysis(sets, start_type, res, policy, mode, filter);
	if (retv) {
		fprintf(stderr, "analysis error %i\n", retv);
		return retv;
	}
	print_relabel_result(sets, res, filter, start_type, policy, out, rules_lvl);

	if (output_filename)
		fclose(out);

	return 0;
} 
