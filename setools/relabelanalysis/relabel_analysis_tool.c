/* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

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

#define RELABEL_ANALYSIS_TOOL_VERSION_INFO "v0.1"

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
	{NULL, 0, NULL, 0}
};

void usage(const char *argv0, int long_version)
{
	printf("usage:\n%s -s <start type> -m \"to\"|\"from\"|\"domain\" [options]\n", argv0);
	if (long_version){
		printf("\n"
"Required Arguments:\n"
"   -s, --start <start type>   starting type for analysis\n"
"   -m, --mode  <mode string>  mode of analysis\n\n"
"Mode Strings:\n"
"   to        list types to which starting type can be relabeled\n"
"   from      list types from which starting type can be relabeled\n"
"   domain    list all types to and from which starting type can relabel\n\n"
"Additional Options:\n"
"   -p, --policy <policy file> specify the policy file to load\n"
"   -f, --filter <filter file> specify a filter file to use\n"
"   -o, --output <output file> create an output file\n"
"   -h, --help                 display this message\n"
"   -v, --version              display version information\n\n"
"Transitive Analysis Options (currently not available)\n"
"   -t, --trans [trans target] include type transition for multi-step relabeling\n"
"   -x, --trans_steps <int n>  analyze paths upto at most n steps\n\n"
);
	} else {
		printf("try %s --help for more information.\n", argv0);
	}
};

int find_obj_in_array(obj_perm_set_t *perm_sets, int num_perm_sets, int obj_idx)
{
	int i;

	if (!perm_sets) return -1;
	if (obj_idx < 0) return -1;

	for (i = 0; i < num_perm_sets; i++) {
		if (perm_sets[i].obj_class == obj_idx) {
			return i;
		}
	}

	return NOTHERE;
};

int apol_fill_filter_sets(FILE *infile, relabel_filter_t *filter, policy_t *policy)
{
        char str [300], *object, *perm, *s;
        int obj_idx, perm_idx, retv = 0;

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
                obj_idx = get_obj_class_idx(object, policy);
                if (*perm == '*')
                        perm_idx = -2;
                else
                        perm_idx = get_perm_idx(perm, policy);

                if (!is_valid_obj_class_idx(obj_idx, policy) )
                        return -1;
                if (perm_idx >= 0) {
                        if (!(is_valid_perm_idx(perm_idx, policy) && is_valid_perm_for_obj_class(policy, obj_idx, perm_idx)))
                                return -1;
                } else {
                        if (perm_idx != -2)
                                return -1;
                }
                if (filter->perm_sets)
                        retv = find_obj_in_array(filter->perm_sets, filter->num_perm_sets, obj_idx);
                if (retv == NOTHERE) {
                        retv = apol_add_class_to_obj_perm_set_list(&(filter->perm_sets), &(filter->num_perm_sets), obj_idx);
                        if (retv == -1)
                                return -1;
                } else if (retv < 0) {
                        return retv;
                }
		
		if (perm_idx >= 0) {
			retv = apol_add_perm_to_obj_perm_set_list(&(filter->perm_sets), &(filter->num_perm_sets), obj_idx, perm_idx);
			if (retv == -1) 
				return -1;
		} else {
			retv = find_obj_in_array(filter->perm_sets, filter->num_perm_sets, obj_idx);
			if (filter->perm_sets[retv].perms) {
				free(filter->perm_sets[retv].perms);
				filter->perm_sets[retv].perms = NULL;
			}
			filter->perm_sets[retv].num_perms = 0;
		}
	}

	return 0;
};

bool_t is_relabel_result_empty(relabel_result_t *res)
{
	bool_t retv = 1;
	int i, temp = 0;

	if (res->num_domains)
		for (i = 0; i < res->num_types; i++)
			temp += res->num_domains[i];
	
	if (temp) retv = 0;

	return retv;
};

void print_relabel_result(relabel_result_t *res, int start_type, policy_t *policy, FILE *out)
{
	int i, j, retv;
	int *temp_dom_list = NULL;
	int temp_dom_list_size = 0;
	char *str = NULL;
	
	if (res->mode == MODE_DOM){
		retv = get_type_name(start_type, &str, policy);
		if (retv) { 
			fprintf(stderr, "out of memory\n");
			return;
		}
		fprintf(out ,"%s can relabel from:\n", str);
		free(str);
		str = NULL;
		for(i = 0; i < res->set->num_from_types; i++) {
			retv = get_type_name(res->set->from_types[i].type, &str, policy);
			if (retv) {
				fprintf(stderr, "out of memory\n");
				return;
			}
			fprintf(out, "   %s\n", str);
			free(str);
			str = NULL;
		}
		if (!res->set->num_from_types)
			fprintf(out, "   <none>\n");

		retv = get_type_name(start_type, &str, policy);
		if (retv) { 
			fprintf(stderr, "out of memory\n");
			return;
		}
		fprintf(out ,"\n%s can relabel to:\n", str);
		free(str);
		str = NULL;
		for(i = 0; i < res->set->num_to_types; i++) {
			retv = get_type_name(res->set->to_types[i].type, &str, policy);
			if (retv) {
				fprintf(stderr, "out of memory\n");
				return;
			}
			fprintf(out, "   %s\n", str);
			free(str);
			str = NULL;
		}
		if (!res->set->num_to_types)
			fprintf(out, "   <none>\n");
	} else {
		for (i = 0; i < res->num_types; i++) {
			for (j = 0; j < res->num_domains[i]; j++) {
				if (find_int_in_array(res->domains[i][j], temp_dom_list, temp_dom_list_size) == -1) {
					retv = add_i_to_a(res->domains[i][j], &temp_dom_list_size, &temp_dom_list);
					if (retv) {
						fprintf(stderr, "out of memory\n");
						return;
					}
				}
			}
		}
		for (i = 0; i < temp_dom_list_size; i++) {
			retv = get_type_name(temp_dom_list[i], &str, policy);
			if (retv) {
				fprintf(stderr, "out of memory\n");
				return;
			}
			fprintf(out, "%s can relabel %s ", str, (res->mode == TOLIST ? "from" : "to"));
			retv = get_type_name(start_type, &str, policy);
			if (retv) {
				fprintf(stderr, "out of memory\n");
				return;
			}
			fprintf(out, "%s %s:\n", str, (res->mode == TOLIST ? "to" : "from"));
			for (j = 0; j < res->num_types; j++) {
				if (find_int_in_array(temp_dom_list[i], res->domains[j], res->num_domains[j]) > -1) {
					retv = get_type_name(res->types[j], &str, policy);
					if (retv) {
						fprintf(stderr, "out of memory\n");
						return;
					}
					fprintf(out, "   %s \n", str);

				}
			}
		}
	}

	/* print rules */
	fprintf(out, "\nResults generated by the following %i rules:\n", res->num_rules);
	if (!res->num_rules)
		fprintf(out, "  <none> \n");
	for (i = 0; i < res->num_rules; i++) {
		if (str) {
			free(str);
			str = NULL;
		}

		str = re_render_av_rule(0, res->rules[i], 0, policy);
		if (!str)
			fprintf(out, "Could not render rule number %i\n", res->rules[i]);
		else
			fprintf(out, "%s\n", str);
	}

	if (temp_dom_list)
		free(temp_dom_list);
	if (str)
		free(str);
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

	int retv, optc, start_type;

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


	while ( (optc = getopt_long(argc, argv, "s:m:p:t::x:f:o:hv", longopts, NULL)) != -1 ) {
		switch (optc) {
		case 's':
			start_type_name = optarg;
			break;
		case 'm':
			if(!strcmp(optarg, "to")) mode->mode = MODE_TO;
			else if (!strcmp(optarg, "from")) mode->mode = MODE_FROM;
			else if (!strcmp(optarg, "domain")) mode->mode = MODE_DOM;
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
		default:
			break;
		}
	}

	if (!start_type_name || !(mode->mode)) {
		usage(argv[0], 0);
		exit(1);
	}

	if (!policy_filename) {
		printf("Enter policy file path:\n");
		scanf("%s", dummy);
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

	retv = apol_do_relabel_analysis(&sets, policy);
	if (retv) { 
		fprintf(stderr," fill relabel sets error %i\n", retv);
		return retv;
	}

	if (filter_filename) {
		retv = apol_fill_filter_sets(filter_file, filter, policy);
		if (retv) {
			fprintf(stderr,"fill filter sets error %i\n", retv);
 			return retv;
		}
		fclose(filter_file);
	}
	
	start_type = get_type_idx(start_type_name, policy);
	if (!is_valid_type(policy, start_type, 0)) { 
		fprintf(stderr, "invalid type\n");
		return -1;
	}

	retv = apol_query_relabel_analysis(sets, start_type, res, policy, mode, filter);
	if (retv) {
		fprintf(stderr, "analysis error %i\n", retv);
		return retv;
	}

	print_relabel_result(res, start_type, policy, out);

	if (output_filename)
		fclose(out);

	return 0;
} 
