#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>
#include <util.h>

#include "relabel_analysis.h"

#define RELABEL_ANALYSIS_TOOL_VERSION_INFO "v0.1"
#define MODE_TO     0x00000001
#define MODE_FROM   0x00000002
#define MODE_DOM    0x00000004
#define MODE_FLTR   0x00000010
#define MODE_TRANS  0x80000000

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
	if(long_version){
		printf("\n\
Required Arguments:\n\
   -s, --start <start type>   starting type for analysis\n\
   -m, --mode  <mode string>  mode of analysis\n\n\
Mode Strings:\n\
   to        list types to which starting type can be relabeled\n\
   from      list types from which starting type can be relabeled\n\
   domain    list all types to and from which starting type can relabel\n\n\
Additional Options:\n\
   -p, --policy <policy file> specify the policy file to load\n\
   -f, --filter <filter file> specify a filter file to use\n\
   -o, --output <output file> create an output file\n\
   -h, --help                 display this message\n\
   -v, --version              display version information\n\n\
Transitive Analysis Options (currently not available)\n\
   -t, --trans [trans target] include type transition for multi-step relabeling\n\
   -x, --trans_steps <int n>  analyze paths upto at most n steps\n\n\
");
	} else {
		printf("try %s --help for more information.\n", argv0);
	}
};

int find_obj_in_array(obj_perm_set_t *perm_sets, int num_perm_sets, int obj_idx)
{
	int i;

	if(!perm_sets) return INVNULL;
	if(obj_idx < 0) return INVAIDX;

		for (i = 0; i < num_perm_sets; i++) {
		if (perm_sets[i].obj_class == obj_idx) {
			return i;
		}
	}

	return NOTHERE;
};

int fill_filter_sets(FILE *infile, obj_perm_set_t **perm_sets, int *num_perm_sets, policy_t *policy)
{
	char *str = NULL, *temp = NULL;
	int i, q, obj_idx, perm_idx, retv;

	if(!infile){ 
		fprintf(stderr, "bad filter file\n");
		return INVNULL;
	}

	if(!perm_sets || !num_perm_sets || !policy){
		fprintf(stderr, "bad parameter\n");
		return INVNULL;
	}

	if(!( str = (char*)calloc(300, sizeof(char)) )){
		fprintf(stderr, "out of memory\n");
		return OOMEMER;
	}

	while(!feof(infile)){
		bzero(str, 300);
		fgets(str, 300, infile);

		if(!str) continue;
		if(str[0] == '#') continue;

		for(i =0; i < strlen(str); i++)
			if(isspace(str[i])) str[i] = '\0';

		q = strlen(str); 

		if(!q) continue;

		temp = strstr(str, ":");
		if(!temp){
			fprintf(stderr, "invalid line format \n");
			return INVNULL;
		}
		if(strlen(temp) > 0){
			temp[0] = '\0';
			temp++;
		}
		if( q - 1 != strlen(str) + strlen(temp)){
			fprintf(stderr,"BAKA!\n");
			return -42;
		}

		obj_idx = get_obj_class_idx(str, policy);
		perm_idx = get_perm_idx(temp, policy);

		if(!is_valid_obj_class_idx(obj_idx, policy) || !(is_valid_perm_idx(perm_idx, policy) && is_valid_perm_for_obj_class(policy, obj_idx, perm_idx))) return INVAIDX;

		if(*perm_sets)
			retv = find_obj_in_array(*perm_sets, *num_perm_sets, obj_idx);
		if(retv == NOTHERE){
			retv = policy_query_add_obj_class(perm_sets, num_perm_sets, obj_idx);
			if(retv == -1) return -7;
		} else if(retv < 0){
			return retv;
		}

		retv = policy_query_add_obj_class_perm(perm_sets, num_perm_sets, obj_idx, perm_idx);
		if(retv == -1) return -7;

	}

	return 0;
};

bool_t is_relabel_result_empty(relabel_result_t *res)
{
	bool_t retv = 1;
	int i, temp = 0;

	if(res->num_domains)
		for(i = 0; i < res->num_domains; i++)
			temp += res->num_types[i];
	
	if(temp) retv = 0;

	return retv;
};

void print_relabel_result(relabel_result_t *res, policy_t *policy, FILE *out)
{
	int i, j, max_dom;
	char *it = NULL;
	if(!res || !policy || !out) {
		fprintf(stderr, "inv null to print\n");
		return;
	}

	if(is_relabel_result_empty(res)){
		fprintf(stderr, "search returned no results\n");
		return;
	}

	if(!( it = (char*)calloc(100, sizeof(char)) )){
		fprintf(stderr, "oom in print\n");
		 return;
	}

	if(res->to_from == BOTHLIST)
		max_dom = 2;
	else
		max_dom = res->num_domains;

	for(i = 0; i < max_dom; i++){
		if(i == 0 || res->to_from != BOTHLIST){
			get_type_name(res->domains[i], &it, policy);
			fprintf(out, "Domain %s\n", it);
		}
		if(res->to_from == TOLIST || (res->to_from == BOTHLIST && i == 0)){
			fprintf(out, "Relabels to:\n");
		}
		else fprintf(out, "Relabels from:\n");

		for(j = 0; j < res->num_types[i]; j++){
			get_type_name(res->types[i][j], &it, policy);
			fprintf(out, "   %s\n", it);
		}
	}
	if(it) free(it);
};

int main (int argc, char** argv)
{
	policy_t *policy = NULL;
	relabel_set_t *sets = NULL;
	relabel_result_t *res = NULL;
	obj_perm_set_t *perm_sets = NULL;

	char *policy_filename = NULL;
	char *output_filename = NULL;
	char *filter_filename = NULL;
	char *start_type_name = NULL;
	char *trans_type_name = NULL;
	char *dummy = NULL;

	FILE *out;
	FILE *filter_file;

	int retv, optc, mode = 0x00000000, trans_steps = 0, num_perm_sets = 0, start_type;

	if(!( dummy = (char*)calloc(2000, sizeof(char)) )) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	while( (optc = getopt_long(argc, argv, "s:m:p:t::x:f:o:hv", longopts, NULL)) != -1 ){
		switch(optc){
		case 's':
			start_type_name = optarg;
			break;
		case 'm':
			if(!strcmp(optarg, "to")) mode |= MODE_TO;
			else if (!strcmp(optarg, "from")) mode |= MODE_FROM;
			else if (!strcmp(optarg, "domain")) mode |= MODE_DOM;
			break;
		case 'p':
			policy_filename = optarg;
			break;
		case 't':
			trans_type_name = optarg;
			mode |= MODE_TRANS;
			break;
		case 'x':
			trans_steps = atoi(optarg);
			break;
		case 'f':
			filter_filename = optarg;
			mode |= MODE_FLTR;
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

	if(!start_type_name || !(mode % 8)){
		usage(argv[0], 0);
		exit(1);
	}

	if(!policy_filename){
		printf("Enter policy file path:\n");
		scanf("%s", dummy);
		policy_filename = dummy;
	}
	
	if(!output_filename){
		out = stdout;
	} else {
		out = fopen(output_filename, "w");
		if(!out){
			fprintf(stderr,"unable to open %s for writing\n", output_filename);
			exit(1);
		}
	}

	fprintf(out, "Relabel Analysis for %s\n", start_type_name);

	if(filter_filename){
		filter_file = fopen(filter_filename, "r");
		if(!filter_file){
			fprintf(stderr, "unable to open %s for reading\n", filter_filename);
			exit(1);
		}
	}

	if(mode < 0){ /* transitive mode flips sign bit */
		fprintf(stderr, "transitive analysis not yet available\n");
		exit(1);
	}

	if(trans_steps){
		fprintf(stderr, "transitive analysis not yet available\n");
		exit(1);
	}

	if(!( res = (relabel_result_t*)malloc(1 * sizeof(relabel_result_t)) )){
		fprintf(stderr, "unable to allocate result collector memory\n");
		exit(1);
	}
	retv = init_relabel_result(res);
	if(retv != NOERROR){
		fprintf(stderr, "unable to initialize result collector\n");
		exit(retv);
	}

	if(open_policy(policy_filename, &policy)){
		fprintf(stderr, "unable to open policy file: %s\n", policy_filename);
		exit(1);
	}

	retv = fill_relabel_sets(&sets, policy);
	if(retv != NOERROR){ 
		fprintf(stderr," fill relabel sets error %i\n", retv);
		return retv;
	}

	if(filter_filename) {
		retv = fill_filter_sets(filter_file, &perm_sets, &num_perm_sets, policy);
		if(retv != NOERROR){
			fprintf(stderr,"fill filter sets error %i\n", retv);
 			return retv;
		}
		fclose(filter_file);
	}
	
	start_type = get_type_idx(start_type_name, policy);
	if(!is_valid_type(policy, start_type, 0)){ 
		fprintf(stderr, "invalid type\n");
		return INVAIDX;
	}

	switch(mode >= 0 ? mode : mode ^ MODE_TRANS ){
	case MODE_TO:
		retv = type_relabel_to(sets, start_type, res, policy);
		break;
	case MODE_FROM:
		retv = type_relabel_from(sets, start_type, res, policy);
		break;
	case MODE_DOM:
		retv = domain_relabel_types(sets, start_type, res, policy);
		break;
	case MODE_TO | MODE_FLTR:
		retv = type_relabel_to(sets, start_type, res, policy);
		if(retv != NOERROR){
			fprintf(stderr, "pre-filtering error\n");
			return retv;
		}
		retv = perm_filter(sets, perm_sets, num_perm_sets, res, policy);
		break;
	case MODE_FROM | MODE_FLTR:
		retv = type_relabel_from(sets, start_type, res, policy);
		if(retv != NOERROR){
			fprintf(stderr, "pre-filtering error\n");
			return retv;
		}
		retv = perm_filter(sets, perm_sets, num_perm_sets, res, policy);
		break;
	case MODE_DOM | MODE_FLTR:
		retv = domain_relabel_types(sets, start_type, res, policy);
		if(retv != NOERROR){
			fprintf(stderr, "pre-filtering error\n");
			return retv;
		}
		retv = perm_filter(sets, perm_sets, num_perm_sets, res, policy);
		break;
	default:
		fprintf(stderr, "Invalid mode specification, aborting.\nmode = 0x%08X\n", mode);
		exit(1);
		break;
	}
	if(retv != NOERROR) {
		fprintf(stderr, "analysis error %i\n", retv);
		return retv;
	}

	print_relabel_result(res, policy, out);

	if(mode < 0)
		;/* TODO transitive analysis code here when available */

	return 0;
} 
