#include <stdio.h>
#include <stdlib.h>
#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>
#include <util.h>
#include "relabel_analysis.h"

void errorprint(int err)
{
	switch(err){
	case NOERROR:
		return;	
		break;
	case INVNULL:
		fprintf(stderr, "invalid null pointer\n");
		exit(1);
		break;
	case OOMEMER:
		fprintf(stderr, "out of memory\n");
		exit(1);
		break;
	case INVAIDX:
		fprintf(stderr, "array index invalid\n");
		exit(1);
		break;
	case INVLIST:
		fprintf(stderr, "invalid list choice\n");
		exit(1);
		break;
	case UNEXPTD:
		fprintf(stderr, "function terminated unexpectedly\n");
		exit(1);
		break;
	case NOTHERE:
		fprintf(stderr, "specified object not found\n");
		break;
	}
};

void print_type_list(int *list, int size, policy_t *policy, FILE *out)
{
	int i;
	char *it = NULL;
	if(!list || !policy || !out)return;
	if(!( it = (char*)calloc(100, sizeof(char)) ))
		return;

	for(i = 0; i < size; i++){
		get_type_name(list[i], &it, policy);
		fprintf(out, "%s\n", it);
	}
	free(it);
};

void print_relabel_result(relabel_result_t *res, policy_t *policy, FILE *out)
{
	int i, j, max_dom;
	char *it = NULL;

	if(!res || !policy || !out) return;
	if(!( it = (char*)calloc(100, sizeof(char)) )) return;

	if(res->to_from == BOTHLIST)
		max_dom = 2;
	else
		max_dom = res->num_domains;

	for(i = 0; i < max_dom; i++){
		if(i == 0 || res->to_from != BOTHLIST){
			get_type_name(res->domains[0], &it, policy);
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

};

void print_relabel_set(relabel_set_t *set, policy_t *policy, FILE *out)
{
	char *it = NULL;
	int *array = NULL;
	int size = 0, i;

	if(!set || !policy || !out) return;
	if(!( it = (char*)calloc(100, sizeof(char)) ))
		return;

	get_type_name(set->domain_type_idx, &it, policy);
	fprintf(out, "Domain %s:\ncan relabel from:\n", it);
	for(i = 0; i < set->num_from; i++){
		add_i_to_a(set->from_types[i].idx, &size, &array);
	}
	print_type_list(array, set->num_from, policy, out);
	free(array);
	array = NULL;
	size = 0;
	fprintf(out, "and can relabel to:\n");
	for(i = 0; i < set->num_to; i++){
		add_i_to_a(set->to_types[i].idx, &size, &array);
	}
	print_type_list(array, set->num_to, policy, out);
	free(array);
	free(it);
};

int main(int argc, char** argv)
{
	int retv;
	int *array = NULL;
	int size = 0;
	policy_t *policy = NULL;
	relabel_set_t *sets= NULL, *out_set = NULL; 
	relabel_result_t *res = NULL;
	int dummy[2];
	obj_perm_set_t perm_set;

	printf("initializing result collector . . . ");
	if(!( res = (relabel_result_t*)malloc(1 * sizeof(relabel_result_t)) )){
		fprintf(stderr, "unable to allocate result collector memory\n");
		exit(1);
	}
	retv = init_relabel_result(res);
	if(retv != NOERROR){
		fprintf(stderr, "unable to initialize result collector\n");
		errorprint(retv);
	}
	retv = init_obj_perm_set(&perm_set);

	if(retv != NOERROR) {
		fprintf(stderr, "unable to initialize permission set\n");
		errorprint(retv);
	}

	printf("done.\ninitializing policy . . . ");
	retv = init_policy(&policy);
	if(retv) {
		fprintf(stderr,"unable to initialize policy\n");
		errorprint(retv);
	}

	if(argc != 2){
		fprintf(stderr, "usage: \n%s <policy file>\n", argv[0]);
		return -1;
	}

	printf("opening policy . . . "); 
	if(open_policy(argv[1], &policy)){
		fprintf(stderr, "unable to open policy file: %s\n", argv[1]);
		return -1;
	}

	printf("done.\nfilling relabel sets . . . ");
	retv = fill_relabel_sets(&sets, policy);
	if(retv != NOERROR) errorprint(retv);

/*	printf("done.\nquerying relabel to . . . ");
	retv = single_type_relabel_to(sets, get_type_idx("sysadm_t", policy),
					 get_type_idx("sysadm_home_t", policy),
					 &array, &size, policy);
	errorprint(retv);
	printf("done.\n");
	
	print_type_list(array, size, policy, stdout);

	printf("querying relabel from . . . ");
	retv = single_type_relabel_from(sets, get_type_idx("sysadm_t", policy),
					get_type_idx("sysadm_home_t", policy),
					&array, &size, policy);
	errorprint(retv);
	printf("done.\n");

	print_type_list(array, size, policy, stdout);

	printf("querying can relabel what . . . ");
	retv = type_relabels_what(sets, get_type_idx("sysadm_t", policy), &out_set, policy);
	errorprint(retv);
	printf("done.\n");

	print_relabel_set(out_set, policy, stdout);
*/
	printf("\nrunning relabel to analysis\n");
	retv = type_relabel_to(sets, get_type_idx("sysadm_home_t", policy), res, policy);
	if(retv != NOERROR){
		fprintf(stderr, "bad result set\n");
		errorprint(retv);
	}
/*	print_relabel_result(res, policy, stdout);

	printf("\nrunning relabel from analysis\n");
	retv = type_relabel_from(sets, get_type_idx("sysadm_home_t", policy), res, policy);
	if(retv != NOERROR){
		fprintf(stderr, "bad result set\n");
		errorprint(retv);
	}
	print_relabel_result(res, policy, stdout);
*/
	printf("\nrunning filter on previous results\n");
	dummy[0] = get_perm_idx("write", policy);
	dummy[1] = get_perm_idx("getattr", policy);
	perm_set.perms = &(dummy[0]);
	perm_set.num_perms = 2;
	perm_set.obj_class = get_obj_class_idx("file", policy);
	retv = perm_filter(sets, &perm_set, 1, res, policy);
	if(retv != NOERROR){
		fprintf(stderr, "bad result set\n");
		errorprint(retv);
	}
	print_relabel_result(res, policy, stdout);

/*	printf("\nrunning domain relabeling analysis\n");
	retv = domain_relabel_types(sets, get_type_idx("sysadm_t", policy), res, policy);
	if(retv != NOERROR){
		fprintf(stderr, "bad result set\n");
		errorprint(retv);
	}
	print_relabel_result(res, policy, stdout);

	printf("\nrunning filter on previous results\n");
	retv = perm_filter(sets, &perm_set, 1, res, policy);
	if(retv != NOERROR){
		fprintf(stderr, "bad result set\n");
		errorprint(retv);
	}
	print_relabel_result(res, policy, stdout);


*/
	if(res){	
		free_relabel_result_data(res);
		free(res);
	}
	if(array) free(array);
	if(policy) free(policy);
	if(sets) free(sets);

	printf("\nEND OF TESTS\n");

	return 0;
}
 
