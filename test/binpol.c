#include "policy.h"
#include "policy-io.h"
#include "binpol/binpol.h"
#include "test.h"
#include <stdio.h>

int main(int argc, char **argv)
{
	FILE *fp;
	int ver;
	policy_t *policy;
	
	init_tests(argc, argv);
	
	/* test reading the policy version */
	fp = fopen("policy/binary_small.17", "r");
	TEST("open binary policy", fp);
	ver =  ap_binpol_version(fp);
	printf("version is %d\n", ver);
	TEST("getting version", ver == 17);
	fclose(fp);
	
	/* reading a binary policy */
	TEST("load", open_policy("policy/binary_small.17", &policy) == 0);
	free_policy(&policy);

	/* test reading the policy version */
	fp = fopen("policy/mls_policy.19", "r");
	TEST("open mls binary policy", fp);
	ver =  ap_binpol_version(fp);
	printf("version is %d\n", ver);
	TEST("getting version", ver == 19);
	fclose(fp);
	
	/* reading a binary policy */
	TEST("load mls binary", open_policy("policy/mls_policy.19", &policy) == 0);
	free_policy(&policy);

	/* test reading the policy version */
	fp = fopen("policy/policy.20", "r");
	TEST("open v20 binary policy", fp);
	ver =  ap_binpol_version(fp);
	printf("version is %d\n", ver);
	TEST("getting version", ver == 20);
	fclose(fp);
	
	/* reading a binary policy */
	TEST("load v20", open_policy("policy/policy.20", &policy) == 0);
	free_policy(&policy);

	return 0;	
}
