#include "policy.h"
#include "policy-io.h"
#include "poldiff.h"
#include <assert.h>

int main()
{
	ap_single_view_diff_t *svd;
	policy_t *p1, *p2;
	int i;

	for (i=0; i<5; i++) {
		assert(open_policy("./policy/small16.conf", &p1) >= 0);
		assert(open_policy("./policy/small17.conf", &p2) >= 0);
		
		svd = ap_single_view_diff_new(POLOPT_ALL, p1, p2, NULL);
		assert(svd);
		
		ap_single_view_diff_sort_te_rules(svd, AP_SRC_TYPE, AP_SVD_OPT_ALL, i%2);
		
		ap_single_view_diff_destroy(svd);
		close_policy(p1);
		close_policy(p2);
	}

	return 0;
}
