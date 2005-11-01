#include "policy.h"
#include "policy-io.h"
#include "test.h"
#include "infoflow.h"
#include "poldiff.h"




int main(int argc, char **argv)
{	
	apol_diff_result_t *diff;
	ap_single_view_diff_t *svd;
	policy_t *p1;
	policy_t *p2;
	int_a_diff_t *iad;
	ap_rtrans_diff_t *ard;

	unsigned int opts = POLOPT_ALL;
	int i;


	init_tests(argc, argv);
	
	/* load up the policies */
	TEST("load policy 1", open_policy("policy/rbac1.conf", &p1) == 0);
	TEST("load policy 2", open_policy("policy/rbac2.conf", &p2) == 0);

	/* diff them */
	TEST("diff policies", (svd = ap_single_view_diff_new(opts, p1, p2, NULL)) != NULL);

	diff = svd->diff;
	/* role allow differences */
	/* 
	   there should be 3 different role allow rules 
	   1 added/removed, 1 changed, 1 missing role in tgt 
	   in each direction 
	*/
	TEST("num role allow diffs from P1->P2 is 3",diff->diff1->num_role_allow == 3);
	TEST("num role allow diffs from P2->P1 is 3",diff->diff2->num_role_allow == 3);

	/* test that the iads are in the right order */
	i = 0;
	iad = diff->diff1->role_allow;
	if(strcmp(iad->str_id,"a_r") == 0)
		i++;
	iad = iad->next;
	if(strcmp(iad->str_id,"c_r") == 0)
		i++;
	iad = iad->next;
	if(strcmp(iad->str_id,"e_r") == 0)
		i++;
	TEST("Role rules are in correct order", i == 3);
	

	/* Here we recall the iads are added in alpha order so this is why we test them like this */
	iad = diff->diff1->role_allow;
	/* test that the rule a_r { c_r f_r } is marked as changed */
	TEST("Rule \"allow a_r { c_r f_r }\" is changed from P2",iad->missing == FALSE);

	iad = iad->next;
	/* test that the rule c_r e_r is marked as changed */
	TEST("Rule \"allow c_r e_r\" is changed from P2",iad->missing == FALSE);

	iad = iad->next;
	/* test that the rule c_r e_r is marked as missing */
	TEST("Rule \"allow e_r c_r\" is missing from P2",iad->missing == TRUE);
	
	iad = diff->diff2->role_allow;
	/* test that allow a_r { b_r f_r }; is marked as changed */
	TEST("Rule \"allow a_r { b_r f_r };\" is changed from P1",iad->missing == FALSE);
	
	iad = iad->next;
	/* test that allow c_r d_r; is marked as changed */
	TEST("Rule \"allow c_r d_r;\" is changed from P1",iad->missing == FALSE);
	
	iad = iad->next;
	/* test that allow d_r c_r; is marked as missing */
	TEST("Rule \"allow d_r c_r;\" is missing from P1",iad->missing == TRUE);

	/* 
	   there should be 6 different role trans rules in each direction
	   1 missing/added complete rule
	   1 changed rule
	   1 rule missing/added where the type is not in the other policy
	   1 rule missing/added where the source role is not in the other policy
	   1 role changed where the target role is not in the other policy
	   1 rule missing where the attribute is not matched by rule in other policy
	*/
	TEST("num role trans diffs from P1->P2 is 6",diff->diff1->num_role_trans == 6);
	TEST("num role trans diffs from P2->P1 is 6",diff->diff2->num_role_trans == 6);

	/* role rules are prepended to the list so have to search in reverse */
	ard = diff->diff1->role_trans;
	
	/* test that role_transition e_r b_t b_r; has all right parts */
	TEST("Rule \"role_transition e_r b_t b_r;\" is 1st node",
	     get_role_idx("e_r",p1) == ard->rs_idx &&
	     get_type_idx("b_t",p1) == ard->t_idx &&
	     get_role_idx("b_r",p1) == ard->rt_idx);
	/* test that role_transition e_r b_t b_r; is marked as not missing */
	TEST("Rule \"role_transition e_r b_t b_r;\" is missing in P2",ard->missing == TRUE);

	ard = ard->next;
	/* test that role_transition c_r b_t e_r; has all right parts */
	TEST("Rule \"role_transition c_r b_t e_r;\" is 2nd node",
	     get_role_idx("c_r",p1) == ard->rs_idx &&
	     get_type_idx("b_t",p1) == ard->t_idx &&
	     get_role_idx("e_r",p1) == ard->rt_idx);
	/* test that role_transition c_r b_t e_r; is marked as not missing */
	TEST("Rule \"role_transition c_r b_t e_r;\" is changed in P2",ard->missing == FALSE);

	ard = ard->next;
	/* test that role_transition b_r a_t a_r; has all right parts */
	TEST("Rule \"role_transition b_r a_t a_r;\" is 3rd node",
	     get_role_idx("b_r",p1) == ard->rs_idx &&
	     get_type_idx("a_t",p1) == ard->t_idx &&
	     get_role_idx("a_r",p1) == ard->rt_idx);
	/* test that role_transition b_r a_t a_r; is marked as not missing */
	TEST("Rule \"role_transition b_r a_t a_r;\" is not missing in P2",ard->missing == FALSE);

	ard = ard->next;
	/* test that role_transition a_r atriba b_r; has all right parts */
	TEST("Rule \"role_transition a_r atriba b_r;\" is 4th node",
	     get_role_idx("a_r",p1) == ard->rs_idx &&
	     get_type_idx("f_t",p1) == ard->t_idx &&
	     get_role_idx("b_r",p1) == ard->rt_idx);
	/* test that role_transition a_r atriba b_r; is marked as missing */
	TEST("Rule \"role_transition a_r atriba b_r; atriba = f_t \" is missing from P2",ard->missing == TRUE);

	ard = ard->next;
	/* test that role_transition a_r e_t b_r; has all right parts */
	TEST("Rule \"role_transition a_r e_t b_r;\" is 5th node",
	     get_role_idx("a_r",p1) == ard->rs_idx &&
	     get_type_idx("e_t",p1) == ard->t_idx &&
	     get_role_idx("b_r",p1) == ard->rt_idx);
	/* test that role_transition a_r e_t b_r; is marked as  missing */
	TEST("Rule \"role_transition a_r e_t b_r;\" is missing in P2",ard->missing == TRUE);


	ard = ard->next;
	/* test that role_transition a_r a_t b_r; has all right parts */
	TEST("Rule \"role_transition a_r a_t b_r;\" is 6th node",
	     get_role_idx("a_r",p1) == ard->rs_idx &&
	     get_type_idx("a_t",p1) == ard->t_idx &&
	     get_role_idx("b_r",p1) == ard->rt_idx);
	/* test that role_transition a_r a_t b_r; is marked as missing */
	TEST("Rule \"role_transition a_r a_t b_r;\" is missing in P2",ard->missing == TRUE);



	/* cleanup the pointers */
	ap_single_view_diff_destroy(svd);

	return 0;
}
