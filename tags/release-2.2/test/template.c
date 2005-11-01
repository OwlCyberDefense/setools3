/* example unit test - see Makefile for information about building
 *
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 */

/* this is the main include for testing */
#include "test.h"
/* libapol files can be included directly */
#include "policy.h"
#include "policy-io.h"

policy_t *policy;

int main(int argc, char **argv)
{
	int rand;
	/* the test framework needs to be initialized so
	 * that it will pick up command line arguments
	 * that it cares about.
	 */
	init_tests(argc, argv);

	/* testing of conditions is done with the TEST macro.
	 * This prints a message letting the user know which
	 * test is being performed, tests the passed in
	 * condition, and exits if it fails (and dumps core
	 * if -c was passed in as a command-line argument).
	 */
	TEST("example testing a constant", 1);

	/* The policy directory holds examples policies that the
	 * tests can use. Any policies specific for this unit
	 * test should be added in that directory and named
	 * appropriately.
	 */
	TEST("loading a policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);

	/* It is often helpful to use random numbers in testing - to
	 * facilitate this get_rand_int is included that generates
	 * a random int between the passed in values (including the
	 * limits - i.e. get_rand_int(1, 10) returns numbers between
	 * 1 and 10 including 1 and 10).
	 */
	rand = get_rand_int(10, 20);
	TEST("random numbers", rand >= 10 && rand <= 20);

	/* Always return 0 on success for automated scripts */
	return 0;
}
