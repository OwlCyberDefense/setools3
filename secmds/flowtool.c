/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Jason Tang (jtang@tresys.com)
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "flowassert.h"
#include "infoflow.h"
#include "perm-map.h"
#include "policy.h"
#include "policy-io.h"
#include "render.h"
#include "util.h"

extern FILE *flowin;
extern void flow_scan_string (char *);

static int do_assertions (char * assertion_contents);
static void parse_command_line (int argc, char **argv);
static void print_version_info(void);
static void usage(char *program_name, bool_t brief);

static policy_t *policy;
static bool_t quiet, short_circuit;

static char *policy_conf_file = NULL;
static char *permission_map_file = NULL;
static char *assert_file = NULL;
static struct option opts[] = 
{
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"policy", required_argument, NULL, 'p'},
        {"permmap", required_argument, NULL, 'm'},
        {"quiet", no_argument, NULL, 'q'},
        {"short-circuit", no_argument, NULL, 's'},
	{NULL, 0, NULL, 0}
};

/* Actually executes the assertions, stored as a null-terminated
 * buffer of newline separated strings.  Takes the results of
 * executions, as a linked list of flow_assert_results_t, and
 * determines what each represent (a success, failure, or some other
 * error.)  Prints to standard out any errors/warnings, but only if
 * 'quiet' is not true.  Returns -1 if execution itself failed (such
 * as out of memory), 0 if all assertions correct, or otherwise a
 * count of total number of warnings and errors. */
static int do_assertions (char *assertion_contents) {
        int num_errors = 0;
        llist_t *results_list;
        llist_node_t *result_node;
    
        results_list = execute_flow_assertion (assertion_contents, policy,
                                               short_circuit);    
        if (results_list == NULL) {
                return -1;
        }
        for (result_node = results_list->head; result_node != NULL;
             result_node = result_node->next) {
                flow_assert_results_t *results =
                        (flow_assert_results_t *) result_node->data;
                if (results->assert_result != FLOW_ASSERT_VALID) {
                        num_errors++;
                }
                if (quiet == TRUE) {
                        continue;
                }
                (void) printf ("line %ld: ", results->rule_lineno);
                switch (results->assert_result) {
                case FLOW_ASSERT_VALID: {
                        (void) printf ("Passed.\n");
                        break;
                }
                case FLOW_ASSERT_FAIL: {
                        int i;
                        char *s = (results->num_rules == 1 ? "" : "s");
                        (void) printf ("Assertion failed, conflict%s found:\n", s);
                        for (i = 0; i < results->num_rules; i++) {
                                flow_assert_rule_t *rule = results->rules + i;
                                char *from, *to;
                                if ((get_type_name (rule->start_type,&from,policy)) != 0) {
                                        from = "<unknown type>";
                                }
                                if ((get_type_name (rule->end_type, &to, policy)) != 0) {
                                        to = "<unknown type>";
                                }
                                if (rule->num_rules > 0) {
                                        int j;
                                        (void) printf ("  %s to %s:\n", from, to);
                                        for (j = 0; j < rule->num_rules; j++) {
                                                char *rule_string = re_render_av_rule (FALSE, rule->rules [j], FALSE, policy);
                                                int rule_lineno = get_rule_lineno (rule->rules [j], RULE_TE_ALLOW, policy);
                                                (void) printf ("    ");
                                                if (is_binary_policy (policy) == 0) {
                                                        (void) printf ("[%d] ", rule_lineno);
                                                }
                                                (void) printf ("%s\n", rule_string);
                                                free (rule_string);
                                        }
                                }
                                else if (rule->via_type >= 0) {
                                        char * via;
                                        if ((get_type_name (rule->via_type,&via,policy)) != 0){
                                                via = "<unknown type>";
                                        }
                                        (void) printf ("  no rule from %s to %s via %s\n",
                                                       from, to, via);
                                }
                                else {
                                        (void) printf ("  no rule from %s to %s\n", from, to);
                                }
                        }
                        break;
                }
                case FLOW_ASSERT_BAD_FORMAT: {
                        (void) printf ("Assertion has illegal mix of options.\n");
                        break;
                }
                case FLOW_ASSERT_UNKNOWN_TYPE: {
                        (void) printf ("Unknown type or attribute specified.\n");
                        break;
                }
                case FLOW_ASSERT_UNKNOWN_CLASS: {
                        (void) printf ("Unknown class specified.\n");
                        break;
                }
                case FLOW_ASSERT_UNKNOWN_VARIABLE: {
                        (void) printf ("Variable undeclared.\n");
                        break;
                }
                case FLOW_ASSERT_SYNTAX_ERROR: {
                        (void) printf ("Syntax error.\n");
                        break;
                }
                case FLOW_ASSERT_ERROR: {
                        (void) printf ("Out of memory\n");
                        break;
                }
                default: {
                        (void) printf ("Invalid return value from execute_flow_execute(): %d\n",
                                       results->assert_result);
                }
                }
        }
        ll_free (results_list, flow_assert_results_destroy);
        return num_errors;
}

/* Parse the command line and set all global options. */
static void parse_command_line(int argc, char **argv)
{
	int optc;
	bool_t help, ver;

	help = ver = FALSE;
        quiet = short_circuit = FALSE;
	while ((optc = getopt_long(argc, argv, "p:m:qsvh", opts, NULL)) != -1) {
                switch(optc) {
                case 'p':
                        policy_conf_file = optarg;
                        break;
                case 'm': {
                        permission_map_file = optarg;
                        break;
                }
                case 'q': { quiet = TRUE; break; }
                case 's': { short_circuit = TRUE; break; }
		case 'h':
                        help = TRUE;
                        break;
		case 'v':
                        ver = TRUE;
                        break;
		case '?':
                        usage(argv[0], FALSE);
                        exit(1);
		default:
                        break;
                }
	}
	if (help || ver) {
                if (help)
                        usage(argv[0], FALSE);
                if (ver)
                        print_version_info();
                exit(1);
	}
        if (optind >= argc) {  /* ran out of arguments */
                (void) printf ("%s: Not enough arguments.\n", argv [0]);
                usage (argv [0], TRUE);
                exit (1);
        }
	else if (optind + 1 < argc) { /* trailing non-options */
                printf("non-option arguments: ");
                while (optind < argc)
                        printf("%s ", argv[optind++]);
                printf("\n");
                exit(1);
	}
        if (strcmp (argv [optind], "-") == 0) {
                assert_file = NULL;
        }
        else {
                assert_file = argv [optind];
        }
}

static void print_version_info(void)
{
	printf("Batch Information Flow Analysis Tool for Security Enhanced Linux.\n\n");
	printf("   libapol version %s\n\n", libapol_get_version());
	return;
}

static void usage(char *program_name, bool_t brief)
{
	printf("Usage: %s [OPTIONS] FILE\n", program_name);
	if (brief) {
		printf("   Try %s --help for more help.\n\n", program_name);
		return;
	}
	printf("Command line interpreter for batch information flow assertion language.\n");
        printf("   FILE                     file containing assertions, '-' for stdin\n");
	printf("   -p FILE, --policy FILE   open policy file named FILE\n");
        printf("   -m FILE, --permmap FILE  open permission map FILE\n");
        printf("   -q, --quiet              be quiet; just return a value\n");
        printf("   -s, --short-circuit      abort upon first failed rule\n");
	printf("   -v, --version            display version information\n");
	printf("   -h, --help               display this help dialog\n\n");
	return;
}


int main (int argc, char *argv []) {
        char *flowfile, *s;
        char buf [1024];
        size_t amount_read, flowfile_size;
        int results, ret, retv;
        FILE *pfp;
    
        /* gather options */
        parse_command_line (argc, argv);
        if (policy_conf_file == NULL) {
                retv = find_default_policy_file(POL_TYPE_BINARY|POL_TYPE_SOURCE, &policy_conf_file);
		if (!policy_conf_file || retv) {
			fprintf(stderr, "error finding default policy\n");
			return retv;
		}
        }
        if (permission_map_file == NULL) {
                permission_map_file = APOL_DEFAULT_PERM_MAP;
        }
    
        if ((open_policy (policy_conf_file, &policy)) != 0) {
                exit (2);
        }
    
        /* open the permission map file and parse it */
        if ((pfp = fopen (permission_map_file, "r")) == NULL) {
                (void) fprintf (stderr, "%s: Could not open permission map file %s.\n", argv [0], permission_map_file);
                exit (2);
        }
        ret = load_policy_perm_mappings (policy, pfp);
        (void) fclose (pfp);
        if (ret & PERMMAP_RET_ERROR) {
                (void) fprintf (stderr, "%s: Error while loading permission map file %s.\n", argv [0], permission_map_file);
                exit (2);
        }
        if (assert_file == NULL) {
                flowin = stdin;
        }
        else {
                if ((flowin = fopen (assert_file, "r")) == NULL) {
                        (void) fprintf (stderr, "%s: Could not open assertion file %s for reading.\n", argv [0], assert_file);
                        exit (2);
                }
        }
        /* read in contents of file */
        flowfile_size = 0;
        if ((flowfile = strdup ("")) == NULL) {
                (void) fprintf (stderr, "Out of memory!\n");
                exit (2);
        }
        while ((amount_read = fread (buf, 1, sizeof (buf), flowin)) > 0) {
                if ((s = realloc (flowfile, flowfile_size + amount_read + 1)) == NULL) {
                        (void) fprintf (stderr, "error in realloc\n");
                        exit (2);
                }
                flowfile = s;
                (void) memcpy (flowfile + flowfile_size, buf, amount_read);
                flowfile_size += amount_read;
                flowfile [flowfile_size] = '\0';
        }
        (void) fclose (flowin);
        if (flowfile_size > 0) {
                results = do_assertions (flowfile);
        }
        else {
                results = 0;
        }
        free (flowfile);
        if (results != 0) {
                exit (1);
        }
        exit (0);
}
