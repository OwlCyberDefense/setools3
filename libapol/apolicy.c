/* Copyright (C) 2001, 2002 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* apolicy
 *
 * This file contains the command line interface to the policy analysis engine.
 * 
 * A basic analysis tool for examining SE Linux security policies.
 * This is intended to examine "policy.conf"  files *after* checkpolicy
 * has successfully parsed the file.  We not real careful about ensuring
 * we have a valid policy.conf file; the assumption is that checkpolicy
 * was run first (although we use checkpolicy's lexer and parser)!
 *
 */
 
/* Some of the code was "borrowed",from SE Linux's checkpolicy program,
 * especially the Lex and YACC stuff, as well as the queue functions
 * The policy database and serach/analysis stuff is all of our own 
 * making specifically for policy analysis. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "util.h"
#include "queue.h"
#include "policy.h"
#include "analyze.h"

extern unsigned int policydb_lineno;
extern policy_t *policy; /*apolicy_parse.y, our policy DB */
extern queue_t id_queue;
extern FILE *yyin;
extern int yyparse(void);
extern void yyrestart(FILE *);
extern unsigned int pass;

#define VERSION_STRING "SELinux Policy Analyzer (version 0.4 WORKING)"


/* converts char to integer, or return -1 if not digit */
int ctoi(char c)
{
	switch(c) {
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	default:
		return -1;
	}
}


bool_t check_yn_ans(char in_ans, const char def_ans, bool_t *bool_ans)
{
	char ans;
	if(in_ans == '\n')
		ans = def_ans;
	else if(in_ans == 'y')
		ans = 'y';
	else if(in_ans == 'n')
		ans = 'n';
	else 
		return 0;
		
	if(ans == 'y')
		*bool_ans = 1;
	else
		*bool_ans = 0;
	
	return 1;
}

int seach_ta_using_substring(FILE *outfp)
{
	int rt;
	char string[81], ans[81];
	bool_t full_info, do_types, do_attribs, use_aliases, ok;
	
	printf("\n Enter substring:  ");
	fgets(string, sizeof(string), stdin);
	fix_string(string, sizeof(string));
	
	ok = 0;
	while(!ok) {
		printf("\tSearch Types? [y]:  ");
		fgets(ans, sizeof(ans), stdin);	
		ok = check_yn_ans(ans[0], 'y', &do_types);
	}
	if(do_types) {
		ok = 0;
		while(!ok) {
			printf("\tUse Type Aliases? [y]:  ");
			fgets(ans, sizeof(ans), stdin);
			ok = check_yn_ans(ans[0], 'y', &use_aliases);
		}
	}
	ok = 0;
	while(!ok) {
		printf("\tSeach Type Attributes? [n]:  ");
		fgets(ans, sizeof(ans), stdin);	
		ok = check_yn_ans(ans[0], 'n', &do_attribs);
	}
	ok = 0;
	while(!ok) {
		printf("\tPrint all information about selected types/attributes? [n]:  ");
		fgets(ans, sizeof(ans), stdin);	
		ok = check_yn_ans(ans[0], 'n', &full_info);
	}

	rt = find_ta_using_substring(string, do_types, do_attribs, use_aliases, full_info, policy, outfp);
	if(rt != 0)
		return rt;
	
	return 0;	
}

int display_roles(FILE *outfp) 
{
	char ans[81];
	int rt, numperline = 5, num;
	printf("\n  Select role display options:\n");
	printf("    1)  show role names only \n");
	printf("    2)  show everything about all roles\n");	
	printf("    Selection:  ");
	
	fgets(ans, sizeof(ans), stdin);	
	fprintf(outfp, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");		
	switch(ans[0]) {
	case '1': /* role names only */
		rt = print_roles(0, 0, policy, outfp);
		if(rt != 0) {
			printf("Could not display role names");			
			return rt;
		}
		break;
	case '2': /* everything about all roles */
		printf("\n     How many types to print per line ('0' for all on one line) [5]:  ");
		fgets(ans, sizeof(ans), stdin);
		if(!isspace(ans[0])) {
			num = ctoi(ans[0]);
			if(num < 1)
				numperline = 0; /* means no newline */
			else 
				numperline = num;
		}
		rt = print_roles(1, numperline, policy, outfp);
		if(rt != 0) {
			printf("Could not display role information");			
			return rt;
		}
		break;
	default:
		printf("Bad role display option\n");
		return -1;
		break;
	}
	fprintf(outfp, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
	return 0;
}

int display_role_rules(FILE *outfp)
{
	char ans[81];
	int rt;
	printf("\n  Select role-based access control rules to display:\n");
	printf("    1)  role allow rules\n");
	printf("    Selection:  ");
	
	fgets(ans, sizeof(ans), stdin);	
	fprintf(outfp, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");		
	switch(ans[0]) {
	case '1': /* role allow rule */
		rt = print_role_allow_rules(policy, outfp);
		if(rt != 0) {
			printf("Could not display role allow rules");			
			return rt;
		}
		break;
	default:
		printf("Bad RBAC display option\n");
		return -1;
		break;
	}
	return 0;
}



int display_types(FILE *outfp)
{
	char ans[81];
	int rt;
	printf("\n  Select type/attribute display options:\n");
	printf("    1)  show everything about all types \n");
	printf("    2)  show everything about all attributes\n");	
	printf("    3)  show only type names\n");
	printf("    4)  show only attribute names\n");
	printf("    5)  show everthing about ONE type or attribute\n");
	printf("    6)  find all types containing two given attributes\n");
	printf("    7)  find types and/or attributes whose name contains a substring\n");
	printf("    Selection:  ");
	
	fgets(ans, sizeof(ans), stdin);	
	fprintf(outfp, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");		
	switch(ans[0]) {
	case '1': /*everthing about types*/
		rt = print_type_analysis(1,1,0,0,0,policy, outfp);
		if(rt != 0) {
			printf("Could not display types and attributes information");			
			return rt;
		}
		break;
	case '2': /*everything about attribs */
		rt = print_type_analysis(0,0,1,1,1,policy, outfp);
		if(rt != 0) {
			printf("Could not display types and attributes information\n");		
			return rt;
		}	
		break;			
	case '3': /* only type names */
		rt = print_type_analysis(1,0,0,0,0,policy, outfp);
		if(rt != 0) {
			printf("Could not display types and attributes information\n");		
			return rt;
		}	
		break;	
	case '4': /* only attrib names */
		rt = print_type_analysis(0,0,1,0,0,policy, outfp);
		if(rt != 0) {
			printf("Could not display types and attributes information\n");		
			return rt;
		}	
		break;	
	case '5': /* ONE specified type or attribute */
	{
		int idx, idx_type;	
		printf("\nEnter type or attrbiute name:  ");
		fgets(ans, sizeof(ans), stdin);
		fix_string(ans, sizeof(ans));
		idx = get_type_or_attrib_idx(ans, &idx_type, policy);
		if(idx < 0) {
			printf("%s is not a valid type or type attribute\n", ans);
			return -1;
		}
		if(idx_type == IDX_TYPE) {
			fprintf(outfp, "Type: ");
			rt = print_type(1,1,1, idx, policy, outfp);
		}
		else if(idx_type == IDX_ATTRIB) {
			fprintf(outfp, "Type Attribute: ");
			rt = print_attrib(1,1,1,0,idx, policy, outfp);
		}
		else {
			printf("Invalid index type (%d), neither Type nor Attribute\n", idx_type);
		}
		if(rt != 0) {
			printf("Could not display information for type or attrbiute: %s\n", ans);
			return rt;
		}
		break;			
	}
	case '6': /* types containing two given attributes */
	{
		int idx1, idx2, rt;
		printf("\nEnter first attribute name:  ");
		fgets(ans, sizeof(ans), stdin);
		fix_string(ans, sizeof(ans));
		idx1 = get_attrib_idx(ans, policy);
		if(idx1 < 0) {
			printf("%s is not a valid type attribute\n", ans);
			return -1;
		}
		printf("\nEnter second attribute name:  ");
		fgets(ans, sizeof(ans), stdin);
		fix_string(ans, sizeof(ans));
		idx2 = get_attrib_idx(ans, policy);
		if(idx2 < 0) {
			printf("%s is not a valid type attribute\n", ans);
			return -1;
		}
		rt = find_types_by_two_attribs(idx1, idx2, 0, policy, outfp);
		if(rt != 0) {
			printf("Error searching types for attributes\n");
			return rt;
		}
		break;
	}
	case '7': /* substring match */
		rt = seach_ta_using_substring(outfp);
		if(rt != 0) {
			printf("Error searching types for attributes\n");
			return rt;
		}
	break;
	default:
		printf("Bad type/attribute display option\n");
		return -1;
		break;
	}	
	fprintf(outfp, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
	return 0;		
}

int display_type_rules(FILE *outfp)
{
	char ans[81];
	int rt;
	printf("\n  Select rule display options:\n");
	printf("1)  display AV type rules\n");
	printf("2)  display type transition, member, change rules\n");
	printf("3)  display clone rules\n");
	printf("    Selection:  ");
	
	fgets(ans, sizeof(ans), stdin);	
	fprintf(outfp, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");	
	switch(ans[0]) {
	case '1':
		rt = print_av_rules(1,1, policy, outfp);
		if(rt != 0) {
			printf("Could not display AV rules information\n");			
			return rt;
		}
		break;			
	case '2':
		rt = print_tt_rules(policy, outfp);
		if(rt != 0) {
			printf("Could not display transition rules information\n");			
			return rt;
		}
		break;				
	case '3':
		rt = print_clone_rules(policy, outfp);
		if(rt != 0) {
			printf("Could not display clone rules information\n");
			return rt;
		}
		break;
	default:
		printf("Bad rule display option\n");
		return -1;
		break;
	}
	fprintf(outfp, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
	return 0;
}

int search_te_rules_one_type(FILE *outfp)
{
	int idx, idx_type, rt;	
	bool_t ok, do_indirect;
	char ans[81];
	printf("enter type or attrbiute name:  ");
	fgets(ans, sizeof(ans), stdin);
	fix_string(ans, sizeof(ans));
	idx = get_type_or_attrib_idx(ans, &idx_type, policy);
	if(idx < 0) {
		printf("%s is not a valid type nor type attribute\n", ans);
		return -1;
	}
	
	if(idx_type == IDX_TYPE) {
		ok = 0;
		while(!ok) {
			printf("\tInclude indirect matches (e.g., using atttributes)? [n]:  ");
			fgets(ans, sizeof(ans), stdin);	
			ok = check_yn_ans(ans[0], 'n', &do_indirect);
		}
	}
	
	rt = find_te_rules(idx, idx_type, 1, do_indirect, policy, outfp);
	if(rt != 0) {
		printf("Could not show matching rules\n");
		return rt;
	}
	return 0;
}

#ifdef CLONE_EXPANSION
int search_cloned_rules(FILE *outfp)
{	
	int idx, rt;
	char ans[81];
	printf("name of type to which rules are being cloned (clone rule's target type):  ");
	fgets(ans, sizeof(ans), stdin);
	fix_string(ans, sizeof(ans));	
	
	idx = get_type_idx(ans, policy);
	
	if(idx < 0) {
		printf("%s is not a valid type n\n", ans);
		return -1;
	}	
	
	rt = find_cloned_rules(idx, 1, policy, outfp); 		
	if(rt != 0) {
		printf("Could not find cloned rules\n");
		return rt;
	}
	
	return 0;
}
#endif

int search_te_rules_src_tgt_types(bool_t do_src, bool_t do_tgt, FILE *outfp)
{
	int src, tgt, src_type, tgt_type, rt;	
	bool_t ok, do_indirect;
	char ans[81];

	if(!do_src && !do_tgt)
		return -1;
		
	if(do_src) {
		printf("enter SOURCE type or attrbiute name:  ");
		fgets(ans, sizeof(ans), stdin);
		fix_string(ans, sizeof(ans));
		src = get_type_or_attrib_idx(ans, &src_type, policy);
		if(src < 0) {
			printf("%s is not a valid type nor type attribute\n", ans);
			return -1;
		}
	}
	else {
		src = -1;
	}
		
	if(do_tgt) {
		printf("enter TARGET type or attrbiute name:  ");
		fgets(ans, sizeof(ans), stdin);
		fix_string(ans, sizeof(ans));
		tgt = get_type_or_attrib_idx(ans, &tgt_type, policy);
		if(tgt < 0) {
			printf("%s is not a valid type nor type attribute\n", ans);
			return -1;
		}
	}
	else {
		tgt = -1;	
	}
		
	if(src_type == IDX_TYPE || tgt_type == IDX_TYPE ) {
		ok = 0;
		while(!ok) {
			printf("\tInclude indirect matches (e.g., using atttributes)? [n]:  ");
			fgets(ans, sizeof(ans), stdin);	
			ok = check_yn_ans(ans[0], 'n', &do_indirect);
		}
	}		
	
	rt = find_te_rules_by_src_tgt(src, src_type, tgt, tgt_type, 1, do_indirect, policy, outfp);
	if(rt != 0) {
		printf("Could not show matching rules\n");
		return rt;
	}
	return 0;	
}

int search_type_rules(FILE *outfp)
{
	char ans[81];
	int rt;
	printf("\n  Select a search type:\n");
	printf("1)  Find TE rules assoicated with a given type/attribute as EITHER source or target\n");
	printf("2)  Find TE rules assoicated with a given SOURCE type/attribute\n");
	printf("3)  Find TE rules assoicated with a given TARGET type/attribute \n");
	printf("4)  Find TE rules assoicated with a given SOURCE and TARGET type/attribute\n");
#ifdef CLONE_EXPANSION
	printf("5)  Find TE rules that are CLONED for a given type (NOT FULLY TESTED!)\n");
#endif
	printf("    Selection:  ");
	fgets(ans, sizeof(ans), stdin);	
	
	fprintf(outfp, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");	
	switch(ans[0]) {
	case '1':
		rt = search_te_rules_one_type(outfp);
		if(rt != 0)
			return rt;
		break;			
	case '2': /*source */
		rt = search_te_rules_src_tgt_types(1,0,outfp);
		if(rt != 0)
			return rt;
		break;		
	case '3':/* target */
		rt = search_te_rules_src_tgt_types(0,1,outfp);
		if(rt != 0)
			return rt;
		break;	
	case '4': /* both */
		rt = search_te_rules_src_tgt_types(1,1,outfp);
		if(rt != 0)
			return rt;
		break;	
#ifdef CLONE_EXPANSION
	case '5': /* cloned rules */
		rt = search_cloned_rules(outfp);
		if(rt != 0)
			return rt;
		break;
#endif
	default:
		printf("Bad search type\n");
		return -1;
		break;
	}
	fprintf(outfp, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
	return 0;
}		

int read_policy(void)
{
	/* assumed yyin is opened to policy file */
	id_queue = queue_create();
	if (!id_queue) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policydb_lineno = 1;
	pass = 1;
	if (yyparse()) {
		fprintf(stderr, "error(s) encountered while parsing configuration\n");
		return -1;
	}
	policydb_lineno = 1;
	pass = 2;
	rewind(yyin);
	yyrestart(yyin);	
	if (yyparse()) {
		fprintf(stderr, "error(s) encountered while parsing configuration\n");
		return -1;
	}
		
	queue_destroy(id_queue);
	fclose(yyin);
	return 0;		
}

int open_policy(void) 
{
	int rt;
	rt = init_policy(&policy);
	if(rt != 0) {
		fprintf(stderr, "error initializing policy\n");
		return -1;
	}
	rt = read_policy();
	if(rt != 0) {
		fprintf(stderr, "error reading policy\n");
		return -1;	
	}
	return 0;
}

	
int menu() {
	printf("\nSelect a command:\n");
	printf("0)  show policy statics and summary\n");
	printf("1)  show information about types & attributes \n");
	printf("2)  dump type-enforcement rules \n");
	printf("3)  search type-enforcement rules\n");
	printf("4)  show information about roles\n");
	printf("5)  dump role-based access control rules\n");
	printf("\n");
	printf("f)  change output file\n");
	printf("p)  reload same or differnt policy file\n");
	printf("v)  show tool verion\n");
	printf("m)  display menu\n");
	printf("q)  quit\n");
	return 0;
}

int main (int argc, char **argv)
{
	int rt, opened_file;
	FILE *outfp, *fp2;
	char ans[81], pol_file[81];

	if(argc < 2 || argc > 3)
		goto usage;
		
	if ((yyin = fopen(argv[1], "r")) == NULL) {
		fprintf (stderr, "%s: cannot open policy file %s\n", argv[0], argv[1]);
		exit(1);
	}
	strncpy(pol_file, argv[1], 80);
	
	if(argc == 3) {
		if((outfp = fopen(argv[2], "w+")) == NULL) {
			fprintf(stderr, "%s: cannot open output file %s\n", argv[0], argv[1]);
			exit(1);
		}
		opened_file = 1;
	}
	else {
		opened_file = 0;
		outfp = stdout;
	}
	
	rt = open_policy();
	if(rt != 0)
		exit(1);
	
	print_policy_summary(policy, stdout);
	menu();
	for(;;) {
		printf("\nCommand (\'m\' for menu):  ");
		fgets(ans, sizeof(ans), stdin);	
		
		switch(ans[0]) {
		case '0':
			fprintf(outfp, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");		
			print_policy_summary(policy, outfp);
			fprintf(outfp, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
			break;
		case '1': 
			display_types(outfp);
			break;
		case '2':
			display_type_rules(outfp);
			break;
		case '3':
			search_type_rules(outfp);
			break;
		case '4':
			display_roles(outfp);
			break;
		case '5':
			display_role_rules(outfp);
			break;
		case 'f':
			printf("Enter new outputfile name [stdout]:  ");
			fgets(ans, sizeof(ans), stdin);
			fix_string(ans, sizeof(ans));
			if(ans[0] == '\0' || strcasecmp(ans, "stdout") == 0) {
				if(opened_file)
					fclose(outfp);
				outfp = stdout;
				opened_file = 0;
				printf("Output file changed to standard output\n");
				break;
			}
			if((fp2 = fopen(ans, "w+")) == NULL) {
				fprintf(stderr, "%s: cannot open output file %s\n", argv[0], ans);
				printf("Output file unchanged.\n");
				break;
			}		
			if(opened_file) 
				fclose(outfp);
			outfp = fp2;
			printf("Output file changed to %s\n", ans);						
			break;
		case 'p': 
		{
			int len;
			printf("Enter policy file [%s]:  ", pol_file);
			fgets(ans, sizeof(ans), stdin);
			fix_string(ans, sizeof(ans));
			len = strlen(ans);
			
			if ((yyin = fopen((len == 0) ? pol_file: ans, "r")) == NULL) {
				fprintf (stderr, "cannot open policy file %s\n", (len == 0) ? pol_file: ans);
				break;
			}	
			free_policy(&policy);
			rt = open_policy();
			if(rt != 0)
				exit(1);
			printf("New policy file read, old policy is now closed\n");
			if(len != 0)
				strcpy(pol_file, ans);
			
			print_policy_summary(policy, stdout);
					
			break;
		}
		case 'm':
			menu();
			break;
		case 'v':
			printf("\n%s\n", VERSION_STRING);
			break;
		case 'q':
			exit(0);
			break;
		default:
			printf("\nInvalid choice\n");
			menu();
			break;
		}
		fflush(outfp);
	}
	
usage:
	printf("\n%s\n", VERSION_STRING);
	printf("\nUsage: %s POLICY-FILE [OUTPUT-FILE]\n", argv[0]);
	printf("Analyze a SE Linux policy.\n\n");
	printf("   POLICY-FILE:     File containing a \"policy.conf\" file.\n");
	printf("   OUTPUT-FILE:     Optional file in which output will be saved.\n\n");
	exit(1);
}

