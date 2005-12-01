/* Copyright (C) 2003-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* seinfo: command line tool for looking at a SE Linux policy,
 * and getting various component elements and statics.
 */
 
/* libapol */
#include <policy.h>
#include <policy-io.h>
#include <render.h>
/* other */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#define _GNU_SOURCE
#include <getopt.h>

/* The following should be defined in the make environment */
#ifndef SEINFO_VERSION_NUM
#define SEINFO_VERSION_NUM "UNKNOWN" 
#endif

#define COPYRIGHT_INFO "Copyright (C) 2003-2005 Tresys Technology, LLC"

char *policy_file = NULL;

static struct option const longopts[] =
{
  {"classes", optional_argument, NULL, 'c'},
  {"types", optional_argument, NULL, 't'},
  {"attribs", optional_argument, NULL, 'a'},
  {"roles", optional_argument, NULL, 'r'},
  {"users", optional_argument, NULL, 'u'},
  {"booleans", optional_argument, NULL, 'b'},
  {"initialsids", optional_argument, NULL, 'i'},
  {"stats", no_argument, NULL, 's'},
  {"all", no_argument, NULL, 'A'},
  {"expand", no_argument, NULL, 'x'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};

void usage(const char *program_name, int brief)
{
	printf("%s (seinfo ver. %s)\n\n", COPYRIGHT_INFO, SEINFO_VERSION_NUM);
	printf("Usage: %s [OPTIONS] [POLICY_FILE]\n", program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Print requested information about an SELinux policy.\n\
  -c[NAME], --classes[=NAME] print a list of object classes\n\
  -t[NAME], --types[=NAME]   print a list of types identifiers\n\
  -a[NAME], --attribs[=NAME] print a list of type attributes\n\
  -r[NAME], --roles[=NAME]   print a list of roles\n\
  -u[NAME], --users[=NAME]   print a list of users\n\
  -b[NAME], --boolean[=NAME] print a lits of conditional boolens\n\
  -i[NAME], --initialsid[=NAME] print a list of initial SIDs\n\
  -A, --all                  print all of the above\n\
  -x, --expand               show additional info for -ctarbuiA\n\
  -s, --stats                print useful policy statics\n\
", stdout);
fputs("\n\
  -h, --help                 display this help and exit\n\
  -v, --version              output version information and exit\n\
", stdout);
fputs("\n\
For -ctarui, if NAME is provided, then only show info for NAME.\n\
 Specifying a name is most useful when used with the -x option.\n\
 If no option is provided, display useful policy statics (-s).\n\n\
The default source policy, or if that is unavailable the default binary\n\
 policy, will be opened if no policy file name is provided.\n", stdout);
	return;
}


int print_stats(FILE *fp, policy_t *policy)
{
	assert(policy != NULL);
	fprintf(fp, "\nStatistics for policy file: %s\n", policy_file);
	fprintf(fp, "Policy Version: %s\n", get_policy_version_name(policy->version));
	if(is_binary_policy(policy))
		fprintf(fp, "Policy Type: binary%s", is_mls_policy(policy)?" mls\n":"\n");
	else
		fprintf(fp, "Policy Type: source%s", is_mls_policy(policy)?" mls\n":"\n");
	fprintf(fp, "\n");

	fprintf(fp, "   Classes:      %7d    Permissions:  %7d\n", num_obj_classes(policy), num_perms(policy));
	/* subtract 1 from types to remove the pseudo type "self" if non-binary policy */
	fprintf(fp, "   Types:        %7d    Attributes:   %7d\n", (is_binary_policy(policy) ? num_types(policy)-1 : num_types(policy)),
									num_attribs(policy));
	fprintf(fp, "   Users:        %7d    Roles:        %7d\n", num_users(policy), num_roles(policy));
	fprintf(fp, "   Booleans:     %7d    Cond. Expr.:  %7d\n", num_cond_bools(policy), num_cond_exprs(policy));
	fprintf(fp, "   Allow:        %7d    Neverallow:   %7d\n", policy->rule_cnt[RULE_TE_ALLOW], policy->rule_cnt[RULE_NEVERALLOW]);
	fprintf(fp, "   Auditallow:   %7d    Dontaudit:    %7d\n", policy->rule_cnt[RULE_AUDITALLOW], policy->rule_cnt[RULE_AUDITDENY] + policy->rule_cnt[RULE_DONTAUDIT]);
	fprintf(fp, "   Type_trans:   %7d    Type_change:  %7d\n", policy->rule_cnt[RULE_TE_TRANS], policy->rule_cnt[RULE_TE_CHANGE]);
	fprintf(fp, "   Role allow:   %7d    Role trans:   %7d\n", policy->rule_cnt[RULE_ROLE_ALLOW], policy->rule_cnt[RULE_ROLE_TRANS]);
	fprintf(fp, "   Initial SIDs: %7d\n", num_initial_sids(policy));
	fprintf(fp, "\n");
		
	return 0;
}

int print_classes(FILE *fp, const char *name, int expand, policy_t *policy)
{
	int i, j, idx, *perms = NULL, num_perms = 0, rt;
	char *cls_name = NULL, *perm_name = NULL;
	
	if(name != NULL) {
		idx = get_obj_class_idx(name, policy);
		if(idx < 0) {
			fprintf(fp, "Provided class (%s) is not a valid class name.\n", name);
			return -1;
		}
	}
	else 
		idx = 0;
	
	if(name == NULL)
		fprintf(fp, "Object classes: %d\n", num_obj_classes(policy));
	
	for(i = idx; is_valid_obj_class_idx(i, policy); i++)  {
		rt = get_obj_class_name(i, &cls_name, policy);
		if(rt != 0) {
			fprintf(fp, "Unexpected error getting class name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", cls_name);
		free(cls_name);
		if(expand) {
			rt = get_obj_class_perms(i, &num_perms, &perms, policy);
			if(rt != 0) {
				fprintf(fp, "Unexpected error expanding permissions\n\n");
				return -1;
			}
			for(j = 0; j < num_perms; j++) {
				rt = get_perm_name(perms[j], &perm_name, policy);
				if(rt != 0) {
					free(perms);
					fprintf(fp, "Unexpected error getting permission name\n\n");
					return -1;
				}
				fprintf(fp, "      %s\n", perm_name);
				free(perm_name);
			}
			free(perms);
		}
		/* if a name was provided, return as we only print the one asked for */
		if(name != NULL)
			break;
	}
	return 0;
}

int print_types(FILE *fp, const char *name, int expand, policy_t *policy)
{
	int i, j, idx, rt, num_attribs = 0, *attribs = NULL;
	char *type_name = NULL, *attrib_name = NULL;
	
	if(name != NULL) {
		idx = get_type_idx(name, policy);
		if(idx < 0) {
			fprintf(fp, "Provided type (%s) is not a valid type name.\n", name);
			return -1;
		}
	}
	else 
		/* If we're looking for all and not binary, we start at 1 since idx==0 is the pseudo type "self" */
		if(is_binary_policy(policy))
			idx = 0;
		else
			idx = 1;
	
	if(name == NULL)
		/* use num_types(policy)-1 to factor out the pseudo type "self" if not binary*/
		fprintf(fp, "\nTypes: %d\n", is_binary_policy(policy) ? num_types(policy) - 1 : num_types(policy));
	
	for(i = idx; is_valid_type_idx(i, policy); i++)  {
		rt = get_type_name(i, &type_name, policy);
		if(rt != 0) {
			fprintf(fp, "Unexpected error getting type name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", type_name);
		free(type_name);
		if(expand) {
			rt = get_type_attribs(i, &num_attribs, &attribs, policy);
			if(rt != 0) {
				fprintf(fp, "Unexpected error expanding attributes\n\n");
				return -1;
			}
			for(j = 0; j < num_attribs; j++) {
				rt = get_attrib_name(attribs[j], &attrib_name, policy);
				if(rt != 0) {
					free(attribs);
					fprintf(fp, "Unexpected error getting attribute name\n\n");
					return -1;
				}
				fprintf(fp, "      %s\n", attrib_name);
				free(attrib_name);
			}
			free(attribs);
		}
		/* if a name was provided, return as we only print the one asked for */
		if(name != NULL)
			break;
	}
	return 0;
}

int print_attribs(FILE *fp, const char *name, int expand, policy_t *policy)
{
	int i, j, idx, rt, num_types = 0, *types = NULL;
	char *type_name = NULL, *attrib_name = NULL;
	
	if(name != NULL) {
		idx = get_attrib_idx(name, policy);
		if(idx < 0) {
			fprintf(fp, "Provided attribute (%s) is not a valid attribute name.\n", name);
			return -1;
		}
	}
	else 
		idx = 0;
	
	if(name == NULL)
		fprintf(fp, "\nAttributes: %d\n", num_attribs(policy));
	
	for(i = idx; is_valid_attrib_idx(i, policy); i++)  {
		rt = get_attrib_name(i, &attrib_name, policy);
		if(rt != 0) {
			fprintf(fp, "Unexpected error getting attribute name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", attrib_name);
		free(attrib_name);
		if(expand) {
			rt = get_attrib_types(i, &num_types, &types, policy);
			if(rt != 0) {
				fprintf(fp, "Unexpected error expanding types\n\n");
				return -1;
			}
			for(j = 0; j < num_types; j++) {
				rt = get_type_name(types[j], &type_name, policy);
				if(rt != 0) {
					free(types);
					fprintf(fp, "Unexpected error getting type name\n\n");
					return -1;
				}
				fprintf(fp, "      %s\n", type_name);
				free(type_name);
			}
			free(types);
		}
		/* if a name was provided, return as we only print the one asked for */
		if(name != NULL)
			break;
	}
	return 0;
}


int print_roles(FILE *fp, const char *name, int expand, policy_t *policy)
{
	int i, j, idx, rt, num_types = 0, *types = NULL;
	char *type_name = NULL, *role_name = NULL;
	
	if(name != NULL) {
		idx = get_role_idx(name, policy);
		if(idx < 0) {
			fprintf(fp, "Provided role (%s) is not a valid role name.\n", name);
			return -1;
		}
	}
	else 
		idx = 0;
	
	if(name == NULL)
		fprintf(fp, "\nRoles: %d\n", num_roles(policy));
	
	for(i = idx; is_valid_role_idx(i, policy); i++)  {
		rt = get_role_name(i, &role_name, policy);
		if(rt != 0) {
			fprintf(fp, "Unexpected error getting role name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", role_name);
		free(role_name);
		if(expand) {
			rt = get_role_types(i, &num_types, &types, policy);
			if(rt != 0) {
				fprintf(fp, "Unexpected error expanding types\n\n");
				return -1;
			}
			for(j = 0; j < num_types; j++) {
				rt = get_type_name(types[j], &type_name, policy);
				if(rt != 0) {
					free(types);
					fprintf(fp, "Unexpected error getting type name\n\n");
					return -1;
				}
				fprintf(fp, "      %s\n", type_name);
				free(type_name);
			}
			free(types);
		}
		/* if a name was provided, return as we only print the one asked for */
		if(name != NULL)
			break;
	}
	return 0;
}

int print_booleans(FILE *fp, const char *name, int expand, policy_t *policy)
{
	int i, idx, rt;
	char *bool_name;
	
	if(name != NULL) {
		idx = get_cond_bool_idx(name, policy);
		if(idx < 0) {
			fprintf(fp, "Provided boolean (%s) is not a valid boolean name.\n", name);
			return -1;
		}
	}
	else 
		idx = 0;
		
	if(name == NULL)
		fprintf(fp, "\nConditional Booleans: %d\n", num_cond_bools(policy));
		
	for(i = idx; is_valid_cond_bool_idx(i, policy); i++) {
		rt = get_cond_bool_name(i, &bool_name, policy);
		if(rt != 0) {
			fprintf(fp, "Unexpected error getting boolean name\n\n");
			return -1;
		}
		fprintf(fp, "   %s", bool_name);
		free(bool_name);
		if(expand) 
			fprintf(fp, ": %s", get_cond_bool_default_state(i, policy) ? "TRUE" : "FALSE");
		fprintf(fp, "\n");
		if(name != NULL)
			break;
	}
	return 0;
}

int print_users(FILE *fp, const char *name, int expand, policy_t *policy)
{
	int i, j, idx, rt, num_roles = 0, *roles = NULL;
	char *user_name = NULL, *role_name = NULL;
	
	if(name != NULL) {
		idx = get_user_idx(name, policy);
		if(idx < 0) {
			fprintf(fp, "Provided user (%s) is not a valid user name.\n", name);
			return -1;
		}
	}
	else 
		idx = 0;
	
	if(name == NULL)
		fprintf(fp, "\nUsers: %d\n", num_users(policy));
	
	for(i = idx; is_valid_user_idx(i, policy); i++)  {
		rt = get_user_name2(i, &user_name, policy);
		if(rt != 0) {
			fprintf(fp, "Unexpected error getting user name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", user_name);
		free(user_name);
		if(expand) {
			rt = get_user_roles(i, &num_roles, &roles, policy);
			if(rt != 0) {
				fprintf(fp, "Unexpected error expanding roles\n\n");
				return -1;
			}
			for(j = 0; j < num_roles; j++) {
				rt = get_role_name(roles[j], &role_name, policy);
				if(rt != 0) {
					free(roles);
					fprintf(fp, "Unexpected error getting type name\n\n");
					return -1;
				}
				fprintf(fp, "      %s\n", role_name);
				free(role_name);
			}
			free(roles);
		}
		/* if a name was provided, return as we only print the one asked for */
		if(name != NULL)
			break;
	}
	return 0;
}

int print_isids(FILE *fp, const char *name, int expand, policy_t *policy)
{
	char *isid_name = NULL, *scontext = NULL;
	int idx, i, rt;
	
	if(name != NULL) {
		idx = get_initial_sid_idx(name, policy);
		if(idx < 0) {
			fprintf(fp, "Provided initial SID name (%s) is not a valid name.\n", name);
			return -1;
		}
	}
	else 
		idx = 0;
		
	if(name == NULL)
		fprintf(fp, "\nInitial SID: %d\n", num_initial_sids(policy));
		
	for(i = idx; is_valid_initial_sid_idx(i, policy); i++) {
		rt = get_initial_sid_name(i, &isid_name, policy);
		if(rt != 0) {
			fprintf(fp, "Unexpected error getting initial SID name\n\n");
			return -1;
		}
		if(expand) {
			fprintf(fp, "%20s:  ", isid_name);
			scontext = re_render_initial_sid_security_context(i, policy);
			if(scontext == NULL) {
				fprintf(fp, "Problem getting security context for %dth initial SID\n\n", i);
				return -1;
			}
			fprintf(fp, "%s", scontext);
			free(scontext);
		}
		else {
			fprintf(fp, "  %s", isid_name);
		}
		free(isid_name);
		fprintf(fp, "\n");
		/* if a name was provided, return as we only print the one asked for */
		if(name != NULL)
			break;
	}
	return 0;
}


int main (int argc, char **argv)
{
	int classes, types, attribs, roles, users, all, expand, stats, rt, optc, isids, bools;
	unsigned int open_opts = 0;
	policy_t *policy;
	char *class_name, *type_name, *attrib_name, *role_name, *user_name, *isid_name, *bool_name;
	unsigned int search_opts = 0;
	
	class_name = type_name = attrib_name = role_name = user_name = isid_name = bool_name = NULL;
	classes = types = attribs = roles = users = all = expand = stats = isids = bools = 0;
	while ((optc = getopt_long (argc, argv, "c::t::a::r::u::b::i::d:sAxhv0:", longopts, NULL)) != -1)  {
		switch (optc) {
		case 0:
	  		break;
	  	case 'c': /* classes */
	  		classes = 1;
	  		open_opts |= POLOPT_CLASSES;
	  		if(optarg != 0) 
	  			class_name = optarg;
	  		break;
	  	case 't': /* types */
	  		types = 1;
	  		open_opts |= POLOPT_TYPES;
	  		if(optarg != 0) 
	  			type_name = optarg;
	  		break;
	  	case 'a': /* attributes */
	  		attribs = 1;
	  		open_opts |= POLOPT_TYPES;
	  		if(optarg != 0) 
	  			attrib_name = optarg;
	  		break;
	  	case 'r': /* roles */
	  		roles = 1;
	  		open_opts |= POLOPT_ROLES;
	  		if(optarg != 0) 
	  			role_name = optarg;
	  		break;
	  	case 'u': /* users */
	  		users = 1;
	  		open_opts |= POLOPT_USERS;
	  		if(optarg != 0) 
	  			user_name = optarg;
	  		break;
	  	case 'b': /* conditional booleans */
	  		bools = 1;
	  		open_opts |= POLOPT_COND_BOOLS;
	  		if(optarg != 0) 
	  			bool_name = optarg;
	  		break;
	  	case 'i': /* initial SIDs */
	  		isids = 1;
	  		open_opts |= POLOPT_INITIAL_SIDS;
	  		if(optarg != 0)
	  			isid_name = optarg;
	  		break;
	  	case 'A': /* all */
	  		all = 1;
	  		open_opts = POLOPT_ALL;
	  		break;
	  	case 'x': /* expand */
	  		expand = 1;
	  		open_opts = POLOPT_ALL;
	  		break;
	  	case 's': /* stats */
	  		stats = 1;
	  		open_opts |= POLOPT_ALL;
	  		break;
	  	case 'h': /* help */
	  		usage(argv[0], 0);
	  		exit(0);
	  	case 'v': /* version */
	  		printf("\n%s (seinfo ver. %s)\n\n", COPYRIGHT_INFO, SEINFO_VERSION_NUM);
	  		exit(0);
	  	default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}
	/* if no options, then show stats */
	if(classes + types + attribs + roles + users + isids + bools + all < 1) {
		open_opts |= POLOPT_ALL;
		stats = 1;
	}
	if (!search_opts)
		search_opts = (POL_TYPE_SOURCE | POL_TYPE_BINARY);
				
	if (argc - optind > 1) {
		usage(argv[0], 1);
		exit(1);
	} else if (argc - optind < 1) {
		rt = find_default_policy_file(search_opts, &policy_file);
		if (rt != FIND_DEFAULT_SUCCESS) {
			printf("Default policy search failed: %s\n", find_default_policy_file_strerr(rt));
			exit(1);
		}
	} else
		policy_file = argv[optind];

	/* attempt to open the policy */
	rt = open_partial_policy(policy_file, open_opts, &policy);
	if(rt != 0)
		exit(1);
	
	/* display requested info */
	if(stats || all) 
		print_stats(stdout, policy);
	if(classes || all)
		print_classes(stdout, class_name, expand, policy);
	if(types || all)
		print_types(stdout, type_name, expand, policy);
	if(attribs|| all)
		print_attribs(stdout, attrib_name, expand, policy);
	if(roles|| all)
		print_roles(stdout, role_name, expand, policy);
	if(users || all)
		print_users(stdout, user_name, expand, policy);
	if(bools || all)
		print_booleans(stdout, bool_name, expand, policy);
	if(isids || all)
		print_isids(stdout, isid_name, expand, policy);
			
	close_policy(policy);
	exit(0);
}


