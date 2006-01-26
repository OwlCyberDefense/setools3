/* Copyright (C) 2003-2006 Tresys Technology, LLC
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

#define COPYRIGHT_INFO "Copyright (C) 2003-2006 Tresys Technology, LLC"

char *policy_file = NULL;

static struct option const longopts[] =
{
  {"classes", optional_argument, NULL, 'c'},
  {"types", optional_argument, NULL, 't'},
  {"attribs", optional_argument, NULL, 'a'},
  {"roles", optional_argument, NULL, 'r'},
  {"users", optional_argument, NULL, 'u'},
  {"booleans", optional_argument, NULL, 'b'},
  {"sensitivities", optional_argument, NULL, 'S'},
  {"categories", optional_argument, NULL, 'C'},
  {"fs_use", optional_argument, NULL, 'f'},
  {"genfscon", optional_argument, NULL, 'g'},
  {"netifcon", optional_argument, NULL, 'n'},
  {"nodecon", optional_argument, NULL, 'o'},
  {"portcon", optional_argument, NULL, 'p'},
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
  -c[NAME], --classes[=NAME]       print a list of object classes\n\
  -t[NAME], --types[=NAME]         print a list of types identifiers\n\
  -a[NAME], --attribs[=NAME]       print a list of type attributes\n\
  -r[NAME], --roles[=NAME]         print a list of roles\n\
  -u[NAME], --users[=NAME]         print a list of users\n\
  -b[NAME], --boolean[=NAME]       print a lits of conditional boolens\n\
  -S[NAME], --sensitivities[=NAME] print a list of sensitivities\n\
  -C[NAME], --categories[=NAME]    print a list of categories\n\
  -f[TYPE], --fs_use[=TYPE]        print a list of fs_use statements\n\
  -g[TYPE], --genfscon[=TYPE]      print a list of genfscon statements\n\
  -n[NAME], --netifcon[=NAME]      print a list of netif contexts\n\
  -o[ADDR], --nodecon[=ADDR]       print a list of node contexts\n\
  -p[NUM],  --portcon[=NUM]        print a list of port contexts\n\
  -i[NAME], --initialsid[=NAME]    print a list of initial SIDs\n\
  -A, --all                        print all of the above\n\
  -x, --expand                     show additional info for -ctarbuSCiA options\n\
  -s, --stats                      print useful policy statistics\n\
", stdout);
fputs("\n\
  -h, --help                       display this help and exit\n\
  -v, --version                    output version information and exit\n\
", stdout);
fputs("\n\
For -ctaruSCfgnopi options, if NAME is provided, then only show info for NAME.\n\
 Specifying a name is most useful when used with the -x option.\n\
 If no option is provided, display useful policy statistics (-s).\n\n\
The default source policy, or if that is unavailable the default binary\n\
 policy, will be opened if no policy file name is provided.\n", stdout);
	return;
}


int print_stats(FILE *fp, policy_t *policy)
{
	char *tmp = NULL;
	int num_genfscon = 0;

	assert(policy != NULL);

	/* there is one path per statement in the policy */
	num_genfscon = ap_genfscon_get_num_paths(policy);

	fprintf(fp, "\nStatistics for policy file: %s\n", policy_file);
	fprintf(fp, "Policy Version & Type: %s\n", (tmp = get_policy_version_type_mls_str(policy))); free(tmp);
	fprintf(fp, "\n");

	fprintf(fp, "   Classes:       %7d    Permissions:   %7d\n", num_obj_classes(policy), num_perms(policy));
	/* subtract 1 from types to remove the pseudo type "self" if non-binary policy */
	fprintf(fp, "   Types:         %7d    Attributes:    %7d\n", (is_binary_policy(policy) ? num_types(policy)-1 : num_types(policy)),
									num_attribs(policy));
	fprintf(fp, "   Users:         %7d    Roles:         %7d\n", num_users(policy), num_roles(policy));
	fprintf(fp, "   Booleans:      %7d    Cond. Expr.:   %7d\n", num_cond_bools(policy), num_cond_exprs(policy));
	fprintf(fp, "   Sensitivities: %7d    Categories:    %7d\n", policy->num_sensitivities, policy->num_categories);
	fprintf(fp, "   Allow:         %7d    Neverallow:    %7d\n", policy->rule_cnt[RULE_TE_ALLOW], policy->rule_cnt[RULE_NEVERALLOW]);
	fprintf(fp, "   Auditallow:    %7d    Dontaudit:     %7d\n", policy->rule_cnt[RULE_AUDITALLOW], policy->rule_cnt[RULE_AUDITDENY] + policy->rule_cnt[RULE_DONTAUDIT]);
	fprintf(fp, "   Role allow:    %7d    Role trans:    %7d\n", policy->rule_cnt[RULE_ROLE_ALLOW], policy->rule_cnt[RULE_ROLE_TRANS]);
	fprintf(fp, "   Type_trans:    %7d    Type_change:   %7d\n", policy->rule_cnt[RULE_TE_TRANS], policy->rule_cnt[RULE_TE_CHANGE]);
	fprintf(fp, "   Type_member:   %7d    Range_trans:   %7d\n", policy->rule_cnt[RULE_TE_MEMBER], policy->num_rangetrans);
	fprintf(fp, "   Constraints:   %7d    Validatetrans: %7d\n", policy->num_constraints, policy->num_validatetrans);
	fprintf(fp, "   Fs_use:        %7d    Genfscon:      %7d\n", policy->num_fs_use, num_genfscon);
	fprintf(fp, "   Portcon:       %7d    Netifcon:      %7d\n", policy->num_portcon, policy->num_netifcon);
	fprintf(fp, "   Nodecon:       %7d    Initial SIDs:  %7d\n", policy->num_nodecon, num_initial_sids(policy));
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
			fprintf(stderr, "Provided class (%s) is not a valid class name.\n", name);
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
			fprintf(stderr, "Unexpected error getting class name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", cls_name);
		free(cls_name);
		if(expand) {
			rt = get_obj_class_perms(i, &num_perms, &perms, policy);
			if(rt != 0) {
				fprintf(stderr, "Unexpected error expanding permissions\n\n");
				return -1;
			}
			for(j = 0; j < num_perms; j++) {
				rt = get_perm_name(perms[j], &perm_name, policy);
				if(rt != 0) {
					free(perms);
					fprintf(stderr, "Unexpected error getting permission name\n\n");
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
			fprintf(stderr, "Provided type (%s) is not a valid type name.\n", name);
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
			fprintf(stderr, "Unexpected error getting type name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", type_name);
		free(type_name);
		if(expand) {
			rt = get_type_attribs(i, &num_attribs, &attribs, policy);
			if(rt != 0) {
				fprintf(stderr, "Unexpected error expanding attributes\n\n");
				return -1;
			}
			for(j = 0; j < num_attribs; j++) {
				rt = get_attrib_name(attribs[j], &attrib_name, policy);
				if(rt != 0) {
					free(attribs);
					fprintf(stderr, "Unexpected error getting attribute name\n\n");
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
			fprintf(stderr, "Provided attribute (%s) is not a valid attribute name.\n", name);
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
			fprintf(stderr, "Unexpected error getting attribute name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", attrib_name);
		free(attrib_name);
		if(expand) {
			rt = get_attrib_types(i, &num_types, &types, policy);
			if(rt != 0) {
				fprintf(stderr, "Unexpected error expanding types\n\n");
				return -1;
			}
			for(j = 0; j < num_types; j++) {
				rt = get_type_name(types[j], &type_name, policy);
				if(rt != 0) {
					free(types);
					fprintf(stderr, "Unexpected error getting type name\n\n");
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
			fprintf(stderr, "Provided role (%s) is not a valid role name.\n", name);
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
			fprintf(stderr, "Unexpected error getting role name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", role_name);
		free(role_name);
		if(expand) {
			if (policy->roles[i].num_dom_roles > 1) {
				fprintf(fp, "      Dominated Roles:\n");
				for(j = 1; j < policy->roles[i].num_dom_roles; j++) {
					fprintf(fp, "         %s\n", policy->roles[policy->roles[i].dom_roles[j]].name);
				}
			}
			rt = get_role_types(i, &num_types, &types, policy);
			if(rt != 0) {
				fprintf(stderr, "Unexpected error expanding types\n\n");
				return -1;
			}
			fprintf(fp, "      Types:\n");
			for(j = 0; j < num_types; j++) {
				rt = get_type_name(types[j], &type_name, policy);
				if(rt != 0) {
					free(types);
					fprintf(stderr, "Unexpected error getting type name\n\n");
					return -1;
				}
				fprintf(fp, "         %s\n", type_name);
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
			fprintf(stderr, "Provided boolean (%s) is not a valid boolean name.\n", name);
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
			fprintf(stderr, "Unexpected error getting boolean name\n\n");
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
	char *tmp = NULL;
	
	if(name != NULL) {
		idx = get_user_idx(name, policy);
		if(idx < 0) {
			fprintf(stderr, "Provided user (%s) is not a valid user name.\n", name);
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
			fprintf(stderr, "Unexpected error getting user name\n\n");
			return -1;
		}
		fprintf(fp, "   %s\n", user_name);
		free(user_name);
		if(expand) {
			if (is_mls_policy(policy)) {
				tmp = re_render_mls_level(policy->users[i].dflt_level, policy);
				if (!tmp) {
					fprintf(stderr, "Unexpected error getting user default level\n\n");
					return -1;
				}
				fprintf(fp, "      default level: %s\n", tmp);
				free(tmp);
				tmp = re_render_mls_range(policy->users[i].range, policy);
				if (!tmp) {
					fprintf(stderr, "Unexpected error getting user range\n\n");
					return -1;
				}
				fprintf(fp, "      range: %s\n", tmp);
				free(tmp);
			}
			rt = get_user_roles(i, &num_roles, &roles, policy);
			if(rt != 0) {
				fprintf(stderr, "Unexpected error expanding roles\n\n");
				return -1;
			}
			fprintf(fp, "      roles:\n");
			for(j = 0; j < num_roles; j++) {
				rt = get_role_name(roles[j], &role_name, policy);
				if(rt != 0) {
					free(roles);
					fprintf(stderr, "Unexpected error getting role name\n\n");
					return -1;
				}
				fprintf(fp, "         %s\n", role_name);
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

int print_sens(FILE *fp, const char *name, int expand, policy_t *policy)
{
	int idx, i;
	char *tmp = NULL;

	if (name) {
		idx = get_sensitivity_idx(name, policy);
		if (idx == -1) {
			fprintf(stderr, "\nProvided sensitivity (%s) is not a valid sensitivity name\n", name);
			return -1;
		}
	} else {
		idx = 0;
		fprintf(fp, "\nSensitivities: %d\n", policy->num_sensitivities);
	}

	for (i = idx; i < policy->num_sensitivities; i++) {
		fprintf(fp, "   %s\n", policy->sensitivities[i].name);
		if (expand) {
			fprintf(fp, "      level %s\n", (tmp = re_render_mls_level(ap_mls_sensitivity_get_level(i, policy), policy)));
			free(tmp);
			tmp = NULL;
		}
		if (name)
			break;
	}

	return 0;
}

int print_cats(FILE *fp, const char *name, int expand, policy_t *policy)
{
	int idx, i, j, retv, num_sens = 0, *sens = NULL;

	if (name) {
		idx = get_category_idx(name, policy);
		if (idx == -1) {
			fprintf(stderr, "\nProvided category (%s) is not a valid category name\n", name);
			return -1;
		}
	} else {
		idx = 0;
		fprintf(fp, "Categories: %d\n", policy->num_categories);
	}

	for (i = idx; i < policy->num_categories; i++) {
		fprintf(fp, "   %s\n", policy->categories[i].name);
		if (expand) {
			retv = ap_mls_category_get_sens(i, &sens, &num_sens, policy);
			if (retv) {
				fprintf(stderr, "Unable to get sensitivities for category %s", policy->categories[i].name);
				return -1;
			}
			fprintf(fp, "      Sensitivities:\n");
			for (j = 0; j < num_sens; j++) {
				fprintf(fp, "         %s\n", policy->sensitivities[sens[j]].name);
			}
			free(sens);
			sens = NULL;
			num_sens = 0;
		}
		if (name)
			break;
	}

	return 0;
}

int print_fsuse(FILE *fp, const char *type, policy_t * policy)
{
	int i, printed = 0;
	char *tmp = NULL;

	if (!type)
		fprintf(fp, "\nFs_use: %d\n", policy->num_fs_use);

	for (i = 0; i < policy->num_fs_use; i++) {
		if ((type && !strcmp(type, policy->fs_use[i].fstype)) || !type) {
			fprintf(fp, "   %s\n", (tmp = re_render_fs_use(&(policy->fs_use[i]), policy)));
			free(tmp);
			printed = 1;
		}
	}

	if (!printed && type)
		fprintf(stderr, "No fs_use statement for filesystem of type %s\n", type);

	return 0;
}

int print_genfscon(FILE *fp, const char *type, policy_t * policy)
{
	int i, printed = 0;
	char *tmp = NULL;
	char *ptr = NULL;

	if (!type)
		fprintf(fp, "\nGenfscon: %d\n", policy->num_genfscon);

	for (i = 0; i < policy->num_genfscon; i++) {
		if ((type && !strcmp(type, policy->genfscon[i].fstype)) || !type) {
			tmp = re_render_genfscon(&(policy->genfscon[i]), policy);
			/* indent to match other compontents even if multi line */
			fprintf(fp, "   ");
			for (ptr = tmp; *ptr; ptr++) {
				if (*ptr == '\n' && ptr[1] != '\0') {
					fprintf(fp, "%c   ", *ptr);
				} else {
					fprintf(fp, "%c", *ptr);
				}
			}
			free(tmp);
			printed = 1;
		}
	}

	if (!printed && type)
		fprintf(stderr, "No genfscon statement for filesystem of type %s\n", type);

	return 0;
}

int print_netifcon(FILE *fp, const char *name, policy_t * policy)
{
	int i, printed = 0;
	char *tmp = NULL;

	if (!name)
		fprintf(fp, "\nNetifcon: %d\n", policy->num_netifcon);

	for (i = 0; i < policy->num_netifcon; i++) {
		if ((name && !strcmp(name, policy->netifcon[i].iface)) || !name) {
			fprintf(fp, "   %s\n", (tmp = re_render_netifcon(&(policy->netifcon[i]), policy)));
			free(tmp);
			printed = 1;
		}
	}

	if (!printed && name)
		fprintf(stderr, "No netifcon statement for interface named %s\n", name);

	return 0;
}

int print_nodecon(FILE *fp, const char *addr, policy_t *policy)
{
	int i, proto = 0;
	char *tmp = NULL;
	uint32_t address[4] = {0,0,0,0};
	int printed = 0;

	if (!addr) {
		fprintf(fp, "Nodecon: %d\n", policy->num_nodecon);
	} else {
		proto = str_to_internal_ip(addr, address);
		if (proto < 0) {
			fprintf(stderr, "Provided address (%s) is not valid\n", addr);
		}
	}

	for (i = 0; i < policy->num_nodecon; i++) {
		if (!addr || (addr && proto == policy->nodecon[i].flag &&
			(address[0] & policy->nodecon[i].mask[0]) == policy->nodecon[i].addr[0] && 
			(address[1] & policy->nodecon[i].mask[1]) == policy->nodecon[i].addr[1] &&
			(address[2] & policy->nodecon[i].mask[2]) == policy->nodecon[i].addr[2] &&
			(address[3] & policy->nodecon[i].mask[3]) == policy->nodecon[i].addr[3] )) {

			fprintf(fp, "   %s\n", (tmp = re_render_nodecon(&(policy->nodecon[i]), policy)));
			free(tmp);
			printed = 1;
		}
	}

	if (addr && !printed) 
		fprintf(stderr, "No matching nodecon for address %s\n", addr);

	return 0;
}

int print_portcon(FILE *fp, const char *num, policy_t *policy)
{
	int i, printed = 0, port = -1;
	char *tmp = NULL, *test = NULL;

	if (!num) {
		fprintf(fp, "\nPortcon: %d\n", policy->num_portcon);
	} else {
		port = strtol(num, &test, 10);
		if (port < 0 || *test != '\0') {
			fprintf(stderr, "Provided port number (%s) is not a valid port\n", num);
			return -1;
		}
	}

	for (i = 0; i < policy->num_portcon; i++) {
		if ((num && policy->portcon[i].lowport <= port && policy->portcon[i].highport >= port) || !num) {
			fprintf(fp, "   %s\n", (tmp = re_render_portcon(&(policy->portcon[i]), policy)));
			free(tmp);
			printed = 1;
		}
	}

	if (!printed && num)
		fprintf(stderr, "No portcon statement for port number %s\n", num);

	return 0;
}

int print_isids(FILE *fp, const char *name, int expand, policy_t *policy)
{
	char *isid_name = NULL, *scontext = NULL;
	int idx, i, rt;
	
	if(name != NULL) {
		idx = get_initial_sid_idx(name, policy);
		if(idx < 0) {
			fprintf(stderr, "Provided initial SID name (%s) is not a valid name.\n", name);
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
			fprintf(stderr, "Unexpected error getting initial SID name\n\n");
			return -1;
		}
		if(expand) {
			fprintf(fp, "%20s:  ", isid_name);
			scontext = re_render_initial_sid_security_context(i, policy);
			if(scontext == NULL) {
				fprintf(stderr, "Problem getting security context for %dth initial SID\n\n", i);
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
	int classes, types, attribs, roles, users, all, expand, stats, rt, optc, isids, bools, sens, cats, fsuse, genfs, netif, node, port;
	unsigned int open_opts = 0;
	policy_t *policy;
	char *class_name, *type_name, *attrib_name, *role_name, *user_name, *isid_name, *bool_name, *sens_name, *cat_name, *fsuse_type, *genfs_type, *netif_name, *node_addr, *port_num;
	unsigned int search_opts = 0;
	
	class_name = type_name = attrib_name = role_name = user_name = isid_name = bool_name = sens_name = cat_name = fsuse_type = genfs_type = netif_name = node_addr = port_num = NULL;
	classes = types = attribs = roles = users = all = expand = stats = isids = bools = sens = cats = fsuse = genfs = netif = node = port = 0;
	while ((optc = getopt_long (argc, argv, "c::t::a::r::u::b::S::C::f::g::n::o::p::i::d:sAxhv", longopts, NULL)) != -1)  {
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
	  	case 'S': /* sensitivities */
	  		sens = 1;
	  		open_opts |= POLOPT_MLS_COMP;
	  		if(optarg != 0) 
	  			sens_name = optarg;
	  		break;
	  	case 'C': /* categories */
	  		cats = 1;
	  		open_opts |= POLOPT_MLS_COMP;
	  		if(optarg != 0) 
	  			cat_name = optarg;
	  		break;
	  	case 'f': /* fs_use */
	  		fsuse = 1;
	  		open_opts |= POLOPT_OCONTEXT;
	  		if(optarg != 0) 
	  			fsuse_type = optarg;
	  		break;
	  	case 'g': /* genfscon */
	  		genfs = 1;
	  		open_opts |= POLOPT_OCONTEXT;
	  		if(optarg != 0) 
	  			genfs_type = optarg;
	  		break;
	  	case 'n': /* netifcon */
	  		netif = 1;
	  		open_opts |= POLOPT_OCONTEXT;
	  		if(optarg != 0) 
	  			netif_name = optarg;
	  		break;
	  	case 'o': /* nodecons */
	  		node = 1;
	  		open_opts |= POLOPT_OCONTEXT;
	  		if(optarg != 0) 
	  			node_addr = optarg;
	  		break;
	  	case 'p': /* portcons */
	  		port = 1;
	  		open_opts |= POLOPT_OCONTEXT;
	  		if(optarg != 0) 
	  			port_num = optarg;
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
	if(classes + types + attribs + roles + users + isids + bools + sens + cats + fsuse + genfs + netif + node + port + all < 1) {
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
	if(sens || all)
		print_sens(stdout, sens_name, expand, policy);
	if(cats || all)
		print_cats(stdout, cat_name, expand, policy);
	if(fsuse || all)
		print_fsuse(stdout, fsuse_type, policy);
	if(genfs || all)
		print_genfscon(stdout, genfs_type, policy);
	if(netif || all)
		print_netifcon(stdout, netif_name, policy);
	if(node || all)
		print_nodecon(stdout, node_addr, policy);
	if(port || all)
		print_portcon(stdout, port_num, policy);
	if(isids || all)
		print_isids(stdout, isid_name, expand, policy);
			
	close_policy(policy);
	exit(0);
}


