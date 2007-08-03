/**
 *  @file
 *  Command line frontend for computing a semantic policy difference.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include <poldiff/poldiff.h>
#include <poldiff/component_record.h>
#include <apol/policy.h>
#include <apol/vector.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define COPYRIGHT_INFO "Copyright (C) 2004-2007 Tresys Technology, LLC"

enum opt_values
{
	DIFF_LEVEL = 256, DIFF_CATEGORY,
	DIFF_AUDITALLOW, DIFF_DONTAUDIT, DIFF_NEVERALLOW,
	DIFF_TYPE_CHANGE, DIFF_TYPE_MEMBER,
	DIFF_ROLE_TRANS, DIFF_ROLE_ALLOW, DIFF_RANGE_TRANS,
	OPT_STATS
};

/* command line options struct */
static struct option const longopts[] = {
	{"class", no_argument, NULL, 'c'},
	{"level", no_argument, NULL, DIFF_LEVEL},
	{"category", no_argument, NULL, DIFF_CATEGORY},
	{"type", no_argument, NULL, 't'},
	{"attribute", no_argument, NULL, 'a'},
	{"role", no_argument, NULL, 'r'},
	{"user", no_argument, NULL, 'u'},
	{"bool", no_argument, NULL, 'b'},
	{"allow", no_argument, NULL, 'A'},
	{"auditallow", no_argument, NULL, DIFF_AUDITALLOW},
	{"dontaudit", no_argument, NULL, DIFF_DONTAUDIT},
	{"neverallow", no_argument, NULL, DIFF_NEVERALLOW},
	{"type_change", no_argument, NULL, DIFF_TYPE_CHANGE},
	{"type_trans", no_argument, NULL, 'T'},
	{"type_member", no_argument, NULL, DIFF_TYPE_MEMBER},
	{"role_trans", no_argument, NULL, DIFF_ROLE_TRANS},
	{"role_allow", no_argument, NULL, DIFF_ROLE_ALLOW},
	{"range_trans", no_argument, NULL, DIFF_RANGE_TRANS},
	{"stats", no_argument, NULL, OPT_STATS},
	{"quiet", no_argument, NULL, 'q'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{NULL, 0, NULL, 0}
};

static void usage(const char *prog_name, int brief)
{
	printf("Usage: %s [OPTIONS] ORIGINAL_POLICY ; MODIFIED_POLICY\n\n", prog_name);
	if (brief) {
		printf("\tTry %s --help for more help.\n\n", prog_name);
		return;
	}
	printf("Semantically differentiate two policies.  By default, all supported\n");
	printf("policy elements sans neverallows are examined.  The following options\n");
	printf("are available:\n\n");
	printf("  -c, --class        object class and common permission definitions\n");
	printf("  --level            MLS level definitions\n");
	printf("  --category         MLS category definitions\n");
	printf("  -t, --type         type definitions\n");
	printf("  -a, --attribute    attribute definitions\n");
	printf("  -r, --role         role definitions\n");
	printf("  -u, --user         user definitions\n");
	printf("  -b, --bool         boolean definitions and default values\n");
	printf("  -A, --allow        allow rules\n");
	printf("  --auditallow       auditallow rules\n");
	printf("  --dontaudit        dontaudit rules\n");
	printf("  --neverallow       neverallow rules\n");
	printf("  --type_change      type_change rules\n");
	printf("  --type_member      type_member rules\n");
	printf("  -T, --type_trans   type_transition rules\n");
	printf("  --role_trans       role_transition rules\n");
	printf("  --role_allow       role allow rules\n");
	printf("  --range_trans      range_transition rules\n");
	printf("\n");
	printf("  -q, --quiet        suppress status output for elements with no differences\n");
	printf("  --stats            print only statistics\n");
	printf("  -h, --help         print this help text and exit\n");
	printf("  -V, --version      print version information and exit\n\n");
}

static void print_diff_string(const char *str, unsigned int indent_level)
{
	const char *c = str;
	unsigned int i;
	static const char *indent = "   ";

	for (i = 0; i < indent_level; i++)
		printf("%s", indent);
	for (; *c; c++) {
		if (*c == '\n') {
			if (*(c + 1) == '\0')
				break;
			printf("%c", *c);
			for (i = 0; i < indent_level; i++)
				printf("%s", indent);
		} else if (*c == '\t') {
			printf("%s", indent);
		} else {
			printf("%c", *c);
		}
	}
}

static void print_rule_section(const poldiff_t * diff, const poldiff_component_record_t * rec, const apol_vector_t * v,
			       poldiff_form_e form)
{
	int i;
	char *str = NULL;
	const void *item1;

	for (i = 0; i < apol_vector_get_size(v); i++) {
		item1 = apol_vector_get_element(v, i);
		if (poldiff_component_record_get_form_fn(rec) (item1) == form) {
			if ((str = poldiff_component_record_get_to_string_fn(rec) (diff, item1)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
}

#define PRINT_ADDED_REMOVED 1
#define PRINT_MODIFIED  2
#define PRINT_ALL 4

static void print_rule_diffs(const poldiff_t * diff, const poldiff_component_record_t * rec, int stats_only, const char *name,
			     uint32_t flags, apol_vector_comp_func sort_by)
{
	const apol_vector_t *internal_v = NULL;
	apol_vector_t *v = NULL;
	size_t stats[5] = { 0, 0, 0, 0, 0 };

	if (!rec || !diff)
		return;

	poldiff_component_record_get_stats_fn(rec) (diff, stats);
	if (flags == PRINT_ADDED_REMOVED) {
		printf("%s (Added %zd, Removed %zd)\n", name, stats[0], stats[1]);
	} else if (flags == PRINT_MODIFIED) {
		printf("%s (Added %zd, Removed %zd, Modified %zd)\n", name, stats[0], stats[1], stats[2]);
	} else if (flags == PRINT_ALL) {
		printf("%s (Added %zd, Added New Type %zd, Removed %zd, Removed Missing Type %zd, Modified %zd)\n", name, stats[0],
		       stats[3], stats[1], stats[4], stats[2]);
	} else {
		fprintf(stderr, "Error, unhandled flag type\n");
	}

	if (stats_only)
		return;
	if ((internal_v = poldiff_component_record_get_results_fn(rec) (diff)) == NULL) {
		return;
	}
	if (!(v = apol_vector_create_from_vector(internal_v, NULL, NULL, NULL))) {
		perror("Error printig results");
		return;
	}

	if (sort_by) {
		apol_vector_sort(v, sort_by, NULL);
	}

	printf("   Added %s: %zd\n", name, stats[0]);
	print_rule_section(diff, rec, v, POLDIFF_FORM_ADDED);

	if (flags == PRINT_ALL) {
		printf("   Added %s because of new type: %zd\n", name, stats[3]);
		print_rule_section(diff, rec, v, POLDIFF_FORM_ADD_TYPE);
	}

	printf("   Removed %s: %zd\n", name, stats[1]);
	print_rule_section(diff, rec, v, POLDIFF_FORM_REMOVED);

	if (flags == PRINT_ALL) {
		printf("   Removed %s because of missing type: %zd\n", name, stats[4]);
		print_rule_section(diff, rec, v, POLDIFF_FORM_REMOVE_TYPE);
	}
	if (flags == PRINT_MODIFIED || flags == PRINT_ALL) {
		printf("   Modified %s: %zd\n", name, stats[2]);
		print_rule_section(diff, rec, v, POLDIFF_FORM_MODIFIED);
	}
	printf("\n");
	apol_vector_destroy(&v);
	return;
}

static void print_class_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_CLASSES), stats_only, "Classes", PRINT_MODIFIED, NULL);
	return;
}

static void print_bool_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_BOOLS), stats_only, "Booleans", PRINT_MODIFIED, NULL);
	return;
}

static void print_common_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_COMMONS), stats_only, "Commons", PRINT_MODIFIED, NULL);
	return;
}

static void print_level_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_LEVELS), stats_only, "Levels", PRINT_MODIFIED, NULL);
	return;
}

static void print_cat_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_CATS), stats_only, "Categories", PRINT_MODIFIED, NULL);
	return;
}

static void print_role_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_ROLES), stats_only, "Roles", PRINT_MODIFIED, NULL);
	return;
}

static void print_user_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_USERS), stats_only, "Users", PRINT_MODIFIED, NULL);
	return;
}

static void print_avallow_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_AVALLOW), stats_only, "AV-Allow Rules", PRINT_ALL, NULL);
}

static void print_avauditallow_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_AVAUDITALLOW), stats_only, "AV-Audit Allow Rules",
			 PRINT_ALL, NULL);
}

static void print_avdontaudit_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_AVDONTAUDIT), stats_only, "AV-Don't Audit Rules",
			 PRINT_ALL, NULL);
}

static void print_avneverallow_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_AVNEVERALLOW), stats_only, "AV-Never Allow Rules",
			 PRINT_ALL, NULL);
}

static void print_role_allow_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_ROLE_ALLOWS), stats_only, "Role Allow Rules",
			 PRINT_MODIFIED, NULL);
}

static void print_role_trans_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_ROLE_TRANS), stats_only, "Role Transitions", PRINT_ALL,
			 NULL);
}

static void print_range_trans_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_RANGE_TRANS), stats_only, "Range Transitions",
			 PRINT_MODIFIED, NULL);
}

/** compare the names for two poldiff_type_t objects.
 * used to sort items prior to display. */
static int type_name_cmp(const void *a, const void *b, void *user_data __attribute__ ((unused)))
{
	poldiff_type_t *ta = (poldiff_type_t *) a;
	poldiff_type_t *tb = (poldiff_type_t *) b;
	if (ta == NULL || tb == NULL)
		return -1;
	return strcmp(poldiff_type_get_name(ta), poldiff_type_get_name(tb));
}

static void print_type_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_TYPES), stats_only, "Types", PRINT_MODIFIED,
			 type_name_cmp);
}

static void print_attrib_diffs(const poldiff_t * diff, int stats_only)
{
	print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_ATTRIBS), stats_only, "Attributes", PRINT_MODIFIED, NULL);
}

static size_t get_diff_total(const poldiff_t * diff, uint32_t flags)
{
	size_t total = 0;
	uint32_t i;
	size_t stats[5] = { 0, 0, 0, 0, 0 };

	if (!diff || !flags)
		return 0;

	/* for all 32 bits possible in flags */
	for (i = 0x80000000; i; i = i >> 1) {
		if (flags & i) {
			poldiff_get_stats(diff, i, stats);
			total += (stats[0] + stats[1] + stats[2] + stats[3] + stats[4]);
		}
	}

	return total;
}

static void print_diff(const poldiff_t * diff, uint32_t flags, int stats, int quiet)
{
	if (flags & POLDIFF_DIFF_CLASSES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_CLASSES))) {
		print_class_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_COMMONS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_COMMONS))) {
		print_common_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_LEVELS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_LEVELS))) {
		print_level_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_CATS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_CATS))) {
		print_cat_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_TYPES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_TYPES))) {
		print_type_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_ATTRIBS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ATTRIBS))) {
		print_attrib_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_ROLES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ROLES))) {
		print_role_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_USERS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_USERS))) {
		print_user_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_BOOLS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_BOOLS))) {
		print_bool_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_AVALLOW && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_AVALLOW))) {
		print_avallow_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_AVAUDITALLOW && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_AVAUDITALLOW))) {
		print_avauditallow_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_AVDONTAUDIT && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_AVDONTAUDIT))) {
		print_avdontaudit_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_AVNEVERALLOW && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_AVNEVERALLOW))) {
		print_avneverallow_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_TECHANGE && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_TECHANGE))) {
		print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_TECHANGE), stats, "TE type_change", PRINT_ALL,
				 NULL);
	}
	if (flags & POLDIFF_DIFF_TEMEMBER && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_TEMEMBER))) {
		print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_TEMEMBER), stats, "TE type_member", PRINT_ALL,
				 NULL);
	}
	if (flags & POLDIFF_DIFF_TETRANS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_TETRANS))) {
		print_rule_diffs(diff, poldiff_get_component_record(POLDIFF_DIFF_TETRANS), stats, "TE type_trans", PRINT_ALL, NULL);
	}
	if (flags & POLDIFF_DIFF_ROLE_ALLOWS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ROLE_ALLOWS))) {
		print_role_allow_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_ROLE_TRANS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ROLE_TRANS))) {
		print_role_trans_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_RANGE_TRANS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_RANGE_TRANS))) {
		print_range_trans_diffs(diff, stats);
	}
}

int main(int argc, char **argv)
{
	int optc = 0, quiet = 0, stats = 0, default_all = 0;
	uint32_t flags = 0;
	apol_policy_t *orig_policy = NULL, *mod_policy = NULL;
	apol_policy_path_type_e orig_path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	char *orig_base_path = NULL;
	apol_vector_t *orig_module_paths = NULL;
	apol_policy_path_t *orig_pol_path = NULL;
	apol_policy_path_type_e mod_path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	char *mod_base_path = NULL;
	apol_vector_t *mod_module_paths = NULL;
	apol_policy_path_t *mod_pol_path = NULL;
	poldiff_t *diff = NULL;
	size_t total = 0;

	while ((optc = getopt_long(argc, argv, "ctarubATNDLMCRqhV", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 'c':
			flags |= (POLDIFF_DIFF_CLASSES | POLDIFF_DIFF_COMMONS);
			break;
		case DIFF_LEVEL:
			flags |= POLDIFF_DIFF_LEVELS;
			break;
		case DIFF_CATEGORY:
			flags |= POLDIFF_DIFF_CATS;
			break;
		case 't':
			flags |= POLDIFF_DIFF_TYPES;
			break;
		case 'a':
			flags |= POLDIFF_DIFF_ATTRIBS;
			break;
		case 'r':
			flags |= POLDIFF_DIFF_ROLES;
			break;
		case 'u':
			flags |= POLDIFF_DIFF_USERS;
			break;
		case 'b':
			flags |= POLDIFF_DIFF_BOOLS;
			break;
		case 'A':
			flags |= POLDIFF_DIFF_AVALLOW;
			break;
		case DIFF_AUDITALLOW:
			flags |= POLDIFF_DIFF_AVAUDITALLOW;
			break;
		case DIFF_DONTAUDIT:
			flags |= POLDIFF_DIFF_AVDONTAUDIT;
			break;
		case DIFF_NEVERALLOW:
			flags |= POLDIFF_DIFF_AVNEVERALLOW;
			break;
		case DIFF_TYPE_CHANGE:
			flags |= POLDIFF_DIFF_TECHANGE;
			break;
		case DIFF_TYPE_MEMBER:
			flags |= POLDIFF_DIFF_TEMEMBER;
			break;
		case 'T':
			flags |= POLDIFF_DIFF_TETRANS;
			break;
		case DIFF_ROLE_ALLOW:
			flags |= POLDIFF_DIFF_ROLE_ALLOWS;
			break;
		case DIFF_ROLE_TRANS:
			flags |= POLDIFF_DIFF_ROLE_TRANS;
			break;
		case DIFF_RANGE_TRANS:
			flags |= POLDIFF_DIFF_RANGE_TRANS;
			break;
		case OPT_STATS:
			stats = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'h':
			usage(argv[0], 0);
			exit(0);
		case 'V':
			printf("sediff %s\n%s\n", VERSION, COPYRIGHT_INFO);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	if (!flags) {
		flags = POLDIFF_DIFF_ALL & ~POLDIFF_DIFF_AVNEVERALLOW;
		default_all = 1;
	}

	if (argc - optind < 2) {
		usage(argv[0], 1);
		exit(1);
	}

	if (!strcmp(";", argv[optind])) {
		ERR(NULL, "%s", "Missing path to original policy.");
		goto err;
	}
	orig_base_path = argv[optind++];
	orig_path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	if (!(orig_module_paths = apol_vector_create(NULL))) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	for (; argc - optind; optind++) {
		if (!strcmp(";", argv[optind])) {
			optind++;
			break;
		}
		if (apol_vector_append(orig_module_paths, (void *)argv[optind])) {
			ERR(NULL, "Error loading module %s", argv[optind]);
			goto err;
		}
		orig_path_type = APOL_POLICY_PATH_TYPE_MODULAR;
	}
	if (apol_file_is_policy_path_list(orig_base_path) > 0) {
		orig_pol_path = apol_policy_path_create_from_file(orig_base_path);
		if (!orig_pol_path) {
			ERR(NULL, "%s", "invalid policy list");
			goto err;
		}
	} else {
		orig_pol_path = apol_policy_path_create(orig_path_type, orig_base_path, orig_module_paths);
		if (!orig_pol_path) {
			ERR(NULL, "%s", strerror(errno));
			goto err;
		}
	}
	apol_vector_destroy(&orig_module_paths);

	if (argc - optind == 0) {
		ERR(NULL, "%s", "Missing path to modified policy.");
		goto err;
	}

	mod_base_path = argv[optind++];
	mod_path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	if (!(mod_module_paths = apol_vector_create(NULL))) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	for (; argc - optind; optind++) {
		if (apol_vector_append(mod_module_paths, (void *)argv[optind])) {
			ERR(NULL, "Error loading module %s", argv[optind]);
			goto err;
		}
		mod_path_type = APOL_POLICY_PATH_TYPE_MODULAR;
	}
	if (apol_file_is_policy_path_list(mod_base_path) > 0) {
		mod_pol_path = apol_policy_path_create_from_file(mod_base_path);
		if (!mod_pol_path) {
			ERR(NULL, "%s", "invalid policy list");
			goto err;
		}
	} else {
		mod_pol_path = apol_policy_path_create(mod_path_type, mod_base_path, mod_module_paths);
		if (!mod_pol_path) {
			ERR(NULL, "%s", strerror(errno));
			goto err;
		}
	}
	apol_vector_destroy(&mod_module_paths);

	int policy_opt = 0;
	if (!(flags & POLDIFF_DIFF_AVNEVERALLOW)) {
		policy_opt |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;
	}
	if (!(flags & POLDIFF_DIFF_RULES)) {
		policy_opt |= QPOL_POLICY_OPTION_NO_RULES;
	}
	orig_policy = apol_policy_create_from_policy_path(orig_pol_path, policy_opt, NULL, NULL);
	if (!orig_policy) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	mod_policy = apol_policy_create_from_policy_path(mod_pol_path, policy_opt, NULL, NULL);
	if (!mod_policy) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}

	qpol_policy_t *orig_qpol = apol_policy_get_qpol(orig_policy);
	qpol_policy_t *mod_qpol = apol_policy_get_qpol(mod_policy);
	/* we disable attribute diffs if either policy does not
	 * support attribute names because the fake attribute names
	 * won't make sense */
	if ((flags & POLDIFF_DIFF_ATTRIBS)
	    && (!(qpol_policy_has_capability(orig_qpol, QPOL_CAP_ATTRIB_NAMES))
		|| !(qpol_policy_has_capability(mod_qpol, QPOL_CAP_ATTRIB_NAMES)))) {
		flags &= ~POLDIFF_DIFF_ATTRIBS;
		WARN(NULL, "%s", "Attribute diffs are not supported for current policies.");
	}

	/* we disable MLS diffs if both policies do not support MLS
	 * but do not warn if it was implicitly requested for two
	 * non-MLS policies */
	if ((flags & POLDIFF_DIFF_MLS)
	    && (!(qpol_policy_has_capability(orig_qpol, QPOL_CAP_MLS)) && !(qpol_policy_has_capability(mod_qpol, QPOL_CAP_MLS)))) {
		flags &= ~(POLDIFF_DIFF_MLS);
		if (!default_all) {
			WARN(NULL, "%s", "MLS diffs are not supported for current policies.");
		}
	}

	/* default callback for error handling is sufficient here */
	if (!(diff = poldiff_create(orig_policy, mod_policy, NULL, NULL))) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	/* poldiff now owns the policies */
	orig_policy = mod_policy = NULL;

	if (poldiff_run(diff, flags)) {
		goto err;
	}

	print_diff(diff, flags, stats, quiet);

	total = get_diff_total(diff, flags);

	apol_policy_path_destroy(&orig_pol_path);
	apol_policy_path_destroy(&mod_pol_path);
	poldiff_destroy(&diff);

	if (total)
		return 1;
	else
		return 0;

      err:
	apol_policy_destroy(&orig_policy);
	apol_policy_destroy(&mod_policy);
	apol_policy_path_destroy(&orig_pol_path);
	apol_policy_path_destroy(&mod_pol_path);
	apol_vector_destroy(&orig_module_paths);
	apol_vector_destroy(&mod_module_paths);
	poldiff_destroy(&diff);
	return 1;
}
