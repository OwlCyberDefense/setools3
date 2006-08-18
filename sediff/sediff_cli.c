/**
 *  @file sediff_cli.c
 *  Command line frontend for computing a semantic policy difference.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <poldiff/poldiff.h>
#include <apol/policy.h>
#include <apol/vector.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef SEDIFF_VERSION
#define SEDIFF_VERSION "UNKNOWN"
#endif
#define COPYRIGHT_INFO "Copyright (C) 2004-2006 Tresys Technology, LLC"

/* command line options struct */
static struct option const longopts[] =
{
  {"classes", no_argument, NULL, 'c'},
  {"types", no_argument, NULL, 't'},
  {"attributes", no_argument, NULL, 'a'},
  {"roles", no_argument, NULL, 'r'},
  {"users", no_argument, NULL, 'u'},
  {"booleans", no_argument, NULL, 'b'},
  {"terules", no_argument, NULL, 'T'},
  {"roleallows", no_argument, NULL, 'A'},
  {"roletrans", no_argument, NULL, 'R'},
  {"conds", no_argument, NULL, 'C'},
  {"stats", no_argument, NULL, 's'},
  {"gui", no_argument, NULL, 'X'},
  {"quiet", no_argument, NULL, 'q'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};

static void usage(const char *prog_name, int brief)
{
	printf("\nSEDiff v%s\n%s\n\n", SEDIFF_VERSION, COPYRIGHT_INFO);
	printf("Usage: %s [OPTIONS] POLICY1 POLICY2\n", prog_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", prog_name);
		return;
	}
	fputs("\n"
"Semantically differentiate two policies.  The policies can be either source\n"
"or binary policy files, version 15 or later.  By default, all supported\n"
"policy elements are examined.  The following diff options are available:\n"
"  -c, --classes     object class and common permission definitions\n"
"  -t, --types       type definitions\n"
"  -a, --attributes  attribute definitions\n"
"  -r, --roles       role definitions\n"
"  -u, --users       user definitions\n"
"  -b, --booleans    boolean definitions and default values\n"
"  -T, --terules     type enforcement rules\n"
"  -R, --roletrans   role transition rules\n"
"  -A, --roleallows  role allow rules\n"  
"  -C, --conds       conditionals and their rules\n\n"
"  -q, --quiet       only print different definitions\n"
"  -s, --stats       print useful policy statics\n"
"  -h, --help        display this help and exit\n"
"  -v, --version     output version information and exit\n\n"
, stdout);
	return;
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
			if (c[1] == '\0')
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

static void print_class_diffs(poldiff_t *diff)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = {0, 0, 0, 0, 0};
	char *str = NULL;
	poldiff_class_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_CLASSES, stats);
	printf("Classes (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	v = poldiff_get_class_vector(diff);
	if (!v)
		return;
	printf("   Added Classes: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_class_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_class_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Classes: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_class_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_class_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Classes: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_class_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_class_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("\n");

	return;
}

static void print_common_diffs(poldiff_t *diff)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = {0, 0, 0, 0, 0};
	char *str = NULL;
	poldiff_common_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_COMMONS, stats);
	printf("Commons (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	v = poldiff_get_common_vector(diff);
	if (!v)
		return;
	printf("   Added Commons: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_common_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_common_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Commons: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_common_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_common_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified common: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_common_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_common_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("\n");

	return;
}

/* TODO template print x function
static void print_XXX_diffs(poldiff_t *diff)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = {0, 0, 0, 0, 0};
	char *str = NULL;
	poldiff_XXX_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_XXX, stats);
	printf("XXX (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	v = poldiff_get_XXX_vector(diff);
	if (!v)
		return;
	printf("   Added XXX: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_XXX_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_XXX_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed XXX: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_XXX_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_XXX_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified XXX: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_XXX_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_XXX_to_string(diff, (const void*)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("\n");

	return;
}
*/

static size_t get_diff_total(poldiff_t *diff, uint32_t flags)
{
	size_t total = 0;
	uint32_t i;
	size_t stats[5] = {0, 0, 0, 0, 0};

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

static void print_diff(poldiff_t *diff, uint32_t flags, int stats, int quiet)
{
	if (flags & POLDIFF_DIFF_CLASSES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_CLASSES))) {
		print_class_diffs(diff);
	}
	if (flags & POLDIFF_DIFF_COMMONS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_COMMONS))) {
		print_common_diffs(diff);
	}
	if (flags & POLDIFF_DIFF_TYPES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_TYPES))) {
		printf("TODO: Types\n\n");
	}
	if (flags & POLDIFF_DIFF_ATTRIBS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ATTRIBS))) {
		printf("TODO: Attributes\n\n");
	}
	if (flags & POLDIFF_DIFF_ROLES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ROLES))) {
		printf("TODO: Roles\n\n");
	}
	if (flags & POLDIFF_DIFF_USERS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_USERS))) {
		printf("TODO: Users\n\n");
	}
	if (flags & POLDIFF_DIFF_BOOLS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_BOOLS))) {
		printf("TODO: Bools\n\n");
	}
	if (flags & POLDIFF_DIFF_AVRULES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_AVRULES))) {
		printf("TODO: AVRules\n\n");
	}
	if (flags & POLDIFF_DIFF_TERULES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_TERULES))) {
		printf("TODO: TERules\n\n");
	}
	if (flags & POLDIFF_DIFF_ROLE_ALLOWS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ROLE_ALLOWS))) {
		printf("TODO: RoleAllows\n\n");
	}
	if (flags & POLDIFF_DIFF_ROLE_TRANS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ROLE_TRANS))) {
		printf("TODO: RoleTrans\n\n");
	}
	if (flags & POLDIFF_DIFF_CONDS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_CONDS))) {
		printf("TODO: Conds\n\n");
	}

	if (stats && !quiet) {
		printf("Total Differences\n");
		if (flags & POLDIFF_DIFF_CLASSES) {
			printf("\tClasses: %zd\n", get_diff_total(diff, POLDIFF_DIFF_CLASSES));
		}
		if (flags & POLDIFF_DIFF_COMMONS) {
			printf("\tCommon Permissions: %zd\n", get_diff_total(diff, POLDIFF_DIFF_COMMONS));
		}
		if (flags & POLDIFF_DIFF_TYPES) {
			printf("\tTypes: %zd\n", get_diff_total(diff, POLDIFF_DIFF_TYPES));
		}
		if (flags & POLDIFF_DIFF_ATTRIBS) {
			printf("\tAttributes: %zd\n", get_diff_total(diff, POLDIFF_DIFF_ATTRIBS));
		}
		if (flags & POLDIFF_DIFF_ROLES) {
			printf("\tRoles: %zd\n", get_diff_total(diff, POLDIFF_DIFF_ROLES));
		}
		if (flags & POLDIFF_DIFF_USERS) {
			printf("\tUsers: %zd\n", get_diff_total(diff, POLDIFF_DIFF_USERS));
		}
		if (flags & POLDIFF_DIFF_BOOLS) {
			printf("\tBooleans: %zd\n", get_diff_total(diff, POLDIFF_DIFF_BOOLS));
		}
		if (flags & POLDIFF_DIFF_AVRULES) {
			printf("\tAV Rules: %zd\n", get_diff_total(diff, POLDIFF_DIFF_AVRULES));
		}
		if (flags & POLDIFF_DIFF_TERULES) {
			printf("\tTE Rules: %zd\n", get_diff_total(diff, POLDIFF_DIFF_TERULES));
		}
		if (flags & POLDIFF_DIFF_ROLE_ALLOWS) {
			printf("\tRole Allows: %zd\n", get_diff_total(diff, POLDIFF_DIFF_ROLE_ALLOWS));
		}
		if (flags & POLDIFF_DIFF_ROLE_TRANS) {
			printf("\tRole Transitions: %zd\n", get_diff_total(diff, POLDIFF_DIFF_ROLE_TRANS));
		}
		if (flags & POLDIFF_DIFF_CONDS) {
			printf("\tConditionals: %zd\n", get_diff_total(diff, POLDIFF_DIFF_CONDS));
		}
	}
}

int main (int argc, char **argv)
{
	int optc = 0, quiet = 0, stats = 0;
	uint32_t flags = 0;
	apol_policy_t *orig_policy = NULL, *mod_policy = NULL;
	char *orig_pol_path = NULL, *mod_pol_path = NULL;
	poldiff_t *diff = NULL;
	size_t total = 0;

	while ((optc = getopt_long(argc, argv, "ctarubTARCsXqhv", longopts, NULL)) != -1) {
		switch (optc) {
			case 0:
				break;
			case 'c':
				flags |= (POLDIFF_DIFF_CLASSES|POLDIFF_DIFF_COMMONS);
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
			case 'T':
				flags |= (POLDIFF_DIFF_AVRULES|POLDIFF_DIFF_TERULES);
				break;
			case 'A':
				flags |= POLDIFF_DIFF_ROLE_ALLOWS;
				break;
			case 'R':
				flags |= POLDIFF_DIFF_ROLE_TRANS;
				break;
			case 'C':
				flags |= POLDIFF_DIFF_CONDS;
				break;
			case 's':
				stats = 1;
				break;
			case 'X':
				printf("No GUI yet: %s\n", strerror(ENOTSUP));
				exit(1);
				break;
			case 'q':
				quiet = 1;
				break;
			case 'h':
				usage(argv[0], 0);
				exit(0);
			case 'v':
				printf("\nSEDiff v%s\n%s\n\n", SEDIFF_VERSION, COPYRIGHT_INFO);
				exit(0);
			default:
				usage(argv[0], 1);
				exit(1);
		}
	}

	if (!flags)
		flags = POLDIFF_DIFF_ALL;

	if (argc - optind > 2 || argc - optind < 1) {
		usage(argv[0], 1);
		exit(1);
	}

	orig_pol_path = argv[optind++];
	mod_pol_path = argv[optind];

	if (apol_policy_open(orig_pol_path, &orig_policy, NULL)) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	if (apol_policy_open(mod_pol_path, &mod_policy, NULL)) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
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


	poldiff_destroy(&diff);

	if (total)
		return 1;
	else
		return 0;

err:
	apol_policy_destroy(&orig_policy);
	apol_policy_destroy(&mod_policy);
	poldiff_destroy(&diff);
	return 1;
}
