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

#include <config.h>

#include <poldiff/poldiff.h>
#include <apol/policy.h>
#include <apol/vector.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef VERSION
#define VERSION "UNKNOWN"
#endif
#define COPYRIGHT_INFO "Copyright (C) 2004-2006 Tresys Technology, LLC"

/* command line options struct */
static struct option const longopts[] = {
	{"classes", no_argument, NULL, 'c'},
	{"types", no_argument, NULL, 't'},
	{"attributes", no_argument, NULL, 'a'},
	{"roles", no_argument, NULL, 'r'},
	{"users", no_argument, NULL, 'u'},
	{"booleans", no_argument, NULL, 'b'},
	{"terules", no_argument, NULL, 'T'},
	{"roleallows", no_argument, NULL, 'A'},
	{"roletrans", no_argument, NULL, 'R'},
	{"stats", no_argument, NULL, 's'},
	{"gui", no_argument, NULL, 'X'},
	{"quiet", no_argument, NULL, 'q'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

static void usage(const char *prog_name, int brief)
{
	printf("\nSEDiff v%s\n%s\n\n", VERSION, COPYRIGHT_INFO);
	printf("Usage: %s [OPTIONS] ORIGINAL_POLICY ; MODIFIED_POLICY\n", prog_name);
	if (brief) {
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
	      "  -A, --roleallows  role allow rules\n\n"
	      "  -q, --quiet       only print different definitions\n"
	      "  -s, --stats       print only statistics\n"
	      "  -h, --help        display this help and exit\n"
	      "  -v, --version     output version information and exit\n\n", stdout);
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

static void print_class_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	const poldiff_class_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_CLASSES, stats);
	printf("Classes (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_class_vector(diff);
	if (!v)
		return;
	printf("   Added Classes: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_class_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_class_to_string(diff, item);
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
			str = poldiff_class_to_string(diff, item);
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
			str = poldiff_class_to_string(diff, item);
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

static void print_bool_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	poldiff_bool_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_BOOLS, stats);
	printf("Booleans (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_bool_vector(diff);
	if (!v)
		return;
	printf("   Added Booleans: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_bool_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_bool_to_string(diff, (const void *)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");

			free(str);
			str = NULL;
		}
	}

	printf("   Removed Booleans: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_bool_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_bool_to_string(diff, (const void *)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Booleans: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_bool_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_bool_to_string(diff, (const void *)item);
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

static void print_common_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	const poldiff_common_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_COMMONS, stats);
	printf("Commons (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_common_vector(diff);
	if (!v)
		return;
	printf("   Added Commons: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_common_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_common_to_string(diff, item);
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
			str = poldiff_common_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Commons: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_common_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_common_to_string(diff, item);
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

static void print_role_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	const poldiff_role_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_ROLES, stats);
	printf("Roles (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_role_vector(diff);
	if (!v)
		return;
	printf("   Added Roles: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_role_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Roles: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_role_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Roles: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_role_to_string(diff, item);
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

static void print_user_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	const poldiff_user_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_USERS, stats);
	printf("Users (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_user_vector(diff);
	if (!v)
		return;
	printf("   Added Users: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_user_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_user_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Users: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_user_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_user_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Users: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_user_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_user_to_string(diff, item);
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

static void print_rule_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v1 = NULL, *v2 = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	const poldiff_avrule_t *item1 = NULL;
	const poldiff_terule_t *item2 = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES, stats);
	printf("TE Rules (Added %zd, Added New Type %zd, Removed %zd, Removed Missing Type %zd, Modified %zd)\n",
	       stats[0], stats[3], stats[1], stats[4], stats[2]);
	if (stats_only)
		return;
	if ((v1 = poldiff_get_avrule_vector(diff)) == NULL || (v2 = poldiff_get_terule_vector(diff)) == NULL) {
		return;
	}
	printf("   Added TE Rules: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v1); i++) {
		item1 = apol_vector_get_element(v1, i);
		if (poldiff_avrule_get_form(item1) == POLDIFF_FORM_ADDED) {
			if ((str = poldiff_avrule_to_string(diff, item1)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
	for (i = 0; i < apol_vector_get_size(v2); i++) {
		item2 = apol_vector_get_element(v2, i);
		if (poldiff_terule_get_form(item2) == POLDIFF_FORM_ADDED) {
			if ((str = poldiff_terule_to_string(diff, item2)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
	printf("   Added TE Rules because of new type: %zd\n", stats[3]);
	for (i = 0; i < apol_vector_get_size(v1); i++) {
		item1 = apol_vector_get_element(v1, i);
		if (poldiff_avrule_get_form(item1) == POLDIFF_FORM_ADD_TYPE) {
			if ((str = poldiff_avrule_to_string(diff, item1)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
	for (i = 0; i < apol_vector_get_size(v2); i++) {
		item2 = apol_vector_get_element(v2, i);
		if (poldiff_terule_get_form(item2) == POLDIFF_FORM_ADD_TYPE) {
			if ((str = poldiff_terule_to_string(diff, item2)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed TE Rules: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v1); i++) {
		item1 = apol_vector_get_element(v1, i);
		if (poldiff_avrule_get_form(item1) == POLDIFF_FORM_REMOVED) {
			if ((str = poldiff_avrule_to_string(diff, item1)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
	for (i = 0; i < apol_vector_get_size(v2); i++) {
		item2 = apol_vector_get_element(v2, i);
		if (poldiff_terule_get_form(item2) == POLDIFF_FORM_REMOVED) {
			if ((str = poldiff_terule_to_string(diff, item2)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
	printf("   Removed TE Rules because of missing type: %zd\n", stats[4]);
	for (i = 0; i < apol_vector_get_size(v1); i++) {
		item1 = apol_vector_get_element(v1, i);
		if (poldiff_avrule_get_form(item1) == POLDIFF_FORM_REMOVE_TYPE) {
			if ((str = poldiff_avrule_to_string(diff, item1)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
	for (i = 0; i < apol_vector_get_size(v2); i++) {
		item2 = apol_vector_get_element(v2, i);
		if (poldiff_terule_get_form(item2) == POLDIFF_FORM_REMOVE_TYPE) {
			if ((str = poldiff_terule_to_string(diff, item2)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified TE Rules: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v1); i++) {
		item1 = apol_vector_get_element(v1, i);
		if (poldiff_avrule_get_form(item1) == POLDIFF_FORM_MODIFIED) {
			if ((str = poldiff_avrule_to_string(diff, item1)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
	for (i = 0; i < apol_vector_get_size(v2); i++) {
		item2 = apol_vector_get_element(v2, i);
		if (poldiff_terule_get_form(item2) == POLDIFF_FORM_MODIFIED) {
			if ((str = poldiff_terule_to_string(diff, item2)) == NULL) {
				return;
			}
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("\n");
	return;
}

static void print_role_allow_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	const poldiff_role_allow_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_ROLE_ALLOWS, stats);
	printf("Role Allow Rules (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_role_allow_vector(diff);
	if (!v)
		return;
	printf("   Added Role Allow Rules: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_allow_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_role_allow_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Role Allow Rules: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_allow_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_role_allow_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Role Allow Rules: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_allow_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_role_allow_to_string(diff, item);
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

static void print_role_trans_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	const poldiff_role_trans_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_ROLE_TRANS, stats);
	printf("Role Transitions (Added %zd, Added New Type %zd, Removed %zd, Removed Missing Type %zd, Modified %zd)\n", stats[0],
	       stats[3], stats[1], stats[4], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_role_trans_vector(diff);
	if (!v)
		return;
	printf("   Added Role Transitions: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_trans_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_role_trans_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}
	printf("   Added Role Transitions because of new type: %zd\n", stats[3]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_trans_get_form(item) == POLDIFF_FORM_ADD_TYPE) {
			str = poldiff_role_trans_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Role Transitions: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_trans_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_role_trans_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Role Transitions because of missing type: %zd\n", stats[4]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_trans_get_form(item) == POLDIFF_FORM_REMOVE_TYPE) {
			str = poldiff_role_trans_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Role Transitions: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_role_trans_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_role_trans_to_string(diff, item);
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

/** compare the names for two poldiff_type_t objects.
 * used to sort items prior to display. */
static int type_name_cmp(const void *a, const void *b, void *user_data)
{
	poldiff_type_t *ta = (poldiff_type_t *) a;
	poldiff_type_t *tb = (poldiff_type_t *) b;
	if (ta == NULL || tb == NULL)
		return -1;
	return strcmp(poldiff_type_get_name(ta), poldiff_type_get_name(tb));
}

static void print_type_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	poldiff_type_t *item = NULL;

	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_TYPES, stats);
	printf("Types (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_type_vector(diff);
	apol_vector_sort(v, type_name_cmp, NULL);
	if (!v)
		return;
	printf("   Added Types: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_type_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_type_to_string(diff, (const void *)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Types: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_type_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_type_to_string(diff, (const void *)item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Types: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_type_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_type_to_string(diff, (const void *)item);
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

static void print_attrib_diffs(poldiff_t * diff, int stats_only)
{
	apol_vector_t *v = NULL;
	size_t i, stats[5] = { 0, 0, 0, 0, 0 };
	char *str = NULL;
	const poldiff_attrib_t *item = NULL;
	if (!diff)
		return;

	poldiff_get_stats(diff, POLDIFF_DIFF_ATTRIBS, stats);
	printf("Attributes (Added %zd, Removed %zd, Modified %zd)\n", stats[0], stats[1], stats[2]);
	if (stats_only)
		return;
	v = poldiff_get_attrib_vector(diff);
	if (!v)
		return;
	printf("   Added Attributes: %zd\n", stats[0]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_attrib_get_form(item) == POLDIFF_FORM_ADDED) {
			str = poldiff_attrib_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Removed Attributes: %zd\n", stats[1]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_attrib_get_form(item) == POLDIFF_FORM_REMOVED) {
			str = poldiff_attrib_to_string(diff, item);
			if (!str)
				return;
			print_diff_string(str, 1);
			printf("\n");
			free(str);
			str = NULL;
		}
	}

	printf("   Modified Attributes: %zd\n", stats[2]);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		if (poldiff_attrib_get_form(item) == POLDIFF_FORM_MODIFIED) {
			str = poldiff_attrib_to_string(diff, item);
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

static size_t get_diff_total(poldiff_t * diff, uint32_t flags)
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

static void print_diff(poldiff_t * diff, uint32_t flags, int stats, int quiet)
{
	if (flags & POLDIFF_DIFF_CLASSES && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_CLASSES))) {
		print_class_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_COMMONS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_COMMONS))) {
		print_common_diffs(diff, stats);
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
	if (flags & (POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES)
	    && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_AVRULES))) {
		print_rule_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_ROLE_ALLOWS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ROLE_ALLOWS))) {
		print_role_allow_diffs(diff, stats);
	}
	if (flags & POLDIFF_DIFF_ROLE_TRANS && !(quiet && !get_diff_total(diff, POLDIFF_DIFF_ROLE_TRANS))) {
		print_role_trans_diffs(diff, stats);
	}
}

int main(int argc, char **argv)
{
	int optc = 0, quiet = 0, stats = 0;
	uint32_t flags = 0;
	apol_policy_t *orig_policy = NULL, *mod_policy = NULL;
	char *orig_pol_path = NULL, *mod_pol_path = NULL;
	poldiff_t *diff = NULL;
	size_t total = 0;

	while ((optc = getopt_long(argc, argv, "ctarubTARsqhv", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 'c':
			flags |= (POLDIFF_DIFF_CLASSES | POLDIFF_DIFF_COMMONS);
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
			flags |= (POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES);
			break;
		case 'A':
			flags |= POLDIFF_DIFF_ROLE_ALLOWS;
			break;
		case 'R':
			flags |= POLDIFF_DIFF_ROLE_TRANS;
			break;
		case 's':
			stats = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'h':
			usage(argv[0], 0);
			exit(0);
		case 'v':
			printf("\nSEDiff v%s\n%s\n\n", VERSION, COPYRIGHT_INFO);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	if (!flags)
		flags = POLDIFF_DIFF_ALL;

	if (argc - optind < 2) {
		usage(argv[0], 1);
		exit(1);
	}

	if (!strcmp(";", argv[optind])) {
		ERR(NULL, "%s", "Missing path to original policy.");
		goto err;
	}
	orig_pol_path = argv[optind++];
	if (flags & POLDIFF_DIFF_RULES) {
		if (apol_policy_open(orig_pol_path, &orig_policy, NULL, NULL)) {
			ERR(NULL, "%s", strerror(errno));
			goto err;
		}
	} else {
		if (apol_policy_open_no_rules(orig_pol_path, &orig_policy, NULL, NULL)) {
			ERR(NULL, "%s", strerror(errno));
			goto err;
		}
	}

	if (argc - optind > 1) {
		if (!qpol_policy_has_capability(apol_policy_get_qpol(orig_policy), QPOL_CAP_MODULES)) {
			ERR(NULL, "%s", "Module linking only supported for modular policies.");
			goto err;
		}
		for (; argc - optind; optind++) {
			qpol_module_t *mod = NULL;
			if (!strcmp(";", argv[optind])) {
				optind++;
				break;
			}
			if (qpol_module_create_from_file(argv[optind], &mod)) {
				ERR(NULL, "Error loading module %s", argv[optind]);
				goto err;
			}
			if (qpol_policy_append_module(apol_policy_get_qpol(orig_policy), mod)) {
				qpol_module_destroy(&mod);
				goto err;
			}
		}
		if (qpol_policy_rebuild(apol_policy_get_qpol(orig_policy))) {
			goto err;
		}
	}

	if (argc - optind == 0) {
		ERR(NULL, "%s", "Missing path to modified policy.");
		goto err;
	}
	mod_pol_path = argv[optind++];
	if (flags & POLDIFF_DIFF_RULES) {
		if (apol_policy_open(mod_pol_path, &mod_policy, NULL, NULL)) {
			ERR(NULL, "%s", strerror(errno));
			goto err;
		}
	} else {
		if (apol_policy_open_no_rules(mod_pol_path, &mod_policy, NULL, NULL)) {
			ERR(NULL, "%s", strerror(errno));
			goto err;
		}
	}
	if (argc - optind > 1) {
		if (!qpol_policy_has_capability(apol_policy_get_qpol(mod_policy), QPOL_CAP_MODULES)) {
			ERR(NULL, "%s", "Module linking only supported for modular policies.");
			goto err;
		}
		for (; argc - optind; optind++) {
			qpol_module_t *mod = NULL;
			if (qpol_module_create_from_file(argv[optind], &mod)) {
				ERR(NULL, "Error loading module %s", argv[optind]);
				goto err;
			}
			if (qpol_policy_append_module(apol_policy_get_qpol(mod_policy), mod)) {
				qpol_module_destroy(&mod);
				goto err;
			}
		}
		if (qpol_policy_rebuild(apol_policy_get_qpol(mod_policy))) {
			goto err;
		}
	}

	/* we disable attribute diffs if either policy does not support attribute
	 * names because the fake attribute names won't make sense */
	if ((flags & POLDIFF_DIFF_ATTRIBS)
	    && (!(qpol_policy_has_capability(apol_policy_get_qpol(orig_policy), QPOL_CAP_ATTRIB_NAMES))
		|| !(qpol_policy_has_capability(apol_policy_get_qpol(mod_policy), QPOL_CAP_ATTRIB_NAMES)))) {
		flags &= ~POLDIFF_DIFF_ATTRIBS;
		WARN(NULL, "%s", "Attribute diffs are not supported for binary policies.");
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
