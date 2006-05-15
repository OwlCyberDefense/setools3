/**
 * @file seinfo.c
 *
 * Command line tool for looking at a SELinux policy
 * and getting various component elements and statistics.
 *
 * @author Frank Mayer  mayerf@tresys.com
 *
 * Copyright (C) 2003-2006 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or
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

/* libapol */
#include <policy.h>
#include <policy-io.h>
#include <render.h>
#include "vector.h"
#include "component-query.h"

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

static char *policy_file = NULL;
static int portconset, protoset;

static void print_type_attrs(FILE *fp, sepol_type_datum_t *type_datum, apol_policy_t *policydb, const int expand);
static void print_attr_types(FILE *fp, sepol_type_datum_t *type_datum, apol_policy_t *policydb, const int expand);
static void print_user_roles(FILE *fp, sepol_user_datum_t *user_datum, apol_policy_t *policydb, const int expand);
static void print_role_types(FILE *fp, sepol_role_datum_t *role_datum, apol_policy_t *policydb, const int expand);
static void print_bool_state(FILE *fp, sepol_bool_datum_t *bool_datum, apol_policy_t *policydb, const int expand);
static void print_class_perms(FILE *fp, sepol_class_datum_t *class_datum, apol_policy_t *policydb, const int expand);

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
  {"portcon", optional_argument, &portconset, 'p'},
  {"protocol", required_argument, &protoset, 'l'},
  {"initialsids", optional_argument, NULL, 'i'},
  {"stats", no_argument, NULL, 's'},
  {"all", no_argument, NULL, 'A'},
  {"expand", no_argument, NULL, 'x'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};

/**
 * Prints a message specifying program options and usage.
 *
 * @param program_name Name of the program
 * @param brief Flag indicating whether brief usage
 * information should be displayed
 */
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
  -lPROTO,  --protocol=PROTO       specify a protocol for portcons\n\
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

/**
 * Prints statistics regarding a policy's components.
 *
 * @param fp Reference to a file to which to print
 * policy statistics
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_stats(FILE *fp, apol_policy_t *policydb)
{
	int retval = -1, mls;
	unsigned int ver = 0, n_perms = 0;
	sepol_iterator_t *iter = NULL;
	apol_type_query_t *type_query = NULL;
	apol_attr_query_t *attr_query = NULL;
	apol_perm_query_t *perm_query = NULL;
	apol_vector_t *perms = NULL, *v = NULL;
	char *str = NULL, *ver_str = NULL;
	int str_sz = 0, ver_str_sz = 16, n_types = 0, n_attrs = 0;
	bool_t binary;
	size_t n_classes = 0, n_users = 0, n_roles = 0, n_bools = 0, n_levels = 0, n_cats = 0,
	       n_portcons = 0, n_netifcons = 0, n_nodecons = 0, n_fsuses = 0, n_genfscons = 0;

	assert(policydb != NULL);

	fprintf(fp, "\nStatistics for policy file: %s\n", policy_file);

	if (sepol_policydb_get_policy_version(policydb->sh, policydb->p, &ver))
		goto cleanup;

	append_str(&str, &str_sz, "");
	mls = sepol_policydb_is_mls_enabled(policydb->sh, policydb->p);
	if (mls < 0)
		goto cleanup;

	append_str(&str, &str_sz, "v.");

	ver_str = malloc(sizeof(unsigned char) * ver_str_sz);
	memset(ver_str, 0x0, ver_str_sz);
	snprintf(ver_str, ver_str_sz, "%u", ver);

	/* we can only handle binary policies at this point */
	binary = TRUE;

	append_str(&str, &str_sz, ver_str);
	append_str(&str, &str_sz, " (");
	append_str(&str, &str_sz, binary ? "binary, " : "source, ");
	append_str(&str, &str_sz, mls ? "MLS" : "non-MLS");
	append_str(&str, &str_sz, ")");

	fprintf(fp, "Policy Version & Type: ");
	fprintf(fp, "%s\n", str);
	free(ver_str);
	free(str);

	if (sepol_policydb_get_class_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_classes))
		goto cleanup;
	sepol_iterator_destroy(&iter);

	perm_query = apol_perm_query_create();
	if (!perm_query)
		goto cleanup;

	/* Match all perms */
	if (apol_get_perm_by_query(policydb, perm_query, &perms))
		goto cleanup;

	n_perms = apol_vector_get_size(perms);
	apol_perm_query_destroy(&perm_query);
	apol_vector_destroy(&perms, NULL);
	fprintf(fp, "\n   Classes:       %7zd    Permissions:   %7d\n", n_classes, n_perms);

	/* types */
	type_query = apol_type_query_create();
	if (!type_query)
		goto cleanup;
	if (apol_get_type_by_query(policydb, type_query, &v) < 0)
		goto cleanup;

	n_types = apol_vector_get_size(v);
	apol_type_query_destroy(&type_query);
	apol_vector_destroy(&v, NULL);

	attr_query = apol_attr_query_create();
	if (!attr_query)
		goto cleanup;
	if (apol_get_attr_by_query(policydb, attr_query, &v) < 0)
		goto cleanup;

	n_attrs = apol_vector_get_size(v);
	apol_attr_query_destroy(&attr_query);
	apol_vector_destroy(&v, NULL);

	fprintf(fp, "   Types:         %7d    Attributes:    %7d\n", n_types, n_attrs);
	sepol_iterator_destroy(&iter);

	/* users/roles */
	if (sepol_policydb_get_user_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_users))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	if (sepol_policydb_get_role_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_roles))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	fprintf(fp, "   Users:         %7zd    Roles:         %7zd\n", n_users, n_roles);

	/* booleans/cond. exprs. */
	if (sepol_policydb_get_bool_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_bools))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	fprintf(fp, "   Booleans:      %7zd    Cond. Expr.:    %6s\n", n_bools, "N/A");

	/* sensitivities/categories */
	if (sepol_policydb_get_level_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_levels))
		goto cleanup;

	sepol_iterator_destroy(&iter);
	if (sepol_policydb_get_cat_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_cats))
		goto cleanup;

	sepol_iterator_destroy(&iter);
	fprintf(fp, "   Sensitivities: %7zd    Categories:    %7zd\n", n_levels, n_cats);
	fprintf(fp, "   Allow:         %7s    Neverallow:    %7s\n", "N/A", "N/A");
	fprintf(fp, "   Auditallow:    %7s    Dontaudit:     %7s\n", "N/A", "N/A");
	fprintf(fp, "   Role allow:    %7s    Role trans:    %7s\n", "N/A", "N/A");
	fprintf(fp, "   Type_trans:    %7s    Type_change:   %7s\n", "N/A", "N/A");
	fprintf(fp, "   Type_member:   %7s    Range_trans:   %7s\n", "N/A", "N/A");
	fprintf(fp, "   Constraints:   %7s    Validatetrans: %7s\n", "N/A", "N/A");

	/* fs_use/genfscon */
	if (sepol_policydb_get_fs_use_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_fsuses))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	if (sepol_policydb_get_genfscon_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_genfscons))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	fprintf(fp, "   Fs_use:        %7zd    Genfscon:      %7zd\n", n_fsuses, n_genfscons);

	/* portcon/netifcon */
	if (sepol_policydb_get_portcon_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_portcons))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	if (sepol_policydb_get_netifcon_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_netifcons))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	fprintf(fp, "   Portcon:       %7zd    Netifcon:      %7zd\n", n_portcons, n_netifcons);

	/* nodecon/isids */
	if (sepol_policydb_get_nodecon_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_nodecons))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	fprintf(fp, "   Nodecon:       %7zd    Initial SIDs:  %7s\n", n_nodecons, "N/A");
	fprintf(fp, "\n");

	retval = 0;
cleanup:
	sepol_iterator_destroy(&iter);
	apol_type_query_destroy(&type_query);
	apol_attr_query_destroy(&attr_query);
	apol_perm_query_destroy(&perm_query);
	apol_vector_destroy(&v, NULL);
	apol_vector_destroy(&perms, NULL);
	return retval;
}

/**
 * Prints statistics regarding a policy's object classes.
 * If this function is given a name, it will attempt to
 * print statistics about a particular object class; otherwise
 * the function prints statistics about all of the policy's object
 * classes.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to an object class' name; if NULL,
 * all object classes will be considered
 * @param expand Flag indicating whether to print object class
 * permissions
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_classes(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
	int retval = -1;
	sepol_iterator_t *iter = NULL;
	size_t n_classes = 0;
	sepol_class_datum_t *class_datum = NULL;

	if (name != NULL) {
		if (sepol_policydb_get_class_by_name(policydb->sh, policydb->p, name, &class_datum))
			goto cleanup;
		print_class_perms(fp, class_datum, policydb, expand);
	} else {
		if (sepol_policydb_get_class_iter(policydb->sh, policydb->p, &iter))
			goto cleanup;
		if (sepol_iterator_get_size(iter, &n_classes))
			goto cleanup;
		fprintf(fp, "Object classes: %d\n", (int)n_classes);

		for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
			if (sepol_iterator_get_item(iter, (void **)&class_datum))
				goto cleanup;
			print_class_perms(fp, class_datum, policydb, expand);
		}
		sepol_iterator_destroy(&iter);
	}

	retval = 0;
cleanup:
	sepol_iterator_destroy(&iter);
	return retval;
}

/**
 * Prints statistics regarding a policy's types.
 * If this function is given a name, it will attempt to
 * print statistics about a particular type; otherwise
 * the function prints statistics about all of the policy's types.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a type's name; if NULL,
 * all object classes will be considered
 * @param expand Flag indicating whether to print each type's attributes
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_types(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
	int retval = -1;
	bool_t binary;
	unsigned int n_types = 0;
	sepol_type_datum_t *type_datum = NULL;
	sepol_iterator_t *iter = NULL;
	size_t iter_sz;

	if(name != NULL) {
		if (sepol_policydb_get_type_by_name(policydb->sh, policydb->p, name, &type_datum))
			goto cleanup;
	}
	else {
		binary = TRUE;   /* We only know how to handle binary policies so far */
	}

	/* Find the number of types in the policy */
	if (sepol_policydb_get_type_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &iter_sz))
		goto cleanup;
	sepol_iterator_destroy(&iter);
	n_types = (unsigned int)iter_sz;

	binary = TRUE;
	if(name == NULL) {
		/* use num_types(policy)-1 to factor out the pseudo type "self" if not binary*/
		fprintf(fp, "\nTypes: %d\n", binary ? n_types - 1 : n_types);
	}

	/* if name was provided, only print that name */
	if (name != NULL) {
		if (sepol_policydb_get_type_by_name(policydb->sh, policydb->p, name, &type_datum))
			goto cleanup;
		print_type_attrs(fp, type_datum, policydb, expand);
	} else {
		if (sepol_policydb_get_type_iter(policydb->sh, policydb->p, &iter))
			goto cleanup;
		/* Print all type names */
		for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
			if (sepol_iterator_get_item(iter, (void **)&type_datum))
				goto cleanup;
			print_type_attrs(fp, type_datum, policydb, expand);
		}
	}

	retval = 0;
cleanup:
	sepol_iterator_destroy(&iter);
	return retval;
}

/**
 * Prints statistics regarding a policy's attributes.
 * If this function is given a name, it will attempt to
 * print statistics about a particular attribute; otherwise
 * the function prints statistics about all of the policy's
 * attributes.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to an attribute's name; if NULL,
 * all object classes will be considered
 * @param expand Flag indicating whether to print each attribute's
 * allowed types
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_attribs(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
	int retval = -1, i;
	apol_attr_query_t *attr_query = NULL;
	apol_vector_t *v = NULL;
	sepol_type_datum_t *type_datum = NULL;
	size_t n_attrs;

	/* we are only printing information about 1 attribute */
	if (name != NULL) {
		attr_query = apol_attr_query_create();
		if (!attr_query)
			goto cleanup;
		if (apol_attr_query_set_attr(policydb, attr_query, name))
			goto cleanup;
		if (apol_get_attr_by_query(policydb, attr_query, &v))
			goto cleanup;
		apol_attr_query_destroy(&attr_query);
		if (apol_vector_get_size(v) == 0) {
			apol_vector_destroy(&v, NULL);
			ERR(policydb, "Provided attribute (%s) is not a valid attribute name.", name);
			goto cleanup;
		}

		type_datum = (sepol_type_datum_t *)apol_vector_get_element(v, (size_t)0);
		print_attr_types(fp, type_datum, policydb, expand);
	} else {
		attr_query = apol_attr_query_create();
		if (!attr_query)
			goto cleanup;
		if (apol_get_attr_by_query(policydb, attr_query, &v))
			goto cleanup;
		apol_attr_query_destroy(&attr_query);
		n_attrs = apol_vector_get_size(v);

		fprintf(fp, "\nAttributes: %zd\n", n_attrs);
		for (i = 0; i < n_attrs; i++) {
			/* get sepol_type_datum_t* item from vector */
			type_datum = (sepol_type_datum_t *)apol_vector_get_element(v, (size_t)i);
			if (!type_datum)
				goto cleanup;
			print_attr_types(fp, type_datum, policydb, expand);
		}
	}
	apol_vector_destroy(&v, NULL);

	retval = 0;
cleanup:
	apol_attr_query_destroy(&attr_query);
	apol_vector_destroy(&v, NULL);
	return retval;
}

/**
 * Prints statistics regarding a policy's roles.
 * If this function is given a name, it will attempt to
 * print statistics about a particular role; otherwise
 * the function prints statistics about all of the policy's roles.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to an role's name; if NULL,
 * all roles will be considered
 * @param expand Flag indicating whether to print valid users
 * for each role
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_roles(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
	int retval = -1;
	sepol_role_datum_t *role_datum = NULL;
	sepol_iterator_t *iter = NULL;
	size_t n_roles = 0;

	if (name != NULL) {
		if (sepol_policydb_get_role_by_name(policydb->sh, policydb->p, name, &role_datum))
			goto cleanup;
		print_role_types(fp, role_datum, policydb, expand);
	} else {
		if (sepol_policydb_get_role_iter(policydb->sh, policydb->p, &iter))
			goto cleanup;
		if (sepol_iterator_get_size(iter, &n_roles))
			goto cleanup;
		fprintf(fp, "\nRoles: %d\n", (int)n_roles);

		for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
			if (sepol_iterator_get_item(iter, (void **)&role_datum))
				goto cleanup;
			print_role_types(fp, role_datum, policydb, expand);
		}
		sepol_iterator_destroy(&iter);
	}

	retval = 0;
cleanup:
	sepol_iterator_destroy(&iter);
	return retval;
}

/**
 * Prints statistics regarding a policy's booleans.
 * If this function is given a name, it will attempt to
 * print statistics about a particular boolean; otherwise
 * the function prints statistics about all of the policy's booleans.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a boolean's name; if NULL,
 * all booleans will be considered
 * @param expand Flag indicating whether to print each
 * boolean's default state
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_booleans(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
	int retval = -1;
	sepol_bool_datum_t *bool_datum = NULL;
	sepol_iterator_t *iter = NULL;
	size_t n_bools = 0;

	if (name != NULL) {
		if (sepol_policydb_get_bool_by_name(policydb->sh, policydb->p, name, &bool_datum))
			goto cleanup;
		print_bool_state(fp, bool_datum, policydb, expand);
	} else {
		if (sepol_policydb_get_bool_iter(policydb->sh, policydb->p, &iter))
			goto cleanup;
		if (sepol_iterator_get_size(iter, &n_bools))
			goto cleanup;
		fprintf(fp, "\nConditional Booleans: %zd\n", n_bools);
		for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
			if (sepol_iterator_get_item(iter, (void **)&bool_datum))
				goto cleanup;
			print_bool_state(fp, bool_datum, policydb, expand);
		}
		sepol_iterator_destroy(&iter);
	}

	retval = 0;
cleanup:
	sepol_iterator_destroy(&iter);
	return retval;
}

/**
 * Prints statistics regarding a policy's users.
 * If this function is given a name, it will attempt to
 * print statistics about a particular user; otherwise
 * the function prints statistics about all of the policy's
 * users.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a user's name; if NULL,
 * all users will be considered
 * @param expand Flag indicating whether to print each user's
 * roles
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_users(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
	int retval = -1;
	sepol_iterator_t *iter = NULL;
	sepol_user_datum_t *user_datum = NULL;
	size_t n_users = 0;

	if(name != NULL) {
		if (sepol_policydb_get_user_by_name(policydb->sh, policydb->p, name, &user_datum))
			goto cleanup;
		print_user_roles(fp, user_datum, policydb, expand);
	} else {
		if (sepol_policydb_get_user_iter(policydb->sh, policydb->p, &iter))
			goto cleanup;
		if (sepol_iterator_get_size(iter, &n_users))
			goto cleanup;
		fprintf(fp, "\nUsers: %d\n", (int)n_users);

		for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
			if (sepol_iterator_get_item(iter, (void **)&user_datum))
				goto cleanup;
			print_user_roles(fp, user_datum, policydb, expand);
		}
		sepol_iterator_destroy(&iter);
	}

	retval = 0;
cleanup:
	sepol_iterator_destroy(&iter);
	return retval;
}

/**
 * Prints statistics regarding a policy's MLS sensitivities.
 * If this function is given a name, it will attempt to
 * print statistics about a particular sensitivity; otherwise
 * the function prints statistics about all of the policy's
 * sensitivities.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a sensitivity's name; if NULL,
 * all sensitivities will be considered
 * @param expand Flag indicating whether to print each
 * sensitivity's categories
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_sens(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
	int retval = -1;
	size_t i;
	char *tmp = NULL, *lvl_name = NULL;
	apol_level_query_t *query = NULL;
	apol_vector_t *v = NULL;
	sepol_level_datum_t *level = NULL;
	apol_mls_level_t *ap_mls_lvl = NULL;

	query = apol_level_query_create();
	if (!query) {
		ERR(policydb, "Out of memory");
		goto cleanup;
	}
	if (apol_level_query_set_sens(policydb, query, name))
		goto cleanup;
	if (apol_get_level_by_query(policydb, query, &v))
		goto cleanup;

	if (!name)
		fprintf(fp, "\nSensitivities: %zd\n", apol_vector_get_size(v));
	for (i = 0; i < apol_vector_get_size(v); i++) {
		level = (sepol_level_datum_t *)apol_vector_get_element(v, i);
		if (sepol_level_datum_get_name(policydb->sh, policydb->p, level, &lvl_name))
			goto cleanup;
		fprintf(fp, "   %s\n", lvl_name);
		if (expand) {
			ap_mls_lvl = (apol_mls_level_t *)apol_mls_level_create_from_sepol_level_datum(policydb, level);
			tmp = re_render_mls_level2(policydb, ap_mls_lvl);
			apol_mls_level_destroy(&ap_mls_lvl);
			if (!tmp)
				goto cleanup;
			fprintf(fp, "      level %s\n", tmp);
			free(tmp);
		}
	}

	if (name && !apol_vector_get_size(v)) {
		ERR(policydb, "Provided sensitivity (%s) is not a valid sensitivity name", name);
		goto cleanup;
	}

	retval = 0;
cleanup:
	apol_level_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	return retval;
}

static int print_cats(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
    /* FIX ME: not done yet */
    #if 0
	int idx, i, j, retv, num_sens = 0, *sens = NULL;

	if (name) {
		idx = get_category_idx(name, policy);
		if (idx == -1) {
			ERR(policydb, "Provided category (%s) is not a valid category name\n", name);
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
    #endif
	return 0;
}

/* FIX ME: need a header here */
static int print_fsuse(FILE *fp, const char *type, apol_policy_t *policydb)
{
	int retval = -1;
	char *tmp = NULL;
	apol_fs_use_query_t *query = NULL;
	apol_vector_t *v = NULL;
	sepol_fs_use_t *fs_use = NULL;
	size_t i;

	query = apol_fs_use_query_create();
	if (!query) {
		ERR(policydb, "Out of memory");
		goto cleanup;
	}
	if (apol_fs_use_query_set_filesystem(policydb, query, type))
		goto cleanup;
	if (apol_get_fs_use_by_query(policydb, query, &v))
		goto cleanup;

	if (!type)
		fprintf(fp, "\nFs_use: %zd\n", apol_vector_get_size(v));

	for (i = 0; i < apol_vector_get_size(v); i++) {
		fs_use = (sepol_fs_use_t *)apol_vector_get_element(v, i);
		tmp =  re_render_fs_use2(policydb, fs_use);
		if (!tmp)
			goto cleanup;
		fprintf(fp, "%s\n", tmp);
		free(tmp);
	}

	if (type && !apol_vector_get_size(v))
		ERR(policydb, "No fs_use statement for filesystem of type %s", type);

	retval = 0;
cleanup:
	apol_fs_use_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	return retval;
}

/**
 * Prints statistics regarding a policy's genfscons.
 * If this function is given a name, it will attempt to
 * print statistics about a particular genfscon; otherwise
 * the function prints statistics about all of the policy's
 * genfscons.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a genfscon's type; if NULL,
 * all genfscons will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_genfscon(FILE *fp, const char *type, apol_policy_t *policydb)
{
	int retval = -1;
	size_t i;
	char *tmp = NULL;
	apol_genfscon_query_t *query = NULL;
	apol_vector_t *v = NULL;
	sepol_genfscon_t *genfscon = NULL;

	query = apol_genfscon_query_create();
	if (!query) {
		ERR(policydb, "Out of memory");
		goto cleanup;
	}

	if (apol_genfscon_query_set_filesystem(policydb, query, type))
		goto cleanup;
	if (apol_get_genfscon_by_query(policydb, query, &v))
		goto cleanup;

	if (!type)
		fprintf(fp, "\nGenfscon: %zd\n", apol_vector_get_size(v));

	for (i = 0; i < apol_vector_get_size(v); i++) {
		genfscon = (sepol_genfscon_t *)apol_vector_get_element(v, i);
		tmp = re_render_genfscon2(policydb, genfscon);
		if (!tmp)
			goto cleanup;
		fprintf(fp, "%s\n", tmp);
		free(tmp);
	}

	if (type && !apol_vector_get_size(v))
		ERR(policydb, "No genfscon statement for filesystem of type %s", type);

	retval = 0;
cleanup:
	apol_genfscon_query_destroy(&query);
	apol_vector_destroy(&v, free);

	return retval;
}

/**
 * Prints statistics regarding a policy's netifcons.
 * If this function is given a name, it will attempt to
 * print statistics about a particular netifcon; otherwise
 * the function prints statistics about all of the policy's
 * netifcons.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a network interface's name; if NULL,
 * all netifcons will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_netifcon(FILE *fp, const char *name, apol_policy_t *policydb)
{
	int retval = -1;
	char *netifcon_name = NULL;
	sepol_netifcon_t *netifcon = NULL;
	sepol_iterator_t *iter = NULL;
	size_t n_netifcons = 0;
/* FIX ME: call re_render_netifcon here */
	if (name != NULL) {
		if (sepol_policydb_get_netifcon_by_name(policydb->sh, policydb->p, name, &netifcon))
			goto cleanup;
		if (sepol_netifcon_get_name(policydb->sh, policydb->p, netifcon, &netifcon_name))
			goto cleanup;
		fprintf(fp, "   %s\n", netifcon_name);
	} else {
		if (sepol_policydb_get_netifcon_iter(policydb->sh, policydb->p, &iter))
			goto cleanup;
		if (sepol_iterator_get_size(iter, &n_netifcons))
			goto cleanup;
		fprintf(fp, "\nNetifcon: %zd\n", n_netifcons);

		for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
			if (sepol_iterator_get_item(iter, (void **)netifcon))
				goto cleanup;
			if (sepol_netifcon_get_name(policydb->sh, policydb->p, netifcon, &netifcon_name))
				goto cleanup;
			fprintf(fp, "   %s\n", netifcon_name);
		}
		sepol_iterator_destroy(&iter);
	}

	retval = 0;
cleanup:
	sepol_iterator_destroy(&iter);
	return retval;
}

/**
 * Prints statistics regarding a policy's nodecons.
 * If this function is given a name, it will attempt to
 * print statistics about a particular nodecon; otherwise
 * the function prints statistics about all of the policy's
 * nodecons.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a textually represented IP address;
 * if NULL, all nodecons will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_nodecon(FILE *fp, const char *addr, apol_policy_t *policydb)
{
	int retval = -1, protocol;
	char *tmp = NULL;
	uint32_t address[4] = {0,0,0,0};
	apol_nodecon_query_t *query = NULL;
	apol_vector_t *v = NULL;
	sepol_nodecon_t *nodecon = NULL;
	size_t n_nodecons = 0, i;

	query = apol_nodecon_query_create();
	if (!query) {
		ERR(policydb, "Out of memory");
		goto cleanup;
	}

	/* address needs to be in a libapol-understandable format */
	if (addr) {
		protocol = apol_str_to_internal_ip(addr, address);
		if (protocol < 0) {
			ERR(policydb, "Unable to parse IP address");
			goto cleanup;
		}
		if (apol_nodecon_query_set_addr(policydb, query, address, protocol))
			goto cleanup;
		if (apol_nodecon_query_set_proto(policydb, query, protocol))
			goto cleanup;
	}

	if (apol_get_nodecon_by_query(policydb, query, &v))
		goto cleanup;

	n_nodecons = apol_vector_get_size(v);
	if (!n_nodecons) {
		ERR(policydb, "Provided address (%s) is not valid", addr);
		goto cleanup;
	}

	if (!addr)
		fprintf(fp, "Nodecon: %zd\n", n_nodecons);

	for (i = 0; i < apol_vector_get_size(v); i++) {
		nodecon = (sepol_nodecon_t *)apol_vector_get_element(v, i);
		tmp = re_render_nodecon2(policydb, nodecon);
		if (!tmp)
			goto cleanup;
		fprintf(fp, "   %s\n", tmp);
		free(tmp);
	}

	if (addr && !n_nodecons)
		ERR(policydb, "No matching nodecon for address %s", addr);

	retval = 0;
cleanup:
	apol_nodecon_query_destroy(&query);
	apol_vector_destroy(&v, free);
	return retval;
}

/**
 * Prints statistics regarding a policy's portcons.
 * If this function is given a name, it will attempt to
 * print statistics about a particular portcon; otherwise
 * the function prints statistics about all of the policy's
 * portcons.
 *
 * @param fp Reference to a file to which to print statistics
 * @param num Reference to a port number; if NULL,
 * all ports will be considered
 * @param protocol Reference to the name of a ISO 7498-1
 * transport layer protocol used to communicate over a port
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_portcon(FILE *fp, const char *num, const char *protocol, apol_policy_t *policydb)
{
	int retval = -1;
	sepol_portcon_t *portcon = NULL;
	sepol_iterator_t *iter = NULL;
	uint16_t low_port, high_port;
	uint8_t ocon_proto, proto = 0;
	size_t n_portcons;
	char *tmp = NULL;

	if (num && protocol) {
		if (!strcmp(protocol, "tcp")) {
			proto = IPPROTO_TCP;
		} else if (!strcmp(protocol, "udp")) {
			proto = IPPROTO_UDP;
		} else {
			ERR(policydb, "Unable to get portcon by port and protocol: bad protocol %s", protocol);
			goto cleanup;
		}

		if (sepol_policydb_get_portcon_by_port(policydb->sh, policydb->p,
		    (uint16_t)atoi(num), (uint16_t)atoi(num), proto, &portcon)) {
			ERR(policydb, "No portcon statement for port number %d", atoi(num));
			goto cleanup;
		}
	}

	if (sepol_policydb_get_portcon_iter(policydb->sh, policydb->p, &iter))
		goto cleanup;
	if (sepol_iterator_get_size(iter, &n_portcons))
		goto cleanup;
	if (!num)
		fprintf(fp, "\nPortcon: %zd\n", n_portcons);

	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, (void **)&portcon))
			goto cleanup;
		if (sepol_portcon_get_low_port(policydb->sh, policydb->p, portcon, &low_port))
			goto cleanup;
		if (sepol_portcon_get_high_port(policydb->sh, policydb->p, portcon, &high_port))
			goto cleanup;
		if (sepol_portcon_get_protocol(policydb->sh, policydb->p, portcon, &ocon_proto))
			goto cleanup;

		if (num && protocol) {
			if (atoi(num) >= low_port && atoi(num) <= high_port && ocon_proto == proto )
				fprintf(fp, "   %s\n", (tmp = re_render_portcon2(policydb, portcon)));
		} else {
			fprintf(fp, "   %s\n", (tmp = re_render_portcon2(policydb, portcon)));
		}
		free(tmp);
		tmp = NULL;
	}

	retval = 0;
cleanup:
	sepol_iterator_destroy(&iter);
	return retval;
}

static int print_isids(FILE *fp, const char *name, int expand, apol_policy_t *policydb)
{
   /* FIX ME: not done yet */
   #if 0
	char *isid_name = NULL, *scontext = NULL;
	int idx, i, rt;
	
	if(name != NULL) {
		idx = get_initial_sid_idx(name, policy);
		if(idx < 0) {
			ERR(policydb, "Provided initial SID name (%s) is not a valid name.", name);
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
			ERR(policydb, "Unexpected error getting initial SID name");
			return -1;
		}
		if(expand) {
			fprintf(fp, "%20s:  ", isid_name);
			scontext = re_render_initial_sid_security_context(i, policy);
			if(scontext == NULL) {
				ERR(policydb, "Problem getting security context for %dth initial SID", i);
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
  #endif
	return 0;
}


int main (int argc, char **argv)
{
	int classes, types, attribs, roles, users, all, expand, stats, rt, optc, isids, bools, sens, cats, fsuse, genfs, netif, node, port;
	unsigned int open_opts = 0;
	apol_policy_t *policydb = NULL;
	char *class_name, *type_name, *attrib_name, *role_name, *user_name, *isid_name, *bool_name, *sens_name, *cat_name, *fsuse_type, *genfs_type, *netif_name, *node_addr, *port_num = NULL, *protocol = NULL;
	unsigned int search_opts = 0;

	class_name = type_name = attrib_name = role_name = user_name = isid_name = bool_name = sens_name = cat_name = fsuse_type = genfs_type = netif_name = node_addr = port_num = NULL;
	classes = types = attribs = roles = users = all = expand = stats = isids = bools = sens = cats = fsuse = genfs = netif = node = port = 0;
	while ((optc = getopt_long (argc, argv, "c::t::a::r::u::b::S::C::f::g::n::o::p::l:i::d:sAxhv", longopts, NULL)) != -1)  {
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
		case 'l': /* protocol */
			open_opts |= POLOPT_OCONTEXT;
			if (optarg != 0)
				protocol = optarg;
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

	/* If searching for a portcon, need to specify protocol as well as port */
	if (port_num && !protocol) {
		fprintf(stderr, "If you are searching for a particular portcon, you must also specify a protocol with -l.\n");
		exit(1);
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
			fprintf(stderr, "Default policy search failed: %s\n", find_default_policy_file_strerr(rt));
			exit(1);
		}
	} else
		policy_file = argv[optind];

	/* attempt to open the policy */
	if (apol_policy_open_binary(policy_file, &policydb)) {
		fprintf(stderr, "Error: opening binary policy.\n");
		exit(1);
	}
	policydb->msg_callback_arg = NULL;

	/* display requested info */
	if(stats || all)
		print_stats(stdout, policydb);
	if(classes || all)
		print_classes(stdout, class_name, expand, policydb);
	if(types || all)
		print_types(stdout, type_name, expand, policydb);
	if(attribs|| all)
		print_attribs(stdout, attrib_name, expand, policydb);
	if(roles|| all)
		print_roles(stdout, role_name, expand, policydb);
	if(users || all)
		print_users(stdout, user_name, expand, policydb);
	if(bools || all)
		print_booleans(stdout, bool_name, expand, policydb);
	if(sens || all)
		print_sens(stdout, sens_name, expand, policydb);
	if(cats || all)
		print_cats(stdout, cat_name, expand, policydb);
	if(fsuse || all)
		print_fsuse(stdout, fsuse_type, policydb);
	if(genfs || all)
		print_genfscon(stdout, genfs_type, policydb);
	if(netif || all)
		print_netifcon(stdout, netif_name, policydb);
	if(node || all)
		print_nodecon(stdout, node_addr, policydb);
	if(port || all)
		print_portcon(stdout, port_num, protocol, policydb);
	if(isids || all)
		print_isids(stdout, isid_name, expand, policydb);

	apol_policy_destroy(&policydb);
	exit(0);
}

static void print_type_attrs(FILE *fp, sepol_type_datum_t *type_datum, apol_policy_t *policydb, const int expand)
{
	sepol_iterator_t *iter = NULL;
	unsigned char isattr;
	char *type_name = NULL, *attr_name = NULL;
	sepol_type_datum_t *attr_datum = NULL;

	if (sepol_type_datum_get_name(policydb->sh, policydb->p, type_datum, &type_name))
		goto cleanup;
	if (sepol_type_datum_get_isattr(policydb->sh, policydb->p, type_datum, &isattr))
		goto cleanup;

	if (!isattr) {
		fprintf(fp, "   %s\n", type_name);
		if (expand) {     /* Print this type's attributes */
			if (sepol_type_datum_get_attr_iter(policydb->sh, policydb->p, type_datum, &iter))
				goto cleanup;
			for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
				if (sepol_iterator_get_item(iter, (void **)&attr_datum))
					goto cleanup;
				if (sepol_type_datum_get_name(policydb->sh, policydb->p, attr_datum, &attr_name))
					goto cleanup;
				fprintf(fp, "      %s\n", attr_name);
			}
		}
	}

cleanup:
	sepol_iterator_destroy(&iter);
	return;
}

static void print_attr_types(FILE *fp, sepol_type_datum_t *type_datum, apol_policy_t *policydb, const int expand)
{
	sepol_type_datum_t *attr_datum = NULL;
	sepol_iterator_t *iter = NULL;
	char *attr_name = NULL, *type_name = NULL;
	unsigned char isattr;

	if (sepol_type_datum_get_name(policydb->sh, policydb->p, type_datum, &attr_name))
		goto cleanup;
	fprintf(fp, "   %s\n", attr_name);

	if (expand) {
		/* get an iterator over all types this attribute has */
		if (sepol_type_datum_get_isattr(policydb->sh, policydb->p, type_datum, &isattr))
			goto cleanup;
		if (isattr) { /* sanity check */
			if (sepol_type_datum_get_type_iter(policydb->sh, policydb->p, type_datum, &iter))
				goto cleanup;
			for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
				if (sepol_iterator_get_item(iter, (void **)&attr_datum))
					goto cleanup;
				if (sepol_type_datum_get_name(policydb->sh, policydb->p, attr_datum, &type_name))
					goto cleanup;
				fprintf(fp, "      %s\n", type_name);
			}
			sepol_iterator_destroy(&iter);

		} else  /* this should never happen */
			goto cleanup;

	}

cleanup:
	sepol_iterator_destroy(&iter);
	return;
}

static void print_user_roles(FILE *fp, sepol_user_datum_t *user_datum, apol_policy_t *policydb, const int expand)
{
	sepol_role_datum_t *role_datum = NULL;
	sepol_iterator_t *iter = NULL;
	sepol_mls_range_t *range = NULL;
	sepol_mls_level_t *dflt_level = NULL, *low_level = NULL, *high_level = NULL;
	char *user_name = NULL, *role_name = NULL, *dfltlevel_name = NULL,
	     *lowlevel_name = NULL, *highlevel_name = NULL;

	if (sepol_user_datum_get_name(policydb->sh, policydb->p, user_datum, &user_name))
		goto cleanup;
	fprintf(fp, "   %s\n", user_name);

	if (expand) {
		if (sepol_policydb_is_mls_enabled(policydb->sh, policydb->p)) {
			if (sepol_user_datum_get_dfltlevel(policydb->sh, policydb->p, user_datum, &dflt_level))
				goto cleanup;
			if (sepol_mls_level_get_sens_name(policydb->sh, policydb->p, dflt_level, &dfltlevel_name))
				goto cleanup;
			fprintf(fp, "      default level: %s\n", dfltlevel_name);
			if (sepol_user_datum_get_range(policydb->sh, policydb->p, user_datum, &range))
				goto cleanup;
			if (sepol_mls_range_get_low_level(policydb->sh, policydb->p, range, &low_level))
				goto cleanup;
			if (sepol_mls_range_get_high_level(policydb->sh, policydb->p, range, &high_level))
				goto cleanup;
			if (sepol_mls_level_get_sens_name(policydb->sh, policydb->p, low_level, &lowlevel_name))
				goto cleanup;
			if (sepol_mls_level_get_sens_name(policydb->sh, policydb->p, high_level, &highlevel_name))
				goto cleanup;
			fprintf(fp, "      range: %s-%s\n", lowlevel_name, highlevel_name);
		}

		fprintf(fp, "      roles:\n");
		if (sepol_user_datum_get_role_iter(policydb->sh, policydb->p, user_datum, &iter))
			goto cleanup;
		for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
			if (sepol_iterator_get_item(iter, (void **)&role_datum))
				goto cleanup;
			if (sepol_role_datum_get_name(policydb->sh, policydb->p, role_datum, &role_name))
				goto cleanup;
			fprintf(fp, "         %s\n", role_name);
		}
	}

cleanup:
	sepol_iterator_destroy(&iter);
	return;
}

static void print_role_types(FILE *fp, sepol_role_datum_t *role_datum, apol_policy_t *policydb, const int expand)
{
	char *role_name = NULL, *type_name = NULL;
	sepol_role_datum_t *dom_datum = NULL;
	sepol_type_datum_t *type_datum = NULL;
	sepol_iterator_t *iter = NULL;
	size_t n_dom = 0, n_types = 0;

	if (sepol_role_datum_get_name(policydb->sh, policydb->p, role_datum, &role_name))
		goto cleanup;
	fprintf(fp, "   %s\n", role_name);

	if(expand) {
		if (sepol_role_datum_get_dominate_iter(policydb->sh, policydb->p, role_datum, &iter))
			goto cleanup;
		if (sepol_iterator_get_size(iter, &n_dom))
			goto cleanup;
		if ((int)n_dom > 0) {
			fprintf(fp, "      Dominated Roles:\n");
			/* print dominated roles */
			for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
				if (sepol_iterator_get_item(iter, (void **)&dom_datum))
					goto cleanup;
				if (sepol_role_datum_get_name(policydb->sh, policydb->p, dom_datum, &role_name))
					goto cleanup;
				fprintf(fp, "         %s\n", role_name);
			}
		}
		sepol_iterator_destroy(&iter);

		if (sepol_role_datum_get_type_iter(policydb->sh, policydb->p, role_datum, &iter))
			goto cleanup;
		if (sepol_iterator_get_size(iter, &n_types))
			goto cleanup;
		if ((int)n_types > 0) {
			fprintf(fp, "      Types:\n");
			/* print types */
			for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
				if (sepol_iterator_get_item(iter, (void **)&type_datum))
					goto cleanup;
				if (sepol_type_datum_get_name(policydb->sh, policydb->p, type_datum, &type_name))
					goto cleanup;
				fprintf(fp, "         %s\n", type_name);
			}
		}
	}

cleanup:
	sepol_iterator_destroy(&iter);
	return;
}

static void print_bool_state(FILE *fp, sepol_bool_datum_t *bool_datum, apol_policy_t *policydb, const int expand)
{
	char *bool_name = NULL;
	int state;

	if (sepol_bool_datum_get_name(policydb->sh, policydb->p, bool_datum, &bool_name))
		return;
	fprintf(fp, "   %s", bool_name);

	if (expand) {
		if (sepol_bool_datum_get_state(policydb->sh, policydb->p, bool_datum, &state))
			return;
		fprintf(fp, ": %s", state ? "TRUE" : "FALSE");
	}
	fprintf(fp, "\n");
}

static void print_class_perms(FILE *fp, sepol_class_datum_t *class_datum, apol_policy_t *policydb, const int expand)
{
	char *class_name = NULL, *perm_name = NULL;
	sepol_iterator_t *iter = NULL;
	sepol_common_datum_t *common_datum = NULL;

	if (!class_datum)
		goto cleanup;

	if (sepol_class_datum_get_name(policydb->sh, policydb->p, class_datum, &class_name))
		goto cleanup;
	fprintf(fp, "   %s\n", class_name);

	if(expand) {
		/* get commons for this class */
		if (sepol_class_datum_get_common(policydb->sh, policydb->p, class_datum, &common_datum))
			goto cleanup;
		if (common_datum) {
			if (sepol_common_datum_get_perm_iter(policydb->sh, policydb->p, common_datum, &iter))
				goto cleanup;
			/* print perms for the common */
			for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
				if (sepol_iterator_get_item(iter, (void **)&perm_name))
					goto cleanup;
				fprintf(fp, "      %s\n", perm_name);
			}
			sepol_iterator_destroy(&iter);
		}
		/* print unique perms for this class */
		if (sepol_class_datum_get_perm_iter(policydb->sh, policydb->p, class_datum, &iter))
			goto cleanup;
		for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
			if (sepol_iterator_get_item(iter, (void **)&perm_name))
				goto cleanup;
			fprintf(fp, "      %s\n", perm_name);
		}
		sepol_iterator_destroy(&iter);
	}

cleanup:
	sepol_iterator_destroy(&iter);
	return;
}
