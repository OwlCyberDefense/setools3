/**
 * @file
 *
 * Command line tool for looking at a SELinux policy
 * and getting various component elements and statistics.
 *
 * @author Frank Mayer  mayerf@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author David Windsor dwindsor@tresys.com
 *
 * Copyright (C) 2003-2007 Tresys Technology, LLC
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

/* libapol */
#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>
#include <apol/vector.h>

/* libqpol */
#include <qpol/policy.h>
#include <qpol/util.h>

/* other */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2007 Tresys Technology, LLC"

static char *policy_file = NULL;

static void print_type_attrs(FILE * fp, qpol_type_t * type_datum, apol_policy_t * policydb, const int expand);
static void print_attr_types(FILE * fp, qpol_type_t * type_datum, apol_policy_t * policydb, const int expand);
static void print_user_roles(FILE * fp, qpol_user_t * user_datum, apol_policy_t * policydb, const int expand);
static void print_role_types(FILE * fp, qpol_role_t * role_datum, apol_policy_t * policydb, const int expand);
static void print_bool_state(FILE * fp, qpol_bool_t * bool_datum, apol_policy_t * policydb, const int expand);
static void print_class_perms(FILE * fp, qpol_class_t * class_datum, apol_policy_t * policydb, const int expand);
static void print_cat_sens(FILE * fp, qpol_cat_t * cat_datum, apol_policy_t * policydb, const int expand);
static int qpol_cat_datum_compare(const void *datum1, const void *datum2, void *data);
static int qpol_level_datum_compare(const void *datum1, const void *datum2, void *data);

enum opt_values
{
	OPT_SENSITIVITY = 256, OPT_CATEGORY,
	OPT_INITIALSID, OPT_FS_USE, OPT_GENFSCON,
	OPT_NETIFCON, OPT_NODECON, OPT_PORTCON, OPT_PROTOCOL,
	OPT_ALL, OPT_STATS
};

static struct option const longopts[] = {
	{"class", optional_argument, NULL, 'c'},
	{"sensitivity", optional_argument, NULL, OPT_SENSITIVITY},
	{"category", optional_argument, NULL, OPT_CATEGORY},
	{"type", optional_argument, NULL, 't'},
	{"attribute", optional_argument, NULL, 'a'},
	{"role", optional_argument, NULL, 'r'},
	{"user", optional_argument, NULL, 'u'},
	{"bool", optional_argument, NULL, 'b'},
	{"initialsid", optional_argument, NULL, OPT_INITIALSID},
	{"fs_use", optional_argument, NULL, OPT_FS_USE},
	{"genfscon", optional_argument, NULL, OPT_GENFSCON},
	{"netifcon", optional_argument, NULL, OPT_NETIFCON},
	{"nodecon", optional_argument, NULL, OPT_NODECON},
	{"portcon", optional_argument, NULL, OPT_PORTCON},
	{"protocol", required_argument, NULL, OPT_PROTOCOL},
	{"stats", no_argument, NULL, OPT_STATS},
	{"all", no_argument, NULL, OPT_ALL},
	{"expand", no_argument, NULL, 'x'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
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
	printf("Usage: %s [OPTIONS] [EXPRESSION] [POLICY ...]\n\n", program_name);
	if (brief) {
		printf("\tTry %s --help for more help.\n\n", program_name);
		return;
	}
	printf("Print information about the components of a SELinux policy.\n\n");
	printf("EXPRESSIONS:\n");
	printf("  -c[NAME], --class[=NAME]         print object classes\n");
	printf("  --sensitivity[=NAME]             print sensitivities\n");
	printf("  --category[=NAME]                print categories\n");
	printf("  -t[NAME], --type[=NAME]          print types (no aliases or attributes)\n");
	printf("  -a[NAME], --attribute[=NAME]     print type attributes\n");
	printf("  -r[NAME], --role[=NAME]          print roles\n");
	printf("  -u[NAME], --user[=NAME]          print users\n");
	printf("  -b[NAME], --bool[=NAME]          print conditional booleans\n");
	printf("  --initialsid[=NAME]              print initial SIDs\n");
	printf("  --fs_use[=TYPE]                  print fs_use statements\n");
	printf("  --genfscon[=TYPE]                print genfscon statements\n");
	printf("  --netifcon[=NAME]                print netif contexts\n");
	printf("  --nodecon[=ADDR]                 print node contexts\n");
	printf("  --portcon[=PORT]                 print port contexts\n");
	printf("  --protocol=PROTO                 specify a protocol for portcons\n");
	printf("  --all                            print all of the above\n");
	printf("OPTIONS:\n");
	printf("  -x, --expand                     show more info for specified components\n");
	printf("  --stats                          print useful policy statistics\n");
	printf("  -h, --help                       print this help text and exit\n");
	printf("  -V, --version                    print version information and exit\n");
	printf("\n");
	printf("For component options, if NAME is provided, then only show info for\n");
	printf("NAME.  Specifying a name is most useful when used with the -x option.\n");
	printf("If no option is provided, display useful policy statistics (-s).\n");
	printf("\n");
	printf("The default source policy, or if that is unavailable the default binary\n");
	printf("policy, will be opened if no policy is provided.\n\n");
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
static int print_stats(FILE * fp, apol_policy_t * policydb)
{
	int retval = -1;
	unsigned int n_perms = 0;
	qpol_iterator_t *iter = NULL;
	apol_type_query_t *type_query = NULL;
	apol_attr_query_t *attr_query = NULL;
	apol_perm_query_t *perm_query = NULL;
	apol_vector_t *perms = NULL, *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	char *str = NULL;
	size_t n_types = 0, n_attrs = 0;
	size_t n_classes = 0, n_users = 0, n_roles = 0, n_bools = 0, n_conds = 0, n_levels = 0,
		n_cats = 0, n_portcons = 0, n_netifcons = 0, n_nodecons = 0, n_fsuses = 0,
		n_genfscons = 0, n_allows = 0, n_neverallows = 0, n_auditallows = 0, n_dontaudits = 0,
		n_typetrans = 0, n_typechanges = 0, n_typemembers = 0, n_isids = 0, n_roleallows = 0,
		n_roletrans = 0, n_rangetrans = 0, n_constr = 0, n_vtrans = 0;

	assert(policydb != NULL);

	fprintf(fp, "\nStatistics for policy file: %s\n", policy_file);

	if (!(str = apol_policy_get_version_type_mls_str(policydb)))
		goto cleanup;

	fprintf(fp, "Policy Version & Type: ");
	fprintf(fp, "%s\n", str);
	free(str);

	if (qpol_policy_get_class_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_classes))
		goto cleanup;
	qpol_iterator_destroy(&iter);

	perm_query = apol_perm_query_create();
	if (!perm_query)
		goto cleanup;

	/* Match all perms */
	if (apol_perm_get_by_query(policydb, perm_query, &perms))
		goto cleanup;

	n_perms = apol_vector_get_size(perms);
	apol_perm_query_destroy(&perm_query);
	apol_vector_destroy(&perms, NULL);
	fprintf(fp, "\n   Classes:       %7zd    Permissions:   %7d\n", n_classes, n_perms);

	/* sensitivities/categories */
	if (qpol_policy_get_level_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_levels))
		goto cleanup;

	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_cat_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_cats))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Sensitivities: %7zd    Categories:    %7zd\n", n_levels, n_cats);

	/* types */
	type_query = apol_type_query_create();
	if (!type_query)
		goto cleanup;
	if (apol_type_get_by_query(policydb, type_query, &v) < 0)
		goto cleanup;

	n_types = apol_vector_get_size(v);
	apol_type_query_destroy(&type_query);
	apol_vector_destroy(&v, NULL);

	attr_query = apol_attr_query_create();
	if (!attr_query)
		goto cleanup;
	if (apol_attr_get_by_query(policydb, attr_query, &v) < 0)
		goto cleanup;

	n_attrs = apol_vector_get_size(v);
	apol_attr_query_destroy(&attr_query);
	apol_vector_destroy(&v, NULL);

	fprintf(fp, "   Types:         %7zd    Attributes:    %7zd\n", n_types, n_attrs);
	qpol_iterator_destroy(&iter);

	/* users/roles */
	if (qpol_policy_get_user_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_users))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_role_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_roles))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Users:         %7zd    Roles:         %7zd\n", n_users, n_roles);

	/* booleans/cond. exprs. */
	if (qpol_policy_get_bool_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_bools))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_cond_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_conds))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Booleans:      %7zd    Cond. Expr.:   %7zd\n", n_bools, n_conds);

	/* allow/neverallow */
	if (qpol_policy_get_avrule_iter(q, QPOL_RULE_ALLOW, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_allows))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_avrule_iter(q, QPOL_RULE_NEVERALLOW, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_neverallows))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Allow:         %7zd    Neverallow:    %7zd\n", n_allows, n_neverallows);

	/* auditallow/dontaudit */
	if (qpol_policy_get_avrule_iter(q, QPOL_RULE_AUDITALLOW, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_auditallows))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_avrule_iter(q, QPOL_RULE_DONTAUDIT, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_dontaudits))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Auditallow:    %7zd    Dontaudit:     %7zd\n", n_auditallows, n_dontaudits);

	/* type_transition/type_change */
	if (qpol_policy_get_terule_iter(q, QPOL_RULE_TYPE_TRANS, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_typetrans))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_terule_iter(q, QPOL_RULE_TYPE_CHANGE, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_typechanges))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Type_trans:    %7zd    Type_change:   %7zd\n", n_typetrans, n_typechanges);

	/* type_member/role allow */
	if (qpol_policy_get_terule_iter(q, QPOL_RULE_TYPE_MEMBER, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_typemembers))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_role_allow_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_roleallows))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Type_member:   %7zd    Role allow:    %7zd\n", n_typemembers, n_roleallows);

	/* role_trans/range_trans */
	if (qpol_policy_get_role_trans_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_roletrans))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_range_trans_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_rangetrans))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Role_trans:    %7zd    Range_trans:   %7zd\n", n_roletrans, n_rangetrans);

	/* constraints/validatetrans */
	if (qpol_policy_get_constraint_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_constr))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_validatetrans_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_vtrans))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Constraints:   %7zd    Validatetrans: %7zd\n", n_constr, n_vtrans);

	/* isids/fs_use */
	if (qpol_policy_get_isid_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_isids))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_fs_use_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_fsuses))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Initial SIDs:  %7zd    Fs_use:        %7zd\n", n_isids, n_fsuses);

	/* genfscon/portcon */
	if (qpol_policy_get_genfscon_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_genfscons))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_portcon_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_portcons))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Genfscon:      %7zd    Portcon:       %7zd\n", n_genfscons, n_portcons);

	/* netifcon/nodecon */
	if (qpol_policy_get_netifcon_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_netifcons))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_nodecon_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_nodecons))
		goto cleanup;
	qpol_iterator_destroy(&iter);
	fprintf(fp, "   Netifcon:      %7zd    Nodecon:       %7zd\n", n_netifcons, n_nodecons);
	fprintf(fp, "\n");

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
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
static int print_classes(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = -1;
	qpol_iterator_t *iter = NULL;
	size_t n_classes = 0;
	qpol_class_t *class_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	if (name != NULL) {
		if (qpol_policy_get_class_by_name(q, name, &class_datum))
			goto cleanup;
		print_class_perms(fp, class_datum, policydb, expand);
	} else {
		if (qpol_policy_get_class_iter(q, &iter))
			goto cleanup;
		if (qpol_iterator_get_size(iter, &n_classes))
			goto cleanup;
		fprintf(fp, "Object classes: %d\n", (int)n_classes);

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&class_datum))
				goto cleanup;
			print_class_perms(fp, class_datum, policydb, expand);
		}
		qpol_iterator_destroy(&iter);
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
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
static int print_types(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = -1;
	qpol_type_t *type_datum = NULL;
	qpol_iterator_t *iter = NULL;
	apol_vector_t *type_vector = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t vector_sz;

	if (name != NULL) {
		if (qpol_policy_get_type_by_name(q, name, &type_datum))
			goto cleanup;
	}

	/* Find the number of types in the policy */
	if (apol_type_get_by_query(policydb, NULL, &type_vector))
		goto cleanup;
	vector_sz = apol_vector_get_size(type_vector);
	apol_vector_destroy(&type_vector, NULL);

	if (name == NULL) {
		fprintf(fp, "\nTypes: %zd\n", vector_sz);
	}

	/* if name was provided, only print that name */
	if (name != NULL) {
		if (qpol_policy_get_type_by_name(q, name, &type_datum))
			goto cleanup;
		print_type_attrs(fp, type_datum, policydb, expand);
	} else {
		if (qpol_policy_get_type_iter(q, &iter))
			goto cleanup;
		/* Print all type names */
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type_datum))
				goto cleanup;
			print_type_attrs(fp, type_datum, policydb, expand);
		}
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
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
static int print_attribs(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = -1, i;
	apol_attr_query_t *attr_query = NULL;
	apol_vector_t *v = NULL;
	qpol_type_t *type_datum = NULL;
	size_t n_attrs;

	/* we are only printing information about 1 attribute */
	if (name != NULL) {
		attr_query = apol_attr_query_create();
		if (!attr_query)
			goto cleanup;
		if (apol_attr_query_set_attr(policydb, attr_query, name))
			goto cleanup;
		if (apol_attr_get_by_query(policydb, attr_query, &v))
			goto cleanup;
		apol_attr_query_destroy(&attr_query);
		if (apol_vector_get_size(v) == 0) {
			apol_vector_destroy(&v, NULL);
			ERR(policydb, "Provided attribute (%s) is not a valid attribute name.", name);
			goto cleanup;
		}

		type_datum = (qpol_type_t *) apol_vector_get_element(v, (size_t) 0);
		print_attr_types(fp, type_datum, policydb, expand);
	} else {
		attr_query = apol_attr_query_create();
		if (!attr_query)
			goto cleanup;
		if (apol_attr_get_by_query(policydb, attr_query, &v))
			goto cleanup;
		apol_attr_query_destroy(&attr_query);
		n_attrs = apol_vector_get_size(v);

		fprintf(fp, "\nAttributes: %zd\n", n_attrs);
		for (i = 0; i < n_attrs; i++) {
			/* get qpol_type_t* item from vector */
			type_datum = (qpol_type_t *) apol_vector_get_element(v, (size_t) i);
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
static int print_roles(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = -1;
	qpol_role_t *role_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_roles = 0;

	if (name != NULL) {
		if (qpol_policy_get_role_by_name(q, name, &role_datum))
			goto cleanup;
		print_role_types(fp, role_datum, policydb, expand);
	} else {
		if (qpol_policy_get_role_iter(q, &iter))
			goto cleanup;
		if (qpol_iterator_get_size(iter, &n_roles))
			goto cleanup;
		fprintf(fp, "\nRoles: %d\n", (int)n_roles);

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&role_datum))
				goto cleanup;
			print_role_types(fp, role_datum, policydb, expand);
		}
		qpol_iterator_destroy(&iter);
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
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
static int print_booleans(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = -1;
	qpol_bool_t *bool_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_bools = 0;

	if (name != NULL) {
		if (qpol_policy_get_bool_by_name(q, name, &bool_datum))
			goto cleanup;
		print_bool_state(fp, bool_datum, policydb, expand);
	} else {
		if (qpol_policy_get_bool_iter(q, &iter))
			goto cleanup;
		if (qpol_iterator_get_size(iter, &n_bools))
			goto cleanup;
		fprintf(fp, "\nConditional Booleans: %zd\n", n_bools);
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&bool_datum))
				goto cleanup;
			print_bool_state(fp, bool_datum, policydb, expand);
		}
		qpol_iterator_destroy(&iter);
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
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
static int print_users(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = -1;
	qpol_iterator_t *iter = NULL;
	qpol_user_t *user_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_users = 0;

	if (name != NULL) {
		if (qpol_policy_get_user_by_name(q, name, &user_datum))
			goto cleanup;
		print_user_roles(fp, user_datum, policydb, expand);
	} else {
		if (qpol_policy_get_user_iter(q, &iter))
			goto cleanup;
		if (qpol_iterator_get_size(iter, &n_users))
			goto cleanup;
		fprintf(fp, "\nUsers: %d\n", (int)n_users);

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&user_datum))
				goto cleanup;
			print_user_roles(fp, user_datum, policydb, expand);
		}
		qpol_iterator_destroy(&iter);
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
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
static int print_sens(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = -1;
	size_t i;
	char *tmp = NULL, *lvl_name = NULL;
	apol_level_query_t *query = NULL;
	apol_vector_t *v = NULL;
	qpol_level_t *level = NULL;
	apol_mls_level_t *ap_mls_lvl = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	query = apol_level_query_create();
	if (!query) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_level_query_set_sens(policydb, query, name))
		goto cleanup;
	if (apol_level_get_by_query(policydb, query, &v))
		goto cleanup;

	if (!name)
		fprintf(fp, "\nSensitivities: %zd\n", apol_vector_get_size(v));
	for (i = 0; i < apol_vector_get_size(v); i++) {
		level = (qpol_level_t *) apol_vector_get_element(v, i);
		if (qpol_level_get_name(q, level, &lvl_name))
			goto cleanup;
		fprintf(fp, "   %s\n", lvl_name);
		if (expand) {
			ap_mls_lvl = (apol_mls_level_t *) apol_mls_level_create_from_qpol_level_datum(policydb, level);
			tmp = apol_mls_level_render(policydb, ap_mls_lvl);
			apol_mls_level_destroy(&ap_mls_lvl);
			if (!tmp)
				goto cleanup;
			fprintf(fp, "      level %s\n", tmp);
			free(tmp);
		}
	}

	if (name && !apol_vector_get_size(v)) {
		ERR(policydb, "Provided sensitivity (%s) is not a valid sensitivity name.", name);
		goto cleanup;
	}

	retval = 0;
      cleanup:
	apol_level_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	return retval;
}

/**
 * Prints statistics regarding a policy's MLS categories.
 * If this function is given a name, it will attempt to
 * print statistics about a particular category; otherwise
 * the function prints statistics about all of the policy's
 * categories.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a MLS category's name; if NULL,
 * all categories will be considered
 * @param expand Flag indicating whether to print each
 * category's sensitivities
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_cats(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = 0;
	apol_cat_query_t *query = NULL;
	apol_vector_t *v = NULL;
	qpol_cat_t *cat_datum = NULL;
	size_t i, n_cats;

	query = apol_cat_query_create();
	if (!query) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_cat_query_set_cat(policydb, query, name))
		goto cleanup;
	if (apol_cat_get_by_query(policydb, query, &v))
		goto cleanup;
	n_cats = apol_vector_get_size(v);
	apol_vector_sort(v, &qpol_cat_datum_compare, policydb);

	if (!name)
		fprintf(fp, "Categories: %zd\n", n_cats);
	for (i = 0; i < n_cats; i++) {
		cat_datum = (qpol_cat_t *) apol_vector_get_element(v, i);
		if (!cat_datum)
			goto cleanup;
		print_cat_sens(fp, cat_datum, policydb, expand);

	}

	if (name && !n_cats) {
		ERR(policydb, "Provided category (%s) is not a valid category name.", name);
		goto cleanup;
	}

	retval = 0;
      cleanup:
	apol_cat_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	return retval;
}

/**
 * Prints statistics regarding a policy's fs_use statements.
 * If this function is given a name, it will attempt to
 * print statistics about a particular filesystem; otherwise
 * the function prints statistics about all of the policy's
 * fs_use statements.
 *
 * @param fp Reference to a file to which to print statistics
 * @param type Reference to the name of a file system type; if NULL,
 * all file system types will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_fsuse(FILE * fp, const char *type, apol_policy_t * policydb)
{
	int retval = -1;
	char *tmp = NULL;
	apol_fs_use_query_t *query = NULL;
	apol_vector_t *v = NULL;
	qpol_fs_use_t *fs_use = NULL;
	size_t i;

	query = apol_fs_use_query_create();
	if (!query) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_fs_use_query_set_filesystem(policydb, query, type))
		goto cleanup;
	if (apol_fs_use_get_by_query(policydb, query, &v))
		goto cleanup;

	if (!type)
		fprintf(fp, "\nFs_use: %zd\n", apol_vector_get_size(v));

	for (i = 0; i < apol_vector_get_size(v); i++) {
		fs_use = (qpol_fs_use_t *) apol_vector_get_element(v, i);
		tmp = apol_fs_use_render(policydb, fs_use);
		if (!tmp)
			goto cleanup;
		fprintf(fp, "   %s\n", tmp);
		free(tmp);
	}
	if (type && !apol_vector_get_size(v))
		ERR(policydb, "No fs_use statement for filesystem of type %s.", type);

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
static int print_genfscon(FILE * fp, const char *type, apol_policy_t * policydb)
{
	int retval = -1;
	size_t i;
	char *tmp = NULL;
	apol_genfscon_query_t *query = NULL;
	apol_vector_t *v = NULL;
	qpol_genfscon_t *genfscon = NULL;

	query = apol_genfscon_query_create();
	if (!query) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (apol_genfscon_query_set_filesystem(policydb, query, type))
		goto cleanup;
	if (apol_genfscon_get_by_query(policydb, query, &v))
		goto cleanup;

	if (!type)
		fprintf(fp, "\nGenfscon: %zd\n", apol_vector_get_size(v));

	for (i = 0; i < apol_vector_get_size(v); i++) {
		genfscon = (qpol_genfscon_t *) apol_vector_get_element(v, i);
		tmp = apol_genfscon_render(policydb, genfscon);
		if (!tmp)
			goto cleanup;
		fprintf(fp, "   %s\n", tmp);
		free(tmp);
	}

	if (type && !apol_vector_get_size(v))
		ERR(policydb, "No genfscon statement for filesystem of type %s.", type);

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
static int print_netifcon(FILE * fp, const char *name, apol_policy_t * policydb)
{
	int retval = -1;
	char *tmp;
	qpol_netifcon_t *netifcon = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_netifcons = 0;

	if (name != NULL) {
		if (qpol_policy_get_netifcon_by_name(q, name, &netifcon))
			goto cleanup;
		tmp = apol_netifcon_render(policydb, netifcon);
		if (!tmp)
			goto cleanup;
		fprintf(fp, "   %s\n", tmp);
		free(tmp);
	} else {
		if (qpol_policy_get_netifcon_iter(q, &iter))
			goto cleanup;
		if (qpol_iterator_get_size(iter, &n_netifcons))
			goto cleanup;
		fprintf(fp, "\nNetifcon: %zd\n", n_netifcons);

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&netifcon))
				goto cleanup;
			tmp = apol_netifcon_render(policydb, netifcon);
			if (!tmp)
				goto cleanup;
			fprintf(fp, "   %s\n", tmp);
			free(tmp);
		}
		qpol_iterator_destroy(&iter);
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
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
static int print_nodecon(FILE * fp, const char *addr, apol_policy_t * policydb)
{
	int retval = -1, protocol;
	char *tmp = NULL;
	uint32_t address[4] = { 0, 0, 0, 0 };
	apol_nodecon_query_t *query = NULL;
	apol_vector_t *v = NULL;
	qpol_nodecon_t *nodecon = NULL;
	size_t n_nodecons = 0, i;

	query = apol_nodecon_query_create();
	if (!query) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	/* address needs to be in a libapol-understandable format */
	if (addr) {
		protocol = apol_str_to_internal_ip(addr, address);
		if (protocol < 0) {
			ERR(policydb, "%s", "Unable to parse IP address");
			goto cleanup;
		}
		if (apol_nodecon_query_set_addr(policydb, query, address, protocol))
			goto cleanup;
		if (apol_nodecon_query_set_proto(policydb, query, protocol))
			goto cleanup;
	}

	if (apol_nodecon_get_by_query(policydb, query, &v))
		goto cleanup;

	n_nodecons = apol_vector_get_size(v);
	if (!n_nodecons) {
		ERR(policydb, "Provided address (%s) is not valid.", addr);
		goto cleanup;
	}

	if (!addr)
		fprintf(fp, "Nodecon: %zd\n", n_nodecons);

	for (i = 0; i < apol_vector_get_size(v); i++) {
		nodecon = (qpol_nodecon_t *) apol_vector_get_element(v, i);
		tmp = apol_nodecon_render(policydb, nodecon);
		if (!tmp)
			goto cleanup;
		fprintf(fp, "   %s\n", tmp);
		free(tmp);
	}

	if (addr && !n_nodecons)
		ERR(policydb, "No matching nodecon for address %s.", addr);

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
static int print_portcon(FILE * fp, const char *num, const char *protocol, apol_policy_t * policydb)
{
	int retval = -1;
	qpol_portcon_t *portcon = NULL;
	qpol_iterator_t *iter = NULL;
	uint16_t low_port, high_port;
	uint8_t ocon_proto, proto = 0;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_portcons;
	char *tmp = NULL;

	if (protocol) {
		if (!strcmp(protocol, "tcp"))
			proto = IPPROTO_TCP;
		else if (!strcmp(protocol, "udp"))
			proto = IPPROTO_UDP;
		else {
			ERR(policydb, "Unable to get portcon by protocol: bad protocol %s.", protocol);
			goto cleanup;
		}
	}
	if (qpol_policy_get_portcon_iter(q, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_portcons))
		goto cleanup;
	if (!num)
		fprintf(fp, "\nPortcon: %zd\n", n_portcons);

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&portcon))
			goto cleanup;
		if (qpol_portcon_get_low_port(q, portcon, &low_port))
			goto cleanup;
		if (qpol_portcon_get_high_port(q, portcon, &high_port))
			goto cleanup;
		if (qpol_portcon_get_protocol(q, portcon, &ocon_proto))
			goto cleanup;
		if (num) {
			if (atoi(num) < low_port || atoi(num) > high_port)
				continue;
		}
		if (protocol) {
			if (ocon_proto != proto)
				continue;
		}
		fprintf(fp, "	%s\n", (tmp = apol_portcon_render(policydb, portcon)));
		free(tmp);
		tmp = NULL;
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}

/**
 * Prints statistics regarding a policy's initial SIDs.
 * If this function is given a name, it will attempt to
 * print statistics about a particular initial SID; otherwise
 * the function prints statistics about all of the policy's
 * initial SIDs.
 *
 * @param fp Reference to a file to which to print statistics
 * @param name Reference to a SID name; if NULL,
 * all initial SIDs will be considered
 * @param expand Flag indicating whether to print each
 * initial SID's security context
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static int print_isids(FILE * fp, const char *name, int expand, apol_policy_t * policydb)
{
	int retval = -1;
	apol_isid_query_t *query = NULL;
	apol_vector_t *v = NULL;
	qpol_isid_t *isid = NULL;
	qpol_context_t *ctxt = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t i, n_isids = 0;
	char *tmp = NULL, *isid_name = NULL;

	query = apol_isid_query_create();
	if (!query) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_isid_query_set_name(policydb, query, name))
		goto cleanup;
	if (apol_isid_get_by_query(policydb, query, &v))
		goto cleanup;
	n_isids = apol_vector_get_size(v);

	if (!name)
		fprintf(fp, "\nInitial SID: %zd\n", n_isids);

	for (i = 0; i < n_isids; i++) {
		isid = (qpol_isid_t *) apol_vector_get_element(v, i);
		if (qpol_isid_get_name(q, isid, &isid_name))
			goto cleanup;
		if (!expand) {
			fprintf(fp, "	    %s\n", isid_name);
		} else {
			if (qpol_isid_get_context(q, isid, &ctxt))
				goto cleanup;
			tmp = apol_qpol_context_render(policydb, ctxt);
			if (!tmp)
				goto cleanup;
			fprintf(fp, "%20s:  %s\n", isid_name, tmp);
			free(tmp);
		}
	}

	if (name && !n_isids) {
		ERR(policydb, "Provided initial SID name (%s) is not a valid name.", name);
		goto cleanup;
	}

	retval = 0;
      cleanup:
	apol_isid_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	return retval;
}

int main(int argc, char **argv)
{
	int classes, types, attribs, roles, users, all, expand, stats, rt, optc, isids, bools, sens, cats, fsuse, genfs, netif,
		node, port;
	apol_policy_t *policydb = NULL;
	apol_policy_path_t *pol_path = NULL;
	apol_vector_t *mod_paths = NULL;
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;

	char *class_name, *type_name, *attrib_name, *role_name, *user_name, *isid_name, *bool_name, *sens_name, *cat_name,
		*fsuse_type, *genfs_type, *netif_name, *node_addr, *port_num = NULL, *protocol = NULL;

	class_name = type_name = attrib_name = role_name = user_name = isid_name = bool_name = sens_name = cat_name = fsuse_type =
		genfs_type = netif_name = node_addr = port_num = NULL;
	classes = types = attribs = roles = users = all = expand = stats = isids = bools = sens = cats = fsuse = genfs = netif =
		node = port = 0;
	while ((optc = getopt_long(argc, argv, "c::t::a::r::u::b::xhV", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 'c':	       /* classes */
			classes = 1;
			if (optarg != 0)
				class_name = optarg;
			break;
		case OPT_SENSITIVITY:
			sens = 1;
			if (optarg != 0)
				sens_name = optarg;
			break;
		case OPT_CATEGORY:
			cats = 1;
			if (optarg != 0)
				cat_name = optarg;
			break;
		case 't':	       /* types */
			types = 1;
			if (optarg != 0)
				type_name = optarg;
			break;
		case 'a':	       /* attributes */
			attribs = 1;
			if (optarg != 0)
				attrib_name = optarg;
			break;
		case 'r':	       /* roles */
			roles = 1;
			if (optarg != 0)
				role_name = optarg;
			break;
		case 'u':	       /* users */
			users = 1;
			if (optarg != 0)
				user_name = optarg;
			break;
		case 'b':	       /* conditional booleans */
			bools = 1;
			if (optarg != 0)
				bool_name = optarg;
			break;
		case OPT_INITIALSID:
			isids = 1;
			if (optarg != 0)
				isid_name = optarg;
			break;
		case OPT_FS_USE:
			fsuse = 1;
			if (optarg != 0)
				fsuse_type = optarg;
			break;
		case OPT_GENFSCON:
			genfs = 1;
			if (optarg != 0)
				genfs_type = optarg;
			break;
		case OPT_NETIFCON:
			netif = 1;
			if (optarg != 0)
				netif_name = optarg;
			break;
		case OPT_NODECON:
			node = 1;
			if (optarg != 0)
				node_addr = optarg;
			break;
		case OPT_PORTCON:
			port = 1;
			if (optarg != 0)
				port_num = optarg;
			break;
		case OPT_PROTOCOL:
			if (optarg != 0)
				protocol = optarg;
			break;
		case OPT_ALL:
			all = 1;
			break;
		case 'x':	       /* expand */
			expand = 1;
			break;
		case OPT_STATS:
			stats = 1;
			break;
		case 'h':	       /* help */
			usage(argv[0], 0);
			exit(0);
		case 'V':	       /* version */
			printf("seinfo %s\n%s\n", VERSION, COPYRIGHT_INFO);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	/* check for naked -l */
	if (protocol && !(port || all)) {
		fprintf(stderr, "The --protocol flag requires either --portcon or --ALL.\n");
		exit(1);
	}
	/* if no options, then show stats */
	if (classes + types + attribs + roles + users + isids + bools + sens + cats + fsuse + genfs + netif + node + port + all < 1) {
		stats = 1;
	}

	if (argc - optind < 1) {
		rt = qpol_default_policy_find(&policy_file);
		if (rt < 0) {
			fprintf(stderr, "Default policy search failed: %s\n", strerror(errno));
			exit(1);
		} else if (rt != 0) {
			fprintf(stderr, "No default policy found.\n");
			exit(1);
		}
	} else {
		policy_file = strdup(argv[optind]);
		if (!policy_file) {
			fprintf(stderr, "Out of memory\n");
			exit(1);
		}
		optind++;
	}

	if (argc - optind > 0) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
		if (!(mod_paths = apol_vector_create())) {
			ERR(policydb, "%s", strerror(ENOMEM));
			free(policy_file);
			exit(1);
		}
		for (; argc - optind; optind++) {
			if (apol_vector_append(mod_paths, (void *)argv[optind])) {
				ERR(policydb, "Error loading module %s", argv[optind]);
				free(policy_file);
				apol_vector_destroy(&mod_paths, NULL);
				exit(1);
			}
		}
	}

	pol_path = apol_policy_path_create(path_type, policy_file, mod_paths);
	if (!pol_path) {
		ERR(policydb, "%s", strerror(ENOMEM));
		free(policy_file);
		apol_vector_destroy(&mod_paths, NULL);
		exit(1);
	}
	apol_vector_destroy(&mod_paths, NULL);

	policydb = apol_policy_create_from_policy_path(pol_path, ((stats || all) ? 0 : APOL_POLICY_OPTION_NO_RULES), NULL, NULL);
	if (!policydb) {
		ERR(policydb, "%s", strerror(errno));
		free(policy_file);
		apol_policy_path_destroy(&pol_path);
		exit(1);
	}

	/* display requested info */
	if (stats || all)
		print_stats(stdout, policydb);
	if (classes || all)
		print_classes(stdout, class_name, expand, policydb);
	if (types || all)
		print_types(stdout, type_name, expand, policydb);
	if (attribs || all)
		print_attribs(stdout, attrib_name, expand, policydb);
	if (roles || all)
		print_roles(stdout, role_name, expand, policydb);
	if (users || all)
		print_users(stdout, user_name, expand, policydb);
	if (bools || all)
		print_booleans(stdout, bool_name, expand, policydb);
	if (sens || all)
		print_sens(stdout, sens_name, expand, policydb);
	if (cats || all)
		print_cats(stdout, cat_name, expand, policydb);
	if (fsuse || all)
		print_fsuse(stdout, fsuse_type, policydb);
	if (genfs || all)
		print_genfscon(stdout, genfs_type, policydb);
	if (netif || all)
		print_netifcon(stdout, netif_name, policydb);
	if (node || all)
		print_nodecon(stdout, node_addr, policydb);
	if (port || all)
		print_portcon(stdout, port_num, protocol, policydb);
	if (isids || all)
		print_isids(stdout, isid_name, expand, policydb);

	apol_policy_destroy(&policydb);
	apol_policy_path_destroy(&pol_path);
	free(policy_file);
	exit(0);
}

/**
 * Prints a textual representation of a type, and possibly
 * all of that type's attributes.
 *
 * @param fp Reference to a file to which to print type information
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * @param expand Flag indicating whether to print each type's
 * attributes
 */
static void print_type_attrs(FILE * fp, qpol_type_t * type_datum, apol_policy_t * policydb, const int expand)
{
	qpol_iterator_t *iter = NULL;
	unsigned char isattr, isalias;
	char *type_name = NULL, *attr_name = NULL;
	qpol_type_t *attr_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	if (qpol_type_get_name(q, type_datum, &type_name))
		goto cleanup;
	if (qpol_type_get_isattr(q, type_datum, &isattr))
		goto cleanup;
	if (qpol_type_get_isalias(q, type_datum, &isalias))
		goto cleanup;

	if (!isattr && !isalias) {
		fprintf(fp, "   %s\n", type_name);
		if (expand) {	       /* Print this type's attributes */
			if (qpol_type_get_attr_iter(q, type_datum, &iter))
				goto cleanup;
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&attr_datum))
					goto cleanup;
				if (qpol_type_get_name(q, attr_datum, &attr_name))
					goto cleanup;
				fprintf(fp, "      %s\n", attr_name);
			}
		}
	}

      cleanup:
	qpol_iterator_destroy(&iter);
	return;
}

/**
 * Prints a textual representation of an attribute, and possibly
 * all of that attribute's types.
 *
 * @param fp Reference to a file to which to print attribute information
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * @param expand Flag indicating whether to print each attribute's
 * types
 */
static void print_attr_types(FILE * fp, qpol_type_t * type_datum, apol_policy_t * policydb, const int expand)
{
	qpol_type_t *attr_datum = NULL;
	qpol_iterator_t *iter = NULL;
	char *attr_name = NULL, *type_name = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	unsigned char isattr;

	if (qpol_type_get_name(q, type_datum, &attr_name))
		goto cleanup;
	fprintf(fp, "   %s\n", attr_name);

	if (expand) {
		/* get an iterator over all types this attribute has */
		if (qpol_type_get_isattr(q, type_datum, &isattr))
			goto cleanup;
		if (isattr) {	       /* sanity check */
			if (qpol_type_get_type_iter(q, type_datum, &iter))
				goto cleanup;
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&attr_datum))
					goto cleanup;
				if (qpol_type_get_name(q, attr_datum, &type_name))
					goto cleanup;
				fprintf(fp, "      %s\n", type_name);
			}
			qpol_iterator_destroy(&iter);

		} else		       /* this should never happen */
			goto cleanup;

	}

      cleanup:
	qpol_iterator_destroy(&iter);
	return;
}

/**
 * Prints a textual representation of a user, and possibly
 * all of that user's roles.
 *
 * @param fp Reference to a file to which to print user information
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * @param expand Flag indicating whether to print each user's
 * roles
 */
static void print_user_roles(FILE * fp, qpol_user_t * user_datum, apol_policy_t * policydb, const int expand)
{
	qpol_role_t *role_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_mls_range_t *range = NULL;
	qpol_mls_level_t *dflt_level = NULL;
	apol_mls_level_t *ap_lvl = NULL;
	apol_mls_range_t *ap_range = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	char *tmp, *user_name, *role_name;

	if (qpol_user_get_name(q, user_datum, &user_name))
		goto cleanup;
	fprintf(fp, "   %s\n", user_name);

	if (expand) {
		if (qpol_policy_has_capability(q, QPOL_CAP_MLS)) {
			/* print default level */
			if (qpol_user_get_dfltlevel(q, user_datum, &dflt_level))
				goto cleanup;
			ap_lvl = apol_mls_level_create_from_qpol_mls_level(policydb, dflt_level);
			tmp = apol_mls_level_render(policydb, ap_lvl);
			if (!tmp)
				goto cleanup;
			fprintf(fp, "      default level: %s\n", tmp);
			free(tmp);
			/* print default range */
			if (qpol_user_get_range(q, user_datum, &range))
				goto cleanup;
			ap_range = apol_mls_range_create_from_qpol_mls_range(policydb, range);
			tmp = apol_mls_range_render(policydb, ap_range);
			if (!tmp)
				goto cleanup;
			fprintf(fp, "      range: %s\n", tmp);
			free(tmp);
		}

		fprintf(fp, "      roles:\n");
		if (qpol_user_get_role_iter(q, user_datum, &iter))
			goto cleanup;
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&role_datum))
				goto cleanup;
			if (qpol_role_get_name(q, role_datum, &role_name))
				goto cleanup;
			fprintf(fp, "         %s\n", role_name);
		}
	}

      cleanup:
	qpol_iterator_destroy(&iter);
	apol_mls_level_destroy(&ap_lvl);
	apol_mls_range_destroy(&ap_range);
	return;
}

/**
 * Prints a textual representation of a role, and possibly
 * all of that role's types.
 *
 * @param fp Reference to a file to which to print role information
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * @param expand Flag indicating whether to print each role's
 * types
 */
static void print_role_types(FILE * fp, qpol_role_t * role_datum, apol_policy_t * policydb, const int expand)
{
	char *role_name = NULL, *type_name = NULL;
	qpol_role_t *dom_datum = NULL;
	qpol_type_t *type_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_dom = 0, n_types = 0;

	if (qpol_role_get_name(q, role_datum, &role_name))
		goto cleanup;
	fprintf(fp, "   %s\n", role_name);

	if (expand) {
		if (qpol_role_get_dominate_iter(q, role_datum, &iter))
			goto cleanup;
		if (qpol_iterator_get_size(iter, &n_dom))
			goto cleanup;
		if ((int)n_dom > 0) {
			fprintf(fp, "      Dominated Roles:\n");
			/* print dominated roles */
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&dom_datum))
					goto cleanup;
				if (qpol_role_get_name(q, dom_datum, &role_name))
					goto cleanup;
				fprintf(fp, "         %s\n", role_name);
			}
		}
		qpol_iterator_destroy(&iter);

		if (qpol_role_get_type_iter(q, role_datum, &iter))
			goto cleanup;
		if (qpol_iterator_get_size(iter, &n_types))
			goto cleanup;
		if ((int)n_types > 0) {
			fprintf(fp, "      Types:\n");
			/* print types */
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&type_datum))
					goto cleanup;
				if (qpol_type_get_name(q, type_datum, &type_name))
					goto cleanup;
				fprintf(fp, "         %s\n", type_name);
			}
		}
	}

      cleanup:
	qpol_iterator_destroy(&iter);
	return;
}

/**
 * Prints a textual representation of a boolean value, and possibly
 * all of that boolean's initial state.
 *
 * @param fp Reference to a file to which to print boolean information
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * @param expand Flag indicating whether to print each boolean's
 * initial state
 */
static void print_bool_state(FILE * fp, qpol_bool_t * bool_datum, apol_policy_t * policydb, const int expand)
{
	char *bool_name = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	int state;

	if (qpol_bool_get_name(q, bool_datum, &bool_name))
		return;
	fprintf(fp, "   %s", bool_name);

	if (expand) {
		if (qpol_bool_get_state(q, bool_datum, &state))
			return;
		fprintf(fp, ": %s", state ? "TRUE" : "FALSE");
	}
	fprintf(fp, "\n");
}

/**
 * Prints a textual representation of an object class and possibly
 * all of that object class' permissions.
 *
 * @param fp Reference to a file to which to print object class information
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * @param expand Flag indicating whether to print each object class'
 * permissions
 */
static void print_class_perms(FILE * fp, qpol_class_t * class_datum, apol_policy_t * policydb, const int expand)
{
	char *class_name = NULL, *perm_name = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_common_t *common_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	if (!class_datum)
		goto cleanup;

	if (qpol_class_get_name(q, class_datum, &class_name))
		goto cleanup;
	fprintf(fp, "   %s\n", class_name);

	if (expand) {
		/* get commons for this class */
		if (qpol_class_get_common(q, class_datum, &common_datum))
			goto cleanup;
		if (common_datum) {
			if (qpol_common_get_perm_iter(q, common_datum, &iter))
				goto cleanup;
			/* print perms for the common */
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&perm_name))
					goto cleanup;
				fprintf(fp, "      %s\n", perm_name);
			}
			qpol_iterator_destroy(&iter);
		}
		/* print unique perms for this class */
		if (qpol_class_get_perm_iter(q, class_datum, &iter))
			goto cleanup;
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&perm_name))
				goto cleanup;
			fprintf(fp, "      %s\n", perm_name);
		}
		qpol_iterator_destroy(&iter);
	}

      cleanup:
	qpol_iterator_destroy(&iter);
	return;
}

/**
 * Prints a textual representation of a MLS category and possibly
 * all of that category's sensitivies.
 *
 * @param fp Reference to a file to which to print category information
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * @param expand Flag indicating whether to print each category's
 * sensitivities
 */
static void print_cat_sens(FILE * fp, qpol_cat_t * cat_datum, apol_policy_t * policydb, const int expand)
{
	char *cat_name, *lvl_name;
	apol_level_query_t *query = NULL;
	apol_vector_t *v = NULL;
	qpol_level_t *lvl_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t i, n_sens = 0;

	if (!fp || !cat_datum || !policydb)
		goto cleanup;

	/* get category name for apol query */
	if (qpol_cat_get_name(q, cat_datum, &cat_name))
		goto cleanup;

	query = apol_level_query_create();
	if (!query) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_level_query_set_cat(policydb, query, cat_name))
		goto cleanup;
	if (apol_level_get_by_query(policydb, query, &v))
		goto cleanup;
	fprintf(fp, "   %s\n", cat_name);

	if (expand) {
		fprintf(fp, "      Sensitivities:\n");
		apol_vector_sort(v, &qpol_level_datum_compare, (void *)policydb);
		n_sens = apol_vector_get_size(v);
		for (i = 0; i < n_sens; i++) {
			lvl_datum = (qpol_level_t *) apol_vector_get_element(v, i);
			if (!lvl_datum)
				goto cleanup;
			if (qpol_level_get_name(q, lvl_datum, &lvl_name))
				goto cleanup;
			fprintf(fp, "         %s\n", lvl_name);
		}
	}

      cleanup:
	apol_level_query_destroy(&query);
	apol_vector_destroy(&v, NULL);
	return;
}

/**
 * Compare two qpol_cat_datum_t objects.
 * This function is meant to be passed to apol_vector_compare
 * as the callback for performing comparisons.
 *
 * @param datum1 Reference to a qpol_type_datum_t object
 * @param datum2 Reference to a qpol_type_datum_t object
 * @param data Reference to a policy
 * @return Greater than 0 if the first argument is less than the second argument,
 * less than 0 if the first argument is greater than the second argument,
 * 0 if the arguments are equal
 */
static int qpol_cat_datum_compare(const void *datum1, const void *datum2, void *data)
{
	qpol_cat_t *cat_datum1 = NULL, *cat_datum2 = NULL;
	apol_policy_t *policydb = NULL;
	qpol_policy_t *q;
	uint32_t val1, val2;

	policydb = (apol_policy_t *) data;
	q = apol_policy_get_qpol(policydb);
	assert(policydb);

	if (!datum1 || !datum2)
		goto exit_err;
	cat_datum1 = (qpol_cat_t *) datum1;
	cat_datum2 = (qpol_cat_t *) datum2;

	if (qpol_cat_get_value(q, cat_datum1, &val1))
		goto exit_err;
	if (qpol_cat_get_value(q, cat_datum2, &val2))
		goto exit_err;

	return (val1 > val2) ? 1 : ((val1 == val2) ? 0 : -1);

      exit_err:
	assert(0);
	return 0;
}

/**
 * Compare two qpol_level_datum_t objects.
 * This function is meant to be passed to apol_vector_compare
 * as the callback for performing comparisons.
 *
 * @param datum1 Reference to a qpol_level_datum_t object
 * @param datum2 Reference to a qpol_level_datum_t object
 * @param data Reference to a policy
 * @return Greater than 0 if the first argument is less than the second argument,
 * less than 0 if the first argument is greater than the second argument,
 * 0 if the arguments are equal
 */
static int qpol_level_datum_compare(const void *datum1, const void *datum2, void *data)
{
	qpol_level_t *lvl_datum1 = NULL, *lvl_datum2 = NULL;
	apol_policy_t *policydb = NULL;
	qpol_policy_t *q;
	uint32_t val1, val2;

	policydb = (apol_policy_t *) data;
	assert(policydb);
	q = apol_policy_get_qpol(policydb);

	if (!datum1 || !datum2)
		goto exit_err;
	lvl_datum1 = (qpol_level_t *) datum1;
	lvl_datum2 = (qpol_level_t *) datum2;

	if (qpol_level_get_value(q, lvl_datum1, &val1))
		goto exit_err;
	if (qpol_level_get_value(q, lvl_datum2, &val2))
		goto exit_err;

	return (val1 > val2) ? 1 : ((val1 == val2) ? 0 : -1);

      exit_err:
	assert(0);
	return 0;
}
