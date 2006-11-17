/**
 * @file replcon.c
 *
 * A tool for replacing file contexts in SE Linux
 *
 * @author Jeremy Stitz <jstitz@tresys.com>
 * @author Kevin Carr <kcarr@tresys.com>
 * @author James Athey <jathey@tresys.com>
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

#include <config.h>

#include <sefs/fsdata.h>
#include <sefs/fshash.h>
/* SE Linux includes*/
#include <selinux/selinux.h>
#include <selinux/context.h>
/* standard library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
/* command line parsing commands */
#include <getopt.h>
/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>
#include <mntent.h>

#include <apol/policy.h>
#include <apol/util.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2006 Tresys Technology, LLC"

#define MAX_INPUT_SIZE 1024
#define NFTW_FLAGS FTW_MOUNT | FTW_PHYS
#define NFTW_DEPTH 1024

#define SEFS_BIND_HASH_SIZE 50

/* Data Structures */

typedef struct replcon_context
{
	char *user;
	char *role;
	char *type;
	char *mls;
} replcon_context_t;

typedef struct replcon_context_pair
{
	replcon_context_t old_context;
	replcon_context_t new_context;
} replcon_context_pair_t;

typedef struct replcon_info
{
	unsigned char use_raw;	       /* whether to use libselinux raw functions */
	unsigned char recursive;
	unsigned char verbose;
	unsigned char quiet;
	unsigned char stdin;
	unsigned char unlabeled;
	sefs_classes_t *obj_classes;
	int num_classes;
#ifndef FINDCON
	replcon_context_pair_t *pairs;
	int num_pairs;
#else
	replcon_context_t *contexts;
	int num_contexts;
#endif
	char **filenames;
	int num_filenames;
} replcon_info_t;

/* globals */
replcon_info_t replcon_info;
char **mounts;
unsigned int num_mounts;
sefs_hash_t *hashtab;

/* use weak bindings to allow runtime checking for raw fcns */
/* the raw functions allow access to the raw context not the context
   returned by the translation library */
extern int lgetfilecon_raw(const char *, security_context_t *)
	__attribute__ ((weak));
extern int lsetfilecon_raw(const char *, security_context_t)
	__attribute__ ((weak));

static struct option const longopts[] = {
	{"raw", no_argument, NULL, 'a'},
	{"recursive", no_argument, NULL, 'r'},
	{"object", required_argument, NULL, 'o'},
	{"context", required_argument, NULL, 'c'},
	{"stdin", no_argument, NULL, 's'},
	{"quiet", no_argument, NULL, 'q'},
	{"verbose", no_argument, NULL, 'V'},
	{"version", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static void sefs_double_array_print(char **array, int size)
{
	int i;
	for (i = 0; i < size; i++) {
		printf("%s\n", array[i]);
	}
}

/**
 * Frees the contents of the specified replcon_context_t
 *
 * @param context Reference to a replcon_context_t object
 */
void replcon_context_free(replcon_context_t * context)
{
	assert(context != NULL);
	if (context->user != NULL) {
		free(context->user);
		context->user = NULL;
	}

	if (context->role != NULL) {
		free(context->role);
		context->role = NULL;
	}

	if (context->type != NULL) {
		free(context->type);
		context->type = NULL;
	}
	if (context->mls != NULL) {
		free(context->mls);
		context->mls = NULL;
	}
}

/**
 * Destroys the specified replcon_context_t.
 *
 * @param context Reference to a replcon_context_t object
 */
void replcon_context_destroy(replcon_context_t * context)
{
	assert(context != NULL);
	replcon_context_free(context);
	free(context);
}

/**
 * Creates a new replcon_context_t object using the specified string
 * NOTE: Checks the string for the format "xxx:xxx:xxx[:xxx]".
 * Will create a 4 part context if mls is in use.
 * Use replcon_is_valid_context_format for more robust
 * context string validation.
 *
 * @param context Reference to a replcon_context_t object
 * @return a reference to a newly allocated replcon_context_t object
 * (caller must free) on success, NULL on error
 */
replcon_context_t *replcon_context_create(const char *ctx_str)
{
	replcon_context_t *context = NULL;
	char **parts = NULL;
	char *tokens = NULL;
	char *tokens_orig = NULL;
	const char *str = NULL;
	int i = 0, context_size = is_selinux_mls_enabled()? 4 : 3;
	int num_colon = 0;

	assert(ctx_str != NULL);
	str = ctx_str;

	while (str[i]) {
		if (str[i] == ':')
			num_colon++;
		i++;
	}

	if ((context = malloc(sizeof(replcon_context_t))) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	memset(context, 0, sizeof(replcon_context_t));

	if ((parts = malloc(context_size * sizeof(char *))) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	memset(parts, 0, sizeof(char *) * context_size);

	tokens_orig = tokens = strdup(ctx_str);
	if (tokens == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}

	i = 0;
	while (i < 3 && (parts[i] = strsep(&tokens, ":")) != NULL) {
		i++;
	}

	if (!parts[0]) {
		if ((context->user = strdup("")) == NULL) {
			fprintf(stderr, "Out of memory.\n");
			goto err;
		}
	} else if ((context->user = strdup(parts[0])) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	if (!parts[1]) {
		if ((context->role = strdup("")) == NULL) {
			fprintf(stderr, "Out of memory.\n");
			goto err;
		}
	} else if ((context->role = strdup(parts[1])) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}

	if (!parts[2]) {
		if ((context->type = strdup("")) == NULL) {
			fprintf(stderr, "Out of memory.\n");
			goto err;
		}
	} else if ((context->type = strdup(parts[2])) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}

	/* if selinux is enabled then tokens should point to whatever is left
	 * of the original string after the first 3 parts of the context */
	if (is_selinux_mls_enabled()) {
		if (tokens) {
			if ((context->mls = strdup(tokens)) == NULL) {
				fprintf(stderr, "Out of memory.\n");
				goto err;
			}
		} else {
			if ((context->mls = strdup("")) == NULL) {
				fprintf(stderr, "Out of memory.\n");
				goto err;
			}
		}
	}
	if (parts)
		free(parts);
	if (tokens_orig)
		free(tokens_orig);

	return context;

      err:
	if (parts)
		free(parts);
	if (tokens_orig)
		free(tokens_orig);
	replcon_context_destroy(context);
	fprintf(stderr, "Could not create file context from %s...\n", ctx_str);
	return NULL;
}

/**
 * Creates a new replcon_context_t object from a
 * security_context_t object.
 *
 * @param sec_con A security_context_t object
 * @return A reference to a newly allocated replcon_context_t object
 * (caller must free) on success, NULL on error
 */
replcon_context_t *replcon_context_create_from_security_context(const security_context_t sec_con)
{
	context_t ctxt;
	replcon_context_t *rcontext = NULL;
	const char *str = NULL;
	size_t sz = 0;

	assert(sec_con != NULL);

	rcontext = malloc(sizeof(replcon_context_t));
	if (!rcontext) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	memset(rcontext, 0, sizeof(replcon_context_t));

	ctxt = context_new(sec_con);
	if (!ctxt)
		goto err;

	sz = 0;
	str = context_user_get(ctxt);
	if (!str)
		goto err;
	apol_str_append(&(rcontext->user), &sz, str);

	str = NULL;
	sz = 0;
	str = context_role_get(ctxt);
	if (!str)
		goto err;
	apol_str_append(&(rcontext->role), &sz, str);

	str = NULL;
	sz = 0;
	str = context_type_get(ctxt);
	if (!str)
		goto err;
	apol_str_append(&(rcontext->type), &sz, str);

	if (is_selinux_mls_enabled()) {
		str = NULL;
		sz = 0;
		str = context_range_get(ctxt);
		if (!str) {
			rcontext->mls = strdup("");
			if (!rcontext->mls) {
				fprintf(stderr, "Out of memory.\n");
				goto err;
			}
		} else {
			apol_str_append(&(rcontext->mls), &sz, str);
		}

	} else {
		rcontext->mls = strdup("");
		if (!rcontext->mls) {
			fprintf(stderr, "Out of memory.\n");
			goto err;
		}
	}

	return rcontext;

      err:
	replcon_context_destroy(rcontext);
	fprintf(stderr, "Could not create file context from %s...\n", sec_con);
	return NULL;
}

/**
 * Sets the mls member of a replcon_context_t object using the specified argument.
 *
 * @param context A reference to a replcon_context_t object
 * @param mls A MLS level
 * @return 0 on success, < 0 on error
 */
int replcon_context_mls_set(replcon_context_t * context, const char *mls)
{
	assert(context != NULL);
	if (context->mls != NULL) {
		free(context->mls);
		context->mls = NULL;
	}

	if ((context->mls = strdup(mls)) == NULL)
		return -1;

	return 0;
}

/**
 * Sets the user member of a replcon_context_t object using the specified argument.
 *
 * @param context A reference to a replcon_context_t object
 * @param user A user
 * @return 0 on success, < 0 on error
 */
int replcon_context_user_set(replcon_context_t * context, const char *user)
{
	assert(context != NULL);
	if (context->user != NULL) {
		free(context->user);
		context->user = NULL;
	}

	if ((context->user = strdup(user)) == NULL)
		return -1;

	return 0;
}

/**
 * Sets the role member of a replcon_context_t object using the specified argument.
 *
 * @param context A reference to a replcon_context_t object
 * @param user A role
 * @return 0 on success, < 0 on error
 */
int replcon_context_role_set(replcon_context_t * context, const char *role)
{
	assert(context != NULL);
	if (context->role != NULL) {
		free(context->role);
		context->role = NULL;
	}

	if ((context->role = strdup(role)) == NULL)
		return -1;

	return 0;
}

/**
 * Sets the type member of a replcon_context_t object using the specified argument.
 *
 * @param context A reference to a replcon_context_t object
 * @param user A type
 * @return 0 on success, < 0 on error
 */
int replcon_context_type_set(replcon_context_t * context, const char *type)
{
	assert(context != NULL);
	if (context->type != NULL) {
		free(context->type);
		context->type = NULL;
	}
	if ((context->type = strdup(type)) == NULL)
		return -1;
	return 0;
}

/**
 * Assembles a security_context_t from the information in the replcon context.
 *
 * @param context A reference to a constant replcon_context_t object
 * @return A newly allocated security_context_t object (caller must free) on success,
 * NULL on error
 */
security_context_t get_security_context(const replcon_context_t * context)
{
	security_context_t sec_con;

	assert(context != NULL);

	if (is_selinux_mls_enabled()) {
		if ((sec_con = (security_context_t) calloc(1,
							   (strlen(context->user) +
							    strlen(context->role) +
							    strlen(context->type) + strlen(context->mls) + 4))) == NULL)
			return NULL;
	} else {
		if ((sec_con = (security_context_t) calloc(1,
							   (strlen(context->user) +
							    strlen(context->role) + strlen(context->type) + 3))) == NULL)
			return NULL;
	}

	strcpy(sec_con, (context->user));
	strcat(sec_con, ":");
	strcat(sec_con, (context->role));
	strcat(sec_con, ":");
	strcat(sec_con, (context->type));
	if (is_selinux_mls_enabled()) {
		strcat(sec_con, ":");
		strcat(sec_con, (context->mls));
	}
	return sec_con;
}

/**
 * Prints out usage instructions for the program. If brief is set to 1 (true) only the
 * syntax for program execution is displayed.
 *
 * @param program_name The name of the program for which to print usage information
 * @param brief Flag indicating whether to print all usage information
 */
void replcon_usage(const char *program_name, int brief)
{
	char **array = NULL;
	int size;
#ifndef FINDCON
	printf("%s (replcon ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
	printf("Usage: %s [OPTIONS] -c OLD NEW FILENAMES\n", program_name);
#else
	printf("%s (findcon ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
	printf("Usage: %s [OPTIONS] -c CONTEXT FILENAMES\n", program_name);
#endif
	if (brief) {
		printf("\nTry %s --help for more help.\n\n", program_name);
		return;
	}
#ifndef FINDCON
	printf("\nFile context replacement tool for Security Enhanced Linux.\n");
	printf("  -c,  --context=OLD NEW  Specify context to replace, see below.\n");
	printf("  -o,  --object=OBJECT    Only replace context for the specified object class.\n");
#else
	printf("\nFile context search tool for Security Enhanced Linux.\n");
	printf("  -c,  --context=CONTEXT  Specify context to search for, see below.\n");
	printf("  -o,  --object=OBJECT    Restrict search to the specified object class.\n");
#endif
	printf("  --raw                   Use raw contexts.\n");
	printf("  -r,  --recursive        Recurse through directories.\n");
	printf("  -s,  --stdin            Read FILENAMES from standard input.\n");
	printf("  -q,  --quiet            Suppress progress output.\n");
	printf("  -V,  --verbose          Display context info.\n");
	printf("  -v,  --version          Display version information and exit.\n");
	printf("  -h,  --help             Display this help and exit.\n");
	printf("\n");
	if (is_selinux_mls_enabled()) {
		printf("A context may be specified as a colon separated list of user, role, type, and\n");
		printf("mls security range as follows - user_u:object_r:user_t:s0.  A single colon can\n");
		printf("be used to match any context, so to find all contexts you only need to type : .\n");
		printf("The tool will automatically match a user, role, type, or range that is not \n");
		printf("specified, with any other user, role, type, or range.  The normal matching is \n");
		printf("done using the translation library if it is enabled.  If you want the tool to \n");
		printf("match raw contexts please use --raw.\n");
	} else {
		printf("A context may be specified as a colon separated list of user, role, and type\n");
		printf("as follows - user_u:object_r:user_t. A single colon can be used to match any \n");
		printf("context, so to find all contexts you only need to type : .  The tool will \n");
		printf("automatically match a user, role, or type that is not specified, with any other\n");
		printf("user, role, or type.\n");
	}
#ifdef FINDCON
	if (is_selinux_mls_enabled()) {
		printf("Search examples:\n");
		printf("    findcon -c : .\n");
		printf("        Find every context in the current directory\n");
		printf("    findcon -c user_u: .\n");
		printf("        Find every context that contains user_u in the current directory\n");
		printf("    findcon -c :::s0 .\n");
		printf("        Find every context that contains MLS range s0 in the current directory\n");
	} else {
		printf("Search examples:\n");
		printf("    findcon -c : .\n");
		printf("        Find every context in the current directory\n");
		printf("    findcon -c :role_r .\n");
		printf("        Find every context that contains role_r in the current directory\n");
		printf("    findcon -c user_u: .\n");
		printf("        Find every context that contains user_u in the current directory\n");
	}
#else
	if (is_selinux_mls_enabled()) {
		printf("Replacement examples:\n");
		printf("    replcon -c : ::type_t .\n");
		printf("        Replace every context in the current directory with type type_t\n");
		printf("    replcon -c user_u: :role_r .\n");
		printf("        Replace every context that contains user_u in the current directory \n");
		printf("        with role role_r\n");
		printf("    replcon -c ::type_t:s0 :::s0:c0\n");
		printf("        Replace every context that contains type type_t and MLS range s0 in the\n");
		printf("        current directory with MLS range s0:c0\n");
	} else {
		printf("Replacement examples:\n");
		printf("    replcon -c : ::type_t .\n");
		printf("        Replace every context in the current directory with type type_t\n");
		printf("    replcon -c user_u: :role_r .\n");
		printf("        Replace every context that contains user_u in the current directory with\n");
		printf("        role role_r\n");
		printf("    replcon -c :role_r :newrole_r .\n");
		printf("        Replace every context that contains role_r in the current directory with\n");
		printf("        newrole_r\n");
	}
#endif
	printf("\nThe special string 'unlabeled' can be provided to the -c option in order\n");
	printf("to find or replace files that have no label.\n\n");
	printf("Valid OBJECT classes to specify include: \n");
	array = sefs_get_valid_object_classes(&size);
	sefs_double_array_print(array, size);
	sefs_double_array_destroy(array, size);

	printf("\n");
}

/**
 * Sets the data members of info to initial values.
 *
 * @param into A reference to a replcon info object
 */
void replcon_info_init(replcon_info_t * info)
{
	assert(info != NULL);
	info->use_raw = 0;
	info->recursive = 0;
	info->quiet = 0;
	info->verbose = 0;
	info->stdin = 0;
	info->unlabeled = 0;
	info->obj_classes = NULL;
#ifndef FINDCON
	info->pairs = NULL;
	info->num_pairs = 0;
#else
	info->contexts = NULL;
	info->num_contexts = 0;
#endif
	info->filenames = NULL;
	info->num_classes = 0;
	info->num_filenames = 0;
}

/**
 * Frees all the allocated memory in info.
 *
 * @param info A reference to a replcon info object
 */
void replcon_info_free(replcon_info_t * info)
{
	int i;

	assert(info != NULL);
	/* Free Object Classes */
	if (info->obj_classes) {
		free(info->obj_classes);
		info->obj_classes = NULL;
	}
#ifndef FINDCON
	/* Free context pairs */
	if (info->pairs) {
		for (i = 0; i < (info->num_pairs); i++) {
			replcon_context_free(&info->pairs[i].old_context);
			replcon_context_free(&info->pairs[i].new_context);
		}
		free(info->pairs);
		info->pairs = NULL;
	}
#else
	/* Free contexts */
	if (info->contexts) {
		for (i = 0; i < (info->num_contexts); i++)
			replcon_context_free(&info->contexts[i]);
		free(info->contexts);
		info->contexts = NULL;
	}
#endif
	/* Free Locations */
	if (info->filenames) {
		for (i = 0; i < info->num_filenames; i++) {
			if (info->filenames[i]) {
				free(info->filenames[i]);
				info->filenames[i] = NULL;
			}
		}
		free(info->filenames);
	}
}

/**
 * Frees all the allocated memory in info.
 *
 * @param info A reference to a replcon info object
 * @param obj_class
 * @return TRUE on success, FALSE on error
 */
int replcon_info_has_object_class(replcon_info_t * info, sefs_classes_t obj_class)
{
	int i;

	assert(info != NULL);
	for (i = 0; i < info->num_classes; i++)
		if (info->obj_classes[i] == obj_class || replcon_info.obj_classes[i] == SEFS_ALL_FILES)
			return TRUE;
	return FALSE;
}

/**
 * Determines if context is a valid file context format.
 *
 * @param ctx_str A string containing a security context
 * @return TRUE if security context string is valid,
 * FALSE if the string is invalid
 */
int replcon_is_valid_context_format(const char *ctx_str)
{
	int i, len, count = 0;

	assert(ctx_str != NULL);
	if (!strcasecmp("unlabeled", ctx_str))
		return TRUE;

	len = strlen(ctx_str);

	for (i = 0; i < len; i++) {
		if (ctx_str[i] == ':')
			count++;
	}

	if (is_selinux_mls_enabled()) {
		if (count > 5)
			return FALSE;
	} else {
		if (count > 2)
			return FALSE;
	}
	return TRUE;
}

/**
 * Adds class_id to the array of object types stored in replcon_info that
 * will have their context changed upon program execution.
 *
 * @param info A reference to a replcon info object
 * @param str A string containing an object class
 * @param allow_all_files If non-zero, then str may be 'all_files'.
 * @return 0 on success, < 0 on error
 */
int replcon_info_add_object_class(replcon_info_t * info, const char *str, const int allow_all_files)
{
	sefs_classes_t class_id;

	assert(info != NULL);
	class_id = sefs_is_valid_object_class(str);
	switch (class_id) {
	case -1:
		break;
	case 0:
		class_id = SEFS_NORM_FILE;
		break;
	case 1:
		class_id = SEFS_DIR;
		break;
	case 2:
		class_id = SEFS_LNK_FILE;
		break;
	case 3:
		class_id = SEFS_CHR_FILE;
		break;
	case 4:
		class_id = SEFS_BLK_FILE;
		break;
	case 5:
		class_id = SEFS_SOCK_FILE;
		break;
	case 6:
		class_id = SEFS_FIFO_FILE;
		break;
	default:
		class_id = SEFS_ALL_FILES;
		break;
	}

	/* Check the object class */
	if (class_id == -1 || (class_id == SEFS_ALL_FILES && !allow_all_files)) {
		fprintf(stderr, "Error: invalid object class \'%s\'\n", optarg);
		return -1;
	}

	info->obj_classes = (sefs_classes_t *) realloc(info->obj_classes, sizeof(sefs_classes_t) * (info->num_classes + 1));
	if (!info->obj_classes) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}

	info->obj_classes[info->num_classes] = class_id;
	info->num_classes++;

	return 0;
}

#ifndef FINDCON
/**
 * Adds the context pair, old and new, to the array of context pairs
 * stored in replcon_info that will be changed upon program execution.
 *
 * @param info A reference to a replcon info object
 * @param old A string representing a security context
 * @param new A string representing a security context
 * @return 0 on success, < 0 on error
 */
int replcon_info_add_context_pair(replcon_info_t * info, const char *old, const char *new)
{
	replcon_context_t *context = NULL;

	assert(info != NULL);
	/* Check the context pairs for format before we do any memory mgmt */
	if (!replcon_is_valid_context_format(old)) {
		fprintf(stderr, "Error: \'%s\' is not a valid context format.\n", old);
		goto err;
	}

	if (!replcon_is_valid_context_format(new)) {
		fprintf(stderr, "Error: \'%s\' is not a valid context format.\n", new);
		goto err;
	}

	info->pairs = (replcon_context_pair_t *) realloc(info->pairs, sizeof(replcon_context_pair_t) * (info->num_pairs + 1));
	if (!info->pairs) {
		fprintf(stderr, "Error: Out of memory\n");
		goto err;
	}

	if (!strcasecmp("unlabeled", old)) {
		if (is_selinux_mls_enabled())
			context = replcon_context_create("!:!:!:!");
		else
			context = replcon_context_create("!:!:!");
	} else
		context = replcon_context_create(old);
	if (context != NULL)
		info->pairs[info->num_pairs].old_context = (*context);
	else {
		fprintf(stderr, "Error: unable to add context \'%s\'.\n", old);
		goto err;
	}

	/* we use free here, because calling replcon_context_destroy would
	 * blow away the strings we just saved in info->pairs */
	free(context);
	if ((context = replcon_context_create(new)) != NULL)
		info->pairs[info->num_pairs].new_context = (*context);
	else {
		fprintf(stderr, "Error: unable to add context \'%s\'.\n", new);
		goto err;
	}

	info->num_pairs++;
	/* we use free here, because calling replcon_context_destroy would
	 * blow away the strings we just saved in info->pairs */
	free(context);
	return 0;

      err:
	if (context)
		free(context);
	return -1;

}
#else
/**
 * Adds the context to the array of contexts stored in replcon_info
 * that will be sought upon program execution.
 *
 * @param info A reference to a replcon info object
 * @param old A constant string representing a security context
 * @return 0 on success, < 0 on error
 */
int replcon_info_add_context(replcon_info_t * info, const char *con)
{
	replcon_context_t *context = NULL;

	assert(info != NULL);
	/* Check the context for format before we do any memory mgmt */
	if (!replcon_is_valid_context_format(con)) {
		fprintf(stderr, "Error: \'%s\' is not a valid context format.\n", con);
		goto err;
	}

	if (!strcasecmp("unlabeled", con)) {
		if (is_selinux_mls_enabled())
			context = replcon_context_create("!:!:!:!");
		else
			context = replcon_context_create("!:!:!");
	} else
		context = replcon_context_create(con);
	if (context) {
		info->contexts =
			(replcon_context_t *) realloc(info->contexts, sizeof(replcon_context_t) * (info->num_contexts + 1));
		if (info->contexts == NULL) {
			fprintf(stderr, "Error: Out of memory.\n");
			goto err;
		}
		info->contexts[info->num_contexts] = (*context);
		info->num_contexts++;
	} else {
		fprintf(stderr, "Error: unable to add context \'%s\'.\n", con);
		goto err;
	}

	/* we use free here, because destroy would blow away the
	 * strings we just saved in info->contexts */
	free(context);
	return 0;

      err:
	if (context)
		free(context);
	return -1;
}
#endif

/**
 * Adds file to the array of file/directory locations stored in replcon_info that will
 * that will have contexts replaced.
 *
 * @param info A reference to a replcon info object
 * @param old A constant string representing a filename
 * @return 0 on success, < 0 on error
 */
int replcon_info_add_filename(replcon_info_t * info, const char *file)
{
	assert(info != NULL);

	info->filenames = realloc(info->filenames, sizeof(char *) * (info->num_filenames + 1));
	if (!info->filenames)
		goto err;
	if ((info->filenames[info->num_filenames] = strdup(file)) == NULL)
		goto err;
	info->num_filenames++;
	return 0;

      err:
	fprintf(stderr, "Error: Out of memory\n");
	return -1;

}

/**
 * Determines whether the patterns match the fields in
 * context.
 * If any context field is empty, that field automatically matches.
 * Example - ::user_t == x_u:y_r:user_t,
 * Example - x_u:y_r:user_t != user_u:y_r:user_t
 *
 * @param context A reference to a replcon context object
 * @param patterns A reference to a replcon context object,
 * whose contents will be used for pattern matching against context
 * @return TRUE on success, FALSE on error
 */
unsigned char replcon_context_equal(const replcon_context_t * context, const replcon_context_t * patterns)
{
	unsigned char user_match, role_match, type_match, mls_match;

	assert((context != NULL) && (patterns != NULL));
	user_match =
		((fnmatch(patterns->user, context->user, 0) == 0) ||
		 (strcmp(context->user, "") == 0) || (strcmp(patterns->user, "") == 0));
	role_match =
		((fnmatch(patterns->role, context->role, 0) == 0) ||
		 (strcmp(context->role, "") == 0) || (strcmp(patterns->role, "") == 0));
	type_match =
		((fnmatch(patterns->type, context->type, 0) == 0) ||
		 (strcmp(context->type, "") == 0) || (strcmp(patterns->type, "") == 0));
	/* set mls_match to return true, if we have mls and no match
	 * it will be set to FNM_NOMATCH
	 * If pattern->mls is "" then we just match everything
	 * If pattern->mls and context->mls match return true
	 */
	mls_match = 1;
	if (is_selinux_mls_enabled()) {
		mls_match = ((strcmp(patterns->mls, "") == 0) || (fnmatch(patterns->mls, context->mls, 0) == 0)
			);
	}
	return (user_match && role_match && type_match && mls_match);

}

#ifndef FINDCON
/**
 * Change the context of the file, as long as it meets the specifications
 * in replcon_info.
 * The caller must pass a valid filename and statptr.
 * If the caller wants to use raw, the passed in context will try to match
 * the raw context of the file not the translated context returned by libsetrans
 * This function can be used as a callback for ftw(3).
 *
 * @param filename A string containing a filename
 * @param stat64 A reference to a constant stat structure
 * @param fileflags This parameter is currently not used, but is
 * needed to maintain this function's compatibility as a callback for
 * ftw(3).
 * @param pfwt This parameter is currently not used, but is
 * needed to maintain this function's compatibility as a callback for
 * ftw(3).
 * @return 0 on success, < 0 on error
 */
int replcon_file_context_replace(const char *filename, const struct stat64 *statptr, int fileflags, struct FTW *pfwt)
{
	int file_class, i, ret;
	unsigned char match = FALSE;
	replcon_context_t *replacement_con = NULL, *original_con = NULL, *new_con = NULL;
	security_context_t old_file_con, new_file_con = NULL;
	replcon_info_t *info = NULL;

	assert(filename != NULL && statptr != NULL);
	info = &replcon_info;
	file_class = sefs_get_file_class(statptr);
	if (!replcon_info_has_object_class(info, file_class))
		return 0;
	if (lgetfilecon_raw && replcon_info.use_raw)
		ret = lgetfilecon_raw(filename, &old_file_con);
	else
		ret = lgetfilecon(filename, &old_file_con);
	if (ret <= 0) {
		if (errno == ENODATA) {
			if (is_selinux_mls_enabled()) {
				if ((old_file_con = strdup("!:!:!:!")) == NULL)
					goto err;
			} else {
				if ((old_file_con = strdup("!:!:!")) == NULL)
					goto err;
			}
		} else {
			fprintf(stderr, "Unable to get file context for %s, skipping...\n", filename);
			return 0;
		}
	}
	if ((original_con = replcon_context_create_from_security_context(old_file_con)) == NULL)
		goto err;

	if (is_selinux_mls_enabled()) {
		if ((replacement_con = replcon_context_create(":::")) == NULL)
			goto err;
	} else {
		if ((replacement_con = replcon_context_create("::")) == NULL)
			goto err;
	}

	for (i = 0; i < info->num_pairs; i++) {
		if (replcon_context_equal(original_con, &(info->pairs[i].old_context))) {
			match = TRUE;
			new_con = &(info->pairs[i].new_context);
			if (strcmp(new_con->user, "") != 0)
				replcon_context_user_set(replacement_con, new_con->user);
			if (strcmp(new_con->role, "") != 0)
				replcon_context_role_set(replacement_con, new_con->role);
			if (strcmp(new_con->type, "") != 0)
				replcon_context_type_set(replacement_con, new_con->type);
			if (is_selinux_mls_enabled()) {
				if (strcmp(new_con->mls, "") != 0)
					replcon_context_mls_set(replacement_con, new_con->mls);
			}
		}
	}

	if (match) {
		/* check to see if this is a bind mount */
		if (sefs_hash_find(hashtab, filename) == 1) {
			if (!info->quiet)
				fprintf(stdout, "Did not replace context for bind mount: %-40s\n", filename);
			goto exit;
		}
		/* If the new context was not spcified completely, fill in the blanks */
		if (strcmp(replacement_con->user, "") == 0)
			replcon_context_user_set(replacement_con, original_con->user);
		if (strcmp(replacement_con->role, "") == 0)
			replcon_context_role_set(replacement_con, original_con->role);
		if (strcmp(replacement_con->type, "") == 0)
			replcon_context_type_set(replacement_con, original_con->type);
		if (is_selinux_mls_enabled()) {
			if (strcmp(replacement_con->mls, "") == 0)
				replcon_context_mls_set(replacement_con, original_con->mls);
		}
		new_file_con = get_security_context(replacement_con);
		if (new_file_con == NULL) {
			fprintf(stderr, "Unable to create new file security context.");
			goto err;
		}
		if (lsetfilecon_raw && replcon_info.use_raw)
			ret = lsetfilecon_raw(filename, new_file_con);
		else
			ret = lsetfilecon(filename, new_file_con);
		if (ret != 0) {
			fprintf(stderr, "Error setting context %s for file %s:\n", new_file_con, filename);
			perror("  lsetfilecon");
			goto err;
		}
		if (!info->quiet) {
			if (info->verbose)
				fprintf(stdout,
					"Replaced context: %-40s\told context: [%s]\tnew context: [%s]\n",
					filename, old_file_con, new_file_con);
			else
				fprintf(stdout, "Replaced context: %-40s\n", filename);
		}
		freecon(new_file_con);
	}

      exit:
	replcon_context_destroy(original_con);
	replcon_context_destroy(replacement_con);
	freecon(old_file_con);
	return 0;

      err:
	if (original_con)
		replcon_context_destroy(original_con);
	if (replacement_con)
		replcon_context_destroy(replacement_con);
	if (old_file_con)
		freecon(old_file_con);
	if (new_file_con)
		freecon(new_file_con);
	return -1;

}

#else
/**
 * The caller must pass a valid filename and statptr.
 * If the caller wants to use raw, the passed in context will try to match
 * the raw context of the file not the translated context returned by libsetrans.
 * This function can be used as a callback for ftw(3).
 *
 * @param filename A constant string containing a filename
 * @param stat64 A reference to a constant stat struct
 * @param fileflags This parameter is currently not used, but is
 * needed to maintain this function's compatibility as a callback for
 * ftw(3).
 * @param pfwt This parameter is currently not used, but is
 * needed to maintain this function's compatibility as a callback for
 * ftw(3).
 * @return 0 on success, < 0 on error
 */
int findcon(const char *filename, const struct stat64 *statptr, int fileflags, struct FTW *pfwt)
{
	int file_class, i, ret;
	replcon_context_t *original_con = NULL;
	security_context_t file_con;

	assert(filename != NULL && statptr != NULL);
	file_class = sefs_get_file_class(statptr);
	if (!replcon_info_has_object_class(&replcon_info, file_class))
		return 0;

	if (lgetfilecon_raw && replcon_info.use_raw)
		ret = lgetfilecon_raw(filename, &file_con);
	else
		ret = lgetfilecon(filename, &file_con);

	if (ret <= 0) {
		if (errno == ENODATA) {
			if (is_selinux_mls_enabled()) {
				if ((file_con = strdup("!:!:!:!")) == NULL)
					goto err;
			} else {
				if ((file_con = strdup("!:!:!")) == NULL)
					goto err;
			}
		} else {
			fprintf(stderr, "Unable to get file context for %s\n, skipping...", filename);
			return 0;
		}
	}

	if ((original_con = replcon_context_create_from_security_context(file_con)) == NULL)
		goto err;

	for (i = 0; i < replcon_info.num_contexts; i++) {
		if (replcon_context_equal(original_con, &(replcon_info.contexts[i]))) {
			if (replcon_info.verbose)
				fprintf(stdout, "%s\t%s\n", filename, file_con);
			else
				fprintf(stdout, "%s\n", filename);
		}
	}

	replcon_context_destroy(original_con);
	freecon(file_con);
	return 0;

      err:
	if (original_con)
		replcon_context_destroy(original_con);
	if (file_con)
		freecon(file_con);
	return -1;

}
#endif

/**
 * Replaces file contexts of files which match filename.
 *
 * @param filename A string containing a filename
 */
void replcon_stat_file_replace_context(const char *filename)
{
	struct stat64 file_status;
	/* Use path length limit defined in limits.h */
	char actual_path[PATH_MAX + 1];
	char *ptr = NULL;
	int i;

	assert(filename != NULL);
	if (stat64(filename, &file_status) != 0) {
		fprintf(stderr, "Warning: Can not stat \'%s\'.  Skipping this file.\n", filename);
		return;
	}

	if (replcon_info.recursive) {
		if ((ptr = realpath(filename, actual_path)) == NULL) {
			perror("replcon_stat_file_replace_context");
			return;
		}
#ifndef FINDCON
		if (nftw64(actual_path, replcon_file_context_replace, NFTW_DEPTH, NFTW_FLAGS)) {
			fprintf(stderr, "Error walking directory tree: %s\n", actual_path);
			return;
		}
#else
		if (nftw64(actual_path, findcon, NFTW_DEPTH, NFTW_FLAGS)) {
			fprintf(stderr, "Error walking directory tree: %s\n", actual_path);
			return;
		}
#endif
		for (i = 0; i < num_mounts; i++) {
			if (strstr(mounts[i], actual_path) == mounts[i])
#ifndef FINDCON
				if (nftw64(mounts[i], replcon_file_context_replace, NFTW_DEPTH, NFTW_FLAGS)) {
					fprintf(stderr, "Error walking directory tree: %s\n", mounts[i]);
					return;
				}
#else
				if (nftw64(mounts[i], findcon, NFTW_DEPTH, NFTW_FLAGS)) {
					fprintf(stderr, "Error walking directory tree: %s\n", mounts[i]);
					return;
				}
#endif
		}
	} else {
#ifndef FINDCON
		replcon_file_context_replace(filename, &file_status, 0, NULL);
#else
		findcon(filename, &file_status, 0, NULL);
#endif
	}
}

/**
 * Removes the newline character from stdin stream input strings.
 *
 * @param filename A string whose newline character should be removed
 */
void remove_new_line_char(char *input)
{
	int i, len;

	assert(input != NULL);
	len = strlen(input);
	for (i = 0; i < len; i++) {
		if (input[i] == '\n')
			input[i] = '\0';
	}
}

/**
 * Function for parsing command line arguments.
 *
 * @param argc Value representing argc as passed to main
 * @param argv Array of arguments as passed to main
 */
void replcon_parse_command_line(int argc, char **argv)
{
	int optc, i;

	/* get option arguments */
	while ((optc = getopt_long(argc, argv, "o:c:rsVqvh", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 'o':
			if (replcon_info_add_object_class(&replcon_info, optarg, 0)) {
				fprintf(stderr, "Unable to add object class.\n");
				goto err;
			}
			break;
		case 'c':
#ifndef FINDCON
			if (optind < argc) {
				/* Two arguments required! */
				if (replcon_info_add_context_pair(&replcon_info, optarg, argv[optind++])) {
					fprintf(stderr, "Unable to add context pair.\n");
					goto err;
				}
			} else {
				fprintf(stderr, "Contexts must be specified in pairs.\n");
				goto err;
			}
#else
			if (replcon_info_add_context(&replcon_info, optarg)) {
				fprintf(stderr, "Unable to add file context.\n");
				goto err;
			}
#endif
			break;
		case 'a':
			replcon_info.use_raw = TRUE;
			break;
		case 'r':	       /* recursive directory parsing */
			replcon_info.recursive = TRUE;
			break;
		case 's':	       /* read from standard in */
			replcon_info.stdin = TRUE;
			break;
		case 'q':
			if (replcon_info.verbose) {
				fprintf(stderr, "Error: Can not specify -q and -V\n");
				goto err;
			}
			replcon_info.quiet = TRUE;
			break;
		case 'V':	       /* verbose program execution */
			if (replcon_info.quiet) {
				fprintf(stderr, "Error: Can not specify -q and -V\n");
				goto err;
			}
			replcon_info.verbose = TRUE;
			break;
		case 'v':	       /* version */
#ifndef FINDCON
			printf("\n%s (replcon ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
#else
			printf("\n%s (findcon ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
#endif

			replcon_info_free(&replcon_info);
			exit(0);
		case 'h':	       /* help */
			replcon_usage(argv[0], 0);
			replcon_info_free(&replcon_info);
			exit(0);
		default:	       /* usage */
			goto err;
		}
	}
	/* If no object class was specified revert to the default of all files */
	if (replcon_info.num_classes == 0) {
		if (replcon_info_add_object_class(&replcon_info, "all_files", 1)) {
			fprintf(stderr, "Unable to add default object class.\n");
			goto err;
		}
	}

	/* Make sure required arguments were supplied */
#ifndef FINDCON
	if ((replcon_info.num_pairs == 0)
#else
	if ((replcon_info.num_contexts == 0)
#endif
	    || (((!replcon_info.stdin) && (argc == optind)))) {
		goto err;
	}

	/* Ensure that locations were not specified in addition to the standard in option */
	if ((replcon_info.num_filenames > 0) && replcon_info.stdin) {
		fprintf(stderr, "Warning: Command line filename(s) will be ignored. Reading from stdin.\n");
	} else {
		/* Add required filenames */
		for (i = (argc - 1); i >= optind; i--) {
			if (replcon_info_add_filename(&replcon_info, argv[i])) {
				fprintf(stderr, "Unable to add file or directory.\n");
				goto err;
			}
		}
	}
	return;

      err:
	replcon_usage(argv[0], 1);
	replcon_info_free(&replcon_info);
	exit(-1);
}

int main(int argc, char **argv)
{
	char stream_input[MAX_INPUT_SIZE];
	int i, rw;

	replcon_info_init(&replcon_info);
	replcon_parse_command_line(argc, argv);
	num_mounts = 0;

#ifndef FINDCON
	rw = 0;
#else
	rw = 1;
#endif
	/* initialize the hash used for bind mounts */
	hashtab = sefs_hash_new(SEFS_BIND_HASH_SIZE);
	if (!hashtab)
		goto err;
	if (sefs_filesystem_find_mount_points("/", rw, hashtab, &mounts, &num_mounts)) {
		fprintf(stderr, "Could not enumerate mountpoints.\n");
		goto err;
	}
	/* check to see if we are using raw and user did not ask */
	if (replcon_info.use_raw == FALSE && lgetfilecon_raw == NULL) {
		printf("Note: System only contains raw contexts\n");
	}

	if (replcon_info.stdin) {
		while (fgets(stream_input, (MAX_INPUT_SIZE - 1), stdin)) {
			remove_new_line_char(stream_input);
			replcon_stat_file_replace_context(stream_input);
		}
	} else {
		for (i = (replcon_info.num_filenames - 1); i >= 0; i--)
			replcon_stat_file_replace_context(replcon_info.filenames[i]);
	}
	replcon_info_free(&replcon_info);
	for (i = 0; i < num_mounts; i++)
		free(mounts[i]);
	free(mounts);
	sefs_hash_destroy(hashtab);
	return 0;

      err:
	replcon_info_free(&replcon_info);
	if (mounts)
		free(mounts);
	sefs_hash_destroy(hashtab);
	return -1;
}
