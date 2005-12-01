/*
 *  Copyright (C) 2003-2005 Tresys Technology, LLC
 *  see file 'COPYING' for use and warranty information
 *
 */

/*
 *  Authors: Jeremy Stitz <jstitz@tresys.com>
 *           Kevin Carr <kcarr@tresys.com>
 *           James Athey <jathey@tresys.com>
 *
 *  replcon: a tool for replacing file contexts in SE Linux
 */

#include <fsdata.h>
#include "fshash.h"
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
#define _GNU_SOURCE
#include <getopt.h>
/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>
#include <mntent.h>

#include <policy.h>



/* REPLCON_VERSION_NUM should be defined in the make environment */
#ifndef REPLCON_VERSION_NUM
#define REPLCON_VERSION_NUM "UNKNOWN"
#endif

/* FINDCON_VERSION_NUM should be defined in the make environment */
#ifndef FINDCON_VERSION_NUM
#define FINDCON_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2003-2005 Tresys Technology, LLC"

#ifndef DEBUG
#define DEBUG 0
#endif
#define MAX_INPUT_SIZE 1024
#define NFTW_FLAGS FTW_MOUNT | FTW_PHYS
#define NFTW_DEPTH 1024

#define SEFS_BIND_HASH_SIZE 50

/* Data Structures */

typedef struct replcon_context {
	char *user;
	char *role;
	char *type;
} replcon_context_t;

typedef struct replcon_context_pair {
	replcon_context_t old_context;
	replcon_context_t new_context;
} replcon_context_pair_t;

typedef struct replcon_info {
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

static struct option const longopts[] = {
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


static void sefs_double_array_print(char **array,int size)
{
	int i;
	for (i=0;i<size;i++){
		printf("%s\n",array[i]);
	}
}

/*
 * replcon_context_free
 *
 * Frees the contents of the specified replcon_context_t
 */
void
replcon_context_free(replcon_context_t *context)
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
}

/*
 * replcon_context_destroy
 *
 * Destroys the specified replcon_context_t
 */
void
replcon_context_destroy(replcon_context_t * context)
{
	assert(context != NULL);
	replcon_context_free(context);
	free(context);
}

/*
 * replcon_context_create
 *
 * Creates a new replcon_context_t object using the specified string
 *
 * NOTE: Only checks the string for the format "xxx:xxx:xxx".
 *       Use replcon_is_valid_context_format for more robust
 *	 constext string validation.
 */
replcon_context_t *
replcon_context_create(const char *context_str)
{
	replcon_context_t *context = NULL;
	char **parts = NULL;
	char *tokens = NULL, *tokens_orig = NULL;
	int i = 0;

	assert(context_str != NULL);
	if ((context = malloc(sizeof (replcon_context_t))) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	if ((parts = malloc(3 * sizeof(char*))) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}

	if ((tokens_orig = tokens = strdup(context_str)) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	
        while (i < 3) {
        	if ((parts[i] = strsep(&tokens, ":")) == NULL) {
        		fprintf(stderr, "Invalid context format.\n");
			goto err;
		}
       	       	i++;
        }
        
	if ((context->user = strdup(parts[0])) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	if ((context->role = strdup(parts[1])) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	if ((context->type = strdup(parts[2])) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		goto err;
	}
	
	free(tokens_orig);
	free(parts);

	return context;

	err:
	  if (tokens_orig) free (tokens_orig);
	  if (parts) free (parts);
	  replcon_context_destroy(context);
	  fprintf(stderr, "Could not create file context from %s...\n", context_str);
	  return NULL;
}

/*
 * replcon_context_user_set
 *
 * Sets the user member of a replcon_context_t object using the specified argument
 */
int replcon_context_user_set(replcon_context_t *context, const char *user)
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

/*
 * replcon_context_role_set
 *
 * Sets the role member of a replcon_context_t object using the specified argument
 */
int replcon_context_role_set(replcon_context_t *context, const char *role)
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

/*
 * replcon_context_type_set
 *
 * Sets the type member of a replcon_context_t object using the specified argument
 */
int replcon_context_type_set(replcon_context_t *context, const char *type)
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

/*
 * get_security_context
 *
 * Assembles a security_context_t from the information in the replcon context
 */
security_context_t
get_security_context(const replcon_context_t *context)
{
	security_context_t sec_con;
	
	assert(context != NULL);
	if ((sec_con = malloc(strlen(context->user) +
			      strlen(context->role) +
			      strlen(context->type) +
			      3)) == NULL)
		return NULL;

	strcpy(sec_con, (context->user));
	strcat(sec_con, ":");
	strcat(sec_con, (context->role));
	strcat(sec_con, ":");
	strcat(sec_con, (context->type));

	return sec_con;
}



/*
 * replcon_usage
 *
 * Prints out usage instructions for the program. If brief is set to 1 (true) only the
 * syntax for program execution is displayed
 */
void
replcon_usage(const char *program_name, int brief)
{
	char **array=NULL;
	int size;
#ifndef FINDCON
	printf("%s (replcon ver. %s)\n\n", COPYRIGHT_INFO, REPLCON_VERSION_NUM);
	printf("Usage: %s [OPTIONS] -c OLD NEW FILENAMES\n", program_name);
#else
	printf("%s (findcon ver. %s)\n\n", COPYRIGHT_INFO, FINDCON_VERSION_NUM);
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
	printf("  -r,  --recursive        Recurse through directories.\n");
	printf("  -s,  --stdin            Read FILENAMES from standard input.\n");
	printf("  -q,  --quiet            Suppress progress output.\n");
	printf("  -V,  --verbose          Display context info.\n");
	printf("  -v,  --version          Display version information and exit.\n");
	printf("  -h,  --help             Display this help and exit.\n");
	printf("\n");
	printf("A context may be specified as a colon separated list of user, role, and type\n");
	printf("as follows - user_u:object_r:user_t. The tool will automatically match a user,\n");
	printf("role, or type that is not specified, with any other user, role, or type.\n");
	printf("For example ::user_t specifies any context that has user_t as the type.\n");
	printf("\nThe special string 'unlabeled' can be provided to the -c option in order\n");
	printf("to find or replace files that have no label.\n\n");
	
	printf("Valid OBJECT classes to specify include: \n");
	array = sefs_get_valid_object_classes(&size);
	sefs_double_array_print(array,size);
	sefs_double_array_destroy(array,size);
				
	printf("\n");
}

/*
 * replcon_info_init
 *
 * Sets the data members of info to initial values
 */
void replcon_info_init(replcon_info_t *info)
{
	assert(info != NULL);
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

/*
 * replcon_info_free
 *
 * Frees all the allocated memory in info
 */
void
replcon_info_free(replcon_info_t *info)
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

/*
 * replcon_info_has_object_class
 *
 * Check if replcon_info has an object class
 */
int replcon_info_has_object_class(replcon_info_t *info, sefs_classes_t obj_class)
{
	int i;

	assert(info != NULL); 
	for (i = 0; i < info->num_classes; i++)
		if (info->obj_classes[i] == obj_class
		    || replcon_info.obj_classes[i] == SEFS_ALL_FILES)
			return TRUE;
	return FALSE;
}


/*
 * replcon_is_valid_context_format
 *
 * Determines if context is a valid file context format
 */
int replcon_is_valid_context_format(const char *context_str)
{
	int i, len, count = 0;

	assert(context_str != NULL);	
	if (!strcasecmp("unlabeled", context_str))
		return TRUE;

	len = strlen(context_str);

	for (i = 0; i < len; i++) {
		if (context_str[i] == ':')
			count++;
	}

	if (count == 2)
		return TRUE;
	else
		return FALSE;
}


/*
 * replcon_info_add_object_class
 *
 * Adds class_id to the array of object types stored in replcon_info that will have their
 * context changed upon program execution
 */
int replcon_info_add_object_class(replcon_info_t *info, const char *str)
{
	sefs_classes_t class_id;

	assert(info != NULL);
	class_id = sefs_is_valid_object_class(str);
	switch(class_id) {
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
	if (class_id == -1) {
		fprintf(stderr, "Error: invalid object class \'%s\'\n", optarg);
		return -1;
	}

	info->obj_classes =
	    (sefs_classes_t *) realloc(info->obj_classes,
					  sizeof (sefs_classes_t) *
					  (info->num_classes + 1));
	if (!info->obj_classes) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}

	info->obj_classes[info->num_classes] = class_id;
	info->num_classes++;

	return 0;
}

#ifndef FINDCON
/*
 * replcon_info_add_context_pair
 *
 * Adds the context pair, old and new, to the array of context pairs stored in replcon_info
 * that will be changed upon program execution
 */
int replcon_info_add_context_pair(replcon_info_t *info, const char *old, const char *new)
{
	replcon_context_t *context = NULL;

	assert(info != NULL);
	/* Check the context pairs for format before we do any memory mgmt */
	if (!replcon_is_valid_context_format(old)) {
		fprintf(stderr,
			"Error: \'%s\' is not a valid context format.\n", old);
		goto err;
	}

	if (!replcon_is_valid_context_format(new)) {
		fprintf(stderr,
			"Error: \'%s\' is not a valid context format.\n", new);
		goto err;
	}

	info->pairs =
	    (replcon_context_pair_t *) realloc(info->pairs,
					       sizeof (replcon_context_pair_t) *
					       (info->num_pairs + 1));
	if (!info->pairs) {
		fprintf(stderr, "Error: Out of memory\n");
		goto err;
	}

	if (!strcasecmp("unlabeled", old))
		context = replcon_context_create("!:!:!");
	else
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
	if (context) free(context);
	return -1;

}
#else
/*
 * replcon_info_add_context
 *
 * Adds the context to the array of contexts stored in replcon_info
 * that will be sought upon program execution
 */
int replcon_info_add_context(replcon_info_t *info, const char *con)
{
	replcon_context_t *context = NULL;

	assert(info != NULL);
	/* Check the context for format before we do any memory mgmt */
	if (!replcon_is_valid_context_format(con)) {
		fprintf(stderr,
			"Error: \'%s\' is not a valid context format.\n", con);
		goto err;
	}

	if (!strcasecmp("unlabeled", con))
		context = replcon_context_create("!:!:!");
	else
		context = replcon_context_create(con);
	if (context) {
		info->contexts =
			(replcon_context_t *) realloc(info->contexts,
						      sizeof (replcon_context_t) *
						      (info->num_contexts + 1));
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
	if (context) free(context);
	return -1;
}
#endif

/*
 * replcon_info_add_filename
 *
 * Adds loc to the array of file/directory locations stored in replcon_info that will
 * have contexts replaced
 */
int replcon_info_add_filename(replcon_info_t *info, const char *file)
{
	assert(info != NULL);
	
	info->filenames =
	    realloc(info->filenames,
		    sizeof (char *) * (info->num_filenames + 1));
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

/*
 * replcon_context_equal
 *
 * return true if the patterns match the fields in context
 * if any context field is empty then that field matches
 * example - ::user_t == x_u:y_r:user_t,
 * example - x_u:y_r:user_t != user_u:y_r:user_t
 */
unsigned char
replcon_context_equal(const replcon_context_t *context, const replcon_context_t *patterns)
{
	unsigned char user_match, role_match, type_match;

	assert((context != NULL) && (patterns != NULL));
	user_match =
	    ((fnmatch(patterns->user, context->user, 0) == 0) ||
	     (strcmp(context->user, "") == 0) ||
	     (strcmp(patterns->user, "") == 0));
	role_match =
	    ((fnmatch(patterns->role, context->role, 0) == 0) ||
	     (strcmp(context->role, "") == 0) ||
	     (strcmp(patterns->role, "") == 0));
	type_match =
	    ((fnmatch(patterns->type, context->type, 0) == 0) ||
	     (strcmp(context->type, "") == 0) ||
	     (strcmp(patterns->type, "") == 0));

	return (user_match && role_match && type_match);
}

#ifndef FINDCON
/*
 * replcon_file_context_replace
 *
 * Change the context of the file, as long as it meets the specifications in replcon_info
 *
 * The caller must pass a valid filename and statptr
 */
int
replcon_file_context_replace(const char *filename, const struct stat64 *statptr,
			     int fileflags, struct FTW *pfwt)
{
	int file_class, i;
	unsigned char match = FALSE;
	replcon_context_t *replacement_con = NULL, *original_con = NULL, *new_con = NULL;
	security_context_t old_file_con, new_file_con = NULL;
	replcon_info_t *info = NULL;

	assert(filename != NULL && statptr != NULL);
	info = &replcon_info;
	file_class = sefs_get_file_class(statptr);
	if (!replcon_info_has_object_class(info, file_class))
		return 0;

	if (lgetfilecon(filename, &old_file_con) <= 0) {
		if (errno == ENODATA) {
			if ((old_file_con = strdup("!:!:!")) == NULL)
				goto err;
		} else {
			fprintf(stderr, "Unable to get file context for %s, skipping...\n", filename);
			return 0;
		}
	}

	if ((original_con = replcon_context_create(old_file_con)) == NULL)
		goto err;

	if ((replacement_con = replcon_context_create("::")) == NULL)
		goto err;

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

		new_file_con = get_security_context(replacement_con);
		if (new_file_con == NULL) {
			fprintf(stderr, "Unable to create new file security context.");	
			goto err;
		}
		if (lsetfilecon(filename, new_file_con) != 0) {
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
	if (original_con) replcon_context_destroy(original_con);
	if (replacement_con) replcon_context_destroy(replacement_con);
	if (old_file_con) freecon(old_file_con);
	if (new_file_con) freecon(new_file_con);
	return -1;

}

#else
/*
 * findcon
 *
 * The caller must pass a valid filename and statptr
 */
int
findcon(const char *filename, const struct stat64 *statptr,
			     int fileflags, struct FTW *pfwt)
{
	int file_class, i;
	replcon_context_t *original_con = NULL;
	security_context_t file_con;
	
	assert(filename != NULL && statptr != NULL);
	file_class = sefs_get_file_class(statptr);
	if (!replcon_info_has_object_class(&replcon_info, file_class))
		return 0;

	if (lgetfilecon(filename, &file_con) <= 0) {
		if (errno == ENODATA) {
			if ((file_con = strdup("!:!:!")) == NULL)
				goto err;
		} else {
			fprintf(stderr, "Unable to get file context for %s\n, skipping...", filename);
			return 0;
		}
	}

	if ((original_con = replcon_context_create(file_con)) == NULL)
		goto err;

	for (i = 0; i < replcon_info.num_contexts; i++) {
		if (replcon_context_equal
		    (original_con, &(replcon_info.contexts[i]))) {
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
	if (original_con) replcon_context_destroy(original_con);
	if (file_con) freecon(file_con);
	return -1;

}
#endif

/*
 * replcon_stat_file_replace_context
 *
 */
void
replcon_stat_file_replace_context(const char *filename)
{
	struct stat64 file_status;
	/* Use path length limit defined in limits.h */
	char actual_path[PATH_MAX+1];
	char *ptr = NULL;
	int i;

	assert(filename != NULL);
	if (stat64(filename, &file_status) != 0) {
		fprintf(stderr,
			"Warning: Can not stat \'%s\'.  Skipping this file.\n",
			filename);
		return;
	}

	if (replcon_info.recursive) {
		if ((ptr = realpath(filename, actual_path)) == NULL) {
			perror("replcon_stat_file_replace_context");
			return;
		}
#ifndef FINDCON
		if (nftw64(actual_path, replcon_file_context_replace, NFTW_DEPTH, NFTW_FLAGS)) {
			fprintf(stderr,
				"Error walking directory tree: %s\n", actual_path);
			return;
		}
#else
		if (nftw64(actual_path, findcon, NFTW_DEPTH, NFTW_FLAGS)) {
			fprintf(stderr,
				"Error walking directory tree: %s\n", actual_path);
			return;
		}
#endif
		for(i = 0; i < num_mounts; i++) {
			if (strstr(mounts[i], actual_path) == mounts[i])
#ifndef FINDCON
				if (nftw64(mounts[i], replcon_file_context_replace, NFTW_DEPTH, NFTW_FLAGS)) {
					fprintf(stderr,
						"Error walking directory tree: %s\n", mounts[i]);
					return;
				}
#else
				if (nftw64(mounts[i], findcon, NFTW_DEPTH, NFTW_FLAGS)) {
					fprintf(stderr,
						"Error walking directory tree: %s\n", mounts[i]);
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

/*
 * remove_new_line_char
 *
 * Removes the new line character from stdin stream input strings
 */
void
remove_new_line_char(char *input)
{
	int i, len;
	
	assert(input != NULL);
	len = strlen(input);
	for (i = 0; i < len; i++) {
		if (input[i] == '\n')
			input[i] = '\0';
	}
}

/*
 * replcon_parse_command_line
 *
 * Function for parsing command line arguments
 */
void
replcon_parse_command_line(int argc, char **argv)
{
	int optc, i;

	/* get option arguments */
	while ((optc =
		getopt_long(argc, argv, "o:c:rsVqvh", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 'o':
			if (replcon_info_add_object_class
			    (&replcon_info, optarg)) {
				fprintf(stderr,
					"Unable to add object class.\n");
				goto err;
			}
			break;
		case 'c':
#ifndef FINDCON
			if (optind < argc) { 
				/* Two arguments required! */
				if (replcon_info_add_context_pair
				    (&replcon_info, optarg, argv[optind++])) {
					fprintf(stderr,
						"Unable to add context pair.\n");
					goto err;
				}
			} else {
				fprintf(stderr, "Contexts must be specified in pairs.\n");
				goto err;
			}
#else
			if (replcon_info_add_context(&replcon_info, optarg)) {
				fprintf(stderr,
					"Unable to add file context.\n");
				goto err;
			}
#endif
			break;
		case 'r':	/* recursive directory parsing */
			replcon_info.recursive = TRUE;
			break;
		case 's':	/* read from standard in */
			replcon_info.stdin = TRUE;
			break;
		case 'q':
			if (replcon_info.verbose) {
				fprintf(stderr,
					"Error: Can not specify -q and -V\n");
				goto err;
			}
			replcon_info.quiet = TRUE;
			break;
		case 'V':	/* verbose program execution */
			if (replcon_info.quiet) {
				fprintf(stderr,
					"Error: Can not specify -q and -V\n");
				goto err;
			}
			replcon_info.verbose = TRUE;
			break;
		case 'v':	/* version */
#ifndef FINDCON
				printf("\n%s (replcon ver. %s)\n\n", COPYRIGHT_INFO,
       					REPLCON_VERSION_NUM);
#else
				printf("\n%s (findcon ver. %s)\n\n", COPYRIGHT_INFO,
       					FINDCON_VERSION_NUM);
#endif
			
			replcon_info_free(&replcon_info);
			exit(0);
		case 'h':	/* help */
			replcon_usage(argv[0], 0);
			replcon_info_free(&replcon_info);
			exit(0);
		default:	/* usage */
			goto err;
		}
	}
	/* If no object class was specified revert to the default of all files */
	if (replcon_info.num_classes == 0) {
		if (replcon_info_add_object_class(&replcon_info, "all_files")) {
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
		fprintf(stderr,
			"Warning: Command line filename(s) will be ignored. Reading from stdin.\n");
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

int
main(int argc, char **argv)
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

	if (find_mount_points("/", &mounts, &num_mounts, hashtab, rw)) {
		fprintf(stderr, "Could not enumerate mountpoints.\n");
		goto err;
	}

	if (replcon_info.stdin) {
		while (fgets(stream_input, (MAX_INPUT_SIZE - 1), stdin)) {
			remove_new_line_char(stream_input);
			replcon_stat_file_replace_context(stream_input);
		}
	} else {
		for (i = (replcon_info.num_filenames - 1); i >= 0; i--)
			replcon_stat_file_replace_context(replcon_info.
							  filenames[i]);
	}

	replcon_info_free(&replcon_info);
	for (i = 0; i < num_mounts; i++)
		free(mounts[i]);
	free(mounts);
	sefs_hash_destroy(hashtab);
	return 0;
	
err:
	replcon_info_free(&replcon_info);
	if (mounts) free(mounts);
	sefs_hash_destroy(hashtab);
	return -1;
}
