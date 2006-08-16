/**
 * @file fsdata.c
 *
 * Routines for creating, saving, and loading a sqlite3 database
 * containing paths + file contexts.  Also contains routines to search
 * a created database.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2003-2006 Tresys Technology, LLC
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

#include <sefs/fsdata.h>
/* sqlite db stuff */
#include "sqlite/sqlite3.h"

/* SE Linux includes*/
#include <selinux/selinux.h>
#include <selinux/context.h>

/* standard library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
#include <regex.h>
#include <stdarg.h>

/* AVL Tree Handling */
#include <apol/avl-util.h>

/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>
#include <mntent.h>

#include <time.h>

#define INDEX_DB_MAGIC 0xf97cff8f
#define INDEX_DB_VERSION 1

#ifndef SEFS_XATTR_UNLABELED
#define SEFS_XATTR_UNLABELED "UNLABELED"
#endif

#define NFTW_FLAGS FTW_MOUNT
#define NFTW_DEPTH 1024

#define STMTSTART_MLS "SELECT types.type_name,users.user_name,paths.path,inodes.obj_class,mls.mls_range from inodes,types,users,paths,mls"
#define STMTSTART_NONMLS "SELECT types.type_name,users.user_name,paths.path,inodes.obj_class from inodes,types,users,paths"
#define STMTEND_MLS "inodes.user = users.user_id AND paths.inode = inodes.inode_id AND types.type_id = inodes.type AND mls.mls_id = inodes.range"
#define STMTEND_NONMLS "inodes.user = users.user_id AND paths.inode = inodes.inode_id AND types.type_id = inodes.type"
#define SORTSTMT "ORDER BY paths.path ASC"

typedef struct inode_key {
	ino_t			inode;
	dev_t			dev;
} inode_key_t;

typedef struct sefs_context {
	int user, role, type, range;
} sefs_context_t;

typedef struct sefs_fileinfo {
	inode_key_t		key;
	uint32_t		num_links;
	sefs_context_t		context;
	char **			path_names;
	char *			symlink_target;
/* this uses defines from above */
	uint32_t		obj_class;
} sefs_fileinfo_t;


typedef struct sefs_typeinfo {
	char*			name;
	uint32_t		num_inodes;
	uint32_t *		index_list;
} sefs_typeinfo_t;


typedef struct sefs_filesystem_data {
	uint32_t		num_types;
	uint32_t		num_users;
	uint32_t		num_range;
	uint32_t		num_files;
	int			fs_had_range;
	sefs_typeinfo_t *	types;
	sefs_fileinfo_t *	files;
	char**			users;
	char**			range;
	/* not stored in index file */
	apol_avl_tree_t		file_tree;
	apol_avl_tree_t		type_tree;
	apol_avl_tree_t		user_tree;
	apol_avl_tree_t		range_tree;
} sefs_filesystem_data_t;


/* As that setools must work with older libselinux versions that may
 * not have the _raw() functions, declare them as weak.	 If libselinux
 * does indeed have the new functions then use them; otherwise
 * fallback to the originals. */

extern int lgetfilecon_raw(const char *, security_context_t *) __attribute__ ((weak));

static int sefs_lgetfilecon(const char *path, security_context_t *context)
{
	if (lgetfilecon_raw != NULL) {
		return lgetfilecon_raw(path, context);
	}
	else {
		return lgetfilecon(path, context);
	}
}


/* Management and creation functions */
static void sefs_types_compare(sqlite3_context *context, int argc, sqlite3_value **argv);
static void sefs_users_compare(sqlite3_context *context, int argc, sqlite3_value **argv);
static void sefs_paths_compare(sqlite3_context *context, int argc, sqlite3_value **argv);
static void sefs_range_compare(sqlite3_context *context, int argc, sqlite3_value **argv);
static int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd);
static void destroy_fsdata(sefs_filesystem_data_t * fsd);
static int sefs_get_class_int(const char *class);

static const char * sefs_get_class_string( int flag_val);

/* our main sqlite db struct */
static struct sqlite3 *db;
/* this is the struct that has sqlite and the old data struct */
static sefs_filesystem_data_t *fsdata = NULL;
/* this is the search key stuff */
static sefs_search_keys_t *sefs_search_keys = NULL;
static sefs_search_ret_t *sefs_search_ret = NULL;

/* these are precompiled regular expressions */
static regex_t types_re;
static regex_t users_re;
static regex_t paths_re;
static regex_t range_re;

#define DB_SCHEMA_MLS "CREATE TABLE types ( \
			   type_id INTEGER PRIMARY KEY, \
			   type_name varchar (48) \
		       );  \
		       CREATE TABLE users ( \
			   user_id INTEGER PRIMARY KEY, \
			   user_name varchar (24) \
		       ); \
		       CREATE TABLE mls ( \
			   mls_id INTEGER PRIMARY KEY, \
			   mls_range varchar (64) \
		       ); \
		       CREATE TABLE paths ( \
			   inode int, \
			   path varchar (128) PRIMARY KEY\
		       ); \
		       CREATE TABLE inodes ( \
			   inode_id INTEGER PRIMARY KEY, \
			   dev	int, \
			   ino	int(64), \
			   user int, \
			   type int, \
			   range int, \
			   obj_class int, \
			   symlink_target varchar (128) \
		       ); \
		       CREATE TABLE info ( \
			   key varchar, \
			   value varchar \
		       ); \
		       CREATE INDEX inodes_index ON inodes (ino,dev); \
		       CREATE INDEX paths_index ON paths (inode); \
		       "

#define DB_SCHEMA_NONMLS "CREATE TABLE types ( \
			      type_id INTEGER PRIMARY KEY, \
			      type_name varchar (48) \
			  );  \
			  CREATE TABLE users ( \
			      user_id INTEGER PRIMARY KEY, \
			      user_name varchar (24) \
			  ); \
			  CREATE TABLE paths ( \
			      inode int, \
			      path varchar (128) PRIMARY KEY\
			  ); \
			  CREATE TABLE inodes ( \
			      inode_id INTEGER PRIMARY KEY, \
			      dev int, \
			      ino int(64), \
			      user int, \
			      type int, \
			      range int, \
			      obj_class int, \
			      symlink_target varchar (128) \
			  ); \
			  CREATE TABLE info ( \
			      key varchar, \
			      value varchar \
			  ); \
			  CREATE INDEX inodes_index ON inodes (ino,dev); \
			  CREATE INDEX paths_index ON paths (inode); \
			  "

static const char *sefs_object_classes[] =
    { "file", "dir", "lnk_file", "chr_file", "blk_file", "sock_file",
"fifo_file", "all_files" };


static int sefs_count_callback(void *NotUsed, int argc, char **argv, char **azColName)
{
	int *count = (int *)NotUsed;
	*count = atoi(argv[0]);
	return 0;
}

/**
 * Append a string to the sql statement being constructed.  If out of
 * memory during reallocation then print an error to stderr.
 *
 * @param stmt Reference to the statement string.
 * @param stmt_size Reference to the number of bytes already allocated
 * to stmt.
 * @param fmt Format of new characters, as per printf(3).
 *
 * @return 0 on success, < 0 on error.
 */
static int sefs_append(char **stmt, size_t *stmt_size, char *fmt, ...)
{
	int retval;
	va_list ap;
	char *tmp;

	/* first calculate how much bigger to make stmt */
	va_start(ap, fmt);
	retval = vsnprintf("", 0, fmt, ap);
	va_end(ap);
	if (retval < 0) {
		fprintf(stderr, "Illegal format string.");
		return -1;
	}

	/* resize statement */
	if ((tmp = realloc(*stmt, *stmt_size + retval + 1)) == NULL) {
		fprintf(stderr, "Out of memory.");
		return -1;
	}
	*stmt = tmp;
	va_start(ap, fmt);
	vsnprintf(*stmt + *stmt_size, retval + 1, fmt, ap);
	*stmt_size += retval;
	va_end(ap);
	return 0;
}

#define APPEND(...) do { if (sefs_append(stmt, &stmt_size, __VA_ARGS__)) return -1; } while (0)

/**
 * Allocate the SQL select statement for a given search keys query.
 * Write the generated statement to the reference pointer stmt; the
 * caller is responsible for free()ing it afterwards.  Note that if
 * the database is not MLS, then MLS related fields within search_keys
 * are ignored.
 *
 * @param stmt Reference to where to store generated SQL statement.
 * @param search_keys Criteria for search.
 * @param objects Array of object class indices for search.
 * @param db_is_mls Flag to indicate if database has MLS components.
 *
 * @return 0 on success, < 0 on error.
 */
static int sefs_stmt_populate(char **stmt, sefs_search_keys_t *search_keys, int *objects, int db_is_mls)
{
	int index, where_added = 0;
	size_t stmt_size = 0;
	*stmt = NULL;

	/* first put the starting statement */
	if (db_is_mls) {
		APPEND("%s", STMTSTART_MLS);
	}
	else {
		APPEND("%s", STMTSTART_NONMLS);
	}

	/* now we go through the search keys populating the statement */
	/* type,user,path,object_class */
	if (search_keys->type && search_keys->num_type > 0) {
		if (!where_added) {
			APPEND(" where (");
			where_added = 1;
		}
		else {
			APPEND(" (");
		}
		for (index = 0; index < search_keys->num_type; index++) {
			if (index > 0) {
				APPEND(" OR");
			}
			if (search_keys->do_type_regEx)
				APPEND(" sefs_types_compare(types.type_name,\"%s\")", search_keys->type[index]);
			else
				APPEND(" types.type_name = \"%s\"", search_keys->type[index]);
		}
	}

	if (search_keys->user && search_keys->num_user > 0) {
		if (!where_added) {
			APPEND(" where (");
			where_added = 1;
		}
		else {
			APPEND(") AND (");
		}
		for (index = 0; index < search_keys->num_user; index++) {
			if (index > 0) {
				APPEND(" OR");
			}
			if (search_keys->do_user_regEx)
				APPEND(" sefs_users_compare(users.user_name,\"%s\")", search_keys->user[index]);
			else
				APPEND(" users.user_name = \"%s\"", search_keys->user[index]);
		}
	}

	if (search_keys->path && search_keys->num_path > 0) {
		if (!where_added) {
			APPEND(" where (");
			where_added = 1;
		}
		else {
			APPEND(") AND (");
		}
		for (index = 0; index < search_keys->num_path; index++) {
			if (index > 0) {
				APPEND(" OR");
			}
			if (search_keys->do_path_regEx)
				APPEND(" sefs_paths_compare(paths.path,\"%s\")", search_keys->path[index]);
			else
				APPEND(" paths.path LIKE \"%s%%\"", search_keys->path[index]);
		}
	}

	if (search_keys->object_class && search_keys->num_object_class > 0) {
		if (!where_added) {
			APPEND(" where (");
			where_added = 1;
		}
		else {
			APPEND(") AND (");
		}
		for (index = 0; index < search_keys->num_object_class; index++) {
			if (index > 0) {
				APPEND(" OR");
			}
			APPEND(" inodes.obj_class = %d", objects[index]);
		}
	}

	if (search_keys->range && search_keys->num_range > 0) {
		if (!where_added) {
			APPEND(" where (");
			where_added = 1;
		}
		else {
			APPEND(") AND (");
		}
		for (index = 0; index < search_keys->num_range; index++) {
			if (index > 0) {
				APPEND(" OR");
			}
			if (search_keys->do_range_regEx)
				APPEND(" sefs_range_compare(mls.mls_range,\"%s\")", search_keys->range[index]);
			else
				APPEND(" mls.mls_range = \"%s\"", search_keys->range[index]);
		}
	}

	if (where_added) {
		APPEND(") AND");
	}
	else {
		APPEND(" where");
	}
	if (db_is_mls) {
		APPEND(" %s %s", STMTEND_MLS, SORTSTMT);
	}
	else {
		APPEND(" %s %s", STMTEND_NONMLS, SORTSTMT);
	}
	return 0;
}

struct search_types_arg {
	char **list;
	int count;
};

static int sefs_search_types_callback(void *data, int argc, char **argv, char **azColName)
{
	struct search_types_arg *arg = (struct search_types_arg *) data;
	/* lets create memory and copy over*/
	if ((arg->list[arg->count] = strdup(argv[0])) == NULL) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}
	arg->count += 1;
	return 0;
}

static int sefs_search_callback(void *arg, int argc, char **argv, char **azColName)
{
	int i, *db_is_mls = (int *) arg;
	sefs_search_ret_t *search_ret=NULL;
	const char *class_string;
	char *type = argv[0];
	char *user = argv[1];
	char *path = argv[2];
	char *class = argv[3];
	char *range = (*db_is_mls ? argv[4] : NULL);

	/* first lets generate a ret struct */
	if ((search_ret = (sefs_search_ret_t *)calloc(1, sizeof(sefs_search_ret_t))) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}

	/* next lets add in the context */
	if (*db_is_mls) {
		i = snprintf("", 0, "%s:object_r:%s:%s", user, type, range);
	}
	else {
		i = snprintf("", 0, "%s:object_r:%s", user, type);
	}
	if ((search_ret->context = malloc(i + 1)) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}
	if (*db_is_mls) {
		snprintf(search_ret->context, (size_t) i + 1, "%s:object_r:%s:%s", user, type, range);
	}
	else {
		snprintf(search_ret->context, (size_t) i + 1, "%s:object_r:%s", user, type);
	}

	/* next we add in the path */
	if ((search_ret->path = strdup(path)) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}

	/* finally its object class */
	class_string = sefs_get_class_string(atoi(class));
	if ((search_ret->object_class = strdup(class_string)) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}

	/* now insert it into the list */
	/* to try to speed this up we keep a global pointer that */
	/* points to the last element in the list */
	if (!sefs_search_keys->search_ret){
		sefs_search_keys->search_ret = search_ret;
		sefs_search_ret = search_ret;
	}
	else {
		sefs_search_ret->next = search_ret;
		sefs_search_ret = search_ret;
	}

	return 0;
}


/* compare a type_name value with a precompiled regular expression */
static void sefs_types_compare(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int retVal=0;
	const char *text;
	regmatch_t pm;

	/* make sure we got the arguments */
	assert(argc == 2);

	/* make sure we got the right kind of argument */
	if (sqlite3_value_type(argv[0]) == SQLITE_TEXT) {
		text = (const char *)sqlite3_value_text(argv[0]);
		if (regexec (&types_re,text, 1, &pm, 0) == 0)
			retVal = 1;
	}
	sqlite3_result_int(context,retVal);
}

/* compare a user_name value with a precompiled regular expression */
static void sefs_users_compare(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int retVal=0;
	const char *text;
	regmatch_t pm;
	/* make sure we got the arguments */
	assert(argc == 2);

	/* make sure we got the right kind of argument */
	if (sqlite3_value_type(argv[0]) == SQLITE_TEXT) {
		text = (const char *)sqlite3_value_text(argv[0]);
		/* if we aren't using regular expressions just match them up */
		if (regexec (&users_re,text, 1, &pm, 0) == 0){
			retVal = 1;
		}
	}
	sqlite3_result_int(context,retVal);
}

/* compare a path value with a precompiled regular expression */
static void sefs_paths_compare(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int retVal=0;
	const char *text;
	regmatch_t pm;

	/* make sure we got the arguments */
	assert(argc == 2);

	/* make sure we got the right kind of argument */
	if (sqlite3_value_type(argv[0]) == SQLITE_TEXT) {
		text = (const char *)sqlite3_value_text(argv[0]);
		if (regexec (&paths_re,text, 1, &pm, 0) == 0)
			retVal = 1;
	}
	sqlite3_result_int(context,retVal);
}

/* compare a range value with a precompiled regular expression */
static void sefs_range_compare(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int retVal=0;
	const char *text;
	regmatch_t pm;

	/* make sure we got the arguments */
	assert(argc == 2);

	/* make sure we got the right kind of argument */
	if (sqlite3_value_type(argv[0]) == SQLITE_TEXT) {
		text = (const char *)sqlite3_value_text(argv[0]);
		if (regexec(&range_re, text, 1, &pm, 0) == 0)
			retVal = 1;
	}
	sqlite3_result_int(context, retVal);
}

/* return the define of the object class */
static int sefs_get_class_int(const char *class)
{
	if (strcmp(class,"file") == 0)
		return SEFS_NORM_FILE;
	else if (strcmp(class,"dir") == 0)
		return SEFS_DIR;
	else if (strcmp(class,"lnk_file") == 0)
		return SEFS_LNK_FILE;
	else if (strcmp(class,"chr_file") == 0)
		return SEFS_CHR_FILE;
	else if (strcmp(class,"blk_file") == 0)
		return SEFS_BLK_FILE;
	else if (strcmp(class,"sock_file") == 0)
		return SEFS_SOCK_FILE;
	else if (strcmp(class,"fifo_file") == 0)
		return SEFS_FIFO_FILE;
	else if (strcmp(class,"all_files") == 0)
		return SEFS_ALL_FILES;
	else return -1;

}

/* returns string from above array */
static const char * sefs_get_class_string( int flag_val)
{
	switch (flag_val) {
		case  SEFS_NORM_FILE:
			return sefs_object_classes[0];
		case  SEFS_DIR:
			return sefs_object_classes[1];
		case  SEFS_LNK_FILE:
			return sefs_object_classes[2];
		case  SEFS_CHR_FILE:
			return sefs_object_classes[3];
		case  SEFS_BLK_FILE:
			return sefs_object_classes[4];
		case  SEFS_SOCK_FILE:
			return sefs_object_classes[5];
		case  SEFS_FIFO_FILE:
			return sefs_object_classes[6];
		default:
			return sefs_object_classes[7];
	}
}

int sefs_get_file_class(const struct stat64 *statptr)
{
	assert(statptr != NULL);
	if (S_ISREG(statptr->st_mode))
		return SEFS_NORM_FILE;
	if (S_ISDIR(statptr->st_mode))
		return SEFS_DIR;
	if (S_ISLNK(statptr->st_mode))
		return SEFS_LNK_FILE;
	if (S_ISCHR(statptr->st_mode))
		return SEFS_CHR_FILE;
	if (S_ISBLK(statptr->st_mode))
		return SEFS_BLK_FILE;
	if (S_ISSOCK(statptr->st_mode))
		return SEFS_SOCK_FILE;
	if (S_ISFIFO(statptr->st_mode))
		return SEFS_FIFO_FILE;
	return SEFS_ALL_FILES;
}

int sefs_filesystem_find_mount_points(const char *dir, int rw, sefs_hash_t *hashtab, char ***mounts, unsigned int *num_mounts)
{
	FILE *mtab = NULL;
	int nel = 0, len = 10;
	struct mntent *entry;
	security_context_t con;
	char *dirdup = strdup(dir);

	if ((mtab = fopen("/etc/mtab", "r")) == NULL) {
		return -1;
	}

	if ((*mounts = malloc(sizeof(char*) * len)) == NULL) {
		fclose(mtab);
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}

	while ((entry = getmntent(mtab))) {
		if (strstr(entry->mnt_dir, dir) != entry->mnt_dir)
			continue;

		/* This checks for bind mounts so that we don't recurse them
		   I'll use a string constant for now */
		if (strstr(entry->mnt_opts, "bind") != NULL) {
			if (!hashtab)
				continue;
			if (sefs_hash_insert(hashtab, entry->mnt_dir) < 0)
				return -1;
		}

		nel = strlen(dirdup);
		if (nel > 1) {
			if (dirdup[nel - 1] == '/')
				dirdup[nel - 1] = '\0';
		}

		if (strcmp(entry->mnt_dir, dir) == 0)
			continue;

		if (rw)
			if (hasmntopt(entry, MNTOPT_RW) == NULL)
				continue;

		if (*num_mounts >= len) {
			len *= 2;
			*mounts = realloc(*mounts, sizeof(char*) * len);
			if (*mounts == NULL) {
				fprintf(stderr, "Out of memory.\n");
				fclose(mtab);
				return -1;
			}
		}

		/* if we can get the file context - keep in mind that there may be an empty context */
		if (getfilecon(entry->mnt_dir,&con) != -1 || errno != EOPNOTSUPP) {
			if (((*mounts)[(*num_mounts)++] = strdup(entry->mnt_dir)) == NULL) {
				fprintf(stderr, "Out of memory.\n");
				fclose(mtab);
				return -1;
			}
		}
	}
	fclose(mtab);
	free(dirdup);
	return 0;
}


static int avl_grow_path_array(void *user_data, int sz)
{
	sefs_fileinfo_t * ptr;
	fsdata = (sefs_filesystem_data_t *)user_data;
	assert(fsdata != NULL);

	if (sz > fsdata->num_files) {
		ptr = (sefs_fileinfo_t *)realloc(fsdata->files, sz * sizeof(sefs_fileinfo_t));
		if (ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		fsdata->files = ptr;
	}

	return 0;
}


static int avl_path_compare(void *user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;
	char *tmp = NULL;
	int rc = 0;

	if ((tmp = (char *)malloc(sizeof(ino_t) + sizeof(dev_t))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	memcpy(tmp, &(fsdata->files[idx].key.inode), sizeof(ino_t));
	memcpy(tmp + sizeof(ino_t), &(fsdata->files[idx].key.dev), sizeof(dev_t));

	rc = memcmp((char*)key, (char *)tmp, sizeof(ino_t) + sizeof(dev_t));
	free(tmp);
	return rc;
}


static int avl_add_path(void *user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;
	inode_key_t * ikey = (inode_key_t *) key;

	assert(fsdata != NULL && ikey != NULL);

	fsdata->files[idx].key = *ikey;
	fsdata->files[idx].path_names = (char**)malloc(sizeof(char*) * 1);
	if (!(fsdata->files[idx].path_names)) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	(fsdata->num_files)++;
	return 0;
}


static int avl_grow_type_array(void * user_data, int sz)
{
	sefs_typeinfo_t * ptr;
	fsdata = (sefs_filesystem_data_t *)user_data;
	assert(fsdata != NULL);

	if (sz > fsdata->num_types) {
		ptr = (sefs_typeinfo_t *)realloc(fsdata->types, sz * sizeof(sefs_typeinfo_t));
		if (ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		fsdata->types = ptr;
	}

	return 0;
}


static int avl_type_compare(void *user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;

	return strcmp((char*)key, fsdata->types[idx].name);
}


static int avl_add_type(void *user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;
	char *path = (char*)key;

	assert(fsdata != NULL && path != NULL);

	fsdata->types[idx].name = (char *)key;
	fsdata->types[idx].num_inodes=0;
	fsdata->types[idx].index_list = NULL;
	(fsdata->num_types)++;

	return 0;
}

static int avl_grow_user_array(void * user_data, int sz)
{
	char** ptr;
	fsdata = (sefs_filesystem_data_t *)user_data;

	assert(fsdata != NULL);

	if (sz > fsdata->num_users)
	{
		if (!( ptr = (char**)realloc(fsdata->users, sz * sizeof(char*)) ))
		{
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		fsdata->users = ptr;
	}

	return 0;
}

static int avl_user_compare(void * user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;

	return strcmp((char*)key, fsdata->users[idx]);
}

static int avl_add_user(void * user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;
	char * user = (char*)key;

	assert(fsdata != NULL && user != NULL);


	fsdata->users[idx] = user;
	(fsdata->num_users)++;

	return 0;
}

static int avl_grow_range_array(void * user_data, int sz)
{
	char** ptr;
	fsdata = (sefs_filesystem_data_t *)user_data;

	assert(fsdata != NULL);

	if (sz > fsdata->num_range) {
		if (!( ptr = (char**)realloc(fsdata->range, sz * sizeof(char*)) )) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		fsdata->range = ptr;
	}
	return 0;
}

static int avl_range_compare(void * user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;

	return strcmp((char*)key, fsdata->range[idx]);
}

static int avl_add_range(void * user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;
	char * range= (char*)key;

	assert(fsdata != NULL && range != NULL);


	fsdata->range[idx] = range;
	(fsdata->num_range)++;

	return 0;
}

void sefs_double_array_destroy(char **array, int size)
{
	int i;
	if (array != NULL) {
		for (i = 0; i < size; i++){
			free(array[i]);
		}
		free(array);
	}
}

void sefs_search_keys_ret_destroy(sefs_search_ret_t *key)
{
	sefs_search_ret_t *curr = NULL;
	sefs_search_ret_t *prev = NULL;
	/* walk the linked list cleaning up that memory */
	curr = key;
	while (curr) {
		if (curr->context)
			free(curr->context);
		if (curr->path)
			free(curr->path);
		if (curr->object_class)
			free(curr->object_class);
		prev = curr;
		curr = curr->next;
		free(prev);
	}
}

/**
 * Takes a security context (which is really a char *) returned by
 * getfilecon() and splits it into its component pieces.  It sets the
 * user, role, type, and range pointers to point into a newly allocated
 * context.  The caller should not free() them.
 *
 * @param con Context to split.
 * @param user Reference to where to store user portion.
 * @param role Reference to where to store role portion.
 * @param type Reference to where to store type portion.
 * @param range Reference to where to store range portion, if context
 * has an MLS component.  Otherwise set reference pointer to NULL.
 *
 * @return 0 on success, < 0 on error.
 */
static int split_context(security_context_t con, const char **user, const char **role, const char **type, const char **range)
{
        context_t ctxt;
        *user = *role = *type = *range = NULL;

        ctxt = context_new(con);
        if (!ctxt)
                return -1;

        *user = context_user_get(ctxt);
        *role = context_role_get(ctxt);
        *type = context_type_get(ctxt);
        if (is_selinux_mls_enabled())
                *range = context_range_get(ctxt);

 /* FIX ME sometime later: ctxt needs to be destroyed.  note that it can't
    be done here because *user etc point into that memory. */
        return 0;
}

static int ftw_handler(const char *file, const struct stat64 *sb, int flag, struct FTW *s)
{
	inode_key_t key;
	int idx, rc = 0;
	sefs_fileinfo_t * pi = NULL;
	security_context_t con = NULL;
	const char *user, *role, *type, *range;
	char *tmp2;
	char** ptr = NULL;

	key.inode = sb->st_ino;
	key.dev = sb->st_dev;

	idx = apol_avl_get_idx(&(fsdata->file_tree), &key);

	if (idx == -1) {
		if ((rc = apol_avl_insert(&(fsdata->file_tree), &key, &idx)) == -1) {
			fprintf(stderr, "avl error\n");
			return -1;
		}

		pi = &(fsdata->files[idx]);
		(pi->num_links) = 0;

		/* Get the file context. Interrogate the link itself, not the file it points to. */
		rc = sefs_lgetfilecon(file, &con);
		if (rc < 0) {
			fprintf(stderr, "could not get context for %s\n", file);
			return -1;
		}
		rc = split_context(con, &user, &role, &type, &range);
		/* (ignore the return value) */

		if (user == NULL) {
			user = SEFS_XATTR_UNLABELED;
		}
		rc = apol_avl_get_idx(&fsdata->user_tree, user);
		if (rc == -1) {
			if ((tmp2 = strdup(user)) == NULL) {
				fprintf(stderr, "Out of memory\n");
				return -1;
			}
			apol_avl_insert(&(fsdata->user_tree),tmp2, &rc);
		}
		pi->context.user=rc;

		if (role != NULL && strcmp(role, "object_r") == 0)
			pi->context.role = SEFS_OBJECT_R;
		else
			/* FIXME v this is bad */
			pi->context.role = 0;

		if (type == NULL) {
			type = SEFS_XATTR_UNLABELED;
		}
		rc = apol_avl_get_idx(&fsdata->type_tree, type);
		if (rc == -1) {
			if ((tmp2 = strdup(type)) == NULL) {
				fprintf(stderr, "Out of memory\n");
				return -1;
			}
			apol_avl_insert(&(fsdata->type_tree), tmp2, &rc);
		}
		pi->context.type=(int32_t)rc;

		if (range == NULL) {
			range = "";
		}
		else {
			fsdata->fs_had_range = 1;
		}
		rc = apol_avl_get_idx(&fsdata->range_tree, range);
		if (rc == -1) {
			if ((tmp2 = strdup(range)) == NULL) {
				fprintf(stderr, "Out of memory\n");
				return -1;
			}
			apol_avl_insert(&(fsdata->range_tree), tmp2, &rc);
		}
		pi->context.range=(int32_t)rc;
	} else {
		pi = &(fsdata->files[idx]);
	}

	freecon(con);

	pi->obj_class = sefs_get_file_class(sb);

	ptr = (char**)realloc(pi->path_names, (pi->num_links + 1) * sizeof(char*));
	if (!ptr) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	pi->path_names = ptr;

	if ((pi->path_names[pi->num_links] = (char *)malloc((strlen(file) + 1) * sizeof(char))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	bzero(pi->path_names[pi->num_links], (strlen(file) + 1) * sizeof(char));
	strncpy(pi->path_names[pi->num_links], file, strlen(file));
	(pi->num_links)++;

	/*check to see if file is a symlink and handle appropriately*/
	if (S_ISLNK(sb->st_mode))
	{
		if (!(tmp2 = (char*)calloc((PATH_MAX + 1), sizeof(char)) ))
		{
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		readlink(file, tmp2, (PATH_MAX + 1) * sizeof(char));
		if (errno == EINVAL || errno == EIO)
		{
			fprintf(stderr, "error reading link\n");
			return -1;
		}
		else if (errno == EACCES)
		{
			errno = 0;
		}
		else
		{
			pi->symlink_target = tmp2;
		}
	} else {
		pi->symlink_target = NULL;
	}
	return 0;
}

static int sefs_init_pathtree(sefs_filesystem_data_t * fsd)
{
	if ((fsd->files = (sefs_fileinfo_t *)malloc(sizeof(sefs_fileinfo_t) * 1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	memset(fsd->files, 0, sizeof(sefs_fileinfo_t) * 1);

	fsd->num_files = 0;

	apol_avl_init(&(fsd->file_tree),
		 (void *)fsd,
		 avl_path_compare,
		 avl_grow_path_array,
		 avl_add_path);

	return 0;
}

static int sefs_init_typetree(sefs_filesystem_data_t * fsd)
{
	if ((fsd->types = (sefs_typeinfo_t *)malloc(sizeof(sefs_typeinfo_t) * 1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	memset(fsd->types, 0, sizeof(sefs_typeinfo_t) * 1);

	fsd->num_types = 0;

	apol_avl_init(&(fsd->type_tree),
		 (void *)fsd,
		 avl_type_compare,
		 avl_grow_type_array,
		 avl_add_type);

	return 0;
}

static int sefs_init_usertree(sefs_filesystem_data_t * fsd)
{
	if (!( fsd->users = (char**)malloc(sizeof(char*) * 1) ))
	{
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	memset(fsd->users, 0, sizeof(char*) * 1);

	fsd->num_users = 0;

	apol_avl_init( &(fsd->user_tree),
		(void*)fsd,
		avl_user_compare,
		avl_grow_user_array,
		avl_add_user);

	return 0;
}

static int sefs_init_rangetree(sefs_filesystem_data_t * fsd)
{
	if (!( fsd->range = (char**)malloc(sizeof(char*) * 1) ))
	{
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	memset(fsd->range, 0, sizeof(char*) * 1);

	fsd->num_range = 0;

	apol_avl_init( &(fsd->range_tree),
		(void*)fsd,
		avl_range_compare,
		avl_grow_range_array,
		avl_add_range);

	return 0;
}

static int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd)
{
	if (fsd == NULL) {
		fprintf(stderr, "Invalid structure\n");
		return -1;
	}

	fsdata = fsd;
	fsd->num_files = 0;
	fsd->num_types = 0;
	fsd->num_users = 0;
	fsd->fs_had_range = 0;
	fsd->files = NULL;
	fsd->types = NULL;
	fsd->users = NULL;
	fsd->range = NULL;

	if (sefs_init_pathtree(fsd) == -1) {
		fprintf(stderr, "fsdata_init_paths() failed\n");
		return -1;
	}

	if (sefs_init_typetree(fsd) == -1) {
		fprintf(stderr, "fsdata_init_types() failed\n");
		return -1;
	}

	if (sefs_init_usertree(fsd) == -1)
	{
		fprintf(stderr, "fsdata_init_users() failed\n");
		return -1;
	}

	if (sefs_init_rangetree(fsd) == -1) {
		fprintf(stderr, "fsdata_init_rangetree() failed\n");
		return -1;
	}

	return 0;
}

int sefs_is_valid_object_class(const char *class_name)
{
	int i;

	assert(class_name != NULL);
	for (i = 0; i < SEFS_NUM_OBJECT_CLASSES; i++)
		if (strcmp(class_name, sefs_object_classes[i]) == 0)
			return i;
	return -1;
}

char **sefs_get_valid_object_classes(int *size)
{
	int i, num_objs_on_line = 0;
	char **local_list = NULL;

	assert(sefs_object_classes != NULL);


	/* malloc out the memory for the types */
	if ((local_list = (char **)malloc(SEFS_NUM_OBJECT_CLASSES * sizeof(char *))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	for (i = 0; i < SEFS_NUM_OBJECT_CLASSES; i++) {
		num_objs_on_line++;
		if ((local_list[i] = (char *)malloc((strlen(sefs_object_classes[i])+1) * sizeof(char))) == NULL){
			sefs_double_array_destroy(local_list,i);
			fprintf(stderr,"out of memory\n");
			return NULL;
		}
		strncpy(local_list[i],sefs_object_classes[i],strlen(sefs_object_classes[i]));
		local_list[i][strlen(sefs_object_classes[i])] = '\0';
	}
	*size = SEFS_NUM_OBJECT_CLASSES;
	return local_list;
}

char **sefs_filesystem_db_get_known(sefs_filesystem_db_t *fsd, int request_type, int *count_in)
{
	char *count_stmt = NULL, *select_stmt = NULL;
	int rc=0, list_size = 0;
	char *errmsg=NULL;
	struct search_types_arg arg;

	db = (sqlite3 *)(*fsd->dbh);

	if (request_type == SEFS_TYPES) {
		count_stmt = "SELECT count(*) from types";
		select_stmt = "SELECT type_name from types order by type_name";
	} else if (request_type == SEFS_USERS) {
		count_stmt = "SELECT count(*) from users";
		select_stmt = "SELECT user_name from users order by user_name";
	} else if (request_type == SEFS_PATHS) {
		count_stmt = "SELECT count(*) from paths";
		select_stmt = "SELECT path from paths order by path";
	} else if (request_type == SEFS_RANGES) {
		count_stmt = "SELECT count(*) from mls";
		select_stmt = "SELECT mls_range from mls";
	}

	if (request_type != SEFS_OBJECTCLASS) {
		/* first get the number	 */
		sqlite3_exec(db,count_stmt,sefs_count_callback,&list_size,&errmsg);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "SQL error: %s\n", errmsg);
			sqlite3_free(errmsg);
			return NULL;
		}
		if (list_size == 0) {
			/* nothing to report -- but can't return NULL
			 * because that would indicate an error
			 * condition */
			*count_in = 0;
			return malloc(sizeof(char *));
		}
		/* malloc out the memory for the types */
		if ((arg.list = (char **) calloc(list_size, sizeof(char *))) == NULL) {
			fprintf(stderr, "out of memory\n");
			return NULL;
		}
		arg.count = 0;
		rc = sqlite3_exec(db, select_stmt, sefs_search_types_callback, &arg, &errmsg);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "SQL error: %s\n", errmsg);
			sqlite3_free(errmsg);
			return NULL;
		}
		*count_in = list_size;
	} else {
		if ((arg.list = (char **)sefs_get_valid_object_classes(&list_size)) == NULL) {
			fprintf(stderr, "No object classes defined!\n");
			return NULL;
		}
		*count_in = list_size;
	}

	return arg.list;
}

static int sefs_is_mls_callback(void *arg,
				int argc __attribute__ ((unused)),
				char **argv __attribute__ ((unused)),
				char **col_names __attribute__ ((unused)))
{
	/* if this callback is invoked, then there exists a table named "mls" */
	int *answer = (int *) arg;
	*answer = 1;
	return 0;
}

int sefs_filesystem_db_is_mls(sefs_filesystem_db_t *fsd)
{
	int rc, answer = 0;
	db = (sqlite3 *)(*fsd->dbh);
	char *errmsg = NULL;
	const char *select_stmt = "select * from sqlite_master where name='mls'";
	rc = sqlite3_exec(db, select_stmt, sefs_is_mls_callback, &answer, &errmsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		answer = -1;
	}
	return answer;
}

int sefs_filesystem_db_search(sefs_filesystem_db_t *fsd,sefs_search_keys_t *search_keys)
{

	char *stmt = NULL;
	int *object_class = NULL;
	int types_regcomp = 0, users_regcomp = 0, paths_regcomp = 0,
		range_regcomp = 0;
	int db_is_mls = 0;
	int rc, i, ret_val=-1;
	char *errmsg = NULL;
	size_t errmsg_sz;

	db = (sqlite3 *)(*fsd->dbh);
	sefs_search_keys = search_keys;

	/* reset the return data */
	/* here put in our search key destructor if not null */
	sefs_search_keys->search_ret = NULL;

	if (!db) {
		fprintf(stderr,"unable to read db\n");
		goto cleanup;
	}
	if ((db_is_mls = sefs_filesystem_db_is_mls(fsd)) < 0) {
		goto cleanup;
	}

	/* malloc out and set up our object classes as ints*/
	if (search_keys->num_object_class > 0) {
		object_class = (int *)malloc(sizeof(int) * search_keys->num_object_class);
		if (object_class == NULL) {
			fprintf(stderr, "Out of memory.");
			goto cleanup;
		}
		for (i=0; i<search_keys->num_object_class; i++){
			object_class[i] = sefs_get_class_int(search_keys->object_class[i]);
		}
	}


	/* are we searching using regexp? */
	if (search_keys->num_type > 0 && search_keys->do_type_regEx) {
		/* create our comparison functions */
		sqlite3_create_function(db,"sefs_types_compare",2,SQLITE_UTF8,NULL,&sefs_types_compare,NULL,NULL);
		rc = regcomp(&types_re, search_keys->type[0],REG_NOSUB|REG_EXTENDED);
		if (rc != 0) {
			errmsg_sz = regerror(rc, &types_re, NULL, 0);
			if ((errmsg = (char *)malloc(errmsg_sz)) == NULL) {
				fprintf(stderr, "Out of memory.");
				goto cleanup;
			}
			regerror(rc, &types_re, errmsg, errmsg_sz);
			fprintf(stderr, "%s", errmsg);
			goto cleanup;
		}
		else {
			types_regcomp = 1;
		}
	}
	if (search_keys->num_user > 0 && search_keys->do_user_regEx) {
		sqlite3_create_function(db,"sefs_users_compare",2,SQLITE_UTF8,NULL,&sefs_users_compare,NULL,NULL);
		rc = regcomp(&users_re, search_keys->user[0], REG_NOSUB|REG_EXTENDED);
		if (rc != 0) {
			errmsg_sz = regerror(rc, &users_re, NULL, 0);
			if ((errmsg = (char *)malloc(errmsg_sz)) == NULL) {
				fprintf(stderr, "Out of memory.");
				goto cleanup;
			}
			regerror(rc, &users_re, errmsg, errmsg_sz);
			fprintf(stderr, "%s", errmsg);
			goto cleanup;
		}
		else {
			users_regcomp = 1;
		}
	}
	if (search_keys->num_path > 0 && search_keys->do_path_regEx) {
		sqlite3_create_function(db,"sefs_paths_compare",2,SQLITE_UTF8,NULL,&sefs_paths_compare,NULL,NULL);
		rc = regcomp(&paths_re, search_keys->path[0],REG_NOSUB|REG_EXTENDED);
		if (rc != 0) {
			errmsg_sz = regerror(rc, &paths_re, NULL, 0);
			if ((errmsg = (char *)malloc(errmsg_sz)) == NULL) {
				fprintf(stderr, "Out of memory.");
				goto cleanup;
			}
			regerror(rc, &paths_re, errmsg, errmsg_sz);
			fprintf(stderr, "%s", errmsg);
			goto cleanup;
		}
		else {
			paths_regcomp = 1;
		}
	}
	if (db_is_mls && search_keys->num_range > 0 && search_keys->do_range_regEx) {
		sqlite3_create_function(db, "sefs_range_compare", 2, SQLITE_UTF8, NULL, &sefs_range_compare, NULL, NULL);
		rc = regcomp(&range_re, search_keys->range[0], REG_NOSUB|REG_EXTENDED);
		if (rc != 0) {
			errmsg_sz = regerror(rc, &range_re, NULL, 0);
			if ((errmsg = (char *)malloc(errmsg_sz)) == NULL) {
				fprintf(stderr, "Out of memory.");
				goto cleanup;
			}
			regerror(rc, &range_re, errmsg, errmsg_sz);
			fprintf(stderr, "%s", errmsg);
			goto cleanup;
		}
		else {
			range_regcomp = 1;
		}
	}
	if (sefs_stmt_populate(&stmt, search_keys, object_class, db_is_mls)) {
		goto cleanup;
	}
	rc = sqlite3_exec(db, stmt, sefs_search_callback, &db_is_mls, &errmsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		errmsg = NULL;
		ret_val = -1;
	}
	else
		ret_val = 0;

 cleanup:
	/* here we deallocate anything that might need to be */
	free(stmt);
	free(errmsg);
	free(object_class);
	if (types_regcomp)
		regfree(&types_re);
	if (users_regcomp)
		regfree(&users_re);
	if (paths_regcomp)
		regfree(&paths_re);
	if (range_regcomp)
		regfree(&range_re);
	return ret_val;
}

int sefs_filesystem_db_populate(sefs_filesystem_db_t *fsd, const char *dir)
{

	char **mounts = NULL;
	unsigned int num_mounts=0;
	int i;
	sefs_filesystem_data_t *fsdh;
	struct stat fstat;

	assert(dir);
	/* Make sure directory exists */
	if (access(dir, R_OK) != 0) {
		return SEFS_DIR_ACCESS_ERROR;
	}
	if (stat(dir, &fstat) != 0) {
		fprintf(stderr, "Error getting file stats.\n");
		return -1;
	}
	/* Verify it is a directory. */
	if (!S_ISDIR(fstat.st_mode)) {
		return SEFS_NOT_A_DIR_ERROR;
	}
	/* malloc out some memory for the fsdh */
	if ((fsdh = (void *)malloc(1 * sizeof(sefs_filesystem_data_t))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	/* init it so that all the old fcns work right */
	sefs_filesystem_data_init(fsdh);

	sefs_filesystem_find_mount_points(dir, 0, NULL, &mounts, &num_mounts);

	int (*fn)(const char *file, const struct stat64 *sb, int flag, struct FTW *s) = ftw_handler;
	for (i = 0; i < num_mounts; i++ ) {
		if (nftw64(mounts[i],fn,NFTW_DEPTH,NFTW_FLAGS) == -1) {
			fprintf(stderr, "Error scanning tree rooted at %s\n", dir);
			return -1;
		}
	}
	free(mounts);
	if (nftw64(dir, fn, NFTW_DEPTH, NFTW_FLAGS) == -1) {
		fprintf(stderr, "Error scanning tree rooted at %s\n", dir);
		return -1;
	}


	fsd->fsdh = (void *)fsdh;

	return 0;


}

int sefs_filesystem_data_index(sefs_filesystem_data_t * fsd)
{
	int loop = 0, idx = 0 , rc = 0;
	sefs_fileinfo_t * pi = NULL;
	sefs_typeinfo_t * ti = NULL;

	for (loop = 0; loop < fsd->num_files; loop++) {

		pi = &(fsd->files[loop]);

		/* index type */
		idx = apol_avl_get_idx(&(fsd->type_tree), fsd->types[pi->context.type].name);
		if (idx == -1) {
			if ((rc = apol_avl_insert(&(fsd->type_tree),
				fsd->types[pi->context.type].name, &idx)) == -1)
			{
				fprintf(stderr, "avl error\n");
				return -1;
			}

			ti = &(fsd->types[idx]);

			if ((ti->index_list = (uint32_t *)malloc(1 * sizeof(uint32_t))) == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			memset(ti->index_list, 0, 1 * sizeof(uint32_t));

			ti->num_inodes = 0;
			ti->index_list[ti->num_inodes] = loop;
		} else {
			ti = &(fsd->types[idx]);
			ti->num_inodes++;

			ti->index_list[ti->num_inodes] = loop;
		}

	}

	return 0;
}

int sefs_filesystem_db_save(sefs_filesystem_db_t *fsd, const char *filename)
{
	int i, j, rc = 0;
	FILE *fp = NULL;
	sefs_fileinfo_t *pinfo = NULL;
	struct sqlite3 *db = NULL;
	char stmt[100000];
	char *errmsg = NULL;
	char *new_stmt = NULL;
	char hostname[100];
	time_t mytime;

	sefs_filesystem_data_t *fsdh = (sefs_filesystem_data_t *)(fsd->fsdh);


	/* we should have an fsdh by now */
	assert(fsdh != NULL);

	fp = fopen(filename, "w");
	if (!fp) {
		fprintf(stderr, "Error opening save file %s\n", filename);
		return -1;
	}
	fclose(fp);

	/* now open up the file db */
	rc = sqlite3_open(filename, &db);
	if ( rc ) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	/* apply our schema to it, based upon if any of the files had
	 * a MLS range associated with them */
	if (fsdh->fs_had_range) {
		rc = sqlite3_exec(db, DB_SCHEMA_MLS, NULL, 0, &errmsg);
	}
	else {
		rc = sqlite3_exec(db, DB_SCHEMA_NONMLS, NULL, 0, &errmsg);
	}
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error while creating database(%d): %s\n",rc, errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(db);
		return -1;
	}


	/* now we basically just go through the old data struct moving */
	/* the data to the places it should be for our sqlite3 db */
	sprintf(stmt,"BEGIN TRANSACTION");
	rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
	if (rc != SQLITE_OK)
		goto bad;
	for (i=0; i < fsdh->num_types; i++) {
		sprintf(stmt,"insert into types (type_name,type_id) values "
			"(\"%s\",%d);",fsdh->types[i].name,i);
		rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
		if (rc != SQLITE_OK)
			goto bad;

	}
	for (i=0; i < fsdh->num_users; i++) {
		sprintf(stmt,"insert into users (user_name,user_id) values "
			"(\"%s\",%d);",fsdh->users[i],i);

		rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
		if (rc != SQLITE_OK)
			goto bad;
	}
	for (i=0; fsdh->fs_had_range && i < fsdh->num_range; i++) {
		sprintf(stmt,"insert into mls (mls_range,mls_id) values "
			"(\"%s\",%d);", fsdh->range[i], i);
		rc = sqlite3_exec(db, stmt, NULL, 0, &errmsg);
		if (rc != SQLITE_OK)
			goto bad;
	}

	for (i=0; i < fsdh->num_files; i++) {

		pinfo = &(fsdh->files[i]);


		if (pinfo->obj_class == SEFS_LNK_FILE && pinfo->symlink_target) {
			sprintf(stmt,"insert into inodes (inode_id,user,type,range,obj_class,symlink_target,dev,ino"
				") values (%d,%d,%d,%d,%d,'%s',%u,%llu);",
				i,
				pinfo->context.user,
				pinfo->context.type,
				pinfo->context.range,
				pinfo->obj_class,
				pinfo->symlink_target,
				(unsigned int)(pinfo->key.dev),
				(unsigned long long)(pinfo->key.inode));
			rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
			if (rc != SQLITE_OK)
				goto bad;
		}
		else {
			sprintf(stmt,"insert into inodes (inode_id,user,type,range,obj_class,symlink_target,dev,ino"
				") values (%d,%d,%d,%d,%d,'',%u,%llu);",
				i,
				pinfo->context.user,
				pinfo->context.type,
				pinfo->context.range,
				pinfo->obj_class,
				(unsigned int)(pinfo->key.dev),
				(unsigned long long)(pinfo->key.inode));
			rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
			if (rc != SQLITE_OK)
				goto bad;
		}

		for (j = 0; j < pinfo->num_links;  j++) {
			new_stmt = sqlite3_mprintf("insert into paths (inode,path) values (%d,'%q')",
				i,(char *)pinfo->path_names[j]);
			rc = sqlite3_exec(db,new_stmt,NULL,0,&errmsg);
			sqlite3_free(new_stmt);
			if (rc != SQLITE_OK)
				goto bad;
		}

	}
	sprintf(stmt,"END TRANSACTION");
	rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
	if (rc != SQLITE_OK)
		goto bad;
	gethostname(hostname,50);
	time(&mytime);
	sprintf(stmt,"insert into info (key,value) values ('dbversion',1);"
		"insert into info (key,value) values ('hostname','%s');"
		"insert into info (key,value) values ('datetime','%s');"
		,hostname,ctime(&mytime));
	rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
	if (rc != SQLITE_OK)
		goto bad;

	return 0;

bad:
	fprintf(stderr, "SQL error\n\tStmt was :%s\nError was:\t%s\n",stmt, errmsg);
	sqlite3_free(errmsg);
	return -1;
}

void sefs_filesystem_db_close(sefs_filesystem_db_t* fsd)
{

	sefs_filesystem_data_t *fsdh = NULL;
	if (fsd->fsdh) {
		fsdh = (sefs_filesystem_data_t *)(fsd->fsdh);
		destroy_fsdata(fsdh);
		free(fsd->fsdh);
		fsd->fsdh = NULL;
	}
	if (fsd->dbh) {
		db = (sqlite3 *)(*fsd->dbh);
		sqlite3_close(db);
		if (*fsd->dbh)
			*(fsd->dbh) = NULL;
		fsd->dbh = NULL;
	}
}

int sefs_filesystem_db_load(sefs_filesystem_db_t *fsd, const char *filename)
{
	int rc, list_size;
	char *errmsg = NULL;

	assert(filename);
	rc = access(filename, R_OK);
	if (rc != 0) {
		perror("Load file");
		return -1;
	}
	rc = sqlite3_open(filename, &db);
	if (rc) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}
	/* HACK!! Currently, a limitation of sqlite is that is
	 * doesn't check whether the file is a valid sqlite database,
	 * so it may have opened  a corrupt file, so we check this by
	 * executing a simple query statment. */
	rc = sqlite3_exec(db, "SELECT type_name from types", sefs_count_callback, &list_size, &errmsg);
	if (rc == SQLITE_NOTADB) {
		sqlite3_close(db);
		fprintf(stderr, "Can't open database: %s\n", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}
	fsd->dbh = (void *)&db;

	return 0;
}

static void destroy_fsdata(sefs_filesystem_data_t * fsd)
{
	int i,j;

	if (fsd == NULL)
		return;
	/* empty arrays */
	for (i = 0; i < fsd->num_types; i++) {
		free(fsd->types[i].name);
		free(fsd->types[i].index_list);
	}

	for (i = 0; i < fsd->num_users; i++) {
		free(fsd->users[i]);
	}
	for (i = 0; i < fsd->num_range; i++) {
		free(fsd->range[i]);
	}

	for (i = 0; i < fsd->num_files; i++) {
		for (j = 0; j < fsd->files[i].num_links; j++) {
			free(fsd->files[i].path_names[j]);
		}
		free(fsd->files[i].path_names);
		free(fsd->files[i].symlink_target);
	}

	/* kill array pinters*/
	free(fsd->users);
	free(fsd->types);
	free(fsd->files);
	free(fsd->range);

	/* fell trees */
	apol_avl_free(&(fsd->file_tree));
	apol_avl_free(&(fsd->type_tree));
	apol_avl_free(&(fsd->user_tree));
	apol_avl_free(&(fsd->range_tree));
}
