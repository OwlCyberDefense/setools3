/**
 *  @file
 *  Defines the public interface for building a database of file
 *  contexts.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#ifndef SEFS_FSDATA_H
#define SEFS_FSDATA_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <sefs/fshash.h>
#include <stdint.h>
#include <sys/types.h>

/* we need this to handle large files */
#define __USE_LARGEFILE64 1

/* I believe this is necessary for portability */
#define __USE_FILE_OFFSET64 1

#include <sys/stat.h>

#define SEFS_NOT_A_DIR_ERROR	-2
#define SEFS_DIR_ACCESS_ERROR	-3

/* Predefined labels */
#define SEFS_OBJECT_R 0

#define SEFS_NUM_OBJECT_CLASSES 7
#define SEFS_NORM_FILE	1
#define SEFS_DIR	2
#define SEFS_LNK_FILE	4
#define SEFS_CHR_FILE	8
#define SEFS_BLK_FILE	16
#define	SEFS_SOCK_FILE	32
#define SEFS_FIFO_FILE	64

#define SEFS_TYPES	1
#define SEFS_USERS	2
#define SEFS_OBJECTCLASS 3
#define SEFS_PATHS	4
#define SEFS_RANGES	5

	typedef int32_t sefs_classes_t;

	typedef struct sefs_search_ret
	{
		char *context;
		char *path;
		char *object_class;
		struct sefs_search_ret *next;
	} sefs_search_ret_t;

/**
 * The caller is in charge of allocating these 2d arrays, and making
 * sure they are deleted when done.
 */
	typedef struct sefs_search_keys
	{
		/* this are are search keys */
		const char **type;
		const char **user;
		const char **path;
		const char **range;
		const char **object_class;

		/* number of types in array */
		int num_type;
		/* number of users in array */
		int num_user;
		/* number of mls ranges in array */
		int num_range;
		/* number of paths in array */
		int num_path;
		/* number of object classes in array */
		int num_object_class;
		int do_type_regEx;
		int do_user_regEx;
		int do_range_regEx;
		int do_path_regEx;
		/* this is a linked list of returned matches */
		sefs_search_ret_t *search_ret;
	} sefs_search_keys_t;

	typedef struct sefs_filesystem_db
	{
		void *fsdh;
		void **dbh;
	} sefs_filesystem_db_t;

/**
 * Save the database, as referenced by the fsd pointer, to disk.  The
 * file will be an sqlite3 database (and thus accessible by the
 * sqlite3 command line utility).
 *
 * @param fsd Pointer to a structure containing a handle to a database.
 * @param filename Name for the database to save.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see http://www.sqlite.org
 */
	extern int sefs_filesystem_db_save(sefs_filesystem_db_t * fsd, const char *filename);

/**
 * Load an sqlite3 database for a file, presumably that written by an
 * earlier to call to sefs_filesystem_db_save().  The fsd pointer must
 * already be allocated by the caller.  <b>Be aware that only one
 * database may be loaded at a time.</b> (This library is <i>not</i>
 * thread-safe.)
 *
 * @param filename Name of database to load.
 * @param fsd Pointer to a structure that will contain a handle to the
 * database.  The caller must call sefs_filesystem_db_close() to free
 * the memory afterwards.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int sefs_filesystem_db_load(sefs_filesystem_db_t * fsd, const char *filename);

/**
 * Close the database referenced by the fsd pointer, and deallocate
 * all space that was associated with the database.  <b>This function
 * does not free() the pointer itself.</b>
 *
 * @param fsd Pointer to a structure containing a handle to a database.
 */
	extern void sefs_filesystem_db_close(sefs_filesystem_db_t * fsd);

/**
 * Beginning from the given directory and recursing within, populate
 * the database pointed to by fsd with all files/directories and their
 * SELinux contexts.
 *
 * @param dir Directory to begin recursing.
 * @param fsd Pointer to a pre-allocated struct to which write the
 * database.  The caller is responsible for calling
 * sefs_filesystem_db_close() to free the memory afterwards.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int sefs_filesystem_db_populate(sefs_filesystem_db_t * fsd, const char *dir);

/**
 * Given a directory, find all mounted filesystems within that
 * directory (or subdirectory within.)  This function consults the
 * entries written to /etc/mtab to determine if something is mounted
 * or not.  Note that if the directory itself is a mount, it will not
 * be reported; a subdirectory might.
 *
 * @param dir Directory to begin search.
 * @param rw If non-zero, then only process mounts that are mounted as
 * read-write.
 * @param hashtab.  If non-NULL, then insert into the hash table all
 * mounts containing the "bind" option.  This hash table must be first
 * initialized with a call to sefs_hash_init().
 * @param mounts Reference to an array of strings.  The strings will
 * contain pathnames to each mounted location.  If hashtab is NULL,
 * then only non-"bind" mounts will be recorded.  The caller is
 * responsible for free()ing this array and its component strings
 * afterwards.
 * @param num_mounts Reference to the number of strings written to
 * mounts.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int sefs_filesystem_find_mount_points(const char *dir,
						     int rw, sefs_hash_t * hashtab, char ***mounts, unsigned int *num_mounts);

/**
 * Given a pointer to a database and a pointer to search criteria,
 * search through the database and return a linked list of
 * sefs_search_ret objects.  Those results will be stored at the field
 * 'search_ret' within the search keys.  The caller is responsible for
 * deallocating the search results via a call to
 * sefs_search_key_ret_destroy().  The caller is also responsible for
 * managing all memory needed by search_keys and its other fields.
 *
 * @param fsd Pointer to a filesystem database.
 * @param search_keys Parameters for search, and also where to write
 * the search results.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int sefs_filesystem_db_search(sefs_filesystem_db_t * fsd, sefs_search_keys_t * search_keys);

/**
 * Given a database, determine if its entries contain MLS ranges or
 * not.
 *
 * @return 1 if the database is MLS, 0 if not, or < 0 on error.
 */
	extern int sefs_filesystem_db_is_mls(sefs_filesystem_db_t * fsd);

/**
 * Given a pointer to the start of a linked list of search results,
 * free all space associated with that result and the pointer itself.
 * This function will proceed to deallocate the rest of the nodes
 * along the list.
 *
 * @param key Head of a linked list.
 */
	extern void sefs_search_keys_ret_destroy(sefs_search_ret_t * key);

/**
 * Given a pointer to a database and a type of request, return an
 * array of strings containing all of those items within the database.
 *
 * @param fsd Pointer to a filesystem database.
 * @param request_type Thing to return, one of SEFS_TYPES, SEFS_USERS,
 * SEFS_PATHS, SEFS_RANGES, or SEFS_OBJECTCLASS.
 * @param count Reference to the number of strings returned.
 *
 * @return Allocated array of strings.  The caller is responsible for
 * free()ing this array as well as the elements within.
 */
	extern char **sefs_filesystem_db_get_known(sefs_filesystem_db_t * fsd, int request_type, int *count);

/**
 * Given an array of strings, free each element within and then the
 * pointer itself.
 *
 * @param array Array to destroy.
 * @param size Number of elements within the array.
 */
	extern void sefs_double_array_destroy(char **array, int size);

/**
 * Given a pointer to stat64 struct (as generated by something akin to
 * ftw(3)), determine the file's class and return that value.
 *
 * @param statptr Pointer to a struct containing a file entry.
 *
 * @return The file's class, one of SEFS_NORM_FILE, SEFS_DIR, etc.
 */
	extern int sefs_get_file_class(const struct stat64 *statptr);

/**
 * Return a newly allocated array of strings consisting of searchable
 * object classes.  When calling sefs_filesystem_db_search, the search
 * key may not contain classes not within this list.
 *
 * @param size Reference to where to write the number of elements
 * returned.
 *
 * @return Allocated array of strings.  The caller is responsible for
 * free()ing this array as well as the elements within.
 */
	extern char **sefs_get_valid_object_classes(int *size);

/**
 * Given a string, return a non-negative value if it represents a
 * searchable object class.  Otherwise return a negative value.
 *
 * @param Name of a class to validate.
 *
 * @return < 0 if the string is not known, non-negative if known.
 *
 * @see sefs_get_valid_object_classes()
 */
	extern int sefs_is_valid_object_class(const char *class_name);

#ifdef	__cplusplus
}
#endif

#endif				       /* SEFS_FSDATA_H */
