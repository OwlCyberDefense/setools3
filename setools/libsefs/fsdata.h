/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* fsdata.h
 *
 * analysis policy database support header 
 *
 */

#ifndef _FSDATA_H
#define _FSDATA_H



#include <stdint.h>

#include <sys/types.h>
/* we need this to handle large files */
#define __USE_LARGEFILE64 1
/* I believe this is necessary for portability */
#define __USE_FILE_OFFSET64 1
#include <sys/stat.h>


/* Predefined labels */
#define OBJECT_R 0

#define SEFS_NUM_OBJECT_CLASSES 8
#define SEFS_NORM_FILE	1
#define SEFS_DIR		2
#define SEFS_LNK_FILE	4
#define SEFS_CHR_FILE	8
#define SEFS_BLK_FILE	16
#define	SEFS_SOCK_FILE	32
#define SEFS_FIFO_FILE	64
#define SEFS_ALL_FILES	(SEFS_NORM_FILE | SEFS_DIR | SEFS_LNK_FILE | SEFS_CHR_FILE | SEFS_BLK_FILE | SEFS_SOCK_FILE | SEFS_FIFO_FILE)
#define SEFS_TYPES      1
#define SEFS_USERS      2
#define SEFS_OBJECTCLASS 3
#define SEFS_PATHS       4


typedef int32_t sefs_classes_t;

typedef struct sefs_search_ret {
	char                  *context;
	char                  *path;
	char                  *object_class;
	struct sefs_search_ret     *next;

} sefs_search_ret_t;


/*
  the caller is in charge of allocated these 2d arrays, and
  making sure they are deleted when done
*/
typedef struct sefs_search_keys {
	/* this are are search keys */
	const char **type;
	const char **user;
	const char **path;
	const char **object_class;

	/* number of types in array */
	int num_type;                 
	/* number of users in array */              
	int num_user;
	/* number of paths in array */
	int num_path;
	/* number of object classes in array */
	int num_object_class;
	int do_type_regEx;
	int do_user_regEx;
	int do_path_regEx;
	/* this is a linked list of returned matches */
	sefs_search_ret_t      *search_ret;

} sefs_search_keys_t;


typedef struct sefs_filesystem_db {
	void *fsdh;
	void **dbh;
} sefs_filesystem_db_t;


/* SEARCHING THE DB??? use db_load to load a created file fsd allocated by caller*/
int sefs_filesystem_db_load(sefs_filesystem_db_t *fsd,char *filename);
/*  close an open db */
int sefs_filesystem_db_close(sefs_filesystem_db_t *fsd);
/* SAVING AN INDEXFILE?? fsd allocated by caller*/
int sefs_filesystem_db_save(sefs_filesystem_db_t *fsd,char *filename);
/* CREATING AN INDEXFILE??? fsd allocated by caller*/
int sefs_filesystem_db_populate(sefs_filesystem_db_t *fsd,char *dir);
/* SEARCH THE LOADED FILE fsd,search_keys allocated by caller search_keys->search_ret is not!!!*/
int sefs_filesystem_db_search(sefs_filesystem_db_t *fsd,sefs_search_keys_t *search_keys);
/* destroy the dynamically allocated return data from search */
int sefs_search_keys_ret_destroy(sefs_search_ret_t *key);
/* print the return data from a search */
void sefs_search_keys_ret_print(sefs_search_ret_t *key);
/* this will return all the known types in the context parameter */
char **sefs_filesystem_db_get_known(sefs_filesystem_db_t *fsd,int *count,int request_type);

int sefs_double_array_destroy(char **array,int size);

/* find the mount points */
int find_mount_points(char *dir, char ***mounts, int *num_mounts, int rw);

/* object classes */
int sefs_get_file_class(const struct stat64 *statptr);
char **sefs_get_valid_object_classes(int *size);
int sefs_is_valid_object_class(const char *class_name);

#endif /* _FSDATA_H */

