/* Copyright (C) 2003-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* fsdata.c
 *
 * analysis policy database filesystem functions 
 *
 */


#include "fsdata.h"
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

/* AVL Tree Handling */
#include <policy.h>
#include <avl-util.h>

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

#define STMTSTART "SELECT types.type_name,users.user_name, paths.path, inodes.obj_class from inodes,types,users,paths where "
#define STMTEND " inodes.user = users.user_id  AND paths.inode = inodes.inode_id AND types.type_id = inodes.type"
#define SORTSTMT  " ORDER BY paths.path ASC"

#define STMTHOLDERSIZE 100000

typedef struct inode_key {
	ino_t			inode;
	dev_t			dev;
} inode_key_t;

typedef struct sefs_fileinfo {
	inode_key_t		key;
	uint32_t		num_links;
	security_con_t		context;
	char **			path_names;
	char * 			symlink_target;
/* this uses defines from above */
	uint32_t		obj_class;
} sefs_fileinfo_t;


typedef struct sefs_typeinfo {
	char*			name;
	uint32_t 		num_inodes;
	uint32_t *		index_list;
} sefs_typeinfo_t;
	

typedef struct sefs_filesystem_data {
	uint32_t 		num_types;
	uint32_t		num_users;
	uint32_t 		num_files;
	sefs_typeinfo_t *	types;
	sefs_fileinfo_t *	files;
	char**			users;

	/* not stored in index file */
	avl_tree_t		file_tree;
	avl_tree_t		type_tree;
	avl_tree_t		user_tree;
} sefs_filesystem_data_t;




/* Management and creation functions */
void sefs_types_compare(sqlite3_context *context, int argc, sqlite3_value **argv);
void sefs_users_compare(sqlite3_context *context, int argc, sqlite3_value **argv);
void sefs_paths_compare(sqlite3_context *context, int argc, sqlite3_value **argv);
int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd);
int sefs_filesystem_data_index(sefs_filesystem_data_t * fsd);
int sefs_scan_tree(char * dir);
void destroy_fsdata(sefs_filesystem_data_t * fsd);
int sefs_get_class_int(const char *class);


int add_uint_to_a(uint32_t i, uint32_t *cnt, uint32_t **a);
const char * sefs_get_class_string( int flag_val);

/* handle statement */
static int sefs_calc_search_size(const char *st,const char **arr,int size);
static int sefs_calc_stmt_size(sefs_search_keys_t *search_keys);
static void sefs_stmt_populate(char *stmt,sefs_search_keys_t *search_keys,int *objects,int stmt_size);


/* our main sqlite db struct */
struct sqlite3 *db;
/* this is the struct that has sqlite and the old data struct */
static sefs_filesystem_data_t *fsdata = NULL;
/* this is the search key stuff */
sefs_search_keys_t *sefs_search_keys = NULL;
sefs_search_ret_t *sefs_search_ret = NULL;
/* list and list size are used for passing back known contexts */
/* and paths */
char **list;
int list_size;

/* these are precompiled regular expressions */
regex_t types_re;
regex_t users_re;
regex_t paths_re;


#define DB_SCHEMA "CREATE TABLE types ( \
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
                           dev  int, \
                           ino  int(64), \
		           user int, \
		           type int, \
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



const char *sefs_object_classes[] =
    { "file", "dir", "lnk_file", "chr_file", "blk_file", "sock_file",
"fifo_file", "all_files" };


static int sefs_count_callback(void *NotUsed, int argc, char **argv, char **azColName) 
{
	int *count = (int *)NotUsed;
	*count = atoi(argv[0]);
	return 0;
}


static void sefs_stmt_populate(char *stmt,sefs_search_keys_t *search_keys,int *objects,int stmt_size) 
{
	int index;
	/* we'll guess that 1000 is enough to hold a portion of our statment */
	char stmt_holder[100000];
	int stmt_length = stmt_size/sizeof(char);
	int stmt_curr_length = 0;

	/* at this point stmt should be empty but better make sure */
	bzero(stmt,stmt_size);	
	/* first put the starting statement */
	sprintf(stmt,"%s ",STMTSTART);
	
	/* now we go through the search keys populating the statement */
	/* type,user,path,object_class */
	index = 0;		
	if (search_keys->type && search_keys->num_type > 0){
		strcat(stmt,"( ");
		bzero(stmt_holder,STMTHOLDERSIZE);	
		stmt_curr_length = strlen(stmt);
		if (search_keys->do_type_regEx) 
			sprintf(stmt_holder," sefs_types_compare(types.type_name,\"%s\") ",search_keys->type[index]);
		else
			sprintf(stmt_holder," types.type_name = \"%s\" ",search_keys->type[index]);
		strncat(stmt,stmt_holder,stmt_length-stmt_curr_length);
		index += 1;
		while (search_keys->type && index < search_keys->num_type){
			bzero(stmt_holder,STMTHOLDERSIZE);	
			stmt_curr_length = strlen(stmt);
			if (search_keys->do_type_regEx) 
				sprintf(stmt_holder," OR sefs_types_compare(types.type_name,\"%s\")  ",search_keys->type[index]);
			else 
				sprintf(stmt_holder," OR types.type_name = \"%s\" ",search_keys->type[index]);
			strncat(stmt,stmt_holder,stmt_length-stmt_curr_length);
			index += 1;
		}
		strcat(stmt," ) AND ");
	}
		
	index = 0;
	if (search_keys->user && search_keys->num_user > 0){
		strcat(stmt,"( ");
		bzero(stmt_holder,STMTHOLDERSIZE);	
		stmt_curr_length = strlen(stmt);
		if (search_keys->do_user_regEx) 
			sprintf(stmt_holder," sefs_users_compare(users.user_name,\"%s\") ",search_keys->user[index]);
		else 
			sprintf(stmt_holder," users.user_name = \"%s\" ",search_keys->user[index]);
		strncat(stmt,stmt_holder,stmt_length-stmt_curr_length);
		index += 1;
		while (search_keys->user && index < search_keys->num_user){
			bzero(stmt_holder,STMTHOLDERSIZE);	
			stmt_curr_length = strlen(stmt);
			if (search_keys->do_user_regEx) 
				sprintf(stmt_holder," OR sefs_users_compare(users.user_name,\"%s\") ",search_keys->user[index]);
			else 
				sprintf(stmt_holder," OR users.user_name = \"%s\" ",search_keys->user[index]);
			strncat(stmt,stmt_holder,stmt_length-stmt_curr_length);
			index += 1;
		}
		strcat(stmt," ) AND ");
	}
	index = 0;
	if (search_keys->path && search_keys->num_path > 0){
		strcat(stmt,"( ");
		bzero(stmt_holder,STMTHOLDERSIZE);	
		stmt_curr_length = strlen(stmt);
		if (search_keys->do_path_regEx) 
			sprintf(stmt_holder," sefs_paths_compare(paths.path,\"%s\") ",search_keys->path[index]);
		else 
			sprintf(stmt_holder," paths.path = \"%s\" ",search_keys->path[index]);
		strncat(stmt,stmt_holder,stmt_length-stmt_curr_length);
		index += 1;
		while (search_keys->user && index < search_keys->num_path){
			bzero(stmt_holder,STMTHOLDERSIZE);	
			stmt_curr_length = strlen(stmt);
			if (search_keys->do_path_regEx) 
				sprintf(stmt_holder," OR sefs_paths_compare(paths.path,\"%s\") ",search_keys->path[index]);
			else 
				sprintf(stmt_holder," OR paths.path = \"%s\" ",search_keys->path[index]);
			strncat(stmt,stmt_holder,stmt_length-stmt_curr_length);
			index += 1;
		}
		strcat(stmt," ) AND ");
	}
	
	index = 0;
	if (search_keys->object_class && search_keys->num_object_class > 0){
		strcat(stmt,"( ");
		bzero(stmt_holder,STMTHOLDERSIZE);	
		stmt_curr_length = strlen(stmt);
		sprintf(stmt_holder," inodes.obj_class = %d ",objects[index]);
		strncat(stmt,stmt_holder,stmt_length-stmt_curr_length);
		index += 1;
		while (search_keys->object_class && index < search_keys->num_object_class){
			bzero(stmt_holder,STMTHOLDERSIZE);	
			stmt_curr_length = strlen(stmt);
			sprintf(stmt_holder," OR inodes.obj_class = %d ",objects[index]);
			strncat(stmt,stmt_holder,stmt_length-stmt_curr_length);
			index += 1;
		}
		strcat(stmt," ) AND ");
	}
	
	stmt_curr_length = strlen(stmt);
	strncat(stmt,STMTEND,stmt_length-stmt_curr_length);
	stmt_curr_length = strlen(stmt);
	/* now put sort statement on the end */
	strncat(stmt,SORTSTMT,stmt_length-stmt_curr_length);
}


static int sefs_calc_search_size(const char *str,const char **arr,int size)
{
	int i,tot_size = 0;
	tot_size += (strlen(str)+1)*size*sizeof(char);
	for ( i=0; i<size; i++) {
		tot_size += (strlen(arr[i])*sizeof(char));
	}

	return tot_size;
}

static int sefs_calc_stmt_size(sefs_search_keys_t *search_keys)
{
	/* first set the size to our normal select options */
	int total_size = (strlen(STMTSTART)*sizeof(char));
	
	
	if (search_keys->num_type != 0) {
		if (search_keys->do_type_regEx) 
			total_size += sefs_calc_search_size(" () AND sefs_types_compare(types.type_name,\"%s\") OR   ",search_keys->type,search_keys->num_type);
		else 
			total_size += sefs_calc_search_size(" () AND types.type_name = \"\" OR ",search_keys->type,search_keys->num_type);
	}
	if (search_keys->num_user != 0) {
		if (search_keys->do_user_regEx) 
			total_size += sefs_calc_search_size(" () AND sefs_users_compare(users.user_name,\"%s\") OR   ",search_keys->user,search_keys->num_user);
		else 
			total_size += sefs_calc_search_size(" () AND users.users_name = OR \"\"  ",search_keys->user,search_keys->num_user);
	}
	if (search_keys->num_path != 0) {
		if (search_keys->do_path_regEx) 
			total_size += sefs_calc_search_size(" () AND sefs_paths_compare(paths.path,\"%s\") OR    ",search_keys->path,search_keys->num_path);
		else 
			total_size += sefs_calc_search_size(" () AND paths.path = OR \"\"  ",search_keys->path,search_keys->num_path);
	}

	if (search_keys->object_class) 
		total_size += sefs_calc_search_size(" () AND inodes.obj_class = OR ",search_keys->object_class,search_keys->num_object_class);
 	total_size += (strlen(STMTEND)*sizeof(char));
 	total_size += (strlen(SORTSTMT)*sizeof(char));
	
	return total_size;
}

static int sefs_search_types_callback(void *NotUsed, int argc, char **argv, char **azColName) 
{
	int *count = (int *)NotUsed;
	/* lets create memory and copy over*/
	if ((list[*count] = (char *)malloc((strlen(argv[0]) +1)* sizeof(char))) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}
	strncpy(list[*count], argv[0],strlen(argv[0]));
	list[*count][strlen(argv[0])] = '\0';			
	*count += 1;

	return 0;
}

static int sefs_search_callback(void *NotUsed, int argc, char **argv, char **azColName) 
{
	int i;
	char retholder[10000];
	sefs_search_ret_t *search_ret=NULL;
	const char *class_string;


	/* first lets generate a ret struct */
	if ((search_ret = (sefs_search_ret_t *)malloc(1 * sizeof(sefs_search_ret_t))) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}

	/* set next to null */
	search_ret->next = NULL;

	/* next lets add in the context */
	sprintf(retholder,"%s:object_r:%s",argv[1],argv[0]);
	if ((search_ret->context = (char *)malloc((strlen(retholder) +1)* sizeof(char))) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}
	strncpy(search_ret->context, retholder,strlen(retholder));
	search_ret->context[strlen(retholder)] = '\0';			


	/* next we add in the path */
	if ((search_ret->path = (char *)malloc((strlen(argv[2]) +1)* sizeof(char))) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}
	strncpy(search_ret->path, argv[2],strlen(argv[2]));
	search_ret->path[strlen(argv[2])] = '\0';			


	/* finally its object class */
	i = atoi(argv[3]);
	class_string = sefs_get_class_string(atoi(argv[3]));
	if ((search_ret->object_class = (char *)malloc((strlen(class_string) + 1) * sizeof(char))) == 0) {
		fprintf(stderr,"Out of memory\n");
		return 1;
	}
	strncpy(search_ret->object_class,class_string, strlen(class_string));
	search_ret->object_class[strlen(class_string)] = '\0';			
	    

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
void sefs_types_compare(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int retVal=0;
	const unsigned char *text;
	regmatch_t pm;

      	/* make sure we got the arguments */
	assert(argc == 2);

	/* make sure we got the right kind of argument */
	if (sqlite3_value_type(argv[0]) == SQLITE_TEXT) {
		text = sqlite3_value_text(argv[0]);	
		if (regexec (&types_re,text, 1, &pm, 0) == 0) 
			retVal = 1;
	}
	sqlite3_result_int(context,retVal);
}

/* compare a user_name value with a precompiled regular expression */
void sefs_users_compare(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int retVal=0;
 	const unsigned char *text;
	regmatch_t pm;
      	/* make sure we got the arguments */
	assert(argc == 2);

	/* make sure we got the right kind of argument */
	if (sqlite3_value_type(argv[0]) == SQLITE_TEXT) {
		text = sqlite3_value_text(argv[0]);
		/* if we aren't using regular expressions just match them up */
		if (regexec (&users_re,text, 1, &pm, 0) == 0){
			retVal = 1;
		}
	}
	sqlite3_result_int(context,retVal);
}

/* compare a path value with a precompiled regular expression */
void sefs_paths_compare(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int retVal=0;
	const unsigned char *text;
	regmatch_t pm;

      	/* make sure we got the arguments */
	assert(argc == 2);

	/* make sure we got the right kind of argument */
	if (sqlite3_value_type(argv[0]) == SQLITE_TEXT) {
		text = sqlite3_value_text(argv[0]);
		if (regexec (&paths_re,text, 1, &pm, 0) == 0)
			retVal = 1;
	}
	sqlite3_result_int(context,retVal);
}

/* return the define of the object class */
int sefs_get_class_int(const char *class)
{
	if (strcmp(class,"file") == 0) 
		return NORM_FILE;
	else if (strcmp(class,"dir") == 0) 
		return DIR;
	else if (strcmp(class,"lnk_file") == 0) 
		return LNK_FILE;
	else if (strcmp(class,"chr_file") == 0) 
		return CHR_FILE;
	else if (strcmp(class,"blk_file") == 0) 
		return BLK_FILE;
	else if (strcmp(class,"sock_file") == 0) 
		return SOCK_FILE;
	else if (strcmp(class,"fifo_file") == 0) 
		return FIFO_FILE;
	else if (strcmp(class,"all_files") == 0) 
		return ALL_FILES;
	else return -1;

}

/* returns string from above array */
const char * sefs_get_class_string( int flag_val)
{
	switch (flag_val) {
		case  NORM_FILE:
			return sefs_object_classes[0];
		case  DIR:
			return sefs_object_classes[1];
		case  LNK_FILE:
			return sefs_object_classes[2];
		case  CHR_FILE:
			return sefs_object_classes[3];
		case  BLK_FILE:
			return sefs_object_classes[4];
		case  SOCK_FILE:
			return sefs_object_classes[5];
		case  FIFO_FILE:
			return sefs_object_classes[6];
		default:
			return sefs_object_classes[7];
	}
}


/*
 * sefs_get_file_class
 *
 * Determines the file's class, and returns it
 */
int sefs_get_file_class(const struct stat64 *statptr)
{
	assert(statptr != NULL);
	if (S_ISREG(statptr->st_mode))
		return NORM_FILE;
	if (S_ISDIR(statptr->st_mode))
		return DIR;
	if (S_ISLNK(statptr->st_mode))
		return LNK_FILE;
	if (S_ISCHR(statptr->st_mode))
		return CHR_FILE;
	if (S_ISBLK(statptr->st_mode))
		return BLK_FILE;
	if (S_ISSOCK(statptr->st_mode))
		return SOCK_FILE;
	if (S_ISFIFO(statptr->st_mode))
		return FIFO_FILE;
	return ALL_FILES;
}

int find_mount_points(char *dir, char ***mounts, int *num_mounts, int rw) 
{
	FILE *mtab = NULL;
	int nel = 0, len = 10;
	struct mntent *entry;
	security_context_t con;	


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
			continue;
		}

		nel = strlen(dir);
		if (nel > 1) {
			if (dir[nel - 1] == '/')
				dir[nel - 1] = '\0';
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

int sefs_double_array_destroy(char **array,int size)
{
	int i;
	for (i=0;i<size;i++){
		free(array[i]);
	}
	free(array);
	return 0;
}
void sefs_double_array_print(char **array,int size)
{
	int i;
	for (i=0;i<size;i++){
		printf("%s\n",array[i]);
	}

}


void sefs_search_keys_ret_print(sefs_search_ret_t *key) 
{
	sefs_search_ret_t *curr = NULL;

	/* walk the linked list  */
	curr = key;
	while (curr) {
		if (curr->context)
			printf("%s\t",curr->context);
		if (curr->object_class)
			printf("%s\t",curr->object_class);
		if (curr->path)
			printf("%s",curr->path);
		printf("\n");
		curr = curr->next;
	}
}



int sefs_search_keys_ret_destroy(sefs_search_ret_t *key) 
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
	return 0;
}


static int ftw_handler(const char *file, const struct stat64 *sb, int flag, struct FTW *s)
{
	inode_key_t key;
	int idx, rc = 0;
	sefs_fileinfo_t * pi = NULL;
	char *con = NULL;
	char *tmp = NULL;
	char *tmp2 = NULL; 
	char** ptr = NULL;
		
	
	key.inode = sb->st_ino;
	key.dev = sb->st_dev;
	
	
	idx = avl_get_idx(&key, &(fsdata->file_tree));
	
	if (idx == -1) {
		if ((rc = avl_insert(&(fsdata->file_tree), &key, &idx)) == -1) {
			fprintf(stderr, "avl error\n");
			return -1;
		}
		
		pi = &(fsdata->files[idx]);
		(pi->num_links) = 0;
		
		/* Get the file context. Interrogate the link itself, not the file it points to. */
		rc = lgetfilecon(file, &con);
		if (con)
			tmp = strtok(con, ":");
		if (tmp) {
			rc = avl_get_idx(tmp, &fsdata->user_tree);
			if (rc == -1) {
				tmp2 = (char*)malloc(sizeof(char) * (strlen(tmp) + 1));
				if (!tmp2) {
					fprintf(stderr, "Out of memory\n");
					return -1;
				}
				strncpy(tmp2, tmp, sizeof(char) * strlen(tmp));
				tmp2[strlen(tmp)] = '\0';			
				avl_insert(&(fsdata->user_tree),tmp2, &rc);
			}
			pi->context.user=rc;
		}
		else {
			rc = avl_get_idx(SEFS_XATTR_UNLABELED, &fsdata->user_tree);
                        if (rc == -1) {
				tmp2 = (char*)malloc(sizeof(char) * (strlen(SEFS_XATTR_UNLABELED) + 1));
				if (!tmp2) {
					fprintf(stderr, "Out of memory\n");
					return -1;
				}
				strncpy(tmp2, SEFS_XATTR_UNLABELED, sizeof(char) * strlen(SEFS_XATTR_UNLABELED));
				tmp2[strlen(SEFS_XATTR_UNLABELED)] = '\0';			
				avl_insert(&(fsdata->user_tree), tmp2, &rc);
			}
			pi->context.user=rc;
		}
		if (con)
			tmp = strtok(NULL, ":");
		if (tmp) {
			if (strncmp(tmp, "object_r", 8) == 0)
				pi->context.role = OBJECT_R;
			else
				pi->context.role = 0;
				/* FIXME ^ this is bad */
		} else
			pi->context.role = 0;
			/* FIXME ^ this is bad */
		if (con)
			tmp = strtok(NULL, ":");
		if (tmp) {
			rc = avl_get_idx(tmp, &fsdata->type_tree);
			if (rc == -1) {
				tmp2 = (char*)malloc(sizeof(char) * (strlen(tmp) + 1));
				if (!tmp2) {
					fprintf(stderr, "Out of memory\n");
					return -1;
				}
				strncpy(tmp2, tmp, sizeof(char) * strlen(tmp));
				tmp2[strlen(tmp)] = '\0';
				avl_insert(&(fsdata->type_tree), tmp2, &rc);
			}
			pi->context.type=(int32_t)rc;
		} else {
			rc = avl_get_idx(SEFS_XATTR_UNLABELED, &fsdata->type_tree);
			if (rc == -1) {
				tmp2 = (char*)malloc(sizeof(char) * (strlen(SEFS_XATTR_UNLABELED) + 1));
				if (!tmp2) {
					fprintf(stderr, "Out of memory\n");
					return -1;
				}
				strncpy(tmp2, SEFS_XATTR_UNLABELED, sizeof(char) * strlen(SEFS_XATTR_UNLABELED));
				tmp2[strlen(SEFS_XATTR_UNLABELED)] = '\0';
				avl_insert(&(fsdata->type_tree), tmp2, &rc);
			}
			pi->context.type = rc;
		}
	} else {
		pi = &(fsdata->files[idx]);
	}	

	if (con)
		free(con);

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
		if (!(tmp = (char*)calloc((PATH_MAX + 1), sizeof(char)) ))
		{
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		readlink(file, tmp, (PATH_MAX + 1) * sizeof(char)); 
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
			pi->symlink_target = tmp;
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

	avl_init(&(fsd->file_tree),
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

	avl_init(&(fsd->type_tree),
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

	avl_init( &(fsd->user_tree),
		(void*)fsd,
		avl_user_compare,
		avl_grow_user_array,
		avl_add_user);

	return 0;
}

int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd)
{
	if (fsd == NULL) {
		fprintf(stderr, "Invalid structure\n");
		return -1;
	}
	
	fsdata = fsd;
	fsd->num_files = 0;
	fsd->num_types = 0;
	fsd->num_users = 0;
	fsd->files = NULL;
	fsd->types = NULL;
	fsd->users = NULL;
	
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

	return 0;
}

/*
 * sefs_is_valid_object_class
 *
 * Determines if class_name is a valid object class.  Return -1 if invalid
 * otherwise the index of the valid object class
 */
int sefs_is_valid_object_class(const char *class_name)
{
	int i;
	
	assert(class_name != NULL);
	for (i = 0; i < NUM_OBJECT_CLASSES; i++)
		if (strcmp(class_name, sefs_object_classes[i]) == 0)
			return i;
	return -1;
}

/*
 * sefs_get_valid_object_classes
 *
 *  returns the valid object classes to specify for the search.
 */
char **sefs_get_valid_object_classes(int *size)
{
	int i, num_objs_on_line = 0;
	char **local_list = NULL;
	
	assert(sefs_object_classes != NULL);


	/* malloc out the memory for the types */
	if ((local_list = (char **)malloc(NUM_OBJECT_CLASSES * sizeof(char *))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	for (i = 0; i < NUM_OBJECT_CLASSES; i++) {
		num_objs_on_line++;
		if ((local_list[i] = (char *)malloc((strlen(sefs_object_classes[i])+1) * sizeof(char))) == NULL){
			sefs_double_array_destroy(local_list,i);
			fprintf(stderr,"out of memory\n");
			return NULL;
		}
		strncpy(local_list[i],sefs_object_classes[i],strlen(sefs_object_classes[i]));
		local_list[i][strlen(sefs_object_classes[i])] = '\0';
	}
	*size = NUM_OBJECT_CLASSES;
	return local_list;
}

char **sefs_filesystem_db_get_known(sefs_filesystem_db_t *fsd,int *count_in,int request_type)
{
	unsigned char count_stmt[1000];
	unsigned char select_stmt[1000];
	int rc=0;
	char *errmsg=NULL;
	int count=0;

	db = (sqlite3 *)(*fsd->dbh);

	if (request_type == SEFS_TYPES) {
		sprintf(count_stmt,"SELECT count(*) from types");
		sprintf(select_stmt,"SELECT type_name from types");
	} else if (request_type == SEFS_USERS) {
		sprintf(count_stmt,"SELECT count(*) from users");
		sprintf(select_stmt,"SELECT user_name from users");
	} else if (request_type == SEFS_PATHS) {
		sprintf(count_stmt,"SELECT count(*) from paths");
		sprintf(select_stmt,"SELECT path from paths");
	} 
	
	if (request_type != SEFS_OBJECTCLASS) {
		/* first get the number  */
		sqlite3_exec(db,count_stmt,sefs_count_callback,&list_size,&errmsg);
		if (rc != SQLITE_OK) {
			printf("unable to select because\n%s\n",errmsg);
			return NULL;
		}
		/* malloc out the memory for the types */
		if ((list = (char **)malloc(list_size * sizeof(char *))) == NULL) {
			fprintf(stderr, "out of memory\n");
			return NULL;
		}
		memset(list, 0, list_size * sizeof(char *));
		
		rc = sqlite3_exec(db,select_stmt,sefs_search_types_callback,&count,&errmsg);
		if (rc != SQLITE_OK) {
			printf("unable to select because\n%s\n",errmsg);
			return NULL;
		}
		*count_in = list_size;
	} else {
		if ((list = (char **)sefs_get_valid_object_classes(&list_size)) == NULL) {
			fprintf(stderr, "No object classes defined!\n");
			return NULL;
		}
		*count_in = list_size;
	}
	
	return list;

}

int sefs_filesystem_db_search(sefs_filesystem_db_t *fsd,sefs_search_keys_t *search_keys)
{
	
	unsigned char *stmt = NULL;
	int *object_class = NULL;
	int rc, sz, i, ret_val=0;
	int stmt_size = 0;
	char *errmsg = NULL;

	db = (sqlite3 *)(*fsd->dbh);
	sefs_search_keys = search_keys;

	/* malloc out the memory needed for stmt */
	stmt_size = sefs_calc_stmt_size(search_keys);
	stmt = (char *)malloc(stmt_size);
	if (stmt == NULL) {
		fprintf(stderr, "Out of memory.");
		return -1;
	}
	
	/* reset the return data */
	/* here put in our search key destructor if not null */
	sefs_search_keys->search_ret = NULL;

	if (!db)
		fprintf(stderr,"unable to read db\n");

	/* malloc out and set up our object classes as ints*/
	if (search_keys->num_object_class != 0) {
		object_class = (int *)malloc(sizeof(int) * search_keys->num_object_class);
		if (object_class == NULL) {
			fprintf(stderr, "Out of memory.");
			return -1;
		}
		for (i=0; i<search_keys->num_object_class; i++){ 
			if (sefs_is_valid_object_class(search_keys->object_class[i]) != -1){
				object_class[i] = sefs_get_class_int(search_keys->object_class[i]);
			}
			else {
				ret_val = -1;
				fprintf(stderr, "Invalid object class provided!\n");
				goto done_search;
			}
		}
	}


	/* are we searching using regexp? */
	if (search_keys->do_type_regEx) {
		/* create our comparison functions */
		sqlite3_create_function(db,"sefs_types_compare",2,SQLITE_UTF8,NULL,&sefs_types_compare,NULL,NULL);
		/* create our compiled regular expressions and our search string*/
		if (search_keys->type) {
			rc = regcomp(&types_re, search_keys->type[0],REG_NOSUB|REG_EXTENDED);
			if (rc != 0) {
				sz = regerror(rc, &types_re, NULL, 0);
				if ((errmsg = (char *)malloc(++sz)) == NULL) {
					fprintf(stderr, "Out of memory.");
					return -1;
				}
				regerror(rc, &types_re, errmsg, sz);
				regfree(&types_re);
				fprintf(stderr, "%s", errmsg);
				free(errmsg);
				return -1;
			}
		}
	} 
	if (search_keys->do_user_regEx) {
		sqlite3_create_function(db,"sefs_users_compare",2,SQLITE_UTF8,NULL,&sefs_users_compare,NULL,NULL);
		if (search_keys->user) {
			rc = regcomp(&users_re, search_keys->user[0], REG_NOSUB|REG_EXTENDED);
			if (rc != 0) {
				sz = regerror(rc, &users_re, NULL, 0);
				if ((errmsg = (char *)malloc(++sz)) == NULL) {
					fprintf(stderr, "Out of memory.");
					return -1;
				}
				regerror(rc, &users_re, errmsg, sz);
				regfree(&users_re);
				fprintf(stderr, "%s", errmsg);
				free(errmsg);
				return -1;
			}
		}
	}
	if (search_keys->do_path_regEx) {
		sqlite3_create_function(db,"sefs_paths_compare",2,SQLITE_UTF8,NULL,&sefs_paths_compare,NULL,NULL);
		if (search_keys->path) {
			rc = regcomp(&paths_re, search_keys->path[0],REG_NOSUB|REG_EXTENDED);
			if (rc != 0) {
				sz = regerror(rc, &paths_re, NULL, 0);
				if ((errmsg = (char *)malloc(++sz)) == NULL) {
					fprintf(stderr, "Out of memory.");
					return -1;
				}
				regerror(rc, &paths_re, errmsg, sz);
				regfree(&paths_re);
				fprintf(stderr, "%s", errmsg);
				free(errmsg);
				return -1;
			}
		}
	}		
	sefs_stmt_populate(stmt,search_keys,object_class,stmt_size); 

	rc = sqlite3_exec(db,stmt,sefs_search_callback,0,&errmsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", errmsg);
		ret_val = -1;
	}
	else
		ret_val = 0;
 done_search:

	/* here we deallocate anything that might need to be */
	if (stmt)
		free(stmt);
	if (object_class)
		free(object_class);

	return ret_val;

}

int sefs_filesystem_db_populate(sefs_filesystem_db_t *fsd, char *dir)
{

	char **mounts = NULL;
	int num_mounts=0;
	int i;
	sefs_filesystem_data_t *fsdh;

	/* malloc out some memory for the fsdh */
	if ((fsdh = (void *)malloc(1 * sizeof(sefs_filesystem_data_t))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	/* init it so that all the old fcns work right */
	sefs_filesystem_data_init(fsdh);

	find_mount_points(dir,&mounts,&num_mounts, 0);

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
		idx = avl_get_idx(fsd->types[pi->context.type].name, &(fsd->type_tree));
		if (idx == -1) {
			if ((rc = avl_insert(&(fsd->type_tree), 
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


int sefs_filesystem_db_save(sefs_filesystem_db_t *fsd, char *filename)
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
		fprintf(stderr, "Error opening file %s\n", filename);
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

	/* apply our schema to it */
	rc = sqlite3_exec(db, DB_SCHEMA, NULL, 0, &errmsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error while creating database(%d): %s\n",rc, errmsg);
		sqlite3_close(db);
		return -1;
	}


	/* now we basically just go through the old data struct moving */
	/* the data to the places it should be for our sqlite3 db */
	sprintf(stmt,"BEGIN TRANSACTION");  
	rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);

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

	for (i=0; i < fsdh->num_files; i++) {

		pinfo = &(fsdh->files[i]);


		if (pinfo->obj_class == LNK_FILE && pinfo->symlink_target) {	    
			sprintf(stmt,"insert into inodes (inode_id,user,type,obj_class,symlink_target,dev,ino"
				") values (%d,%d,%d,%d,'%s',%u,%llu);",i,pinfo->context.user,
				pinfo->context.type,pinfo->obj_class,
				pinfo->symlink_target,(unsigned int)(pinfo->key.dev),
				(unsigned long long)(pinfo->key.inode));  
			rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
			if (rc != SQLITE_OK) 
				goto bad;
		}
		else {
			sprintf(stmt,"insert into inodes (inode_id,user,type,obj_class,symlink_target,dev,ino"
				") values (%d,%d,%d,%d,'',%u,%llu);",i,pinfo->context.user,
			        pinfo->context.type,pinfo->obj_class,
				(unsigned int)(pinfo->key.dev),(unsigned long long)(pinfo->key.inode));  
			rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);
			if (rc != SQLITE_OK) 
				goto bad;
		}
	
		for (j = 0; j < pinfo->num_links;  j++) {
			new_stmt = sqlite3_mprintf("insert into paths (inode,path) values (%d,'%q')",
				i,(char *)pinfo->path_names[j]);
			rc = sqlite3_exec(db,new_stmt,NULL,0,&errmsg);
			if (rc != SQLITE_OK) 
				goto bad;
			sqlite3_free(new_stmt);
		}

	}
	sprintf(stmt,"END TRANSACTION");  
	rc = sqlite3_exec(db,stmt,NULL,0,&errmsg);

 	gethostname(hostname,50);
	time(&mytime);
	sprintf(stmt,"insert into info (key,value) values ('dbversion',1);"
		"insert into info (key,value) values ('hostname','%s');"
		"insert into info (key,value) values ('datetime','%s');"	
		,hostname,ctime(&mytime));

	
	sefs_filesystem_db_close(fsd);
	return 0;

	bad:

		fprintf(stderr, "SQL error\n\tStmt was :%s\nError was:\t%s\n",stmt, errmsg);
		sefs_filesystem_db_close(fsd);
		return -1;
}

int sefs_filesystem_db_close(sefs_filesystem_db_t* fsd)
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
	return 0;
}

/* load an sqlite3 db from a file */
int sefs_filesystem_db_load(sefs_filesystem_db_t* fsd, char *file)
{
	int rc;
	
	assert(file);
	
	rc = access(file, R_OK);
	if (rc != 0) {
		perror("access");
		return -1;
     	}
	rc = sqlite3_open(file, &db);
	if ( rc ) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}
	
        fsd->dbh = (void *)&db;

	return 0;
}

void destroy_fsdata(sefs_filesystem_data_t * fsd) 
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

	for (i = 0; i < fsd->num_files; i++) {
		for (j = 0; j < fsd->files[i].num_links; j++) {
			free(fsd->files[i].path_names[j]);
		}
		free(fsd->files[i].path_names);
		if (fsd->files[i].symlink_target)
			free(fsd->files[i].symlink_target);
	}

	/* kill array pinters*/
	free(fsd->users);
	free(fsd->types);
	free(fsd->files);

	/* fell trees */
	avl_free(&(fsd->file_tree));
	avl_free(&(fsd->type_tree));
	avl_free(&(fsd->user_tree));

}


