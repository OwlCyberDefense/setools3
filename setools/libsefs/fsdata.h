/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: tmitchem@tresys.com 
 */

/* fsdata.h
 *
 * analysis policy database support header 
 *
 */

#ifndef _FSDATA_H
#define _FSDATA_H

#include <stdint.h>

/* Endian conversion for reading and writing binary index */

#include <byteswap.h>
#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#endif

/* AVL Tree Handling */
#include <policy.h>
#include <avl-util.h>

#define INDEX_DB_MAGIC 0xf97cff8f
#define INDEX_DB_VERSION 1

#ifndef SEFS_XATTR_LABELED_FILESYSTEMS
#define SEFS_XATTR_LABELED_FILESYSTEMS "ext2 ext3"
#endif

#ifndef SEFS_XATTR_UNLABELED
#define SEFS_XATTR_UNLABELED "UNLABELED"
#endif

/* Predefined lables */
#define OBJECT_R 0

#define NUM_OBJECT_CLASSES 8

/* this is what replcon currently uses and needs to be fixed */
typedef enum sefs_classes {
	NORM_FILE,
	DIR,
	LNK_FILE,
	CHR_FILE,
	BLK_FILE,
	SOCK_FILE,
	FIFO_FILE,
	ALL_FILES
} sefs_classes_t;

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
#define NORM_FILE	1
#define DIR			2
#define LNK_FILE	4
#define CHR_FILE	8
#define BLK_FILE	16
#define	SOCK_FILE	32
#define FIFO_FILE	64
#define ALL_FILES	(NORM_FILE | DIR | LNK_FILE | CHR_FILE | BLK_FILE | SOCK_FILE | FIFO_FILE)
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
int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd);
int sefs_filesystem_data_index(sefs_filesystem_data_t * fsd);
int sefs_scan_tree(char * dir);
int sefs_filesystem_data_save(sefs_filesystem_data_t * fsd, char * filename);
int sefs_filesystem_data_load(sefs_filesystem_data_t * fsd, char *filename);
int sefs_get_file_class(const struct stat *statptr);
int sefs_is_valid_object_class(const char *class_name);
void sefs_print_valid_object_classes( void );

#endif /* _FSDATA_H */

