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

/* AVL Tree Handling */
#include <policy.h>
#include <avl-util.h>

#ifndef SEFS_XATTR_LABELED_FILESYSTEMS
#define SEFS_XATTR_LABELED_FILESYSTEMS "ext2 ext3"
#endif

#ifndef SEFS_XATTR_UNLABELED
#define SEFS_XATTR_UNLABELED "UNLABELED"
#endif

typedef struct sefs_fileinfo {
	struct stat 		sb;
	unsigned int		numpaths;
	unsigned int		pathlistsize;
	context_t 		context;
	char **			pathnames;
} sefs_fileinfo_t;


typedef struct sefs_typeinfo {
	char * 			setypename;
	unsigned int 		numpaths;
	unsigned int 		pathlistsize;
	unsigned int *		pathitems;
} sefs_typeinfo_t;
	

typedef struct sefs_filesystem_data {
	unsigned int 		numpaths;
	unsigned int 		numtypes;
	unsigned int		pathlistsize;
	unsigned int		typelistsize;
	sefs_fileinfo_t *	paths;
	sefs_typeinfo_t *	types;
	avl_tree_t		pathtree;
	avl_tree_t		typetree;
} sefs_filesystem_data_t;


/* Management and creation functions */
int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd);
int sefs_filesystem_data_index(sefs_filesystem_data_t * fsd);
int sefs_scan_tree(char * dir);
int sefs_filesystem_data_save(sefs_filesystem_data_t * fsd, char * filename);
int sefs_filesystem_data_load(sefs_filesystem_data_t * fsd, char *filename);

#endif /* _FSDATA_H */

