/* Copyright (C) 2001-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* fsdata.c
 *
 * analysis policy database filesystem functions 
 *
 */

/* SE Linux includes*/
#include <selinux/selinux.h>
#include <selinux/context.h>
/* standard library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>
#include <mntent.h>

#include <fsdata.h>

#define NFTW_FLAGS FTW_MOUNT | FTW_PHYS
#define NFTW_DEPTH 1024

static sefs_filesystem_data_t *fsdata = NULL;


static int avl_grow_path_array(void *user_data, int sz)
{
	sefs_fileinfo_t * ptr;
	fsdata = (sefs_filesystem_data_t *)user_data;
	assert(fsdata != NULL);

	if (sz > fsdata->pathlistsize) {
		ptr = (sefs_fileinfo_t *)realloc(fsdata->paths,
						      (LIST_SZ + fsdata->pathlistsize)
						      * sizeof(sefs_fileinfo_t));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		fsdata->paths = ptr;
		fsdata->pathlistsize += LIST_SZ;
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
	
	memcpy(tmp, &(fsdata->paths[idx].sb.st_ino), sizeof(ino_t));
	memcpy(tmp + sizeof(ino_t), &(fsdata->paths[idx].sb.st_dev), sizeof(dev_t));

	rc = memcmp((char*)key, (char *)tmp, sizeof(ino_t) + sizeof(dev_t));
	free(tmp);
	return rc;
}


static int avl_add_path(void *user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;
	char *path = (char*)key;
	
	assert(fsdata != NULL && path != NULL);
	
	(fsdata->numpaths)++;
		
	return 0;
}


static int avl_grow_type_array(void * user_data, int sz)
{
	sefs_typeinfo_t * ptr;
	fsdata = (sefs_filesystem_data_t *)user_data;
	assert(fsdata != NULL);

	if (sz > fsdata->typelistsize) {
		ptr = (sefs_typeinfo_t *)realloc(fsdata->types,
					         (LIST_SZ + fsdata->typelistsize)
						 * sizeof(sefs_typeinfo_t));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		fsdata->types = ptr;
		fsdata->typelistsize += LIST_SZ;
	}

	return 0;	
}


static int avl_type_compare(void *user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;

	return strcmp((char*)key, fsdata->types[idx].setypename);
}


static int avl_add_type(void *user_data, const void *key, int idx)
{
	fsdata = (sefs_filesystem_data_t *)user_data;
	char *path = (char*)key;
	
	assert(fsdata != NULL && path != NULL);
	
	fsdata->types[idx].setypename = (char *)key;
	(fsdata->numtypes)++;
		
	return 0;
}


static int ftw_handler(const char *file, const struct stat *sb, int flag, struct FTW *s)
{
	void *key = NULL;
	int idx = 0, rc = 0;
	sefs_fileinfo_t * pi = NULL;
	char ** ptr = NULL;
	char *con = NULL;
		
	if ((key = (void *)malloc(12)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	
	memcpy(key, &(sb->st_ino), sizeof(ino_t));
	memcpy(key + sizeof(ino_t), &(sb->st_dev), sizeof(dev_t));
	
	idx = avl_get_idx(key, &(fsdata->pathtree));
	
	if (idx == -1) {
		if ((rc = avl_insert(&(fsdata->pathtree), key, &idx)) == -1) {
			fprintf(stderr, "avl error\n");
			return -1;
		}
		
		pi = &(fsdata->paths[idx]);
		memcpy(&(pi->sb), sb, sizeof(struct stat));
		if ((pi->pathnames = (char **)malloc(LIST_SZ * sizeof(char *))) == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		
		pi->pathlistsize = LIST_SZ;
		pi->numpaths = 0;
		
		if ((pi->pathnames[pi->numpaths] = (char *)malloc(strlen(file) + 1)) == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
	
		strncpy(pi->pathnames[pi->numpaths], file, strlen(file));
		
		rc = getfilecon(file, &con);

		if (rc == -1) {
			pi->context = context_new("UNLABELED:UNLABELED:UNLABELED");
		} else {
			pi->context = context_new(con);
		}
		
		pi->numpaths++;
		
	} else {
		pi = &(fsdata->paths[idx]);
		memcpy(&(pi->sb), sb, sizeof(struct stat));
		
		if (pi->numpaths > pi->pathlistsize) {
			if ((ptr = (char **)realloc(pi->pathnames,
					            (LIST_SZ + pi->pathlistsize)
						     * sizeof(char *))) == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			pi->pathnames = ptr;
			pi->pathlistsize += LIST_SZ;
		}

		if ((pi->pathnames[pi->numpaths] = (char *)malloc(strlen(file) + 1)) == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}

		strncpy(pi->pathnames[pi->numpaths], file, strlen(file));
		pi->numpaths++;
	}
	
	return 0;
}


static int sefs_init_pathtree(sefs_filesystem_data_t * fsd)
{
	if ((fsd->paths = (sefs_fileinfo_t *)malloc(sizeof(sefs_fileinfo_t) * LIST_SZ)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	
	memset(fsd->paths, 0, sizeof(sefs_fileinfo_t) * LIST_SZ);
	fsd->pathlistsize = LIST_SZ;
	fsd->numpaths = 0;

	avl_init(&(fsd->pathtree),
		 (void *)fsd,
		 avl_path_compare,
		 avl_grow_path_array,
		 avl_add_path);
		 
	return 0;
}


static int sefs_init_typetree(sefs_filesystem_data_t * fsd)
{

	if ((fsd->types = (sefs_typeinfo_t *)malloc(sizeof(sefs_typeinfo_t) * LIST_SZ)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	
	memset(fsd->types, 0, sizeof(sefs_typeinfo_t) * LIST_SZ);
	fsd->typelistsize = LIST_SZ;
	fsd->numtypes = 0;

	avl_init(&(fsd->typetree),
		 (void *)fsd,
		 avl_type_compare,
		 avl_grow_type_array,
		 avl_add_type);
	
	return 0;
}


int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd)
{
	if (fsd == NULL) {
		fprintf(stderr, "Invalid structure\n");
		return -1;
	}
	
	fsdata = fsd;
	fsd->numpaths = 0;
	fsd->numtypes = 0;
	fsd->pathlistsize = 0;
	fsd->typelistsize = 0;
	fsd->paths = NULL;
	fsd->types = NULL;
	
	if (sefs_init_pathtree(fsd) == -1) {
		fprintf(stderr, "fsdata_init_paths() failed\n");
		return -1;
	}
	
	if (sefs_init_typetree(fsd) == -1) {
		fprintf(stderr, "fsdata_init_types() failed\n");
		return -1;
	}
	
	return 1;
}


int sefs_scan_tree(char * dir)
{
	int (*fn)(const char *file, const struct stat *sb, int flag, struct FTW *s) = ftw_handler;

	if (nftw(dir, fn, NFTW_DEPTH, NFTW_FLAGS) == -1) {
		fprintf(stderr, "Error scanning tree rooted at %s\n", dir);
		return -1;
	}
		
	return 1;	
}


int sefs_filesystem_data_index(sefs_filesystem_data_t * fsd) {
	int loop = 0, idx = 0 , rc = 0;
	sefs_fileinfo_t * pi = NULL;
	sefs_typeinfo_t * ti = NULL;

	for(loop = 0; loop < fsd->numpaths; loop++) {
		unsigned int * ptr;
		
		pi = &(fsd->paths[loop]);
		idx = avl_get_idx(context_type_get(pi->context), &(fsd->typetree));
		
		if (idx == -1) {
			if ((rc = avl_insert(&(fsd->typetree), (char *)context_type_get(pi->context), &idx)) == -1) {
				fprintf(stderr, "avl error\n");
				return -1;
			}

			ti = &(fsd->types[idx]);
			if ((ti->pathitems = (int *)malloc(LIST_SZ * sizeof(unsigned int))) == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			memset(ti->pathitems, 0, LIST_SZ * sizeof(unsigned int));
			
			ti->pathlistsize = LIST_SZ;
			ti->numpaths = 0;
			ti->pathitems[ti->numpaths] = loop;
		} else {
			ti = &(fsd->types[idx]);
			ti->numpaths++;
			
			if (ti->numpaths > ti->pathlistsize) {
				if ((ptr = (int *)realloc(ti->pathitems, (LIST_SZ + ti->pathlistsize)
							     	        * sizeof(unsigned int))) == NULL) {
					fprintf(stderr, "out of memory\n");
					return -1;
				}
				ti->pathitems = ptr;
				ti->pathlistsize += LIST_SZ;
			}
			
			ti->pathitems[ti->numpaths] = loop;
		}
		
	}

	return 1;	
}


int sefs_filesystem_data_save(sefs_filesystem_data_t * fsd, char *filename)
{
	int rc = 0, loop = 0, fd = -1, i = 0, len = 0;
	int keysize = sizeof(dev_t) + sizeof(ino_t);
	void * key = NULL;
	sefs_fileinfo_t * pinfo = NULL;
	
	if ((fd = open(filename, O_RDWR | O_CREAT | O_TRUNC)) == -1) {
		fprintf(stderr, "Error opening file %s\n", filename);
		return -1;
	}
	
	/* write out the total number of path info entries */
	if ((rc = write(fd, &(fsd->numpaths), sizeof(unsigned int))) != sizeof(unsigned int)) {
		fprintf(stderr, "error writing file %s\n", filename);
		return -1;
	}
	
	if ((key = (void *)malloc(keysize)) == NULL) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}
	
	for (loop = 0; loop < fsd->numpaths; loop++) {
		pinfo = &(fsd->paths[loop]);

		memcpy(key, &(pinfo->sb.st_ino), sizeof(ino_t));
		memcpy(key + sizeof(ino_t), &(pinfo->sb.st_dev), sizeof(dev_t));

		/* Write the key */
		if ((rc = write(fd, key, keysize)) != keysize) {
			fprintf(stderr, "error writing file %s\n", filename);
			return -1;
		}
		
		/* Get the context length */
		len = strlen(context_str(pinfo->context));
		
		/* Write the context length */
		if ((rc = write(fd, &len, sizeof(unsigned int))) != sizeof(unsigned int)) {
			fprintf(stderr, "error writing file %s\n", filename);
			return -1;
		}
		
		/* Write the context */
		if ((rc = write(fd, context_str(pinfo->context), len)) != len) {
			fprintf(stderr, "error writing file %s\n", filename);
			return -1;
		}
		
		/* Write the number of pathnames */
		len = sizeof(unsigned int);
		if ((rc = write(fd, &(pinfo->numpaths), len)) != len) {
			fprintf(stderr, "error writing file %s\n", filename);
			return -1;
		}
		
		for (i = 0; i < pinfo->numpaths;  i++) {
			/* Write the pathname length */
			len = strlen(pinfo->pathnames[i]);
			if ((rc = write(fd, &len, sizeof(unsigned int))) != sizeof(unsigned int)) {
				fprintf(stderr, "error writing file %s\n", filename);
				return -1;
			}
			
			/* Write the pathname */
			if ((rc = write(fd, pinfo->pathnames[i], len)) != len) {
				fprintf(stderr, "error writing file %s\n", filename);
				return -1;
			}
		}
		
	}
	
	close(fd);
	return 0;
}


int sefs_filesystem_data_load(sefs_filesystem_data_t* fsd, char *filename)
{
	int rc = 0, loop = 0, fd = -1, i = 0;
	unsigned int len = 0;
	int keysize = sizeof(dev_t) + sizeof(ino_t);
	void * key = NULL;
	sefs_fileinfo_t * pinfo = NULL;
	security_context_t con = NULL;
	
	if ((fd = open(filename, O_RDONLY)) == -1) {
		fprintf(stderr, "Error opening file %s\n", filename);
		return -1;
	}

	if ((rc = read(fd, &(fsd->numpaths), sizeof(unsigned int))) != sizeof(unsigned int)) {
		fprintf(stderr, "error reading file %s\n", filename);
		return -1;
	}
	
	if ((pinfo = (sefs_fileinfo_t *)malloc(fsd->numpaths * sizeof(sefs_fileinfo_t))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	
	fsd->paths = pinfo;
	
	if ((key = (void *)malloc(keysize)) == NULL) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}
	
	for(loop = 0; loop < fsd->numpaths; loop++) {
		pinfo = &(fsd->paths[loop]);
		
		// Read the key
		if ((rc = read(fd, key, keysize)) != keysize) {
			fprintf(stderr, "error reading file %s\n", filename);
			return -1;
		}
		
		memcpy(&(pinfo->sb.st_ino), key,  sizeof(ino_t));
		memcpy(&(pinfo->sb.st_dev), key + sizeof(ino_t), sizeof(dev_t));
		
		// Read the context length		
		if ((rc = read(fd, &len, sizeof(unsigned int))) != sizeof(unsigned int)) {
			fprintf(stderr, "error reading file %s\n", filename);
			return -1;
		}
		
		if ((con = (security_context_t)malloc((len + 1) * sizeof(char))) == NULL) {
			fprintf(stderr, "Out of memory\n");
			return -1;
		}
		
		bzero(con, len + 1);
		
		// Read the context
		if ((rc = read(fd, con, len)) != len) {
			fprintf(stderr, "error reading file %s\n", filename);
			return -1;
		}
		
		if ((pinfo->context = context_new((char *)con)) == NULL) {
			fprintf(stderr, "error creating context");
			return -1;
		}
		
		// Read the pathname count
		len = sizeof(unsigned int);
		if ((rc = read(fd, &(pinfo->numpaths), len)) != len) {
			fprintf(stderr, "error reading file %s\n", filename);
			return -1;
		}

		pinfo->pathlistsize = pinfo->numpaths;
		
		if ((pinfo->pathnames = (char **)malloc(pinfo->numpaths * sizeof(char *))) == NULL) {
			fprintf(stderr, "Out of memory\n");
			return -1;
		}
		
		for (i = 0; i < pinfo->numpaths; i++) {
			if ((rc = read(fd, &len, sizeof(unsigned int))) != sizeof(unsigned int)) {
				fprintf(stderr, "error reading file %s\n", filename);
				return -1;
			}
			
			if ((pinfo->pathnames[i] = (char *)malloc((len + 1) * sizeof(char))) == NULL) {
				fprintf(stderr, "Out of memory\n");
				return -1;
			}
			
			bzero(pinfo->pathnames[i], len + 1);
			
			if ((rc = read(fd, pinfo->pathnames[i], len)) != len) {
				fprintf(stderr, "error reading file %s\n", filename);
				return -1;
			}
		}
		
	}
	
	close(fd);
	return 1;
}

