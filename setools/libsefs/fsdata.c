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
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>
#include <mntent.h>
#include <policy.h>

#include "fsdata.h"

/* I believe this is necessary for portability */
#define __USE_FILE_OFFSET64 1
#include <sys/types.h>
#include <sys/stat.h>

#define NFTW_FLAGS FTW_MOUNT | FTW_PHYS
#define NFTW_DEPTH 1024

static sefs_filesystem_data_t *fsdata = NULL;

const char *sefs_object_classes[] =
    { "file", "dir", "lnk_file", "chr_file", "blk_file", "sock_file",
"fifo_file", "all_files" };


/*
 * sefs_get_file_class
 *
 * Determines the file's class, and returns it
 */
int sefs_get_file_class(const struct stat *statptr)
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

int add_uint_to_a(uint32_t i, uint32_t *cnt, uint32_t **a)
{
        if(cnt == NULL || a == NULL)
                return -1;

        /* FIX: This is not very elegant! We use an array that we
         * grow as new int are added to an array.  But rather than be smart
         * about it, for now we realloc() the array each time a new int is added! */
        if(*a != NULL) {
                *a = (uint32_t *) realloc(*a, (*cnt + 1) * sizeof(uint32_t));
        } else /* empty list */ {
                *cnt = 0;
                *a = (uint32_t *) malloc(sizeof(uint32_t));
        }
        if(*a == NULL) {
                fprintf(stderr, "out of memory\n");
                return -1;
        }
        (*a)[*cnt] = i;
        (*cnt)++;
        return 0;
}


static int avl_grow_path_array(void *user_data, int sz)
{
	sefs_fileinfo_t * ptr;
	fsdata = (sefs_filesystem_data_t *)user_data;
	assert(fsdata != NULL);

	if (sz > fsdata->num_files) {
		ptr = (sefs_fileinfo_t *)realloc(fsdata->files, sz * sizeof(sefs_fileinfo_t));
		if(ptr == NULL) {
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
	if(!(fsdata->files[idx].path_names)){
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
		if(ptr == NULL) {
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

	if(sz > fsdata->num_users) 
	{
		if(!( ptr = (char**)realloc(fsdata->users, sz * sizeof(char*)) ))
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

static int ftw_handler(const char *file, const struct stat *sb, int flag, struct FTW *s)
{
	inode_key_t key;
	int idx, rc = 0;
	sefs_fileinfo_t * pi = NULL;
	char *con = NULL;
	char *tmp = NULL;
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

		rc = getfilecon(file, &con);
		/* extract the context parts */
		tmp = strtok(con, ":");
		if (tmp) {
			rc = avl_get_idx(tmp, &fsdata->user_tree);
			if(rc != -1)
				pi->context.user=rc;
			else 
			{
				avl_insert(&(fsdata->user_tree),tmp, &rc);
				pi->context.user=rc;
			}
		}
		else
			pi->context.user = XATTR_UNLABELED;

		tmp = strtok(NULL, ":");
		if (tmp) {
			if(strncmp(tmp, "object_r", 8) == 0)
				pi->context.role = OBJECT_R;
			else
				pi->context.role = XATTR_UNLABELED;
		}
		else
			pi->context.role = XATTR_UNLABELED;

		tmp = strtok(NULL, ":");
		if (tmp) {
			rc = avl_get_idx(tmp, &fsdata->type_tree);
			if (rc == -1) {
				avl_insert(&(fsdata->type_tree), tmp, &rc);
			}
			pi->context.type=(int32_t)rc;
		} else {
			rc = avl_get_idx(SEFS_XATTR_UNLABELED, &fsdata->type_tree);
			if (rc == -1) {
				avl_insert(&(fsdata->type_tree), SEFS_XATTR_UNLABELED, &rc);
			}
			pi->context.type = rc;
		}
	} else {
		pi = &(fsdata->files[idx]);
	}	

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
			rc = lgetfilecon(file, &con);
			if(!(tmp = (char*)calloc((PATH_MAX + 1), sizeof(char)) ))
			{
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			readlink(file, tmp, (PATH_MAX + 1) * sizeof(char)); 
			if(errno == EINVAL || errno == EIO)
			{
				fprintf(stderr, "error reading link\n");
				return -1;
			}
			else if (errno == EACCES)
			{
				fprintf(stderr, "Access denied to link at %s\n", file);
				errno = 0;
			}
			else
			{
				pi->symlink_target = tmp;
			}
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
	if(!( fsd->users = (char**)malloc(sizeof(char*) * 1) )) 
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


int sefs_scan_tree(char * dir)
{
	int (*fn)(const char *file, const struct stat *sb, int flag, struct FTW *s) = ftw_handler;
	if (nftw(dir, fn, NFTW_DEPTH, NFTW_FLAGS) == -1) {
		fprintf(stderr, "Error scanning tree rooted at %s\n", dir);
		return -1;
	}
		
	return 0;	
}


int sefs_filesystem_data_index(sefs_filesystem_data_t * fsd) {
	int loop = 0, idx = 0 , rc = 0;
	sefs_fileinfo_t * pi = NULL;
	sefs_typeinfo_t * ti = NULL;

	for(loop = 0; loop < fsd->num_files; loop++) {
				
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


int sefs_filesystem_data_save(sefs_filesystem_data_t * fsd, char *filename)
{
	int i, j, rc = 0;
	FILE *fp;
	uint32_t buf[3], len;
	int32_t sbuf[3];
	size_t items2, items = 0;
	sefs_fileinfo_t * pinfo = NULL;

	fp = fopen(filename, "w");
	if (!fp) {
		fprintf(stderr, "Error opening file %s\n", filename);
		return -1;
	}
	
	/* File magic number and version */
	buf[items++] = cpu_to_le32(INDEX_DB_MAGIC);
	buf[items++] = cpu_to_le32(INDEX_DB_VERSION);
	
	/* number of types */
	buf[items++] = cpu_to_le32(fsd->num_types);
	
	rc = fwrite(buf, sizeof(uint32_t), items, fp);
	if (rc != items) 
		goto bad;
	

	for(i=0; i < fsd->num_types; i++) {
		/* write length of type */
		len = strlen(fsd->types[i].name);
		buf[0] = cpu_to_le32(len);
		rc = fwrite(buf, sizeof(uint32_t), 1, fp);
		if (rc != 1)
			goto bad;

		/* write the type */
		rc = fwrite(fsd->types[i].name, sizeof(char), len, fp);
		if (rc != len)
			goto bad;
/*
--Not doing this anymore --
		len = fsd->types[i].num_inodes;
		buf[0] = cpu_to_le32(len);
		rc = fwrite(buf, sizeof(uint32_t), 1, fp);
		if (rc != 1)
			goto bad;

	
		for (j = 0; j < len; j++) {
			buf[0] = cpu_to_le32(fsd->types[i].index_list[j]);
			rc = fwrite(buf, sizeof(uint32_t), 1, fp);
			if (rc != 1)
				goto bad;

		}
*/
	}

	buf[0] = cpu_to_le32(fsd->num_users);
	rc = fwrite(buf, sizeof(uint32_t), 1, fp);
	if (rc != 1)
		goto bad;

	for (i=0; i < fsd->num_users; i++) {
		/* write the length of the user */
		len = strlen(fsd->users[i]);
		buf[0] = cpu_to_le32(len);
		rc = fwrite(buf, sizeof(uint32_t), 1, fp);
		if (rc != 1)
			goto bad;

		/* write the user */
		rc = fwrite(fsd->users[i], sizeof(char), len, fp);
		if (rc != len)
			goto bad;

	}

	/* number of dev/inodes */
	buf[0] = cpu_to_le32(fsd->num_files);
	rc = fwrite(buf, sizeof(uint32_t), 1, fp);
	if (rc != 1)
		goto bad;
			
	for(i=0; i < fsd->num_files; i++) {

		pinfo = &(fsd->files[i]);
	
		/* Write the key */
		buf[0] = cpu_to_le32(pinfo->key.dev);
		items2 = fwrite(buf, sizeof(uint32_t), 1, fp);
		if (items2 != 1) {
			fprintf(stderr, "1 error writing file %s\n", filename);
			return -1;
		}
		
		items2 = fwrite(cpu_to_le64(&pinfo->key.inode), sizeof(uint64_t), 1, fp);
		if (items2 != 1) {
			fprintf(stderr, "2 error writing file %s\n", filename);
			return -1;
		}

		
		items = 0;
		sbuf[items++] = cpu_to_le32(pinfo->context.user);
		sbuf[items++] = cpu_to_le32(pinfo->context.role);
		sbuf[items++] = cpu_to_le32(pinfo->context.type);
		sbuf[items++] = cpu_to_le32(pinfo->obj_class);
				
		items2 = fwrite(sbuf, sizeof(int32_t), items, fp);
		if (items2 != items) {
			fprintf(stderr, "3 error writing file %s\n", filename);
			return -1;
		}
		
		if (pinfo->obj_class || LNK_FILE) {
				/* write our symlink target */
				len = strlen(pinfo->symlink_target);
				buf[0] = cpu_to_le32(len);
				items = fwrite(buf, sizeof(uint32_t), 1, fp);
				if (items != 1)
					goto bad;
					
				items = fwrite(pinfo->symlink_target, sizeof(char), len, fp);
				if (items != len)
					goto bad;
					
		}
		
		/* Write the number of pathnames */
		buf[0] = cpu_to_le32(pinfo->num_links);
		items2 = fwrite(buf, sizeof(uint32_t), 1, fp);
		if (items2 != 1) {
			fprintf(stderr, "4 error writing file %s\n", filename);
			return -1;
		}
		
		for (j = 0; j < pinfo->num_links;  j++) {
			/* Write the pathname length */
			len = strlen(pinfo->path_names[j]);
			buf[0] = cpu_to_le32(len);
			items2 = fwrite(buf, sizeof(uint32_t), 1, fp);
			if (items2 != 1) {
				fprintf(stderr, "5 error writing file %s\n", filename);
				return -1;
			}
			
			/* Write the pathname */
			items2 = fwrite(pinfo->path_names[j], sizeof(char), len, fp);
			if (items2 != len) {
				fprintf(stderr, "6 error writing file %s\n", filename);
				return -1;
			}
		}
		
	}

	fclose(fp);
	return 0;

	bad:
		fclose(fp);
		return -1;
}


int sefs_filesystem_data_load(sefs_filesystem_data_t* fsd, char *filename)
{
	int i, j;
	inode_key_t *key = NULL;
	sefs_fileinfo_t * pinfo = NULL;
	FILE *fp;
	size_t items;
	uint32_t buf[PATH_MAX],len;
	int32_t sbuf[3];
	
	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Error opening file %s\n", filename);
		return -1;
	}
	
	items = fread(buf, sizeof(uint32_t), 3, fp);
	if (items != 3) {
		fprintf(stderr, "error reading file %s\n", filename);
		return -1;
	}

	for (i = 0; i < 2; i++) 
		buf[i] = le32_to_cpu(buf[i]);

	if (buf[0] != INDEX_DB_MAGIC) {
			fprintf(stderr, "invalid file type\n");
			return -1;
	}			

	if (buf[1] != INDEX_DB_VERSION) {
			fprintf(stderr, "unknown file version\n");
			return -1;
	}
	
	fsd->num_types = buf[2];
	
	fsd->types = (sefs_typeinfo_t *)malloc(fsd->num_types * sizeof(sefs_typeinfo_t));
	if (!fsd->types) { 
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	for (i = 0; i< fsd->num_types; i++) {
printf("on type %d\t", i);
	
		items = fread(buf, sizeof(uint32_t), 1, fp);
		if (items != 1)
			goto bad;

		len = le32_to_cpu(buf[0]);
printf("of length %d\t",len);
		items = fread(buf, sizeof(char), len, fp);
		if (items != len)
			goto bad;

		fsd->types[i].name = (char *) malloc (sizeof(char) * (len + 1));
		if (!fsd->types[i].name) 
			goto bad;
		bzero(fsd->types[i].name, sizeof(char) * (len + 1));	
			
		memcpy(fsd->types[i].name, buf, len);
printf("type: %s \n", fsd->types[i].name);
	
	
/*	
		items = fread(buf, sizeof(uint32_t), 1, fp);
		if (items != 1)
			goto bad;
	
		len = le32_to_cpu(buf[0]);
			
printf("with %d inodes\n", len);

		pbuf = (uint32_t *) malloc(sizeof(uint32_t) * len);
		if (!pbuf)
			goto bad;
		bzero(pbuf, len);

		items = fread(pbuf, sizeof(uint32_t), len, fp);
		if (items != len)
			goto bad;

		for (j = 0; j < len; j++) {
			len = le32_to_cpu(pbuf[j]);
			add_uint_to_a(len, &fsd->types[i].num_inodes, &fsd->types[i].index_list);
		}

		free(pbuf);
*/	
	}

	/* read the number of users */
	items = fread(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		goto bad;
		
	fsd->num_users = le32_to_cpu(buf[0]);
	
	fsd->users = (char **)malloc(sizeof(char *) * fsd->num_users);
	if (!fsd->users) 
		goto bad;
	
	for (i = 0; i < fsd->num_users ; i++) {
		/* read the length of the user */
		items = fread(buf, sizeof(uint32_t), 1, fp);
		if (items != 1) 
			goto bad;
			
		len = le32_to_cpu(buf[0]);				
		items = fread(buf, sizeof(char), len, fp);
		if (items != len)
			goto bad;
			
		fsd->users[i] = (char *) malloc(sizeof(char) * (len +1));
		if (!fsd->users[i])
			goto bad;
		bzero(fsd->users[i], (sizeof(char) * (len + 1)));
		
		memcpy(fsd->users[i], buf, len);

printf("got me a user! %s\n", fsd->users[i]);
	}

	/* read the number of inodes */
	items = fread(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		goto bad;
		
	fsd->num_files = le32_to_cpu(buf[0]);

	pinfo = (sefs_fileinfo_t *) malloc(fsd->num_files * sizeof(sefs_fileinfo_t));
	if (!pinfo) {
		fprintf(stderr, "4out of memory\n");
		return -1;
	}
	fsd->files = pinfo;

printf("number of files: %d\n", fsd->num_files);	
	for(i = 0; i < fsd->num_files; i++) {
		
		pinfo = &(fsd->files[i]);

		key = (inode_key_t *)malloc(sizeof(inode_key_t));
		if (!key) {
			fprintf(stderr, "3Out of memory\n");
			return -1;
		}
		
		/* Read the key*/
		items = fread(&(key->inode), sizeof(uint64_t), 1, fp);
		if (items != 1) {
			fprintf(stderr, "error reading file %s\n", filename);
			return -1;
		}
		
		items = fread(&(key->dev), sizeof(uint32_t), 1, fp);
		if (items != 1) {
			fprintf(stderr, "error reading file %s\n", filename);
			return -1;
		}
		
		/* Read the context */
		items = fread(sbuf, sizeof(int32_t), 4, fp);
		if (items != 3) {
			fprintf(stderr, "error reading file %s\n", filename);
			return -1;
		}		
		
		pinfo->context.user = sbuf[0];
		pinfo->context.role = sbuf[1];
		pinfo->context.type = sbuf[2];
		pinfo->obj_class = sbuf[4];

		if (pinfo->obj_class || LNK_FILE) {
				/* read the symlink target */
				items = fread(buf, sizeof(uint32_t), 1, fp);
				if (items != 1)
					goto bad;
				
				len = le32_to_cpu(buf[0]);
				
				pinfo->symlink_target = (char *) malloc(sizeof(char) * (len +1));
				if (!pinfo->symlink_target)
					goto bad;
				bzero(pinfo->symlink_target, (sizeof(char) * (len + 1)));	
							
				items = fread(pinfo->symlink_target, sizeof(char), len, fp);
				if (items != len)
					goto bad;
		}

		/* add the type of this inode to the type index list */
printf ("adding path %d to type %d\n",i,pinfo->context.type);
		add_uint_to_a(i, &fsd->types[pinfo->context.type].num_inodes, &fsd->types[pinfo->context.type].index_list);
		
		/* Read the pathname count */
		items = fread(&(pinfo->num_links), sizeof(uint32_t), 1, fp);
		if (items != 1) {
			fprintf(stderr, "error reading file %s\n", filename);
			return -1;
		}

		pinfo->path_names = (char **)malloc(pinfo->num_links * sizeof(char *));
		if (!pinfo->path_names) {
			fprintf(stderr, "1 %d %d Out of memory\n", pinfo->num_links, pinfo->key.inode);
			return -1;
		}
		
		for (j = 0; j < pinfo->num_links; j++) {
			items = fread(&len, sizeof(uint32_t), 1, fp);
			if (items != 1) {
				fprintf(stderr, "error reading file %s\n", filename);
				return -1;
			}
			
			if ((pinfo->path_names[j] = (char *)malloc((len + 1) * sizeof(char))) == NULL) {
				fprintf(stderr, "2Out of memory\n");
				return -1;
			}
			
			bzero(pinfo->path_names[j], len + 1);
			
			items = fread(pinfo->path_names[j], sizeof(char), len, fp);
			if (items != len) {
				fprintf(stderr, "error reading file %s\n", filename);
				return -1;
			}
		}
		
	}

	fclose(fp);
	return 0;

	bad:
		fclose(fp);
		return -1;
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
 * sefs_print_valid_object_classes
 *
 * Prints out the valid object classes to specify for the search.
 */
void sefs_print_valid_object_classes( void )
{
	int i, num_objs_on_line = 0, obj_max = 8;
	
	assert(sefs_object_classes != NULL);
	printf("   ");
	for (i = 0; i < NUM_OBJECT_CLASSES; i++) {
		num_objs_on_line++;
		if (i == (NUM_OBJECT_CLASSES - 1))
			printf("%s\n", sefs_object_classes[i]);
		else if (num_objs_on_line == obj_max) {
			printf("%s,\n", sefs_object_classes[i]);
			printf("   ");
		}
		else 
			printf("%s, ", sefs_object_classes[i]);
		
	}
}
