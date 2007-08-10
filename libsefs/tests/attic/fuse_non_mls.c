/*
 * The approach described below does not actually work.  Apparantly,
 * SELinux will assign a context based upond the underlying policy
 * (typically from a fs_use statement); the operating system will not
 * invoke this file's fuse_getxattr() function at all.  Thus it is
 * not possible to use FUSE to create a virtual filesystem with
 * arbitrary file contexts.
 */

/**
 *  @file
 *
 *  Use the FUSE (filesystem in userspace) to create a virtual
 *  filesystem for libsefs tests.  This particular filesystem will not
 *  contain MLS contexts.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#define FUSE_USE_VERSION 25

#define XATTR_NAME_SELINUX "security.selinux"

#include <apol/bst.h>
#include <fuse.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/*************** definition of the virtual filesystem ***************/

static apol_bst_t *bst = NULL;

struct fuse_entry
{
	const char *path;
	mode_t mode;
	const char *context;
};

static struct fuse_entry fs[] = {
	{"/", S_IFDIR, "user_r:object_r:system_t"},
	{"/foo", S_IFREG, "user_r:object_r:system_t"},
	{NULL, 0, NULL}
};

static int fuse_comp(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const struct fuse_entry *f1 = (const struct fuse_entry *)a;
	const struct fuse_entry *f2 = (const struct fuse_entry *)b;
	return strcmp(f1->path, f2->path);
}

/*************** required fuse functions ***************/

static int fuse_getattr(const char *path, struct stat *stbuf)
{
	struct fuse_entry key = { path, 0, NULL };
	struct fuse_entry *e;
	memset(stbuf, 0, sizeof(*stbuf));
	if (apol_bst_get_element(bst, &key, NULL, (void **)&e) < 0) {
		return -ENOENT;
	}
	if (e->mode == S_IFDIR) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = e->mode | 0444;
		stbuf->st_nlink = 1;
	}
	return 0;
}

static int fuse_getxattr(const char *path, const char *attrib_name, char *buf, size_t buflen)
{
	struct fuse_entry key = { path, 0, NULL };
	struct fuse_entry *e;
	if (apol_bst_get_element(bst, &key, NULL, (void **)&e) < 0) {
		return -ENOENT;
	}
	if (strcmp(attrib_name, XATTR_NAME_SELINUX) != 0) {
		return -ENOSYS;
	}
	strncpy(buf, e->context, buflen);
	return strlen(e->context) + 1;
}

static int fuse_open(const char *path, struct fuse_file_info *fi __attribute__ ((unused)))
{
	struct fuse_entry key = { path, 0, NULL };
	struct fuse_entry *e;
	if (apol_bst_get_element(bst, &key, NULL, (void **)&e) < 0) {
		return -ENOENT;
	}

	return -EACCES;
}

static int fuse_read(const char *path, char *buf __attribute__ ((unused)), size_t size, off_t offset __attribute__ ((unused)),
		     struct fuse_file_info *fi __attribute__ ((unused)))
{
	struct fuse_entry key = { path, 0, NULL };
	struct fuse_entry *e;
	if (apol_bst_get_element(bst, &key, NULL, (void **)&e) < 0) {
		return -ENOENT;
	}
	return size;
}

struct stem_data
{
	const char *stem;
	void *buf;
	fuse_fill_dir_t filler;
};

static int fuse_stem_match(void *a, void *data)
{
	const struct fuse_entry *e = (const struct fuse_entry *)a;
	struct stem_data *sd = (struct stem_data *)data;

	size_t e_len = strlen(e->path);
	size_t stem_len = strlen(sd->stem);
	if (e_len <= stem_len) {
		/* entry's path is too longer than the requested path */
		return 0;
	}
	if (strncmp(e->path, sd->stem, stem_len) != 0) {
		/* stem is not the beginning of entry's path */
		return 0;
	}
	const char *file = e->path + 1;
	if (strchr(file, '/') != NULL) {
		/* member of a subdirectory of stem */
		return 0;
	}
	return -sd->filler(sd->buf, file, NULL, 0);
}

static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset __attribute__ ((unused)), struct fuse_file_info *fi __attribute__ ((unused)))
{
	struct fuse_entry key = { path, 0, NULL };
	struct fuse_entry *e;
	if (apol_bst_get_element(bst, &key, NULL, (void **)&e) < 0) {
		return -ENOENT;
	}

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	struct stem_data sd = { path, buf, filler };
	return -apol_bst_inorder_map(bst, fuse_stem_match, &sd);
}

int main(int argc, char *argv[])
{
	if ((bst = apol_bst_create(fuse_comp, NULL)) < 0) {
		return 1;
	}
	for (size_t i = 0; fs[i].path != NULL; i++) {
		if (apol_bst_insert(bst, &fs[i], NULL) < 0) {
			return 1;
		}
	}

	struct fuse_operations non_mls_oper = {
		.getattr = fuse_getattr,
		.getxattr = fuse_getxattr,
		.open = fuse_open,
		.read = fuse_read,
		.readdir = fuse_readdir,
	};
	return fuse_main(argc, argv, &non_mls_oper);
}
