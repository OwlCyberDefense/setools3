/**
 *  @file
 *  Implementation of the sefs_filesystem class.
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

#include "sefs_internal.hh"
#include "new_ftw.h"

#include <sefs/entry.hh>
#include <sefs/filesystem.hh>
#include <apol/util.h>
#include <selinux/context.h>
#include <selinux/selinux.h>
#include <assert.h>
#include <errno.h>
#include <mntent.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

extern int lgetfilecon_raw(const char *, security_context_t *) __attribute__ ((weak));

/**
 * As that setools must work with older libselinux versions that may
 * not have the _raw() functions, declare them as weak.  If libselinux
 * does indeed have the new functions then use them; otherwise
 * fallback to the originals.
 */
static int filesystem_lgetfilecon(const char *path, security_context_t * context)
{
	if (lgetfilecon_raw != NULL)
	{
		return lgetfilecon_raw(path, context);
	}
	else
	{
		return lgetfilecon(path, context);
	}
}

/**
 * Given a directory, find all bounded mounted filesystems within that
 * directory (or subdirectory within.)  This function consults the
 * entries written to /etc/mtab to determine if something is mounted
 * or not and if it has the "bind" option.  Note that if \a dir itself
 * is a mount, it will not be reported; a subdirectory might.
 *
 * @param dir Directory to begin search.
 * @param rw If true, then only process mounts that are mounted as
 * read-write.  Otherwise only find read-only mounts.
 *
 * @return An allocated vector containing pathnames (type char *) to
 * each mounted location with the "bind" option.  The caller is
 * responsible for calling apol_vector_destroy() afterwards.
 */
static apol_vector_t *filesystem_find_mount_points(const char *dir, bool rw) throw(std::bad_alloc, std::runtime_error)
{
	char *dirdup = NULL;
	apol_vector_t *v = NULL;
	FILE *mtab = NULL;
	struct mntent *entry;

	try
	{
		if ((dirdup = strdup(dir)) == NULL)
		{
			throw std::bad_alloc();
		}
		size_t len = strlen(dirdup);
		if (len > 1 && dirdup[len - 1] == '/')
		{
			dirdup[len - 1] = '\0';
		}
		if ((v = apol_vector_create(free)) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((mtab = fopen("/etc/mtab", "r")) == NULL)
		{
			throw std::runtime_error(strerror(errno));
		}
		// note non thread-safeness below
		while ((entry = getmntent(mtab)) != NULL)
		{
			if (strstr(entry->mnt_dir, dir) != entry->mnt_dir)
			{
				continue;
			}
			if (strcmp(entry->mnt_dir, dirdup) == 0)
			{
				continue;
			}
			if (rw && hasmntopt(entry, MNTOPT_RW) == NULL)
			{
				continue;
			}
			if (strstr(entry->mnt_opts, "bind") != NULL)
			{
				char *s = strdup(entry->mnt_dir);
				if (s == NULL)
				{
					throw std::bad_alloc();
				}
				if (apol_vector_append(v, s) < 0)
				{
					free(s);
					throw std::bad_alloc();
				}
			}
		}

	}
	catch(...)
	{
		free(dirdup);
		apol_vector_destroy(&v);
		if (mtab != NULL)
		{
			fclose(mtab);
		}
		throw;
	}
	free(dirdup);
	fclose(mtab);
	return v;
}

/******************** public functions below ********************/

sefs_filesystem::sefs_filesystem(const char *root, bool rw, sefs_callback_fn_t msg_callback, void *varg)throw(std::bad_alloc, std::invalid_argument, std::runtime_error):sefs_fclist(SEFS_FCLIST_TYPE_FILESYSTEM,
	    msg_callback,
	    varg)
{
	if (root == NULL)
	{
		errno = EINVAL;
		throw std::invalid_argument(strerror(EINVAL));
	}
	_root = NULL;
	_rw = rw;
	_mls = false;
	_mounts = NULL;
	try
	{
		// check that root exists and is readable
		struct stat64 sb;
		if (stat64(root, &sb) != 0 && !S_ISDIR(sb.st_mode))
		{
			errno = EINVAL;
			throw std::invalid_argument(strerror(EINVAL));
		}

		// determine if filesystem is MLS or not
		security_context_t scon;
		if (filesystem_lgetfilecon(root, &scon) < 0)
		{
			throw std::runtime_error(strerror(errno));
		}
		context_t con;
		if ((con = context_new(scon)) == 0)
		{
			freecon(scon);
			throw std::runtime_error(strerror(errno));
		}
		freecon(scon);
		const char *range = context_range_get(con);
		if (range != NULL)
		{
			_mls = true;
		}
		context_free(con);

		if ((_root = strdup(root)) == NULL)
		{
			throw std::bad_alloc();
		}
		_mounts = filesystem_find_mount_points(root, rw);
	}
	catch(...)
	{
		free(_root);
		apol_vector_destroy(&_mounts);
		throw;
	}
}

sefs_filesystem::~sefs_filesystem()
{
	free(_root);
	apol_vector_destroy(&_mounts);
}

struct filesystem_ftw_struct
{
	sefs_fclist *fclist;
	sefs_query *query;
	sefs_fclist_map_fn_t fn;
	void *data;
	bool aborted;
	int retval;
};

static int filesystem_ftw_handler(const char *fpath, const struct stat64 *sb __attribute__ ((unused)), int typeflag
				  __attribute__ ((unused)), struct FTW *ftwbuf __attribute__ ((unused)), void *data)
{
	struct filesystem_ftw_struct *s = static_cast < struct filesystem_ftw_struct *>(data);

	if (!sefs_filesystem::isQueryMatch(fpath, s->query))
	{
		return 0;
	}
	// generate a entry for this file
	sefs_entry *entry = NULL;      // FIX ME

	// invoke real callback (not just the nftw handler)
	s->retval = s->fn(s->fclist, entry, s->data);
	delete entry;
	if (s->retval < 0)
	{
		s->aborted = true;
		return s->retval;
	}

	return 0;
}

int sefs_filesystem::runQueryMap(sefs_query * query, sefs_fclist_map_fn_t fn, void *data) throw(std::runtime_error)
{
	struct filesystem_ftw_struct s;
	s.fclist = this;
	s.query = query;
	s.fn = fn;
	s.data = data;
	s.aborted = false;
	s.retval = 0;

	// FIX ME: should this have FTW_MOUNT flag?
	int retval = new_nftw64(_root, filesystem_ftw_handler, 1024, FTW_MOUNT, &s);
	if (retval != 0 && !s.aborted)
	{
		// error was generated by new_nftw64() itself, not
		// from callback
		return retval;
	}
	return s.retval;
}

bool sefs_filesystem::isMLS() const
{
	return _mls;
}

const char *sefs_filesystem::root() const
{
	return _root;
}

bool sefs_filesystem::isQueryMatch(const char *path, sefs_query * query)
{
	if (query == NULL)
	{
		return true;
	}
	if (path == NULL)
	{
		errno = EINVAL;
		return false;
	}
	struct stat sb;
	if (lstat(path, &sb) < 0)
	{
		return false;
	}
	// rw flag

	// check user

	// role

	// type

	// range

	// object class

	// path

	if (query->_inode != 0 && query->_inode != sb.st_ino)
	{
		return false;
	}

	if (query->_dev != 0 && query->_dev != sb.st_dev)
	{
		return false;
	}

	// root_dir

	return true;
}

/******************** private functions below ********************/

/******************** C functions below ********************/

sefs_filesystem_t *sefs_filesystem_create(const char *root, bool rw, sefs_callback_fn_t msg_callback, void *varg)
{
	sefs_filesystem_t *fs;
	try
	{
		fs = new sefs_filesystem(root, rw, msg_callback, varg);
	}
	catch(...)
	{
		errno = ENOMEM;
		return NULL;
	}
	return fs;
}

const char *sefs_filesystem_get_root(const sefs_filesystem_t * fs)
{
	if (fs == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	return fs->root();
}
