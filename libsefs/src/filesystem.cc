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
 * Note that the returned vector in never actually used by this
 * library.  This function existed in previous versions of libsefs,
 * but was never documented why it existed.  Rather than eliminate
 * this function, it is retained (but effectively unused), in case a
 * future revision of libsefs necessitates finding bind mounts.
 *
 * @param dir Directory to begin search.
 *
 * @return An allocated vector containing pathnames (type char *) to
 * each mounted location with the "bind" option.  The caller is
 * responsible for calling apol_vector_destroy() afterwards.
 */
static apol_vector_t *filesystem_find_mount_points(const char *dir) throw(std::bad_alloc, std::runtime_error)
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

sefs_filesystem::sefs_filesystem(const char *new_root, sefs_callback_fn_t msg_callback, void *varg)throw(std::bad_alloc, std::invalid_argument, std::runtime_error):sefs_fclist(SEFS_FCLIST_TYPE_FILESYSTEM,
	    msg_callback,
	    varg)
{
	if (new_root == NULL)
	{
		SEFS_ERR("%s", strerror(EINVAL));
		errno = EINVAL;
		throw std::invalid_argument(strerror(EINVAL));
	}
	_root = NULL;
	_mls = false;
	_mounts = NULL;
	try
	{
		// check that root exists and is readable
		struct stat64 sb;
		if (stat64(new_root, &sb) != 0 && !S_ISDIR(sb.st_mode))
		{
			SEFS_ERR("%s", strerror(EINVAL));
			errno = EINVAL;
			throw std::invalid_argument(strerror(EINVAL));
		}

		// determine if filesystem is MLS or not
		security_context_t scon;
		if (filesystem_lgetfilecon(new_root, &scon) < 0)
		{
			SEFS_ERR("Could not read SELinux file context for %s.", new_root);
			throw std::runtime_error(strerror(errno));
		}
		context_t con;
		if ((con = context_new(scon)) == 0)
		{
			SEFS_ERR("%s", strerror(errno));
			freecon(scon);
			throw std::runtime_error(strerror(errno));
		}
		freecon(scon);
		const char *range = context_range_get(con);
		if (range != NULL && range[0] != '\0')
		{
			_mls = true;
		}
		context_free(con);

		if ((_root = strdup(new_root)) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::bad_alloc();
		}
		_mounts = filesystem_find_mount_points(new_root);
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
	sefs_filesystem *fs;
	sefs_query *query;
	apol_vector_t *dev_map;	       //< vector of filesystem_dev entries
	apol_vector_t *type_list;
	apol_mls_range_t *range;
	sefs_fclist_map_fn_t fn;
	void *data;
	bool aborted;
	int retval;
};

// wrapper functions to go between non-OO land into OO member functions

inline struct sefs_context_node *filesystem_get_context(sefs_filesystem * fs, security_context_t scon) throw(std::bad_alloc)
{
	return fs->getContext(scon);
}

inline sefs_entry *filesystem_get_entry(sefs_filesystem * fs, const struct sefs_context_node * node, uint32_t objClass,
					const char *path, ino64_t ino, const char *dev_name)throw(std::bad_alloc)
{
	return fs->getEntry(node, objClass, path, ino, dev_name);
}

inline bool filesystem_is_query_match(sefs_filesystem * fs, const sefs_query * query, const char *path, const char *dev,
				      const struct stat64 * sb, apol_vector_t * type_list,
				      apol_mls_range_t * range)throw(std::runtime_error)
{
	return fs->isQueryMatch(query, path, dev, sb, type_list, range);
}

inline void filesystem_err(sefs_filesystem * fs, const char *fmt, const char *arg)
{
	fs->SEFS_ERR(fmt, arg);
}

static uint32_t filesystem_stat_to_objclass(const struct stat64 *sb)
{
	if (S_ISREG(sb->st_mode))
	{
		return QPOL_CLASS_FILE;
	}
	if (S_ISDIR(sb->st_mode))
	{
		return QPOL_CLASS_DIR;
	}
	if (S_ISCHR(sb->st_mode))
	{
		return QPOL_CLASS_CHR_FILE;
	}
	if (S_ISBLK(sb->st_mode))
	{
		return QPOL_CLASS_BLK_FILE;
	}
	if (S_ISFIFO(sb->st_mode))
	{
		return QPOL_CLASS_FIFO_FILE;
	}
	if (S_ISLNK(sb->st_mode))
	{
		return QPOL_CLASS_LNK_FILE;
	}
	if (S_ISSOCK(sb->st_mode))
	{
		return QPOL_CLASS_SOCK_FILE;
	}
	assert(0);		       // should never get here
	return 0;
}

struct filesystem_dev
{
	dev_t dev;
	char *dev_name;		       //< pointer into the dev_tree
};

static int filesystem_dev_cmp(const void *a, const void *b __attribute__ ((unused)), void *arg)
{
	const struct filesystem_dev *d1 = static_cast < const struct filesystem_dev *>(a);
	dev_t *d2 = static_cast < dev_t * >(arg);
	if (d1->dev < *d2)
	{
		return -1;
	}
	else if (d1->dev > *d2)
	{
		return 1;
	}
	return 0;
}

static int filesystem_ftw_handler(const char *fpath, const struct stat64 *sb, int typeflag
				  __attribute__ ((unused)), struct FTW *ftwbuf __attribute__ ((unused)), void *data)
{
	struct filesystem_ftw_struct *s = static_cast < struct filesystem_ftw_struct *>(data);

	size_t i;
	void *dev_num = const_cast < void *>(static_cast < const void *>(&(sb->st_dev)));
	int rc = apol_vector_get_index(s->dev_map, NULL, filesystem_dev_cmp, dev_num, &i);
	assert(rc == 0);
	struct filesystem_dev *d = static_cast < struct filesystem_dev *>(apol_vector_get_element(s->dev_map, i));
	const char *dev = d->dev_name;

	try
	{
		if (!filesystem_is_query_match(s->fs, s->query, fpath, dev, sb, s->type_list, s->range))
		{
			return 0;
		}
	}
	catch(...)
	{
		return -1;
	}

	security_context_t scon;
	if (filesystem_lgetfilecon(fpath, &scon) < 0)
	{
		filesystem_err(s->fs, "Could not read SELinux file context for %s.", fpath);
		return -1;
	}
	struct sefs_context_node *node = NULL;
	try
	{
		node = filesystem_get_context(s->fs, scon);
	}
	catch(...)
	{
		freecon(scon);
		return -1;
	}
	freecon(scon);

	uint32_t objClass = filesystem_stat_to_objclass(sb);

	sefs_entry *entry = NULL;
	try
	{
		entry = filesystem_get_entry(s->fs, node, objClass, fpath, sb->st_ino, dev);
	}
	catch(...)
	{
		return -1;
	}

	// invoke real callback (not just the nftw handler)
	s->retval = s->fn(s->fs, entry, s->data);
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
	s.dev_map = NULL;
	s.type_list = NULL;
	s.range = NULL;
	try
	{
		s.dev_map = buildDevMap();
		if (query != NULL)
		{
			query->compile();
			if (policy != NULL)
			{
				if (query->_type != NULL &&
				    (s.type_list =
				     query_create_candidate_type(policy, query->_type, query->_retype, query->_regex,
								 query->_indirect)) == NULL)
				{
					SEFS_ERR("%s", strerror(errno));
					throw std::runtime_error(strerror(errno));
				}
				if (query->_range != NULL &&
				    (s.range = apol_mls_range_create_from_string(policy, query->_range)) == NULL)
				{
					SEFS_ERR("%s", strerror(errno));
					throw std::runtime_error(strerror(errno));
				}
			}
		}
	}
	catch(...)
	{
		apol_vector_destroy(&s.dev_map);
		apol_vector_destroy(&s.type_list);
		apol_mls_range_destroy(&s.range);
		throw;
	}
	s.fs = this;
	s.query = query;
	s.fn = fn;
	s.data = data;
	s.aborted = false;
	s.retval = 0;

	int retval = new_nftw64(_root, filesystem_ftw_handler, 1024, 0, &s);
	apol_vector_destroy(&s.dev_map);
	apol_vector_destroy(&s.type_list);
	apol_mls_range_destroy(&s.range);
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

/******************** private functions below ********************/

static void filesystem_dev_free(void *elem)
{
	if (elem != NULL)
	{
		struct filesystem_dev *d = static_cast < struct filesystem_dev *>(elem);
		// don't free the device name pointer, because it's pointing
		// into the dev_tree BST
		free(d);
	}
}

const char *sefs_filesystem::getDevName(const dev_t dev) throw(std::runtime_error)
{
	apol_vector_t *dev_map = buildDevMap();
	size_t i;
	void *devp = const_cast < dev_t * >(&dev);
	int rc = apol_vector_get_index(dev_map, NULL, filesystem_dev_cmp, devp, &i);
	if (rc < 0)
	{
		apol_vector_destroy(&dev_map);
		return NULL;
	}
	struct filesystem_dev *d = static_cast < struct filesystem_dev *>(apol_vector_get_element(dev_map, i));
	const char *dev_name = d->dev_name;	// this is pointing into this->_dev_tree
	apol_vector_destroy(&dev_map);
	return dev_name;
}

/**
 * For each entry in /etc/mtab, record the device number and the name
 * of the mounted file system.  This provides the mapping between a
 * device number and its source device.
 *
 * @return Vector of filesystem_dev entries.  The caller must call
 * apol_vector_destroy() upon the vector afterwards.
 * @exception If error allocating space, unable to open /etc/mtab, or
 * unable to parse mtab file.
 */
apol_vector_t *sefs_filesystem::buildDevMap(void)throw(std::runtime_error)
{
	apol_vector_t *dev_map;
	if ((dev_map = apol_vector_create(filesystem_dev_free)) == NULL)
	{
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}
	FILE *f = NULL;
	try
	{
		if ((f = fopen("/etc/mtab", "r")) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		char buf[256];
		struct mntent mntbuf;
		while (getmntent_r(f, &mntbuf, buf, 256) != NULL)
		{
			struct stat sb;
			if (stat(mntbuf.mnt_dir, &sb) == -1)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			else
			{
				struct filesystem_dev *d = static_cast < struct filesystem_dev *>(calloc(1, sizeof(*d)));
				if (d == NULL)
				{
					SEFS_ERR("%s", strerror(errno));
					throw std::runtime_error(strerror(errno));
				}
				if (apol_vector_append(dev_map, d) < 0)
				{
					SEFS_ERR("%s", strerror(errno));
					filesystem_dev_free(d);
					throw std::runtime_error(strerror(errno));
				}
				d->dev = sb.st_dev;
				char *mnt_fsname = strdup(mntbuf.mnt_fsname);
				if (mnt_fsname == NULL)
				{
					SEFS_ERR("%s", strerror(errno));
					throw std::runtime_error(strerror(errno));
				}
				if (apol_bst_insert_and_get(dev_tree, (void **)&mnt_fsname, NULL) < 0)
				{
					SEFS_ERR("%s", strerror(errno));
					free(mnt_fsname);
					throw std::runtime_error(strerror(errno));
				}
				d->dev_name = mnt_fsname;
			}
		}
	}
	catch(...)
	{
		apol_vector_destroy(&dev_map);
		if (f != NULL)
		{
			fclose(f);
		}
		throw;
	}
	fclose(f);
	return dev_map;
}

bool sefs_filesystem::isQueryMatch(const sefs_query * query, const char *path, const char *dev, const struct stat64 * sb,
				   apol_vector_t * type_list, apol_mls_range_t * range)throw(std::runtime_error)
{
	if (query == NULL)
	{
		return true;
	}
	security_context_t scon;
	if (filesystem_lgetfilecon(path, &scon) < 0)
	{
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}
	context_t con;
	if ((con = context_new(scon)) == 0)
	{
		SEFS_ERR("%s", strerror(errno));
		freecon(scon);
		throw std::runtime_error(strerror(errno));
	}
	freecon(scon);

	if (!query_str_compare(context_user_get(con), query->_user, query->_reuser, query->_regex))
	{
		context_free(con);
		return false;
	}
	if (!query_str_compare(context_role_get(con), query->_role, query->_rerole, query->_regex))
	{
		context_free(con);
		return false;
	}
	if (type_list == NULL)
	{
		if (!query_str_compare(context_type_get(con), query->_type, query->_retype, query->_regex))
		{
			context_free(con);
			return false;
		}
	}
	else
	{
		size_t index;
		if (apol_vector_get_index(type_list, context_type_get(con), apol_str_strcmp, NULL, &index) < 0)
		{
			context_free(con);
			return false;
		}
	}

	if (range == NULL)
	{
		if (!query_str_compare(context_range_get(con), query->_range, query->_rerange, query->_regex))
		{
			context_free(con);
			return false;
		}
	}
	else
	{
		assert(policy != NULL);
		apol_mls_range_t *context_range = apol_mls_range_create_from_string(policy, context_range_get(con));
		if (context_range == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			context_free(con);
			throw std::runtime_error(strerror(errno));
		}
		int ret;
		ret = apol_mls_range_compare(policy, range, context_range, query->_rangeMatch);
		apol_mls_range_destroy(&context_range);
		if (ret <= 0)
		{
			context_free(con);
			return false;
		}
	}
	context_free(con);

	if (query->_objclass != 0 && query->_objclass != filesystem_stat_to_objclass(sb))
	{
		return false;
	}

	if (!query_str_compare(path, query->_path, query->_repath, query->_regex))
	{
		return false;
	}

	if (query->_inode != 0 && query->_inode != sb->st_ino)
	{
		return false;
	}

	if (!query_str_compare(dev, query->_dev, query->_redev, query->_regex))
	{
		return false;
	}

	return true;
}

sefs_entry *sefs_filesystem::getEntry(const struct sefs_context_node * context, uint32_t objectClass,
				      const char *path, ino64_t ino, const char *dev_name)throw(std::bad_alloc)
{
	char *s = strdup(path);
	if (s == NULL)
	{
		SEFS_ERR("%s", strerror(errno));
		throw std::bad_alloc();
	}
	if (apol_bst_insert_and_get(path_tree, (void **)&s, NULL) < 0)
	{
		SEFS_ERR("%s", strerror(errno));
		free(s);
		throw std::bad_alloc();
	}
	sefs_entry *e = new sefs_entry(this, context, objectClass, s);
	e->_inode = ino;
	e->_dev = dev_name;
	return e;
}

/******************** C functions below ********************/

sefs_filesystem_t *sefs_filesystem_create(const char *root, sefs_callback_fn_t msg_callback, void *varg)
{
	sefs_filesystem_t *fs;
	try
	{
		fs = new sefs_filesystem(root, msg_callback, varg);
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

extern const char *sefs_filesystem_get_dev_name(sefs_filesystem_t * fs, const dev_t dev)
{
	if (fs == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	const char *dev_name = NULL;
	try
	{
		dev_name = fs->getDevName(dev);
	}
	catch(...)
	{
		return NULL;
	}
	return dev_name;
}
