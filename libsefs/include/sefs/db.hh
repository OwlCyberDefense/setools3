/**
 *  @file
 *  Defines the public interface for the database fc list object.
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

#ifndef SEFS_DB_H
#define SEFS_DB_H

#include "fclist.hh"

#ifdef __cplusplus
extern "C"
{
#endif
#include <time.h>
#include <apol/vector.h>

#ifdef __cplusplus
}

/**
 * This class represents a database that maps files to their SELinux
 * file contexts.
 */
class sefs_db:public sefs_fclist
{
      public:

	/**
	 * Allocate and return a new sefs database from the filesystem \a
	 * fs.
	 * @param fs Sefs filesystem from which to create the database.
	 * @param msg_callback Callback to invoke as errors/warnings are
	 * generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to the
	 * callback function.
	 */
	sefs_db(const sefs_filesystem & fs, sefs_callback_fn_t msg_callback, void *varg);

	/**
	 * Allocate and return a new sefs database, loading the
	 * entries from the saved database \a path.
	 * @param path Path of a sefs database from which to load.
	 * @param msg_callback Callback to invoke as errors/warnings
	 * are generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to
	 * the callback function.
	 */
	 sefs_db(const char *path, sefs_callback_fn_t msg_callback, void *varg);

	~sefs_db();

	/**
	 * Write a database to disk, overwriting any existing file.
	 * The database may then be read by calling the appropriate
	 * constructor.
	 * @param filename Name of file to which write.
	 * @return 0 on success, < 0 on error.
	 */
	int save(const char *filename);

	/**
	 * Get the creation time of a sefs database.
	 * @return Creation time of the database, or 0 on error.
	 */
	time_t getCTime() const;

      private:
	struct sqlite3 *db;
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore
//the compatibility section.
#ifndef SWIG

	typedef struct sefs_db sefs_db_t;

/**
 * Allocate and return a new sefs database from the filesystem \a fs.
 * @see sefs_db::sefs_db(const sefs_filesystem &fs, sefs_callback_fn_t msg_callback, void *varg)
 */
	sefs_fclist_t *sefs_db_create_from_filesystem(const sefs_filesystem_t * fs, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Allocate and return a new sefs database, loading the entries from
 * the saved database \a path.
 * @see sefs_db::sefs_db(const char *path, sefs_callback_fn_t msg_callback, void *varg)
 */
	sefs_fclist_t *sefs_db_create_from_file(const char *path, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Write a database to disk, overwriting any existing file.
 * @see sefs_db::save()
 */
	int sefs_db_save(sefs_db_t * db, const char *filename);

/**
 * Get the creation time of a sefs database.
 * @see sefs_db::getCTime()
 */
	time_t sefs_db_get_ctime(sefs_db_t * db);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_DB_H */
