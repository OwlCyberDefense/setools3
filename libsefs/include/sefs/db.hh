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

#include <sefs/fclist.hh>

#ifdef __cplusplus
extern "C"
{
#endif
#include <time.h>
#include <apol/bst.h>
#include <apol/vector.h>

#ifdef __cplusplus
}

#include <stdexcept>

class sefs_filesystem;

/**
 * This class represents a database that maps files to their SELinux
 * file contexts.
 */
class sefs_db:public sefs_fclist
{
#ifndef SWIG_FRIENDS
	// private functions -- do not call these directly from
	// outside of the library
	friend int db_create_from_filesystem(sefs_fclist * fclist __attribute__ ((unused)), const sefs_entry * entry, void *arg);
	friend struct sefs_context_node *db_get_context(sefs_db *, const char *, const char *, const char *,
							const char *) throw(std::bad_alloc);
	friend sefs_entry *db_get_entry(sefs_db *, const struct sefs_context_node *, uint32_t, const char *, ino64_t,
					const char *) throw(std::bad_alloc);
	friend void db_err(sefs_db *, const char *, const char *);
#endif

      public:

	/**
	 * Allocate and return a new sefs database initialized with
	 * entries from the filesystem \a fs.
	 * @param fs Sefs filesystem from which to create the database.
	 * @param msg_callback Callback to invoke as errors/warnings are
	 * generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to the
	 * callback function.
	 * @exception std::invalid_argument Filesystem does not exist.
	 * @exception std::runtime_error Error while reading the
	 * database.
	 */
	 sefs_db(sefs_filesystem * fs, sefs_callback_fn_t msg_callback, void *varg) throw(std::invalid_argument,
											  std::runtime_error);

	/**
	 * Allocate and return a new sefs database, loading the
	 * entries from an existing database stored at \a path.
	 * @param filename Name of a sefs database from which to load.
	 * @param msg_callback Callback to invoke as errors/warnings
	 * are generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to
	 * the callback function.
	 * @exception std::invalid_argument Database does not exist.
	 * @exception std::runtime_error Error while reading the
	 * database.
	 */
	 sefs_db(const char *filename, sefs_callback_fn_t msg_callback, void *varg) throw(std::invalid_argument,
											  std::runtime_error);

	~sefs_db();

	/**
	 * Perform a sefs query on this database object, and then
	 * invoke a callback upon each matching entry.  Entries will
	 * be returned in alphabetical order by path.
	 * @param query Query object containing search parameters.  If
	 * NULL, invoke the callback on all entries.
	 * @param fn Function to invoke upon matching entries.  This
	 * function will be called with three parameters: a pointer to
	 * this database, pointer to a matching entry, and an
	 * arbitrary data pointer.  It should return a non-negative
	 * value upon success, negative value upon error and to abort
	 * the mapping.
	 * @param data Arbitrary pointer to be passed into \fn as a
	 * third parameter.
	 * @return Last value returned by fn() (i.e., >= on success, <
	 * 0 on failure).  If the database has no entries then
	 * return 0.
	 * @exception std::runtime_error Error while reading contexts
	 * from the database.
	 */
	int runQueryMap(sefs_query * query, sefs_fclist_map_fn_t fn, void *data) throw(std::runtime_error);

	/**
	 * Determine if the contexts stored in this database contain
	 * MLS fields.
	 * @return \a true if MLS fields are present, \a false if not
	 * or undeterminable.
	 */
	bool isMLS() const;

	/**
	 * Write a database to disk, overwriting any existing file.
	 * The database may then be read by calling the appropriate
	 * constructor.
	 * @param filename Name of file to which write.
	 * @exception std::invalid_argument No filename given.
	 * @exception std::runtime_error Error while writing the
	 * database.
	 */
	void save(const char *filename) throw(std::invalid_argument, std::runtime_error);

	/**
	 * Get the creation time of a sefs database.
	 * @return Creation time of the database, or 0 on error.
	 */
	time_t getCTime() const;

	/**
	 * Determine if the given file is a valid sefs_db.  This
	 * does not thoroughly load the file, rather just the header
	 * of the file.
	 * @param filename Name of file to check.
	 * @return True if the file appears to be a database, false if not.
	 */
	static bool isDB(const char *filename);

      private:
	/**
	 * Upgrade an existing version 1 database to version 2.
	 */
	void upgradeToDB2() throw(std::runtime_error);

	const struct sefs_context_node *getContextNode(const sefs_entry * entry);
	sefs_entry *getEntry(const struct sefs_context_node *context, uint32_t objectClass, const char *path, ino64_t inode,
			     const char *dev) throw(std::bad_alloc);
	struct sqlite3 *_db;
	time_t _ctime;
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore
//the compatibility section.
#ifndef SWIG

	typedef struct sefs_db sefs_db_t;
	typedef struct sefs_filesystem sefs_filesystem_t;

/**
 * Allocate and return a new sefs database from the filesystem \a fs.
 * @see sefs_db::sefs_db(const sefs_filesystem &fs, sefs_callback_fn_t msg_callback, void *varg)
 */
	extern sefs_fclist_t *sefs_db_create_from_filesystem(sefs_filesystem_t * fs, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Allocate and return a new sefs database, loading the entries from
 * the saved database \a path.
 * @see sefs_db::sefs_db(const char *filename, sefs_callback_fn_t msg_callback, void *varg)
 */
	extern sefs_fclist_t *sefs_db_create_from_file(const char *path, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Write a database to disk, overwriting any existing file.
 * @see sefs_db::save()
 */
	extern int sefs_db_save(sefs_db_t * db, const char *filename);

/**
 * Get the creation time of a sefs database.
 * @see sefs_db::getCTime()
 */
	extern time_t sefs_db_get_ctime(sefs_db_t * db);

/**
 * Determine if the given file is a valid sefs_db.
 * @see sefs_db::isDB()
 */
	extern bool sefs_db_is_db(const char *filename);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_DB_H */
