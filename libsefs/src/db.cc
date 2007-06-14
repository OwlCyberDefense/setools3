/**
 * @file
 *
 * Routines for creating, saving, and loading a sqlite3 database
 * containing paths + file contexts.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include <sefs/db.hh>
#include <sefs/filesystem.hh>
#include <sefs/entry.hh>
#include <apol/util.h>

#include <sqlite3.h>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DB_SCHEMA_NONMLS \
	"CREATE TABLE users (user_id INTEGER PRIMARY KEY, user_name varchar (24));" \
	"CREATE TABLE roles (role_id INTEGER PRIMARY KEY, role_name varchar (24));" \
	"CREATE TABLE types (type_id INTEGER PRIMARY KEY, type_name varchar (48));" \
	"CREATE TABLE paths (inode int, path varchar (128) PRIMARY KEY);" \
	"CREATE TABLE inodes (inode_id INTEGER PRIMARY KEY, dev int, ino int(64), user int, role int, type int, range int, obj_class int, symlink_target varchar (128));" \
	"CREATE TABLE info (key varchar, value varchar);" \
	"CREATE INDEX inodes_index ON inodes (ino,dev);" \
	"CREATE INDEX paths_index ON paths (inode);"

#define DB_SCHEMA_MLS DB_SCHEMA_NONMLS \
	"CREATE TABLE mls (mls_id INTEGER PRIMARY KEY, mls_range varchar (64));"

// wrapper functions to go between non-OO land into OO member functions

inline struct sefs_context_node *db_get_context(sefs_db * db, const char *user, const char *role, const char *type,
						const char *range) throw(std::bad_alloc)
{
	return db->getContext(user, role, type, range);
}

inline sefs_entry *db_get_entry(sefs_db * db, const struct sefs_context_node * node, uint32_t objClass,
				const char *path, ino64_t inode, dev_t dev)throw(std::bad_alloc)
{
	return db->getEntry(node, objClass, path, inode, dev);
}

/******************** sqlite3 callback functions ********************/

struct db_callback_arg
{
	struct sqlite3 *db;
	char *errmsg;
	const char *source_db, *target_db;
};

struct db_query_arg
{
	sefs_db *db;
	char *user, *role, *type, *range, *path;
	bool regex, db_is_mls;
	regex_t *reuser, *rerole, *retype, *rerange, *repath;
	sefs_fclist_map_fn_t fn;
	void *data;
	bool aborted;
	int retval;
};

/**
 * Callback invoked when selecting names of tables from a database.
 */
static int db_copy_schema(void *arg, int argc __attribute__ ((unused)), char *argv[], char *column_names[] __attribute__ ((unused)))
{
	// argv[0] contains a SQL statement that, if executed against a
	// db, will create a table
	struct db_callback_arg *db = static_cast < struct db_callback_arg *>(arg);
	if (sqlite3_exec(db->db, argv[0], NULL, NULL, &(db->errmsg)) != SQLITE_OK)
	{
		return -1;
	}
	return 0;
}

/**
 * Callback invoked when selecting each row from a table.
 */
static int db_copy_table(void *arg, int argc __attribute__ ((unused)), char *argv[], char *column_names[] __attribute__ ((unused)))
{
	// argv[0] contains the name of a table
	struct db_callback_arg *db = static_cast < struct db_callback_arg *>(arg);
	char *insert = NULL;
	if (asprintf(&insert, "INSERT INTO %s%s SELECT * FROM %s%s", db->target_db, argv[0], db->source_db, argv[0]) < 0)
	{
		db->errmsg = strdup(strerror(errno));
		return -1;
	}
	int rc = sqlite3_exec(db->db, insert, NULL, NULL, &(db->errmsg));
	free(insert);
	if (rc != SQLITE_OK)
	{
		return -1;
	}
	return 0;
}

/**
 * Callback invoked when selecting a user (for a sefs_query).
 */
static void db_user_compare(sqlite3_context * context, int argc __attribute__ ((unused)), sqlite3_value ** argv)
{
	void *arg = sqlite3_user_data(context);
	struct db_query_arg *q = static_cast < struct db_query_arg *>(arg);
	assert(sqlite3_value_type(argv[0]) == SQLITE_TEXT);
	const char *text = reinterpret_cast < const char *>(sqlite3_value_text(argv[0]));
	bool retval = query_str_compare(text, q->user, q->reuser, q->regex);
	sqlite3_result_int(context, (retval ? 1 : 0));
}

/**
 * Callback invoked when selecting a role (for a sefs_query).
 */
static void db_role_compare(sqlite3_context * context, int argc __attribute__ ((unused)), sqlite3_value ** argv)
{
	void *arg = sqlite3_user_data(context);
	struct db_query_arg *q = static_cast < struct db_query_arg *>(arg);
	assert(sqlite3_value_type(argv[0]) == SQLITE_TEXT);
	const char *text = reinterpret_cast < const char *>(sqlite3_value_text(argv[0]));
	bool retval = query_str_compare(text, q->role, q->rerole, q->regex);
	sqlite3_result_int(context, (retval ? 1 : 0));
}

/**
 * Callback invoked when selecting a type (for a sefs_query).
 */
static void db_type_compare(sqlite3_context * context, int argc __attribute__ ((unused)), sqlite3_value ** argv)
{
	void *arg = sqlite3_user_data(context);
	struct db_query_arg *q = static_cast < struct db_query_arg *>(arg);
	assert(sqlite3_value_type(argv[0]) == SQLITE_TEXT);
	const char *text = reinterpret_cast < const char *>(sqlite3_value_text(argv[0]));
	bool retval = query_str_compare(text, q->type, q->retype, q->regex);
	sqlite3_result_int(context, (retval ? 1 : 0));
}

/**
 * Callback invoked when selecting a path (for a sefs_query).
 */
static void db_path_compare(sqlite3_context * context, int argc __attribute__ ((unused)), sqlite3_value ** argv)
{
	void *arg = sqlite3_user_data(context);
	struct db_query_arg *q = static_cast < struct db_query_arg *>(arg);
	assert(sqlite3_value_type(argv[0]) == SQLITE_TEXT);
	const char *text = reinterpret_cast < const char *>(sqlite3_value_text(argv[0]));
	bool retval = query_str_compare(text, q->path, q->repath, q->regex);
	sqlite3_result_int(context, (retval ? 1 : 0));
}

/**
 * Callback invoked when selecting rows during a query.
 */
static int db_query_callback(void *arg, int argc, char *argv[], char *column_names[] __attribute__ ((unused)))
{
	struct db_query_arg *q = static_cast < struct db_query_arg *>(arg);
	char *user = argv[0];
	char *role = argv[1];
	char *type = argv[2];
	char *range, *path, *objclass_str;
	ino64_t ino;
	dev_t dev;
	if (q->db_is_mls)
	{
		range = argv[3];
		path = argv[4];
		objclass_str = argv[5];
		assert(argc == 8);
		ino = static_cast < ino64_t > (strtoul(argv[6], NULL, 10));
		dev = static_cast < dev_t > (strtoul(argv[7], NULL, 10));
	}
	else
	{
		range = NULL;
		path = argv[3];
		objclass_str = argv[4];
		assert(argc == 7);
		ino = static_cast < ino64_t > (strtoul(argv[5], NULL, 10));
		dev = static_cast < dev_t > (strtoul(argv[6], NULL, 10));
	}
	struct sefs_context_node *node = NULL;
	try
	{
		node = db_get_context(q->db, user, role, type, range);
	}
	catch(...)
	{
		return -1;
	}

	uint32_t objClass = static_cast < uint32_t > (atoi(objclass_str));
	sefs_entry *entry = NULL;
	try
	{
		entry = db_get_entry(q->db, node, objClass, path, ino, dev);
	}
	catch(...)
	{
		return -1;
	}

	// invoke real callback (not just the sqlite3 exec callback)
	q->retval = q->fn(q->db, entry, q->data);
	delete entry;
	if (q->retval < 0)
	{
		q->aborted = true;
		return -1;
	}
	return 0;
}

/**
 * Callback invoked when checking if there exists any row with the
 * given select parameters.
 */
static int db_row_exist_callback(void *arg,
				 int argc __attribute__ ((unused)),
				 char **argv __attribute__ ((unused)), char **col_names __attribute__ ((unused)))
{
	bool *answer = static_cast < bool * >(arg);
	*answer = true;
	return 0;
}

/**
 * Callback invoked when obtaining the ctime value from the database.
 */
static int db_ctime_callback(void *arg, int argc __attribute__ ((unused)), char **argv, char **col_names __attribute__ ((unused)))
{
	time_t *ctime = static_cast < time_t * >(arg);
	// argv has the result of a call to ctime_r(); convert the string
	// back to a time_t value
	struct tm t;
	if (strptime(argv[0], "%a %b %d %T %Y", &t) == NULL)
	{
		return -1;
	}
	*ctime = mktime(&t);
	return 0;
}

/**
 * Callback invoked to determine how many rows match a particular
 * select statement.
 */
static int db_count_callback(void *arg, int argc __attribute__ ((unused)), char **argv, char **column_names
			     __attribute__ ((unused)))
{
	int *count = static_cast < int *>(arg);
	*count = atoi(argv[0]);
	return 0;
}

/******************** public functions below ********************/

static int db_create_from_filesystem(sefs_fclist * fclist __attribute__ ((unused)), const sefs_entry * entry, void *arg)
{
	struct sqlite3 *db = static_cast < struct sqlite3 *>(arg);
	// FIX ME: for each entry, add its information into DB
	return 0;
}

sefs_db::sefs_db(sefs_filesystem * fs, sefs_callback_fn_t msg_callback, void *varg)throw(std::invalid_argument, std::runtime_error):sefs_fclist
	(SEFS_FCLIST_TYPE_DB, msg_callback,
	 varg)
{
	if (fs == NULL)
	{
		errno = EINVAL;
		SEFS_ERR("%s", strerror(EINVAL));
		throw std::invalid_argument(strerror(EINVAL));
	}

	char *errmsg = NULL;
	try
	{
		if (sqlite3_open(":memory:", &_db) != SQLITE_OK)
		{
			SEFS_ERR("%s", sqlite3_errmsg(_db));
			throw std::runtime_error(sqlite3_errmsg(_db));
		}
		// FIX ME: enable PRAGMA auto_vacuum = 1
		int rc;
		if (fs->isMLS())
		{
			rc = sqlite3_exec(_db, DB_SCHEMA_MLS, NULL, 0, &errmsg);
		}
		else
		{
			rc = sqlite3_exec(_db, DB_SCHEMA_NONMLS, NULL, 0, &errmsg);
		}
		if (rc != SQLITE_OK)
		{
			SEFS_ERR("%s", errmsg);
			throw std::runtime_error(errmsg);
		}
		if (fs->runQueryMap(NULL, db_create_from_filesystem, _db) < 0)
		{
			throw std::runtime_error(sqlite3_errmsg(_db));
		}

		// store metadata about the database
		const char *dbversion = "2";
		char hostname[64];
		gethostname(hostname, sizeof(hostname));
		hostname[63] = '\0';
		_ctime = time(NULL);
		char datetime[32];
		ctime_r(&_ctime, datetime);

		char *info_insert = NULL;
		if (asprintf(&info_insert,
			     "INSERT INTO diskdb.info (key,value) VALUES ('dbversion','%s');"
			     "INSERT INTO diskdb.info (key,value) VALUES ('hostname','%s');"
			     "INSERT INTO diskdb.info (key,value) VALUES ('datetime','%s');", dbversion, hostname, datetime) < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		rc = sqlite3_exec(_db, info_insert, NULL, NULL, &errmsg);
		free(info_insert);
		if (rc != SQLITE_OK)
		{
			SEFS_ERR("%s", errmsg);
			throw std::runtime_error(errmsg);
		}

	}
	catch(...)
	{
		if (errmsg != NULL)
		{
			sqlite3_free(errmsg);
		}
		sqlite3_close(_db);
		throw;
	}
}

sefs_db::sefs_db(const char *filename, sefs_callback_fn_t msg_callback, void *varg) throw(std::invalid_argument,
											  std::
											  runtime_error):sefs_fclist
	(SEFS_FCLIST_TYPE_DB, msg_callback, varg)
{
	if (filename == NULL)
	{
		errno = EINVAL;
		SEFS_ERR("%s", strerror(EINVAL));
		throw std::invalid_argument(strerror(EINVAL));
	}

	if (!sefs_db::isDB(filename))
	{
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}

	if (sqlite3_open(filename, &_db) != SQLITE_OK)
	{
		SEFS_ERR("%s", sqlite3_errmsg(_db));
		sqlite3_close(_db);
		throw std::runtime_error(strerror(errno));
	}

	char *errmsg = NULL;

	const char *select_stmt = "SELECT * FROM info WHERE key = 'dbversion' AND value >= 2";
	bool answer = false;
	if (sqlite3_exec(_db, select_stmt, db_row_exist_callback, &answer, &errmsg) != SQLITE_OK)
	{
		SEFS_ERR("%s", errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(_db);
		throw std::runtime_error(strerror(errno));
	}
	if (!answer)
	{
		SEFS_WARN("%s is a pre-libsefs-4.0 database and will be upgraded.", filename);
		upgradeToDB2();
	}

	// get ctime from db
	_ctime = 0;
	const char *ctime_stmt = "SELECT value FROM info WHERE key='datetime'";
	if (sqlite3_exec(_db, ctime_stmt, db_ctime_callback, &_ctime, &errmsg) != SQLITE_OK)
	{
		SEFS_ERR("%s", errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(_db);
		throw std::runtime_error(strerror(errno));
	}
}

sefs_db::~sefs_db()
{
	if (_db != NULL)
	{
		sqlite3_close(_db);
		_db = NULL;
	}
}

int sefs_db::runQueryMap(sefs_query * query, sefs_fclist_map_fn_t fn, void *data) throw(std::runtime_error)
{
	// copy the query fields over to the C land struct; this is
	// because the query members are private, and thus not accessible
	// from a C callback
	struct db_query_arg q;
	memset(&q, sizeof(q), 0);

	q.db = this;
	if (query != NULL)
	{
		query->compile();
		// FIX ME: build candidate types list and stuff upon policy
		q.user = query->_user;
		q.role = query->_role;
		q.type = query->_type;
		q.range = query->_range;
		q.path = query->_path;
		q.regex = query->_regex;
		q.reuser = query->_reuser;
		q.rerole = query->_rerole;
		q.retype = query->_retype;
		q.rerange = query->_rerange;
		q.repath = query->_repath;
	}
	q.db_is_mls = isMLS();
	q.fn = fn;
	q.data = data;
	q.retval = 0;
	q.aborted = false;

	char *select_stmt = NULL, *errmsg = NULL;
	size_t len = 0;

	try
	{
		bool where_added = false;

		if (apol_str_append(&select_stmt, &len, "SELECT users.user_name, roles.role_name, types.type_name") < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (q.db_is_mls && apol_str_append(&select_stmt, &len, ", mls.mls_range") < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (apol_str_append(&select_stmt, &len,
				    ", paths.path, inodes.obj_class, inodes.ino, inodes.dev FROM users, roles, types") < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (q.db_is_mls && apol_str_append(&select_stmt, &len, ", mls") < 0)
		{
			throw std::runtime_error(strerror(errno));
		}
		if (apol_str_append(&select_stmt, &len, ", paths, inodes ") < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}

		if (q.user != NULL)
		{
			if (sqlite3_create_function(_db, "user_compare", 1, SQLITE_UTF8, &q, db_user_compare, NULL, NULL) !=
			    SQLITE_OK)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (user_compare(users.user_name))", (where_added ? " AND" : " WHERE")) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (q.role != NULL)
		{
			if (sqlite3_create_function(_db, "role_compare", 1, SQLITE_UTF8, &q, db_role_compare, NULL, NULL) !=
			    SQLITE_OK)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (role_compare(roles.role_name))", (where_added ? " AND" : " WHERE")) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (q.type != NULL)
		{
			if (sqlite3_create_function(_db, "type_compare", 1, SQLITE_UTF8, &q, db_type_compare, NULL, NULL) !=
			    SQLITE_OK)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (type_compare(types.type_name))", (where_added ? " AND" : " WHERE")) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (q.range != NULL)
		{
			// FIX ME
		}

		if (query->_objclass != 0)
		{
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (inodes.obj_class = %d)", (where_added ? " AND" : " WHERE"), query->_objclass) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (q.path != NULL)
		{
			if (sqlite3_create_function(_db, "path_compare", 1, SQLITE_UTF8, &q, db_path_compare, NULL, NULL) !=
			    SQLITE_OK)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (path_compare(paths.path))", (where_added ? " AND" : " WHERE")) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (query->_inode != 0)
		{
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (inodes.ino = %lld)", (where_added ? " AND" : " WHERE"), query->_inode) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (query->_dev != 0)
		{
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (inodes.dev = %lld)", (where_added ? " AND" : " WHERE"), query->_dev) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (apol_str_appendf(&select_stmt, &len,
				     "%s (inodes.user = users.user_id AND inodes.role = roles.role_id AND inodes.type = types.type_id",
				     (where_added ? " AND" : "WHERE")) < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (q.db_is_mls && apol_str_appendf(&select_stmt, &len, " AND inodes.range = mls.mls_id") < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (apol_str_append(&select_stmt, &len, " AND inodes.inode_id = paths.inode) ORDER BY paths.path ASC") < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}

		int rc = sqlite3_exec(_db, select_stmt, db_query_callback, &q, &errmsg);
		if (rc != SQLITE_OK && (rc != SQLITE_ABORT || !q.aborted))
		{
			SEFS_ERR("%s", errmsg);
			throw std::runtime_error(errmsg);
		}
	}
	catch(...)
	{
		free(select_stmt);
		sqlite3_free(errmsg);
		throw;
	}

	free(select_stmt);
	sqlite3_free(errmsg);
	return q.retval;
}

bool sefs_db::isMLS() const
{
	int rc;
	bool answer = false;
	char *errmsg = NULL;
	const char *select_stmt = "SELECT * FROM sqlite_master WHERE name='mls'";
	rc = sqlite3_exec(_db, select_stmt, db_row_exist_callback, &answer, &errmsg);
	if (rc != SQLITE_OK)
	{
		SEFS_ERR("%s", errmsg);
		sqlite3_free(errmsg);
		answer = false;
	}
	return answer;
}

void sefs_db::save(const char *filename) throw(std::invalid_argument, std::runtime_error)
{
	FILE *fp = NULL;
	struct db_callback_arg diskdb;
	diskdb.db = NULL;
	diskdb.errmsg = NULL;
	bool in_transaction = false;

	try
	{
		if (filename == NULL)
		{
			errno = EINVAL;
			throw std::invalid_argument(strerror(errno));
		}
		// check that target file is creatable; this will also
		// remove the file if it already exists
		if ((fp = fopen(filename, "w")) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		fclose(fp);
		fp = NULL;

		// copy database schema from in-memory db to the one on disk
		if (sqlite3_open(filename, &(diskdb.db)) != SQLITE_OK)
		{
			SEFS_ERR("%s", sqlite3_errmsg(diskdb.db));
			throw std::runtime_error(sqlite3_errmsg(diskdb.db));
		}
		if (sqlite3_exec(_db, "SELECT sql FROM sqlite_master WHERE sql NOT NULL", db_copy_schema, &diskdb, &diskdb.errmsg)
		    != SQLITE_OK)
		{
			SEFS_ERR("%s", diskdb.errmsg);
			throw std::runtime_error(diskdb.errmsg);
		}
		sqlite3_close(diskdb.db);

		// copy contents from in-memory db to the one on disk
		if (sqlite3_exec(_db, "BEGIN TRANSACTION", NULL, NULL, &(diskdb.errmsg)) != SQLITE_OK)
		{
			SEFS_ERR("%s", diskdb.errmsg);
			throw std::runtime_error(diskdb.errmsg);
		}
		in_transaction = true;
		char *attach = NULL;
		if (asprintf(&attach, "ATTACH '%s' AS diskdb", filename) < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		diskdb.source_db = "";
		diskdb.target_db = "diskdb.";
		int rc = sqlite3_exec(_db, attach, NULL, NULL, &diskdb.errmsg);
		free(attach);
		if (rc != SQLITE_OK)
		{
			SEFS_ERR("%s", diskdb.errmsg);
			throw std::runtime_error(diskdb.errmsg);
		}
		if (sqlite3_exec(_db, "SELECT name FROM sqlite_master WHERE type ='table'", db_copy_table, &diskdb, &diskdb.errmsg)
		    != SQLITE_OK)
		{
			SEFS_ERR("%s", diskdb.errmsg);
			throw std::runtime_error(diskdb.errmsg);
		}

		sqlite3_exec(_db, "DETACH diskdb", NULL, NULL, NULL);

		if (sqlite3_exec(_db, "END TRANSACTION", NULL, 0, &(diskdb.errmsg)) != SQLITE_OK)
		{
			SEFS_ERR("%s", diskdb.errmsg);
			throw std::runtime_error(diskdb.errmsg);
		}
		in_transaction = false;
	}
	catch(...)
	{
		if (fp != NULL)
		{
			fclose(fp);
		}
		if (in_transaction)
		{
			sqlite3_exec(_db, "ROLLBACK TRANSACTION", NULL, NULL, NULL);
		}
		if (diskdb.db != NULL)
		{
			sqlite3_close(diskdb.db);
		}
		sqlite3_free(diskdb.errmsg);
		throw;
	}
	sqlite3_close(diskdb.db);
	sqlite3_free(diskdb.errmsg);
}

time_t sefs_db::getCTime() const
{
	return _ctime;
}

bool sefs_db::isDB(const char *filename)
{
	if (filename == NULL)
	{
		errno = EINVAL;
		return false;
	}

	int rc = access(filename, R_OK);
	if (rc != 0)
	{
		return false;
	}

	struct sqlite3 *db = NULL;
	rc = sqlite3_open(filename, &db);
	if (rc != SQLITE_OK)
	{
		sqlite3_close(db);
		errno = EIO;
		return false;
	}

	// Run a simple query to check that the database is legal.
	int list_size;
	char *errmsg = NULL;
	rc = sqlite3_exec(db, "SELECT type_name FROM types", db_count_callback, &list_size, &errmsg);
	if (rc != SQLITE_OK)
	{
		sqlite3_close(db);
		sqlite3_free(errmsg);
		errno = EIO;
		return false;
	}
	sqlite3_close(db);
	return true;
}

/******************** private functions below ********************/

void sefs_db::upgradeToDB2() throw(std::runtime_error)
{
	char *errmsg;

	// Add a role field for each inode entry within the database;
	// assume that the role is 'object_r'.  Also update the object
	// class values, from older class values to new ones.  Old
	// class_id values come from the old libsefs < 4.0 definitions
	// that were in fsdata.h; the new style is in
	// qpol/genfscon_query.h.
	_ctime = time(NULL);
	char datetime[32];
	ctime_r(&_ctime, datetime);
	char *alter_stmt = NULL;
	if (asprintf(&alter_stmt, "BEGIN TRANSACTION;" "CREATE TABLE roles (role_id INTEGER PRIMARY KEY, role_name varchar (24));" "ALTER TABLE inodes ADD COLUMN role int DEFAULT 0;" "INSERT INTO roles (role_id, role_name) VALUES (0, 'object_r');" "UPDATE inodes SET obj_class = 11 WHERE obj_class = 16;"	// block file
		     "UPDATE inodes SET obj_class = 10 WHERE obj_class = 8;"	// char file
		     "UPDATE inodes SET obj_class = 7 WHERE obj_class = 2;"	// dir
		     "UPDATE inodes SET obj_class = 13 WHERE obj_class = 64;"	// fifo file
		     "UPDATE inodes SET obj_class = 6 WHERE obj_class = 1;"	// normal file
		     "UPDATE inodes SET obj_class = 9 WHERE obj_class = 4;"	// link file
		     "UPDATE inodes SET obj_class = 12 WHERE obj_class = 32;"	// sock file
		     "UPDATE info SET value = '%s' WHERE key = 'datetime';" "END TRANSACTION;", datetime) < 0)
	{
		SEFS_ERR("%s", errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(_db);
		throw std::runtime_error(strerror(errno));
	}

	if (sqlite3_exec(_db, alter_stmt, NULL, NULL, &errmsg) != SQLITE_OK)
	{
		SEFS_ERR("%s", errmsg);
		free(alter_stmt);
		sqlite3_free(errmsg);
		sqlite3_close(_db);
		throw std::runtime_error(strerror(errno));
	}
	free(alter_stmt);
}

sefs_entry *sefs_db::getEntry(const struct sefs_context_node *context, uint32_t objectClass, const char *path, ino64_t inode,
			      dev_t dev) throw(std::bad_alloc)
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
	e->_inode = inode;
	// e->_dev = dev; FIX ME
	return e;
}

/******************** C functions below ********************/

sefs_fclist_t *sefs_db_create_from_filesystem(sefs_filesystem_t * fs, sefs_callback_fn_t msg_callback, void *varg)
{
	sefs_fclist_t *fc = NULL;
	try
	{
		fc = new sefs_db(fs, msg_callback, varg);
	}
	catch(...)
	{
		return NULL;
	}
	return fc;
}

sefs_fclist_t *sefs_db_create_from_file(const char *filename, sefs_callback_fn_t msg_callback, void *varg)
{
	sefs_fclist_t *fc = NULL;
	try
	{
		fc = new sefs_db(filename, msg_callback, varg);
	}
	catch(...)
	{
		return NULL;
	}
	return fc;
}

int sefs_db_save(sefs_db_t * db, const char *filename)
{
	if (db == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	try
	{
		db->save(filename);
	}
	catch(...)
	{
		return -1;
	}
	return 0;
}

time_t sefs_db_get_ctime(sefs_db_t * db)
{
	if (db == NULL)
	{
		errno = EINVAL;
		return static_cast < time_t > (-1);
	}
	return db->getCTime();
}

bool sefs_db_is_db(const char *filename)
{
	return sefs_db::isDB(filename);
}

#if 0

typedef struct inode_key
{
	ino_t inode;
	dev_t dev;
} inode_key_t;

struct sefs_typeinfo;

typedef struct sefs_context
{
	char *user, *role;
	struct sefs_typeinfo *type;
	char *range;
} sefs_context_t;

typedef struct sefs_fileinfo
{
	inode_key_t key;
	uint32_t num_links;
	sefs_context_t context;
	char **path_names;
	char *symlink_target;
/* this uses defines from above */
	uint32_t obj_class;
} sefs_fileinfo_t;

typedef struct sefs_typeinfo
{
	char *name;
	uint32_t num_inodes;
	uint32_t *index_list;
} sefs_typeinfo_t;

/* Management and creation functions */
static int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd);
static void destroy_fsdata(sefs_filesystem_data_t * fsd);
static int sefs_get_class_int(const char *class);

/**
 * Allocate the SQL select statement for a given search keys query.
 * Write the generated statement to the reference pointer stmt; the
 * caller is responsible for free()ing it afterwards.  Note that if
 * the database is not MLS, then MLS related fields within search_keys
 * are ignored.
 *
 * @param stmt Reference to where to store generated SQL statement.
 * @param search_keys Criteria for search.
 * @param objects Array of object class indices for search.
 * @param db_is_mls Flag to indicate if database has MLS components.
 *
 * @return 0 on success, < 0 on error.
 */
static int sefs_stmt_populate(char **stmt, sefs_search_keys_t * search_keys, int *objects, int db_is_mls)
{
	int idx, where_added = 0;
	size_t stmt_size = 0;
	*stmt = NULL;

	/* first put the starting statement */
	if (db_is_mls)
	{
		APPEND("%s", STMTSTART_MLS);
	}
	else
	{
		APPEND("%s", STMTSTART_NONMLS);
	}

	/* now we go through the search keys populating the statement */
	/* type,user,path,object_class */
	if (search_keys->type && search_keys->num_type > 0)
	{
		if (!where_added)
		{
			APPEND(" where (");
			where_added = 1;
		}
		else
		{
			APPEND(" (");
		}
		for (idx = 0; idx < search_keys->num_type; idx++)
		{
			if (idx > 0)
			{
				APPEND(" OR");
			}
			if (search_keys->do_type_regEx)
				APPEND(" sefs_types_compare(types.type_name,\"%s\")", search_keys->type[idx]);
			else
				APPEND(" types.type_name = \"%s\"", search_keys->type[idx]);
		}
	}

	if (search_keys->user && search_keys->num_user > 0)
	{
		if (!where_added)
		{
			APPEND(" where (");
			where_added = 1;
		}
		else
		{
			APPEND(") AND (");
		}
		for (idx = 0; idx < search_keys->num_user; idx++)
		{
			if (idx > 0)
			{
				APPEND(" OR");
			}
			if (search_keys->do_user_regEx)
				APPEND(" sefs_users_compare(users.user_name,\"%s\")", search_keys->user[idx]);
			else
				APPEND(" users.user_name = \"%s\"", search_keys->user[idx]);
		}
	}

	if (search_keys->path && search_keys->num_path > 0)
	{
		if (!where_added)
		{
			APPEND(" where (");
			where_added = 1;
		}
		else
		{
			APPEND(") AND (");
		}
		for (idx = 0; idx < search_keys->num_path; idx++)
		{
			if (idx > 0)
			{
				APPEND(" OR");
			}
			if (search_keys->do_path_regEx)
				APPEND(" sefs_paths_compare(paths.path,\"%s\")", search_keys->path[idx]);
			else
				APPEND(" paths.path LIKE \"%s%%\"", search_keys->path[idx]);
		}
	}

	if (search_keys->object_class && search_keys->num_object_class > 0)
	{
		if (!where_added)
		{
			APPEND(" where (");
			where_added = 1;
		}
		else
		{
			APPEND(") AND (");
		}
		for (idx = 0; idx < search_keys->num_object_class; idx++)
		{
			if (idx > 0)
			{
				APPEND(" OR");
			}
			APPEND(" inodes.obj_class = %d", objects[idx]);
		}
	}

	if (search_keys->range && search_keys->num_range > 0)
	{
		if (!where_added)
		{
			APPEND(" where (");
			where_added = 1;
		}
		else
		{
			APPEND(") AND (");
		}
		for (idx = 0; idx < search_keys->num_range; idx++)
		{
			if (idx > 0)
			{
				APPEND(" OR");
			}
			if (search_keys->do_range_regEx)
				APPEND(" sefs_range_compare(mls.mls_range,\"%s\")", search_keys->range[idx]);
			else
				APPEND(" mls.mls_range = \"%s\"", search_keys->range[idx]);
		}
	}

	if (where_added)
	{
		APPEND(") AND");
	}
	else
	{
		APPEND(" where");
	}
	if (db_is_mls)
	{
		APPEND(" %s %s", STMTEND_MLS, SORTSTMT);
	}
	else
	{
		APPEND(" %s %s", STMTEND_NONMLS, SORTSTMT);
	}
	return 0;
}

struct search_types_arg
{
	char **list;
	int count;
};

/* compare a range value with a precompiled regular expression */
static void sefs_range_compare(sqlite3_context * context, int argc, sqlite3_value ** argv)
{
	int retVal = 0;
	const char *text;
	regmatch_t pm;

	/* make sure we got the arguments */
	assert(argc == 2);

	/* make sure we got the right kind of argument */
	if (sqlite3_value_type(argv[0]) == SQLITE_TEXT)
	{
		text = (const char *)sqlite3_value_text(argv[0]);
		if (regexec(&range_re, text, 1, &pm, 0) == 0)
			retVal = 1;
	}
	sqlite3_result_int(context, retVal);
}

int sefs_filesystem_db_search(sefs_filesystem_db_t * fsd, sefs_search_keys_t * search_keys)
{

	char *stmt = NULL;
	int *object_class = NULL;
	int types_regcomp = 0, users_regcomp = 0, paths_regcomp = 0, range_regcomp = 0;
	int db_is_mls = 0;
	int rc, i, ret_val = -1;
	char *errmsg = NULL;
	size_t errmsg_sz;

	db = (sqlite3 *) (*fsd->dbh);
	sefs_search_keys = search_keys;

	/* reset the return data */
	/* here put in our search key destructor if not null */
	sefs_search_keys->search_ret = NULL;

	if (!db)
	{
		fprintf(stderr, "unable to read db\n");
		goto cleanup;
	}
	if ((db_is_mls = sefs_filesystem_db_is_mls(fsd)) < 0)
	{
		goto cleanup;
	}

	/* malloc out and set up our object classes as ints */
	if (search_keys->num_object_class > 0)
	{
		object_class = (int *)malloc(sizeof(int) * search_keys->num_object_class);
		if (object_class == NULL)
		{
			fprintf(stderr, "Out of memory.");
			goto cleanup;
		}
		for (i = 0; i < search_keys->num_object_class; i++)
		{
			object_class[i] = sefs_get_class_int(search_keys->object_class[i]);
		}
	}

	/* are we searching using regexp? */
	if (search_keys->num_type > 0 && search_keys->do_type_regEx)
	{
		/* create our comparison functions */
		sqlite3_create_function(db, "sefs_types_compare", 2, SQLITE_UTF8, NULL, &sefs_types_compare, NULL, NULL);
		rc = regcomp(&types_re, search_keys->type[0], REG_NOSUB | REG_EXTENDED);
		if (rc != 0)
		{
			errmsg_sz = regerror(rc, &types_re, NULL, 0);
			if ((errmsg = (char *)malloc(errmsg_sz)) == NULL)
			{
				fprintf(stderr, "Out of memory.");
				goto cleanup;
			}
			regerror(rc, &types_re, errmsg, errmsg_sz);
			fprintf(stderr, "%s", errmsg);
			goto cleanup;
		}
		else
		{
			types_regcomp = 1;
		}
	}
	if (search_keys->num_user > 0 && search_keys->do_user_regEx)
	{
		sqlite3_create_function(db, "sefs_users_compare", 2, SQLITE_UTF8, NULL, &sefs_users_compare, NULL, NULL);
		rc = regcomp(&users_re, search_keys->user[0], REG_NOSUB | REG_EXTENDED);
		if (rc != 0)
		{
			errmsg_sz = regerror(rc, &users_re, NULL, 0);
			if ((errmsg = (char *)malloc(errmsg_sz)) == NULL)
			{
				fprintf(stderr, "Out of memory.");
				goto cleanup;
			}
			regerror(rc, &users_re, errmsg, errmsg_sz);
			fprintf(stderr, "%s", errmsg);
			goto cleanup;
		}
		else
		{
			users_regcomp = 1;
		}
	}
	if (search_keys->num_path > 0 && search_keys->do_path_regEx)
	{
		sqlite3_create_function(db, "sefs_paths_compare", 2, SQLITE_UTF8, NULL, &sefs_paths_compare, NULL, NULL);
		rc = regcomp(&paths_re, search_keys->path[0], REG_NOSUB | REG_EXTENDED);
		if (rc != 0)
		{
			errmsg_sz = regerror(rc, &paths_re, NULL, 0);
			if ((errmsg = (char *)malloc(errmsg_sz)) == NULL)
			{
				fprintf(stderr, "Out of memory.");
				goto cleanup;
			}
			regerror(rc, &paths_re, errmsg, errmsg_sz);
			fprintf(stderr, "%s", errmsg);
			goto cleanup;
		}
		else
		{
			paths_regcomp = 1;
		}
	}
	if (db_is_mls && search_keys->num_range > 0 && search_keys->do_range_regEx)
	{
		sqlite3_create_function(db, "sefs_range_compare", 2, SQLITE_UTF8, NULL, &sefs_range_compare, NULL, NULL);
		rc = regcomp(&range_re, search_keys->range[0], REG_NOSUB | REG_EXTENDED);
		if (rc != 0)
		{
			errmsg_sz = regerror(rc, &range_re, NULL, 0);
			if ((errmsg = (char *)malloc(errmsg_sz)) == NULL)
			{
				fprintf(stderr, "Out of memory.");
				goto cleanup;
			}
			regerror(rc, &range_re, errmsg, errmsg_sz);
			fprintf(stderr, "%s", errmsg);
			goto cleanup;
		}
		else
		{
			range_regcomp = 1;
		}
	}
	if (sefs_stmt_populate(&stmt, search_keys, object_class, db_is_mls))
	{
		goto cleanup;
	}
	rc = sqlite3_exec(db, stmt, sefs_search_callback, &db_is_mls, &errmsg);
	if (rc != SQLITE_OK)
	{
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		errmsg = NULL;
		ret_val = -1;
	}
	else
		ret_val = 0;

      cleanup:
	/* here we deallocate anything that might need to be */
	free(stmt);
	free(errmsg);
	free(object_class);
	if (types_regcomp)
		regfree(&types_re);
	if (users_regcomp)
		regfree(&users_re);
	if (paths_regcomp)
		regfree(&paths_re);
	if (range_regcomp)
		regfree(&range_re);
	return ret_val;
}

struct sefs_sql_data
{
	char *stmt;
	char **errmsg;
	int id;
	struct sqlite3 *sqldb;
};

static int INSERT_TYPES(const sefs_typeinfo_t * t, struct sefs_sql_data *d)
{
	int rc = 0;

	sprintf(d->stmt, "insert into types (type_name,type_id) values " "(\"%s\",%zu);", t->name, (size_t) t);
	rc = sqlite3_exec(d->sqldb, d->stmt, NULL, 0, d->errmsg);
	d->id++;
	/* sqlite returns 0 for success and positive for
	 * failure.  returning -rc  will make this fit the
	 * desired behavior. */
	return -rc;
}

static int INSERT_USERS(const char *user, struct sefs_sql_data *d)
{
	int rc = 0;
	sprintf(d->stmt, "insert into users (user_name,user_id) values " "(\"%s\",%zu);", user, (size_t) user);

	rc = sqlite3_exec(d->sqldb, d->stmt, NULL, 0, d->errmsg);
	d->id++;

	return -rc;
}

static int INSERT_RANGE(const char *range, struct sefs_sql_data *d)
{
	int rc = 0;
	sprintf(d->stmt, "insert into mls (mls_range,mls_id) values " "(\"%s\",%zu);", range, (size_t) range);
	rc = sqlite3_exec(d->sqldb, d->stmt, NULL, 0, d->errmsg);
	d->id++;

	return -rc;
}

static int INSERT_FILE(const sefs_fileinfo_t * pinfo, struct sefs_sql_data *d)
{
	int rc = 0;
	int j = 0;
	char *new_stmt = NULL;

	if (pinfo->obj_class == SEFS_LNK_FILE && pinfo->symlink_target)
	{
		sprintf(d->stmt, "insert into inodes (inode_id,user,type,range,obj_class,symlink_target,dev,ino"
			") values (%zu,%zu,%zu,%zu,%zu,'%s',%lu,%lu);",
			d->id,
			(size_t) pinfo->context.user, (size_t) pinfo->context.type, (size_t) pinfo->context.range, pinfo->obj_class,
			/* dev_t is an alias for (unsigned long) */
			pinfo->symlink_target, /*(dev_t) */ (unsigned long)(pinfo->key.dev), (ino_t) (pinfo->key.inode));
	}
	else
	{
		sprintf(d->stmt, "insert into inodes (inode_id,user,type,range,obj_class,symlink_target,dev,ino"
			") values (%zu,%zu,%zu,%zu,%zu,'',%lu,%lu);",
			d->id, (size_t) pinfo->context.user, (size_t) pinfo->context.type, (size_t) pinfo->context.range,
			/* dev_t is an alias for (unsigned long) */
			pinfo->obj_class, /*(dev_t) */ (unsigned long)(pinfo->key.dev), (ino_t) (pinfo->key.inode));
	}
	rc = sqlite3_exec(d->sqldb, d->stmt, NULL, 0, d->errmsg);
	if (rc != SQLITE_OK)
		return -rc;

	/* NOTE: the following block of code does not correctly return the
	 * invalid sql statement.  It is, however, how things were done
	 * before I started mucking about with this.  It should probably get
	 * fixed at some point in case any of those statemnts fail.
	 *
	 * NOTE: it will correctly return the SQL error message.
	 */
	for (j = 0; j < pinfo->num_links; j++)
	{
		new_stmt = sqlite3_mprintf("insert into paths (inode,path) values (%d,'%q')", d->id, (char *)pinfo->path_names[j]);
		rc = sqlite3_exec(d->sqldb, new_stmt, NULL, 0, d->errmsg);
		sqlite3_free(new_stmt);
		if (rc != SQLITE_OK)
			return -rc;
	}

	d->id++;
	return -rc;
}

int sefs_filesystem_db_save(sefs_filesystem_db_t * fsd, const char *filename)
{
	int rc = 0;
	FILE *fp = NULL;
	struct sqlite3 *sqldb = NULL;
	char stmt[100000];
	char *errmsg = NULL;
	char hostname[100];
	time_t mytime;
	struct sefs_sql_data ssd;

	sefs_filesystem_data_t *fsdh = (sefs_filesystem_data_t *) (fsd->fsdh);

	/* we should have an fsdh by now */
	assert(fsdh != NULL);

	fp = fopen(filename, "w");
	if (!fp)
	{
		fprintf(stderr, "Error opening save file %s\n", filename);
		return -1;
	}
	fclose(fp);

	/* now open up the file sqldb */
	rc = sqlite3_open(filename, &sqldb);
	if (rc)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sqldb));
		sqlite3_close(sqldb);
		return -1;
	}

	/* apply our schema to it, based upon if any of the files had
	 * a MLS range associated with them */
	if (fsdh->fs_had_range)
	{
		rc = sqlite3_exec(sqldb, DB_SCHEMA_MLS, NULL, 0, &errmsg);
	}
	else
	{
		rc = sqlite3_exec(sqldb, DB_SCHEMA_NONMLS, NULL, 0, &errmsg);
	}
	if (rc != SQLITE_OK)
	{
		fprintf(stderr, "SQL error while creating database(%d): %s\n", rc, errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(sqldb);
		return -1;
	}

	/* now we basically just go through the old data struct moving */
	/* the data to the places it should be for our sqlite3 sqldb */
	sprintf(stmt, "BEGIN TRANSACTION");
	rc = sqlite3_exec(sqldb, stmt, NULL, 0, &errmsg);
	if (rc != SQLITE_OK)
		goto bad;

/******************************************************************
 * replace the following groups with apol_bst_inorder_map() calls
 ******************************************************************/

	/* setup state for map functions */
	ssd.stmt = stmt;	       /* buffer for sql statement */
	ssd.errmsg = &errmsg;	       /* location to store the error message */
	ssd.sqldb = sqldb;	       /* database */

	ssd.id = 0;		       /* ids begin at 0 */
	rc = apol_bst_inorder_map(fsdh->type_tree, (int (*)(const void *, void *))INSERT_TYPES, &ssd);
	if (rc != SQLITE_OK)
		goto bad;

	ssd.id = 0;
	rc = apol_bst_inorder_map(fsdh->user_tree, (int (*)(const void *, void *))INSERT_USERS, &ssd);
	if (rc != SQLITE_OK)
		goto bad;

	if (fsdh->fs_had_range)
	{
		ssd.id = 0;
		rc = apol_bst_inorder_map(fsdh->range_tree, (int (*)(const void *, void *))INSERT_RANGE, &ssd);
		if (rc != SQLITE_OK)
			goto bad;
	}

	ssd.id = 0;
	rc = apol_bst_inorder_map(fsdh->file_tree, (int (*)(const void *, void *))INSERT_FILE, &ssd);
	if (rc != SQLITE_OK)
		goto bad;

	sprintf(stmt, "END TRANSACTION");
	rc = sqlite3_exec(sqldb, stmt, NULL, 0, &errmsg);
	if (rc != SQLITE_OK)
		goto bad;
	gethostname(hostname, 50);
	time(&mytime);
	sprintf(stmt, "insert into info (key,value) values ('dbversion', 2);"
		"insert into info (key,value) values ('hostname','%s');"
		"insert into info (key,value) values ('datetime','%s');", hostname, ctime(&mytime));
	rc = sqlite3_exec(sqldb, stmt, NULL, 0, &errmsg);
	if (rc != SQLITE_OK)
		goto bad;

	return 0;

      bad:
	fprintf(stderr, "SQL error\n\tStmt was :%s\nError was:\t%s\n", stmt, errmsg);
	sqlite3_free(errmsg);
	return -1;
}

#endif
