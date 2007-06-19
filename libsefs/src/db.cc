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
#include <sys/stat.h>
#include <sys/types.h>

#define DB_MAX_VERSION "2"

#define DB_SCHEMA_NONMLS \
	"CREATE TABLE users (user_id INTEGER PRIMARY KEY, user_name varchar (24));" \
	"CREATE TABLE roles (role_id INTEGER PRIMARY KEY, role_name varchar (24));" \
	"CREATE TABLE types (type_id INTEGER PRIMARY KEY, type_name varchar (48));" \
	"CREATE TABLE devs (dev_id INTEGER PRIMARY KEY, dev_name varchar (32));" \
	"CREATE TABLE paths (path varchar (128) PRIMARY KEY, ino int(64), dev int, user int, role int, type int, range int, obj_class int, symlink_target varchar (128));" \
	"CREATE TABLE info (key varchar, value varchar);"

#define DB_SCHEMA_MLS DB_SCHEMA_NONMLS \
	"CREATE TABLE mls (mls_id INTEGER PRIMARY KEY, mls_range varchar (64));"

// wrapper functions to go between non-OO land into OO member functions

inline struct sefs_context_node *db_get_context(sefs_db * db, const char *user, const char *role, const char *type,
						const char *range) throw(std::bad_alloc)
{
	return db->getContext(user, role, type, range);
}

inline sefs_entry *db_get_entry(sefs_db * db, const struct sefs_context_node * node, uint32_t objClass,
				const char *path, ino64_t inode, const char *dev)throw(std::bad_alloc)
{
	return db->getEntry(node, objClass, path, inode, dev);
}

inline void db_err(sefs_db * db, const char *fmt, const char *arg)
{
	db->SEFS_ERR(fmt, arg);
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
	char *user, *role, *type, *range, *path, *dev;
	bool regex, db_is_mls;
	regex_t *reuser, *rerole, *retype, *rerange, *repath, *redev;
	int rangeMatch;
	sefs_fclist_map_fn_t fn;
	void *data;
	apol_vector_t *type_list;
	apol_mls_range_t *apol_range;
	apol_policy_t *policy;
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
	bool retval;
	if (q->type_list == NULL)
	{
		retval = query_str_compare(text, q->type, q->retype, q->regex);
	}
	else
	{
		assert(q->policy != NULL);
		size_t index;
		retval = (apol_vector_get_index(q->type_list, text, apol_str_strcmp, NULL, &index) >= 0);
	}
	sqlite3_result_int(context, (retval ? 1 : 0));
}

/**
 * Callback invoked when selecting a range (for a sefs_query).
 */
static void db_range_compare(sqlite3_context * context, int argc __attribute__ ((unused)), sqlite3_value ** argv)
{
	void *arg = sqlite3_user_data(context);
	struct db_query_arg *q = static_cast < struct db_query_arg *>(arg);
	assert(sqlite3_value_type(argv[0]) == SQLITE_TEXT);
	const char *text = reinterpret_cast < const char *>(sqlite3_value_text(argv[0]));
	bool retval;
	if (q->apol_range == NULL)
	{
		retval = query_str_compare(text, q->range, q->rerange, q->regex);
	}
	else
	{
		assert(q->policy != NULL);
		apol_mls_range_t *db_range = apol_mls_range_create_from_string(q->policy, text);
		int ret;
		ret = apol_mls_range_compare(q->policy, q->apol_range, db_range, q->rangeMatch);
		apol_mls_range_destroy(&db_range);
		retval = (ret > 0);
	}
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
 * Callback invoked when selecting a device name (for a sefs_query).
 */
static void db_dev_compare(sqlite3_context * context, int argc __attribute__ ((unused)), sqlite3_value ** argv)
{
	void *arg = sqlite3_user_data(context);
	struct db_query_arg *q = static_cast < struct db_query_arg *>(arg);
	assert(sqlite3_value_type(argv[0]) == SQLITE_TEXT);
	const char *text = reinterpret_cast < const char *>(sqlite3_value_text(argv[0]));
	bool retval = query_str_compare(text, q->dev, q->redev, q->regex);
	sqlite3_result_int(context, (retval ? 1 : 0));
}

/**
 * Callback invoked when selecting rows during a query.
 */
static int db_query_callback(void *arg, int argc, char *argv[], char *column_names[] __attribute__ ((unused)))
{
	struct db_query_arg *q = static_cast < struct db_query_arg *>(arg);
	assert(argc == (q->db_is_mls ? 9 : 8));
	char *path = argv[0];
	ino64_t ino = static_cast < ino64_t > (strtoul(argv[1], NULL, 10));
	char *dev = argv[2];
	char *user = argv[3];
	char *role = argv[4];
	char *type = argv[5];
	char *range, *objclass_str, *link_target;

	if (q->db_is_mls)
	{
		range = argv[6];
		objclass_str = argv[7];
		link_target = argv[8];
	}
	else
	{
		range = NULL;
		objclass_str = argv[6];
		link_target = argv[7];
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

/******************** convert from a filesystem to a db ********************/

struct strindex
{
	const char *str;
	int id;
};

static int db_strindex_comp(const void *a, const void *b, void *arg __attribute__ ((unused)))
{
	const struct strindex *n1 = static_cast < const struct strindex *>(a);
	const struct strindex *n2 = static_cast < const struct strindex *>(b);
	return strcmp(n1->str, n2->str);
}

class db_convert
{
      public:
	db_convert(sefs_db * db, struct sqlite3 * &target_db)throw(std::runtime_error)
	{
		_db = db;
		_target_db = target_db;
		_user = _role = _type = _range = _dev = NULL;
		_user_id = _role_id = _type_id = _range_id = _dev_id = 0;
		_errmsg = NULL;
		try
		{
			if ((_user = apol_bst_create(db_strindex_comp, free)) == NULL)
			{
				db_err(_db, "%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if ((_role = apol_bst_create(db_strindex_comp, free)) == NULL)
			{
				db_err(_db, "%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if ((_type = apol_bst_create(db_strindex_comp, free)) == NULL)
			{
				db_err(_db, "%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if ((_range = apol_bst_create(db_strindex_comp, free)) == NULL)
			{
				db_err(_db, "%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if ((_dev = apol_bst_create(db_strindex_comp, free)) == NULL)
			{
				db_err(_db, "%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
		}
		catch(...)
		{
			apol_bst_destroy(&_user);
			apol_bst_destroy(&_role);
			apol_bst_destroy(&_type);
			apol_bst_destroy(&_range);
			apol_bst_destroy(&_dev);
			throw;
		}
	}
	~db_convert()
	{
		apol_bst_destroy(&_user);
		apol_bst_destroy(&_role);
		apol_bst_destroy(&_type);
		apol_bst_destroy(&_range);
		apol_bst_destroy(&_dev);
		sqlite3_free(_errmsg);
	}
	int getID(const char *sym, apol_bst_t * tree, int &id, const char *table) throw(std::bad_alloc)
	{
		struct strindex st = { sym, -1 }, *result;
		if (apol_bst_get_element(tree, &st, NULL, (void **)&result) == 0)
		{
			return result->id;
		}
		if ((result = static_cast < struct strindex * >(malloc(sizeof(*result)))) == NULL)
		{
			db_err(_db, "%s", strerror(errno));
			throw std::bad_alloc();
		}
		result->str = sym;
		result->id = id++;
		if (apol_bst_insert(tree, result, NULL) < 0)
		{
			db_err(_db, "%s", strerror(errno));
			free(result);
			throw std::bad_alloc();
		}
		char *insert_stmt = NULL;
		if (asprintf(&insert_stmt, "INSERT INTO %s VALUES (%d, '%s')", table, result->id, result->str) < 0)
		{
			db_err(_db, "%s", strerror(errno));
			throw std::bad_alloc();
		}
		if (sqlite3_exec(_target_db, insert_stmt, NULL, NULL, &_errmsg) != SQLITE_OK)
		{
			db_err(_db, "%s", _errmsg);
			free(insert_stmt);
			throw std::runtime_error(_errmsg);
		}
		free(insert_stmt);
		return result->id;
	}
	apol_bst_t *_user, *_role, *_type, *_range, *_dev;
	int _user_id, _role_id, _type_id, _range_id, _dev_id;
	bool _isMLS;
	char *_errmsg;
	sefs_db *_db;
	struct sqlite3 *_target_db;
};

int db_create_from_filesystem(sefs_fclist * fclist __attribute__ ((unused)), const sefs_entry * entry, void *arg)
{
	db_convert *dbc = static_cast < db_convert * >(arg);

	const struct sefs_context_node *context = dbc->_db->getContextNode(entry);
	try
	{

		// add the user, role, type, range, and dev into the
		// target_db if needed
		int user_id = dbc->getID(context->user, dbc->_user, dbc->_user_id, "users");
		int role_id = dbc->getID(context->role, dbc->_role, dbc->_role_id, "roles");
		int type_id = dbc->getID(context->type, dbc->_type, dbc->_type_id, "types");
		int range_id = 0;
		if (dbc->_isMLS)
		{
			range_id = dbc->getID(context->range, dbc->_range, dbc->_range_id, "mls");
		}
		int dev_id = dbc->getID(entry->dev(), dbc->_dev, dbc->_dev_id, "devs");
		const char *path = entry->path();
		const ino64_t inode = entry->inode();
		const uint32_t objclass = entry->objectClass();
		char link_target[128] = "";
		// determine the link target as necessary
		struct stat64 sb;
		if (stat64(path, &sb) == -1)
		{
			db_err(dbc->_db, "%s", strerror(errno));
			throw std::bad_alloc();
		}
		if (S_ISLNK(sb.st_mode))
		{
			if (readlink(path, link_target, 128) == 0)
			{
				db_err(dbc->_db, "%s", strerror(errno));
				throw std::bad_alloc();
			}
			link_target[127] = '\0';
		}

		char *insert_stmt = NULL;
		if (asprintf
		    (&insert_stmt, "INSERT INTO paths VALUES ('%s', %lu, %d, %d, %d, %d, %d, %u, '%s')", path,
		     static_cast < long unsigned int >(inode), dev_id, user_id, role_id, type_id, range_id, objclass,
		     link_target) < 0)
		{
			db_err(dbc->_db, "%s", strerror(errno));
			throw std::bad_alloc();
		}
		if (sqlite3_exec(dbc->_target_db, insert_stmt, NULL, NULL, &dbc->_errmsg) != SQLITE_OK)
		{
			db_err(dbc->_db, "%s", dbc->_errmsg);
			free(insert_stmt);
			throw std::runtime_error(dbc->_errmsg);
		}
		free(insert_stmt);
	}
	catch(...)
	{
		return -1;
	}
	return 0;
}

/******************** public functions below ********************/

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

		db_convert dbc(this, _db);
		dbc._isMLS = fs->isMLS();
		if (fs->runQueryMap(NULL, db_create_from_filesystem, &dbc) < 0)
		{
			throw std::runtime_error(strerror(errno));
		}

		// store metadata about the database
		const char *dbversion = DB_MAX_VERSION;
		char hostname[64];
		gethostname(hostname, sizeof(hostname));
		hostname[63] = '\0';
		_ctime = time(NULL);
		char datetime[32];
		ctime_r(&_ctime, datetime);

		char *info_insert = NULL;
		if (asprintf(&info_insert,
			     "INSERT INTO info (key,value) VALUES ('dbversion','%s');"
			     "INSERT INTO info (key,value) VALUES ('hostname','%s');"
			     "INSERT INTO info (key,value) VALUES ('datetime','%s');", dbversion, hostname, datetime) < 0)
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

	const char *select_stmt = "SELECT * FROM info WHERE key = 'dbversion' AND value >= " DB_MAX_VERSION;
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
		if (policy != NULL)
		{
			if (query->_type != NULL)
			{
				q.type_list =
					query_create_candidate_type(policy, query->_type, query->_retype, query->_regex,
								    query->_indirect);
				if (q.type_list == NULL)
				{
					SEFS_ERR("%s", strerror(errno));
					throw std::runtime_error(strerror(errno));
				}
			}
			if (query->_range != NULL)
			{
				q.apol_range = apol_mls_range_create_from_string(policy, query->_range);
				if (q.apol_range == NULL)
				{
					apol_vector_destroy(&q.type_list);
					SEFS_ERR("%s", strerror(errno));
					throw std::runtime_error(strerror(errno));
				}
			}
		}
		q.user = query->_user;
		q.role = query->_role;
		q.type = query->_type;
		q.range = query->_range;
		q.path = query->_path;
		q.dev = query->_dev;
		q.regex = query->_regex;
		q.reuser = query->_reuser;
		q.rerole = query->_rerole;
		q.retype = query->_retype;
		q.rerange = query->_rerange;
		q.repath = query->_repath;
		q.redev = query->_redev;
		q.rangeMatch = query->_rangeMatch;
		q.policy = this->policy;
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

		if (apol_str_append
		    (&select_stmt, &len,
		     "SELECT paths.path, paths.ino, devs.dev_name, users.user_name, roles.role_name, types.type_name") < 0)
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
				    ", paths.obj_class, paths.symlink_target FROM paths, devs, users, roles, types") < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (q.db_is_mls && apol_str_append(&select_stmt, &len, ", mls") < 0)
		{
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
			if (sqlite3_create_function(_db, "range_compare", 1, SQLITE_UTF8, &q, db_range_compare, NULL, NULL) !=
			    SQLITE_OK)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (range_compare(mls.mls_range_name))", (where_added ? " AND" : " WHERE")) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (query->_objclass != 0)
		{
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (paths.obj_class = %d)", (where_added ? " AND" : " WHERE"), query->_objclass) < 0)
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
					     "%s (paths.ino = %lu)", (where_added ? " AND" : " WHERE"),
					     static_cast < long unsigned int >(query->_inode)) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (query->_dev != 0)
		{
			if (sqlite3_create_function(_db, "dev_compare", 1, SQLITE_UTF8, &q, db_dev_compare, NULL, NULL) !=
			    SQLITE_OK)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			if (apol_str_appendf(&select_stmt, &len,
					     "%s (dev_compare(devs.dev_name)", (where_added ? " AND" : " WHERE")) < 0)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::runtime_error(strerror(errno));
			}
			where_added = true;
		}

		if (apol_str_appendf(&select_stmt, &len,
				     "%s (paths.user = users.user_id AND paths.role = roles.role_id AND paths.type = types.type_id",
				     (where_added ? " AND" : " WHERE")) < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (q.db_is_mls && apol_str_appendf(&select_stmt, &len, " AND paths.range = mls.mls_id") < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (apol_str_append(&select_stmt, &len, " AND paths.dev = devs.dev_id) ORDER BY paths.path ASC") < 0)
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
		apol_vector_destroy(&q.type_list);
		apol_mls_range_destroy(&q.apol_range);
		free(select_stmt);
		sqlite3_free(errmsg);
		throw;
	}

	apol_vector_destroy(&q.type_list);
	apol_mls_range_destroy(&q.apol_range);
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

		char *attach = NULL;
		if (asprintf(&attach, "ATTACH '%s' AS diskdb", filename) < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		diskdb.db = _db;
		diskdb.source_db = "";
		diskdb.target_db = "diskdb.";
		int rc = sqlite3_exec(_db, attach, NULL, NULL, &diskdb.errmsg);
		free(attach);
		if (rc != SQLITE_OK)
		{
			SEFS_ERR("%s", diskdb.errmsg);
			throw std::runtime_error(diskdb.errmsg);
		}

		// copy contents from in-memory db to the one on disk
		if (sqlite3_exec(_db, "BEGIN TRANSACTION", NULL, NULL, &(diskdb.errmsg)) != SQLITE_OK)
		{
			SEFS_ERR("%s", diskdb.errmsg);
			throw std::runtime_error(diskdb.errmsg);
		}
		in_transaction = true;
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

const struct sefs_context_node *sefs_db::getContextNode(const sefs_entry * entry)
{
	return entry->_context;
}

/**
 * Callback invoked while upgrading a libsefs database version 1 to
 * version 2.  Merge the inodes and paths table into one, remap the
 * object class value, and explicitly set the role and dev fields to
 * zero.
 */
static int db_upgrade_reinsert(void *arg, int argc, char *argv[], char *column_names[])
{
	struct sqlite3 *db = static_cast < struct sqlite3 *>(arg);
	bool mls = (argc == 7);
	assert(argc >= 6 && argc <= 7);
	uint32_t obj_class = static_cast < uint32_t > (atoi(argv[(mls ? 5 : 4)]));

	switch (obj_class)
	{
	case 16:
		obj_class = QPOL_CLASS_BLK_FILE;
		break;
	case 8:
		obj_class = QPOL_CLASS_CHR_FILE;
		break;
	case 2:
		obj_class = QPOL_CLASS_DIR;
		break;
	case 64:
		obj_class = QPOL_CLASS_FIFO_FILE;
		break;
	case 1:
		obj_class = QPOL_CLASS_FILE;
		break;
	case 4:
		obj_class = QPOL_CLASS_LNK_FILE;
		break;
	case 32:
		obj_class = QPOL_CLASS_SOCK_FILE;
		break;
	}

	char *insert_stmt = NULL;
	if (mls)
	{
		if (asprintf(&insert_stmt,
			     "INSERT INTO new_paths (path, ino, dev, user, role, type, range, obj_class, symlink_target) VALUES ('%s', %s, 0, %s, 0, %s, %s, %u, '%s')",
			     argv[0], argv[1], argv[2], argv[3], argv[4], obj_class, argv[6]) < 0)
		{
			return -1;
		}
	}
	else
	{
		if (asprintf(&insert_stmt,
			     "INSERT INTO new_paths (path, ino, dev, user, role, type, range, obj_class, symlink_target) VALUES ('%s', %s, 0, %s, 0, %s, 0, %u, '%s')",
			     argv[0], argv[1], argv[2], argv[3], obj_class, argv[5]) < 0)
		{
			return -1;
		}
	}
	if (sqlite3_exec(db, insert_stmt, NULL, NULL, NULL) != SQLITE_OK)
	{
		free(insert_stmt);
		return -1;
	}
	free(insert_stmt);
	return 0;
}

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
	if (asprintf(&alter_stmt, "BEGIN TRANSACTION;" "CREATE TABLE roles (role_id INTEGER PRIMARY KEY, role_name varchar (24));"	// add a roles table
		     "INSERT INTO roles (role_id, role_name) VALUES (0, 'object_r');"	// assume that all previous contexts had as their role 'object_r'
		     "CREATE TABLE devs (dev_id INTEGER PRIMARY KEY, dev_name varchar (32));"	// add a table that maps between device names and some numeric ID
		     "INSERT INTO devs (dev_id, dev_name) VALUES (0, '<<unknown>>');"	// device names were not stored in old DB
		     "CREATE TABLE new_paths (path varchar (128) PRIMARY KEY, ino int(64), dev int, user int, role int, type int, range int, obj_class int, symlink_target varchar (128));"	// create new paths table
		     "SELECT paths.path, inodes.ino, inodes.user, inodes.type, %sinodes.obj_class, inodes.symlink_target FROM paths, inodes WHERE (inodes.inode_id = paths.inode)",	// rebuild new paths table from older tables
		     isMLS()? "inodes.range, " : "") < 0)
	{
		SEFS_ERR("%s", errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(_db);
		throw std::runtime_error(strerror(errno));
	}
	if (sqlite3_exec(_db, alter_stmt, db_upgrade_reinsert, _db, &errmsg) != SQLITE_OK)
	{
		SEFS_ERR("%s", errmsg);
		free(alter_stmt);
		sqlite3_free(errmsg);
		sqlite3_close(_db);
		throw std::runtime_error(strerror(errno));
	}

	free(alter_stmt);
	alter_stmt = NULL;

	if (asprintf(&alter_stmt, "DROP TABLE inodes; DROP TABLE paths;"	// drop the old tables
		     "ALTER TABLE new_paths RENAME TO paths;"	// move ver 2 paths table as main table
		     "UPDATE info SET value = '%s' WHERE key = 'datetime';"
		     "UPDATE info SET value = '%s' WHERE key = 'dbversion';"
		     "END TRANSACTION;" "VACUUM", datetime, DB_MAX_VERSION) < 0)
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
			      const char *dev) throw(std::bad_alloc)
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

	s = NULL;
	if ((s = strdup(dev)) == NULL || apol_bst_insert_and_get(dev_tree, (void **)&s, NULL) < 0)
	{
		SEFS_ERR("%s", strerror(errno));
		free(s);
		throw std::bad_alloc();
	}
	e->_dev = dev;
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
