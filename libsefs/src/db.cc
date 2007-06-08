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
#include <sefs/entry.hh>

#include "sqlite/sqlite3.h"

#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DB_SCHEMA_NONMLS "CREATE TABLE types ( \
			      type_id INTEGER PRIMARY KEY, \
			      type_name varchar (48) \
			  );  \
			  CREATE TABLE users ( \
			      user_id INTEGER PRIMARY KEY, \
			      user_name varchar (24) \
			  ); \
			  CREATE TABLE roles ( \
			      role_id INTEGER PRIMARY KEY, \
			      role_name varchar (24) \
			  ); \
			  CREATE TABLE paths ( \
			      inode int, \
			      path varchar (128) PRIMARY KEY\
			  ); \
			  CREATE TABLE inodes ( \
			      inode_id INTEGER PRIMARY KEY, \
			      dev int, \
			      ino int(64), \
			      user int, \
			      role int, \
			      type int, \
			      range int, \
			      obj_class int, \
			      symlink_target varchar (128) \
			  ); \
			  CREATE TABLE info ( \
			      key varchar, \
			      value varchar \
			  ); \
			  CREATE INDEX inodes_index ON inodes (ino,dev); \
			  CREATE INDEX paths_index ON paths (inode); \
			  "

#define DB_SCHEMA_MLS DB_SCHEMA_NONMLS \
		      "CREATE TABLE mls ( \
			   mls_id INTEGER PRIMARY KEY, \
			   mls_range varchar (64) \
		       );"

/******************** public functions below ********************/

sefs_db::sefs_db(sefs_filesystem * fs, sefs_callback_fn_t msg_callback, void *varg) throw(std::invalid_argument,
											  std::
											  runtime_error):sefs_fclist
	(SEFS_FCLIST_TYPE_DB, msg_callback, varg)
{
	if (fs == NULL)
	{
		errno = EINVAL;
		SEFS_ERR("%s", strerror(EINVAL));
		throw std::invalid_argument(strerror(EINVAL));
	}

	// FIX ME:
	// create a memory DB
	// foreach entries in fs
	//   insert into DB
	// record time and determine MLS
	_ctime = time(NULL);
}

static int db_count_callback(void *arg, int argc __attribute__ ((unused)), char **argv, char **column_names
			     __attribute__ ((unused)))
{
	int *count = static_cast < int *>(arg);
	*count = atoi(argv[0]);
	return 0;
}

sefs_db::sefs_db(const char *filename, sefs_callback_fn_t msg_callback, void *varg)throw(std::invalid_argument, std::runtime_error):sefs_fclist(SEFS_FCLIST_TYPE_DB, msg_callback,
	    varg)
{
	if (filename == NULL)
	{
		errno = EINVAL;
		SEFS_ERR("%s", strerror(EINVAL));
		throw std::invalid_argument(strerror(EINVAL));
	}

	_db = NULL;
	int rc = access(filename, R_OK);
	if (rc != 0)
	{
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}
	rc = sqlite3_open(filename, &_db);
	if (rc)
	{
		SEFS_ERR("%s", sqlite3_errmsg(_db));
		sqlite3_close(_db);
		throw std::runtime_error(strerror(errno));
	}
	char *errmsg = NULL;
	/* A limitation of sqlite is that is does not check whether
	 * the file is a valid sqlite database.  Run a simple query to
	 * check that the database is legal. */
	int list_size;
	rc = sqlite3_exec(_db, "SELECT type_name from types", db_count_callback, &list_size, &errmsg);
	if (rc == SQLITE_NOTADB)
	{
		SEFS_ERR("%s", errmsg);
		sqlite3_close(_db);
		sqlite3_free(errmsg);
		errno = EIO;
		throw std::runtime_error(strerror(EIO));
	}
	// FIX ME: get ctime from db
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
	return -1;
}

static int db_mls_callback(void *arg,
			   int argc __attribute__ ((unused)),
			   char **argv __attribute__ ((unused)), char **col_names __attribute__ ((unused)))
{
	// if this callback is invoked, then there exists a table named
	// "mls"
	bool *answer = static_cast < bool * >(arg);
	*answer = true;
	return 0;
}

bool sefs_db::isMLS() const
{
	int rc;
	bool answer = false;
	char *errmsg = NULL;
	const char *select_stmt = "select * from sqlite_master where name='mls'";
	rc = sqlite3_exec(_db, select_stmt, db_mls_callback, &answer, &errmsg);
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
	struct sqlite3 *diskdb = NULL;
	char *errmsg = NULL;
	try
	{
		if (filename == NULL)
		{
			errno = EINVAL;
			throw std::invalid_argument(strerror(errno));
		}
		if ((fp = fopen(filename, "w")) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		fclose(fp);
		fp = NULL;

		int rc = sqlite3_open(filename, &diskdb);
		if (rc)
		{
			SEFS_ERR("%s", sqlite3_errmsg(diskdb));
			throw std::runtime_error(sqlite3_errmsg(diskdb));
		}

		// apply schema to it, based upon if it should have MLS or not
		// a MLS range associated with them
		if (isMLS())
		{
			rc = sqlite3_exec(diskdb, DB_SCHEMA_MLS, NULL, 0, &errmsg);
		}
		else
		{
			rc = sqlite3_exec(diskdb, DB_SCHEMA_NONMLS, NULL, 0, &errmsg);
		}
		if (rc != SQLITE_OK)
		{
			SEFS_ERR("%s", errmsg);
			throw std::runtime_error(errmsg);
		}

		// copy contents from in-memory db to the one on disk
		rc = sqlite3_exec(diskdb, "BEGIN TRANSACTION", NULL, 0, &errmsg);
		if (rc != SQLITE_OK)
		{
			SEFS_ERR("%s", errmsg);
			throw std::runtime_error(errmsg);
		}

		rc = sqlite3_exec(diskdb, "END TRANSACTION", NULL, 0, &errmsg);
		if (rc != SQLITE_OK)
		{
			SEFS_ERR("%s", errmsg);
			throw std::runtime_error(errmsg);
		}
	}
	catch(...)
	{
		if (fp != NULL)
		{
			fclose(fp);
		}
		if (diskdb != NULL)
		{
			sqlite3_close(diskdb);
		}
		sqlite3_free(errmsg);
		throw;
	}
	sqlite3_close(diskdb);
	sqlite3_free(errmsg);
}

time_t sefs_db::getCTime() const
{
	return _ctime;
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

#if 0

#define STMTSTART_MLS "SELECT types.type_name,users.user_name,paths.path,inodes.obj_class,mls.mls_range from inodes,types,users,paths,mls"
#define STMTSTART_NONMLS "SELECT types.type_name,users.user_name,paths.path,inodes.obj_class from inodes,types,users,paths"
#define STMTEND_MLS "inodes.user = users.user_id AND paths.inode = inodes.inode_id AND types.type_id = inodes.type AND mls.mls_id = inodes.range"
#define STMTEND_NONMLS "inodes.user = users.user_id AND paths.inode = inodes.inode_id AND types.type_id = inodes.type"
#define SORTSTMT "ORDER BY paths.path ASC"

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
 * Append a string to the sql statement being constructed.  If out of
 * memory during reallocation then print an error to stderr.
 *
 * @param stmt Reference to the statement string.
 * @param stmt_size Reference to the number of bytes already allocated
 * to stmt.
 * @param fmt Format of new characters, as per printf(3).
 *
 * @return 0 on success, < 0 on error.
 */
static int sefs_append(char **stmt, size_t * stmt_size, char *fmt, ...)
{
	int retval;
	va_list ap;
	char *tmp;

	/* first calculate how much bigger to make stmt */
	va_start(ap, fmt);
	retval = vsnprintf("", 0, fmt, ap);
	va_end(ap);
	if (retval < 0)
	{
		fprintf(stderr, "Illegal format string.");
		return -1;
	}

	/* resize statement */
	if ((tmp = realloc(*stmt, *stmt_size + retval + 1)) == NULL)
	{
		fprintf(stderr, "Out of memory.");
		return -1;
	}
	*stmt = tmp;
	va_start(ap, fmt);
	vsnprintf(*stmt + *stmt_size, retval + 1, fmt, ap);
	*stmt_size += retval;
	va_end(ap);
	return 0;
}

#define APPEND(...) do { if (sefs_append(stmt, &stmt_size, __VA_ARGS__)) return -1; } while (0)

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

static int sefs_search_types_callback(void *data, int argc, char **argv, char **azColName)
{
	struct search_types_arg *arg = (struct search_types_arg *)data;
	/* lets create memory and copy over */
	if ((arg->list[arg->count] = strdup(argv[0])) == NULL)
	{
		fprintf(stderr, "Out of memory\n");
		return 1;
	}
	arg->count += 1;
	return 0;
}

static int sefs_search_callback(void *arg, int argc, char **argv, char **azColName)
{
	int i, *db_is_mls = (int *)arg;
	sefs_search_ret_t *search_ret = NULL;
	const char *class_string;
	char *type = argv[0];
	char *user = argv[1];
	char *path = argv[2];
	char *class = argv[3];
	char *range = (*db_is_mls ? argv[4] : NULL);

	/* first lets generate a ret struct */
	if ((search_ret = (sefs_search_ret_t *) calloc(1, sizeof(sefs_search_ret_t))) == 0)
	{
		fprintf(stderr, "Out of memory\n");
		return 1;
	}

	/* next lets add in the context */
	if (*db_is_mls)
	{
		i = snprintf("", 0, "%s:object_r:%s:%s", user, type, range);
	}
	else
	{
		i = snprintf("", 0, "%s:object_r:%s", user, type);
	}
	if ((search_ret->context = malloc(i + 1)) == 0)
	{
		fprintf(stderr, "Out of memory\n");
		return 1;
	}
	if (*db_is_mls)
	{
		snprintf(search_ret->context, (size_t) i + 1, "%s:object_r:%s:%s", user, type, range);
	}
	else
	{
		snprintf(search_ret->context, (size_t) i + 1, "%s:object_r:%s", user, type);
	}

	/* next we add in the path */
	if ((search_ret->path = strdup(path)) == 0)
	{
		fprintf(stderr, "Out of memory\n");
		return 1;
	}

	/* finally its object class */
	class_string = sefs_get_class_string(atoi(class));
	if ((search_ret->object_class = strdup(class_string)) == 0)
	{
		fprintf(stderr, "Out of memory\n");
		return 1;
	}

	/* now insert it into the list */
	/* to try to speed this up we keep a global pointer that */
	/* points to the last element in the list */
	if (!sefs_search_keys->search_ret)
	{
		sefs_search_keys->search_ret = search_ret;
		sefs_search_ret = search_ret;
	}
	else
	{
		sefs_search_ret->next = search_ret;
		sefs_search_ret = search_ret;
	}

	return 0;
}

/* compare a type_name value with a precompiled regular expression */
static void sefs_types_compare(sqlite3_context * context, int argc, sqlite3_value ** argv)
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
		if (regexec(&types_re, text, 1, &pm, 0) == 0)
			retVal = 1;
	}
	sqlite3_result_int(context, retVal);
}

/* compare a user_name value with a precompiled regular expression */
static void sefs_users_compare(sqlite3_context * context, int argc, sqlite3_value ** argv)
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
		/* if we aren't using regular expressions just match them up */
		if (regexec(&users_re, text, 1, &pm, 0) == 0)
		{
			retVal = 1;
		}
	}
	sqlite3_result_int(context, retVal);
}

/* compare a path value with a precompiled regular expression */
static void sefs_paths_compare(sqlite3_context * context, int argc, sqlite3_value ** argv)
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
		if (regexec(&paths_re, text, 1, &pm, 0) == 0)
			retVal = 1;
	}
	sqlite3_result_int(context, retVal);
}

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

static int sefs_filesystem_data_init(sefs_filesystem_data_t * fsd)
{
	if (fsd == NULL)
	{
		fprintf(stderr, "Invalid structure\n");
		return -1;
	}

	fsdata = fsd;
	fsd->num_files = 0;
	fsd->num_types = 0;
	fsd->num_users = 0;
	fsd->fs_had_range = 0;

	/* sefs_init_*tree return -ENOMEM on failure and 0 for success
	 *   at the moment there is no other way for that family of
	 *   functions to fail, so bail with the same error code in case
	 *   anyone else cares.
	 */
	if (sefs_init_pathtree(fsd) != 0)
	{
		fprintf(stderr, "fsdata_init_paths() failed\n");
		return -ENOMEM;
	}

	if (sefs_init_typetree(fsd) != 0)
	{
		fprintf(stderr, "fsdata_init_types() failed\n");
		return -ENOMEM;
	}

	if (sefs_init_usertree(fsd) != 0)
	{
		fprintf(stderr, "fsdata_init_users() failed\n");
		return -ENOMEM;
	}

	if (sefs_init_rangetree(fsd) != 0)
	{
		fprintf(stderr, "fsdata_init_rangetree() failed\n");
		return -ENOMEM;
	}

	return 0;
}

char **sefs_filesystem_db_get_known(sefs_filesystem_db_t * fsd, int request_type, int *count_in)
{
	char *count_stmt = NULL, *select_stmt = NULL;
	int rc = 0, list_size = 0;
	char *errmsg = NULL;
	struct search_types_arg arg;

	db = (sqlite3 *) (*fsd->dbh);

	if (request_type == SEFS_TYPES)
	{
		count_stmt = "SELECT count(*) from types";
		select_stmt = "SELECT type_name from types order by type_name";
	}
	else if (request_type == SEFS_USERS)
	{
		count_stmt = "SELECT count(*) from users";
		select_stmt = "SELECT user_name from users order by user_name";
	}
	else if (request_type == SEFS_PATHS)
	{
		count_stmt = "SELECT count(*) from paths";
		select_stmt = "SELECT path from paths order by path";
	}
	else if (request_type == SEFS_RANGES)
	{
		count_stmt = "SELECT count(*) from mls";
		select_stmt = "SELECT mls_range from mls";
	}

	if (request_type != SEFS_OBJECTCLASS)
	{
		/* first get the number  */
		sqlite3_exec(db, count_stmt, sefs_count_callback, &list_size, &errmsg);
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "SQL error: %s\n", errmsg);
			sqlite3_free(errmsg);
			return NULL;
		}
		if (list_size == 0)
		{
			/* nothing to report -- but can't return NULL
			 * because that would indicate an error
			 * condition */
			*count_in = 0;
			return malloc(sizeof(char *));
		}
		/* malloc out the memory for the types */
		if ((arg.list = (char **)calloc(list_size, sizeof(char *))) == NULL)
		{
			fprintf(stderr, "out of memory\n");
			return NULL;
		}
		arg.count = 0;
		rc = sqlite3_exec(db, select_stmt, sefs_search_types_callback, &arg, &errmsg);
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "SQL error: %s\n", errmsg);
			sqlite3_free(errmsg);
			return NULL;
		}
		*count_in = list_size;
	}
	else
	{
		if ((arg.list = (char **)sefs_get_valid_object_classes(&list_size)) == NULL)
		{
			fprintf(stderr, "No object classes defined!\n");
			return NULL;
		}
		*count_in = list_size;
	}

	return arg.list;
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
	sprintf(stmt, "insert into info (key,value) values ('dbversion',1);"
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
