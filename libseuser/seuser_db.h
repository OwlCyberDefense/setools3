 /* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* seuser_db.h
 *
 * The user database functions for seuser.
 *
 */
#ifndef _SEUSER_DB_H_
#define _SEUSER_DB_H_

#include "../libapol/policy.h"

/* The following should be defined in the make environment */
#ifndef SEUSER_VERSION_STRING
	#define SEUSER_VERSION_STRING "UNKNOWN"
#endif
/* NOTE: As of version 1.0, we completely remove all support for the older
 * default_context and cron_context; which greatly simplified the code.
 * Also structure lib so that it no longer requires the TCL interface
 * to be used.
 */

#define CONFIG_FILE	"seuser.conf"

/* user database structure; based in part on APOL's structures */
typedef struct user_db {
	int		num_users;
	user_list_t	users;
	/* stash the conf file info here */
	bool_t		conf_init;	/* indicate whether config data is initialized */
	char		*config_dir;
	char 		*policy_conf;
	char 		*user_file;
	char 		*policy_dir;
} user_db_t;

/* macros */
#define seuser_is_conf_loaded(db) (db == NULL ? FALSE : (db)->conf_init)

/* prototypes */
int seuser_open_user_db(user_db_t *db, policy_t **policy);
int seuser_get_user_by_name(const char *name, user_item_t **user, user_db_t *db);
int seuser_get_user_context(const char *user, int which, char **role, char **type, user_db_t *db, policy_t *policy);
int seuser_write_user_file(user_db_t *db, policy_t *policy);
int seuser_write_default_context(int which, user_db_t *db, policy_t *policy, FILE *fp);
int seuser_update_user(user_item_t *user, bool_t newuser, user_db_t *db, policy_t *policy);
int seuser_remove_user(const char *name, user_db_t *db);
int seuser_is_proper_user_record(user_item_t *user, user_db_t *db, policy_t *policy);
int seuser_free_db(user_db_t *db, bool_t free_conf);
int seuser_init_db(user_db_t *db, bool_t init_conf);
int seuser_rename_user(const char *oldname, const char *newname, user_db_t *db);
bool_t seuser_does_user_exist(const char *name, user_db_t *db);
int seuser_read_conf_info(user_db_t *db);
int seuser_remake_policy_conf(const char *tmpfile, user_db_t *db);
int seuser_reinstall_policy(const char *tmpfile, user_db_t *db);
int seuser_check_commit_perm(user_db_t *db);
const char* seuser_decode_read_conf_err(int err);
int seuser_add_change_user(bool_t new_user, const char *user, char ** roles, int num_roles, user_db_t *db, policy_t *policy);

#endif /*_SEUSER_DB_H_ */



