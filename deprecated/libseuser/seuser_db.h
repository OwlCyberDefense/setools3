 /* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 * Modified: don.patterson@tresys.com
 *
 */

/* seuser_db.h
 *
 * The user database functions for seuser.
 * 
 * NOTE: As of version 1.0, we completely remove all support for the older
 * default_context and cron_context; which greatly simplified the code.
 * Also structure lib so that it no longer requires the TCL interface
 * to be used.
 *
 *
 */
#ifndef _SEUSER_DB_H_
#define _SEUSER_DB_H_

#include "policy.h"


/* user statements; linked list */
typedef struct user_item {
	char			*name;
	ta_item_t		*roles;
	struct user_item	*next;
	void 			*data;	/* generic pointer used by libseuser; ignored in apol */
} user_item_t;

typedef struct user_list {
	user_item_t	*head;
	user_item_t	*tail;
} user_list_t;

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
	char 		*file_contexts_file;
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
int seuser_label_home_dir(const char *user, user_db_t *db, policy_t *policy, const char *output_file);
const char* seuser_decode_labeling_err(int err);
const char* libseuser_get_version(void);

int append_user(user_item_t *newuser, user_list_t *list);
int free_user(user_item_t *ptr);
int get_user_name(user_item_t *user, char **name);

#endif /*_SEUSER_DB_H_ */



