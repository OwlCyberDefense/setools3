/* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* seuser_db.c
 *
 * The user database functions for seuser.
 *
 */

#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef LIBSELINUX
#include <selinux/selinux.h>
#include <limits.h>
#endif
#include "seuser_db.h"

/* apol lib */
#include "../libapol/policy.h"
#include "../libapol/policy-io.h"

/* assumed defines */
#define MAKEFILE		"Makefile"
#define CONFIG_FILE		"seuser.conf"

/* The following should be defined in the make environment */
#ifndef SETFILES_PROG
	#define SETFILES_PROG	"/usr/sbin/setfiles"
#endif

#ifndef LIBSEUSER_VERSION_STRING
	#define LIBSEUSER_VERSION_STRING "UNKNOWN"
#endif

/* With the Aug 2002 policy mgt patch, we use intall rather than
 * policy.conf as our "refresh" target.  This will make policy.conf
 * and install the changes to both intalled policy forms (policy.conf)
 * and binary policy file.
 */
#define POLICY_CONF_TARGET	"install"
#define INSTALL_TARGET		"load"

/********************************************************************
 * Functions Decrepcated within libapol but still used by libseuser */

/* does not free the generic data pointer; that's up to the user of the pointer*/
int free_user(user_item_t *ptr)
{
	free(ptr->name);
	free_ta_list(ptr->roles);
	free(ptr->data);
	free(ptr);
	return 0;
}

/* user names; allocates memory  */
int get_user_name(user_item_t *user, char **name)
{
	if(user == NULL || name == NULL) {
		return -1;
	}
	if((*name = (char *)malloc(strlen(user->name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, user->name);
	return 0;
}

/* add a user to user list */
int append_user(user_item_t *newuser, user_list_t *list)
{
	if(newuser == NULL || list == NULL)
		return -1;
	newuser->next = NULL;
	
	if(list->head == NULL) {
		list->head = newuser;
		list->tail = newuser;		
	}
	else {
		list->tail->next = newuser;
		list->tail = newuser;
	}

	return 0;
}



/* End libapol deprecated functions
 *********************************************************************/


/* frees conf info in db  */
static int free_conf_info (user_db_t *db)
{
	if(db == NULL)
		return -1;
	if(db->policy_conf != NULL) free(db->policy_conf);
	if(db->user_file != NULL) free(db->user_file);
	if(db->policy_dir != NULL ) free(db->policy_dir); 
	if(db->file_contexts_file != NULL ) free(db->file_contexts_file); 
	if(db->config_dir != NULL) free(db->config_dir);
	return 0;
}

static int init_conf_info(user_db_t *db)
{
	db->policy_conf = NULL;
	db->user_file = NULL;
	db->policy_dir = NULL;
	db->config_dir = NULL;
	db->file_contexts_file = NULL; 
	db->conf_init = FALSE;
	return 0;
}

int seuser_init_db(user_db_t *db, bool_t init_conf)
{
	if(db == NULL)
		return -1;
	db->num_users = 0;
	db->users.head = NULL;
	db->users.tail = NULL;
	if(init_conf)
		init_conf_info(db);
	return 0;
}

/* free all memory assoicated with a user database */
int seuser_free_db(user_db_t *db, bool_t free_conf)
{
	user_item_t *ptr;
	
	if(db == NULL)
		return -1;
	if(free_conf) {
		if(free_conf_info(db) != 0)
			return -1;
	}
	for(ptr = db->users.head; ptr != NULL; ptr = ptr->next) {
		free_user(ptr);		
	}		
	return 0;
}

const char* libseuser_get_version(void)
{
	return LIBSEUSER_VERSION_STRING;
}

const int seuser_copy_db_from_apol(user_db_t *db, policy_t *policy)
{
	int rt, i, j, *roles, num_roles;
	user_item_t *user;
	
	if(db == NULL || policy == NULL) {
		return -1;
	}
	
	db->users.tail = NULL;
	if(num_users(policy) == 0) {
		db->users.head = NULL;
		db->num_users = 0;
		return 0;
	}
	db->num_users = num_users(policy);
	
	for(i = 0; is_valid_user_idx(i, policy); i++) {
		user = (user_item_t *)malloc(sizeof(user_item_t));
		if(user == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		memset(user, 0, sizeof(user_item_t));		
		rt = get_user_name2(i, &user->name, policy);
		if(rt < 0)
			return rt;
		
		rt = get_user_roles(i, &num_roles, &roles, policy);
		if(rt < 0)
			return rt;
		
		for(j = 0; j < num_roles; j++) {
			ta_item_t *newta;
			newta = (ta_item_t *) malloc(sizeof(ta_item_t));
			if(newta == NULL) {
				fprintf(stderr, "out of memory");
				return -1;
			}
			newta->type = IDX_ROLE;
			newta->idx = roles[j];
			rt = insert_ta_item(newta, &(user->roles));
			if(rt != 0) {
				fprintf(stderr, "problem inserting role in user");
				return -1;
			}
		}

		rt = append_user(user, &(db->users));
		if(rt != 0) {
			fprintf(stderr, "problem inserting user in database ");
			return -1;
		}	
	}
	return 0;
}

/* takes a user db, initializes it, opens the policy, and copies the policy db data to
 * the user db.  The config info must bed read PRIOR to calling this function */
int seuser_open_user_db(user_db_t *db, policy_t **policy)
{
	int rt;
     	if(db == NULL || policy == NULL || !seuser_is_conf_loaded(db)) {
     		return -1;
	}
	seuser_init_db(db, FALSE);
		
	/* open policy with apol; all we need are users, roles, and types */
	rt = open_partial_policy(db->policy_conf, (POLOPT_USERS|POLOPT_ROLES|POLOPT_TYPES), policy);
	//rt = open_policy(db->policy_conf, policy);
	if(rt != 0)
		return rt;
	/* create user database from the policy  */
	rt = seuser_copy_db_from_apol(db, *policy);
	if(rt != 0) {
		return -1;
	}
	return 0;
}


/* check if user exists*/
bool_t seuser_does_user_exist(const char *name, user_db_t *db)
{
	user_item_t *ptr;
	if(name == NULL || db == NULL) {
		return FALSE;
	}
	
	for(ptr = db->users.head; ptr != NULL; ptr = ptr->next) {
		if(strcasecmp(name, ptr->name) == 0) {
			return TRUE;
		}
	}
	return FALSE;	
}


/* FIX: Currently we're return a pointer to the record in the REAL db: CALLER-DO NOT FREE *
 *check if user exists, and if so return a pointer to its structure */
int seuser_get_user_by_name(const char *name, user_item_t **user, user_db_t *db)
{
	user_item_t *ptr;
	if(user == NULL || name == NULL || db == NULL) {
		return -1;
	}
	
	for(ptr = db->users.head; ptr != NULL; ptr = ptr->next) {
		if(strcasecmp(name, ptr->name) == 0) {
			*user = ptr;
			return 0;
		}
	}
	return -1;
}



/* following return codes 
 * 
 *  0	is proper
 * -1	unexpected error
 *  1	a user role is not a valid role
 */
int seuser_is_proper_user_record(user_item_t *user, user_db_t *db, policy_t *policy)
{
	ta_item_t *taitem;
	
	/* various pointers */
	if(user == NULL || policy == NULL || user->name == NULL || user->roles == NULL ) {
			return -1;
	}
		
	/* roles */
	for(taitem = user->roles; taitem != NULL; taitem = taitem->next) {
		if(taitem->type != IDX_ROLE) {
			return -1;
		}
		if(!is_valid_role_idx(taitem->idx, policy)) {
			return 1;
		}
	}
	return 0;
}


/* rename a user from the database 
 *  0  success
 *  1  user doesn't exist
 * -1  other error
 */
int seuser_rename_user(const char *oldname, const char *newname, user_db_t *db)
{
	user_item_t *ptr;
	char *tmp;
	
	if(oldname == NULL || newname == NULL || db == NULL)
		return -1;
		
	for(ptr = db->users.head; ptr != NULL; ptr = ptr->next) {
		if(strcasecmp(oldname, ptr->name) == 0) {
			break;
		}
	}
	if(ptr == NULL)
		return 1; /* user doens't exist */
	
	tmp = (char *)malloc(strlen(newname)+1);
	if(tmp == NULL) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	strcpy(tmp, newname);
	assert(ptr->name != NULL);
	free(ptr->name);
	ptr->name = tmp;
		
	return 0;
}


/* remove a user from the database 
 *  0  success
 *  1  user doesn't exist
 * -1  other error
 */
int seuser_remove_user(const char *name, user_db_t *db)
{
	user_item_t *ptr, *ptr2;
	
	if(name == NULL || db == NULL)
		return -1;
		
	for(ptr = db->users.head, ptr2 = NULL; ptr != NULL; ptr2 = ptr, ptr = ptr->next) {
		if(strcasecmp(name, ptr->name) == 0) {
			if(ptr2 == NULL) { 
				/* case: head of list */
				assert(ptr == db->users.head);
				db->users.head = ptr->next;
			}
			else {
				assert(ptr2->next == ptr);
				ptr2->next = ptr->next;
				if(ptr == db->users.tail) {
					db->users.tail = ptr2;
				}
			}
			free_user(ptr);
			(db->num_users)--;
			return 0;
		}
	}
	
	return 1;
}

/* add or change a user record to the db 
 *  0  success
 *  1  user already exists in selinux policy and is newuser
 *  2  user doesnt exist and !newuser
 *  3  improperly formed user record
 * -1  other error
 */
int seuser_update_user(user_item_t *user, bool_t newuser, user_db_t *db, policy_t *policy) 
{
	user_item_t *tmpuser;
	int rt;
	
	if(user == NULL || db == NULL || policy == NULL)
		return -1;
	
	if(seuser_is_proper_user_record(user, db, policy) != 0)
		return 3;
	
	rt = seuser_get_user_by_name(user->name, &tmpuser, db);
	if(rt == 0 && newuser) {
		return 1; /* user already exists */
	}
	else if(rt != 0 && !newuser) {
		return 2; /* no user to update */
	}
	if(!newuser) {
		rt = seuser_remove_user(user->name, db);
		assert(rt != 1); /* can't possibly be that the user didn't exist at this point */
		if(rt < 0) {
			return -1;
		}
	}
	
	return(append_user(user, &(db->users)));	
}


/* add or change a user record 
 * Returns:
 *	see return codes from seuser_update_user(), in addition:
 *	4  an invalid role name was provided
 *	5  error inserting role into user record
 */
int seuser_add_change_user(bool_t new_user, const char *user,  char ** roles, int num_roles, user_db_t *db, policy_t *policy) 
{
	user_item_t *uitem;
	int idx, i, rt;

	/* assemble the new/changed user record */
	uitem = (user_item_t *)malloc(sizeof(user_item_t));
	memset(uitem, 0, sizeof(user_item_t));		
	if(uitem == NULL) 
		return -1;

	/* name */
	(uitem)->name = (char *)malloc(strlen(user) + 1);
	if((uitem)->name == NULL) {
		fprintf(stderr, "out of memory");
		free_user(uitem);
		return -1;
	}
	strcpy((uitem)->name, user);
	
	/* roles */
	for(i = 0; i < num_roles; i++) {
		ta_item_t *newta;
				
		idx = get_role_idx(roles[i], policy);
		if(idx < 0) {
			free_user(uitem);
			return 4;
		}
		newta = (ta_item_t *) malloc(sizeof(ta_item_t));
		if(newta == NULL) {
			fprintf(stderr, "out of memory");
			free_user(uitem);
			return -1;
		}
		memset(newta, 0, sizeof(ta_item_t));
		newta->idx = idx;
		newta->type = IDX_ROLE;
		rt = insert_ta_item(newta, &(uitem->roles));
		if(rt != 0) {
			free_user(uitem);
			return 5;
		}
		
	}
	
	/* new add/change the new record; if successful, don't free user record */
	rt = seuser_update_user(uitem, new_user, db, policy);
	if(rt != 0)
		free_user(uitem);
	return rt;
}

/* Function name: seuser_get_user_home_dir 
 */
static int seuser_get_user_home_dir(const char *user, char **home_dir)
{
	struct passwd *line = NULL;

	assert(user != NULL && home_dir != NULL);	
	line = getpwnam(user);
	if (line != NULL) {
		*home_dir = (char *)malloc(strlen(line->pw_dir) + 1);
	     	if (*home_dir == NULL) {
	     		fprintf(stderr, "out of memory\n");
	     		return -1;
	     	}
		sprintf(*home_dir, "%s", line->pw_dir);
	} 
   	
     	return 0;
}

static int call_make(const char *target, const char *output, const char *policy_dir)
{
	char *make_str;
	int rt;

	assert(target != NULL);
	assert(output != NULL);
	
     	make_str = (char *)malloc((strlen(policy_dir) + strlen(MAKEFILE) + 
     		strlen(target) + strlen(output) + 50) * sizeof(char));
     	if(make_str == NULL) {
     		fprintf(stderr, "out of memory\n");
     		return -1;
     	}
     	sprintf(make_str, "make -f %s -C %s %s > %s 2>&1", MAKEFILE, policy_dir, target, output);
	
     	rt = system(make_str);	
     	if(rt != 0) {
     		fprintf(stderr, "Error: Make string: %s.", make_str);
     		free(make_str);
     		return -1;
     	} 
	free(make_str);
	return 0;
}

/* Function name: seuser_call_make_file_contexts 
 * Description: Re-makes the file_contexts/file_contexts file.
 */
static int seuser_call_make_file_contexts(user_db_t *db, const char *output_file)
{
	int rt, len; 
	char *c;
	
	assert(db != NULL && db->policy_dir != NULL);
	/* in order to force the file_contexts to be remade, we touch a file that
	 * the file_contexts target lists as a dependency. The correct thing would
	 * be to have the file_contexts target list the users file as a dependency.
	 * FIXME */
	len = (strlen("touch ") + strlen(db->policy_dir) + strlen("file_contexts/types.fc") + 3)
		* sizeof(char);
	c = (char*)malloc(len);
	if (!c) {
		fprintf(stderr, "Memory error!\n");
		return -1;
	}
	
	snprintf(c, len, "touch %s/file_contexts/types.fc", db->policy_dir);
	
	rt = system(c);
	if (rt != 0) {
		fprintf(stderr, "Error making system call: %s\n", c);
		free(c);
		return -1;
	}
	
	free(c);
	
	/* reinstall the policy - this will remake the file contexts and install */
	rt = seuser_reinstall_policy(output_file, db);
	if (rt != 0)
		return -1;
	return 0;
}

static int call_set_files_on_home_dir(const char *home_dir, user_db_t *db)
{
	char *setfiles_str = NULL;
	int rt;
	
	assert(home_dir != NULL && db != NULL && db->file_contexts_file != NULL);	
	setfiles_str = (char *)malloc(strlen(SETFILES_PROG) + 
		strlen(db->file_contexts_file) + strlen(home_dir) + 3);
     	if (setfiles_str == NULL) {
     		fprintf(stderr, "out of memory\n");
     		return -1;
     	}
     	sprintf(setfiles_str, "%s %s %s", SETFILES_PROG, db->file_contexts_file, home_dir);
	rt = system(setfiles_str);	
	if(rt != 0) {
     		free(setfiles_str);
     		return -1;
     	} 
     	free(setfiles_str);
     	return 0;
}

/* return code definitions for seuser_label_home_dir(). */
#define LIBSEUSER_LABEL_ERR_GENERAL		-1
#define LIBSEUSER_LABEL_ERR_INVALID_USER	-2
#define LIBSEUSER_LABEL_ERR_NO_HOME_DIR		-3

/* Error TEXT definitions for decoding the above error definitions. */
#define LIBSEUSER_LABEL_ERR_INVALID_USER_TEXT	"User is not defined in the policy.\n"
#define LIBSEUSER_LABEL_ERR_NO_HOME_DIR_TEXT	"Home directory does not exist.\n"
#define LIBSEUSER_LABEL_ERR_GENERAL_TEXT 	"Error relabeling users home directory files."

/* returns an error string based on a return error from seuser_label_home_dir() */
const char* seuser_decode_labeling_err(int err)
{
	switch(err) {
	case LIBSEUSER_LABEL_ERR_INVALID_USER:
		return LIBSEUSER_LABEL_ERR_INVALID_USER_TEXT;
	case LIBSEUSER_LABEL_ERR_NO_HOME_DIR:
		return LIBSEUSER_LABEL_ERR_NO_HOME_DIR_TEXT;
	default:
		return LIBSEUSER_LABEL_ERR_GENERAL_TEXT;
	}
}

/* Function name: seuser_label_home_dir 
 * Description: Labels the specified users home directory files with appropriate 
 *		security contexts from the selinux policys' file_contexts file. 
 *		
 * Arguments: 	user - username of home dir to label 	
 */
int seuser_label_home_dir(const char *user, user_db_t *db, policy_t *policy, const char *output_file)
{
	char *home_dir = NULL;
	int rt;
		
     	/* remake the file_contexts file */
     	rt = seuser_call_make_file_contexts(db, output_file);
     	if(rt != 0) {
     		return -1;
     	}
     		
	/* Get the users home directory */
	rt = seuser_get_user_home_dir(user, &home_dir);
	if (rt != 0) {
		return -1;
	}

	if (home_dir == NULL) {
		return LIBSEUSER_LABEL_ERR_NO_HOME_DIR;
	}
	
	/* Given the home directory and specs file path as arguments, call setfiles 
	 * to label the users home directory files appropriately. */
	rt = call_set_files_on_home_dir(home_dir, db);	
     	if(rt != 0) {
     		free(home_dir);
     		return LIBSEUSER_LABEL_ERR_GENERAL;
     	}  
	free(home_dir);
			
	return 0;
}

/* write out the users file
 */
int seuser_write_user_file(user_db_t *db, policy_t *policy)
{
	user_item_t *ptr;
	ta_item_t *taptr;
	char *name;
	int rt;
	time_t ltime;
	FILE *fp;
	
	if(db == NULL || policy == NULL || !(db->conf_init))
		return -1;
	
	/* open users file */
	if((fp = fopen(db->user_file, "w+")) == NULL) {
		return -1;
	}
	
	time(&ltime);
	rt = fprintf(fp, "# seuser\n# This file created automatically by seuser on %s\n", ctime(&ltime));	
	if(rt < 0) {
		fclose(fp);
		return -1;
	}
	rt = fprintf(fp, "#\n# user file\n\n");
	if(rt < 0) {
		fclose(fp);
		return -1;
	}

	for(ptr = db->users.head; ptr != NULL; ptr = ptr->next) {
		rt = fprintf(fp, "user %s roles { ", ptr->name);
		if(rt < 0) {
			fclose(fp);
			return -1;
		}
		for(taptr = ptr->roles; taptr != NULL; taptr = taptr->next) {
			assert(taptr->type == IDX_ROLE);
			rt = get_role_name(taptr->idx, &name, policy);
			if(rt != 0) {
				fprintf(stderr, "Problem looking up role name in seuser_write_user_file");
				fclose(fp);
				return -1;
			}
			rt = fprintf(fp, "%s ", name);
			free(name);
			if(rt < 0)  {
				fclose(fp);
				return -1;
			}
		}
		rt = fprintf(fp, "} ;\n");
		if(rt < 0) {
			fclose(fp);
			return -1;
		} 
	}
	fclose(fp);
	return 0;
}


#define	CONF_ERR_SUCCESS	"Success!"
#define CONF_ERR_FIND_CONFIG	"Could not find seuser.conf file.\n"
#define CONF_ERR_OPEN_CONFIG	"Could not open seuser.conf file.\n"
#define CONF_ERR_FIND_POLICY	"You need to define the policy.conf parameter in your seuser.conf file.\n"
#define CONF_ERR_OPEN_POLICY	"Error accessing the policy.conf file. See seuser.conf file.\n"
#define CONF_ERR_OPEN_DIR	"You need to define the policy directory parameter in your seuser.conf file.\n"
#define CONF_ERR_ACCESS_DIR	"Error accessing the policy directory. See seuser.conf file.\n"
#define CONF_ERR_FIND_FCONTEXT	"You need to define the file_contexts parameter in your seuser.conf file.\n"
#define CONF_ERR_FIND_USER	"You need to define the user file parameter in your seuser.conf file.\n"
#define CONF_ERR_ERROR		"Error reading seuser.conf file.\n"
/* returns an error string based on a return error from seuser_read_conf_info() */
const char* seuser_decode_read_conf_err(int err)
{
	switch(err) {
	case 0:
		return CONF_ERR_SUCCESS;
	case 1:
		return CONF_ERR_FIND_CONFIG;
	case 2:
		return CONF_ERR_OPEN_CONFIG;
	case 3:
		return CONF_ERR_FIND_POLICY;
	case 4: 
		return CONF_ERR_OPEN_POLICY;
	case 5:
		return CONF_ERR_OPEN_DIR;
	case 6:
		return CONF_ERR_ACCESS_DIR;
	case 7:
		return CONF_ERR_FIND_USER;
	case 8:
		return CONF_ERR_FIND_FCONTEXT;
	default:
		return CONF_ERR_ERROR;
	}
}


/* read the seuser config info */
/* return code hints:
 * 0	success
 * 1	couldn't FIND config file
 * 2	couldn't OPEN config file
 * 3	couldn't find policy.conf in config file
 * 4 	couldn't read policy.conf file
 * 5	couldn't find policy dir
 * 6	couldn't access policy dir
 * 7	couldn't find user file
 * -1	general error
 */
int seuser_read_conf_info(user_db_t *db)
{
#ifndef LIBSELINUX
	char *full_config = NULL;
	FILE *fp;
#endif
	int rt;
	
	if(db == NULL)
		return -1;
	
	if(db->conf_init)
		return 0; /* already read */

#ifndef LIBSELINUX		
	/* we need to find the conf file.  We use the same logic
	 * as apol uses, and generally expect the config file for	
	 * seuser to be stored with the apol stuff.  
	 */
	db->config_dir = find_file(CONFIG_FILE);
	if(db->config_dir == NULL) 
		return 1;
     	full_config = (char *)malloc(strlen(db->config_dir) + strlen(CONFIG_FILE) + 3);
     	if(full_config == NULL) {
     		fprintf(stderr, "out of memory");
     		free(db->config_dir);
     		db->config_dir = NULL;
     		return -1;
     	}
     	sprintf(full_config, "%s/%s", db->config_dir, CONFIG_FILE);

	if((fp = fopen(full_config, "r")) == NULL) {
		free(full_config);
		free(db->config_dir);
		db->config_dir = NULL;
		return 2;
	}	
	free(full_config);
	
	db->policy_conf = get_config_var("policy.conf", fp);
	if(db->policy_conf == NULL) {
		fclose(fp);
		free_conf_info(db);
		init_conf_info(db);
		return 3;
     	}
	rt = access(db->policy_conf, R_OK);
	if(rt != 0) {
		fclose(fp);
		perror("access");
		free_conf_info(db);
		init_conf_info(db);
		return 4;
     	}
#else
	if ((db->policy_conf = (char *)malloc(sizeof(char)*PATH_MAX)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	}
	snprintf(db->policy_conf, PATH_MAX - 1, "%s/src/policy/policy.conf", 
		 selinux_policy_root());
	rt = access(db->policy_conf, R_OK);
	if(rt != 0) {
		perror("access");
		free_conf_info(db);
		init_conf_info(db);
		return 4;
     	}
#endif
	

#ifndef LIBSELINUX
	db->policy_dir = get_config_var("policy_dir", fp);
	if(db->policy_dir == NULL) {
		fclose(fp);
		free_conf_info(db);
		init_conf_info(db);
		return 5;
     	}
	rt = access(db->policy_dir, R_OK);
	if(rt != 0) {
		fclose(fp);
		perror("access");
		free_conf_info(db);
		init_conf_info(db);
		return 6;
     	}  
#else
	if ((db->policy_dir = (char *)malloc(sizeof(char)*PATH_MAX)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	}
	snprintf(db->policy_dir, PATH_MAX - 1, "%s/src/policy", selinux_policy_root());
	rt = access(db->policy_dir, R_OK);
	if(rt != 0) {
		perror("access");
		free_conf_info(db);
		init_conf_info(db);
		return 6;
     	}  
#endif
	

#ifndef LIBSELINUX
	db->user_file = get_config_var("user_file", fp);
	if(db->user_file == NULL) {
     		fclose(fp);
		free_conf_info(db);
		init_conf_info(db);
		return 7;
     	}
#else
	if ((db->user_file = (char *)malloc(sizeof(char)*PATH_MAX)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return GENERAL_ERROR;
	}
	snprintf(db->user_file, PATH_MAX - 1, "%s/src/policy/users", selinux_policy_root());
#endif    	   	
	/* users file may not exist which is ok, so we won't check read access. */  

#ifndef LIBSELINUX
	db->file_contexts_file = get_config_var("file_contexts_file", fp);
	if(db->file_contexts_file == NULL) {
		fclose(fp);
		free_conf_info(db);
		init_conf_info(db);
		return 8;
     	}
     	fclose(fp);
#else
	db->file_contexts_file = strdup(selinux_file_context_path());
#endif
     	/* file_contexts file may not exist which is ok, so we won't check read access. */  
   
	db->conf_init = TRUE; 	
	return 0;
}

/* re-make policy */
int seuser_remake_policy_conf(const char *tmpfile, user_db_t *db)
{
	int rt;
	if(tmpfile == NULL || db == NULL || !seuser_is_conf_loaded(db))
		return -1;	
	assert(db->policy_dir != NULL);

	rt = call_make(POLICY_CONF_TARGET, tmpfile, db->policy_dir);	
     	if(rt != 0) {
     		return -1;
     	}     	
	
	return 0;
}

/* re-make & install new policy */
int seuser_reinstall_policy(const char *tmpfile, user_db_t *db)
{
	int rt;
	if(tmpfile == NULL || db == NULL || !seuser_is_conf_loaded(db))
		return -1;	
	assert(db->policy_dir != NULL);

	rt = call_make(INSTALL_TARGET, tmpfile, db->policy_dir);	
     	if(rt != 0) {
    		return -1;

     	}     	
	
	return 0;
}


/* "commit" means write access to user file, return values are:
 *
 *  0	permission allowed
 *  1	permission denied to users
 * -1	error
 *
 * the file names are stoed in global vars
 */
int seuser_check_commit_perm(user_db_t *db)
{
	int rt;
	if(db ==NULL || !seuser_is_conf_loaded(db))
		return -1;	
	/* if user_file doesn't exist, check whether we can in fact create it */
	rt = access(db->user_file, F_OK);
	if(rt == 0) 
		rt = access(db->user_file, W_OK);
	else
		/* FIX: For now we're assuming (yuk!) that the users file is in the policy_dir 
		 * so if the users files doesn't exist, check that we can indeed create it in the
		 * policy_dir */
		rt = access(db->policy_dir, W_OK);
	if(rt != 0)
		return 1;
	return 0;
}



