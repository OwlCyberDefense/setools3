/* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* seuser_wrap.h
 * 
 * This file contains wrapper functions to make
 * the libseuser functions available to non-TCL/TK
 * programs.
 */
 

#ifndef _SEUSER_WRAP_H_
#define _SEUSER_WRAP_H_
#include "../libapol/policy.h"
 
int seu_init(); 
int seu_exit();
int seu_initUserdb();
int seu_closedb();
int seu_isUserValid(char *user);
int seu_removeUser(char *user);
int seu_remakePolicyConf();
int seu_reinstallPolicy();
bool_t seu_checkCommitAccess();
int seu_commitChanges();
int seu_editUser(const char *cmd, char *user, char **roles, int numroles, 
		bool_t default_context,	char *drole, char *dtype, 
		bool_t cron_context, char *crole, char *ctype);
int seu_validate_role(char *userName, char *givenRole);
int seu_show_users(const char *user, char **outstr);
int seu_show_roles(char **outstr);
int seu_renameUser(const char *oldname, const char *newname);
bool_t seu_does_user_exist(const char *user);

#endif /*_SEUSER_WRAP_H_*/




