/* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* seuser_wrap.c
 * 
 * This file contains wrapper functions to make
 * the libseuser functions available to non-TCL/TK
 * programs.
 */
 
#include <tcl.h>
#include <tk.h>
#include <assert.h>
#include "seuser_tcl.h"
#include "seuser_db.h"
#include "../libapol/apol_tcl.h"
#include "../libapol/policy.h"


/* globals */
Tcl_Interp * interp;
user_db_t *seu_db = NULL;

#define ALLOC_SZ 512
/* ensure string buffer is large enough and if not increase it */
static int check_str_sz(char **str, int *sz, int needed)
{
	char *tmp;
	
	if((strlen(*str) + needed) >= (*sz)+1) {
		if(needed > ALLOC_SZ)
			*sz += needed;
		else
			*sz += ALLOC_SZ;
			
		tmp = (char *)realloc(*str, *sz);
		if(tmp == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		*str = tmp;
	}	
	return 0;
}

int seu_init()
{
	int rt;
	rt = set_login_version();
	if (rt != 0) {
		fprintf(stderr, "Problem initializing login version\n");
		return -1;
	}
	interp = Tcl_CreateInterp();
	rt = read_conf_info(interp);
	if(rt != 0) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
	se_mktmpfile();
	
	return 0;
}
 
int seu_exit()
{
	int ac;
	char *av[1];
	
	av[0] = NULL;
	ac = 1;
	
	if(Seuser_Exit(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
		
	return 0;
}


int seu_initUserdb()
{
	int ac;
	char *av[1];
	
	av[0] = NULL;
	ac = 1;
	
	if(Seuser_InitUserdb(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
	/* seu_db is a locally defined global */
	seu_db = get_user_db();
	if(seu_db == NULL)
		return -1;
	
	return 0;
}

int seu_closedb()
{
	int ac;
	char *av[1];
	
	av[0] = NULL;
	ac = 1;
	
	if(Seuser_CloseDatabase(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
	return 0;
}


int seu_isUserValid(char *user)
{
	int ac;
	char *av[2];
	
	if(user == NULL)
		return -1;
	
	av[0] = NULL;
	av[1] = user;
	ac = 2;
	
	if(Seuser_IsUserValid(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
	return 0;
}

int seu_removeUser(char *user)
{
	int ac;
	char *av[2];
	
	if(user == NULL)
		return -1;
	
	av[0] = NULL;
	av[1] = user;
	ac = 2;
	
	if(Seuser_RemoveUser(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
	return 0;
}


int seu_renameUser(const char *oldname, const char *newname)
{
		
	if(seu_db == NULL || oldname == NULL || newname == NULL) {
		return -1;
	}
	return seuser_rename_user(oldname, newname, seu_db);
}

int seu_remakePolicyConf()
{
	int ac;
	char *av[1];
	
	av[0] = NULL;
	ac = 1;
	
	if(Seuser_RemakePolicyConf(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
	return 0;
}

int seu_commitChanges()
{
	int ac;
	char *av[1];
	
	av[0] = NULL;
	ac = 1;
	
	if(Seuser_Commit(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
	return 0;
}


int seu_reinstallPolicy()
{
	int ac;
	char *av[1];
	
	av[0] = NULL;
	ac = 1;
	
	if(Seuser_ReinstallPolicy(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return -1;
	}
	return 0;
}


int seu_editUser(char *cmd, char *user, char **roles, int numroles, 
		bool_t default_context,	char *drole, char *dtype, 
		bool_t cron_context, char *crole, char *ctype)
{
	int ac;
	char *av[10], *roles_str;
	
	av[0] = NULL;
	av[1] = cmd;
	av[2] = user;
	av[4] = (default_context ? "1" : "0");
	av[5] = drole;
	av[6] = dtype;
	av[7] = (cron_context ? "1" : "0");;
	av[8] = crole;
	av[9] = ctype;
	ac = 10;
	
	roles_str = Tcl_Merge(numroles, roles);
	av[3] = roles_str;
		
	if(Seuser_EditUser(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		Tcl_Free(roles_str);
		return -1;
	}
	Tcl_Free(roles_str);
	return 0;
}

bool_t seu_checkCommitAccess()
{
	int ac;
	char *av[1];
	
	av[0] = NULL;
	ac = 1;
	
	if(Seuser_CheckCommitAccess(NULL, interp, ac, av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
		return FALSE;
	}
	return TRUE;
}


int seu_validate_role(char *userName, char *givenRole)
{
	int rt;
	
	rt = validate_given_role(userName, givenRole);
	if(rt != 0) {
		return 1;		
	}
		
	return 0;
}

/* return a string with users and user roles, if user == NULL then show all users,
 * otherwise only the user provided.  return -2 if the provided user is not defined. */
int seu_show_users(const char *user, char **outstr)
{
	user_item_t *ptr;
	char *name, *role, *tmp;
	int sz;
	bool_t found = FALSE;
	ta_item_t *item;
	policy_t *policy = get_seuser_policy();
		
	if(seu_db == NULL || outstr == NULL) {
		return -1;
	}
	
	sz = ALLOC_SZ;
	tmp = (char *)malloc(sz);
	if(tmp == NULL) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	tmp[0] = '\0';
	for(ptr = seu_db->users.head; get_user_name(ptr, &name) == 0; ptr = ptr->next) {
		if(user != NULL) {
			if(strcmp(user, name) == 0) 
				found = TRUE;
			else 
				continue;
		}
		/* ensure enough room for name and ending \n character and ": "*/
		if(check_str_sz(&tmp, &sz, strlen(name)+3) != 0) {
			return -1;
		}
		strcat(tmp, name);
		strcat(tmp, ": ");

		/* add each role */
		for(item = ptr->roles; item != NULL; item = item->next) {
			if(get_role_name(item->idx, &role, policy) != 0) {
				return -1;
			}
			if(check_str_sz(&tmp, &sz, strlen(role)+1) != 0) {
				return -1;
			}
			strcat(tmp, role);
			strcat(tmp, " ");
			free(role);
		}
		
		strcat(tmp, "\n");
		free(name);
	}
	
	if(strlen(tmp) == 0) {
		free(tmp);
		if(user != NULL)
			return -2; /* user specified but not found */
		*outstr = NULL; /* no users defined at all */
	}
	else
		*outstr = tmp;
		
	return 0;
}

int seu_show_roles(char **outstr)
{
	char *tmp, *role;
	int i, sz;
	policy_t *policy = get_seuser_policy();
	
	if(seu_db == NULL || outstr == NULL) {
		return -1;
	}
	sz = ALLOC_SZ;
	tmp = (char *)malloc(sz);
	if(tmp == NULL) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	tmp[0] = '\0';
	for(i = 0; is_valid_role_idx(i, policy); i++) {
		if(get_role_name(i, &role, policy) != 0) {
			return -1;
		}
		if(check_str_sz(&tmp, &sz, strlen(role)+1) != 0) {
			return -1;
		}
		strcat(tmp, role);
		strcat(tmp, "\n");
		free(role);
	}
	if(strlen(tmp) == 0) {
		free(tmp);
		*outstr = NULL;
	}
	else
		*outstr = tmp;	
	
	
	return 0;
}


bool_t seu_does_user_exist(const char *user) {
	return seuser_does_user_exist(user, seu_db);
}


