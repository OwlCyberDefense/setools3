/* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com, dac@tresys.com
 */

/* seuser_tcl.c
 *
 */ 

#include <unistd.h>
#include <tcl.h>
#include <tk.h>
#include <assert.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <stdio.h>
#include "seuser_tcl.h"
#include "seuser_db.h"

/* apol lib */
#include "../libapol/policy.h"
#include "../libapol/apol_tcl.h"
#include "../libapol/util.h"

/* Login vesion checking is now removed; provide
 * this for backwards compatability */
char *login_version_str = NEW_LOGIN_STR;

/* temp file for make output */
char *tmpmakeout = NULL;

/* 
 * Several of the public C functions provided by the Tcl/Tk 8.4 libraries 
 * have had their declarations augmented with the addition of CONST modifiers 
 * on pointers. In order to support both the 8.3 and 8.4 prototype Tcl/Tk 
 * libraries, we use the internal symbol CONST84 instead of const. In this 
 * way, compiling against the 8.4 headers, will use the const-ified interfaces, 
 * but compiling against the 8.3 headers, will user the original interfaces.
 */
#ifndef CONST84
#define CONST84
#endif

/* database global */
user_db_t db;
bool_t db_init = FALSE;

/* policy */
policy_t *policy; /* our local global policy*/



/*******************************************************************
 *
 * Support functions
 *
 *******************************************************************/
int se_mktmpfile() 
{
	/* get a temp file name if this is first time initializing
	 * we use this file name for our temporary make output */
	/* tmpmakeout is a global variable */
	if(tmpmakeout == NULL) {
		tmpmakeout = tempnam("/tmp", "seuser_tmp.");
	}
	return 0;
}



/* determine user type and return appropriate string.  Caller must 
 * free() type_string
 */
char * determine_user_type(const char* user)
{
	char *result;
	int rt;
	user_item_t *uitem;
	
	/* alloc string..caller must free */
	result = (char *)malloc(SYSUSER_MAX_STR_SZ);
	if(result == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	
	if(strcmp(user, SPECIAL_USER_SYSTEM) == 0 || strcmp(user, SPECIAL_USER_USER) == 0) {
		strcpy(result, SYSUSER_SPECIAL_STR);
	}
	else {
		rt = seuser_get_user_by_name(user, &uitem, &db);
		if(rt != 0) {
			rt = seuser_get_user_by_name(SPECIAL_USER_USER, &uitem, &db);
			if(rt != 0) 
				strcpy(result, SYSUSER_UNDEFINED_STR);
			else
				strcpy(result, SYSUSER_GENERIC_STR);
		}
		else {
			strcpy(result, SYSUSER_DEFINED_STR);
		}
	}
	return result;
}

/*******************************************************************
 *
 * TCL Commands
 *
 *******************************************************************/

int Seuser_GetVersion(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	Tcl_AppendResult(interp, (char*)libseuser_get_version(),
			 (char *) NULL);
	return TCL_OK;
}

/* Deprecated */
int Seuser_Get_Login_Version(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]) 
{	
	Tcl_AppendResult(interp, login_version_str, (char *) NULL);

	return TCL_OK;
}

/* Deprecated */
int Seuser_Use_Old_Login_Contexts(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]) 
{	
	/* always false */
	Tcl_AppendResult(interp, "0", (char *) NULL);
	return TCL_OK;
}

int Seuser_Exit(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(argc > 1) {
		Tcl_AppendResult(interp, "Seuser_Exit: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(tmpmakeout != NULL) {
		remove(tmpmakeout);
	}
	return TCL_OK;
}

int Seuser_GetTmpMakeFileName(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	if(argc > 1) {
		Tcl_AppendResult(interp, "Seuser_GetTmpMakeFileName: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(tmpmakeout == NULL) {
		Tcl_AppendResult(interp, "Not initialized: Seuser_InitUserdb must be called first", (char *) NULL);
		return TCL_ERROR;
	}
	Tcl_AppendResult(interp, tmpmakeout, (char *) NULL);
	return TCL_OK;
}

/* initialize User database */
int Seuser_InitUserdb(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
	int rt;
	
	if(argc > 1) {
		Tcl_AppendResult(interp, "Seuser_InitUserdb: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	
     	/* read conf info if not already set */
	seuser_init_db(&db, TRUE);
     	if(!seuser_is_conf_loaded(&db)) {
     		rt = seuser_read_conf_info(&db);
		if(rt != 0) {
			Tcl_AppendResult(interp, seuser_decode_read_conf_err(rt), (char *) NULL);
			return TCL_ERROR;
		}
	}
	
	se_mktmpfile();
	rt = seuser_open_user_db(&db, &policy);
	if(rt != 0) {
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "Problem opening policy and/or initializing the user database (make sure policy.conf is configured correctly.", (char *) NULL);
		return TCL_ERROR;
	}	
	db_init = TRUE;
	return TCL_OK;
}


/* frees the current user data base, and uninitialzes the tool configuration 
 * One can then safely call Seuser_InitUserdb again to re-initialze*/
int Seuser_CloseDatabase(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
	int rt;
	
	if(argc > 1) {
		Tcl_AppendResult(interp, "Seuser_CloseDatabase: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	
	rt = Apol_ClosePolicy( clientData, interp, argc, argv);
	if(rt != TCL_OK)
		return rt;
	
	if(db_init) {
		rt = seuser_free_db(&db, TRUE);
		if(rt != 0) {
			Tcl_AppendResult(interp, "Problem free user database", (char *) NULL);
			return TCL_ERROR;
		}
		db_init = FALSE;
	}	
	return TCL_OK;
}



/* get db list of users */
int Seuser_GetSeUserNames(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	user_item_t *ptr;
	char *name;

	Tcl_ResetResult(interp);
	if(argc > 1) {
		Tcl_AppendResult(interp, "Seuser_GetSeUserNames: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(!db_init) {
		Tcl_AppendResult(interp,"User database not initialized!", (char *) NULL);
		return TCL_ERROR;
	}
	
	for(ptr = db.users.head; get_user_name(ptr, &name) == 0; ptr = ptr->next) {
		Tcl_AppendElement(interp, name);
		free(name);
	}
	
	return TCL_OK;
}

/* Takes a user name, and determines whether the cooresponding SE Linux user
 * record as existing in the database is "valid".  If not valid, and error
 * with appropriate message will be returned.  An error is also returned
 * if the user name is not currently defined in the database
 */
int Seuser_IsUserValid(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
	int rt;
	char *user, tmpbuf[256];
	user_item_t *uitem;

	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(!db_init) {
		Tcl_AppendResult(interp,"User database not initialized!", (char *) NULL);
		return TCL_ERROR;
	}	
	assert(policy != NULL);
	
	user = argv[1];
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "User name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	rt = seuser_get_user_by_name(user, &uitem, &db);
	if(rt != 0) {
		Tcl_AppendResult(interp,"User does not exist in database!", (char *) NULL);
		return TCL_ERROR;
	}
	rt = seuser_is_proper_user_record(uitem, &db,policy);
	
	switch (rt) {
	case 0: 
		return TCL_OK;
		break;
	case 1: 
		sprintf(tmpbuf, "A user role is not a valid role");
		break;
	default:
		sprintf(tmpbuf, "Unknown error");
		break;
	}
	Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
	return TCL_ERROR;
}


/* remove a user from the database 
 * argv[1] username
 */
int Seuser_RemoveUser(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
	int rt;
	char tbuf[256];
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(!db_init) {
		Tcl_AppendResult(interp,"User database not initialized!", (char *) NULL);
		return TCL_ERROR;
	}
	
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "User name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	rt = seuser_remove_user(argv[1], &db);
	if(rt == 1) {
		sprintf(tbuf, "User (%s) does not exist in the database", argv[1]);
		Tcl_AppendResult(interp, tbuf, (char *) NULL);
		return TCL_ERROR;
	}
	else if(rt != 0) {
		Tcl_AppendResult(interp, "Error removing the user from the database");
		return TCL_ERROR;
	}		
	
	return TCL_OK;
}

/* re-make policy.conf file */
int Seuser_RemakePolicyConf(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
	int rt;
	if(argc != 1) {
		Tcl_AppendResult(interp, "Seuser_RemakePolicyConf: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
		
	/* Caller can see error by displaying the make output */
	rt = seuser_remake_policy_conf(tmpmakeout, &db);
	if(rt != 0)
		return TCL_ERROR;
	return TCL_OK;
}

/* re-install policy */
int Seuser_ReinstallPolicy(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
	int rt;
	if(argc != 1) {
		Tcl_AppendResult(interp, "Seuser_ReinstallPolicy: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}	
	/* Caller can see error by displaying the make output */
	rt = seuser_reinstall_policy(tmpmakeout, &db);
	if(rt != 0)
		return TCL_ERROR;
	return TCL_OK;
}

/* change an existing or add a new user 
 * argv[1]	command ("add" or "change")
 * argv[2]	username
 * argv[3]	roles (a TCL list string)
*** NOTE: The following ar deprecated and can be ommitted (they will be ignored) ***
 * argv[4]	default_login (bool) 	** deprecated & ignored **
 * argv[5]	login_role		** deprecated & ignored **
 * argv[6]	login_type		** deprecated & ignored **
 * argv[7]	default_cron (bool)	** deprecated & ignored **
 * argv[8]	cron_role		** deprecated & ignored **
 * argv[9]	cron_type		** deprecated & ignored **
 */
int Seuser_EditUser(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char **roles;
	char *cmd, *user, tmpbuf[512];
	int rt, num_roles;
	bool_t new_user;

	if(!(argc != 4 || argc != 10)) {
		Tcl_AppendResult(interp, "Seuser_EditUser: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(!db_init) {
		Tcl_AppendResult(interp,"User database not initialized!", (char *) NULL);
		return TCL_ERROR;
	}
	assert(policy != NULL);
	
	/* parse all the parameters */
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "Command name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	cmd = argv[1];
	if(strcmp(cmd, "add") == 0) {
		new_user = TRUE;
	}
	else if(strcmp(cmd, "change") == 0) {
		new_user = FALSE;
	}
	else {
		sprintf(tmpbuf, "Invalid command (%s), must be add or change", cmd);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;
	}
	
	if(!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "User name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	user = argv[2];
	if(user == NULL || (strcmp(user, "") == 0)) {
		Tcl_AppendResult(interp, "No user name provided", (char *) NULL);
		return TCL_ERROR;
	}
	
	/* Make sure the there is at least one role defined for the user. */
	rt = Tcl_SplitList(interp, argv[3], &num_roles, (CONST84 char***) &roles);
	if(rt != TCL_OK) {
		return rt;
	}
	if(num_roles < 1) {
		Tcl_AppendResult(interp, "Users must have at least one role defined for them.", (char *) NULL);
		Tcl_Free((char *)roles);
		return TCL_ERROR;
	}
	
	rt = seuser_add_change_user(new_user, user, roles, num_roles, &db, policy);
	Tcl_Free((char *)roles);
	switch (rt) {
	case 0: 
		return TCL_OK;
		break;
	case 1: 
		sprintf(tmpbuf, "Cannot add user %s, user already exists", user);
		break;
	case 2:
		sprintf(tmpbuf, "Cannot change user %s, user does not exist", user);
		break;
	case 3:
		sprintf(tmpbuf, "Bug: Improperly formed user record");
		break;
	case 4: 
		sprintf(tmpbuf, "An invalid role name was provided");
		break;
	case 5:
		sprintf(tmpbuf, "Bug: error inserting role into user record");
		break;
	default:
		sprintf(tmpbuf, "Error trying to add/update record");
		break;
	}
	Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
	return TCL_ERROR;
}

/* check for commit (write) access */
int Seuser_CheckCommitAccess(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt;
	
	if(argc != 1) {
		Tcl_AppendResult(interp, "ClientData: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}

	rt = seuser_check_commit_perm(&db);
	switch (rt) {
		case 0:	{
			return TCL_OK;
			break;
		}
		case 1: {
			Tcl_AppendResult(interp,"You do not have commit permission (users file)", (char *) NULL);
			return TCL_ERROR;
			break;
		}
		default: {
			Tcl_AppendResult(interp,"Unexepcted error checking commit permission", (char *) NULL);
			return TCL_ERROR;
			break;
		}
	}
	return TCL_OK;
}

/* commit changes to the user database */
int Seuser_Commit(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt;
	
	if(argc != 1) {
		Tcl_AppendResult(interp, "ClientData: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(!db_init) {
		Tcl_AppendResult(interp,"User database not initialized!", (char *) NULL);
		return TCL_ERROR;
	}
	
	rt = seuser_write_user_file(&db, policy);
	if(rt != 0) {
		Tcl_AppendResult(interp, "Problem writing the user file");
		return TCL_ERROR;
	}	
	return TCL_OK;
}

int Seuser_LabelHomeDirectory(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	int rt;
	
	if(argc != 2) {
		Tcl_AppendResult(interp, "Seuser_Exit: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "User name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	rt = seuser_label_home_dir(argv[1], &db, policy, tmpmakeout);
	if (rt != 0) {
		Tcl_AppendResult(interp, seuser_decode_labeling_err(rt), (char *) NULL);
		return TCL_ERROR;
	}
	return TCL_OK;
}

/* get roles for a user *
 * argv[1] user name
 */
int Seuser_UserRoles(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	char tmpbuf[256], *name;
	user_item_t *user;
	ta_item_t *ptr;
	int rt;
	
	Tcl_ResetResult(interp);
	if(argc != 2) {
		Tcl_AppendResult(interp, "Seuser_UserRoles: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(!db_init) {
		Tcl_AppendResult(interp,"User database not initialized!", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "User name string too large", (char *) NULL);
		return TCL_ERROR;
	}
	rt = seuser_get_user_by_name(argv[1], &user, &db);
	if(rt != 0) {
		sprintf(tmpbuf, "Invalid user name (%s)", argv[1]);
		Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
		return TCL_ERROR;		
	}
	
	for(ptr = user->roles; ptr != NULL; ptr = ptr->next) {
		assert(ptr->type == IDX_ROLE);
		rt = get_role_name(ptr->idx, &name, policy);
		if(rt != 0) {
			Tcl_ResetResult(interp);
			Tcl_AppendResult(interp, "error getting role name", (char *) NULL);			
			return TCL_ERROR;
		}
		Tcl_AppendElement(interp, name);
		free(name);
	}
		
	return TCL_OK;
}

/* get default context for a user *
 */
int Seuser_UserContext(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[])
{
	Tcl_AppendResult(interp, "Function (and old style login context) no longer supported", (char *) NULL);
	return TCL_ERROR;

}


/* get the list of system-defined users */
/* argv[1] 	Indicate if user type is wanted (opt bool)
 *
 * if argv[1] != 0, then the resturn result will be list where there
 * are two elements for each user (username type).  The type will be a string
 * with one of the SYSUSER_TYPE values from the header file.
 *
 * NOTE: if user type info is wanted then user_u and system_u will also be
 * included as system users if they exist in the policy.
 */
int Seuser_GetSysUsers(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
   	struct passwd *line = (struct passwd *)malloc(sizeof(struct passwd));
   	bool_t include_type;
   	char *type;

	Tcl_ResetResult(interp);
	if(argc > 2) {
		Tcl_AppendResult(interp, "Seuser_GetSysUsers: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if(argc == 2) {
		if(!is_valid_str_sz(argv[1])) {
			Tcl_AppendResult(interp, "Boolean string too large", (char *) NULL);
			return TCL_ERROR;
		}
		include_type = getbool(argv[1]);
	}
	else 
		include_type = FALSE;
		
	while ( (line = getpwent()) != NULL) {
     		Tcl_AppendElement(interp, line->pw_name);
     		if(include_type) {
     			type = determine_user_type(line->pw_name);
     			Tcl_AppendElement(interp, type);
     			free(type);
     		}
   	}
   	free(line);
   	endpwent();
   	
   	/* now add the special users if they exist and type is requested */
	if(include_type) {
		user_item_t *uitem;
		int rt;
		rt = seuser_get_user_by_name(SPECIAL_USER_SYSTEM, &uitem, &db);
		if(rt == 0) {
			Tcl_AppendElement(interp, SPECIAL_USER_SYSTEM);
			Tcl_AppendElement(interp, SYSUSER_SPECIAL_STR);
		}
		rt = seuser_get_user_by_name(SPECIAL_USER_USER, &uitem, &db);
		if(rt == 0) {
			Tcl_AppendElement(interp, SPECIAL_USER_USER);
			Tcl_AppendElement(interp, SYSUSER_SPECIAL_STR);
		}
	}
	return TCL_OK;
}


/* get the list of system-defined groups */
int Seuser_GetSysGroups(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[])
{
   	struct group *line = (struct group *)malloc(sizeof(struct group));

	Tcl_ResetResult(interp);
	if(argc != 1) {
		Tcl_AppendResult(interp, "Seuser_GetSysGroups: wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	while ( (line = getgrent()) != NULL) {
     		Tcl_AppendElement(interp, line->gr_name);
   	}
   	free(line);
   	endgrent();

	return TCL_OK;
}


/* Package initialization */
int Seuser_Init(Tcl_Interp *interp) 
{
	Tcl_CreateCommand(interp, "seuser_InitUserdb", (Tcl_CmdProc *) Seuser_InitUserdb, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_GetSysUsers", (Tcl_CmdProc *) Seuser_GetSysUsers, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_GetSysGroups", (Tcl_CmdProc *) Seuser_GetSysGroups, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_GetSeUserNames", (Tcl_CmdProc *) Seuser_GetSeUserNames, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_UserRoles", (Tcl_CmdProc *) Seuser_UserRoles, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_UserContext", (Tcl_CmdProc *) Seuser_UserContext, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_Commit", (Tcl_CmdProc *) Seuser_Commit, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_RemoveUser", (Tcl_CmdProc *) Seuser_RemoveUser, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_CloseDatabase", (Tcl_CmdProc *) Seuser_CloseDatabase, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_EditUser", (Tcl_CmdProc *) Seuser_EditUser, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_RemakePolicyConf", (Tcl_CmdProc *) Seuser_RemakePolicyConf, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_ReinstallPolicy", (Tcl_CmdProc *) Seuser_ReinstallPolicy, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_IsUserValid", (Tcl_CmdProc *) Seuser_IsUserValid, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_GetVersion", (Tcl_CmdProc *) Seuser_GetVersion, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "euser_Get_Login_Version", (Tcl_CmdProc *) Seuser_Get_Login_Version, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_GetTmpMakeFileName", (Tcl_CmdProc *) Seuser_GetTmpMakeFileName, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_Use_Old_Login_Contexts", (Tcl_CmdProc *) Seuser_Use_Old_Login_Contexts, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_Exit", (Tcl_CmdProc *) Seuser_Exit, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_CheckCommitAccess", (Tcl_CmdProc *) Seuser_CheckCommitAccess, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateCommand(interp, "seuser_LabelHomeDirectory", (Tcl_CmdProc *) Seuser_LabelHomeDirectory, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	
	Tcl_PkgProvide(interp, "seuser", (char*)libseuser_get_version());

	return TCL_OK;
}
