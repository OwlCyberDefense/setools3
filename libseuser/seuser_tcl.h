 /* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* seuser_tcl.h
 *
 */
 
#ifndef _SEUSER_TCL_H_
#define _SEUSER_TCL_H_

#include "seuser_db.h"
#include "../libapol/policy.h"


#define NEW_LOGIN_STR	"System using NEW stlye login contexts"


/* Types strings for system users */
#define SYSUSER_DEFINED_STR	"defined"	/* user defined to policy */
#define SYSUSER_GENERIC_STR	"generic"	/* not defined and user_u exists */
#define SYSUSER_UNDEFINED_STR	"undefined"	/* not defined and user_u does not exist */
#define SYSUSER_SPECIAL_STR	"special"	/* system_u or user_u */
#define SYSUSER_MAX_STR_SZ	10

/* Special user accounts */
#define SPECIAL_USER_SYSTEM	"system_u"
#define SPECIAL_USER_USER	"user_u"


/* The tcl functions to support the GUI using TK */

int Seuser_Init(Tcl_Interp *interp);

int Seuser_InitUserdb(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Seuser_GetSysUsers(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Seuser_GetSysGroups(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Seuser_EditUser(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Seuser_Exit(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Seuser_CloseDatabase(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Seuser_IsUserValid(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Seuser_RemoveUser(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Seuser_RemakePolicyConf(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Seuser_ReinstallPolicy(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Seuser_CheckCommitAccess(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Seuser_UserRoles(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Seuser_Commit(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Seuser_Get_System_Version(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Seuser_GetVersion(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Seuser_LabelHomeDirectory(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);


#endif


