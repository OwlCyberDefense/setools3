/* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 */

/* apol_tcl.h
 *
 */
 
#ifndef _APOLICY_TCL_H_
#define _APOLICY_TCL_H_
#include <tcl.h>
#include <tk.h>

/* The tcl functions to support the GUI using TK */
int Apol_Init(Tcl_Interp *interp);

/* The following are exposed for C wrappers.  They wouldn't be used directly by TCL */
int Apol_GetScriptDir(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetHelpDir(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_OpenPolicy(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_ClosePolicy(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetVersion(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetStats(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetNames(ClientData clientData, Tcl_Interp * interp, int argc, char *argv[]);
int Apol_GetTErules(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_SearchTErules(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetSingleTypeInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetTypeInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetSingleRoleInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetRolesByType(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetRoleRules(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_UserRoles(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_RoleTypes(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetAttribTypesList(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_DomainTransitionAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_DirectInformationFlowAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_LoadPermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_SavePermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_UpdatePermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetPermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_IsPermMapLoaded(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetDefault_PermMap(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_TransitiveFlowAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_TransitiveFindPathsStart(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_TransitiveFindPathsNext(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_TransitiveFindPathsGetResults(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_TransitiveFindPathsAbort(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetPolicyVersionString(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetPolicyVersionNumber(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_SearchInitialSIDs(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_GetInitialSIDInfo(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_Cond_Bool_SetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_Cond_Bool_GetBoolValue(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_TypesRelationshipAnalysis(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);
int Apol_FlowAssertExecute (ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]);

#endif /*_APOLICY_TCL_H_*/

