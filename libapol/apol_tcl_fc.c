/* Copyright (C) 2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 */

#include <config.h>
#include <tcl.h>

#include "apol_tcl_other.h"

#ifdef LIBSEFS
#include "../libsefs/fsdata.h"
sefs_filesystem_db_t *fsdata = NULL; /* local global for file context DB */
static bool_t is_libsefs_builtin = TRUE;
#else
static bool_t is_libsefs_builtin = FALSE;
#endif


/* 
 * argv[1] - file name to save 
 * argv[2] - directory to start scanning
 */
static int Apol_Create_FC_Index_File(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{	
	if(argc != 3) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}	
#ifndef LIBSEFS
	Tcl_AppendResult(interp, "You need to build apol with libsefs to use this feature!", (char *) NULL);
	return TCL_ERROR;
#else	
	sefs_filesystem_db_t fsdata_local;
	int rt;
	
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "File string too large", (char *) NULL);
		return TCL_ERROR;
	}
	if(!is_valid_str_sz(argv[2])) {
		Tcl_AppendResult(interp, "Directory string too large", (char *) NULL);
		return TCL_ERROR;
	}
	
	fsdata_local.dbh = NULL;
	fsdata_local.fsdh = NULL;
	rt = sefs_filesystem_db_populate(&fsdata_local, (char *) argv[2]);
 	if (rt == -1) {
		Tcl_AppendResult(interp, "Error populating database.\n", (char *) NULL);
		return TCL_ERROR;
	} else if (rt == SEFS_NOT_A_DIR_ERROR) {
		Tcl_AppendResult(interp, "The pathname (", argv[2], ") is not a directory.\n", (char *) NULL);
		return TCL_ERROR;
	} else if (rt == SEFS_DIR_ACCESS_ERROR) {
		Tcl_AppendResult(interp, "You do not have permission to read the directory ", argv[2], ".\n", (char *) NULL);
		return TCL_ERROR;
	}
	if (sefs_filesystem_db_save(&fsdata_local, (char *) argv[1]) != 0) {
		/* Make sure the database is closed and memory freed. */
		sefs_filesystem_db_close(&fsdata_local);
		Tcl_AppendResult(interp, "Error creating index file\n", (char *) NULL);
		return TCL_ERROR;
	}
	sefs_filesystem_db_close(&fsdata_local);
	
	return TCL_OK;
#endif
}

/* 
 * argv[1] - index file to load
 */
static int Apol_Load_FC_Index_File(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
#ifndef LIBSEFS
	Tcl_AppendResult(interp, "You need to build apol with libsefs to use this feature!", (char *) NULL);
	return TCL_ERROR;
#else		
	if(!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "File string too large", (char *) NULL);
		return TCL_ERROR;
	}
	if (fsdata != NULL) {
		sefs_filesystem_db_close(fsdata);
	} else {
		fsdata = (sefs_filesystem_db_t*)malloc(sizeof(sefs_filesystem_db_t));
		if (fsdata == NULL) {
			Tcl_AppendResult(interp, "Out of memory\n", (char *) NULL);
			return TCL_ERROR;
		}
		memset(fsdata, 0, sizeof(sefs_filesystem_db_t));
	}

 	if (sefs_filesystem_db_load(fsdata, (char *) argv[1]) == -1) {
 		Tcl_AppendResult(interp, "Loading of database failed.\n", (char *) NULL);
		return TCL_ERROR;
	}
	
	return TCL_OK;
#endif
}

/* 
 * No arguments.
 */
static int Apol_Close_FC_Index_DB(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
#ifdef LIBSEFS
	if (fsdata != NULL) {
 		sefs_filesystem_db_close(fsdata);
 		free(fsdata);
 		fsdata = NULL;
	}	
#endif
	return TCL_OK;
}

#ifdef LIBSEFS
static int append_search_fc_index_to_list(Tcl_Interp *interp, sefs_search_ret_t *key, Tcl_Obj *result_list)
{
	sefs_search_ret_t *curr = key;
	
	/* walk the linked list */
	while (curr) {
		Tcl_Obj *fscon[3], *fscon_list;
		if (curr->context) {
			fscon[0] = Tcl_NewStringObj(curr->context, -1);
		}
		else {
			fscon[0] = Tcl_NewStringObj("", -1);
		}
		if (curr->object_class) {
			fscon[1] = Tcl_NewStringObj(curr->object_class, -1);
		}
		else {
			fscon[1] = Tcl_NewStringObj("", -1);
		}
		if (curr->path) {
			fscon[2] = Tcl_NewStringObj(curr->path, -1);
		}
		else {
			fscon[2] = Tcl_NewStringObj("", -1);
		}
		fscon_list = Tcl_NewListObj(3, fscon);
		if (Tcl_ListObjAppendElement(interp, result_list, fscon_list) == TCL_ERROR) {
			return TCL_ERROR;
		}
		curr = curr->next;
	}
	return TCL_OK;
}
#endif


/**
 * Assuming that the file contexts database has already been open,
 * return a list of file contexts (3-ple of context, object class,
 * path) that match the given criteria.
 *	argv[1] - list of user strings
 *	argv[2] - list of type strings
 *	argv[3] - list of object class strings
 *	argv[4] - list of MLS ranges
 *	argv[5] - list of path strings
 *	argv[6] - use regular expressions for user
 *	argv[7] - use regular expressions for type
 *	argv[8] - use regular expressions for MLS ranges
 *	argv[9] - use regular expressions for path
 */
static int Apol_Search_FC_Index_DB(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{	
#ifndef LIBSEFS
	Tcl_SetResult(interp, "You need to build apol with libsefs to use this feature!", TCL_STATIC);
	return TCL_ERROR;
#else		
	sefs_search_keys_t search_keys;
	CONST char **object_classes = NULL, **types = NULL, **users = NULL,
	    **ranges = NULL, **paths = NULL;
	int retval = TCL_ERROR;
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);

	memset(&search_keys, 0, sizeof(search_keys));
	if (argc != 10) {
		Tcl_SetResult(interp, "Need a list of users, list of types, list of object classes, list of ranges, list of paths, user_regex, type_regex, range_regex, and path_regex", TCL_STATIC);
		goto cleanup;
	}
	
	if (fsdata == NULL) {
		Tcl_SetResult(interp, "No Index File Loaded!", TCL_STATIC);
		goto cleanup;
	}

	if (Tcl_SplitList(interp, argv[1], &search_keys.num_user, &users) == TCL_ERROR ||
	    Tcl_SplitList(interp, argv[2], &search_keys.num_type, &types) == TCL_ERROR ||
	    Tcl_SplitList(interp, argv[3], &search_keys.num_object_class, &object_classes) == TCL_ERROR ||
	    Tcl_SplitList(interp, argv[4], &search_keys.num_range, &ranges) == TCL_ERROR ||
	    Tcl_SplitList(interp, argv[5], &search_keys.num_path, &paths) == TCL_ERROR) {
		goto cleanup;
	}
	search_keys.user = users;
	search_keys.type = types;
	search_keys.object_class = object_classes;
	search_keys.range = ranges;
	search_keys.path = paths;
	if (Tcl_GetInt(interp, argv[6], &search_keys.do_user_regEx) == TCL_ERROR ||
	    Tcl_GetInt(interp, argv[7], &search_keys.do_type_regEx) == TCL_ERROR ||
	    Tcl_GetInt(interp, argv[8], &search_keys.do_range_regEx) == TCL_ERROR ||
	    Tcl_GetInt(interp, argv[9], &search_keys.do_path_regEx) == TCL_ERROR) {
		goto cleanup;
	}

	if (sefs_filesystem_db_search(fsdata, &search_keys) != 0) {
		Tcl_SetResult(interp, "FC search failed.", TCL_STATIC);
		goto cleanup;
	}
	if (append_search_fc_index_to_list(interp, search_keys.search_ret, result_obj) == TCL_ERROR) {
		goto cleanup;
	}

	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	sefs_search_keys_ret_destroy(search_keys.search_ret);
	if (users) Tcl_Free((char *) users);
	if (types) Tcl_Free((char *) types);
	if (object_classes) Tcl_Free((char *) object_classes);
	if (ranges) Tcl_Free((char *) ranges);
	if (paths) Tcl_Free((char *) paths);
	return retval;
#endif
}

/**
 * Assuming that the file contexts database has already been open,
 * return a list of item names for a particular table.	Valid table
 * names are: "types", "users", "classes", and "ranges".
 */
static int Apol_FC_Index_DB_Get_Items(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	if (argc != 2) {
		Tcl_SetResult(interp, "Need one of \"types\", \"users\", \"classes\", or \"ranges\".", TCL_STATIC);
		return TCL_ERROR;
	}
#ifndef LIBSEFS
	Tcl_SetResult(interp, "You need to build apol with libsefs!", TCL_STATIC);
	return TCL_ERROR;
#else		
	int list_sz = 0, i, request_type;
	char **list_ret = NULL;
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);
	
	if (fsdata == NULL) {
		Tcl_SetResult(interp, "No Index File Loaded!", TCL_STATIC);
		return TCL_ERROR;
	}

	if (strcmp("types", argv[1]) == 0) {
		request_type = SEFS_TYPES;
	}
	else if (strcmp("users", argv[1]) == 0) {
		request_type = SEFS_USERS;
	}
	else if (strcmp("classes", argv[1]) == 0) {
		request_type = SEFS_OBJECTCLASS;
	}
	else if (strcmp("ranges", argv[1]) == 0) {
		int retval = sefs_filesystem_db_is_mls(fsdata);
		if (retval < 0) {
			Tcl_SetResult(interp, "Error determining if database is MLS.", TCL_STATIC);
			return TCL_ERROR;
		}
		else if (retval == 0) {
			/* database does not have MLS, so nothing to return */
			Tcl_SetObjResult(interp, result_obj);
			return TCL_OK;
		}
		request_type = SEFS_RANGES;
	} else {
		Tcl_SetResult(interp, "Need an item type.", TCL_STATIC);
		return TCL_ERROR;
	}

	if ((list_ret = sefs_filesystem_db_get_known(fsdata, &list_sz, request_type)) == NULL) {
		Tcl_SetResult(interp, "Error in getting items.", TCL_STATIC);
		return TCL_ERROR;
	}
	for (i = 0; i < list_sz; i++){
		Tcl_Obj *s = Tcl_NewStringObj(list_ret[i], -1);
		if (Tcl_ListObjAppendElement(interp, result_obj, s) == TCL_ERROR) {
			sefs_double_array_destroy(list_ret, list_sz);
			return TCL_ERROR;
		}
	}
	sefs_double_array_destroy(list_ret, list_sz);
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
#endif
}

static int Apol_FC_Is_MLS(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
#ifndef LIBSEFS
	Tcl_SetResult(interp, "You need to build apol with libsefs!", TCL_STATIC);
	return TCL_ERROR;
#else
	int retval;
	Tcl_Obj *result_obj;

	if (fsdata == NULL) {
		Tcl_SetResult(interp, "No Index File Loaded!", TCL_STATIC);
		return TCL_ERROR;
	}
	retval = sefs_filesystem_db_is_mls(fsdata);
	if (retval < 0) {
		Tcl_SetResult(interp, "Error determining if database is MLS.", TCL_STATIC);
		return TCL_ERROR;
	}
	result_obj = Tcl_NewIntObj(retval);
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
#endif
}

static int Apol_IsLibsefs_BuiltIn(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj;
	if (is_libsefs_builtin) {
		result_obj = Tcl_NewIntObj(1);
	}
	else {
		result_obj = Tcl_NewIntObj(0);
	}
	Tcl_SetObjResult(interp, result_obj);
	return TCL_OK;
}

int ap_tcl_fc_init(Tcl_Interp *interp) {
	Tcl_CreateCommand(interp, "apol_Create_FC_Index_File", Apol_Create_FC_Index_File, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_Load_FC_Index_File", Apol_Load_FC_Index_File, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_Close_FC_Index_DB", Apol_Close_FC_Index_DB, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_Search_FC_Index_DB", Apol_Search_FC_Index_DB, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_FC_Index_DB_Get_Items", Apol_FC_Index_DB_Get_Items, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_FC_Is_MLS", Apol_FC_Is_MLS, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsLibsefs_BuiltIn", Apol_IsLibsefs_BuiltIn, NULL, NULL);

	return TCL_OK;
}
