/* Copyright (C) 2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 */

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
static void apol_search_fc_index_append_results(sefs_search_ret_t *key, Tcl_Interp *interp) 
{
	sefs_search_ret_t *curr = key;
	
	/* walk the linked list */
	while (curr) {
		if (curr->path)
			Tcl_AppendElement(interp, curr->path);
		if (curr->context)
			Tcl_AppendElement(interp, curr->context);
		if (curr->object_class)
			Tcl_AppendElement(interp, curr->object_class);
		curr = curr->next;
	}
}
#endif


/*
 * This function expects a file context index to be loaded into memory.
 * Arguments:
 *	argv[1] - use_type [bool]
 * 	argv[2] - type [TCL list of strings]
 * 	argv[3] - use_user [bool]
 *	argv[4] - user [TCL list of strings]
 * 	argv[5] - use_class [bool]
 * 	argv[6] - object class [TCL list of strings]
 * 	argv[7] - use_path [bool]
 * 	argv[8] - path [Tcl list of strings]
 * 	argv[9] - use regular expressions for user
 * 	argv[10] - use regular expressions for type
 *	argv[11] - use regular expressions for path
 */
static int Apol_Search_FC_Index_DB(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{	
	if(argc != 12) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
#ifndef LIBSEFS
	Tcl_AppendResult(interp, "You need to build apol with libsefs to use this feature!", (char *) NULL);
	return TCL_ERROR;
#else		
	int rt;
	int num_types, num_users, num_classes, num_paths;
	sefs_search_keys_t search_keys;
	CONST char **object_classes, **types, **users, **paths;
	
	if (fsdata == NULL) {
		Tcl_AppendResult(interp, "No Index File Loaded!", (char *) NULL);
		return TCL_ERROR;
	}
	object_classes = types = users = paths = NULL;

	search_keys.user = NULL;
	search_keys.path = NULL;
	search_keys.type = NULL;
	search_keys.object_class = NULL;
	search_keys.num_type = 0;
	search_keys.num_user = 0;
	search_keys.num_object_class = 0;
	search_keys.num_path = 0;
	
	if (getbool(argv[1])) {
		rt = Tcl_SplitList(interp, argv[2], &num_types, &types);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		
		if (num_types < 1) {
			Tcl_AppendResult(interp, "Must provide at least 1 type.", (char *) NULL);
			goto err;
		}
		search_keys.num_type = num_types;
		search_keys.type = types;
	}
	if (getbool(argv[3])) {
		rt = Tcl_SplitList(interp, argv[4], &num_users, &users);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		
		if (num_users < 1) {
			Tcl_AppendResult(interp, "Must provide at least 1 user.", (char *) NULL);
			goto err;
		}
		search_keys.num_user = num_users;
		search_keys.user = users;
	}
	if (getbool(argv[5])) {
		rt = Tcl_SplitList(interp, argv[6], &num_classes, &object_classes);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		
		if (num_classes < 1) {
			Tcl_AppendResult(interp, "Must provide at least 1 object class.", (char *) NULL);
			goto err;
		}
		search_keys.num_object_class = num_classes;
		search_keys.object_class = object_classes;
	}
	if (getbool(argv[7])) {
		rt = Tcl_SplitList(interp, argv[8], &num_paths, &paths);
		if (rt != TCL_OK) {
			Tcl_AppendResult(interp, "Error splitting TCL list.", (char *) NULL);
			goto err;
		}
		
		if (num_paths < 1) {
			Tcl_AppendResult(interp, "Must provide at least 1 path.", (char *) NULL);
			goto err;
		}
		search_keys.num_path = num_paths;
		search_keys.path = paths;
	}

	rt = Tcl_GetInt(interp, argv[9], &search_keys.do_user_regEx);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp, "argv[9] apparently is not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	rt = Tcl_GetInt(interp, argv[10], &search_keys.do_type_regEx);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp, "argv[10] apparently is not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	rt = Tcl_GetInt(interp, argv[11], &search_keys.do_path_regEx);
	if (rt == TCL_ERROR) {
		Tcl_AppendResult(interp, "argv[11] apparently is not an integer", (char *) NULL);
		return TCL_ERROR;
	}
	
	if (!search_keys.type && !search_keys.user && !search_keys.object_class && !search_keys.path) {
		Tcl_AppendResult(interp, "You must specify search criteria!", (char *) NULL);
		goto err;
	}
	
	rt = sefs_filesystem_db_search(fsdata, &search_keys);
	if (rt != 0) {
		Tcl_AppendResult(interp, "Search failed\n", (char *) NULL);
		goto err;
	}
	apol_search_fc_index_append_results(search_keys.search_ret, interp);
	sefs_search_keys_ret_destroy(search_keys.search_ret);
	if (types) Tcl_Free((char *) types);
	if (users) Tcl_Free((char *) users);
	if (object_classes) Tcl_Free((char *) object_classes);
	if (paths) Tcl_Free((char *) paths);
	return TCL_OK;
err:
	if (types) Tcl_Free((char *) types);
	if (users) Tcl_Free((char *) users);
	if (object_classes) Tcl_Free((char *) object_classes);
	if (paths) Tcl_Free((char *) paths);
	return TCL_ERROR;
#endif
}

/* 
 * No arguments, however, this function expects a file context index to be loaded into memory.
 */
static int Apol_FC_Index_DB_Get_Items(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	if(argc != 2) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
#ifndef LIBSEFS
	Tcl_AppendResult(interp, "You need to build apol with libsefs!", (char *) NULL);
	return TCL_ERROR;
#else		
	int list_sz = 0, i, request_type;
	char **list_ret = NULL;
	
	if (fsdata == NULL) {
		Tcl_AppendResult(interp, "No Index File Loaded!", (char *) NULL);
		return TCL_ERROR;
	}
	
	if(strcmp("types", argv[1]) == 0) {
		request_type = SEFS_TYPES;
	} else if(strcmp("users", argv[1]) == 0) {
		request_type = SEFS_USERS;
	} else if(strcmp("classes", argv[1]) == 0) {
		request_type = SEFS_OBJECTCLASS;
	}  else {
		Tcl_AppendResult(interp, "Invalid option: ", argv[1], (char *) NULL);
		return TCL_ERROR;
	}
	
 	if ((list_ret = sefs_filesystem_db_get_known(fsdata, &list_sz, request_type)) != NULL) {
		for (i = 0; i < list_sz; i++){
			Tcl_AppendElement(interp, list_ret[i]);
		}
		sefs_double_array_destroy(list_ret, list_sz);
	}

	return TCL_OK;
#endif
}

static int Apol_IsLibsefs_BuiltIn(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	char tbuf[64];
	
	if(argc != 1) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (is_libsefs_builtin) 
		sprintf(tbuf, "%d", 1);
	else 
		sprintf(tbuf, "%d", 0);
	Tcl_AppendElement(interp, tbuf);
	return TCL_OK;
}


int ap_tcl_fc_init(Tcl_Interp *interp) {
	Tcl_CreateCommand(interp, "apol_Create_FC_Index_File", Apol_Create_FC_Index_File, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_Load_FC_Index_File", Apol_Load_FC_Index_File, NULL, NULL);
        Tcl_CreateCommand(interp, "apol_Close_FC_Index_DB", Apol_Close_FC_Index_DB, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_Search_FC_Index_DB", Apol_Search_FC_Index_DB, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_FC_Index_DB_Get_Items", Apol_FC_Index_DB_Get_Items, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsLibsefs_BuiltIn", Apol_IsLibsefs_BuiltIn, NULL, NULL);

        return TCL_OK;
}
