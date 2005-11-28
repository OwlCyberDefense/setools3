 /* Copyright (C) 2003-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* tcl_render.c */

/* This file takes various policy stuff and returns formatted Tcl
   lists, suitable for displaying results in Apol. */

#include "policy.h"
#include "render.h"

#include <tcl.h>

static int tcl_render_ta_item_list(Tcl_Interp *interp, Tcl_Obj *dest_listobj, ta_item_t *name, policy_t *policy) {
        int retv;
        char *tmp_name;
        Tcl_Obj *type_obj;
	while (name != NULL) {
		retv = get_ta_item_name(name, &tmp_name, policy);
		if (retv) {
                        Tcl_SetResult(interp, "Illegal type name in range transition.", TCL_STATIC);
                        return TCL_ERROR;
		}
                type_obj = Tcl_NewStringObj(NULL, 0);
                Tcl_AppendStringsToObj(type_obj,
                                       (name->type & IDX_SUBTRACT ? "-" : ""),
                                       tmp_name,
                                       NULL);
                free(tmp_name);
                if (Tcl_ListObjAppendElement(interp, dest_listobj, type_obj) == TCL_ERROR) {
                        return TCL_ERROR;
                }
                name = name->next;
	}
        return TCL_OK;
}

int ap_tcl_render_rangetrans(Tcl_Interp *interp, bool_t addlineno, int idx, policy_t *policy)
{
        Tcl_Obj *result_obj;
        Tcl_Obj *linenum_obj, *source_obj, *target_obj, *type_obj, *range_obj;
        char *rendered_range;

	if (!policy || idx < 0 || idx >= policy->num_rangetrans) {
                Tcl_SetResult(interp, "Illegal range transition index.", TCL_STATIC);
                return TCL_ERROR;
        }

	if (addlineno) {
                linenum_obj = Tcl_NewLongObj((long) policy->rangetrans[idx].lineno);
        }
        else {
                linenum_obj = Tcl_NewStringObj(NULL, 0);
        }

	/* render source(s) */
        source_obj = Tcl_NewListObj(0, NULL);
	if (policy->rangetrans[idx].flags & AVFLAG_SRC_STAR) {
		type_obj = Tcl_NewStringObj("*", -1);
	} else if (policy->rangetrans[idx].flags & AVFLAG_SRC_TILDA) {
		type_obj = Tcl_NewStringObj("~", -1);
	}
        else {
                type_obj = Tcl_NewStringObj(NULL, 0);   
        }
        if (Tcl_ListObjAppendElement(interp, source_obj, type_obj) == TCL_ERROR) {
                return TCL_ERROR;
        }
        if (tcl_render_ta_item_list(interp, source_obj, policy->rangetrans[idx].src_types, policy) == TCL_ERROR) {
                return TCL_ERROR;
        }

	/* render target(s) */
        target_obj = Tcl_NewListObj(0, NULL);
	if (policy->rangetrans[idx].flags & AVFLAG_TGT_STAR) {
		type_obj = Tcl_NewStringObj("*", -1);
	} else if (policy->rangetrans[idx].flags & AVFLAG_TGT_TILDA) {
		type_obj = Tcl_NewStringObj("~", -1);
	}
        else {
                type_obj = Tcl_NewStringObj(NULL, 0);   
        }
        if (Tcl_ListObjAppendElement(interp, target_obj, type_obj) == TCL_ERROR) {
                return TCL_ERROR;
        }
        if (tcl_render_ta_item_list(interp, target_obj, policy->rangetrans[idx].tgt_types, policy) == TCL_ERROR) {
                return TCL_ERROR;
        }

	/* render range */
        rendered_range = re_render_mls_range(policy->rangetrans[idx].range, policy);
        if (rendered_range == NULL) {
                Tcl_SetResult(interp, "Illegal range specification.", TCL_STATIC);
                return TCL_ERROR;
        }
        range_obj = Tcl_NewStringObj(rendered_range, -1);
        free(rendered_range);

        result_obj = Tcl_NewListObj(0, NULL);
        if (Tcl_ListObjAppendElement(interp, result_obj, linenum_obj) == TCL_ERROR ||
            Tcl_ListObjAppendElement(interp, result_obj, source_obj) == TCL_ERROR ||
            Tcl_ListObjAppendElement(interp, result_obj, target_obj) == TCL_ERROR ||
            Tcl_ListObjAppendElement(interp, result_obj, range_obj) == TCL_ERROR) {
                return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, result_obj);
        return TCL_OK;
}
