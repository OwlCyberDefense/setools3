 /* Copyright (C) 2003-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* tcl_render.c */

/* This file takes various policy stuff and returns formatted Tcl
   lists, suitable for displaying results in Apol. */

#include "policy.h"
#include "render.h"

#include "apol_tcl_other.h"

#include <tcl.h>

#include <assert.h>

int ap_tcl_append_type_str(bool_t do_attribs, bool_t do_aliases, bool_t newline, int idx, 
	policy_t *policy, Tcl_DString *buf)
{
	int j;
	char tbuf[APOL_STR_SZ + 64];
	if(idx >= policy->num_types || buf == NULL) {
		return -1;
	}

	Tcl_DStringAppend(buf, policy->types[idx].name, -1);
	
	if(do_aliases) {
		if(policy->types[idx].aliases != NULL) {
			name_item_t *ptr;
			Tcl_DStringAppend(buf, " alias {", -1);
			for(ptr = policy->types[idx].aliases; ptr != NULL; ptr = ptr->next) {
				Tcl_DStringAppend(buf, ptr->name, -1);
				if(ptr->next != NULL)
					Tcl_DStringAppend(buf, " ", -1);
			}
			Tcl_DStringAppend(buf, "} ", -1);
		}
	}
	
	if(do_attribs) {
		sprintf(tbuf, " (%d attributes)\n", policy->types[idx].num_attribs);
		Tcl_DStringAppend(buf, tbuf, -1);
		for(j = 0; j < policy->types[idx].num_attribs; j++) {
			sprintf(tbuf, "\t%s\n", policy->attribs[policy->types[idx].attribs[j]].name);
			Tcl_DStringAppend(buf, tbuf, -1);
		}
	}
	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);	

	return 0;
}


int ap_tcl_append_attrib_str(bool_t do_types, bool_t do_type_attribs, bool_t use_aliases, 
	bool_t newline, bool_t upper, int idx, policy_t *policy, Tcl_DString *buf)
{
	int j, k;
	char tbuf[APOL_STR_SZ+64];

	if(idx >= policy->num_attribs || buf == NULL) {
		return -1;
	}	

	if(upper) {
		Tcl_DStringAppend(buf, uppercase(policy->attribs[idx].name, tbuf), -1);
	}
	else
		Tcl_DStringAppend(buf, policy->attribs[idx].name, -1);
		
	if(do_types) {
		sprintf(tbuf, " (%d types)\n", policy->attribs[idx].num);
		Tcl_DStringAppend(buf, tbuf, -1);
		for(j = 0; j < policy->attribs[idx].num; j++) {
			Tcl_DStringAppend(buf, "\t", -1);
			Tcl_DStringAppend(buf, policy->types[policy->attribs[idx].a[j]].name, -1);
			/* aliases */
			if(use_aliases && policy->types[policy->attribs[idx].a[j]].aliases != NULL) {
				name_item_t *ptr;
				Tcl_DStringAppend(buf, ":", -1);
				for(ptr = policy->types[policy->attribs[idx].a[j]].aliases; ptr != NULL; ptr = ptr->next) {
					Tcl_DStringAppend(buf, " ", -1);
					Tcl_DStringAppend(buf, ptr->name, -1);
					if(ptr->next != NULL)
						Tcl_DStringAppend(buf, ",", -1);
				}
			}			
			if(do_type_attribs) {
				Tcl_DStringAppend(buf, " { ", -1);
				for(k = 0; k < policy->types[policy->attribs[idx].a[j]].num_attribs; k++) {
					if(strcmp(policy->attribs[idx].name, policy->attribs[policy->types[policy->attribs[idx].a[j]].attribs[k]].name) != 0)
						Tcl_DStringAppend(buf, policy->attribs[policy->types[policy->attribs[idx].a[j]].attribs[k]].name, -1);
						Tcl_DStringAppend(buf, " ", -1);
				}
				Tcl_DStringAppend(buf, "}", -1);
			}
			Tcl_DStringAppend(buf, "\n", -1);
		}
	}
	if(newline)
		Tcl_DStringAppend(buf, "\n", -1);		

	return 0;
}

static int Apol_RenderLevel(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        ap_mls_level_t level;
        int retval;
        char *rendered_level;

        if (argc != 2) {
                Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
                return TCL_ERROR;
        }
        retval = ap_tcl_level_string_to_level(interp, argv[1], &level);
        if (retval == -1) {
                return TCL_ERROR;
        }
        else if (retval == 1) {
                return TCL_OK;                     /* no render possible */
        }
        rendered_level = re_render_mls_level(&level, policy);
        ap_mls_level_free(&level);
        Tcl_AppendResult(interp, rendered_level, NULL);
        free(rendered_level);
        return TCL_OK;
}

/* Takes a Tcl context object (argv[1]) and returns a single string
 * with the context rendered.  If argv[2] exists and is non-zero then
 * consider the fourth element of argv[1] to be a MLS range object. */
static int Apol_RenderContext(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        Tcl_Obj *context_obj, *user_obj, *role_obj, *type_obj;
        char *s;
        security_con_t context;
        ap_mls_level_t low, high;
        ap_mls_range_t range;
        char *rendered_context;
        int range_len = -1;

        if (argc < 1 || argc > 3) {
                Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
                return TCL_ERROR;
        }
	if(policy == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
        context_obj = Tcl_NewStringObj(argv[1], -1);

        if (Tcl_ListObjIndex(interp, context_obj, 0, &user_obj) == TCL_ERROR ||
                user_obj == NULL) {
                Tcl_SetResult(interp, "Invalid user name", TCL_STATIC);
        }
        s = Tcl_GetString(user_obj);
        if ((context.user = get_user_idx(s, policy)) < 0) {
                Tcl_AppendResult(interp, "Invalid user name ", s, NULL);
                return TCL_ERROR;
        }

        if (Tcl_ListObjIndex(interp, context_obj, 1, &role_obj) == TCL_ERROR ||
                role_obj == NULL) {
                Tcl_SetResult(interp, "Invalid role name", TCL_STATIC);
        }
        s = Tcl_GetString(role_obj);
        if ((context.role = get_role_idx(s, policy)) < 0) {
                Tcl_AppendResult(interp, "Invalid role ", s, NULL);
                return TCL_ERROR;
        }

        if (Tcl_ListObjIndex(interp, context_obj, 2, &type_obj) == TCL_ERROR ||
                type_obj == NULL) {
                Tcl_SetResult(interp, "Invalid type name", TCL_STATIC);
        }
        s = Tcl_GetString(type_obj);
        if ((context.type = get_type_idx(s, policy)) < 0) {
                Tcl_AppendResult(interp, "Invalid type ", s, NULL);
                return TCL_ERROR;
        }

        /* now add MLS component as necessary */
        if (argc == 2 || strcmp(argv[2], "0") == 0) {
                context.range = NULL;
        }
        else {
                Tcl_Obj *range_obj, *low_obj, *high_obj;
                if (Tcl_ListObjIndex(interp, context_obj, 3, &range_obj) == TCL_ERROR ||
                    range_obj == NULL) {
                        Tcl_SetResult(interp, "Invalid range", TCL_STATIC);
                }

                if (Tcl_ListObjIndex(interp, range_obj, 0, &low_obj) == TCL_ERROR ||
                    low_obj == NULL) {
                        Tcl_SetResult(interp, "Invalid low level", NULL);
                }
                s = Tcl_GetString(low_obj);
                if (ap_tcl_level_string_to_level(interp, s, &low) != 0) {
                        Tcl_AppendResult(interp, "Invalid low level ", s, NULL);
                        return TCL_ERROR;
                }
                range.low = &low;

                if (Tcl_ListObjLength(interp, range_obj, &range_len) == TCL_ERROR ||
                    range_len > 2) {
                        Tcl_SetResult(interp, "Invalid range", TCL_STATIC);
                        return TCL_ERROR;
                }
                if (range_len == 1) {
                        /* only single level given */
                        range.high = &low;
                }
                else {
                        if (Tcl_ListObjIndex(interp, range_obj, 1, &high_obj) == TCL_ERROR ||
                            high_obj == NULL) {
                                Tcl_SetResult(interp, "Invalid high level", NULL);
                        }
                        s = Tcl_GetString(high_obj);
                        if (ap_tcl_level_string_to_level(interp, s, &high) != 0) {
                                Tcl_AppendResult(interp, "Invalid high level ", s, NULL);
                                ap_mls_level_free(&low);
                                return TCL_ERROR;
                        }
                        range.high = &high;
                }
                context.range = &range;
        }
        if ((rendered_context = re_render_security_context(&context, policy)) == NULL) {
                Tcl_SetResult(interp, "Error while rendering context.", TCL_STATIC);
                return TCL_ERROR;
        }
        if (range_len != -1) {
                ap_mls_range_free(&range);
        }
        Tcl_SetResult(interp, rendered_context, TCL_VOLATILE);
        free(rendered_context);
        return TCL_OK;
}


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

/* Render a single range transition rule, given its index */
static int Apol_RenderRangeTrans(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
        int idx;
        Tcl_Obj *result_obj;
        Tcl_Obj *linenum_obj, *source_obj, *target_obj, *type_obj, *range_obj;
        char *rendered_range;

        if (argc != 2) {
                Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
                return TCL_ERROR;
        }
        if (policy == NULL) {
                Tcl_SetResult(interp, "Could not display range transition because no policy was loaded.", TCL_STATIC);
                return TCL_ERROR;
        }
        if (Tcl_GetInt(interp, argv[1], &idx) == TCL_ERROR) {
                return TCL_ERROR;
        }
	if (idx < 0 || idx >= policy->num_rangetrans) {
                Tcl_SetResult(interp, "Illegal range transition index.", TCL_STATIC);
                return TCL_ERROR;
        }
        if (is_binary_policy(policy)) {
                linenum_obj = Tcl_NewStringObj(NULL, 0);
        }
        else {
                linenum_obj = Tcl_NewLongObj((long) policy->rangetrans[idx].lineno);
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

int ap_tcl_render_init(Tcl_Interp *interp) {
        Tcl_CreateCommand(interp, "apol_RenderLevel", Apol_RenderLevel, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderContext", Apol_RenderContext, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderRangeTrans", Apol_RenderRangeTrans, NULL, NULL);
	return TCL_OK;
}
