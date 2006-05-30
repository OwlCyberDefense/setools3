/**
 * @file apol_tcl_render.c
 * Implementation for the apol interface to render parts of a policy.
 * This file takes various policy stuff and returns formatted Tcl
 * lists, suitable for displaying results in Apol.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "policy.h"
#include "render.h"

#include "apol_tcl_other.h"

#include "policy-query.h"

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

/**
 * Take a Tcl string representing a level (level = sensitivity + list
 * of categories) and return a string representation of it.  If the
 * level is nat valid according to the policy then return an empty
 * string.
 *
 * @param argv A MLS level.
 */
static int Apol_RenderLevel(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj;
	apol_mls_level_t *level = NULL;
	char *rendered_level = NULL;
	int retval = TCL_ERROR, retval2;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "Need a level to render.");
		goto cleanup;
	}
	if ((level = apol_mls_level_create()) == NULL) {
		ERR(policydb, "Out of memory.");
		goto cleanup;
	}
	retval2 = apol_tcl_string_to_level(interp, argv[1], level);
	if (retval2 < 0) {
		goto cleanup;
	}
	else if (retval2 == 1) {
		/* no render possible */
		retval = TCL_OK;
		goto cleanup;
	}
	if ((rendered_level = apol_mls_level_render(policydb, level)) == NULL) {
		goto cleanup;
	}
	result_obj = Tcl_NewStringObj(rendered_level, -1);
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_mls_level_destroy(&level);
	free(rendered_level);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Take a Tcl string representing a context and return a string
 * representation of it.  A Tcl context is:
 * <code>
 *   { user role type range }
 * </code>
 *
 * If the policy is non-mls, then the fourth parameter is ignored.
 *
 * @param argv This function takes two parameters:
 * <ol>
 *   <li>Tcl string representing a context
 * </ol>
 */
static int Apol_RenderContext(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *result_obj;
	apol_context_t *context = NULL;
	char *rendered_context = NULL;
	int retval = TCL_ERROR;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "Need a context.");
		goto cleanup;
	}
	if ((context = apol_context_create()) == NULL) {
		ERR(policydb, "Out of memory!");
		goto cleanup;
	}
	if (apol_tcl_string_to_context(interp, argv[1], context) < 0) {
		goto cleanup;
	}

	/* check that all components exist */
	if (context->user == NULL || context->role == NULL || context->type == NULL ||
	    (apol_policy_is_mls(policydb) && context->range == NULL)) {
		ERR(policydb, "Context string '%s' is not valid.", argv[1]);
		goto cleanup;
	}
	if ((rendered_context = apol_context_render(policydb, context)) == NULL) {
		goto cleanup;
	}
	result_obj = Tcl_NewStringObj(rendered_context, -1);
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
 cleanup:
	apol_context_destroy(&context);
	free(rendered_context);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
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

int apol_tcl_render_init(Tcl_Interp *interp) {
        Tcl_CreateCommand(interp, "apol_RenderLevel", Apol_RenderLevel, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderContext", Apol_RenderContext, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_RenderRangeTrans", Apol_RenderRangeTrans, NULL, NULL);
	return TCL_OK;
}
