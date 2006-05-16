/* Copyright (C) 2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com and Don Patterson <don.patterson@tresys.com>
 */

#include <tcl.h>
#include <assert.h>

#include "policy-query.h"
#include "render.h"

#include "apol_tcl_other.h"
#include "apol_tcl_render.h"

#ifdef LIBSEFS
#include "../libsefs/fsdata.h"
#endif

extern char *rulenames[]; /* in render.c*/


/* search and return type enforcement rules */

static int append_av_rule(bool_t addnl, bool_t addlineno, int idx, bool_t is_au, policy_t *policy, Tcl_DString *buf)
{ 
	char *rule;
	
	if(buf == NULL) {
		return -1;
	}
	
	rule = re_render_av_rule(addlineno, idx, is_au, policy);
	if(rule == NULL)
		return -1;
	Tcl_DStringAppend(buf, rule, -1);
	free(rule);

	if(addnl) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	return 0;
}


static int append_tt_rule(bool_t addnl, bool_t addlineno, int idx, policy_t *policy, Tcl_DString *buf) 
{
	char *rule;
	
	if(buf == NULL) {
		return -1;
	}
	
	rule = re_render_tt_rule(addlineno, idx, policy);
	if(rule == NULL)
		return -1;
	Tcl_DStringAppend(buf, rule, -1);
	free(rule);
	
	if(addnl) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	return 0;	

}

/* append_clone_rule() - Its use is deprecated. */ 
static int append_clone_rule(bool_t addnl, bool_t addlineno, cln_item_t *item, policy_t *policy, Tcl_DString *buf) 
{
	char tbuf[APOL_STR_SZ+64];
	
	if(buf == NULL) {
		return -1;
	}
	
	Tcl_DStringAppend(buf, rulenames[RULE_CLONE], -1);
	Tcl_DStringAppend(buf, " ", -1);
	if(ap_tcl_append_type_str(0,0, 0, item->src, policy, buf) != 0)
		return -1;	
	Tcl_DStringAppend(buf, " ", -1);		
	if(ap_tcl_append_type_str(0,0, 0, item->tgt, policy, buf) != 0)
		return -1;
	Tcl_DStringAppend(buf, ";", -1);

	if(addlineno) {
		sprintf(tbuf, "       (%lu)", item->lineno);
		Tcl_DStringAppend(buf, tbuf, -1);
	}
	if(addnl) {
		Tcl_DStringAppend(buf, "\n", -1);
	}
	return 0;
}


/* This is a newer function that replaces the legacy Apol_GetTErules() function (below).  The 
 * latter is deprecated.  This function returns the search results in a tcl list.  This list
 * is organized as follows:
 *	index		contexts
 *	0		# of returned rules
 *	1		first rule (if any)
 *	2		first rule's lineno ref into policy.co
 *	3		2nd rule (if any)
 *	4		2nd rule lineno ref
 *	n-1		last rule
 *	n		last rule's lineno ref
 *
 * arg ordering; argv[x] where x is:
 *  1		te_allow
 *  2		neverallow
 *  3		clone
 *  4		auallow
 *  5		audeny
 *  6		dontaudit
 *  7		ttrans
 *  8		tmember
 *  9		tchange
 * 10		use_1
 * 11		indirect_1
 * 12		ta1	(first type/attrib search parameter)
 * 13		which	(indicates whether ta1 is used for source, or any location
 * 14		use_2
 * 15		indirect_2
 * 16		ta2	(second type/attrib search parameter, always as target)
 * 17		use_3
 * 18		indirect_3
 * 19		ta3
 * 20		classes (list)
 * 21		perms (list)
 * 22		allow_regex (bool, indicate whether ta* are regexp or not)
 * 23		ta1_opt (indicates whether ta1 is a TYPES, ATTRIBS, or BOTH)
 * 24		ta2_opt (same for ta2; NOTE ta3 is always a TYPES)
 * 25		include only rules that are enabled by the conditional policy (boolean)
 */
static int Apol_SearchTErules(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{	
	int i, rt;
	teq_query_t query;
	teq_results_t results;
	Tcl_DString buffer, *buf = &buffer;
	char tmpbuf[APOL_STR_SZ+64];
	CONST char **classes, **perms;
	bool_t use_1, use_2, use_3;

	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(argc != 26) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	
	init_teq_query(&query);
	init_teq_results(&results);

	if(getbool(argv[1]))
		query.rule_select |= TEQ_ALLOW;
	if(getbool(argv[2]))
		query.rule_select |= TEQ_NEVERALLOW;
	if(getbool(argv[3]))
		query.rule_select |= TEQ_CLONE;
	if(getbool(argv[4]))
		query.rule_select |= TEQ_AUDITALLOW;
	if(getbool(argv[5]))
		query.rule_select |= TEQ_AUDITDENY;
	if(getbool(argv[6]))
		query.rule_select |= TEQ_DONTAUDIT;
	if(getbool(argv[7]))
		query.rule_select |= TEQ_TYPE_TRANS;
	if(getbool(argv[8]))
		query.rule_select |= TEQ_TYPE_MEMBER;
	if(getbool(argv[9]))
		query.rule_select |= TEQ_TYPE_CHANGE;		
	query.use_regex = getbool(argv[22]);
	query.only_enabled = getbool(argv[25]);
	
	query.ta1.indirect = getbool(argv[11]);
	query.ta2.indirect = getbool(argv[15]);
	query.ta3.indirect = getbool(argv[18]);
	

	use_1 = getbool(argv[10]);
	if(use_1) {
                if(argv[12] == NULL || str_is_only_white_space(argv[12])) {
		        Tcl_AppendResult(interp, "empty source type/attrib!", (char *) NULL);
		        return TCL_ERROR;
	        }
		if(!is_valid_str_sz(argv[12])) {
			Tcl_AppendResult(interp, "Source type/attrib string too large", (char *) NULL);
			return TCL_ERROR;
		}
		if(strcmp(argv[13], "source") == 0) 
			query.any = FALSE;
		else if(strcmp(argv[13], "either") == 0)
			query.any = TRUE;
		else {
			Tcl_AppendResult(interp, "Invalid which option for source parameter", (char *) NULL);
			return TCL_ERROR;			
		}
		
		query.ta1.ta = (char *)malloc(strlen(argv[12]) + 1);
		if(query.ta1.ta == NULL) {
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		strcpy(query.ta1.ta, argv[12]);	/* The ta string */
		
       	        if(strcmp("types", argv[23])  == 0) 
		        query.ta1.t_or_a = IDX_TYPE;
	        else if(strcmp("attribs", argv[23]) == 0) 
		        query.ta1.t_or_a = IDX_ATTRIB;
   	        else if((strcmp("both", argv[23]) == 0) ||( strcmp("either", argv[23]) == 0)) 
		        query.ta1.t_or_a = IDX_BOTH;
	        else {
		        sprintf(tmpbuf, "ta1_opt value invalid: %s", argv[23]);
 		        free_teq_query_contents(&query);
		        Tcl_AppendResult(interp, tmpbuf, (char*) NULL);
		        return TCL_ERROR;
	        }
	}
	use_2 = (getbool(argv[14]) & ! query.any);
	if(use_2) {
	        if(argv[16] == NULL || str_is_only_white_space(argv[16])) {
		        Tcl_AppendResult(interp, "empty target type/attrib!", (char *) NULL);
		        return TCL_ERROR;
	        }
		if(!is_valid_str_sz(argv[16])) {
			Tcl_AppendResult(interp, "Target type/attrib string too large", (char *) NULL);
			return TCL_ERROR;
		}
		query.ta2.ta = (char *)malloc(strlen(argv[16]) + 1);
		if(query.ta2.ta == NULL) {
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		strcpy(query.ta2.ta, argv[16]);	/* The ta string */

		if(strcmp("types", argv[24])  == 0) 
			query.ta2.t_or_a = IDX_TYPE;
		else if(strcmp("attribs", argv[24]) == 0) 
			query.ta2.t_or_a = IDX_ATTRIB;
		else if((strcmp("both", argv[24]) == 0) || ( strcmp("either", argv[24]) == 0)) 
			query.ta2.t_or_a = IDX_BOTH;
		else {
			sprintf(tmpbuf, "ta2_opt value invalid: %s", argv[24]);
			free_teq_query_contents(&query);
			Tcl_AppendResult(interp, tmpbuf, (char*) NULL);		
			return TCL_ERROR;
		}
	}
	use_3 = getbool(argv[17]) && !query.any;
	if(use_3) {
	        if(argv[19] == NULL || str_is_only_white_space(argv[19])) {
		        Tcl_AppendResult(interp, "empty default type!", (char *) NULL);
		        return TCL_ERROR;
	        }
		if(!is_valid_str_sz(argv[19])) {
			Tcl_AppendResult(interp, "Default type string too large", (char *) NULL);
			return TCL_ERROR;
		}
		query.ta3.ta = (char *)malloc(strlen(argv[19]) + 1);
		if(query.ta3.ta == NULL) {
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		strcpy(query.ta3.ta, argv[19]);	/* The ta string */
		query.ta3.t_or_a = IDX_TYPE; /* can only ever be type */
	}

	/* classes */
	rt = Tcl_SplitList(interp, argv[20], &query.num_classes, &classes);
	if(rt != TCL_OK) {
		Tcl_AppendResult(interp, "error splitting classes", (char *) NULL);
		free_teq_query_contents(&query);
		return rt;
	}
	if(query.num_classes < 1) {
		query.classes = NULL;
	}
	else {
		query.classes = (int *)malloc(sizeof(int)*query.num_classes );
		if(query.classes == NULL) {
			Tcl_Free((char *) classes);
			free_teq_query_contents(&query);
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		for(i = 0; i < query.num_classes; i++) {
			query.classes[i] = get_obj_class_idx(classes[i], policy);
			if(query.classes[i] < 0) {
				sprintf(tmpbuf, "%s is not a valid object class name", classes[i]);
				Tcl_Free((char *) classes);
				free_teq_query_contents(&query);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) classes);
	}
	/* perms */
	rt = Tcl_SplitList(interp, argv[21], &query.num_perms, &perms);
	if(rt != TCL_OK) {
		free_teq_query_contents(&query);
		Tcl_AppendResult(interp, "error splitting perms", (char *) NULL);
		return rt;
	}
	if(query.num_perms < 1) {
		query.perms = NULL;
	}
	else {
		query.perms = (int *)malloc(sizeof(int)*query.num_perms);
		if(query.perms == NULL) {
			Tcl_Free((char *) perms);
			free_teq_query_contents(&query);
			Tcl_AppendResult(interp, "out of memory", (char *) NULL);
			return TCL_ERROR;
		}
		for(i = 0; i < query.num_perms; i++) {
			query.perms[i] = get_perm_idx(perms[i], policy);
			if(query.perms[i] < 0) {
				sprintf(tmpbuf, "%s is not a permission name", perms[i]);
				Tcl_Free((char *) perms);
				free_teq_query_contents(&query);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;
			}
		}
		Tcl_Free((char *) perms);
	}
		

	/* submit query */
	rt = search_te_rules(&query, &results, policy);
	if(rt == -1) {
		Tcl_AppendResult(interp, "Unrecoverable error when searching TE rules", (char *) NULL);
		free_teq_results_contents(&results);
		free_teq_query_contents(&query);
		return TCL_ERROR;
	}
	else if(rt == -2) {
		switch(results.err) {
		case TEQ_ERR_TA1_REGEX:
			Tcl_AppendResult(interp, "Source type string is invalid regular expression", (char *) NULL);
			break;
		case TEQ_ERR_TA2_REGEX:
			Tcl_AppendResult(interp, "Target type string is invalid regular expression", (char *) NULL);
			break;
		case TEQ_ERR_TA3_REGEX:
			Tcl_AppendResult(interp, "Default type string is invalid regular expression", (char *) NULL);
			break;
		case TEQ_ERR_TA1_INVALID:
			Tcl_AppendResult(interp, "Source is not a valid type nor attribute", (char *) NULL);
			break;
		case TEQ_ERR_TA2_INVALID:
			Tcl_AppendResult(interp, "Target is not a valid type nor attribute", (char *) NULL);
			break;
		case TEQ_ERR_TA3_INVALID:
			Tcl_AppendResult(interp, "Default is not a valid type nor attribute", (char *) NULL);
			break;
		case TEQ_ERR_TA1_STRG_SZ:
			Tcl_AppendResult(interp, "Source string is too large", (char *) NULL);
			break;
		case TEQ_ERR_TA2_STRG_SZ:
			Tcl_AppendResult(interp, "Target string is too large", (char *) NULL);
			break;
		case TEQ_ERR_TA3_STRG_SZ:
			Tcl_AppendResult(interp, "Default string is too large", (char *) NULL);
			break;
		case TEQ_ERR_INVALID_CLS_Q:
			Tcl_AppendResult(interp, "The list of classes is incoherent", (char *) NULL);
			break;
		case TEQ_ERR_INVALID_PERM_Q:
			Tcl_AppendResult(interp, "The list of permissions is incoherent", (char *) NULL);
			break;
		case TEQ_ERR_INVALID_CLS_IDX:
			Tcl_AppendResult(interp, "One of the class indicies is incorrect", (char *) NULL);
			break;
		case TEQ_ERR_INVALID_PERM_IDX:
			Tcl_AppendResult(interp, "One of the permission indicies is incorrect", (char *) NULL);
			break;
		default:
			Tcl_AppendResult(interp, "Unexpected error searching rules", (char *) NULL);
			break;
		}
		free_teq_results_contents(&results);
		free_teq_query_contents(&query);
		return TCL_ERROR;
	}
	
	
	/* render results*/
	Tcl_DStringInit(buf);
	if(results.num_av_access > 0) {
		for(i = 0; i < results.num_av_access; i++) {
			rt = append_av_rule(0, 0, results.av_access[i], FALSE, policy, buf);
			if(rt != 0) {
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				free_teq_query_contents(&query);
				free_teq_results_contents(&results);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, buf->string);
			Tcl_DStringFree(buf);
			sprintf(tmpbuf, "%lu", policy->av_access[results.av_access[i]].lineno);
			Tcl_AppendElement(interp, tmpbuf);
			
			/* Append boolean values to indicate whether this is a conditional rule 
			 * and whether it is enabled for conditional policy support */
			if (policy->av_access[results.av_access[i]].cond_expr != -1)
				Tcl_AppendElement(interp, "1");
			else 
				Tcl_AppendElement(interp, "0");
			sprintf(tmpbuf, "%d", policy->av_access[results.av_access[i]].enabled);
			Tcl_AppendElement(interp, tmpbuf);
		}
	}
	if(results.num_av_audit > 0) {
		for(i = 0; i < results.num_av_audit; i++) {
			rt = append_av_rule(0, 0, results.av_audit[i], TRUE, policy, buf);
			if(rt != 0) {
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				free_teq_query_contents(&query);
				free_teq_results_contents(&results);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, buf->string);
			Tcl_DStringFree(buf);
			sprintf(tmpbuf, "%lu", policy->av_audit[results.av_audit[i]].lineno);
			Tcl_AppendElement(interp, tmpbuf);
			/* Append boolean values to indicate whether this is a conditional rule 
			 * and whether it is enabled for conditional policy support */
			if (policy->av_audit[results.av_audit[i]].cond_expr != -1)
				Tcl_AppendElement(interp, "1");
			else 
				Tcl_AppendElement(interp, "0");
			sprintf(tmpbuf, "%d", policy->av_audit[results.av_audit[i]].enabled);
			Tcl_AppendElement(interp, tmpbuf);
		}
	}
	if(results.num_type_rules > 0) { 
		for(i = 0; i < results.num_type_rules; i++) {
			rt = append_tt_rule(0, 0, results.type_rules[i], policy, buf);
			if(rt != 0) {
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				free_teq_query_contents(&query);
				free_teq_results_contents(&results);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, buf->string);
			Tcl_DStringFree(buf);
			sprintf(tmpbuf, "%lu", policy->te_trans[results.type_rules[i]].lineno);
			Tcl_AppendElement(interp, tmpbuf);
			/* Append boolean values to indicate whether this is a conditional rule 
			 * and whether it is enabled for conditional policy support */
			if (policy->te_trans[results.type_rules[i]].cond_expr != -1)
				Tcl_AppendElement(interp, "1");
			else 
				Tcl_AppendElement(interp, "0");
			sprintf(tmpbuf, "%d", policy->te_trans[results.type_rules[i]].enabled);
			Tcl_AppendElement(interp, tmpbuf);
		}
	}
	if(results.num_clones > 0) {
		for(i = 0; i < results.num_clones; i++) {
			rt = append_clone_rule(0, 0, &(policy->clones[results.clones[i]]), policy, buf);
			if(rt != 0) {
				Tcl_DStringFree(buf);
				Tcl_ResetResult(interp);
				free_teq_query_contents(&query);
				free_teq_results_contents(&results);
				return TCL_ERROR;
			}
			Tcl_AppendElement(interp, buf->string);
			Tcl_DStringFree(buf);
			sprintf(tmpbuf, "%lu", policy->clones[results.clones[i]].lineno);
			Tcl_AppendElement(interp, tmpbuf);
			/* Append 0 to indicate this is not a conditional rule. */
			Tcl_AppendElement(interp, "0");
			/* Since the enabled flag member is only supported in access, audit and type 
			 * transition rules, always append TRUE, so the returned list can be parsed 
			 * correctly. */
			Tcl_AppendElement(interp, "1");
		}
	}
	free_teq_query_contents(&query);
	free_teq_results_contents(&results);

	return TCL_OK;	
}

static void apol_cond_rules_append_expr(cond_expr_t *exp, policy_t *policy, Tcl_Interp *interp)
{
	char tbuf[BUF_SZ];
	cond_expr_t *cur;
	Tcl_DString buffer, *buf = &buffer;
	
	Tcl_DStringInit(buf);
			
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			snprintf(tbuf, sizeof(tbuf)-1, "%s ", policy->cond_bools[cur->bool].name); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_NOT:
			snprintf(tbuf, sizeof(tbuf)-1, "! "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_OR:
			snprintf(tbuf, sizeof(tbuf)-1, "|| "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_AND:
			snprintf(tbuf, sizeof(tbuf)-1, "&& "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_XOR:
			snprintf(tbuf, sizeof(tbuf)-1, "^ "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_EQ:
			snprintf(tbuf, sizeof(tbuf)-1, "== "); 
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		case COND_NEQ:
			snprintf(tbuf, sizeof(tbuf)-1, "!= ");
			Tcl_DStringAppend(buf, tbuf, -1);
			break;
		default:
			break;
		}
	}
	/* Append the conditional expression to our tcl list */
	Tcl_AppendElement(interp, buf->string);
	Tcl_DStringFree(buf);
}

static void apol_cond_rules_append_cond_list(cond_rule_list_t *list, bool_t include_allow, bool_t include_audit, bool_t include_tt, 
				     	     policy_t *policy, Tcl_Interp *interp)
{
	int i;
	char tbuf[BUF_SZ], *rule = NULL;
	
	if (!list) {
		/* Indicate that there are no rules, since the list is empty. */
		Tcl_AppendElement(interp, "0");
		Tcl_AppendElement(interp, "0");
		Tcl_AppendElement(interp, "0");
		return;
	}
	assert(policy != NULL);
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_av_access);
	Tcl_AppendElement(interp, tbuf);
	if (include_allow) {
		for (i = 0; i < list->num_av_access; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->av_access[list->av_access[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_av_rule(FALSE, list->av_access[i], FALSE, policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->av_access[list->av_access[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_av_audit);
	Tcl_AppendElement(interp, tbuf);
	if (include_audit) {
		for (i = 0; i < list->num_av_audit; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->av_audit[list->av_audit[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_av_rule(FALSE, list->av_audit[i], TRUE, policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->av_audit[list->av_audit[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
	
	snprintf(tbuf, sizeof(tbuf)-1, "%d", list->num_te_trans);
	Tcl_AppendElement(interp, tbuf);
	if (include_tt) {
		for (i = 0; i < list->num_te_trans; i++) {
			/* Append the line number for the rule */
			sprintf(tbuf, "%lu", policy->te_trans[list->te_trans[i]].lineno);
			Tcl_AppendElement(interp, tbuf);
			
			/* Append the rule string */
			rule = re_render_tt_rule(FALSE, list->te_trans[i], policy);
			assert(rule);
			snprintf(tbuf, sizeof(tbuf)-1, "%s", rule);
			Tcl_AppendElement(interp, tbuf);
			free(rule);
			
			/* Append flag indicating if this is a disabled or enabled rule */
			if (policy->te_trans[list->te_trans[i]].enabled)
				Tcl_AppendElement(interp, "1"); 
			else 
				Tcl_AppendElement(interp, "0"); 
		}
	}
}

/* 
 * argv[1] boolean name
 * argv[2] use reg expression
 * argv[3] include allow rules
 * argv[4] include audit rules
 * argv[5] include type transition rules
 * argv[6] use boolean for search
 */
static int Apol_SearchConditionalRules(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	char *error_msg = NULL;
	bool_t regex, *exprs_b, use_bool;
	bool_t include_allow, include_audit, include_tt;
	int i;
	
	if (argc != 7) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}
	if (policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	
	if (!is_valid_str_sz(argv[1])) {
		Tcl_AppendResult(interp, "The provided user string is too large.", (char *) NULL);
		return TCL_ERROR;
	}
	
	regex = getbool(argv[2]);
	include_allow = getbool(argv[3]);
	include_audit = getbool(argv[4]);
	include_tt = getbool(argv[5]);
	use_bool = getbool(argv[6]);
	if (use_bool && str_is_only_white_space(argv[1])) {
		Tcl_AppendResult(interp, "You umust provide a boolean!", (char *) NULL);
		return TCL_ERROR;
	}
	/* If regex is turned OFF, then validate that the boolean exists. */
	if (use_bool && !regex && get_cond_bool_idx(argv[1], policy) < 0) {
		Tcl_AppendResult(interp, "Invalid boolean name provided. You may need to turn on the regular expression option.", (char *) NULL);
		return TCL_ERROR;
	}
	exprs_b = (bool_t*)malloc(sizeof(bool_t) * policy->num_cond_exprs);
	if (!exprs_b) {
		Tcl_AppendResult(interp, "Memory error\n", (char *) NULL);
		return TCL_ERROR;
	}
	memset(exprs_b, FALSE, sizeof(bool_t) * policy->num_cond_exprs);
	
	if (search_conditional_expressions(use_bool, (char *) argv[1], regex, exprs_b, &error_msg, policy) != 0) {
		Tcl_AppendResult(interp, "Error searching conditional expressions: ", error_msg, (char *) NULL);
		free(error_msg);
		return TCL_ERROR;
	}
	for (i = 0; i < policy->num_cond_exprs; i++) {
		if (exprs_b[i]) {
			apol_cond_rules_append_expr(policy->cond_exprs[i].expr, policy, interp);
		
			apol_cond_rules_append_cond_list(policy->cond_exprs[i].true_list, 
							include_allow, include_audit, include_tt, 
							policy, interp);
			
			apol_cond_rules_append_cond_list(policy->cond_exprs[i].false_list, 
							include_allow, include_audit, include_tt, 
							policy, interp);
		}
	}
	free(exprs_b);
										
	return TCL_OK;
}

static int append_role_allow_rule(role_allow_t *rule, policy_t *policy, Tcl_DString *buf)
{
	ta_item_t *tptr;	
	int multiple = 0;
	if(buf == NULL) {
		return -1;
	}
		
	Tcl_DStringAppend(buf, rulenames[RULE_ROLE_ALLOW], -1);

	/* source roles */
	if(rule->flags & AVFLAG_SRC_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->src_roles != NULL && rule->src_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		Tcl_DStringAppend(buf, "*", -1);
			
	for(tptr = rule->src_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	/* target roles */
	if(rule->flags & AVFLAG_TGT_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->tgt_roles != NULL && rule->tgt_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		Tcl_DStringAppend(buf, "*", -1);

	
	for(tptr = rule->tgt_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	
	Tcl_DStringAppend(buf, ";\n", -1);
		
	return 0;
}

static int append_role_trans_rule(rt_item_t *rule, policy_t *policy, Tcl_DString *buf)
{
	ta_item_t *tptr;	
	int multiple = 0;
	if(buf == NULL) {
		return -1;
	}
		
	Tcl_DStringAppend(buf, rulenames[RULE_ROLE_TRANS], -1);
	
	/* source roles */
	if(rule->flags & AVFLAG_SRC_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->src_roles != NULL && rule->src_roles->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		Tcl_DStringAppend(buf, "*", -1);
			
	for(tptr = rule->src_roles; tptr != NULL; tptr = tptr->next) {
		assert(tptr->type == IDX_ROLE);
		Tcl_DStringAppend(buf, " ", -1);
		Tcl_DStringAppend(buf, policy->roles[tptr->idx].name, -1);
		Tcl_DStringAppend(buf, " ", -1);
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	/* target types/attributes */
	if(rule->flags & AVFLAG_TGT_TILDA) 
		Tcl_DStringAppend(buf, " ~", -1);
	else
		Tcl_DStringAppend(buf, " ", -1);
	if(rule->tgt_types != NULL && rule->tgt_types->next != NULL) {
		multiple = 1;
		Tcl_DStringAppend(buf, "{", -1);
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		Tcl_DStringAppend(buf, "*", -1);

	for(tptr = rule->tgt_types; tptr != NULL; tptr = tptr->next) {
		if ((tptr->type & IDX_SUBTRACT)) {
			Tcl_DStringAppend(buf, "-", -1);
		}
		if ((tptr->type & IDX_TYPE)) {
			Tcl_DStringAppend(buf, " ", -1);
			if(ap_tcl_append_type_str(0, 0, 0, tptr->idx, policy, buf) != 0)
				return -1;
		}
		else if ((tptr->type & IDX_ATTRIB)) {
			Tcl_DStringAppend(buf, " ", -1);
			if(ap_tcl_append_attrib_str(0, 0, 0, 0, 0, tptr->idx, policy, buf) != 0)
				return -1;
		}			
		else {
			fprintf(stderr, "Invalid index type: %d\n", tptr->type);
			return -1;
		}
	}
	if(multiple) {
		Tcl_DStringAppend(buf, "}", -1);
		multiple = 0;
	}
	
	/* default role */
	Tcl_DStringAppend(buf, " ", -1);
	assert(rule->trans_role.type == IDX_ROLE);
	Tcl_DStringAppend(buf, policy->roles[rule->trans_role.idx].name, -1);
	
	Tcl_DStringAppend(buf, ";\n", -1);
		
	return 0;
}

/* Search role rules */
/* arg ordering for argv[x]:
 * 1	allow (bool)		get allow rules
 * 2	trans (bool)		get role_transition rules
 * 3	use_src (bool)		whether to search by source role
 * 4	source			the source role
 * 5	which			whether source used for source or any (if any, others ignored)
 *					possible values: "source", "any"
 * 6	use_tgt (bool)		whether to search by target role (allow) or type (trans)
 * 7	target			the target role/type
 * 8	tgt_is_role (bool) 	whther target is role (allow only) or type (trans only)
 * 9	use_default (bool) 	search using default role (trans only)
 * 10	default			the default role
 */
static int Apol_GetRoleRules(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	int i, rt, src_idx = -1, tgt_idx = -1, tgt_type = IDX_ROLE, dflt_idx = -1;
	Tcl_DString buffer, *buf = &buffer;
	char tmpbuf[APOL_STR_SZ+64];
	bool_t allow, trans, any = FALSE, use_src, use_tgt, tgt_is_role, use_dflt;
	rbac_bool_t src_b, tgt_b, dflt_b;
	
	if(policy == NULL) {
		Tcl_AppendResult(interp,"No current policy file is opened!", (char *) NULL);
		return TCL_ERROR;
	}
	if(argc != 11) {
		Tcl_AppendResult(interp, "wrong # of args", (char *) NULL);
		return TCL_ERROR;
	}

	allow = getbool(argv[1]);
	trans = getbool(argv[2]);
	use_src = getbool(argv[3]);
	tgt_is_role = getbool(argv[8]);

	if(use_src) {
		if(strcmp(argv[5], "source") == 0)
			any = FALSE;
		else if(strcmp(argv[5], "any") == 0)
			any = TRUE;
		else {
			Tcl_AppendResult(interp, "Invalid which option for source ", (char *) NULL);
			return TCL_ERROR;			
		}
		if(!is_valid_str_sz(argv[4])) {
			Tcl_AppendResult(interp, "Source string is too large", (char *) NULL);
			return TCL_ERROR;
		}		
		src_idx = get_role_idx(argv[4], policy);
		if(src_idx < 0) {
			sprintf(tmpbuf, "Invalid source role name (%s)", argv[4]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			return TCL_ERROR;			
		}
		
	}
	use_tgt = getbool(argv[6]) && !any;
	if(use_tgt) {
		if(allow && trans) {
			Tcl_AppendResult(interp, "Invalid option, target option may only be used if EITHER allow or role_trans is selected, but not both", (char *) NULL);
			return TCL_ERROR;
		}
		if(tgt_is_role && (!allow || trans)) {
			Tcl_AppendResult(interp, "Invalid option, target option may be a ROLE when allow, and only allow, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(!tgt_is_role && (allow || !trans)) {
			Tcl_AppendResult(interp, "Invalid option, target option may be a TYPE when role_trans, and only role_trans, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(tgt_is_role) {
			if(!is_valid_str_sz(argv[7])) {
				Tcl_AppendResult(interp, "Target string is too large", (char *) NULL);
				return TCL_ERROR;
			}
			tgt_idx = get_role_idx(argv[7], policy);
			if(tgt_idx < 0) {
				sprintf(tmpbuf, "Invalid target role name (%s)", argv[7]);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;			
			}
			tgt_type = IDX_ROLE;
		}
		else {
			if(!is_valid_str_sz(argv[7])) {
				Tcl_AppendResult(interp, "Target string is too large", (char *) NULL);
				return TCL_ERROR;
			}
			tgt_idx = get_type_or_attrib_idx(argv[7], &tgt_type, policy);
			if(tgt_idx < 0) {
				sprintf(tmpbuf, "Invalid target type or attribute (%s)", argv[7]);
				Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
				return TCL_ERROR;			
			}
		}
		
	}
	use_dflt = getbool(argv[9]) && !any;
	if(use_dflt) {
		if(allow || !trans) {
			Tcl_AppendResult(interp, "Invalid option, default may use when role_trans, and only role_trans, is selected", (char *) NULL);
			return TCL_ERROR;
		}
		if(!is_valid_str_sz(argv[10])) {
			Tcl_AppendResult(interp, "Default string is too large", (char *) NULL);
			return TCL_ERROR;
		}
		dflt_idx = get_role_idx(argv[10], policy);
		if(dflt_idx < 0) {
			sprintf(tmpbuf, "Invalid default role name (%s)", argv[10]);
			Tcl_AppendResult(interp, tmpbuf, (char *) NULL);
			return TCL_ERROR;			
		}
	}
	
	Tcl_DStringInit(buf);
	
	if(init_rbac_bool(&src_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing src rules bool", (char *) NULL);
		return TCL_ERROR;
	}
	if(init_rbac_bool(&tgt_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing tgt rules bool", (char *) NULL);
		free_rbac_bool(&src_b);	
		return TCL_ERROR;
	}
	if(init_rbac_bool(&dflt_b, policy, FALSE) != 0) {
		Tcl_AppendResult(interp, "error initializing default rules bool", (char *) NULL);
		free_rbac_bool(&src_b);	
		free_rbac_bool(&tgt_b);	
		return TCL_ERROR;
	}
	
	if(use_src) {
		if(match_rbac_rules(src_idx, IDX_ROLE, SRC_LIST, FALSE, tgt_is_role, &src_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching source", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
	}
	else {
		all_true_rbac_bool(&src_b, policy);
	}
	if(use_src && any) {
		if(match_rbac_rules(src_idx, IDX_ROLE, TGT_LIST, FALSE, TRUE, &tgt_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching target", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
		if(match_rbac_rules(src_idx, IDX_ROLE, DEFAULT_LIST, FALSE, TRUE, &dflt_b, policy) != 0) {
			Tcl_AppendResult(interp, "error matching default", (char *) NULL);
			free_rbac_bool(&src_b);	
			free_rbac_bool(&tgt_b);	
			free_rbac_bool(&dflt_b);	
			return TCL_ERROR;			
		}
	}
	else {
		
		if(use_tgt && tgt_is_role) {
			if(match_rbac_rules(tgt_idx, IDX_ROLE, TGT_LIST, FALSE, TRUE, &tgt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching target", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}
		}
		else if(use_tgt && !tgt_is_role) {
			if(match_rbac_rules(tgt_idx, tgt_type, TGT_LIST, FALSE, FALSE, &tgt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching target", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}			
		}
		else {
			all_true_rbac_bool(&tgt_b, policy);
		}
		if(use_dflt) {
			if(match_rbac_rules(dflt_idx, IDX_ROLE, DEFAULT_LIST, FALSE, FALSE, &dflt_b, policy) != 0) {
				Tcl_AppendResult(interp, "error matching default", (char *) NULL);
				free_rbac_bool(&src_b);	
				free_rbac_bool(&tgt_b);	
				free_rbac_bool(&dflt_b);	
				return TCL_ERROR;			
			}
		}
		else {
			all_true_rbac_bool(&dflt_b, policy);
		}
	}
	
	if(allow) {
		for(i = 0; i < policy->num_role_allow; i++) {
			if((!any && (src_b.allow[i] && tgt_b.allow[i])) ||
			   (any && (src_b.allow[i] || tgt_b.allow[i]))) {
				rt = append_role_allow_rule(&(policy->role_allow[i]), policy, buf);
				if(rt != 0) {
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending role allow rule", (char *) NULL);
					free_rbac_bool(&src_b);	
					free_rbac_bool(&tgt_b);	
					free_rbac_bool(&dflt_b);
					return TCL_ERROR;
				}
			}
		}
	}
	if(trans) {
		for(i =0; i < policy->num_role_trans; i++) {
			if((!any && (src_b.trans[i] && tgt_b.trans[i] && dflt_b.trans[i])) ||
			   (any && (src_b.trans[i] || tgt_b.trans[i] || dflt_b.trans[i]))) {
				rt = append_role_trans_rule(&(policy->role_trans[i]), policy, buf);
				if(rt != 0) {
					Tcl_DStringFree(buf);
					Tcl_ResetResult(interp);
					Tcl_AppendResult(interp, "error appending role_transition rule", (char *) NULL);
					free_rbac_bool(&src_b);	
					free_rbac_bool(&tgt_b);	
					free_rbac_bool(&dflt_b);
					return TCL_ERROR;
				}
			}
		}
	}
	
	Tcl_DStringResult(interp, buf);
	free_rbac_bool(&src_b);	
	free_rbac_bool(&tgt_b);	
	free_rbac_bool(&dflt_b);				
	return TCL_OK;	
}


/* Perform a range transition search.  Expected arguments are:
 *
 *  argv[1] - list of source types  (string)
 *  argv[2] - list of target types  (string)
 *  argv[3] - low level             (2-ple of sensitivity + list of categories)
 *  argv[4] - high level            (2-ple of sensitivity + list of categories)
 *  argv[5] - search type           ("", "exact", "subset", or "superset")
 *
 * If search type is "" then ignore argv[3] and argv[4].
 * Returns a list of range_transition indices.
 */
static int Apol_SearchRangeTransRules(ClientData clientData, Tcl_Interp *interp, int argc, const char *argv[])
{
        int *types[2] = {NULL, NULL}, num_types[2] = {0, 0};
        ap_mls_range_t range;
        unsigned search_type = 0;
        int *found_rules = NULL;
        int num_rules;
        int retval = TCL_ERROR;

        ap_mls_level_t low = {0, NULL, 0}, high = {0, NULL, 0};
        int i, j;
        Tcl_Obj *result_list_obj;

        if (argc != 6) {
		Tcl_SetResult(interp, "wrong # of args", TCL_STATIC);
		return TCL_ERROR;
	}

        for (i = 0; i < 2; i++) {
                Tcl_Obj *types_list_obj = Tcl_NewStringObj(argv[i + 1], -1);
                Tcl_Obj *types_obj;
                char *type_string;
                int num_list_objs, type_value;
                if (Tcl_ListObjLength(interp, types_list_obj, &num_list_objs) == TCL_ERROR) {
                        goto cleanup;
                }
                for (j = 0; j < num_list_objs; j++) {
                        if (Tcl_ListObjIndex(interp, types_list_obj, j, &types_obj) == TCL_ERROR) {
                                goto cleanup;
                        }
                        assert(types_obj != NULL);
                        type_string = Tcl_GetString(types_obj);
                        if ((type_value = get_type_idx(type_string, policy)) < 0) {
                                Tcl_AppendResult(interp, "Unknown type ", type_string, NULL);
                                goto cleanup;
                        }
                        if (add_i_to_a(type_value, num_types + i, types + i)) {
                                Tcl_SetResult(interp, "Out of memory!", TCL_STATIC);
                                goto cleanup;
                        }
                }
        }
        if (num_types[0] > 0) {
                search_type |= AP_MLS_RTS_SRC_TYPE;
        }
        if (num_types[1] > 0) {
                search_type |= AP_MLS_RTS_TGT_TYPE;
        }
        
        if (argv[5][0] != '\0') {
                /* in a search type was given, then try to parse the range */
            /* FIX ME: not done yet
               
                if (strcmp(argv[5], "exact") == 0) {
                        search_type |= AP_MLS_RTS_RNG_EXACT;
                }
                else if (strcmp(argv[5], "subset") == 0) {
                        search_type |= AP_MLS_RTS_RNG_SUB;
                }
                else if (strcmp(argv[5], "superset") == 0) {
                        search_type |= AP_MLS_RTS_RNG_SUPER;
                }
                else {
                        Tcl_SetResult(interp, "Illegal search type given.", TCL_STATIC);
                        goto cleanup;
                }

                if (ap_tcl_level_string_to_level(interp, argv[3], &low) != 0) {
                        goto cleanup;
                }
                if (ap_tcl_level_string_to_level(interp, argv[4], &high) != 0) {
                        goto cleanup;
                }
            */
        }
        range.low = &low;
        range.high = &high;

        num_rules = ap_mls_range_transition_search(types[0], num_types[0], 
                                                   IDX_TYPE, types[1], 
                                                   num_types[1], IDX_TYPE, 
                                                   &range, search_type,
                                                   &found_rules, policy);
        if (num_rules < 0) {
                Tcl_SetResult(interp, "Error while executing range transition search.", TCL_STATIC);
		char buf[1024];
		sprintf(buf, "%d", num_rules);
		Tcl_AppendResult(interp, buf, NULL);
                goto cleanup;
        }
        
        result_list_obj = Tcl_NewListObj(0, NULL);
        for (i = 0; i < num_rules; i++) {
                Tcl_Obj *rule_obj = Tcl_NewIntObj(found_rules[i]);
                if (Tcl_ListObjAppendElement(interp, result_list_obj, rule_obj) == TCL_ERROR) {
                        goto cleanup;
                }
        }
        Tcl_SetObjResult(interp, result_list_obj);
        retval = TCL_OK;

 cleanup:
        free(types[0]);
        free(types[1]);
        ap_mls_level_free(&low);
        ap_mls_level_free(&high);
        free(found_rules);
        return retval;
}


int ap_tcl_rules_init(Tcl_Interp *interp) {

	Tcl_CreateCommand(interp, "apol_SearchTErules", Apol_SearchTErules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SearchConditionalRules", Apol_SearchConditionalRules, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetRoleRules", Apol_GetRoleRules, NULL, NULL);
        Tcl_CreateCommand(interp, "apol_SearchRangeTransRules", Apol_SearchRangeTransRules, NULL, NULL);

        return TCL_OK;
}
