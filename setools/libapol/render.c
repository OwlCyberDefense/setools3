 /* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* render.c */

/* Utility functions to render aspects of a policy into strings */

/* TODO: Need to add all rule rendering functions below, and change the
 * TCL interface (and any other) to use these rather than do their own
 * thing.
 */
 

#include "util.h"
#include "policy.h"
#include "semantic/avhash.h"
#include "semantic/avsemantics.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* global with rule names */
char *rulenames[] = {"allow", "auditallow", "auditdeny", "dontaudit", "neverallow", "type_transition", 
			"type_member", "type_change", "clone", "allow", "role_transition", "user"};
 /* classes and perm strings */
static int re_append_cls_perms(ta_item_t *list, 
				bool_t iscls,		/* 1 if list is classes, 0 if not (i.e., permissions) */
				unsigned char flags, 	/* from av_item_t object */
				char **buf,
				int *buf_sz,
				policy_t *policy)
{
	ta_item_t *ptr;
	int multiple = 0;

	if(flags & (!iscls ? AVFLAG_PERM_TILDA : AVFLAG_NONE)) {
		if(append_str(buf, buf_sz, " ~") != 0)
			return -1;
		}
	else {
		if(append_str(buf, buf_sz, " ") != 0 )
			return -1;
	}
	if(list != NULL && list->next != NULL) {
		multiple = 1;
		if(append_str(buf, buf_sz, "{ ") != 0) 
			return -1;
	}
	if(flags & (!iscls ? AVFLAG_PERM_STAR : AVFLAG_NONE))
		if(append_str(buf, buf_sz, "* ") != 0)
			return -1;
		
	for(ptr = list; ptr != NULL; ptr = ptr->next) {
		assert( (iscls && ptr->type == IDX_OBJ_CLASS) || (!iscls && ptr->type == IDX_PERM) );
		if(iscls) {
			if(append_str(buf, buf_sz, policy->obj_classes[ptr->idx].name) != 0)
				return -1;
		}
		else {
			if(append_str(buf, buf_sz, policy->perms[ptr->idx]) != 0)
				return -1;
		}
		if(append_str(buf, buf_sz, " ") != 0)
			return -1;
	}
	
	if(multiple) {
		if(append_str(buf, buf_sz, "}") != 0)
			return -1;
	}
	return 0;	
}
 
static int append_type_attrib(char **buf, int *buf_sz, ta_item_t *tptr, policy_t *policy)
{
	if (append_str(buf, buf_sz, " ") != 0)  {
		free(buf);
		return -1;
	}
	if ((tptr->type & IDX_SUBTRACT)) {
		if (append_str(buf, buf_sz, "-") != 0)  {
			free(buf);
			return -1;
		}
	}
	if ((tptr->type & IDX_TYPE)) {
		if (append_str(buf, buf_sz, policy->types[tptr->idx].name) != 0)  {
			free(buf);
			return -1;
		}
	} else if(tptr->type & IDX_ATTRIB) {
		if (append_str(buf, buf_sz,  policy->attribs[tptr->idx].name) != 0)  {
			free(buf);
			return -1;
		}
	} else {
		free(buf);
		return -1;
	}
	return 0;
}
 
/* return NULL for error, mallocs memory, caller must free */
char *re_render_av_rule(bool_t 	addlineno, 	/* add policy.conf line  */
			int	idx, 		/* rule idx */
			bool_t is_au,		/* whether audit rules */
			policy_t *policy
			) 
{
	av_item_t *rule;
	ta_item_t *tptr;
	char *buf;
	int buf_sz;	
	int multiple = 0;
	char tbuf[APOL_STR_SZ+64];

	if(policy == NULL || !is_valid_av_rule_idx(idx, (is_au ? 0:1), policy)) {
		return NULL;
	}
	if(!is_au) 
		rule = &(policy->av_access[idx]);
	else
		rule = &(policy->av_audit[idx]);
	
	
	/* remember to init the buffer */
	buf = NULL;
	buf_sz = 0;
	
	if(addlineno) {
		sprintf(tbuf, "[%7lu] ", rule->lineno);
		if(append_str(&buf, &buf_sz, tbuf) != 0) {
			free(buf);
			return NULL;
		}
	}
		
	if(append_str(&buf, &buf_sz, rulenames[rule->type]) != 0) {
		return NULL;
	}
	
	/* source types */
	if(rule->flags & AVFLAG_SRC_TILDA) {
		if(append_str(&buf, &buf_sz, " ~") != 0) {
			free(buf);
			return NULL;
		}
	}
	else {
		if(append_str(&buf, &buf_sz, " ") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->src_types != NULL && rule->src_types->next != NULL) {
		multiple = 1;
		if(append_str(&buf, &buf_sz, "{") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		if(append_str(&buf, &buf_sz, "*") != 0) {
			free(buf);
			return NULL;
		}
	
	for(tptr = rule->src_types; tptr != NULL; tptr = tptr->next) {
		if (append_type_attrib(&buf, &buf_sz, tptr, policy) == -1)
			return NULL;
	}
	if(multiple) {
		if(append_str(&buf, &buf_sz, " }") != 0) {
			free(buf);
			return NULL;
		}
		multiple = 0;
	}
	
	/* tgt types */
	if(rule->flags & AVFLAG_TGT_TILDA) {
		if(append_str(&buf, &buf_sz, " ~") != 0) {
			free(buf);
			return NULL;
		}
	}
	else {
		if(append_str(&buf, &buf_sz, " ") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->tgt_types != NULL && rule->tgt_types->next != NULL) {
		multiple = 1;
		if(append_str(&buf, &buf_sz, "{") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		if(append_str(&buf, &buf_sz, "*") != 0) {
			free(buf);
			return NULL;
		}
				
	for(tptr = rule->tgt_types; tptr != NULL; tptr = tptr->next) {
		if (append_type_attrib(&buf, &buf_sz, tptr, policy) == -1)
			return NULL;
	}
	if(multiple) {
		if(append_str(&buf, &buf_sz, " }") != 0) {
			free(buf);
			return NULL;
		}
		multiple = 0;
	}
	if(append_str(&buf, &buf_sz, " :") != 0) {
		free(buf);
		return NULL;
	}
	
	/* classes */
	if(re_append_cls_perms(rule->classes, 1, rule->flags, &buf, &buf_sz, policy) != 0) {
		free(buf);
		return NULL;
	}
		
	/* permissions */
	if(re_append_cls_perms(rule->perms, 0, rule->flags, &buf, &buf_sz, policy)!= 0) {
		free(buf);
		return NULL;
	}

	if(append_str(&buf, &buf_sz, ";") != 0) {
		free(buf);
		return NULL;
	}
		
	return buf;
}

/* return NULL for error, mallocs memory, caller must free */
char *re_render_tt_rule(bool_t addlineno, int idx, policy_t *policy) 
{
	tt_item_t *rule;
	ta_item_t *tptr;
	char *buf;
	int buf_sz;	
	int multiple = 0;
	char tbuf[APOL_STR_SZ+64];
	
	if(policy == NULL || !is_valid_tt_rule_idx(idx,  policy)) {
		return NULL;
	}
	
	/* remember to init the buffer */
	buf = NULL;
	buf_sz = 0;
	rule = &(policy->te_trans[idx]);

	if(addlineno) {
		sprintf(tbuf, "[%7lu] ", rule->lineno);
		if(append_str(&buf, &buf_sz, tbuf) != 0) {
			free(buf);
			return NULL;
		}
	}

	if(append_str(&buf, &buf_sz, rulenames[rule->type]) != 0) {
		free(buf);
		return NULL;
	}

	/* source types */
	if(rule->flags & AVFLAG_SRC_TILDA)  {
		if(append_str(&buf, &buf_sz, " ~") != 0) {
			free(buf);
			return NULL;
		}
	}
	else
		if(append_str(&buf, &buf_sz, " ") != 0) {
			free(buf);
			return NULL;
		}
					
	if(rule->src_types != NULL && rule->src_types->next != NULL) {
		multiple = 1;
		if(append_str(&buf, &buf_sz, "{") != 0) {
			free(buf);
			return NULL;		
		}
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		if(append_str(&buf, &buf_sz, "*") != 0) {
			free(buf);
			return NULL;
		}
	
	for(tptr = rule->src_types; tptr != NULL; tptr = tptr->next) {
		if (append_type_attrib(&buf, &buf_sz, tptr, policy) == -1)
			return NULL;
	}
	if(multiple) {
		if(append_str(&buf, &buf_sz, " }") != 0) {
			free(buf);
			return NULL;
		}
		multiple = 0;
	}

	/* tgt types */
	if(rule->flags & AVFLAG_TGT_TILDA) {
		if(append_str(&buf, &buf_sz, " ~") != 0) {
			free(buf);
			return NULL;
		}
	}
	else {
		if(append_str(&buf, &buf_sz, " ") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->tgt_types != NULL && rule->tgt_types->next != NULL) {
		multiple = 1;
		if(append_str(&buf, &buf_sz, "{") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		if(append_str(&buf, &buf_sz, "*") != 0) {
			free(buf);
			return NULL;
		}
	
	for(tptr = rule->tgt_types; tptr != NULL; tptr = tptr->next) {
		if (append_type_attrib(&buf, &buf_sz, tptr, policy) == -1)
			return NULL;
	}
	if(multiple) {
		if(append_str(&buf, &buf_sz, " }") != 0) {
			free(buf);
			return NULL;
		}
		multiple = 0;
	}
	if(append_str(&buf, &buf_sz, " :") != 0) {
		free(buf);
		return NULL;
	}
			
	/* classes */
	if(re_append_cls_perms(rule->classes, 1, rule->flags, &buf, &buf_sz, policy) != 0) {
		free(buf);
		return NULL;
	}
		
	/* default type */
	if(rule->dflt_type.type == IDX_TYPE) {
		sprintf(tbuf, " %s", policy->types[rule->dflt_type.idx].name);
	}
	else if(rule->dflt_type.type == IDX_ATTRIB) {
		sprintf(tbuf, " %s", policy->attribs[rule->dflt_type.idx].name);
	}			
	else {
		fprintf(stderr, "Invalid index type: %d\n", rule->dflt_type.type);
		free(buf);
		return NULL;
	}	
	if(append_str(&buf, &buf_sz, tbuf) != 0) {
		free(buf);
		return NULL;
	}
	
	if(append_str(&buf, &buf_sz, ";") != 0) {
		free(buf);
		return NULL;
	}
		

	return buf;	

}

/* security contexts */
char *re_render_security_context(const security_con_t *context,
				 policy_t *policy
				 )
{
	char *buf, *name;
	int buf_sz;
	if(policy == NULL )
		return NULL;
	
	if(context != NULL && (!is_valid_type_idx(context->type, policy) || !is_valid_role_idx(context->role, policy) || 
			!is_valid_user_idx(context->user, policy)) )
		return NULL;

	/* initialize the buffer */
	buf = NULL;
	buf_sz = 0;

	/* handle case where initial SID does not have a context */
	if(context == NULL) {
		if(append_str(&buf, &buf_sz, "<no context>") != 0) 
			goto err_return;
		return buf;
	}

	/* render context */
	if(get_user_name2(context->user, &name, policy) != 0)
		goto err_return;
	if(append_str(&buf, &buf_sz, name) != 0) 
		goto err_return;
	free(name);
	if(append_str(&buf, &buf_sz, ":") != 0) 
		goto err_return;
	if(get_role_name(context->role, &name, policy) != 0) 
		goto err_return;
	if(append_str(&buf, &buf_sz, name) != 0) 
		goto err_return;
	free(name);
	if(append_str(&buf, &buf_sz, ":") != 0) 
		goto err_return;
	if(get_type_name(context->type, &name, policy) != 0) 
		goto err_return;
	if(append_str(&buf, &buf_sz, name) != 0) 
		goto err_return;
	free(name);	
	
	return buf;
err_return:
	if(buf != NULL) 
		free(buf);
	return NULL;	
}


char * re_render_initial_sid_security_context(int idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_initial_sid_idx(idx, policy) ) {
		return NULL;
	}
	return(re_render_security_context(policy->initial_sids[idx].scontext, policy));
}

/* render a AV/Type rule from av hash table; caller must free memory.
 * Return NULL on error. */

/* conditional states */
char *re_render_avh_rule_cond_state(avh_node_t *node, policy_t *p)
{
	char *t = NULL;
	int sz = 0, rt;
	
	if(node == NULL || p == NULL)
		return NULL;
	if(node->flags & AVH_FLAG_COND) {
		if(node->cond_list) {
			rt = append_str(&t, &sz, "CT");
		}
		else {
			rt = append_str(&t, &sz, "CF");
		}
	}
	else {
		rt = append_str(&t, &sz, "  ");
	}
	if(rt < 0)
		goto err_return;
	
	if(avh_is_enabled(node, p))
		rt = append_str(&t, &sz, " E: ");
	else
		rt = append_str(&t, &sz, " D: ");
	if(rt < 0)
		goto err_return;

		
	return t;
err_return:
	if(t != NULL)
		free(t);
	return NULL;	
}

/* source line numbers if not binary */
char *re_render_avh_rule_linenos(avh_node_t *node, policy_t *p)
{
	char *t = NULL;
	int rt, sz;
	avh_rule_t *r;
	static char buf[128];
	bool_t is_av;
	void *rlist;
	int rlist_num;
	unsigned long lineno;
	
	if(node == NULL || p == NULL)
		return NULL;
	
	if(is_binary_policy(p))
		return NULL;  /* no linenos to render */
	
	if(is_av_access_rule_type(node->key.rule_type)) {
		is_av = TRUE;
		rlist = p->av_access;
		rlist_num = p->num_av_access;
	}
	else if(is_av_audit_rule_type(node->key.rule_type)) {
		is_av = TRUE;
		rlist = p->av_audit;
		rlist_num = p->num_av_audit;
	}
	else if(is_type_rule_type(node->key.rule_type)) {
		is_av = FALSE;
		rlist = p->te_trans;
		rlist_num = p->num_te_trans;
	}
	else {
		assert(0);
		return NULL;
	}

	for(r = node->rules; r != NULL; r = r->next) {
		assert(r->rule < rlist_num);
		if(is_av) 
			lineno = ((av_item_t *)rlist)[r->rule].lineno;
		else
			lineno = ((tt_item_t *)rlist)[r->rule].lineno;
		sprintf(buf, "%ld", lineno);
		rt = append_str(&t, &sz, buf);
		if(rt < 0)
			goto err_return;
		if(r->next != NULL) {
			rt = append_str(&t, &sz, " ");
			if(rt < 0)
				goto err_return;
		}
	}

	return t;
err_return:
	if(t != NULL)
		free(t);
	return NULL;	
}

/* rule itself as it is in the hash */
char *re_render_avh_rule(avh_node_t *node, policy_t *p)
{
	char *t = NULL, *name;
	int sz = 0, rt, i;
	
	/* rule identifier */
	assert(node->key.rule_type >= RULE_TE_ALLOW && node->key.rule_type <= RULE_TE_CHANGE);
	if(append_str(&t, &sz, rulenames[node->key.rule_type]) != 0) 
		goto err_return;
	rt = append_str(&t, &sz, " ");
	if(rt < 0)
		goto err_return;
	
	/* source */
	assert(is_valid_type(p, node->key.src, FALSE));
	rt = get_type_name(node->key.src, &name, p);
	if(rt < 0)
		goto err_return;
	rt = append_str(&t, &sz, name);
	free(name);
	if(rt < 0)
		goto err_return;
	rt = append_str(&t, &sz, " ");
	if(rt < 0)
		goto err_return;
	
	/* target */
	assert(is_valid_type(p, node->key.tgt, FALSE));
	rt = get_type_name(node->key.tgt, &name, p);
	if(rt < 0)
		goto err_return;
	rt = append_str(&t, &sz, name);
	free(name);
	if(rt < 0)
		goto err_return;
	rt = append_str(&t, &sz, " : ");
	if(rt < 0)
		goto err_return;
	
	/* class */
	assert(is_valid_obj_class(p, node->key.cls));
	rt = get_obj_class_name(node->key.cls, &name, p);
	if(rt < 0)
		goto err_return;
	rt = append_str(&t, &sz, name);
	free(name);
	if(rt < 0)
		goto err_return;

	/* permissions (AV rules) or default type (Type rules) */
	if(node->key.rule_type <= RULE_MAX_AV) {
		/* permissions */
	/* TODO: skip this assertion for now; there is a bug in binpol */
	/*	assert(node->num_data > 0); */
		rt = append_str(&t, &sz, " { ");
		if(rt < 0)
			goto err_return;
		for(i = 0; i < node->num_data; i++) {
			rt = get_perm_name(node->data[i], &name, p);
			if(rt < 0)
				goto err_return;
			rt = append_str(&t, &sz, name);
			free(name);
			if(rt < 0)
				goto err_return;
			rt = append_str(&t, &sz, " ");
			if(rt < 0)
				goto err_return;
		}
		rt = append_str(&t, &sz, "};");
		if(rt < 0)
			goto err_return;
	}
	else {
		/* default type */
		assert(node->num_data == 1);
		rt = append_str(&t, &sz, " ");
		if(rt < 0)
			goto err_return;
		rt = get_type_name(node->data[0], &name, p);
		if(rt < 0)
			goto err_return;
		rt = append_str(&t, &sz, name);
		free(name);	
		rt = append_str(&t, &sz, " ;");
		if(rt < 0)
			goto err_return;
	}
				
	return t;
err_return:
	if(t != NULL)
		free(t);
	return NULL;
}

