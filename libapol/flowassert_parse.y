/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jtang@tresys.com 
 */
 
%{
#include <stdio.h>
#include <stdlib.h>

#include "infoflow.h"
#include "policy.h"
#include "policy-query.h"
#include "util.h"

#include "flowassert.h"
#include "symtable.h"

extern int flowerror (char *msg);
extern int flowlex (void);
extern int flow_scan_string (char * const);
extern unsigned long flowassert_lineno;

/* these options are set by execute_flow_assertion() */
static policy_t *current_policy = NULL;
static bool_t short_circuit; 
static llist_t *flowassert_results;

/* the following VA_ARGS throws a warning under GCC -ansi, though it
   is legal under C99 */
#define DIE(...) do { (void) fprintf (stderr, __VA_ARGS__); exit (-1); } while (0);

static symbol_t *init_lvalue (char *varname);
static bool_t dereference_variable (char *symbol_name);
static void init_flow_assert (enum assert_mode assert_mode);
static bool_t append_type_or_attr (char *objname);
static bool_t remove_type_or_attr (char *objname);
static bool_t append_object (char *objname);
static int execute_assert (void);

/* pointer to a created flow_assert_t */
static flow_assert_t *current_assert = NULL;

/* pointer to data struction in which type identifiers should be added */
static llist_t *current_list = NULL;

/* pointer to current assert type in which object classes should be added */
static llist_node_t *recent_list = NULL;

%}

%union {
        int i;
        char *s;
}

%token NOFLOW MUSTFLOW ONLYFLOW
%token <s> IDENTIFIER VARNAME
%token <i> NUMBER

%left LOWER_THAN_ALL
%left '{'
%left NUMBER
%left ';'
                        
%%

cmds:           cmd cmds
        |       /* empty */
        ;

cmd:            assignment ';'
        |       assert ';'
        |       error ';' { yyerrok; }
        ;

assignment:     VARNAME { current_list = init_lvalue ($1)->value;
                          free ($1); } '=' type_or_list
        ;

assert:         assert_type from_list to_list exceptions_list weight {
                    int assert_result = execute_assert ();
                    if (assert_result == FLOW_ASSERT_FAIL &&
                        short_circuit == TRUE) {
                        YYABORT;
                    }
                }
        ;

assert_type:    NOFLOW    { init_flow_assert (FLOW_ASSERT_NOFLOW_MODE);   }
        |       MUSTFLOW  { init_flow_assert (FLOW_ASSERT_MUSTFLOW_MODE); }
        |       ONLYFLOW  { init_flow_assert (FLOW_ASSERT_ONLYFLOW_MODE); }
        ;

from_list:      { current_list = current_assert->from_list; } type_or_list
        ;
         
to_list:        { current_list = current_assert->to_list; }   type_or_list
        ;

exceptions_list: %prec LOWER_THAN_ALL /* empty */
        |       { current_list = current_assert->via_list; }  type_or_list
        ;

weight:         %prec LOWER_THAN_ALL /* empty */
        |       NUMBER { current_assert->min_weight = $1; }
        ;

type_or_list:   type
        |       '{' type_list '}' objclass_or_list
        ;

type_list:      type type_list
        |       type
        ;

type:           typeid objclass_or_list
        ;

typeid:         '*'        { (void) append_type_or_attr (NULL); }
        |       IDENTIFIER {
                    if ((append_type_or_attr ($1)) == FALSE) {
                        /*flowwarn ("Unknown attribute or type `%s'.", $1);*/
                        flowassert_add_error_result (FLOW_ASSERT_UNKNOWN_TYPE);
                        free ($1);
                        YYERROR;
                    }
                    free ($1);
                }
        |       '-' IDENTIFIER {
                    if ((remove_type_or_attr ($2)) == FALSE) {
                        /*flowwarn ("Unknown attribute or type `%s'.", $2);*/
                        flowassert_add_error_result (FLOW_ASSERT_UNKNOWN_TYPE);
                        free ($2);
                        YYERROR;
                    }
                    free ($2);
                }
        |       VARNAME {
                    if ((dereference_variable ($1)) == FALSE) {
                        /*flowwarn ("Variable `%s' undeclared.", $1);*/
                        flowassert_add_error_result (FLOW_ASSERT_UNKNOWN_VARIABLE);
                        free ($1);
                        YYERROR;
                    }
                    free ($1);
                }
        ;

objclass_or_list: /* empty */
        |       ':' objclass
        |       ':' '{' objclass_list '}'
        ;

objclass:       IDENTIFIER {
                    if ((append_object ($1)) == FALSE) {
                        /*flowwarn ("Unknown object class `%s'.", $1);*/
                        flowassert_add_error_result (FLOW_ASSERT_UNKNOWN_CLASS);
                        free ($1);
                        YYERROR;
                    }
                    free ($1);
                }
        ;

objclass_list:  objclass objclass_list
        |       objclass
        ;

%%

/* Executes a series of assertion statements.  Returns a linked
   list of flow_assert_results_t.  Caller is responsible for free()ing
   the list; see flow_assert_results_destroy(). */
llist_t *execute_flow_assertion (char *assertion_contents, policy_t *policy,
                                 bool_t short_circuit_while_executing) {
        current_policy = policy;
        short_circuit = short_circuit_while_executing;
        flow_scan_string (assertion_contents);
        if ((flowassert_results = ll_new ()) == NULL) {
                DIE ("Out of memory.\n");
        }
        flowassert_lineno = 1;
        (void) flowparse ();
        return flowassert_results;
}


/* Adds a single node to the [hopefully initialized] assert_results
   list. */
void flowassert_add_error_result (int error_code) {
        flow_assert_results_t *assert_results;
        if ((assert_results = flow_assert_results_create ()) == NULL) {
                DIE ("Out of memory while creating results\n");
        }
        assert_results->rule_lineno = flowassert_lineno;
        assert_results->assert_result = error_code;
        if (ll_append_data (flowassert_results, assert_results) != 0) {
                DIE ("Out of memory.\n");
        }
}


/* Initializes a variable.  If the variable does not yet exist create
   one and add it to the symbol table.  Otherwise clear its old
   content. */
static symbol_t *init_lvalue (char *varname) {
        symbol_t *sym = get_symbol (varname);
        if (sym == NULL) {
                if ((sym = new_symbol (varname)) == NULL) {
                        DIE ("Out of memory.\n");
                }
        }
        else {
                ll_free (sym->value, flow_assert_id_destroy);
                sym->value = ll_new ();
        }
        return sym;
}


/* Check if a variable exists within the symbol table.  If so, copy
   all of its contents to the list (second paramenter) and return
   TRUE.  Otherwise if variable does not exist return FALSE. */
static bool_t dereference_variable (char *symbol_name) {
        symbol_t *sym = get_symbol (symbol_name);
        llist_node_t *node_ptr;
        if (sym == NULL) {
                return FALSE;
        }
        recent_list = current_list->tail;
        for (node_ptr = sym->value->head; node_ptr != NULL;
             node_ptr = node_ptr->next) {
                if ((ll_append_data (current_list, node_ptr->data)) != 0) {
                        DIE ("Error while appending in dereference\n");
                }
        }
        if (recent_list == NULL) {
                recent_list = current_list->head;
        }
        else {
                recent_list = recent_list->next;
        }
        return TRUE;
}


/* Initializes the current assert context. */
static void init_flow_assert (enum assert_mode assert_mode) {
        if ((current_assert = flow_assert_create ()) == NULL) {
                DIE ("Could not initialize assert\n");
        }
        current_assert->assert_mode = assert_mode;
}


/* Adds a type or attribute to the current list.  Returns TRUE if the
   name was found, FALSE otherwise. */
static bool_t append_type_or_attr (char *name) {
        int NO_TYPE = FLOW_ASSERT_STAR - 1;
        int type_id, num_types = 1, i;
        int *type_id_list = NULL;
        type_id = NO_TYPE;

        if (name == NULL) {
                type_id = FLOW_ASSERT_STAR;
        } else {
                int attrib_index;
                if ((attrib_index = get_attrib_idx (name, current_policy))
                    >= 0) {
                        if (get_attrib_types (attrib_index, &num_types,
                                         &type_id_list, current_policy) != 0) {
                                DIE ("Out of memory\n");
                        }
                }
                else if ((type_id = get_type_idx (name, current_policy)) <= 0){
                        return FALSE;
                }
        }
        for (i = 0; i < num_types; i++) {
                flow_assert_id_t *flow_assert_id;
                if (type_id == NO_TYPE) {
                        type_id = type_id_list [i];
                }
                if ((flow_assert_id = calloc (1, sizeof (*flow_assert_id)))
                    == NULL) {
                        DIE ("Out of memory\n");
                }
                flow_assert_id->type_id = type_id;
                if (ll_append_data (current_list, flow_assert_id) != 0) {
                        DIE ("Error while appending type\n");
                }
                if (i == 0) {
                        recent_list = current_list->tail;
                }
                type_id = NO_TYPE;
        }
        free (type_id_list);
        return TRUE;
}


/* Remove a type or attribute from the current list.  Returns TRUE if
   the name was found, FALSE otherwise. */
static bool_t remove_type_or_attr (char *name) {
        int type_id = -1, num_types = 1, attrib_index, i;
        int *type_id_list = NULL;
        if ((attrib_index = get_attrib_idx (name, current_policy)) >= 0) {
                if (get_attrib_types (attrib_index, &num_types,
                                      &type_id_list, current_policy) != 0) {
                        DIE ("Out of memory\n");
                }
        }
        else if ((type_id = get_type_idx (name, current_policy)) <= 0) {
                return FALSE;
        }
        for (i = 0; i < num_types; i++) {
                llist_node_t *node;
                if (type_id == -1) {
                        type_id = type_id_list [i];
                }
                node = current_list->head;
                while (node != NULL) {
                        flow_assert_id_t *node_id =
                                (flow_assert_id_t *) node->data;
                        if (node_id->type_id == type_id) {
                                if (ll_unlink_node (current_list, node) != 0) {
                                        DIE ("Error while unlinking\n");
                                }
                                if (recent_list == node) {
                                        recent_list = node->next;
                                }
                                node = ll_node_free (node,
                                                     flow_assert_id_destroy);
                        }
                        else {
                                node = node->next;
                        }
                }
                type_id = -1;
        }
        free (type_id_list);
        return TRUE;
}


/* Adds an object class specifier to the most recently specified
   type(s).  If the object class name is unknown then returns
   FALSE. */
static bool_t append_object (char *objname) {
        /* FIX ME - for now, completely disable object classes
         * because infoquery.c does not return all possible paths
        int obj_id = get_obj_class_idx (objname, current_policy);
        llist_node_t *node;
        if (obj_id == -1) {
                return FALSE;
        }
        for (node = recent_list; node != NULL; node = node->next) {
                flow_assert_id_t *current_id = (flow_assert_id_t *) node->data;
                if (add_i_to_a (obj_id, &(current_id->num_obj_classes),
                                &(current_id->obj_classes)) != 0) {
                        DIE ("Out of memory\n");
                }
        }
        return TRUE;
        */
        return FALSE;
}


/* Executes the most recently [correctly] parsed assert.  If
   conflict(s) was found then display to stderr the offending rules if
   QUIET != true.  Returns 0 if conflict found, 1 on success, or -1 if
   assert was incorrectly formatted.  free()s the current assert
   regardless of result of executing it. */
static int execute_assert (void) {
        flow_assert_results_t *assert_results;

        if ((assert_results = flow_assert_results_create ()) == NULL) {
                DIE ("Out of memory!\n");
        }
        assert_results->mode = current_assert->assert_mode;
        assert_results->rule_lineno = flowassert_lineno;
        assert_results->assert_result =
                flow_assert_execute (current_assert, current_policy,
                                     assert_results, short_circuit);
        if (ll_append_data (flowassert_results, assert_results) != 0) {
                DIE ("Out of memory!\n");
        }
        flow_assert_destroy (current_assert);
        return assert_results->assert_result;
}
