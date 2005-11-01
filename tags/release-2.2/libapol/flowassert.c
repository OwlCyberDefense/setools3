/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Jason Tang (jtang@tresys.com)
 */

#include <assert.h>

#include "flowassert.h"
#include "infoflow.h"
#include "perm-map.h"
#include "policy.h"
#include "util.h"

static int check_noflow (flow_assert_t *assert, iflow_query_t *iflow_query,
                         iflow_transitive_t *trans,
                         flow_assert_results_t *assert_results,
                         policy_t *policy);
static int check_mustflow (flow_assert_t *assert, iflow_query_t *iflow_query,
                           iflow_transitive_t *trans,
                           flow_assert_results_t *assert_results,
                           policy_t *policy);
static int check_onlyflow (flow_assert_t *assert, iflow_query_t *iflow_query,
                           iflow_transitive_t *trans,
                           flow_assert_results_t *assert_results,
                           policy_t *policy);
static bool_t is_type_in_path (iflow_t *iflow, int num_iflows,
                               flow_assert_id_t *type_id,
                               policy_t *policy);
static int append_assert_id (llist_t *target_list,
                             flow_assert_id_t *source_id);
static int add_assert_result (flow_assert_results_t *assert_results,
                              int start_type, int end_type, int via_type,
                              iflow_path_t *iflow, policy_t *policy);

/* Initializes a flow assert object by zeroing its field and
 * ll_new()ing the linked lists within.  Returns a pointer to the
 * assert object, NULL on failure. */
flow_assert_t *flow_assert_create (void) {
        flow_assert_t *assert;
        if ((assert = calloc (1, sizeof (*assert))) == NULL) {
                return NULL;
        }
        assert->assert_mode = FLOW_ASSERT_INVALID_MODE;
        assert->min_weight = 0;
        assert->from_list = assert->to_list = assert->via_list = NULL;
        if ((assert->from_list = ll_new ()) == NULL) {
                flow_assert_destroy (assert);
                return NULL;
        }
        if ((assert->to_list = ll_new ()) == NULL) {
                flow_assert_destroy (assert);
                return NULL;
        }
        if ((assert->via_list = ll_new ()) == NULL) {
                flow_assert_destroy (assert);
                return NULL;
        }
        return assert;
}


/* Destroys a assert object by ll_free()ing all elements within as
 * well as free()ing the assert object itself. */
void flow_assert_destroy (flow_assert_t *assert) {
        if (assert != NULL) {
                ll_free (assert->from_list, flow_assert_id_destroy);
                ll_free (assert->to_list, flow_assert_id_destroy);
                ll_free (assert->via_list, flow_assert_id_destroy);
                free (assert);
        }
}


/* Free a pointer to a flow_assert_id_t, including itself.  This
 * function is mainly used as the second parameter to ll_free().  */
void flow_assert_id_destroy (void *ptr) {
        flow_assert_id_t *flow_assert_id = (flow_assert_id_t *) ptr;
        if (flow_assert_id != NULL) {
                free (flow_assert_id->obj_classes);
                free (flow_assert_id);
        }
}


/* Allocates space for a flow_assert_results_t and initializes the
 * structure.  Returns a pointer to the space.  */
flow_assert_results_t *flow_assert_results_create (void) {
        flow_assert_results_t *flow_assert_results;
        if ((flow_assert_results = calloc (1, sizeof (*flow_assert_results)))
            == NULL) {
                return NULL;
        }
        return flow_assert_results;
}

/* Free a pointer to the results from an assert and the pointer
 * itself.  This function is mainly used as the second parameter to
 * ll_free(). */
void flow_assert_results_destroy (void *assert_results) {
        flow_assert_results_t *results =
                (flow_assert_results_t *) assert_results;
        if (results != NULL) {
                int i;
                for (i = 0; i < results->num_rules; i++) {
                        free (results->rules [i].rules);
                }
                free (results->rules);
                free (results);
        }
}


/* Returns FLOW_ASSERT_VALID if assert succeeds.  Returns
 * FLOW_ASSERT_FAIL if failed (e.g., noflow actually found a flow).
 * Returns FLOW_ASSERT_BAD_FORMAT if assert parameters are invalid.
 * Returns FLOW_ASSERT_ERROR on all other errors, such as out of
 * memory. */
int flow_assert_execute (flow_assert_t *assert,
                         policy_t *policy,
                         flow_assert_results_t *assert_results,
                         bool_t abort_after_first_conflict) {
        llist_t *todo_list = NULL;
        llist_node_t *from_pointer, *to_pointer, *via_pointer;
        llist_node_t *todo_pointer;
        iflow_query_t *iflow_query = NULL;
        iflow_transitive_t *iflow_trans = NULL;
        int result = FLOW_ASSERT_VALID;

        /* expand the source type(s) in case a star is given */
        if ((todo_list = ll_new ()) == NULL) {
                result = FLOW_ASSERT_ERROR;
                goto cleanup;
        }
        from_pointer = assert->from_list->head;
        while (from_pointer != NULL) {
                flow_assert_id_t *from_assert_id =
                        (flow_assert_id_t *) from_pointer->data;
                int start_id, end_id, i;
                if (from_assert_id->type_id == FLOW_ASSERT_STAR) {
                        /* expand asterisk here */
                        start_id = 1;
                        end_id = num_types (policy) - 1;
                } else {
                        start_id = end_id = from_assert_id->type_id;
                }
                for (i = start_id; i <= end_id; i++) {
                        if (append_assert_id (todo_list, from_assert_id) != 0){
                                result = FLOW_ASSERT_ERROR;
                                goto cleanup;
                        }
                        ((flow_assert_id_t *)todo_list->tail->data)->type_id=i;
                }
                from_pointer = from_pointer->next;
        }

        /* actually execute each assert */
        todo_pointer = todo_list->head;
        while (todo_pointer != NULL && (result==FLOW_ASSERT_VALID ||
                                        abort_after_first_conflict == FALSE)) {
                int check_result;
                /* construct an infoflow assert */
                flow_assert_id_t *todo_assert_id =
                        (flow_assert_id_t *) todo_pointer->data;
                if ((iflow_query = iflow_query_create ()) == NULL) {
                        result = FLOW_ASSERT_ERROR;
                        goto cleanup;
                }
                iflow_query->start_type = todo_assert_id->type_id;
                iflow_query->direction = IFLOW_OUT;
                iflow_query->num_end_types = 0;
        
                to_pointer = assert->to_list->head;
                while (to_pointer != NULL) {
                        flow_assert_id_t *to_assert =
                                (flow_assert_id_t *) to_pointer->data;
                        int id = to_assert->type_id;
                        if (id == FLOW_ASSERT_STAR) {  /* star was requested */
                                free (iflow_query->end_types);
                                iflow_query->end_types = NULL;
                                iflow_query->num_end_types = 0;
                        }
                        else {
                                if (iflow_query_add_end_type (iflow_query, id)
                                    != 0) {
                                        result = FLOW_ASSERT_ERROR;
                                        goto cleanup;
                                }
                        }
                        to_pointer = to_pointer->next;
                }

                /* check that exceptions list is legal */
                via_pointer = assert->via_list->head;
                while (via_pointer != NULL) {
                        flow_assert_id_t *via_assert =
                                (flow_assert_id_t *) via_pointer->data;
                        int id = via_assert->type_id;
                        if (id == FLOW_ASSERT_STAR) {
                                /* star not allowed in exceptions list */
                                result = FLOW_ASSERT_BAD_FORMAT;
                                goto cleanup;
                        }
                        via_pointer = via_pointer->next;
                }

                iflow_query->min_weight = assert->min_weight;
                
                /* execute it */
                if ((iflow_trans = iflow_transitive_flows(policy, iflow_query))
                    == NULL) {
                        result = FLOW_ASSERT_BAD_FORMAT;
                        goto cleanup;
                }

                /* interpret results */
                switch (assert->assert_mode) {
                case FLOW_ASSERT_NOFLOW_MODE: {
                        check_result = check_noflow
                                (assert, iflow_query, iflow_trans,
                                 assert_results, policy);
                        break;
                }                
                case FLOW_ASSERT_MUSTFLOW_MODE: {
                        check_result = check_mustflow
                                (assert, iflow_query, iflow_trans,
                                 assert_results, policy);
                        break;
                }
                case FLOW_ASSERT_ONLYFLOW_MODE: {
                        check_result = check_onlyflow
                                (assert, iflow_query, iflow_trans,
                                 assert_results, policy);
                        break;
                }
                default: {
                        /* invalid assertion mode */
                        result = FLOW_ASSERT_BAD_FORMAT;
                        goto cleanup;
                }
                }
                if (check_result != FLOW_ASSERT_VALID) {
                        result = check_result;
                }
                iflow_query_destroy (iflow_query);
                iflow_query = NULL;
                iflow_transitive_destroy (iflow_trans);
                iflow_trans = NULL;
                todo_pointer = todo_pointer->next;
        }

 cleanup:
        ll_free (todo_list, flow_assert_id_destroy);
        if (iflow_query != NULL) {
                iflow_query_destroy (iflow_query);
        }
        if (iflow_trans != NULL) {
                iflow_transitive_destroy (iflow_trans);
        }
        return result;
}


/* Returns FLOW_ASSERT_VALID if there is no flow found,
 * FLOW_ASSERT_FAIL if flow found that was not listed as an exception,
 * FLOW_ASSERT_ERROR upon error.  Read this as "no flow from A to B
 * except through an element z in C". */
static int check_noflow (flow_assert_t *assert, iflow_query_t *iflow_query,
                         iflow_transitive_t *trans,
                         flow_assert_results_t *assert_results,
                         policy_t *policy) {
        int result = FLOW_ASSERT_VALID;
        int end_type_index;
        for (end_type_index = 0; end_type_index < trans->num_end_types;
             end_type_index++) {
                int end_type = trans->end_types [end_type_index];
                iflow_path_t *path = trans->paths [end_type_index];
                while (path != NULL) {
                        iflow_t *iflow = path->iflows;
                        bool_t illegal_path_found = TRUE;
                        llist_node_t *type_node = assert->via_list->head;
                        while (type_node != NULL) {
                                flow_assert_id_t *via_id =
                                        (flow_assert_id_t *)type_node->data;
                                if (is_type_in_path
                                    (iflow, path->num_iflows, via_id, policy)
                                    == TRUE) {
                                        illegal_path_found = FALSE;
                                        break;
                                }
                                type_node = type_node->next;
                        }
                        if (illegal_path_found == TRUE) {
                                if (add_assert_result
                                    (assert_results, iflow_query->start_type,
                                     end_type, -1, path, policy) == -1) {
                                        return FLOW_ASSERT_ERROR;
                                }
                                result = FLOW_ASSERT_FAIL;
                        }
                        path = path->next;
                }
        }
        return result;
}


/* Returns FLOW_ASSERT_VALID if all flows accounted found,
 * FLOW_ASSERT_FAIL if flow not found, FLOW_ASSERT_ERROR upon error.
 * Read this as "for all elements z in C, there must be a flow from A
 * to B through z".  B may not have an ASSERT_STAR within. */
static int check_mustflow (flow_assert_t *assert, iflow_query_t *iflow_query,
                           iflow_transitive_t *trans,
                           flow_assert_results_t *assert_results,
                           policy_t *policy) {
        int result = FLOW_ASSERT_VALID;
        int end_type_index;
        llist_node_t *to_pointer;
        for (end_type_index = 0; end_type_index < trans->num_end_types;
             end_type_index++) {
                /* build a copy of the via_list.  as each mustflow
                   within trans is found, mark it off the copy by
                   setting its flag.  at the end, if any from
                   via_copy_list are unset then mustflow failed. */
                int end_type = trans->end_types [end_type_index];   
                iflow_path_t *path = trans->paths [end_type_index];
                llist_t *via_copy_list;
                llist_node_t *orig_via_pointer = assert->via_list->head;
                llist_node_t *via_pointer;
                if ((via_copy_list = ll_new ()) == NULL) {
                        return FLOW_ASSERT_ERROR;
                }
                while (orig_via_pointer != NULL) {
                        flow_assert_id_t *orig_assert_id =
                                orig_via_pointer->data;
                        if (append_assert_id (via_copy_list, orig_assert_id)
                            != 0) {
                                ll_free (via_copy_list,flow_assert_id_destroy);
                                return FLOW_ASSERT_ERROR;
                        }
                        orig_via_pointer = orig_via_pointer->next;
                }
                while (path != NULL) {
                        iflow_t *iflow = path->iflows;
                        via_pointer = via_copy_list->head;
                        while (via_pointer != NULL) {
                                flow_assert_id_t *via_id =
                                        (flow_assert_id_t *)via_pointer->data;
                                if (is_type_in_path
                                    (iflow, path->num_iflows, via_id, policy)
                                    == TRUE) {
                                        via_id->flags = 1;
                                }
                                via_pointer = via_pointer->next;
                        }
                        path = path->next;
                }
                /* examine everything in via_copy_list; if any items
                   are still not set then mustflow failed */
                via_pointer = via_copy_list->head;
                while (via_pointer != NULL) {
                        flow_assert_id_t *via_id =
                                (flow_assert_id_t *) via_pointer->data;
                        if (via_id->flags == 0) {
                                if (result == FLOW_ASSERT_VALID) {
                                        result = FLOW_ASSERT_FAIL;
                                }
                                if (add_assert_result
                                    (assert_results, iflow_query->start_type,
                                     end_type, via_id->type_id, NULL, policy)
                                    == -1) {
                                        result = FLOW_ASSERT_ERROR;
                                }
                        }
                        via_pointer = via_pointer->next;
                }
                ll_free (via_copy_list, flow_assert_id_destroy);
        }
        /* ensure that all items within assert->to_list have a path */
        to_pointer = assert->to_list->head;
        while (to_pointer != NULL) {
                flow_assert_id_t *to_id = (flow_assert_id_t *)to_pointer->data;
                bool_t path_found = FALSE;
                if (to_id->type_id == FLOW_ASSERT_STAR) {
                        /* kind of late to be checking for this, but oh well */
                        return FLOW_ASSERT_BAD_FORMAT;
                }
                for (end_type_index = 0; end_type_index < trans->num_end_types;
                     end_type_index++) {
                        int end_type = trans->end_types [end_type_index];   
                        if (end_type == to_id->type_id) {
                                path_found = TRUE;
                                break;
                        }
                }
                if (path_found == FALSE) {
                        if (add_assert_result
                            (assert_results, iflow_query->start_type,
                             to_id->type_id, -1, NULL, policy) == -1) {
                                return FLOW_ASSERT_ERROR;
                        }
                        result = FLOW_ASSERT_FAIL;
                }
                to_pointer = to_pointer->next;
        }
        return result;
}


/* Returns FLOW_ASSERT_VALID if for every flow found it was through
 * one of the items in via_list, FLOW_ASSERT_FAIL if flow found that
 * was not listed as an exception, FLOW_ASSERT_ERROR upon error.  Read
 * this as "there must be a flow(s) from A to B, and that flow can
 * only be through an element z in C" */
static int check_onlyflow (flow_assert_t *assert, iflow_query_t *iflow_query,
                           iflow_transitive_t *trans,
                           flow_assert_results_t *assert_results,
                           policy_t *policy) {
        int result = FLOW_ASSERT_VALID;
        int end_type_index;
        llist_node_t *to_pointer;
        if (assert->via_list->head == NULL) {
                return FLOW_ASSERT_BAD_FORMAT;
        }
        for (end_type_index = 0; end_type_index < trans->num_end_types;
             end_type_index++) {
                int end_type = trans->end_types [end_type_index];
                iflow_path_t *path = trans->paths [end_type_index];
                while (path != NULL) {
                        iflow_t *iflow = path->iflows;
                        bool_t path_found = FALSE;
                        llist_node_t *type_node = assert->via_list->head;
                        while (type_node != NULL && path_found == FALSE) {
                                flow_assert_id_t *via_id =
                                        (flow_assert_id_t *)type_node->data;
                                if (is_type_in_path
                                    (iflow, path->num_iflows, via_id, policy)
                                    == TRUE) {
                                        path_found = TRUE;
                                }
                                type_node = type_node->next;
                        }
                        if (path_found == FALSE) {
                                if (add_assert_result
                                    (assert_results, iflow_query->start_type,
                                     end_type, -1, path, policy) == -1) {
                                        return FLOW_ASSERT_ERROR;
                                }
                                result = FLOW_ASSERT_FAIL;
                        }
                        path = path->next;
                }
        }
        /* ensure that all items within assert->to_list have a path */
        to_pointer = assert->to_list->head;
        while (to_pointer != NULL) {
                flow_assert_id_t *to_id = (flow_assert_id_t *)to_pointer->data;
                bool_t path_found = FALSE;
                for (end_type_index = 0; end_type_index < trans->num_end_types;
                     end_type_index++) {
                        int end_type = trans->end_types [end_type_index];   
                        if (end_type == to_id->type_id) {
                                path_found = TRUE;
                                break;
                        }
                }
                if (path_found == FALSE) {
                        if (add_assert_result
                            (assert_results, iflow_query->start_type,
                             to_id->type_id, -1, NULL, policy) == -1) {
                                return FLOW_ASSERT_ERROR;
                        }
                        result = FLOW_ASSERT_FAIL;
                }
                to_pointer = to_pointer->next;
        }
        return result;
}

/* Returns TRUE if assert_id is in any part of the flow iflow, FALSE
 * otherwise. */   
static bool_t is_type_in_path (iflow_t *iflow, int num_iflows,
                               flow_assert_id_t *assert_id,
                               policy_t *policy) {
        int flow_num;
        int type_id = assert_id->type_id;
        for (flow_num = 0; flow_num < num_iflows; flow_num++) {
                iflow_t *flow = iflow + flow_num;
                if (flow->start_type == type_id || flow->end_type == type_id) {
                        int i;
                        bool_t maybe_match = FALSE;            
                        /* type matched; check object classes, if any */
                        if (assert_id->num_obj_classes == 0) {
                                maybe_match = TRUE;
                        }
                        for (i = 0; i < flow->num_obj_classes &&
                                     maybe_match == FALSE; i++) {
                                if ((flow->obj_classes + i)->num_rules > 0 &&
                                    find_int_in_array(i,assert_id->obj_classes,
                                            assert_id->num_obj_classes) >= 0) {
                                        maybe_match = TRUE;
                                }
                        }
                        return TRUE;
                }
        }
        return FALSE;
}


/* Takes a flow_assert_id_t and appends a clone of it to the tail of
 * target_list.  Returns 0 on success, 1 on error. */
static int append_assert_id (llist_t *target_list,
                             flow_assert_id_t *source_id) {
        flow_assert_id_t *new_id = malloc (sizeof (*new_id));
        if (new_id == NULL) {
                return 1;
        }
        new_id->type_id = source_id->type_id;
        new_id->obj_classes = NULL;
        new_id->flags = 0;
        if ((new_id->num_obj_classes = source_id->num_obj_classes) > 0 &&
            copy_int_array (&(new_id->obj_classes), source_id->obj_classes,
                            source_id->num_obj_classes) != 0) {
                free (new_id);
                return 1;
        }            
        if ((ll_append_data (target_list, new_id)) != 0) {
                free (new_id->obj_classes);
                free (new_id);
                return 1;
        }
        return 0;
}


/* A helper routine that appends a new assert result to to the current
 * results list.  Returns 0 on success, -1 on failure. */
static int add_assert_result (flow_assert_results_t *assert_results,
                              int start_type, int end_type, int via_type,
                              iflow_path_t *iflow_path, policy_t *policy) {
        int i;
        flow_assert_rule_t *assert_rule;
        if ((assert_rule = realloc (assert_results->rules,
                       (assert_results->num_rules + 1) * sizeof(*assert_rule)))
            == NULL) {
                return -1;
        }
        assert_results->rules = assert_rule;
        assert_rule = assert_results->rules + assert_results->num_rules;
        assert_rule->start_type = start_type;
        assert_rule->end_type = end_type;
        assert_rule->via_type = via_type;
        assert_rule->num_rules = 0;
        assert_rule->rules = NULL;
        assert_results->num_rules++;
        for (i = 0; iflow_path != NULL && i < iflow_path->num_iflows; i++) {
                iflow_t *iflow = iflow_path->iflows + i;
                int j;
                /* just get the first rule from the first object with
                 * rules */
                for (j = 0; j < iflow->num_obj_classes; j++) {
                        iflow_obj_class_t *obj_class = iflow->obj_classes + j;
                        if (obj_class->num_rules > 0) {
                                if (add_i_to_a (obj_class->rules [0],
                                                &assert_rule->num_rules,
                                                &assert_rule->rules) == -1) {
                                        return -1;
                                }
                                break;
                        }
                }
        }
        return 0;
}
