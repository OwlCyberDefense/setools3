/**
 * @file infoflow-analysis.c
 * Implementation of the information flow analysis.
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

#include "policy-query-internal.h"
#include <apol/perm-map.h>

#include <errno.h>
#include <time.h>

/*
 * Nodes in the graph represent either a type used in the source
 * of an allow rule or the target: these defines are used to
 * represent which.
 */
#define APOL_INFOFLOW_NODE_SOURCE 0x0
#define APOL_INFOFLOW_NODE_TARGET 0x1

/*
 * These defines are used to color nodes in the graph algorithms.
 */
#define APOL_INFOFLOW_COLOR_WHITE 0
#define APOL_INFOFLOW_COLOR_GREY  1
#define APOL_INFOFLOW_COLOR_BLACK 2
#define APOL_INFOFLOW_COLOR_RED   3

typedef struct apol_infoflow_node apol_infoflow_node_t;
typedef struct apol_infoflow_edge apol_infoflow_edge_t;

struct apol_infoflow_graph {
	/** vector of apol_infoflow_node_t */
	apol_vector_t *nodes;
	/** vector of apol_infoflow_edge_t */
	apol_vector_t *edges;
        unsigned int mode, direction;
        regex_t *regex;
};

struct apol_infoflow_node {
	qpol_type_t *type;
	qpol_class_t *obj_class;
	/** one of APOL_INFOFLOW_NODE_SOURCE or APOL_INFOFLOW_NODE_TARGET */
	int node_type;
	/** vector of apol_infoflow_edge_t, pointing into the graph */
	apol_vector_t *in_edges;
	/** vector of apol_infoflow_edge_t, pointing into the graph */
	apol_vector_t *out_edges;
	unsigned char color;
	apol_infoflow_node_t *parent;
	int distance;
};

struct apol_infoflow_edge {
	/** vector of qpol_avrule_t, pointing into the policy */
	apol_vector_t *rules;
	/** pointer into a node within the graph */
	apol_infoflow_node_t *start_node;
	/** pointer into a node within the graph */
	apol_infoflow_node_t *end_node;
	int length;
};

/**
 * apol_infoflow_analysis_h encapsulates all of the paramaters of a
 * query.  It should always be allocated with
 * apol_infoflow_analysis_create() and deallocated with
 * apol_infoflow_analysis_destroy().  Limiting by ending_types,
 * obj_classes, intermed types, obj_class permissions is optional - if
 * the vector is empty then no limiting is done.
 *
 * All of the vectors except end_types should contain the items that
 * you want to not appear in the results.  end_types lists the types
 * that you do want to appear.
 */
struct apol_infoflow_analysis {
	unsigned int mode, direction;
	char *type, *result;
	apol_vector_t *class_perms;
	int min_weight;
};

struct apol_infoflow_result {
	qpol_type_t *start_type, *end_type;
	apol_vector_t *rules;
	unsigned int direction;
};

/******************** infoflow graph node routines ********************/

/**
 * Given a pointer to an apol_infoflow_node_t, free its space
 * including the pointer itself.  Does nothing if the pointer is
 * already NULL.
 *
 * @param data Node to free.
 */
static void apol_infoflow_node_free(void *data)
{
	apol_infoflow_node_t *node = (apol_infoflow_node_t *) data;
	if (node != NULL) {
		/* the edges themselves are owned by the graph, not by
		 * the node */
		apol_vector_destroy(&node->in_edges, NULL);
		apol_vector_destroy(&node->out_edges, NULL);
		free(node);
	}
}

struct apol_infoflow_node_key {
	qpol_type_t *type;
	qpol_class_t *obj_class;
	int node_type;
};

/**
 * Given an infoflow node and a key, returns 0 if they are the same,
 * non-zero if not.
 *
 * @param a Existing node within the infoflow graph.
 * @param b <i>Unused.</i>
 * @param data Pointer to a struct infoflow_node_key.
 *
 * @return 0 if the key matches a, non-zero if not.
 */
static int apol_infoflow_node_compare(const void *a, const void *b __attribute__ ((unused)), void *data)
{
	apol_infoflow_node_t *node = (apol_infoflow_node_t *) a;
	struct apol_infoflow_node_key *key = (struct apol_infoflow_node_key *) data;
	if (node->type == key->type &&
	    node->obj_class == key->obj_class &&
	    node->node_type == key->node_type) {
		return 0;
	}
	return -1;
}

/**
 * Attempt to allocate a new node, add it to the infoflow graph, and
 * return a pointer to it.  If there already exists a node with the
 * same type and object class then reuse that node.
 *
 * @param p Policy handler, for error reporting.
 * @param g Infoflow to which add the node.
 * @param type Type for the new node.
 * @param obj_class Objects class for the new node.
 * @param node_type Node type, one of APOL_INFOFLOW_NODE_SOURCE or
 * APOL_INFOFLOW_NODE_TARGET.
 *
 * @return Pointer an allocated node within the infoflow graph, or
 * NULL upon error.
 */
static apol_infoflow_node_t *apol_infoflow_graph_create_node(apol_policy_t *p,
							     apol_infoflow_graph_t *g,
							     qpol_type_t *type,
							     qpol_class_t *obj_class,
							     int node_type)
{
	struct apol_infoflow_node_key key = {type, obj_class, node_type};
	size_t i;
	apol_infoflow_node_t *node = NULL;
	if (apol_vector_get_index(g->nodes, NULL, apol_infoflow_node_compare, &key, &i) == 0) {
		node = (apol_infoflow_node_t *) apol_vector_get_element(g->nodes, i);
		return node;
	}
	if ((node = calloc(1, sizeof(*node))) == NULL ||
	    (node->in_edges = apol_vector_create()) == NULL ||
	    (node->out_edges = apol_vector_create()) == NULL ||
            apol_vector_append(g->nodes, node) < 0) {
		apol_infoflow_node_free(node);
		ERR(p, "Out of memory!");
		return NULL;
	}
	node->type = type;
	node->obj_class = obj_class;
	node->node_type = node_type;
	return node;
}

/******************** infoflow graph edge routines ********************/

/**
 * Given a pointer to an apol_infoflow_edge_t, free its space
 * including the pointer itself.  Does nothing if the pointer is
 * already NULL.
 *
 * @param data Edge to free.
 */
static void apol_infoflow_edge_free(void *data)
{
	apol_infoflow_edge_t *edge = (apol_infoflow_edge_t *) data;
	if (edge != NULL) {
		apol_vector_destroy(&edge->rules, NULL);
		free(edge);
	}
}

struct apol_infoflow_edge_key {
	apol_infoflow_node_t *start_node, *end_node;
};

/**
 * Given an infoflow edge and a key, returns 0 if they are the same,
 * non-zero if not.
 *
 * @param a Existing edge within the infoflow graph.
 * @param b <i>Unused.</i>
 * @param data Pointer to a struct infoflow_edge_key.
 *
 * @return 0 if the key matches a, non-zero if not.
 */
static int apol_infoflow_edge_compare(const void *a, const void *b __attribute__ ((unused)), void *data)
{
	apol_infoflow_edge_t *edge = (apol_infoflow_edge_t *) a;
	struct apol_infoflow_edge_key *key = (struct apol_infoflow_edge_key *) data;
	if (key->start_node != NULL && edge->start_node == key->start_node) {
		return -1;
	}
	if (key->end_node != NULL && edge->end_node == key->end_node) {
		return -1;
	}
	return 0;
}

/**
 * Attempt to allocate a new edge, add it to the infoflow graph, and
 * return a pointer to it.  If there already exists a edge from the
 * start node to the end node then reuse that edge.
 *
 * @param p Policy handler, for error reporting.
 * @param g Infoflow graph to which add the edge.
 * @param start_node Starting node for the edge.
 * @param end_node Ending node for the edge.
 * @param len Length of edge (proportionally inverse of permission weight)
 *
 * @return Pointer an allocated node within the infoflow graph, or
 * NULL upon error.
 */
static apol_infoflow_edge_t *apol_infoflow_graph_create_edge(apol_policy_t *p,
							     apol_infoflow_graph_t *g,
							     apol_infoflow_node_t *start_node,
							     apol_infoflow_node_t *end_node,
							     int len)
{
	struct apol_infoflow_edge_key key = {NULL, end_node};
	size_t i;
	apol_infoflow_edge_t *edge = NULL;
	if (apol_vector_get_index(start_node->out_edges, NULL, apol_infoflow_edge_compare, &key, &i) == 0) {
		edge = (apol_infoflow_edge_t *) apol_vector_get_element(start_node->out_edges, i);
		if (edge->length < len) {
			edge->length = len;
		}
		return edge;
	}
	if ((edge = calloc(1, sizeof(*edge))) == NULL ||
	    (edge->rules = apol_vector_create()) == NULL ||
	    apol_vector_append(g->edges, edge) < 0) {
		apol_infoflow_edge_free(edge);
		ERR(p, "Out of memory!");
		return NULL;
	}
	edge->start_node = start_node;
	edge->end_node = end_node;
	edge->length = len;
	if (apol_vector_append(start_node->out_edges, edge) < 0 ||
	    apol_vector_append(end_node->in_edges, edge) < 0) {
		/* don't free the edge -- it is owned by the graph */
		ERR(p, "Out of memory!");
		return NULL;
	}
	return edge;
}

/******************** infoflow graph creation routines ********************/

/**
 * Take an avrule within a policy and possibly add it to the infoflow
 * graph.  The rule must refer to types that are within the types
 * vector.  If the rule is to be added, then add its end nodes as
 * necessary, and an edge connecting those nodes as necessary, and
 * then add the rule to the edge.
 *
 * @param p Policy containing rules.
 * @param g Information flow graph being created.
 * @param rule AV rule to use.
 * @param types If non-NULL, then a list of qpol_type_t pointers.  The
 * rule's source and target types must be an element of this list for
 * it to be added to the graph.
 * @param found_read Non-zero to indicate that this rule performs a
 * read operation.
 * @param read_len Length of the edge to create (proportionally
 * inverse of permission weight).
 * @param found_write Non-zero to indicate that this rule performs a
 * write operation.
 * @param write_len Length of the edge to create (proportionally
 * inverse of permission weight).
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_graph_connect_nodes(apol_policy_t *p,
					     apol_infoflow_graph_t *g,
					     qpol_avrule_t *rule,
					     apol_vector_t *types,
					     int found_read,
					     int read_len,
					     int found_write,
					     int write_len)
{
	qpol_type_t *src_type, *tgt_type;
	qpol_class_t *obj_class;
	size_t i;
	apol_infoflow_node_t *src_node, *tgt_node;
	apol_infoflow_edge_t *edge;
	int retval = -1;

	if (qpol_avrule_get_source_type(p->qh, p->p, rule, &src_type) < 0 ||
	    qpol_avrule_get_target_type(p->qh, p->p, rule, &tgt_type) < 0 ||
            qpol_avrule_get_object_class(p->qh, p->p, rule, &obj_class) < 0) {
		goto cleanup;
	}

	/* only add source nodes that are in the types vector */
	if (types != NULL &&
	    apol_vector_get_index(types, src_type, NULL, NULL, &i) < 0) {
		retval = 0;
		goto cleanup;
	}
	if ((src_node = apol_infoflow_graph_create_node(p, g, src_type, obj_class, APOL_INFOFLOW_NODE_SOURCE)) == NULL) {
		goto cleanup;
	}

	/* only add target nodes that are in the types vector */
	if (types != NULL &&
	    apol_vector_get_index(types, tgt_type, NULL, NULL, &i) < 0) {
		retval = 0;
		goto cleanup;
	}
	if ((tgt_node = apol_infoflow_graph_create_node(p, g, tgt_type, obj_class, APOL_INFOFLOW_NODE_TARGET)) == NULL) {
		goto cleanup;
	}
	if (found_read) {
		if ((edge = apol_infoflow_graph_create_edge(p, g, tgt_node, src_node, read_len)) == NULL) {
			goto cleanup;
		}
		if (apol_vector_append(edge->rules, rule) < 0) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}
	if (found_write) {
		if ((edge = apol_infoflow_graph_create_edge(p, g, src_node, tgt_node, write_len)) == NULL) {
			goto cleanup;
		}
		if (apol_vector_append(edge->rules, rule) < 0) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}
	retval = 0;
 cleanup:
	return retval;
}

/**
 * Given a policy and a partially completed infoflow graph, create the
 * nodes and edges associated with a particular rule.
 *
 * @param p Policy from which to create the infoflow graph.
 * @param g Infoflow graph being created.
 * @param rule AV rule to add.
 * @param types Vector of qpol_type_t, containing which source and
 * target types to add.  If NULL, then allow all types.
 * @param max_len Maximum permission length (i.e., inverse of
 * permission weight) to consider when deciding to add this rule or
 * not.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_graph_create_avrule(apol_policy_t *p,
					     apol_infoflow_graph_t *g,
					     qpol_avrule_t *rule,
					     apol_vector_t *types,
					     int max_len)
{
	qpol_class_t *obj_class;
	qpol_iterator_t *perm_iter = NULL;
	char *obj_class_name, *perm_name;
	int found_read = 0, found_write = 0;
	int read_len = INT_MAX, write_len = INT_MAX;
	int retval = -1;
	if (qpol_avrule_get_object_class(p->qh, p->p, rule, &obj_class) < 0 ||
	    qpol_class_get_name(p->qh, p->p, obj_class, &obj_class_name) < 0 ||
	    qpol_avrule_get_perm_iter(p->qh, p->p, rule, &perm_iter) < 0) {
		goto cleanup;
	}

	/* find read or write flows for each object class/perm pair */
	for ( ; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		int perm_map, perm_weight, len;

		if (qpol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
			goto cleanup;
		}
		if (apol_permmap_get(p, obj_class_name, perm_name, &perm_map, &perm_weight) < 0) {
			goto cleanup;
		}
		if (perm_map == APOL_PERMMAP_UNMAPPED) {
			continue;
		}
		len = APOL_PERMMAP_MAX_WEIGHT - perm_weight + 1;
		if (len < APOL_PERMMAP_MIN_WEIGHT) {
			len = APOL_PERMMAP_MIN_WEIGHT;
		}
		else if (len > APOL_PERMMAP_MAX_WEIGHT) {
			len = APOL_PERMMAP_MAX_WEIGHT;
		}
		if (perm_map & APOL_PERMMAP_READ) {
			if (len < read_len && len <= max_len) {
				found_read = 1;
				read_len = len;
			}
		}
		if (perm_map & APOL_PERMMAP_WRITE) {
			if (len < write_len && len <= max_len) {
				found_write = 1;
				write_len = len;
			}
		}
	}

	/* if we have found any flows then connect them within the graph */
	if ((found_read || found_write) &&
	    apol_infoflow_graph_connect_nodes(p, g, rule, types, found_read, read_len, found_write, write_len) < 0) {
		goto cleanup;
	}

	retval = 0;
 cleanup:
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

/**
 * Determine if an av rule matches a list of apol_obj_perm_t.  The
 * rule's class must match at least one item in the list, and at least
 * one of the rule's permissions must be on the list.
 *
 * @param p Policy to which look up classes and permissions.
 * @param rule AV rule to check.
 * @param class_perms Vector of apol_obj_perm_t, of which rules' class
 * and permissions must be a member.  If NULL or empty then allow all
 * classes and permissions.
 *
 * @return 1 if rule matches, 0 if not, < 0 on error.
 */
static int apol_infoflow_graph_check_class_perms(apol_policy_t *p,
						 qpol_avrule_t *rule,
						 apol_vector_t *class_perms)
{
	qpol_class_t *obj_class;
	char *obj_name, *perm;
	qpol_iterator_t *iter = NULL;
	apol_obj_perm_t *obj_perm = NULL;
	apol_vector_t *obj_perm_v = NULL;
	size_t i;
	int retval = -1;

	if (class_perms == NULL || apol_vector_get_size(class_perms) == 0) {
		retval = 1;
		goto cleanup;
	}
	if (qpol_avrule_get_object_class(p->qh, p->p, rule, &obj_class) < 0 ||
	    qpol_class_get_name(p->qh, p->p, obj_class, &obj_name) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(class_perms); i++) {
		obj_perm = (apol_obj_perm_t *) apol_vector_get_element(class_perms, i);
		if (strcmp(apol_obj_perm_get_obj_name(obj_perm), obj_name) == 0) {
			obj_perm_v = apol_obj_perm_get_perm_vector(obj_perm);
			break;
		}
	}
	if (i >= apol_vector_get_size(class_perms)) {
		retval = 0;  /* no matching class */
		goto cleanup;
	}
        if (qpol_avrule_get_perm_iter(p->qh, p->p, rule, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &perm) < 0) {
			goto cleanup;
		}
		if (apol_vector_get_index(obj_perm_v, perm, apol_str_strcmp, NULL, &i) == 0) {
			retval = 1;
			goto cleanup;
		}
	}
	retval = 0;  /* no matching perm */
 cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}

/**
 * Given a particular information flow analysis object, generate an
 * infoflow graph relative to a particular policy.  This graph is
 * customized for the particular analysis.
 *
 * @param p Policy from which to create the infoflow graph.
 * @param ia Parameters to tune the created graph.
 * @param g Reference to where to store the graph.  The caller is
 * responsible for calling apol_infoflow_graph_destroy() upon this.
 *
 * @return 0 if the graph was created, < 0 on error.  Upon error *g
 * will be set to NULL.
 */
static int apol_infoflow_graph_create(apol_policy_t *p,
				      apol_infoflow_analysis_t *ia,
				      apol_infoflow_graph_t **g)
{
	apol_vector_t *types = NULL;
	qpol_iterator_t *iter = NULL;
	int max_len = APOL_PERMMAP_MAX_WEIGHT - ia->min_weight + 1;
	int compval, retval = -1;

	*g = NULL;
	if (p->pmap == NULL) {
		ERR(p, "A permission map must be loaded prior to building the infoflow graph.");
		goto cleanup;
	}
        /* FIX ME: trans mode does something different
	if (ia->mode == APOL_INFOFLOW_MODE_DIRECT &&
	    (types = apol_query_create_candidate_type_list(p, ia->type, 0, 1)) == NULL) {
		goto cleanup;
	}
        */

	if ((*g = calloc(1, sizeof(**g))) == NULL ||
	    ((*g)->nodes = apol_vector_create()) == NULL ||
	    ((*g)->edges = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	(*g)->mode = ia->mode;
	(*g)->direction = ia->direction;
	if (ia->result != NULL && ia->result[0] != '\0') {
		if (((*g)->regex = malloc(sizeof(regex_t))) == NULL ||
		    regcomp((*g)->regex, ia->result, REG_EXTENDED | REG_NOSUB)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}
	if (qpol_policy_get_avrule_iter(p->qh, p->p, QPOL_RULE_ALLOW, &iter) < 0) {
		goto cleanup;
	}

	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_avrule_t *rule;
		uint32_t is_enabled;
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0) {
			goto cleanup;
		}
		if (qpol_avrule_get_is_enabled(p->qh, p->p, rule, &is_enabled) < 0) {
			goto cleanup;
		}
		if (!is_enabled) {
			continue;
		}
		compval = apol_infoflow_graph_check_class_perms(p, rule, ia->class_perms);
		if (compval < 0) {
			goto cleanup;
		}
		else if (compval == 0) {
			continue;
		}
		if (apol_infoflow_graph_create_avrule(p, *g, rule, types, max_len) < 0) {
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	apol_vector_destroy(&types, NULL);
	qpol_iterator_destroy(&iter);
	if (retval < 0) {
		apol_infoflow_graph_destroy(g);
		*g = NULL;
	}
	return retval;
}

void apol_infoflow_graph_destroy(apol_infoflow_graph_t **flow)
{
	if (*flow != NULL) {
		apol_vector_destroy(&(*flow)->nodes, apol_infoflow_node_free);
		apol_vector_destroy(&(*flow)->edges, apol_infoflow_edge_free);
		apol_regex_destroy(&(*flow)->regex);
		free(*flow);
		*flow = NULL;
	}
}

/*************** infoflow graph direct analysis routines ***************/

/**
 * Given a graph and a target type, append to vector v all nodes
 * (apol_infoflow_node_t) within the graph that use that type or one
 * of that type's aliases.
 *
 * @param p Error reporting handler.
 * @param g Information flow graph containing nodes.
 * @param type Target type name to find.
 * @param v Initialized vector to which append nodes.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_graph_get_nodes_for_type(apol_policy_t *p,
						  apol_infoflow_graph_t *g,
						  const char *type,
						  apol_vector_t *v)
{
	size_t i, j;
	apol_vector_t *cand_list = NULL;
	int retval = -1;
	if ((cand_list = apol_query_create_candidate_type_list(p, type, 0, 1)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(g->nodes); i++) {
		apol_infoflow_node_t *node;
		node = (apol_infoflow_node_t *) apol_vector_get_element(g->nodes, i);
		if (apol_vector_get_index(cand_list, node->type, NULL, NULL, &j) == 0 &&
		    apol_vector_append(v, node) < 0) {
			goto cleanup;
		}
	}
	retval = 0;
 cleanup:
	apol_vector_destroy(&cand_list, NULL);
	return retval;
}

/**
 * Return a usable infoflow result object.  If there already exists a
 * result object within vector v with the same start and ending type
 * then reuse that object.  Otherwise allocate and return a new
 * infoflow result with its start and end type fields set.
 *
 * @param p Policy handler, for error reporting.
 * @param v Non-null vector of infoflow results.
 * @param start_type Starting type for returned infoflow result object.
 * @param end_type Starting type for returned infoflow result object.
 *
 * @return A usable infoflow result object, or NULL upon error.
 */
static apol_infoflow_result_t *apol_infoflow_direct_get_result(apol_policy_t *p,
							       apol_vector_t *v,
							       qpol_type_t *start_type,
							       qpol_type_t *end_type)
{
	size_t i;
	apol_infoflow_result_t *r;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		r = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		if (r->start_type == start_type && r->end_type == end_type) {
			return r;
		}
	}
	if ((r = calloc(1, sizeof(*r))) == NULL ||
	    (r->rules = apol_vector_create()) == NULL ||
	    apol_vector_append(v, r) < 0) {
		ERR(p, "Out of memory!");
		apol_infoflow_result_free(r);
		return NULL;
	}
	r->start_type = start_type;
	r->end_type = end_type;
	return r;
}

/**
 * Set the rules and directions of an infoflow result.
 *
 * @param p Policy containing rules.
 * @param edge Infoflow edge containing rules.
 * @param direction Direction of flow, one of APOL_INFOFLOW_IN, etc.
 * @param r Infoflow result to modify.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_result_define(apol_policy_t *p,
				       apol_infoflow_edge_t *edge,
				       unsigned int direction,
				       apol_infoflow_result_t *r)
{
	r->direction |= direction;
	if (apol_vector_cat(r->rules, edge->rules) < 0) {
		ERR(p, "Out of memory!");
		return -1;
	}
	return 0;
}

/**
 * Given the regular expression compiled into the graph object and a
 * type, determine if that regex matches a node's type or any of the
 * type's aliases.
 *
 * @param p Policy containing type names.
 * @param g Graph object containing regex.
 * @param node Ndoe to check against.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
static int apol_infoflow_graph_compare(apol_policy_t *p,
				       apol_infoflow_graph_t *g,
				       apol_infoflow_node_t *node)
{
	char *type_name;
	qpol_iterator_t *alias_iter = NULL;
	int compval = 0;
	if (qpol_type_get_name(p->qh, p->p, node->type, &type_name) < 0) {
		return -1;
	}
	if (g->regex == NULL) {
		return 1;
	}
	if (regexec(g->regex, type_name, 0, NULL, 0) == 0) {
		return 1;
	}
	/* also check for matches against any of target's aliases */
	if (qpol_type_get_alias_iter(p->qh, p->p, node->type, &alias_iter) < 0) {
		return -1;
	}
	for ( ; !qpol_iterator_end(alias_iter); qpol_iterator_next(alias_iter)) {
		char *iter_name;
		if (qpol_iterator_get_item(alias_iter, (void **) &iter_name) < 0) {
			compval = -1;
			break;
		}
		if (regexec(g->regex, iter_name, 0, NULL, 0) == 0) {
			compval = 1;
			break;
		}
	}
	qpol_iterator_destroy(&alias_iter);
	return compval;
}

/**
 * For each result object in vector working_results, append a
 * duplicate of it to vector results if (a) the infoflow analysis
 * object direction is not BOTH or (b) the result object's direction
 * is BOTH.  Regardless of success or error, it is safe to destroy
 * either vector without concern of double-free()ing things.
 *
 * @param p Policy handler, to report errors.
 * @param working_results Vector of infoflow results to check.
 * @param direction Direction of search.
 * @param results Vector to which append duplicated infoflow results.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_results_check_both(apol_policy_t *p,
					    apol_vector_t *working_results,
					    unsigned int direction,
					    apol_vector_t *results)
{
	size_t i;
	apol_infoflow_result_t *r, *new_r;
	for (i = 0; i < apol_vector_get_size(working_results); i++) {
		r = (apol_infoflow_result_t *) apol_vector_get_element(working_results, i);
		if (direction != APOL_INFOFLOW_BOTH ||
		    r->direction == APOL_INFOFLOW_BOTH) {
			if ((new_r = calloc(1, sizeof(*new_r))) == NULL) {
				ERR(p, "Out of memory");
				return -1;
			}
			memcpy(new_r, r, sizeof(*new_r));
			r->rules = NULL;
			if (apol_vector_append(results, new_r) < 0) {
				apol_infoflow_result_free(new_r);
				ERR(p, "Out of memory");
				return -1;
			}
		}
	}
	return 0;
}

/**
 * Perform a direct information flow analysis upon the given infoflow
 * graph.
 *
 * @param p Policy to analyze.
 * @param g Information flow graph to analyze.
 * @param start_type Type from which to begin search.
 * @param results Non-NULL vector to which append infoflow results.
 * The caller is responsible for calling apol_infoflow_results_free()
 * upon each element afterwards.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_analysis_direct(apol_policy_t *p,
					 apol_infoflow_graph_t *g,
					 const char *start_type,
					 apol_vector_t *results)
{
	apol_vector_t *nodes = NULL;
	size_t i, j;
	apol_infoflow_node_t *node, *end_node;
	apol_infoflow_edge_t *edge;
	apol_infoflow_result_t *r;
	apol_vector_t *working_results = NULL;
	int retval = -1, compval;

	if ((nodes = apol_vector_create()) == NULL ||
	    (working_results = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	if (apol_infoflow_graph_get_nodes_for_type(p, g, start_type, nodes) < 0) {
		goto cleanup;
	}

	if (g->direction == APOL_INFOFLOW_IN ||
	    g->direction == APOL_INFOFLOW_EITHER ||
	    g->direction == APOL_INFOFLOW_BOTH) {
		for (i = 0; i < apol_vector_get_size(nodes); i++) {
			node = (apol_infoflow_node_t *) apol_vector_get_element(nodes, i);
			for (j = 0; j < apol_vector_get_size(node->in_edges); j++) {
				edge = (apol_infoflow_edge_t *) apol_vector_get_element(node->in_edges, j);
				if (edge->start_node == node) {
					end_node = edge->end_node;
				}
				else {
					end_node = edge->start_node;
				}
				compval = apol_infoflow_graph_compare(p, g, end_node);
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval == 0) {
					continue;
				}
				if ((r = apol_infoflow_direct_get_result(p, working_results, node->type, end_node->type)) == NULL ||
				    apol_infoflow_result_define(p, edge, APOL_INFOFLOW_IN, r) < 0) {
					goto cleanup;
				}
			}
		}
	}
	if (g->direction == APOL_INFOFLOW_OUT ||
	    g->direction == APOL_INFOFLOW_EITHER ||
	    g->direction == APOL_INFOFLOW_BOTH) {
		for (i = 0; i < apol_vector_get_size(nodes); i++) {
			node = (apol_infoflow_node_t *) apol_vector_get_element(nodes, i);
			for (j = 0; j < apol_vector_get_size(node->out_edges); j++) {
				edge = (apol_infoflow_edge_t *) apol_vector_get_element(node->out_edges, j);
				if (edge->start_node == node) {
					end_node = edge->end_node;
				}
				else {
					end_node = edge->start_node;
				}
				compval = apol_infoflow_graph_compare(p, g, end_node);
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval == 0) {
					continue;
				}
				if ((r = apol_infoflow_direct_get_result(p, working_results, node->type, end_node->type)) == NULL ||
				    apol_infoflow_result_define(p, edge, APOL_INFOFLOW_OUT, r) < 0) {
					goto cleanup;
				}
			}
		}
	}

	if (apol_infoflow_results_check_both(p, working_results, g->direction, results) < 0) {
		goto cleanup;
	}

	retval = 0;
 cleanup:
	apol_vector_destroy(&nodes, NULL);
	apol_vector_destroy(&working_results, apol_infoflow_result_free);
	return retval;
}

/******************** infoflow analysis object routines ********************/

int apol_infoflow_analysis_do(apol_policy_t *p,
			      apol_infoflow_analysis_t *ia,
			      apol_vector_t **v,
			      apol_infoflow_graph_t **g)
{
	qpol_type_t *start_type;
	int retval = -1;
	*v = NULL;
	*g = NULL;

	if (ia->mode == 0 || ia->direction == 0) {
		ERR(p, strerror(EINVAL));
		goto cleanup;
	}
	if (apol_query_get_type(p, ia->type, &start_type) < 0) {
		goto cleanup;
	}

	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	if (apol_infoflow_graph_create(p, ia, g) < 0) {
		goto cleanup;
	}

	if (ia->mode == APOL_INFOFLOW_MODE_DIRECT &&
	    apol_infoflow_analysis_direct(p, *g, ia->type, *v) < 0) {
		goto cleanup;
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, apol_infoflow_result_free);
		apol_infoflow_graph_destroy(g);
	}
	return retval;
}

int apol_infoflow_analysis_do_more(apol_policy_t *p,
				   apol_infoflow_graph_t *g,
				   const char *type,
				   apol_vector_t **v)
{
	qpol_type_t *start_type;
	int retval = -1;
	*v = NULL;

	if (apol_query_get_type(p, type, &start_type) < 0) {
		goto cleanup;
	}

	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}

	if (g->mode == APOL_INFOFLOW_MODE_DIRECT &&
	    apol_infoflow_analysis_direct(p, g, type, *v) < 0) {
		goto cleanup;
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, apol_infoflow_result_free);
	}
	return retval;
}

apol_infoflow_analysis_t *apol_infoflow_analysis_create(void)
{
	return calloc(1, sizeof(apol_infoflow_analysis_t));
}

void apol_infoflow_analysis_destroy(apol_infoflow_analysis_t **ia)
{
	if (*ia != NULL) {
		free((*ia)->type);
		free((*ia)->result);
		apol_vector_destroy(&(*ia)->class_perms, apol_obj_perm_free);
		free(*ia);
		*ia = NULL;
	}
}

int apol_infoflow_analysis_set_mode(apol_policy_t *p,
				    apol_infoflow_analysis_t *ia,
				    unsigned int mode)
{
	switch (mode) {
	case APOL_INFOFLOW_MODE_DIRECT:
	case APOL_INFOFLOW_MODE_TRANS: {
		ia->mode = mode;
		break;
	}
	default: {
		ERR(p, strerror(EINVAL));
		return -1;
	}
	}
	return 0;
}

int apol_infoflow_analysis_set_dir(apol_policy_t *p,
				   apol_infoflow_analysis_t *ia,
				   unsigned int dir)
{
	switch (dir) {
	case APOL_INFOFLOW_IN:
	case APOL_INFOFLOW_OUT:
	case APOL_INFOFLOW_BOTH:
	case APOL_INFOFLOW_EITHER: {
		ia->direction = dir;
		break;
	}
	default: {
		ERR(p, strerror(EINVAL));
		return -1;
	}
	}
	return 0;
}

int apol_infoflow_analysis_set_type(apol_policy_t *p,
				    apol_infoflow_analysis_t *ia,
				    const char *name)
{
	if (name == NULL) {
		ERR(p, strerror(EINVAL));
		return -1;
	}
	return apol_query_set(p, &ia->type, NULL, name);
}

static int compare_class_perm_by_class_name(const void *in_op, const void *class_name, void *unused __attribute__ ((unused)))
{
	const apol_obj_perm_t *op = (const apol_obj_perm_t*)in_op;
	const char *name = (const char*)class_name;

	return strcmp(apol_obj_perm_get_obj_name(op), name);
}

int apol_infoflow_analysis_append_class_perm(apol_policy_t *p,
                                             apol_infoflow_analysis_t *ia,
                                             const char *class_name,
                                             const char *perm_name)
{
	apol_obj_perm_t *op = NULL;
	size_t i;

	if (class_name == NULL) {
		apol_vector_destroy(&ia->class_perms, apol_obj_perm_free);
		return 0;
	}

	if (ia->class_perms == NULL &&
	    (ia->class_perms = apol_vector_create()) == NULL) {
		ERR(p, "Error adding class and permission to analysis: %s", strerror(ENOMEM));
		return -1;
	}

	if (apol_vector_get_index(ia->class_perms, (void*)class_name, compare_class_perm_by_class_name, NULL, &i) < 0) {
		if (perm_name) {
			if ((op = apol_obj_perm_create()) == NULL) {
				ERR(p, "Error adding class and permission to analysis: %s", strerror(ENOMEM));
				return -1;
			}
			if (apol_obj_perm_set_obj_name(op, class_name) ||
			    apol_obj_perm_append_perm(op, perm_name) ||
			    apol_vector_append(ia->class_perms, op)) {
				ERR(p, "Error adding class and permission to analysis: %s", strerror(ENOMEM));
				apol_obj_perm_free(op);
				return -1;
			}
		}
		else {
			return 0; /* nothing to clear; done */
		}
	}
	else {
		op = apol_vector_get_element(ia->class_perms, i);
		if (apol_obj_perm_append_perm(op, perm_name)) {
			ERR(p, "Error adding class and permission to analysis: %s", strerror(ENOMEM));
			return -1;
		}
	}
	return 0;
}

int apol_infoflow_analysis_set_result_regex(apol_policy_t *p,
					    apol_infoflow_analysis_t *ia,
					    const char *result)
{
	return apol_query_set(p, &ia->result, NULL, result);
}

/*************** functions to access infoflow results ***************/

void apol_infoflow_result_free(void *result)
{
	if (result != NULL) {
		apol_infoflow_result_t *r = (apol_infoflow_result_t *) result;
		apol_vector_destroy(&r->rules, NULL);
		free(r);
	}
}

unsigned int apol_infoflow_result_get_dir(apol_infoflow_result_t *result)
{
	return result->direction;
}

qpol_type_t *apol_infoflow_result_get_start_type(apol_infoflow_result_t *result)
{
	return result->start_type;
}

qpol_type_t *apol_infoflow_result_get_end_type(apol_infoflow_result_t *result)
{
	return result->end_type;
}

apol_vector_t *apol_infoflow_result_get_rules(apol_infoflow_result_t *result)
{
	return result->rules;
}

#if 0
	int num_end_types;
	int *end_types;			/* indices into policy->types */
	int num_types;				/* number of intermediate types */
	int *types;				/* indices of intermediate types in policy->types */
	int num_obj_options;			/* number of permission options */
	obj_perm_set_t *obj_options;		/* Allows the exclusion of individual permissions
						 * or entire object classes. This struct is defined
						 * in policy.h */

#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <time.h>

#include "policy.h"
#include "util.h"
#include "infoflow.h"
#include "queue.h"

/* check to make certain that a query is consistent and makes
 * sense with the graph/policy */
bool_t iflow_query_is_valid(iflow_query_t *q, policy_t *policy)
{
	int i;

#ifdef DEBUG_QUERIES
	printf("start type: %s\n", policy->types[q->start_type].name);
	printf("types[%d]:\n", q->num_types);
	for (i = 0; i < q->num_types; i++)
		printf("\t%s\n", policy->types[q->types[i]].name);
	printf("end types[%d]: \n", q->num_end_types);
	for (i = 0; i < q->num_end_types; i++)
		printf("\t%s\n", policy->types[q->end_types[i]].name);
	printf("obj options[%d]: \n", q->num_obj_options);
	for (i = 0; i < q->num_obj_options; i++) {
		int j;
		printf("\tobj class [%d]%s perms [%d]:\n", q->obj_options[i].obj_class,
		       policy->obj_classes[q->obj_options[i].obj_class].name,
		       q->obj_options[i].num_perms);
		for (j = 0; j < q->obj_options[i].num_perms; j++)
			printf("\t\t%s\n", policy->perms[q->obj_options[i].perms[j]]);
	}
#endif

	/* check the start type - we don't allow self (which is always 0) */
	if (!is_valid_type(policy, q->start_type, FALSE)) {
		fprintf(stderr, "invalid start type %d in query\n", q->start_type);
		return FALSE;
	}

	/* transitive analysis will have to do further checks */
	if (!(q->direction == IFLOW_IN || q->direction == IFLOW_OUT
	      || q->direction == IFLOW_BOTH || q->direction == IFLOW_EITHER)) {
		fprintf(stderr, "invalid direction %d in query\n", q->direction);
		return FALSE;
	}

	if (q->num_end_types) {
		if (!q->end_types) {
			fprintf(stderr, "query num_end_types was %d but end_types was NULL\n",
				q->num_end_types);
			return FALSE;
		}
		for (i = 0; i < q->num_end_types; i++) {
			if (!is_valid_type(policy, q->end_types[i], FALSE)) {
				fprintf(stderr, "Invalid end type %d in query\n", q->end_types[i]);
				return FALSE;
			}
		}
	}

	if (q->num_types) {
		if (!q->types) {
			fprintf(stderr, "query num_types was %d but types was NULL\n",
				q->num_types);
			return FALSE;
		}
		for (i = 0; i < q->num_types; i++) {
			if (!is_valid_type(policy, q->types[i], FALSE)) {
				fprintf(stderr, "Invalid end type %d in query\n", q->types[i]);
				return FALSE;
			}
		}
	}

	if (q->num_obj_options) {
		if (!q->obj_options) {
			fprintf(stderr, "query num_obj_options was %d by obj_options was NULL\n",
				q->num_obj_options);
			return FALSE;
		}
		for (i = 0; i < q->num_obj_options; i++) {
			if (!iflow_obj_option_is_valid(&q->obj_options[i], policy)) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

static int ta_find_edge(iflow_graph_t *g, iflow_query_t *q, int path_len, int *path, int start)
{
	int i, edge = -1;

	if (q->direction == IFLOW_OUT) {
		for (i = 0; i < g->nodes[path[start]].num_out_edges; i++) {
			edge = g->nodes[path[start]].out_edges[i];
			if (g->edges[edge].start_node == path[start] &&
				g->edges[edge].end_node == path[start + 1])
				break;
		}
		if (i == g->nodes[path[start]].num_out_edges) {
			fprintf(stderr, "Did not find an edge\n");
			return -1;
		}
	} else {
		for (i = 0; i < g->nodes[path[start]].num_in_edges; i++) {
			edge = g->nodes[path[start]].in_edges[i];
			if (g->edges[edge].end_node == path[start] &&
				g->edges[edge].start_node == path[start + 1])
				break;
		}
		if (i == g->nodes[path[start]].num_in_edges) {
			fprintf(stderr, "Did not find an edge\n");
			return -1;
		}
	}
	return edge;
}

static iflow_path_t *ta_build_path(iflow_graph_t *g, iflow_query_t *q, int path_len, int *path)
{
	int i, length, edge;
	iflow_path_t *p;

	p = (iflow_path_t*)malloc(sizeof(iflow_path_t));
	if (!p) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(p, 0, sizeof(iflow_path_t));

	p->iflows = (iflow_t*)malloc(sizeof(iflow_t) * (path_len - 1));
	if (!p->iflows) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	p->num_iflows = path_len - 1;
	memset(p->iflows, 0, sizeof(iflow_t) * (path_len - 1));

	/* build the path */
	length = 0;
	for (i = 0; i < path_len - 1; i++) {
		edge = ta_find_edge(g, q, path_len, path, i);
		if (edge < 0)
			return NULL;

		length += g->edges[edge].length;

		if (iflow_init(g, &p->iflows[i])) {
			fprintf(stderr, "Memory error\n");
			return NULL;
		}
		if (q->direction == IFLOW_OUT) {
			if (iflow_define_flow(g, &p->iflows[i], IFLOW_OUT,
					      path[i], edge))
				return NULL;
		} else {
			if (iflow_define_flow(g, &p->iflows[i], IFLOW_IN,
					      path[i + 1], edge))
				return NULL;
		}
	}
	p->length = length;

	return p;
}

static bool_t ta_iflow_equal(iflow_t *a, iflow_t *b)
{
	if (a->start_type != b->start_type || a->end_type != b->end_type || a->direction != b->direction)
		return FALSE;
	return TRUE;
}

/* helper for iflow_transitive_flows */
static int transitive_answer_append(iflow_graph_t *g, iflow_query_t *q, iflow_transitive_t* a,
				    int end_node, int path_len, int *path)
{
	int i, j, cur_type, cur;
	iflow_path_t *p, *last_path = NULL;
	bool_t found_dup, new_path = FALSE;

	p = ta_build_path(g, q, path_len, path);
	if (!p)
		return -1;

	/* First we look for duplicate paths */
	cur_type = g->nodes[end_node].type;
	for (i = 0; i < a->num_end_types; i++) {
		if (a->end_types[i] != cur_type)
			continue;
		/* find the last path while checking for duplicates */
		last_path = a->paths[i];
		while (1) {
			if (last_path->num_iflows != p->num_iflows)
				goto next;
			found_dup = TRUE;
			for (j = 0; j < last_path->num_iflows; j++) {
				if (!ta_iflow_equal(&last_path->iflows[j], &p->iflows[j])) {
					found_dup = FALSE;
					break;
				}
			}
			/* found a dup TODO - make certain all of the object class / rules are kept */
			if (found_dup) {
				iflow_path_destroy(p);
				return 0;
			}
		next:
			if (!last_path->next)
				break;
			last_path = last_path->next;
		}
		new_path = TRUE;
		a->num_paths[i]++;
		last_path->next = p;
		break;
	}

	/* If we are here there are no other paths with this end type */
	if (!last_path) {
		new_path = TRUE;
		cur = a->num_end_types;
		if (add_i_to_a(cur_type, &a->num_end_types, &a->end_types))
			return -1;
		a->paths = (iflow_path_t**)realloc(a->paths, a->num_end_types
							* sizeof(iflow_path_t*));
		if (a->paths == NULL) {
			fprintf(stderr, "Memory error!\n");
			return -1;
		}

		a->num_paths = (int*)realloc(a->num_paths, a->num_end_types
					     * sizeof(int));
		if (a->num_paths == NULL) {
			fprintf(stderr, "Memory error!\n");
			return -1;
		}
		new_path = TRUE;
		a->paths[cur] = p;
		a->num_paths[cur] = 1;
	}

	if (new_path)
		return 1;
	return 0;
}

static int iflow_path_compare(const void *a, const void *b)
{
	iflow_path_t *path_a, *path_b;
	path_a = *((iflow_path_t**)a);
	path_b = *((iflow_path_t**)b);

	if (path_a->length == path_b->length)
		return 0;
	else if (path_a->length < path_b->length)
		return -1;
	else
		return 1;
}

static iflow_path_t *iflow_sort_paths(iflow_path_t *path)
{
	int i, num_paths;
	iflow_path_t *cur, *start, **paths;

	if (!path) {
		fprintf(stderr, "sort_iflow_paths got NULL path\n");
		return NULL;
	}

	num_paths = 0;
	cur = path;
	while (cur) {
		num_paths++;
		cur = cur->next;
	}

	if (num_paths == 1) {
		return path;
	}

	paths = (iflow_path_t**)malloc(sizeof(iflow_path_t*) * num_paths);
	if (!paths) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(paths, 0, sizeof(iflow_path_t*) * num_paths);

	i = 0;
	cur = path;
	while (cur) {
		paths[i++] = cur;
		cur = cur->next;
	}

	qsort(paths, num_paths, sizeof(iflow_path_t*), iflow_path_compare);

	cur = start = paths[0];
	for (i = 1; i < num_paths; i++) {
		cur->next = paths[i];
		cur = cur->next;
	}
	cur->next = NULL;

	return start;
}

static int shortest_path_find_path(iflow_graph_t *g, int start_node, int end_node, int *path)
{
	int next_node = end_node;
	int i, tmp, path_len = 0;

	while (1) {
		path[path_len++] = next_node;
		if (next_node == start_node)
			break;
		if (path_len >= g->num_nodes) {
			fprintf(stderr, "Infinite loop in shortest_path_find_path\n");
			return -1;
		}
		next_node = g->nodes[next_node].parent;
		if (next_node >= g->num_nodes) {
			fprintf(stderr, "Something strange in shortest_path_find_path\n");
			return -1;
		}
	}

	/* reverse the path */
	for (i = 0; i < path_len / 2; i++) {
		tmp = path[i];
		path[i] = path[(path_len - 1) - i];
		path[(path_len - 1) - i] = tmp;
	}

	return path_len;
}

/* This is a label correcting shortest path algorithm see Bertsekas,
 * D. P., "A Simple and Fast Label Correcting Algorithm for Shortest
 * Paths," Networks, Vol. 23, pp. 703-709, 1993. for more
 * information. A label correcting algorithm is needed instead of the
 * more common Dijkstra label setting algorithm to correctly handle
 * the the cycles that are possible in these graphs.
 *
 * This algorithm finds the shortest path between a given start node
 * and all other nodes in the graph. Any paths that it finds it
 * appends to the iflow_transitive_t structure. This is a basic label
 * correcting algorithm with 1 optimization. It uses the D'Esopo-Pape
 * method for node selection in the node queue. Why is this faster?
 * The paper referenced above says "No definitive explanation has been
 * given." They have fancy graphs to show that it is faster though and
 * the important part is that the worst case isn't much worse that N^2
 * - much better than an n^3 transitive closure. Additionally, most
 * normal sparse graphs are significantly better than the worst case.
 */
int iflow_graph_shortest_path(iflow_graph_t *g, int start_node, iflow_transitive_t *a, iflow_query_t *q)
{
	int i, rc = 0;
	int *path = NULL;
	queue_t queue = NULL;

	queue = queue_create();
	if (!queue) {
		fprintf(stderr, "Error creating queue\n");
		rc = -1;
		goto out;
	}

	path = (int*)malloc(g->num_nodes * sizeof(int));
	if (!path) {
		rc = -1;
		goto out;
	}

	/* initialization */
	g->nodes[start_node].distance = 0;
	g->nodes[start_node].parent = -1;
	g->nodes[start_node].color = IFLOW_COLOR_RED;

	for (i = 0; i < g->num_nodes; i++) {
		if (i == start_node)
			continue;
		g->nodes[i].distance = INT_MAX;
		g->nodes[i].parent = -1;
		g->nodes[i].color = IFLOW_COLOR_WHITE;
	}

	if (queue_insert(queue, (void*)(start_node + 1)) < 0) {
		fprintf(stderr, "Error inserting into queue\n");
		rc = -1;
		goto out;
	}

	while (queue_head(queue)) {
		void *cur_ptr;
		int cur;
		int num_edges;

		cur_ptr = queue_remove(queue);
		if (cur_ptr == NULL) {
			rc = -1;
			goto out;
		}
		cur = ((int)cur_ptr) - 1;

		g->nodes[cur].color = IFLOW_COLOR_GREY;

		if (q->direction == IFLOW_OUT)
			num_edges = g->nodes[cur].num_out_edges;
		else
			num_edges = g->nodes[cur].num_in_edges;

		for (i = 0; i < num_edges; i++) {
			int edge, node;

			if (q->direction == IFLOW_OUT) {
				edge = g->nodes[cur].out_edges[i];
				node = g->edges[edge].end_node;
			} else {
				edge = g->nodes[cur].in_edges[i];
				node = g->edges[edge].start_node;
			}

			if (start_node == node)
				continue;

			if (g->nodes[node].distance > (g->nodes[cur].distance + g->edges[edge].length)) {
				g->nodes[node].distance = g->nodes[cur].distance + g->edges[edge].length;
				g->nodes[node].parent = cur;
				if (g->nodes[node].color != IFLOW_COLOR_RED) {
					/* If this node has been inserted into the queue before insert
					 * it at the beginning, otherwise it goes to the end. See the
					 * comment at the beginning of the function for why. */
					if (g->nodes[node].color == IFLOW_COLOR_GREY) {
						if (queue_push(queue, (void*)(node + 1)) < 0) {
							fprintf(stderr, "Error inserting into queue\n");
							rc = -1;
							goto out;
						}
					} else {
						if (queue_insert(queue, (void*)(node + 1)) < 0) {
							fprintf(stderr, "Error inserting into queue\n");
							rc = -1;
							goto out;
						}
					}
					g->nodes[node].color = IFLOW_COLOR_RED;
				}

			}
		}
	}

	/* Find all of the paths and stick them in the iflow_transitive_t struct */
	for (i = 0; i < g->num_nodes; i++) {
		int path_len;

		if (g->nodes[i].parent == -1)
			continue;
		if (i == start_node)
			continue;

		if (q->num_end_types) {
			if (find_int_in_array(g->nodes[i].type, q->end_types, q->num_end_types) == -1) {
				continue;
			}
		}

		path_len = shortest_path_find_path(g, start_node, i, path);
		if (path_len < 0) {
			rc = -1;
			goto out;
		}
		if (transitive_answer_append(g, q, a, i, path_len, path) == -1) {
			rc = -1;
			goto out;
		}
	}

out:
	if (queue)
		queue_destroy(queue);
	if (path)
		free(path);
	return rc;
}

iflow_transitive_t *iflow_transitive_flows(policy_t *policy, iflow_query_t *q)
{
	int num_nodes, *nodes;
	int i;
	iflow_transitive_t *a;
	iflow_graph_t *g;

	if (!iflow_query_is_valid(q, policy))
		return NULL;

	if (!((q->direction == IFLOW_OUT ) || (q->direction == IFLOW_IN))) {
		fprintf(stderr, "Direction must be IFLOW_IN or IFLOW_OUT\n");
		return NULL;
	}

	g = iflow_graph_create(policy, q);
	if (!g) {
		fprintf(stderr, "Error creating graph\n");
		return NULL;
	}

	a = (iflow_transitive_t*)malloc(sizeof(iflow_transitive_t));
	if (a == NULL) {
		fprintf(stderr, "Memory error!\n");
		goto err;
	}
	memset(a, 0, sizeof(iflow_transitive_t));

	if (iflow_graph_get_nodes_for_type(g, q->start_type, &num_nodes, &nodes) < 0)
		return NULL;

	if (num_nodes == 0) {
		goto out;
	}

	a->start_type = q->start_type;

	for (i = 0; i < num_nodes; i++) {
		if (iflow_graph_shortest_path(g, nodes[i], a, q) != 0)
			goto err;
	}

	/* sort the paths by length */
	for (i = 0; i < a->num_end_types; i++) {
		/* sort the paths by length */
		a->paths[i] = iflow_sort_paths(a->paths[i]);
		if (a->paths[i] == NULL) {
			goto err;
		}
	}

out:
	iflow_graph_destroy(g);
	free(g);
	if (nodes)
		free(nodes);
	return a;
err:
	iflow_transitive_destroy(a);
	a = NULL;
	goto out;
}

/* Random shuffle from Knuth Seminumerical Algorithms p. 139 */
static void shuffle_list(int len, int *list)
{
	float U;
	int j, k, tmp;

	srand((int)time(NULL));

	for (j = len - 1; j > 0; j--) {
		/* get a random number between 1 and j */
		U = rand() / (float)RAND_MAX;
		k = ((int)(j * U)) + 1;
		tmp = list[k];
		list[k] = list[j];
		list[j] = tmp;
	}
}

static int get_random_edge_list(int edges_len, int **edge_list)
{

	int i;

	*edge_list = (int*)malloc(sizeof(int) * edges_len);
	if (!*edge_list) {
		fprintf(stderr, "Memory error\n");
		return -1;
	}
	for (i = 0; i < edges_len; i++)
		(*edge_list)[i] = i;

	shuffle_list(edges_len, *edge_list);

	return 0;
}

typedef struct bfs_random_state {
	iflow_graph_t *g;
	queue_t queue;
	iflow_query_t *q;
	policy_t *policy;
	iflow_transitive_t *a;
	int *path;
	int num_nodes;
	int *nodes;
	int num_enodes;
	int *enodes;
	int cur;
} bfs_random_state_t;

void bfs_random_state_destroy(bfs_random_state_t *s)
{
	if (s->g) {
		iflow_graph_destroy(s->g);
		free(s->g);
	}

	if (s->q)
		iflow_query_destroy(s->q);

	if (s->queue) {
		queue_destroy(s->queue);
	}

	if (s->path)
		free(s->path);
	if (s->nodes)
		free(s->nodes);
	if (s->enodes)
		free(s->enodes);
}

int bfs_random_state_init(bfs_random_state_t *s, policy_t *p, iflow_query_t *q, iflow_transitive_t *a)
{
	assert(s);
	memset(s, 0, sizeof(bfs_random_state_t));
	s->policy = p;
	s->a = a;

	s->q = iflow_query_create();
	if (!s->q) {
		fprintf(stderr, "Error creating query\n");
		return -1;
	}

	if (iflow_query_copy(s->q, q)) {
		fprintf(stderr, "Error copy query\n");
		return -1;
	}

	if (!iflow_query_is_valid(q, p))
		return -1;

	if (q->num_end_types != 1) {
		fprintf(stderr, "You must provide exactly 1 end type\n");
		return -1;
	}


	s->g = iflow_graph_create(p, q);
	if (!s->g) {
		fprintf(stderr, "Error creating graph\n");
		return -1;
	}

	s->queue = queue_create();
	if (!s->queue) {
		fprintf(stderr, "Error creating queue\n");
		goto err;
	}

	if (iflow_graph_get_nodes_for_type(s->g, q->start_type, &s->num_nodes, &s->nodes) < 0)
		goto err;
	if (iflow_graph_get_nodes_for_type(s->g, q->end_types[0], &s->num_enodes, &s->enodes) <0)
		goto err;

	s->path = (int*)malloc(sizeof(int) * s->g->num_nodes);
	if (!s->path) {
		fprintf(stderr, "Memory error\n");
		goto err;
	}

	return 0;
err:
	bfs_random_state_destroy(s);
	return -1;
}

static int breadth_first_find_path(iflow_graph_t *g, int node, int *path)
{
	int next_node = node;
	int path_len = g->nodes[node].distance + 1;
	int i = path_len - 1;

	while (i >= 0) {
		path[i] = next_node;
		next_node = g->nodes[next_node].parent;
		i--;
	}

	return path_len;
}

static int do_breadth_first_search_random(bfs_random_state_t *s)
{
	int i, ret = 0, path_len, *edge_list = NULL;
	int num_edges, cur;
	void *cur_ptr;
	bool_t found_new_path = FALSE;

	while (queue_head(s->queue)) {

		cur_ptr = queue_remove(s->queue);
		if (cur_ptr == NULL) {
			ret = -1;
			goto out;
		}
		cur = ((int)cur_ptr) - 1;

		if (find_int_in_array(cur, s->enodes, s->num_enodes) != -1) {
			path_len = breadth_first_find_path(s->g, cur, s->path);
			if (path_len == -1) {
				ret = -1;
				goto out;
			}
			ret = transitive_answer_append(s->g, s->q, s->a, cur, path_len, s->path);
			if (ret == -1) {
				fprintf(stderr, "Error in transitive answer append\n");
				goto out;
			} else if (ret > 0) {
				found_new_path = TRUE;
			}
		}

		s->g->nodes[cur].color = IFLOW_COLOR_BLACK;
		if (s->q->direction == IFLOW_OUT)
			num_edges = s->g->nodes[cur].num_out_edges;
		else
			num_edges = s->g->nodes[cur].num_in_edges;
		if (num_edges) {
			if (get_random_edge_list(num_edges, &edge_list) < 0) {
				ret = -1;
				goto out;
			}
		}
		for (i = 0; i < num_edges; i++) {
			int cur_edge, cur_node;
			if (s->q->direction == IFLOW_OUT) {
				cur_edge = s->g->nodes[cur].out_edges[edge_list[i]];
				cur_node = s->g->edges[cur_edge].end_node;
			} else {
				cur_edge = s->g->nodes[cur].in_edges[edge_list[i]];
				cur_node = s->g->edges[cur_edge].start_node;
			}
			if (s->g->nodes[cur_node].color == IFLOW_COLOR_WHITE) {
				s->g->nodes[cur_node].color = IFLOW_COLOR_GREY;
				s->g->nodes[cur_node].distance = s->g->nodes[cur].distance + 1;
				s->g->nodes[cur_node].parent = cur;
				if (queue_insert(s->queue, (void*)(cur_node + 1)) < 0) {
					fprintf(stderr, "Error inserting into queue\n");
					ret = -1;
					goto out;
				}
			}
		}
		if (edge_list) {
			free(edge_list);
			edge_list = NULL;
		}
	}

	if (found_new_path)
		ret = 1;
out:
	if (edge_list)
		free(edge_list);
	return ret;
}

int iflow_find_paths_next(void *state)
{
	int j, start_node;
	bfs_random_state_t *s = (bfs_random_state_t*)state;
	int num_paths;

	/* paint all nodes white */
	for (j = 0; j < s->g->num_nodes; j++) {
		s->g->nodes[j].color = IFLOW_COLOR_WHITE;
		s->g->nodes[j].parent = -1;
		s->g->nodes[j].distance = -1;
	}

	start_node = s->nodes[s->cur];

	s->g->nodes[start_node].color = IFLOW_COLOR_GREY;
	s->g->nodes[start_node].distance = 0;
	s->g->nodes[start_node].parent = -1;

	if (queue_insert(s->queue, (void*)(start_node + 1)) < 0) {
		fprintf(stderr, "Error inserting into queue\n");
		return -1;
	}

	if (do_breadth_first_search_random(s) < 0)
		return -1;

	s->cur++;
	if (s->cur >= s->num_nodes) {
		s->cur = 0;
		shuffle_list(s->num_nodes, s->nodes);
	}

	if (s->a->num_paths)
		num_paths = s->a->num_paths[0];
	else
		num_paths = 0;

	return num_paths;
}

/* caller does not need to free the query */
void *iflow_find_paths_start(policy_t *policy, iflow_query_t *q)
{
	bfs_random_state_t *s;
	iflow_transitive_t *a;

	s = (bfs_random_state_t*)malloc(sizeof(bfs_random_state_t));
	if (!s) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}

	a = (iflow_transitive_t*)malloc(sizeof(iflow_transitive_t));
	if (!a) {
		free(s);
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(a, 0, sizeof(iflow_transitive_t));

	if (bfs_random_state_init(s, policy, q, a)) {
		fprintf(stderr, "Random state init error\n");
		free(s);
		free(a);
		return NULL;
	}
	return (void*)s;
}

iflow_transitive_t *iflow_find_paths_end(void *state)
{
	bfs_random_state_t *s = (bfs_random_state_t*)state;
	iflow_transitive_t *a;
	int i;

	a = s->a;
	bfs_random_state_destroy(s);
	free(s);

	/* sort the paths by length */
	for (i = 0; i < a->num_end_types; i++) {
		/* sort the paths by length */
		a->paths[i] = iflow_sort_paths(a->paths[i]);
		if (a->paths[i] == NULL) {
			return NULL;
		}
	}

	return a;
}

void iflow_find_paths_abort(void *state)
{
	bfs_random_state_t *s = (bfs_random_state_t*)state;

	bfs_random_state_destroy(s);
	free(s);
	iflow_transitive_destroy(s->a);
}

#endif
