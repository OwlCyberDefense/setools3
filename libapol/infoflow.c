/* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: kmacmillan@tresys.com
 * Modified by: mayerf@tresys.com (Apr 2004) - separated information
 *   flow from main analysis.c file, and added noflow/onlyflow batch
 *   capabilitiy.
 */

/* infoflow.c
 *
 * Information Flow analysis routines for libapol
 */
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <time.h>

#include "policy.h"
#include "util.h"
#include "infoflow.h"
#include "policy-query.h"
#include "queue.h"

/*
 * Nodes in the graph represent either a type used in the source
 * of an allow rule or the target: these defines are used to
 * represent which.
 */
#define IFLOW_SOURCE_NODE 	0x0
#define IFLOW_TARGET_NODE 	0x1

/*
 * These defines are used to color nodes in the graph algorithms.
 */
#define IFLOW_COLOR_WHITE 0
#define IFLOW_COLOR_GREY  1
#define IFLOW_COLOR_BLACK 2
#define IFLOW_COLOR_RED   3

typedef struct iflow_edge {
	int num_rules;
	int *rules;
	int start_node; /* index into iflow_graph->nodes */
	int end_node; /* index into iflow_graph->nodes */
	int length;
} iflow_edge_t;

typedef struct iflow_node {
	int type;
	int node_type;
	int obj_class;
	int num_in_edges;
	int *in_edges;
	int num_out_edges;
	int *out_edges;
	unsigned char color;
	int parent;
	int distance;
} iflow_node_t;

typedef struct iflow_graph {
	int num_nodes; /* the number of slots used in nodes */
	iflow_node_t *nodes;
	int *src_index;
	int *tgt_index;
	int num_edges;
	iflow_edge_t *edges;
	policy_t *policy;
	iflow_query_t *query;
} iflow_graph_t;

/* iflow_query_t */
iflow_query_t *iflow_query_create(void)
{
	iflow_query_t* q = (iflow_query_t*)malloc(sizeof(iflow_query_t));
	if (q == NULL) {
		fprintf(stderr, "Memory error!\n");
		return NULL;
	}
	memset(q, 0, sizeof(iflow_query_t));
	q->start_type = -1;
	q->direction = IFLOW_IN;

	return q;
}

static int iflow_obj_options_copy(obj_perm_set_t *dest, obj_perm_set_t *src)
{
        dest->obj_class = src->obj_class;
        dest->num_perms = src->num_perms;
        if (src->num_perms) {
                assert(src->perms);
                if (copy_int_array(&dest->perms, src->perms, src->num_perms))
                        return -1;
        }
        return 0;
}

/* perform a deep copy of an iflow_query_t - dest should be
 * a newly created iflow_query */
static int iflow_query_copy(iflow_query_t *dest, iflow_query_t *src)
{
        int i;

        assert(dest && src);
        dest->start_type = src->start_type;
        dest->direction = src->direction;
        if (src->num_end_types) {
                assert(src->end_types);
                if (copy_int_array(&dest->end_types, src->end_types, src->num_end_types))
                        return -1;
                dest->num_end_types = src->num_end_types;
        }
        
        if (src->num_types) {
                assert(src->types);
                if (copy_int_array(&dest->types, src->types, src->num_types))
                        return -1;
                dest->num_types = src->num_types;
        }

        if (src->num_obj_options) {
                assert(src->obj_options);
                dest->obj_options = (obj_perm_set_t*)malloc(sizeof(obj_perm_set_t) * 
                                                                 src->num_obj_options);
                if (!dest->obj_options) {
                        fprintf(stderr, "Memory error\n");
                        return -1;
                }
                memset(dest->obj_options, 0, sizeof(obj_perm_set_t) * src->num_obj_options);
                for (i = 0; i < src->num_obj_options; i++) {
                        if (iflow_obj_options_copy(dest->obj_options + i, src->obj_options + i))
                                return -1;
                }
                dest->num_obj_options = src->num_obj_options;
        }
        return 0;
}

void iflow_query_destroy(iflow_query_t *q)
{
	int i;

	if (q->end_types)
		free(q->end_types);
	if (q->types)
		free(q->types);

	for (i = 0; i < q->num_obj_options; i++) {
		if (q->obj_options[i].perms)
			free(q->obj_options[i].perms);
	}
	if (q->obj_options)
		free(q->obj_options);
	free(q);
}

/* Object class filter macros.
 *	Transitive information flow - if perms is non-NULL then only those 
 *	permissions are ignored, otherwise the entire object class is ignored. 
 */
int iflow_query_add_obj_class(iflow_query_t *q, int obj_class)
{
	return apol_add_class_to_obj_perm_set_list(&q->obj_options, &q->num_obj_options, obj_class);

}

int iflow_query_add_obj_class_perm(iflow_query_t *q, int obj_class, int perm)
{
	return apol_add_perm_to_obj_perm_set_list(&q->obj_options, &q->num_obj_options, obj_class, perm);
}

int iflow_query_add_end_type(iflow_query_t *q, int end_type)
{
	return policy_query_add_type(&q->end_types, &q->num_end_types, end_type);
}

int iflow_query_add_type(iflow_query_t *q, int type)
{
	return policy_query_add_type(&q->types, &q->num_types, type);
}

/*
 * Check that the iflow_obj_option_t is valid for the graph/policy.
 */
bool_t iflow_obj_option_is_valid(obj_perm_set_t *o, policy_t *policy)
{
	int i;

	assert(o && policy);

	if (!is_valid_obj_class_idx(o->obj_class, policy))
		return FALSE;

	if (o->num_perms) {
		if (!o->perms) {
			fprintf(stderr, "query with num_perms %d and perms is NULL\n", o->num_perms);
			return FALSE;
		}
		for (i = 0; i < o->num_perms; i++) {
			if (!is_valid_perm_for_obj_class(policy, o->obj_class, o->perms[i])) {
				fprintf(stderr, "query with invalid perm %d for object class %d\n",
					o->perms[i], o->obj_class);
				return FALSE;
			}
		}
	}
	return TRUE;
}

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

/* iflow_t */

int iflow_init(iflow_graph_t *g, iflow_t *flow)
{
	memset(flow, 0, sizeof(iflow_t));
	flow->num_obj_classes = g->policy->num_obj_classes;
	flow->obj_classes = (iflow_obj_class_t*)malloc(sizeof(iflow_obj_class_t) *
						       flow->num_obj_classes);
	if (!flow->obj_classes) {
		fprintf(stderr, "Memory Error\n");
		return -1;
	}
	memset(flow->obj_classes, 0, sizeof(iflow_obj_class_t) *
	       flow->num_obj_classes);
	return 0;
}

static void iflow_destroy_data(iflow_t *flow)
{
	int i;
	
	if (flow->obj_classes) {
		for (i = 0; i < flow->num_obj_classes; i++) {
			if (flow->obj_classes[i].rules)
				free(flow->obj_classes[i].rules);
		}
		free(flow->obj_classes);
	}
}

void iflow_destroy(iflow_t *flow)
{
	if (!flow)
		return;
	
	iflow_destroy_data(flow);

	free(flow);
}

/* iflow_transitive_t */

static void iflow_path_destroy(iflow_path_t *path)
{
	int i;

	if (!path)
		return;
	for (i = 0; i < path->num_iflows; i++) {
		iflow_destroy_data(&path->iflows[i]);
	}
	if (path->iflows)
		free(path->iflows);
	free(path);
}

static void iflow_path_destroy_list(iflow_path_t *path)
{
	iflow_path_t *next;

	while (path) {
		next = path->next;
		iflow_path_destroy(path);
		path = next;
	}
}

void iflow_transitive_destroy(iflow_transitive_t *flow)
{
	int i;

	if (!flow)
		return;

	if (flow->end_types)
		free(flow->end_types);
	for (i = 0; i < flow->num_end_types; i++) {
		iflow_path_destroy_list(flow->paths[i]);
	}
	if (flow->paths)
		free(flow->paths);
	if (flow->num_paths)
		free(flow->num_paths);
	free(flow);
}

/* iflow_node_t */

static void iflow_node_destroy_data(iflow_node_t *node)
{
	if (!node)
		return;
	if (node->in_edges)
		free(node->in_edges);
	if (node->out_edges)
		free(node->out_edges);
}

/* iflow_graph_t */

#define get_src_index(type) type
#define get_tgt_index(g, type, obj_class) ((type * g->policy->num_obj_classes) + obj_class)

static iflow_graph_t *iflow_graph_alloc(policy_t *policy)
{
	iflow_graph_t *g;
	int index_size;

	g = (iflow_graph_t*)malloc(sizeof(iflow_graph_t));
	if (!g) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(g, 0, sizeof(iflow_graph_t));

	index_size = policy->num_types;
	g->src_index = (int*)malloc(sizeof(int) * index_size);
	if (!g->src_index) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(g->src_index, -1, sizeof(int) * index_size);
	
	index_size = policy->num_types * policy->num_obj_classes;
	g->tgt_index = (int*)malloc(sizeof(int) * index_size);
	if (!g->tgt_index) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(g->tgt_index, -1, sizeof(int) * index_size);
	
	g->policy = policy;
	return g;
}

void iflow_graph_destroy(iflow_graph_t *g)
{
	int i;

	if (!g)
		return;

	for (i = 0; i < g->num_nodes; i++)
		iflow_node_destroy_data(&g->nodes[i]);

	if (g->src_index)
		free(g->src_index);
	if (g->tgt_index)
		free(g->tgt_index);

	if (g->nodes)
		free(g->nodes);
	if (g->edges) {
		for (i = 0; i < g->num_edges; i++) {
			if (g->edges[i].rules)
				free(g->edges[i].rules);
		}
		free(g->edges);
	}
}

static int iflow_graph_get_nodes_for_type(iflow_graph_t *g, int type, int *len, int **types)
{
	int i;

	*len = 0;
	*types = NULL;

	if (g->src_index[get_src_index(type)] >= 0)
		if (add_i_to_a(g->src_index[get_src_index(type)], len, types) < 0)
			return -1;
	for (i = 0; i < g->policy->num_obj_classes; i++) {
		if (g->tgt_index[get_tgt_index(g, type, i)] >= 0)
			if (add_i_to_a(g->tgt_index[get_tgt_index(g, type, i)], len, types) < 0)
				return -1;
	}
	return 0;
}

static int iflow_graph_connect(iflow_graph_t *g, int start_node, int end_node, int length)
{

	iflow_node_t* start, *end;
	int i;

	start = &g->nodes[start_node];
	end = &g->nodes[end_node];

	for (i = 0; i < start->num_out_edges; i++) {
		if (g->edges[start->out_edges[i]].end_node == end_node) {
			if (g->edges[start->out_edges[i]].length < length)
				g->edges[start->out_edges[i]].length = length;
			return start->out_edges[i];
		}
	}

	g->edges = (iflow_edge_t*)realloc(g->edges, (g->num_edges + 1)
					  * sizeof(iflow_edge_t));
	if (g->edges == NULL) {
		fprintf(stderr, "Memory error!\n");
		return -1;
	}

	memset(&g->edges[g->num_edges], 0, sizeof(iflow_edge_t));
	
	g->edges[g->num_edges].start_node = start_node;
	g->edges[g->num_edges].end_node = end_node;
	g->edges[g->num_edges].length = length;
	
	if (add_i_to_a(g->num_edges, &start->num_out_edges, &start->out_edges) != 0) {
		return -1;
	}	

	if (add_i_to_a(g->num_edges, &end->num_in_edges, &end->in_edges) != 0) {
		return -1;
	}

	g->num_edges++;
	return g->num_edges - 1;
}

static int iflow_graph_add_node(iflow_graph_t *g, int type, int node_type, int obj_class)
{
	assert(node_type == IFLOW_SOURCE_NODE || node_type == IFLOW_TARGET_NODE);

	/* check for an existing node and update the indexes if not */
	if (node_type == IFLOW_SOURCE_NODE) {
		if (g->src_index[get_src_index(type)] >= 0)
			return g->src_index[get_src_index(type)];
		else
			g->src_index[type] = g->num_nodes;
	} else {
		if (g->tgt_index[get_tgt_index(g, type, obj_class)] >= 0) {
			return g->tgt_index[get_tgt_index(g, type, obj_class)];
		} else {
			g->tgt_index[get_tgt_index(g, type, obj_class)] = g->num_nodes;
		}
	}
	
	/* create a new node */
	g->nodes = (iflow_node_t*)realloc(g->nodes, sizeof(iflow_node_t) * (g->num_nodes + 1));
	if (!g->nodes) {
		fprintf(stderr, "Memory error\n");
		return -1;
	}
	memset(&g->nodes[g->num_nodes], 0, sizeof(iflow_node_t));
	g->nodes[g->num_nodes].node_type = node_type;
	g->nodes[g->num_nodes].type = type;
	g->nodes[g->num_nodes].obj_class = obj_class;
	
	g->num_nodes++;
	return g->num_nodes - 1;
}

/* helper for iflow_graph_create */
static int add_edges(iflow_graph_t* g, int obj_class, int rule_idx, bool_t found_read, int read_len,
	bool_t found_write, int write_len) {
	int i, j, k, ret;
	int src_node, tgt_node;

	bool_t all_src_types = FALSE;
	int cur_src_type;
	int num_src_types = 0;
	int* src_types = NULL;

	bool_t all_tgt_types = FALSE;
	int cur_tgt_type;
	int num_tgt_types = 0;
	int *tgt_types = NULL;

	av_item_t* rule;

	/* extract all of the rules */
	rule = &g->policy->av_access[rule_idx];

	ret = extract_types_from_te_rule(rule_idx, RULE_TE_ALLOW, SRC_LIST, &src_types, &num_src_types, g->policy);
	if (ret == -1)
		return -1;
	if (ret == 2)
		all_src_types = TRUE;

	ret = extract_types_from_te_rule(rule_idx, RULE_TE_ALLOW, TGT_LIST, &tgt_types, &num_tgt_types, g->policy);
	if (ret == -1)
		return -1;
	if (ret == 2)
		all_tgt_types = TRUE;
	
	for (i = 0; i < num_src_types; i++) {
		if (all_src_types) {
			/* skip self */
			if (i == 0)
				continue;
			cur_src_type = i;
		} else {
			cur_src_type = src_types[i];
		}
		/* self should never be a src type */
		assert(cur_src_type);

		if (g->query->num_types) {
			bool_t filter_type = FALSE;
			for (k = 0; k < g->query->num_types; k++) {
				if (g->query->types[k] == cur_src_type) {
					filter_type = TRUE;
					break;
				}
			}
			if (filter_type) {
				continue;
			}
		}

		/* add the source type */
		src_node = iflow_graph_add_node(g, cur_src_type, IFLOW_SOURCE_NODE, -1);
		if (src_node < 0)
			return -1;
		
		for (j = 0; j < num_tgt_types; j++) {
			int edge;
			
			if (all_tgt_types) {
				cur_tgt_type = j;
				if (j == 0)
					continue;
			} else if (tgt_types[j]==0) {
				/* idx 0 is self */
				cur_tgt_type = cur_src_type;
			} else {
				cur_tgt_type = tgt_types[j];
			}
			
			if (g->query->num_types) {
				bool_t filter_type = FALSE;
				for (k = 0; k < g->query->num_types; k++) {
					if (g->query->types[k] == cur_tgt_type) {
						filter_type = TRUE;
						break;
					}
				}
				if (filter_type) {
					continue;
				}
			}
			
			/* add the target type */
			tgt_node = iflow_graph_add_node(g, cur_tgt_type, IFLOW_TARGET_NODE, obj_class);
			if (tgt_node < 0)
				return -1;
			
			if (found_read) {
				edge = iflow_graph_connect(g, tgt_node, src_node, read_len);
				if (edge < 0) {
					fprintf(stderr, "Could not add edge!\n");
					return -1;
				}
				
				if (add_i_to_a(rule_idx, &g->edges[edge].num_rules,
					       &g->edges[edge].rules) != 0) {
					fprintf(stderr, "Could not add rule!\n");
				}
			}
			if (found_write) {
				edge = iflow_graph_connect(g, src_node, tgt_node, write_len);
				if (edge < 0) {
					fprintf(stderr, "Could not add edge!\n");
					return -1;
				}
				
				if (add_i_to_a(rule_idx, &g->edges[edge].num_rules,
					       &g->edges[edge].rules) != 0) {
					fprintf(stderr, "Could not add rule!\n");
				}
			}
		}
	}
	if (!all_src_types) {
		free(src_types);
	}
	if (!all_tgt_types) {
		free(tgt_types);
	}
	return 0;
}

/*
 * Create an information flow graph of a policy.
 */
iflow_graph_t *iflow_graph_create(policy_t* policy, iflow_query_t *q)
{
	int i, j, k, l, ret;
	unsigned char map;
	iflow_graph_t* g;
	bool_t perm_error = FALSE;
        int max_len = PERMMAP_MAX_WEIGHT - q->min_weight + 1;

	assert(policy && q);

	if (policy->pmap == NULL) {
		fprintf(stderr, "Perm map must be loaded first.\n");
		return NULL;
	}
	
	g = iflow_graph_alloc(policy);
	if (g == NULL)
		return NULL;
	g->query = q;

	for (i = 0; i < policy->num_av_access; i++) {
		av_item_t* rule;
		int cur_obj_class, num_obj_classes = 0, *obj_classes = NULL;
		bool_t all_obj_classes = FALSE, all_perms = FALSE;
		int cur_perm, num_perms = 0, *perms = NULL;

		rule = &policy->av_access[i];
		if (rule->type != RULE_TE_ALLOW)
			continue;
		if (!rule->enabled)
			continue;
		
		/* get the object classes for this rule */
		ret = extract_obj_classes_from_te_rule(i, RULE_TE_ALLOW, &obj_classes, &num_obj_classes, policy);
		if (ret == -1) {
			iflow_graph_destroy(g);
			return NULL;
		} else if (ret == 2) {
			all_obj_classes = TRUE;
		}
		
		ret = extract_perms_from_te_rule(i, RULE_TE_ALLOW, &perms, &num_perms, policy);
		if (ret == -1) {
			iflow_graph_destroy(g);
			if (!all_obj_classes)
				free(obj_classes);
			return NULL;
		} else if (ret == 2) {
			all_perms = TRUE;
		}

		/* find read or write flows for each object class */
		for (j = 0; j < num_obj_classes; j++ ) {
			class_perm_map_t* cur_pmap;
			bool_t found_read = FALSE, found_write = FALSE;
			int cur_obj_options = -1;
			int len = 0, read_len, write_len;

			if (all_obj_classes)
				cur_obj_class = j;
			else
				cur_obj_class = obj_classes[j];

			/* Check to see if we should filter this object class. If we find
			 * the object class in the obj_options and it doesn't list specific
			 * perms then we filter. If we find the object class in the obj_options
			 * but it has specific perms we save the index into obj_options and
			 * check the perms below */
			if (q->num_obj_options != 0) {
				bool_t filter_obj_class = FALSE;
				for (k = 0; k < q->num_obj_options; k++) {
					if (q->obj_options[k].obj_class == cur_obj_class) {
						if (q->obj_options[k].num_perms == 0)
							filter_obj_class = TRUE;
						else
							cur_obj_options = k;
						break;
					}
				}
				if (filter_obj_class)
					continue;
			}

			cur_pmap = &policy->pmap->maps[cur_obj_class];
			if (all_perms) {
				ret = get_obj_class_perms(cur_obj_class, &num_perms, &perms, policy);
				if (ret != 0) {
					iflow_graph_destroy(g);	
					if (!all_obj_classes)
						free(obj_classes);
					return NULL;
				}
			}
			
			read_len = write_len = INT_MAX;
			for (k = 0; k < num_perms; k++) {
				cur_perm = perms[k];
				/* Check to see if we should ignore this permission */
				if (cur_obj_options >= 0) {
					bool_t filter_perm = FALSE;
					for (l = 0; l < q->obj_options[cur_obj_options].num_perms; l++) {
						if (q->obj_options[cur_obj_options].perms[l] == cur_perm) {
							filter_perm = TRUE;
							break;
						}
					}
					if (filter_perm)
						continue;
				}

				/* get the mapping for the perm */
				map = 0;
				for (l = 0; l < cur_pmap->num_perms; l++) {
					if (cur_pmap->perm_maps[l].perm_idx == cur_perm) {
						map = cur_pmap->perm_maps[l].map;
						len = PERMMAP_MAX_WEIGHT - cur_pmap->perm_maps[l].weight + 1;
						if (len < PERMMAP_MIN_WEIGHT)
							len = PERMMAP_MIN_WEIGHT;
						else if (len > PERMMAP_MAX_WEIGHT)
							len = PERMMAP_MAX_WEIGHT;
						break;
					}
				}
				if (map == 0) {
					perm_error = TRUE;
					continue;
				}
				if (map & PERMMAP_READ) {
                                        if (len < read_len && len <= max_len) {
                                                found_read = TRUE;
						read_len = len;
                                        }
				}
				if (map & PERMMAP_WRITE) {
					if (len < write_len && len <= max_len) {
                                                found_write = TRUE;
						write_len = len;
                                        }
				}
			}
			if (all_perms)
				free(perms);

			if (!found_read && !found_write) {
				continue;
			}

			/* if we have found any flows add the edge */
			if (add_edges(g, cur_obj_class, i, found_read, read_len, found_write, write_len) != 0) {
				iflow_graph_destroy(g);
				if (!all_perms)
					free(perms);
				if (!all_obj_classes)
					free(obj_classes);
				return NULL;
			}

			
		}
		if (!all_perms)
			free(perms);
		if (!all_obj_classes)
			free(obj_classes);
	}

	if (perm_error)
		fprintf(stderr, "Not all of the permissions found had associated permission maps.\n");

	return g;
}

/* direct information flow */

/* helper for iflow_direct_flows */
static bool_t edge_matches_query(iflow_graph_t* g, iflow_query_t* q, int edge)
{
	int end_type, ending_node;
	
	if (g->nodes[g->edges[edge].start_node].type == q->start_type) {
		ending_node = g->edges[edge].end_node;
	} else {
		ending_node = g->edges[edge].start_node;
	}

	if (q->num_end_types != 0) {
		end_type = g->nodes[ending_node].type;
		if (find_int_in_array(end_type, q->end_types, q->num_end_types) == -1)
			return FALSE;
	}

	return TRUE;
}

static int iflow_define_flow(iflow_graph_t *g, iflow_t *flow, int direction, int start_node, int edge)
{
	int i, end_node, obj_class;
	iflow_edge_t *edge_ptr;
	
	edge_ptr = &g->edges[edge];

	if (edge_ptr->start_node == start_node) {
		end_node = edge_ptr->end_node;
	} else {
		end_node = edge_ptr->start_node;
	}

	flow->direction |= direction;
	flow->start_type = g->nodes[start_node].type;
	flow->end_type = g->nodes[end_node].type;
	
	obj_class = g->nodes[edge_ptr->start_node].obj_class;
	if (obj_class == -1)
		obj_class = g->nodes[edge_ptr->end_node].obj_class;
	for (i = 0; i < edge_ptr->num_rules; i++) {
		if (find_int_in_array(edge_ptr->rules[i], flow->obj_classes[obj_class].rules,
				      flow->obj_classes[obj_class].num_rules) == -1) {
			if (add_i_to_a(edge_ptr->rules[i], &flow->obj_classes[obj_class].num_rules,
				       &flow->obj_classes[obj_class].rules) < 0) {
					return 	-1;
			}
		}
	}

	return 0;
}

static int direct_find_flow(iflow_graph_t *g, int start_node, int end_node, int *num_answers, iflow_t **answers)
{
	iflow_t *cur;
	int i;

	assert(num_answers);

	/* see if a flow already exists */
	if (*answers) {
		for (i = 0; i < *num_answers; i++) {
			cur = &(*answers)[i];
			if (cur->start_type == g->nodes[start_node].type &&
			    cur->end_type == g->nodes[end_node].type) {
				return i;
			}
		}
	}

	/* if we didn't find a matching flow make space for a new one */
	*answers = (iflow_t*)realloc(*answers, (*num_answers + 1)
				     * sizeof(iflow_t));
	if (*answers == NULL) {
		fprintf(stderr,	"Memory error!\n");
		return -1;
	}
	if (iflow_init(g, &(*answers)[*num_answers])) {
		return -1;
	}

	(*num_answers)++;
	return *num_answers - 1;
}

int iflow_direct_flows(policy_t *policy, iflow_query_t *q, int *num_answers,
		       iflow_t **answers)
{
	int i, j, edge, ret = 0;
	iflow_node_t* node;
	bool_t edge_matches;
	int num_nodes, *nodes;
	int flow, end_node;
	iflow_graph_t *g;

	if (!iflow_query_is_valid(q, policy))
		return -1;

	g = iflow_graph_create(policy, q);
	if (!g) {
		fprintf(stderr, "Error creating graph\n");
		return -1;
	}
	
	*num_answers = 0;
	*answers = NULL;
	
	if (iflow_graph_get_nodes_for_type(g, q->start_type, &num_nodes, &nodes) < 0)
		return -1;
	/*
	 * Because the graph doesn't contain every type (i.e. it is possible that the query
	 * made a type not match), not finding a node means that there are no flows. This
	 * used to indicate an error.
	 */
	if (num_nodes == 0) {
		return 0;
	}
	
	if (q->direction == IFLOW_IN || q->direction == IFLOW_EITHER || q->direction == IFLOW_BOTH) {
		for (i = 0; i < num_nodes; i++) {
			node = &g->nodes[nodes[i]];
			for (j = 0; j < node->num_in_edges; j++) {
				edge = node->in_edges[j];
				edge_matches = edge_matches_query(g, q, edge);
				if (!edge_matches)
					continue;

				if (g->edges[edge].start_node == nodes[i])
					end_node = g->edges[edge].end_node;
				else
					end_node = g->edges[edge].start_node;

				flow = direct_find_flow(g, nodes[i], end_node, num_answers, answers);
				if (flow < 0) {
					ret = -1;
					goto out;
				}
				if (iflow_define_flow(g, &(*answers)[flow], IFLOW_IN, nodes[i], edge)) {
					ret = -1;
					goto out;
				}
			}
		}
	}
	if (q->direction == IFLOW_OUT || q->direction == IFLOW_EITHER || q->direction == IFLOW_BOTH) {
		for (i = 0; i < num_nodes; i++) {
			node = &g->nodes[nodes[i]];
			for (j = 0; j < node->num_out_edges; j++) {
				edge = node->out_edges[j];
				edge_matches = edge_matches_query(g, q, edge);
				if (!edge_matches)
					continue;

				if (g->edges[edge].start_node == nodes[i])
					end_node = g->edges[edge].end_node;
				else
					end_node = g->edges[edge].start_node;

				flow = direct_find_flow(g, nodes[i], end_node, num_answers, answers);
				if (flow < 0) {
					ret = -1;
					goto out;
				}
				if (iflow_define_flow(g, &(*answers)[flow], IFLOW_OUT, nodes[i], edge)) {
					ret = -1;
					goto out;
				}
			}
		}
	}

	if (*num_answers == 0)
		goto out;

	/* do some extra checks for both */
	if (q->direction == IFLOW_BOTH) {
		int tmp_num_answers = *num_answers;
		iflow_t *tmp_answers = *answers;

		*num_answers = 0;
		*answers = NULL;

		for (i = 0; i < tmp_num_answers; i++) {
			if (tmp_answers[i].direction != IFLOW_BOTH) {
				iflow_destroy_data(&tmp_answers[i]);
				continue;
			}
			*answers = (iflow_t*)realloc(*answers, (*num_answers + 1)
						     * sizeof(iflow_t));
			if (*answers == NULL) {
				fprintf(stderr,	"Memory error!\n");
				goto out;
			}
			(*answers)[*num_answers] = tmp_answers[i];
			*num_answers += 1;
		}
		free(tmp_answers);
	}

out:
	if (nodes)
		free(nodes);
	iflow_graph_destroy(g);
	return ret;
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

/* This is a label correcting shortest path algorithm
 * see Bertsekas, D. P., "A Simple and Fast Label Correcting Algorithm for Shortest Paths,"
 * Networks, Vol. 23, pp. 703-709, 1993. for more information. A label correcting algorithm is
 * needed instead of the more common Dijkstra label setting algorithm to correctly handle the
 * the cycles that are possible in these graphs.
 *
 * This algorithm finds the shortest path between a given start node and all other nodes in
 * the graph. Any paths that it finds it appends to the iflow_transitive_t structure. This
 * is a basic label correcting algorithm with 1 optimization. It uses the D'Esopo-Pape method
 * for node selection in the node queue. Why is this faster? The paper referenced above says
 * "No definitive explanation has been given." They have fancy graphs to show that it is faster
 * though and the important part is that the worst case isn't much worse that N^2 - much better
 * than an n^3 transitive closure. Additionally, most normal sparse graphs are significantly better
 * than the worst case.
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
