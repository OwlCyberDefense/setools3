/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 */

#include "sort.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static sort_action_node_t *current_list = NULL;

#define sort_type_check(a, b, types) assert(((msg_t*)a)->msg_type & types && \
                                            ((msg_t*)b)->msg_type & types)

static int compare_chain(const msg_t *a, const msg_t *b, sort_action_node_t *cl) {
	if (cl->next) {
		sort_type_check(a, b, cl->next->msg_types);
		return cl->next->sort(a, b, cl->next);
	} else {
		return 0;
	}
}

void sort_action_list_destroy(sort_action_node_t *cl)
{
	sort_action_node_t *cur, *next;

	cur = cl;
	while (cur) {
		next = cur->next;
		free(cur);
		cur = next;
	}
}

int audit_log_append_sort(audit_log_t *log, sort_action_node_t *node)
{
	if (!log->sort_actions) {
		log->sort_actions = node;
		log->last_sort_action = node;
		return 0;
	}
	log->last_sort_action->next = node;
	node->prev = log->last_sort_action->next;
	log->last_sort_action = node;
	return 0;
}

int audit_log_remove_sort(audit_log_t *log, sort_action_node_t *node)
{
	sort_action_node_t *cur;

	for (cur = log->sort_actions; cur; cur = cur->next) {
		if (cur == node) {
			if (cur == log->last_sort_action) {
				log->last_sort_action = cur->prev;
				cur->prev->next = NULL;
			} else if (cur == log->sort_actions) {
				if (cur->next) {
					log->sort_actions = cur->next;
					cur->next->prev = NULL;
				} else {
					log->sort_actions = NULL;
				}
			} else {
				cur->prev->next = cur->next;
				cur->next->prev = cur->prev;
			}
			return 0;
		}
	}
	return 1;
}


int audit_log_sort(audit_log_t *log)
{
	if (!log->fltr_msgs || !log->sort_actions)
		return -1;
	if (log->num_fltr_msgs == 1)
		/* that was easy */
		return 0;

	current_list = log->sort_actions;
	qsort(log->fltr_msgs, log->num_fltr_msgs, sizeof(msg_t*), &msg_compare);
	return 0;
}

int msg_compare(const void *a, const void *b)
{
	assert(current_list);
       	sort_type_check(a, b, current_list->msg_types);
	return current_list->sort((const msg_t*)a, (const msg_t*)b, current_list);
}

static int date_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	time_t at, bt;
	at = mktime(a->date_stamp);
	bt = mktime(b->date_stamp);
	if (at == bt)
		return compare_chain(a, b, cl);
	if (at < bt)
		return -1;
	else
		return 1;

}

static int src_user_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->src_user == msg_get_avc_data(b)->src_user) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->src_user < msg_get_avc_data(b)->src_user) {
		return -1;
	} else {
		return 1;
	}
}

static int tgt_user_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->tgt_user == msg_get_avc_data(b)->tgt_user) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->tgt_user < msg_get_avc_data(b)->tgt_user) {
		return -1;
	} else {
		return 1;
	}
}

static int src_role_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->src_role == msg_get_avc_data(b)->src_role) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->src_role < msg_get_avc_data(b)->src_role) {
		return -1;
	} else {
		return 1;
	}
}

static int tgt_role_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->tgt_role == msg_get_avc_data(b)->tgt_role) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->tgt_role < msg_get_avc_data(b)->tgt_role) {
		return -1;
	} else {
		return 1;
	}
}

static int src_type_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->src_type == msg_get_avc_data(b)->src_type) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->src_type < msg_get_avc_data(b)->src_type) {
		return -1;
	} else {
		return 1;
	}
}

static int tgt_type_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->tgt_type == msg_get_avc_data(b)->tgt_type) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->tgt_type < msg_get_avc_data(b)->tgt_type) {
		return -1;
	} else {
		return 1;
	}
}

static int obj_class_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->obj_class == msg_get_avc_data(b)->obj_class) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->obj_class < msg_get_avc_data(b)->obj_class) {
		return -1;
	} else {
		return 1;
	}
}

static int exe_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	int ret = strcmp(msg_get_avc_data(a)->exe, msg_get_avc_data(b)->exe);
	if (ret == 0)
		return compare_chain(a, b, cl);
	else
		return ret;
}

static int path_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	int ret = strcmp(msg_get_avc_data(a)->path, msg_get_avc_data(b)->path);
	if (ret == 0)
		return compare_chain(a, b, cl);
	else
		return ret;
}

static int dev_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	int ret = strcmp(msg_get_avc_data(a)->dev, msg_get_avc_data(b)->dev);
	if (ret == 0)
		return compare_chain(a, b, cl);
	else
		return ret;
}

static int inode_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->inode == msg_get_avc_data(b)->inode) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->inode < msg_get_avc_data(b)->inode) {
		return -1;
	} else {
		return 1;
	}
}

static int pid_compare(const msg_t *a, const msg_t *b, sort_action_node_t *cl)
{
	if (msg_get_avc_data(a)->pid == msg_get_avc_data(b)->pid) {
		return compare_chain(a, b, cl);
	} else if (msg_get_avc_data(a)->pid < msg_get_avc_data(b)->pid) {
		return -1;
	} else {
		return 1;
	}
}

static sort_action_node_t *sort_action_node_create(void)
{
	sort_action_node_t *cl;
	cl = (sort_action_node_t*)malloc(sizeof(sort_action_node_t));
	if (!cl) {
		fprintf(stderr, "Out of memory\n");
		return NULL;
	}
	memset(cl, 0, sizeof(sort_action_node_t));
	return cl;
}

sort_action_node_t *date_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &date_compare;
	return node;
}

sort_action_node_t *src_user_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &src_user_compare;
	return node;
}

sort_action_node_t *tgt_user_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &tgt_user_compare;
	return node;
}

sort_action_node_t *src_role_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &src_role_compare;
	return node;
}

sort_action_node_t *tgt_role_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &tgt_role_compare;
	return node;
}

sort_action_node_t *src_type_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &src_type_compare;
	return node;
}

sort_action_node_t *tgt_type_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &tgt_type_compare;
	return node;
}

sort_action_node_t *obj_class_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &obj_class_compare;
	return node;
}

sort_action_node_t *exe_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &exe_compare;
	return node;
}

sort_action_node_t *path_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &path_compare;
	return node;
}

sort_action_node_t *dev_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &dev_compare;
	return node;
}

sort_action_node_t *inode_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &inode_compare;
	return node;
}

sort_action_node_t *pid_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &pid_compare;
	return node;
}
