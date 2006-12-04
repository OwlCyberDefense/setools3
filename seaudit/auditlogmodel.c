/* Copyright (C) 2003-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *         Kevin Carr <kcarr@tresys.com>
 *         Jeremy Stitz <jstitz@tresys.com>
 */

#include "auditlogmodel.h"
#include "seaudit_callback.h"
#include "parse.h"
#include "sort.h"
#include "seaudit.h"

#include <glib.h>
#include <stdlib.h>
#include <gtk/gtk.h>

static void log_view_store_init(SEAuditLogViewStore * store);
static void log_view_store_class_init(SEAuditLogViewStoreClass * class);
static void log_view_store_tree_model_init(GtkTreeModelIface * iface);
static void log_view_store_finalize(GObject * object);

static GtkTreeModelFlags log_view_store_get_flags(GtkTreeModel * tree_model);
static gint log_view_store_get_n_columns(GtkTreeModel * tree_model);
static GType log_view_store_get_column_type(GtkTreeModel * tree_model, gint index);
static gboolean log_view_store_get_iter(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreePath * path);
static GtkTreePath *log_view_store_get_path(GtkTreeModel * tree_model, GtkTreeIter * iter);
static void log_view_store_get_value(GtkTreeModel * tree_model, GtkTreeIter * iter, gint column, GValue * value);
static gboolean log_view_store_iter_next(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gboolean log_view_store_iter_children(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent);
static gboolean log_view_store_iter_has_child(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gint log_view_store_iter_n_children(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gboolean log_view_store_iter_nth_child(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent, gint n);
static gboolean log_view_store_iter_parent(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * child);

/* sorting */
static void seaudit_log_view_store_sortable_init(GtkTreeSortableIface * iface);
static gboolean seaudit_log_view_store_get_sort_column_id(GtkTreeSortable * sortable, gint * column_id, GtkSortType * order);
static void seaudit_log_view_store_set_sort_column_id(GtkTreeSortable * sortable, gint sort_column_id, GtkSortType order);
static gboolean seaudit_log_view_store_has_default_sort_func(GtkTreeSortable * sortable);

static GObjectClass *parent_class = NULL;

GType seaudit_log_view_store_get_type(void)
{
	static GType store_type = 0;

	if (!store_type) {
		static const GTypeInfo log_view_store_info = {
			sizeof(SEAuditLogViewStoreClass),
			NULL,
			NULL,
			(GClassInitFunc) log_view_store_class_init,
			NULL,
			NULL,
			sizeof(SEAuditLogViewStore),
			0,
			(GInstanceInitFunc) log_view_store_init,
		};

		static const GInterfaceInfo tree_model_info = {
			(GInterfaceInitFunc) log_view_store_tree_model_init,
			NULL,
			NULL
		};

		static const GInterfaceInfo sortable_info = {
			(GInterfaceInitFunc) seaudit_log_view_store_sortable_init,
			NULL,
			NULL
		};

		store_type = g_type_register_static(G_TYPE_OBJECT, "SEAuditLogViewStore", &log_view_store_info, 0);

		g_type_add_interface_static(store_type, GTK_TYPE_TREE_MODEL, &tree_model_info);

		g_type_add_interface_static(store_type, GTK_TYPE_TREE_SORTABLE, &sortable_info);
	}

	return store_type;
}

static void log_view_store_class_init(SEAuditLogViewStoreClass * class)
{
	GObjectClass *object_class;

	parent_class = g_type_class_peek_parent(class);
	object_class = (GObjectClass *) class;

	object_class->finalize = log_view_store_finalize;
}

static void log_view_store_tree_model_init(GtkTreeModelIface * iface)
{
	iface->get_flags = log_view_store_get_flags;
	iface->get_n_columns = log_view_store_get_n_columns;
	iface->get_column_type = log_view_store_get_column_type;
	iface->get_iter = log_view_store_get_iter;
	iface->get_path = log_view_store_get_path;
	iface->get_value = log_view_store_get_value;
	iface->iter_next = log_view_store_iter_next;
	iface->iter_children = log_view_store_iter_children;
	iface->iter_has_child = log_view_store_iter_has_child;
	iface->iter_n_children = log_view_store_iter_n_children;
	iface->iter_nth_child = log_view_store_iter_nth_child;
	iface->iter_parent = log_view_store_iter_parent;
}

static void seaudit_log_view_store_sortable_init(GtkTreeSortableIface * iface)
{
	iface->get_sort_column_id = seaudit_log_view_store_get_sort_column_id;
	iface->set_sort_column_id = seaudit_log_view_store_set_sort_column_id;
	iface->set_sort_func = NULL;
	iface->set_default_sort_func = NULL;
	iface->has_default_sort_func = seaudit_log_view_store_has_default_sort_func;
}

static void log_view_store_init(SEAuditLogViewStore * store)
{
	store->log_view = NULL;
	store->stamp = g_random_int();
	store->sort_column_id = GTK_TREE_SORTABLE_DEFAULT_SORT_COLUMN_ID;
}

SEAuditLogViewStore *seaudit_log_view_store_create(void)
{
	SEAuditLogViewStore *store;

	store = g_object_new(SEAUDIT_TYPE_LOG_VIEW_STORE, NULL);
	store->log_view = audit_log_view_create();
	return store;
}

static void log_view_store_finalize(GObject * object)
{
	(*parent_class->finalize) (object);
}

static GtkTreeModelFlags log_view_store_get_flags(GtkTreeModel * tree_model)
{
	g_return_val_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(tree_model), 0);
	return GTK_TREE_MODEL_ITERS_PERSIST | GTK_TREE_MODEL_LIST_ONLY;
}

static gint log_view_store_get_n_columns(GtkTreeModel * tree_model)
{
	return NUM_FIELDS;
}

static GType log_view_store_get_column_type(GtkTreeModel * tree_model, gint index)
{
	g_return_val_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(tree_model), G_TYPE_INVALID);
	/* everything is a string for now */
	return G_TYPE_STRING;
}

static gboolean log_view_store_get_iter(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreePath * path)
{
	gint i;
	SEAuditLogViewStore *store;

	store = (SEAuditLogViewStore *) tree_model;
	if (store->log_view == NULL)
		return FALSE;

	g_return_val_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(tree_model), FALSE);
	g_return_val_if_fail(gtk_tree_path_get_depth(path) > 0, FALSE);

	i = gtk_tree_path_get_indices(path)[0];
	if (i >= store->log_view->num_fltr_msgs)
		return FALSE;

	iter->stamp = store->stamp;
	iter->user_data = GINT_TO_POINTER(i);
	return TRUE;
}

static GtkTreePath *log_view_store_get_path(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	GtkTreePath *retval;
	SEAuditLogViewStore *store;

	store = (SEAuditLogViewStore *) tree_model;
	g_return_val_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(tree_model), NULL);
	g_return_val_if_fail(iter->stamp == store->stamp, NULL);

	retval = gtk_tree_path_new();
	gtk_tree_path_append_index(retval, GPOINTER_TO_INT(iter->user_data));
	return retval;
}

static void set_utf8_return_value(GValue * value, const char *str)
{
	if (str != NULL && g_utf8_validate(str, -1, NULL))
		g_value_set_string(value, str);
	else
		g_value_set_string(value, "");
}

#define DATE_STR_SIZE 256
static void log_view_store_get_value(GtkTreeModel * tree_model, GtkTreeIter * iter, gint column, GValue * value)
{
	SEAuditLogViewStore *store;
	int i, j, indx;
	avc_msg_t *cur_msg;
	load_policy_msg_t *policy_msg;
	boolean_msg_t *boolean_msg;
	const char *cur_perm;
	const char *cur_bool;
	GString *string;
	msg_t *msg;

	store = (SEAuditLogViewStore *) tree_model;
	if (!store->log_view)
		return;
	if (!store->log_view->my_log)
		return;

	g_return_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(tree_model));
	g_return_if_fail(iter->stamp == store->stamp);
	g_return_if_fail(column < NUM_FIELDS);
	i = GPOINTER_TO_INT(iter->user_data);
	g_assert(i < store->log_view->num_fltr_msgs);
	g_value_init(value, G_TYPE_STRING);
	indx = store->log_view->fltr_msgs[i];
	msg = apol_vector_get_element(store->log_view->my_log->msg_list, indx);

	if (DATE_FIELD == column) {
		char date[DATE_STR_SIZE];
		/* check to see if we have been given a valid year, if so display, otherwise no year displayed */
		if (msg->date_stamp->tm_year == 0)
			strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", msg->date_stamp);
		else
			strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S %Y", msg->date_stamp);
		set_utf8_return_value(value, date);
		return;
	}
	if (HOST_FIELD == column) {
		set_utf8_return_value(value, audit_log_get_host(store->log_view->my_log, msg->host));
		return;
	}
	if (msg->msg_type == BOOLEAN_MSG) {
		if (AVC_MSG_FIELD == column) {
			set_utf8_return_value(value, "Boolean");
			return;
		} else if (AVC_MISC_FIELD == column) {
			boolean_msg = msg->msg_data.boolean_msg;
			if (boolean_msg->num_bools > 0) {
				string = g_string_new(audit_log_get_bool(store->log_view->my_log, boolean_msg->booleans[0]));
				if (!string)
					return;
				g_string_append_printf(string, ":%d", boolean_msg->values[0]);
				for (j = 1; j < boolean_msg->num_bools; j++) {
					cur_bool = audit_log_get_bool(store->log_view->my_log, boolean_msg->booleans[j]);
					string = g_string_append(string, ",  ");
					if (!string)
						return;
					string = g_string_append(string, cur_bool);
					if (!string)
						return;

					g_string_append_printf(string, ":%d", boolean_msg->values[j]);
				}
				set_utf8_return_value(value, string->str);
				g_string_free(string, TRUE);
			}
			return;
		} else {
			set_utf8_return_value(value, "");
			return;
		}
	} else if (msg->msg_type == LOAD_POLICY_MSG) {
		if (AVC_MSG_FIELD == column) {
			set_utf8_return_value(value, "Load");
			return;
		}
		if (AVC_MISC_FIELD == column) {
			string = g_string_new("");
			policy_msg = msg->msg_data.load_policy_msg;
			g_string_printf(string, "users=%d roles=%d types=%d bools=%d classes=%d rules=%d",
					policy_msg->users, policy_msg->roles, policy_msg->types,
					policy_msg->bools, policy_msg->classes, policy_msg->rules);
			set_utf8_return_value(value, string->str);
			g_string_free(string, TRUE);
			return;
		} else {
			set_utf8_return_value(value, "");
			return;
		}
	} else if (msg->msg_type != AVC_MSG) {
		set_utf8_return_value(value, "");
		return;
	}

	cur_msg = msg->msg_data.avc_msg;

	switch (column) {
	case AVC_MSG_FIELD:
		if (cur_msg->msg == AVC_DENIED)
			set_utf8_return_value(value, "Denied");
		else
			set_utf8_return_value(value, "Granted");
		break;
	case AVC_EXE_FIELD:
		set_utf8_return_value(value, cur_msg->exe);
		break;
	case AVC_COMM_FIELD:
		set_utf8_return_value(value, cur_msg->comm);
		break;
	case AVC_PATH_FIELD:
		set_utf8_return_value(value, cur_msg->path);
		break;
	case AVC_DEV_FIELD:
		set_utf8_return_value(value, cur_msg->dev);
		break;
	case AVC_SRC_USER_FIELD:
		set_utf8_return_value(value, audit_log_get_user(store->log_view->my_log, cur_msg->src_user));
		break;
	case AVC_SRC_ROLE_FIELD:
		set_utf8_return_value(value, audit_log_get_role(store->log_view->my_log, cur_msg->src_role));
		break;
	case AVC_SRC_TYPE_FIELD:
		set_utf8_return_value(value, audit_log_get_type(store->log_view->my_log, cur_msg->src_type));
		break;
	case AVC_TGT_USER_FIELD:
		set_utf8_return_value(value, audit_log_get_user(store->log_view->my_log, cur_msg->tgt_user));
		break;
	case AVC_TGT_ROLE_FIELD:
		set_utf8_return_value(value, audit_log_get_role(store->log_view->my_log, cur_msg->tgt_role));
		break;
	case AVC_TGT_TYPE_FIELD:
		set_utf8_return_value(value, audit_log_get_type(store->log_view->my_log, cur_msg->tgt_type));
		break;
	case AVC_OBJ_CLASS_FIELD:
		set_utf8_return_value(value, audit_log_get_obj(store->log_view->my_log, cur_msg->obj_class));
		break;
	case AVC_PERM_FIELD:
		if (apol_vector_get_size(cur_msg->perms) > 0) {
			string = g_string_new((char *)apol_vector_get_element(cur_msg->perms, 0));
			if (!string)
				return;
			for (j = 1; j < apol_vector_get_size(cur_msg->perms); j++) {
				cur_perm = apol_vector_get_element(cur_msg->perms, j);
				string = g_string_append(string, ",");
				if (!string)
					return;
				string = g_string_append(string, cur_perm);
				if (!string)
					return;
			}
			set_utf8_return_value(value, string->str);
			g_string_free(string, TRUE);
		}
		break;
	case AVC_INODE_FIELD:
		string = g_string_new("");
		if (!string)
			return;
		if (cur_msg->is_inode)
			g_string_printf(string, "%lu", cur_msg->inode);
		set_utf8_return_value(value, string->str);
		g_string_free(string, TRUE);
		break;
	case AVC_PID_FIELD:
		string = g_string_new("");
		if (!string)
			return;
		g_string_printf(string, "%d", cur_msg->pid);
		set_utf8_return_value(value, string->str);
		g_string_free(string, TRUE);
		break;
	case AVC_MISC_FIELD:
		string = g_string_new("");
		if (!string)
			return;
		if (cur_msg->dev)
			g_string_append_printf(string, "dev=%s ", cur_msg->dev);
		if (cur_msg->ipaddr)
			g_string_append_printf(string, "ipaddr=%s ", cur_msg->ipaddr);
		if (cur_msg->laddr)
			g_string_append_printf(string, "laddr=%s ", cur_msg->laddr);
		if (cur_msg->lport != 0)
			g_string_append_printf(string, "lport=%d ", cur_msg->lport);
		if (cur_msg->faddr)
			g_string_append_printf(string, "faddr=%s ", cur_msg->faddr);
		if (cur_msg->fport != 0)
			g_string_append_printf(string, "fport=%d ", cur_msg->fport);
		if (cur_msg->daddr)
			g_string_append_printf(string, "daddr=%s ", cur_msg->daddr);
		if (cur_msg->dest != 0)
			g_string_append_printf(string, "dest=%d ", cur_msg->dest);
		if (cur_msg->port != 0)
			g_string_append_printf(string, "port=%d ", cur_msg->port);
		if (cur_msg->saddr)
			g_string_append_printf(string, "saddr=%s ", cur_msg->saddr);
		if (cur_msg->source != 0)
			g_string_append_printf(string, "source=%d ", cur_msg->source);
		if (cur_msg->netif)
			g_string_append_printf(string, "netif=%s ", cur_msg->netif);
		if (cur_msg->is_key)
			g_string_append_printf(string, "key=%d ", cur_msg->key);
		if (cur_msg->is_capability)
			g_string_append_printf(string, "capability=%d ", cur_msg->capability);
		if (!(cur_msg->tm_stmp_sec == 0 && cur_msg->tm_stmp_nano == 0 && cur_msg->serial == 0)) {
			g_string_append_printf(string, "timestamp=%lu.%03lu ", cur_msg->tm_stmp_sec, cur_msg->tm_stmp_nano);
			g_string_append_printf(string, "serial=%u ", cur_msg->serial);
		}
		set_utf8_return_value(value, string->str);
		g_string_free(string, TRUE);
	};
}

static gboolean log_view_store_iter_next(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	SEAuditLogViewStore *store;
	int i;

	store = (SEAuditLogViewStore *) tree_model;
	if (store->log_view == NULL)
		return FALSE;

	g_return_val_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(tree_model), FALSE);
	g_return_val_if_fail(iter->stamp == store->stamp, FALSE);

	i = GPOINTER_TO_INT(iter->user_data) + 1;

	iter->user_data = GINT_TO_POINTER(i);

	return i < store->log_view->num_fltr_msgs;
}

static gboolean log_view_store_iter_children(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent)
{
	SEAuditLogViewStore *store;

	if (parent)
		return FALSE;
	g_return_val_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(tree_model), FALSE);
	store = (SEAuditLogViewStore *) tree_model;
	if (!store->log_view)
		return FALSE;

	if (store->log_view->num_fltr_msgs) {
		iter->stamp = store->stamp;
		iter->user_data = GINT_TO_POINTER(0);
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean log_view_store_iter_has_child(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	return FALSE;
}

static gint log_view_store_iter_n_children(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	SEAuditLogViewStore *store;

	g_return_val_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(tree_model), -1);
	store = (SEAuditLogViewStore *) tree_model;
	if (!store->log_view)
		return 0;
	if (iter == NULL)
		return store->log_view->num_fltr_msgs;

	return 0;
}

static gboolean log_view_store_iter_nth_child(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent, gint n)
{
	SEAuditLogViewStore *store = (SEAuditLogViewStore *) tree_model;
	if (!store)
		return FALSE;
	if (!store->log_view)
		return FALSE;

	if (parent)
		return FALSE;

	if (n < store->log_view->num_fltr_msgs) {
		iter->stamp = store->stamp;
		iter->user_data = GINT_TO_POINTER(n);
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean log_view_store_iter_parent(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * child)
{
	return FALSE;
}

int seaudit_log_view_store_iter_to_idx(SEAuditLogViewStore * store, GtkTreeIter * iter)
{
	g_return_val_if_fail(iter->stamp == store->stamp, -1);
	return GPOINTER_TO_INT(iter->user_data);
}

/* sortable interface */

static void seaudit_log_view_store_sort(SEAuditLogViewStore * store)
{
	gint *new_order = NULL;
	GtkTreePath *path;
	int reverse = 0;

	if (!store->log_view)
		return;
	if (!store->log_view->my_log)
		return;

	if (store->order == GTK_SORT_DESCENDING)
		reverse = 1;

	if (audit_log_view_sort(store->log_view, &new_order, reverse))
		return;

	if (!new_order)
		return;

	path = gtk_tree_path_new();
	gtk_tree_model_rows_reordered(GTK_TREE_MODEL(store), path, NULL, new_order);
	gtk_tree_path_free(path);
	/* must be free - was allocated with malloc */
	free(new_order);
}

static gboolean seaudit_log_view_store_get_sort_column_id(GtkTreeSortable * sortable, gint * sort_column_id, GtkSortType * order)
{
	SEAuditLogViewStore *store = (SEAuditLogViewStore *) sortable;

	g_return_val_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(store), FALSE);

	if (store->sort_column_id == GTK_TREE_SORTABLE_DEFAULT_SORT_COLUMN_ID)
		return FALSE;

	if (sort_column_id)
		*sort_column_id = store->sort_column_id;
	if (order)
		*order = store->order;
	return TRUE;
}

static void seaudit_log_view_store_set_sort_column_id(GtkTreeSortable * sortable, gint sort_column_id, GtkSortType order)
{
	SEAuditLogViewStore *store = (SEAuditLogViewStore *) sortable;

	g_return_if_fail(SEAUDIT_IS_LOG_VIEW_STORE(store));
	if (store->log_view == NULL)
		return;
	if ((store->sort_column_id == sort_column_id) && (store->order == order)) {
		/* just sort again */
		gtk_tree_sortable_sort_column_changed(sortable);
		seaudit_log_view_store_sort(store);
		return;
	}

	store->sort_column_id = sort_column_id;
	store->order = order;

	sort_action_list_destroy(store->log_view->sort_actions);
	store->log_view->sort_actions = NULL;
	store->log_view->last_sort_action = NULL;

	switch (store->sort_column_id) {
	case DATE_FIELD:
		if (audit_log_view_append_sort(store->log_view, date_sort_action_create()))
			return;
		break;
	case HOST_FIELD:
		if (audit_log_view_append_sort(store->log_view, host_sort_action_create()))
			return;
		break;
	case AVC_MSG_FIELD:
		if (audit_log_view_append_sort(store->log_view, msg_sort_action_create()))
			return;
		break;
	case AVC_EXE_FIELD:
		if (audit_log_view_append_sort(store->log_view, exe_sort_action_create()))
			return;
		break;
	case AVC_COMM_FIELD:
		if (audit_log_view_append_sort(store->log_view, comm_sort_action_create()))
			return;
		break;
	case AVC_PATH_FIELD:
		if (audit_log_view_append_sort(store->log_view, path_sort_action_create()))
			return;
		break;
	case AVC_DEV_FIELD:
		if (audit_log_view_append_sort(store->log_view, dev_sort_action_create()))
			return;
		break;
	case AVC_SRC_USER_FIELD:
		if (audit_log_view_append_sort(store->log_view, src_user_sort_action_create()))
			return;
		break;
	case AVC_SRC_ROLE_FIELD:
		if (audit_log_view_append_sort(store->log_view, src_role_sort_action_create()))
			return;
		break;
	case AVC_SRC_TYPE_FIELD:
		if (audit_log_view_append_sort(store->log_view, src_type_sort_action_create()))
			return;
		break;
	case AVC_TGT_USER_FIELD:
		if (audit_log_view_append_sort(store->log_view, tgt_user_sort_action_create()))
			return;
		break;
	case AVC_TGT_ROLE_FIELD:
		if (audit_log_view_append_sort(store->log_view, tgt_role_sort_action_create()))
			return;
		break;
	case AVC_TGT_TYPE_FIELD:
		if (audit_log_view_append_sort(store->log_view, tgt_type_sort_action_create()))
			return;
		break;
	case AVC_OBJ_CLASS_FIELD:
		if (audit_log_view_append_sort(store->log_view, obj_class_sort_action_create()))
			return;
		break;
	case AVC_PERM_FIELD:
		if (audit_log_view_append_sort(store->log_view, perm_sort_action_create()))
			return;
		break;
	case AVC_INODE_FIELD:
		if (audit_log_view_append_sort(store->log_view, inode_sort_action_create()))
			return;
		break;
	case AVC_PID_FIELD:
		if (audit_log_view_append_sort(store->log_view, pid_sort_action_create()))
			return;
		break;
	case AVC_MISC_FIELD:
	default:
		return;
	};

	gtk_tree_sortable_sort_column_changed(sortable);
	seaudit_log_view_store_sort(store);
}

static gboolean seaudit_log_view_store_has_default_sort_func(GtkTreeSortable * sortable)
{
	return FALSE;
}

static int int_compare(const void *aptr, const void *bptr)
{
	int *a = (int *)aptr;
	int *b = (int *)bptr;

	assert(a);
	assert(b);

	if (*a < *b)
		return -1;
	if (*a > *b)
		return 1;
	return 0;
}

void seaudit_log_view_store_do_filter(SEAuditLogViewStore * store)
{
	int *deleted = NULL, num_deleted, num_kept, old_sz, new_sz, cnt = 0, i;
	GtkTreePath *path;
	GtkTreeIter iter;
	gint sortId;
	gboolean sorted;

	if (!store->log_view)
		return;

	sorted = gtk_tree_sortable_get_sort_column_id(GTK_TREE_SORTABLE(store), &sortId, &store->order);
	old_sz = store->log_view->num_fltr_msgs;
	audit_log_view_do_filter(store->log_view, &deleted, &num_deleted);
	new_sz = store->log_view->num_fltr_msgs;
	iter.stamp = store->stamp;
	qsort(deleted, num_deleted, sizeof(int), &int_compare);
	for (i = 0; i < num_deleted; i++) {
		path = gtk_tree_path_new();
		g_assert(deleted[i] - cnt >= 0);
		iter.user_data = GINT_TO_POINTER(deleted[i] - cnt);
		path = log_view_store_get_path(GTK_TREE_MODEL(store), &iter);
		gtk_tree_model_row_deleted(GTK_TREE_MODEL(store), path);
		gtk_tree_path_free(path);
		cnt++;

	}
	num_kept = old_sz - num_deleted;

	g_assert(num_kept >= 0);
	g_assert(num_kept <= new_sz);
	iter.stamp = store->stamp;
	for (i = num_kept; i < new_sz; i++) {
		iter.user_data = GINT_TO_POINTER(i);
		path = gtk_tree_path_new();
		path = log_view_store_get_path(GTK_TREE_MODEL(store), &iter);
		gtk_tree_model_row_inserted(GTK_TREE_MODEL(store), path, &iter);
		gtk_tree_path_free(path);
	}
	if (deleted) {
		free(deleted);
	}
	if (sorted)
		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(store), sortId, store->order);
	else
		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(store), DATE_FIELD, GTK_SORT_ASCENDING);
	log_filtered_signal_emit();    /* To Do: need to pass store to signal emit */
	return;
}

void seaudit_log_view_store_close_log(SEAuditLogViewStore * store)
{
	GtkTreeIter iter;
	GtkTreePath *path;
	int i;

	if (!store || !store->log_view)
		return;
	iter.stamp = store->stamp;
	for (i = 0; i < store->log_view->num_fltr_msgs; i++) {
		path = gtk_tree_path_new();
		iter.user_data = GINT_TO_POINTER(0);
		path = log_view_store_get_path(GTK_TREE_MODEL(store), &iter);
		gtk_tree_model_row_deleted(GTK_TREE_MODEL(store), path);
		gtk_tree_path_free(path);
	}
	audit_log_view_set_log(store->log_view, NULL);
}

int seaudit_log_view_store_open_log(SEAuditLogViewStore * store, audit_log_t * new_log)
{
	GtkTreeIter iter;
	GtkTreePath *path;
	int i;

	if (!store || !store->log_view)
		return -1;

	iter.stamp = store->stamp;
	audit_log_view_set_log(store->log_view, new_log);
	for (i = 0; i < store->log_view->num_fltr_msgs; i++) {
		path = gtk_tree_path_new();
		iter.user_data = GINT_TO_POINTER(i);
		path = log_view_store_get_path(GTK_TREE_MODEL(store), &iter);
		gtk_tree_model_row_inserted(GTK_TREE_MODEL(store), path, &iter);
		gtk_tree_path_free(path);
	}
	seaudit_log_view_store_sort(store);
	return 0;
}

void seaudit_log_view_store_refresh(SEAuditLogViewStore * store)
{
	if (store == NULL || store->log_view == NULL)
		return;
	seaudit_log_view_store_do_filter(store);
}
