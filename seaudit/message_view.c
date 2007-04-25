/**
 *  @file
 *  Implementation of the view for a libseaudit model.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include "message_view.h"
#include "modify_view.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <apol/util.h>

/**
 * A custom model that implements the interfaces GtkTreeModel and
 * GtkTreeSortable.
 */
typedef struct message_view_store
{
	/** this must be the first field, to satisfy glib */
	GObject parent;
	/** pointer to the store's controller */
	message_view_t *view;
	/** vector of seaudit_message_t, as returned by
         * seaudit_model_get_messages() */
	apol_vector_t *messages;
	/** column that is currently being sorted; use OTHER_FIELD to
         * indicate no sorting */
	gint sort_field;
	/** current sort direction, either 1 or ascending or -1 for
	 * descending */
	int sort_dir;
	/** unique integer for each instance of a model */
	gint stamp;
} message_view_store_t;

typedef struct message_view_store_class
{
	GObjectClass parent_class;
} message_view_store_class_t;

static GType message_view_store_get_type(void);
#define SEAUDIT_TYPE_MESSAGE_VIEW_STORE (message_view_store_get_type())
#define SEAUDIT_IS_MESSAGE_VIEW_STORE(obj) \
 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAUDIT_TYPE_MESSAGE_VIEW_STORE))

struct message_view
{
	seaudit_model_t *model;
	toplevel_t *top;
	/** toplevel of the view, currently a scrolled_window */
	GtkWidget *w;
	/** actual GTK+ tree view widget that displays the rows and
         * columns of message data */
	GtkTreeView *view;
	/** GTK+ store that models messages within the tree */
	message_view_store_t *store;
	/** filename for when this view was saved (could be NULL) */
	char *filename;
	/** most recent filename for exported messages (could be NULL) */
	char *export_filename;
};

typedef seaudit_sort_t *(*sort_generator_fn_t) (int direction);

struct view_column_record
{
	preference_field_e id;
	const char *name;
	const char *sample_text;
	sort_generator_fn_t sort;
};

static const struct view_column_record column_data[] = {
	{HOST_FIELD, "Hostname", "Hostname", seaudit_sort_by_host},
	{MESSAGE_FIELD, "Message", "Message", seaudit_sort_by_message_type},
	{DATE_FIELD, "Date", "Jan 01 00:00:00", seaudit_sort_by_date},
	{SUSER_FIELD, "Source\nUser", "Source", seaudit_sort_by_source_user},
	{SROLE_FIELD, "Source\nRole", "Source", seaudit_sort_by_source_role},
	{STYPE_FIELD, "Source\nType", "unlabeled_t", seaudit_sort_by_source_type},
	{TUSER_FIELD, "Target\nUser", "Target", seaudit_sort_by_target_user},
	{TROLE_FIELD, "Target\nRole", "Target", seaudit_sort_by_target_role},
	{TTYPE_FIELD, "Target\nType", "unlabeled_t", seaudit_sort_by_target_type},
	{OBJCLASS_FIELD, "Object\nClass", "Object", seaudit_sort_by_object_class},
	{PERM_FIELD, "Permission", "Permission", seaudit_sort_by_permission},
	{EXECUTABLE_FIELD, "Executable", "/usr/bin/cat", seaudit_sort_by_executable},
	{COMMAND_FIELD, "Command", "/usr/bin/cat", seaudit_sort_by_command},
	{NAME_FIELD, "Name", "iceweasel", seaudit_sort_by_name},
	{PID_FIELD, "PID", "12345", seaudit_sort_by_pid},
	{INODE_FIELD, "Inode", "123456", seaudit_sort_by_inode},
	{PATH_FIELD, "Path", "/home/gburdell/foo", seaudit_sort_by_path},
	{OTHER_FIELD, "Other", "Lorem ipsum dolor sit amet, consectetur", NULL}
};

static const size_t num_columns = sizeof(column_data) / sizeof(column_data[0]);

/**
 * (Re)sort the view based upon which column is clicked.  If already
 * sorting on this column, then reverse the sort direction.  Also
 * update the sort indicator for this column.
 */
static gboolean message_view_on_column_click(GtkTreeViewColumn * column, gpointer user_data)
{
	gint column_id = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(column), "column id"));
	message_view_t *view = (message_view_t *) user_data;
	int dir = 0;
	seaudit_sort_t *sort;
	GtkTreeViewColumn *prev_column;
	if (column_id == view->store->sort_field) {
		dir = view->store->sort_dir * -1;
	} else {
		dir = 1;
	}

	if ((sort = column_data[(preference_field_e) column_id].sort(dir)) == NULL) {
		toplevel_ERR(view->top, "%s", strerror(errno));
		return TRUE;
	}
	seaudit_model_clear_sorts(view->model);
	if (seaudit_model_append_sort(view->model, sort) < 0) {
		seaudit_sort_destroy(&sort);
		toplevel_ERR(view->top, "%s", strerror(errno));
	}
	prev_column = gtk_tree_view_get_column(view->view, view->store->sort_field);
	if (prev_column != NULL) {
		gtk_tree_view_column_set_sort_indicator(prev_column, FALSE);
	}
	gtk_tree_view_column_set_sort_indicator(column, TRUE);
	if (dir > 0) {
		gtk_tree_view_column_set_sort_order(column, GTK_SORT_ASCENDING);
	} else {
		gtk_tree_view_column_set_sort_order(column, GTK_SORT_DESCENDING);
	}

	view->store->sort_field = column_id;
	view->store->sort_dir = dir;
	message_view_update_rows(view);
	return TRUE;
}

/*************** implementation of a custom GtkTreeModel ***************/

static GObjectClass *parent_class = NULL;

static void message_view_store_init(message_view_store_t * m);
static void message_view_store_class_init(message_view_store_class_t * c);
static void message_view_store_tree_init(GtkTreeModelIface * iface);
static void message_view_store_finalize(GObject * object);
static GtkTreeModelFlags message_view_store_get_flags(GtkTreeModel * tree_model);
static gint message_view_store_get_n_columns(GtkTreeModel * tree_model);
static GType message_view_store_get_column_type(GtkTreeModel * tree_model, gint index);
static gboolean message_view_store_get_iter(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreePath * path);
static GtkTreePath *message_view_store_get_path(GtkTreeModel * tree_model, GtkTreeIter * iter);
static void message_view_store_get_value(GtkTreeModel * tree_model, GtkTreeIter * iter, gint column, GValue * value);
static gboolean message_view_store_iter_next(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gboolean message_view_store_iter_children(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent);
static gboolean message_view_store_iter_has_child(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gint message_view_store_iter_n_children(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gboolean message_view_store_iter_nth_child(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent, gint n);
static gboolean message_view_store_iter_parent(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * child);

static GType message_view_store_get_type(void)
{
	static GType store_type = 0;
	static const GTypeInfo store_info = {
		sizeof(message_view_store_class_t),
		NULL,
		NULL,
		(GClassInitFunc) message_view_store_class_init,
		NULL,
		NULL,
		sizeof(message_view_store_t),
		0,
		(GInstanceInitFunc) message_view_store_init
	};
	static const GInterfaceInfo tree_model_info = {
		(GInterfaceInitFunc) message_view_store_tree_init,
		NULL,
		NULL
	};

	if (store_type)
		return store_type;

	store_type = g_type_register_static(G_TYPE_OBJECT, "message_view_store", &store_info, (GTypeFlags) 0);
	g_type_add_interface_static(store_type, GTK_TYPE_TREE_MODEL, &tree_model_info);
	return store_type;
}

static void message_view_store_init(message_view_store_t * m)
{
	static int next_stamp = 0;
	m->messages = NULL;
	m->sort_field = OTHER_FIELD;
	m->sort_dir = 1;
	m->stamp = next_stamp++;
}

static void message_view_store_class_init(message_view_store_class_t * c)
{
	GObjectClass *object_class;
	parent_class = g_type_class_peek_parent(c);
	object_class = (GObjectClass *) c;
	object_class->finalize = message_view_store_finalize;
}

static void message_view_store_tree_init(GtkTreeModelIface * iface)
{
	iface->get_flags = message_view_store_get_flags;
	iface->get_n_columns = message_view_store_get_n_columns;
	iface->get_column_type = message_view_store_get_column_type;
	iface->get_iter = message_view_store_get_iter;
	iface->get_path = message_view_store_get_path;
	iface->get_value = message_view_store_get_value;
	iface->iter_next = message_view_store_iter_next;
	iface->iter_children = message_view_store_iter_children;
	iface->iter_has_child = message_view_store_iter_has_child;
	iface->iter_n_children = message_view_store_iter_n_children;
	iface->iter_nth_child = message_view_store_iter_nth_child;
	iface->iter_parent = message_view_store_iter_parent;
}

static void message_view_store_finalize(GObject * object)
{
	(*parent_class->finalize) (object);
}

static GtkTreeModelFlags message_view_store_get_flags(GtkTreeModel * tree_model)
{
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), 0);
	return GTK_TREE_MODEL_ITERS_PERSIST | GTK_TREE_MODEL_LIST_ONLY;
}

static gint message_view_store_get_n_columns(GtkTreeModel * tree_model __attribute__ ((unused)))
{
	return OTHER_FIELD + 1;
}

static GType message_view_store_get_column_type(GtkTreeModel * tree_model, gint idx __attribute__ ((unused)))
{
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), G_TYPE_INVALID);
	/* everything is a string for now */
	return G_TYPE_STRING;
}

static gboolean message_view_store_get_iter(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreePath * path)
{
	gint i;
	message_view_store_t *store = (message_view_store_t *) tree_model;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), FALSE);
	g_return_val_if_fail(gtk_tree_path_get_depth(path) > 0, FALSE);
	i = gtk_tree_path_get_indices(path)[0];
	if (i >= apol_vector_get_size(store->messages))
		return FALSE;

	iter->stamp = store->stamp;
	iter->user_data = apol_vector_get_element(store->messages, i);
	iter->user_data2 = GINT_TO_POINTER(i);
	iter->user_data3 = store->view;
	return TRUE;
}

static GtkTreePath *message_view_store_get_path(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	GtkTreePath *retval;
	message_view_store_t *store = (message_view_store_t *) tree_model;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), NULL);
	g_return_val_if_fail(iter->stamp == store->stamp, NULL);
	retval = gtk_tree_path_new();
	gtk_tree_path_append_index(retval, GPOINTER_TO_INT(iter->user_data2));
	return retval;
}

/**
 * Given a string, check that it is UTF8 legal.  If not, or if the
 * string is NULL, then return an empty string.  Otherwise return the
 * original string.
 */
static void message_view_to_utf8(GValue * value, const char *s)
{
	if (s == NULL || !g_utf8_validate(s, -1, NULL)) {
		g_value_set_string(value, "");
	}
	g_value_set_string(value, s);
}

static void message_view_store_get_value(GtkTreeModel * tree_model, GtkTreeIter * iter, gint column, GValue * value)
{
	message_view_store_t *store;
	message_view_t *view;
	seaudit_message_t *m;
	seaudit_message_type_e type;
	void *data;
	seaudit_avc_message_t *avc;
	g_return_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model));
	g_return_if_fail(iter != NULL);
	g_return_if_fail(column <= OTHER_FIELD);
	g_value_init(value, G_TYPE_STRING);
	store = (message_view_store_t *) tree_model;
	view = store->view;
	m = (seaudit_message_t *) iter->user_data;
	data = seaudit_message_get_data(m, &type);
	preference_field_e field = column;

	switch (field) {
	case HOST_FIELD:{
			message_view_to_utf8(value, seaudit_message_get_host(m));
			return;
		}
	case MESSAGE_FIELD:{
			char *message = "Invalid";
			switch (type) {
			case SEAUDIT_MESSAGE_TYPE_BOOL:{
					message = "Boolean";
					break;
				}
			case SEAUDIT_MESSAGE_TYPE_LOAD:{
					message = "Load";
					break;
				}
			case SEAUDIT_MESSAGE_TYPE_AVC:{
					avc = (seaudit_avc_message_t *) data;
					seaudit_avc_message_type_e avc_type;
					avc_type = seaudit_avc_message_get_message_type(avc);
					switch (avc_type) {
					case SEAUDIT_AVC_DENIED:{
							message = "Denied";
							break;
						}
					case SEAUDIT_AVC_GRANTED:{
							message = "Granted";
							break;
						}
					default:{
							/* should never get here */
							toplevel_ERR(view->top, "Got an invalid AVC message type %d!", avc_type);
							assert(0);
							return;
						}
					}
					break;
				}
			default:{
					/* should never get here */
					toplevel_ERR(view->top, "Got an invalid message type %d!", type);
					assert(0);
					return;
				}
			}
			message_view_to_utf8(value, message);
			return;
		}
	case DATE_FIELD:{
			struct tm *tm = seaudit_message_get_time(m);
			char date[256];
			/* check to see if we have been given a valid year, if
			 * so display, otherwise no year displayed */
			if (tm->tm_year == 0) {
				strftime(date, 256, "%b %d %H:%M:%S", tm);
			} else {
				strftime(date, 256, "%b %d %H:%M:%S %Y", tm);
			}
			message_view_to_utf8(value, date);
			return;
		}
	case OTHER_FIELD:{
			char *other = seaudit_message_to_misc_string(m);;
			if (other == NULL) {
				toplevel_ERR(view->top, "%s", strerror(errno));
				return;
			}
			message_view_to_utf8(value, other);
			free(other);
			return;
		}
	default:		       /* FALLTHROUGH */
		break;
	}

	if (type != SEAUDIT_MESSAGE_TYPE_AVC) {
		/* the rest of the columns are blank for non-AVC
		 * messages */
		message_view_to_utf8(value, "");
		return;
	}
	avc = (seaudit_avc_message_t *) data;

	switch (field) {
	case SUSER_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_source_user(avc));
			return;
		}
	case SROLE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_source_role(avc));
			return;
		}
	case STYPE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_source_type(avc));
			return;
		}
	case TUSER_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_target_user(avc));
			return;
		}
	case TROLE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_target_role(avc));
			return;
		}
	case TTYPE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_target_type(avc));
			return;
		}
	case OBJCLASS_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_object_class(avc));
			return;
		}
	case PERM_FIELD:{
			apol_vector_t *perms = seaudit_avc_message_get_perm(avc);
			char *perm = NULL;
			size_t i, len = 0;
			for (i = 0; perms != NULL && i < apol_vector_get_size(perms); i++) {
				char *p = apol_vector_get_element(perms, i);
				if (apol_str_appendf(&perm, &len, "%s%s", (i > 0 ? "," : ""), p) < 0) {
					toplevel_ERR(view->top, "%s", strerror(errno));
					return;
				}
			}
			message_view_to_utf8(value, perm);
			free(perm);
			return;
		}
	case EXECUTABLE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_exe(avc));
			return;
		}
	case COMMAND_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_comm(avc));
			return;
		}
	case NAME_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_name(avc));
			return;
		}
	case PID_FIELD:{
			char *s;
			if (asprintf(&s, "%u", seaudit_avc_message_get_pid(avc)) < 0) {
				toplevel_ERR(view->top, "%s", strerror(errno));
				return;
			}
			message_view_to_utf8(value, s);
			free(s);
			return;
		}
	case INODE_FIELD:{
			char *s;
			if (asprintf(&s, "%lu", seaudit_avc_message_get_inode(avc)) < 0) {
				toplevel_ERR(view->top, "%s", strerror(errno));
				return;
			}
			message_view_to_utf8(value, s);
			free(s);
			return;
		}
	case PATH_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_path(avc));
			return;
		}
	default:		       /* FALLTHROUGH */
		break;
	}
	/* should never get here */
	toplevel_ERR(view->top, "Got an invalid column %d!", field);
	assert(0);
}

static gboolean message_view_store_iter_next(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	gint i;
	message_view_store_t *store = (message_view_store_t *) tree_model;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), FALSE);
	g_return_val_if_fail(iter->stamp == store->stamp, FALSE);
	if (iter == NULL || iter->user_data == NULL)
		return FALSE;
	i = GPOINTER_TO_INT(iter->user_data2) + 1;
	if (i >= apol_vector_get_size(store->messages)) {
		return FALSE;
	}
	iter->user_data = apol_vector_get_element(store->messages, i);
	iter->user_data2 = GINT_TO_POINTER(i);
	iter->user_data3 = store->view;
	return TRUE;
}

static gboolean message_view_store_iter_children(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent)
{
	message_view_store_t *store;
	g_return_val_if_fail(parent == NULL || parent->user_data != NULL, FALSE);
	if (parent)
		return FALSE;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), FALSE);

	/* set iterator to first row, if possible */
	store = (message_view_store_t *) tree_model;
	if (store->messages == NULL || apol_vector_get_size(store->messages) == 0)
		return FALSE;

	iter->stamp = store->stamp;
	iter->user_data = apol_vector_get_element(store->messages, 0);
	iter->user_data2 = GINT_TO_POINTER(0);
	iter->user_data3 = store->view;
	return TRUE;
}

static gboolean message_view_store_iter_has_child(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	return FALSE;
}

static gint message_view_store_iter_n_children(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	message_view_store_t *store;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), -1);
	g_return_val_if_fail(iter == NULL || iter->user_data != NULL, 0);
	store = (message_view_store_t *) tree_model;
	/* return the number of rows, if iterator is at the top;
	 * otherwise return 0 because this store is just a list */
	if (iter != NULL || store->messages == NULL) {
		return 0;
	}
	return apol_vector_get_size(store->messages);
}

static gboolean message_view_store_iter_nth_child(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent, gint n)
{
	message_view_store_t *store;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), FALSE);
	store = (message_view_store_t *) tree_model;
	if (store->messages == NULL || parent != NULL) {
		return FALSE;
	}
	if (n >= apol_vector_get_size(store->messages)) {
		return FALSE;
	}
	iter->stamp = store->stamp;
	iter->user_data = apol_vector_get_element(store->messages, n);
	iter->user_data2 = GINT_TO_POINTER(n);
	iter->user_data3 = store->view;
	return TRUE;
}

static gboolean message_view_store_iter_parent(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * child)
{
	return FALSE;
}

/*************** end of custom GtkTreeModel implementation ***************/

/**
 * Show all messages within the messages vector (type seaudit_message_t *)
 */
static void message_view_messages_vector(message_view_t * view, apol_vector_t * messages)
{
	GtkWidget *window;
	GtkWidget *scroll;
	GtkWidget *text_view;
	GtkTextBuffer *buffer;
	GtkTextIter iter;
	size_t i;
	window = gtk_dialog_new_with_buttons("View Messages",
					     toplevel_get_window(view->top),
					     GTK_DIALOG_DESTROY_WITH_PARENT, GTK_STOCK_CLOSE, GTK_RESPONSE_CLOSE, NULL);
	gtk_dialog_set_default_response(GTK_DIALOG(window), GTK_RESPONSE_CLOSE);
	gtk_window_set_modal(GTK_WINDOW(window), FALSE);
	g_signal_connect_swapped(window, "response", G_CALLBACK(gtk_widget_destroy), window);
	scroll = gtk_scrolled_window_new(NULL, NULL);
	text_view = gtk_text_view_new();
	gtk_window_set_default_size(GTK_WINDOW(window), 480, 300);
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(window)->vbox), scroll);
	gtk_container_add(GTK_CONTAINER(scroll), text_view);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);
	gtk_widget_show(text_view);
	gtk_widget_show(scroll);
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
	gtk_text_buffer_get_start_iter(buffer, &iter);
	for (i = 0; i < apol_vector_get_size(messages); i++) {
		seaudit_message_t *m = apol_vector_get_element(messages, i);
		char *s;
		if ((s = seaudit_message_to_string(m)) == NULL) {
			toplevel_ERR(view->top, "%s", strerror(errno));
			continue;
		}
		gtk_text_buffer_insert(buffer, &iter, s, -1);
		gtk_text_buffer_insert(buffer, &iter, "\n", -1);
		free(s);
	}
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_widget_show(window);

}

/******************** handlers for  right click menu ********************/

static void message_view_popup_on_view_message_activate(GtkMenuItem * menuitem, gpointer user_data)
{
	message_view_t *v = g_object_get_data(G_OBJECT(menuitem), "view-object");
	message_view_entire_message(v);
}

static void message_view_popup_on_find_terules_activate(GtkMenuItem * menuitem, gpointer user_data)
{
	message_view_t *v = g_object_get_data(G_OBJECT(menuitem), "view-object");
	toplevel_find_terules(v->top, (seaudit_message_t *) user_data);
}

static void message_view_popup_on_export_selected_messages_activate(GtkMenuItem * menuitem, gpointer user_data
								    __attribute__ ((unused)))
{
	message_view_t *v = g_object_get_data(G_OBJECT(menuitem), "view-object");
	message_view_export_selected_messages(v);
}

static void message_view_popup_menu(GtkWidget * treeview, GdkEventButton * event, message_view_t * view,
				    seaudit_message_t * message)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
	gint num_selected_rows = gtk_tree_selection_count_selected_rows(selection);
	GtkWidget *menu, *menuitem, *menuitem2, *menuitem3;
	int button, event_time;

	menu = gtk_menu_new();
	if (num_selected_rows == 1) {
		menuitem = gtk_menu_item_new_with_label("View Selected Message");
		menuitem3 = gtk_menu_item_new_with_label("Export Selected Message...");
	} else {
		menuitem = gtk_menu_item_new_with_label("View Selected Messages");
		menuitem3 = gtk_menu_item_new_with_label("Export Selected Messages...");
	}
	menuitem2 = gtk_menu_item_new_with_label("Find TERules using Message...");
	g_signal_connect(menuitem, "activate", (GCallback) message_view_popup_on_view_message_activate, message);
	g_signal_connect(menuitem2, "activate", (GCallback) message_view_popup_on_find_terules_activate, message);
	g_signal_connect(menuitem3, "activate", (GCallback) message_view_popup_on_export_selected_messages_activate, NULL);
	g_object_set_data(G_OBJECT(menuitem), "view-object", view);
	g_object_set_data(G_OBJECT(menuitem2), "view-object", view);
	g_object_set_data(G_OBJECT(menuitem3), "view-object", view);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem2);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem3);
	gtk_widget_show_all(menu);
	if (toplevel_get_policy(view->top) == NULL) {
		gtk_widget_set_sensitive(menuitem2, FALSE);
	}

	if (event) {
		button = event->button;
		event_time = event->time;
	} else {
		button = 0;
		event_time = gtk_get_current_event_time();
	}
	gtk_menu_attach_to_widget(GTK_MENU(menu), treeview, NULL);
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, button, event_time);
}

static gboolean message_view_delayed_selection_menu_item(gpointer data)
{
	message_view_t *view = (message_view_t *) data;
	toplevel_update_selection_menu_item(view->top);
	return FALSE;
}

static gboolean message_view_on_button_press(GtkWidget * treeview, GdkEventButton * event, gpointer user_data)
{
	message_view_t *view = (message_view_t *) user_data;
	if (event->type == GDK_BUTTON_PRESS && event->button == 3) {
		GtkTreePath *path = NULL;
		GtkTreeIter iter;
		GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
		if (!gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(treeview), event->x, event->y, &path, NULL, NULL, NULL)) {
			return FALSE;
		}
		/* if the right click occurred on an unselected row, remove
		 * all selections and select the item under the pointer */
		if (!gtk_tree_selection_path_is_selected(selection, path)) {
			gtk_tree_selection_unselect_all(selection);
			gtk_tree_selection_select_path(selection, path);
		}
		message_view_store_get_iter(GTK_TREE_MODEL(view->store), &iter, path);
		/* popup a menu for the row that was clicked */
		message_view_popup_menu(treeview, event, view, (seaudit_message_t *) iter.user_data);
		return TRUE;
	} else if (event->type == GDK_BUTTON_PRESS && event->button == 1) {
		/* n.b.: rows can be selected but never deselected.
		 * delay updating the menu, for upon the first click
		 * there is not a selection yet */
		g_idle_add(&message_view_delayed_selection_menu_item, view);
		return FALSE;
	}
	return FALSE;
}

static void message_view_gtk_tree_path_free(gpointer data, gpointer user_data __attribute__ ((unused)))
{
	gtk_tree_path_free((GtkTreePath *) data);
}

static gboolean message_view_on_popup_menu(GtkWidget * treeview, gpointer user_data)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
	GList *glist = gtk_tree_selection_get_selected_rows(selection, NULL);
	message_view_t *view = (message_view_t *) user_data;
	GtkTreePath *path;
	GtkTreeIter iter;
	if (glist == NULL) {
		return FALSE;
	}
	path = g_list_nth_data(glist, 0);
	message_view_store_get_iter(GTK_TREE_MODEL(view->store), &iter, path);
	g_list_foreach(glist, message_view_gtk_tree_path_free, NULL);
	g_list_free(glist);
	message_view_popup_menu(treeview, NULL, view, (seaudit_message_t *) iter.user_data);
	return TRUE;
}

static void message_view_on_row_activate(GtkTreeView * tree_view __attribute__ ((unused)), GtkTreePath * path
					 __attribute__ ((unused)), GtkTreeViewColumn * column
					 __attribute__ ((unused)), gpointer user_data)
{
	message_view_t *view = (message_view_t *) user_data;
	toplevel_update_selection_menu_item(view->top);
}

/******************** other public functions below ********************/

message_view_t *message_view_create(toplevel_t * top, seaudit_model_t * model, const char *filename)
{
	message_view_t *view;
	GtkTreeSelection *selection;
	GtkCellRenderer *renderer;
	size_t i;

	if ((view = calloc(1, sizeof(*view))) == NULL || (filename != NULL && (view->filename = strdup(filename)) == NULL)) {
		int error = errno;
		toplevel_ERR(top, "%s", strerror(error));
		message_view_destroy(&view);
		errno = error;
		return NULL;
	}
	view->top = top;
	view->model = model;
	view->store = (message_view_store_t *) g_object_new(SEAUDIT_TYPE_MESSAGE_VIEW_STORE, NULL);
	view->store->view = view;
	view->store->sort_field = OTHER_FIELD;
	view->store->sort_dir = 1;
	view->w = gtk_scrolled_window_new(NULL, NULL);
	view->view = GTK_TREE_VIEW(gtk_tree_view_new_with_model(GTK_TREE_MODEL(view->store)));
	selection = gtk_tree_view_get_selection(view->view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	gtk_container_add(GTK_CONTAINER(view->w), GTK_WIDGET(view->view));
	gtk_widget_show(GTK_WIDGET(view->view));
	gtk_widget_show(view->w);

	renderer = gtk_cell_renderer_text_new();
	for (i = 0; i < num_columns; i++) {
		struct view_column_record r = column_data[i];
		PangoLayout *layout = gtk_widget_create_pango_layout(GTK_WIDGET(view->view), r.sample_text);
		gint width;
		GtkTreeViewColumn *column;
		pango_layout_get_pixel_size(layout, &width, NULL);
		g_object_unref(G_OBJECT(layout));
		width += 12;
		column = gtk_tree_view_column_new_with_attributes(r.name, renderer, "text", r.id, NULL);
		gtk_tree_view_column_set_clickable(column, TRUE);
		gtk_tree_view_column_set_resizable(column, TRUE);
		if (r.sort != NULL) {
			g_object_set_data(G_OBJECT(column), "column id", GINT_TO_POINTER(r.id));
			g_signal_connect_after(G_OBJECT(column), "clicked", G_CALLBACK(message_view_on_column_click), view);
		}
		gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_column_set_fixed_width(column, width);
		gtk_tree_view_append_column(view->view, column);
	}

	g_signal_connect(G_OBJECT(view->view), "button-press-event", G_CALLBACK(message_view_on_button_press), view);
	g_signal_connect(G_OBJECT(view->view), "popup-menu", G_CALLBACK(message_view_on_popup_menu), view);
	g_signal_connect(G_OBJECT(view->view), "row-activated", G_CALLBACK(message_view_on_row_activate), view);
	message_view_update_visible_columns(view);
	message_view_update_rows(view);
	return view;
}

void message_view_destroy(message_view_t ** view)
{
	if (view != NULL && *view != NULL) {
		seaudit_model_destroy(&(*view)->model);
		apol_vector_destroy(&((*view)->store->messages));
		g_free((*view)->filename);
		g_free((*view)->export_filename);
		/* let glib handle destruction of object */
		g_object_unref((*view)->store);
		free(*view);
		*view = NULL;
	}
}

seaudit_model_t *message_view_get_model(message_view_t * view)
{
	return view->model;
}

void message_view_set_model(message_view_t * view, seaudit_model_t * model)
{
	seaudit_model_destroy(&view->model);
	view->model = model;
	toplevel_update_tabs(view->top);
	message_view_update_rows(view);
}

GtkWidget *message_view_get_view(message_view_t * view)
{
	return view->w;
}

size_t message_view_get_num_log_messages(message_view_t * view)
{
	if (view->store->messages == NULL) {
		return 0;
	}
	return apol_vector_get_size(view->store->messages);
}

gboolean message_view_is_message_selected(message_view_t * view)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(view->view);
	GList *glist = gtk_tree_selection_get_selected_rows(selection, NULL);
	if (glist == NULL) {
		return FALSE;
	}
	g_list_foreach(glist, message_view_gtk_tree_path_free, NULL);
	g_list_free(glist);
	return TRUE;
}

void message_view_entire_message(message_view_t * view)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(view->view);
	GList *glist = gtk_tree_selection_get_selected_rows(selection, NULL);
	GList *l;
	apol_vector_t *messages;
	if (glist == NULL) {
		return;
	}
	if ((messages = apol_vector_create(NULL)) == NULL) {
		toplevel_ERR(view->top, "%s", strerror(errno));
		g_list_foreach(glist, message_view_gtk_tree_path_free, NULL);
		g_list_free(glist);
		return;
	}
	for (l = glist; l != NULL; l = l->next) {
		GtkTreePath *path = (GtkTreePath *) l->data;
		GtkTreeIter iter;
		message_view_store_get_iter(GTK_TREE_MODEL(view->store), &iter, path);
		if (apol_vector_append(messages, iter.user_data) < 0) {
			toplevel_ERR(view->top, "%s", strerror(errno));
			g_list_foreach(glist, message_view_gtk_tree_path_free, NULL);
			g_list_free(glist);
			apol_vector_destroy(&messages);
			return;
		}
	}
	message_view_messages_vector(view, messages);
	g_list_foreach(glist, message_view_gtk_tree_path_free, NULL);
	g_list_free(glist);
	apol_vector_destroy(&messages);
}

void message_view_save(message_view_t * view)
{
	if (view->filename == NULL) {
		GtkWindow *parent = toplevel_get_window(view->top);
		char *path = util_save_file(parent, "Save View", NULL);
		if (path == NULL) {
			return;
		}
		view->filename = path;
	}
	if (seaudit_model_save_to_file(view->model, view->filename) < 0) {
		toplevel_ERR(view->top, "Error saving view: %s", strerror(errno));
	}
}

void message_view_saveas(message_view_t * view)
{
	GtkWindow *parent = toplevel_get_window(view->top);
	char *path = util_save_file(parent, "Save View As", view->filename);
	if (path == NULL) {
		return;
	}
	g_free(view->filename);
	view->filename = path;
	if (seaudit_model_save_to_file(view->model, view->filename) < 0) {
		toplevel_ERR(view->top, "Error saving view: %s", strerror(errno));
	}
}

void message_view_modify(message_view_t * view)
{
	if (modify_view_run(view->top, view)) {
		toplevel_update_status_bar(view->top);
	}
}

/**
 * Write to a file all messages in the given vector.  Upon success,
 * update the view object's export filename.
 *
 * @param view View containing messages to write.
 * @param path Destination to write file, overwriting existing files
 * as necessary.
 * @param messages Vector of seaudit_message_t.
 */
static void message_view_export_messages_vector(message_view_t * view, char *path, apol_vector_t * messages)
{
	FILE *f = NULL;
	size_t i;
	g_free(view->export_filename);
	view->export_filename = path;
	if ((f = fopen(path, "w")) == NULL) {
		toplevel_ERR(view->top, "Could not open %s for writing.", path);
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(messages); i++) {
		seaudit_message_t *m = apol_vector_get_element(messages, i);
		char *s = seaudit_message_to_string(m);
		if (s == NULL || fprintf(f, "%s\n", s) < 0) {
			toplevel_ERR(view->top, "Error writing string: %s", strerror(errno));
			goto cleanup;
		}
		free(s);
	}
      cleanup:
	if (f != NULL) {
		fclose(f);
	}
}

void message_view_export_all_messages(message_view_t * view)
{
	GtkWindow *parent = toplevel_get_window(view->top);
	char *path = util_save_file(parent, "Export Messages", view->export_filename);
	apol_vector_t *messages = view->store->messages;
	if (path == NULL) {
		return;
	}
	message_view_export_messages_vector(view, path, messages);
}

void message_view_export_selected_messages(message_view_t * view)
{
	GtkWindow *parent = toplevel_get_window(view->top);
	char *path;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(view->view);
	GList *glist = gtk_tree_selection_get_selected_rows(selection, NULL);
	GList *l;
	apol_vector_t *messages;
	if (glist == NULL) {
		return;
	}
	path = util_save_file(parent, "Export Selected Messages", view->export_filename);
	if (path == NULL) {
		return;
	}
	if ((messages = apol_vector_create(NULL)) == NULL) {
		toplevel_ERR(view->top, "%s", strerror(errno));
		g_list_foreach(glist, message_view_gtk_tree_path_free, NULL);
		g_list_free(glist);
		return;
	}
	for (l = glist; l != NULL; l = l->next) {
		GtkTreePath *tree_path = (GtkTreePath *) l->data;
		GtkTreeIter iter;
		message_view_store_get_iter(GTK_TREE_MODEL(view->store), &iter, tree_path);
		if (apol_vector_append(messages, iter.user_data) < 0) {
			toplevel_ERR(view->top, "%s", strerror(errno));
			g_list_foreach(glist, message_view_gtk_tree_path_free, NULL);
			g_list_free(glist);
			apol_vector_destroy(&messages);
			return;
		}
	}
	message_view_export_messages_vector(view, path, messages);
	g_list_foreach(glist, message_view_gtk_tree_path_free, NULL);
	g_list_free(glist);
	apol_vector_destroy(&messages);
}

/**
 * Given the name of a column, return its column record data.
 */
static const struct view_column_record *get_record(const char *name)
{
	size_t i;
	for (i = 0; i < num_columns; i++) {
		const struct view_column_record *r = column_data + i;
		if (strcmp(r->name, name) == 0) {
			return r;
		}
	}
	return NULL;
}

void message_view_update_visible_columns(message_view_t * view)
{
	GList *columns, *c;
	preferences_t *prefs = toplevel_get_prefs(view->top);
	columns = gtk_tree_view_get_columns(view->view);
	c = columns;
	while (c != NULL) {
		GtkTreeViewColumn *vc = GTK_TREE_VIEW_COLUMN(c->data);
		const gchar *title = gtk_tree_view_column_get_title(vc);
		const struct view_column_record *r = get_record(title);
		if (preferences_is_column_visible(prefs, r->id)) {
			gtk_tree_view_column_set_visible(vc, TRUE);
		} else {
			gtk_tree_view_column_set_visible(vc, FALSE);
		}
		c = g_list_next(c);
	}
	g_list_free(columns);
}

void message_view_update_rows(message_view_t * view)
{
	/* remove all existing rows, then insert them back into the
	 * view according to the model.  automatically scroll to the
	 * same seleceted row(s). */
	GtkTreeSelection *selection;
	GList *rows, *r, *selected = NULL;
	GtkTreePath *path;
	GtkTreeIter iter;
	seaudit_log_t *log;
	size_t i, num_old_messages = 0, num_new_messages = 0, num_changed;
	int first_scroll = 0;

	if (!seaudit_model_is_changed(view->model)) {
		return;
	}

	/* convert the current selection into a GList of message
	 * pointers */
	selection = gtk_tree_view_get_selection(view->view);
	rows = gtk_tree_selection_get_selected_rows(selection, NULL);
	for (r = rows; r != NULL; r = r->next) {
		path = (GtkTreePath *) r->data;
		message_view_store_get_iter(GTK_TREE_MODEL(view->store), &iter, path);
		selected = g_list_prepend(selected, iter.user_data);
	}
	g_list_foreach(rows, message_view_gtk_tree_path_free, NULL);
	g_list_free(rows);

	log = toplevel_get_log(view->top);
	if (view->store->messages != NULL) {
		num_old_messages = apol_vector_get_size(view->store->messages);
	}
	apol_vector_destroy(&view->store->messages);
	if (log != NULL) {
		view->store->messages = seaudit_model_get_messages(log, view->model);
		num_new_messages = apol_vector_get_size(view->store->messages);
	}
	gtk_tree_selection_unselect_all(selection);

	/* mark which rows have been changed/removed/inserted.  do
	 * this as a single pass, rather than a two pass
	 * mark-and-sweep, for GTK+ tree views can be somewhat slow */
	num_changed = num_old_messages;
	if (num_new_messages < num_changed) {
		num_changed = num_new_messages;
	}
	for (i = 0; i < num_changed; i++) {
		path = gtk_tree_path_new();
		gtk_tree_path_append_index(path, i);
		iter.user_data = apol_vector_get_element(view->store->messages, i);
		iter.user_data2 = GINT_TO_POINTER(i);
		iter.user_data3 = view;
		gtk_tree_model_row_changed(GTK_TREE_MODEL(view->store), path, &iter);
		for (r = selected; r != NULL; r = r->next) {
			if (r->data == iter.user_data) {
				gtk_tree_selection_select_iter(selection, &iter);
				if (!first_scroll) {
					gtk_tree_view_scroll_to_cell(view->view, path, NULL, FALSE, 0.0, 0.0);
					first_scroll = 1;
				}
				break;
			}
		}
		gtk_tree_path_free(path);
	}
	if (num_old_messages > num_changed) {
		/* delete in reverse order, else indices get renumbered */
		for (i = num_old_messages; i > num_changed; i--) {
			path = gtk_tree_path_new();
			gtk_tree_path_append_index(path, i - 1);
			gtk_tree_model_row_deleted(GTK_TREE_MODEL(view->store), path);
			gtk_tree_path_free(path);
		}
	} else {
		for (; i < num_new_messages; i++) {
			path = gtk_tree_path_new();
			gtk_tree_path_append_index(path, i);
			iter.user_data = apol_vector_get_element(view->store->messages, i);
			iter.user_data2 = GINT_TO_POINTER(i);
			iter.user_data3 = view;
			gtk_tree_model_row_inserted(GTK_TREE_MODEL(view->store), path, &iter);
			for (r = selected; r != NULL; r = r->next) {
				if (r->data == iter.user_data) {
					gtk_tree_selection_select_iter(selection, &iter);
					if (!first_scroll) {
						gtk_tree_view_scroll_to_cell(view->view, path, NULL, FALSE, 0.0, 0.0);
						first_scroll = 1;
					}
					break;
				}
			}
			gtk_tree_path_free(path);
		}
	}
	g_list_free(selected);
}
