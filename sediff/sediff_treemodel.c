/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 28, 2004
 */
#include "sediff_treemodel.h"
#include <render.h>

#include <stdlib.h>

const gchar *diff_labels[] = { "Classes and Permissions", 
			       "Types", 
			       "Roles", 
			       "Users", 
			       "Booleans", 
			       "Initial SIDs", 
			       "TE Rules",
			       "RBAC Rules",
			       "Conditionals and Rules",
			       NULL };
			      			       
/* Local static functions */
static void sediff_tree_view_store_init(SEDiffTreeViewStore *store);
static void sediff_tree_view_store_class_init(SEDiffTreeViewStore *klass);
static void sediff_tree_view_store_tree_model_init(GtkTreeModelIface *iface);
static void sediff_tree_view_store_finalize(GObject *object);
static void sediff_tree_view_store_get_value(GtkTreeModel *tree_model, GtkTreeIter *iter, gint column, GValue *value);

static GType sediff_tree_view_store_get_column_type(GtkTreeModel *tree_model, gint index);
static GtkTreeModelFlags sediff_tree_view_store_get_flags(GtkTreeModel *tree_model);
static GtkTreePath *sediff_tree_view_store_get_path(GtkTreeModel *tree_model, GtkTreeIter *iter);
static gint sediff_tree_view_store_get_n_columns(GtkTreeModel *tree_model);
static gint sediff_tree_view_store_iter_n_children(GtkTreeModel *tree_model, GtkTreeIter *iter);
static gboolean sediff_tree_view_store_get_iter(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreePath *path);
static gboolean sediff_tree_view_store_iter_next(GtkTreeModel *tree_model, GtkTreeIter *iter);
static gboolean sediff_tree_view_store_iter_children(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *parent);
static gboolean sediff_tree_view_store_iter_has_child(GtkTreeModel *tree_model, GtkTreeIter *iter);
static gboolean sediff_tree_view_store_iter_nth_child(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *parent,
						      gint n);
static gboolean sediff_tree_view_store_iter_parent(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *child);

static GObjectClass *parent_class = NULL;  /* GObject stuff - nothing to worry about */

/* Start of static function prototypes */
static void sediff_tree_view_store_class_init(SEDiffTreeViewStore *klass)
{
	GObjectClass *object_class;
	
	/* 'klass' is used instead of 'class', because 'class' is a C++ keyword */
	parent_class = g_type_class_peek_parent(klass);
	object_class = (GObjectClass*)klass;

	object_class->finalize = sediff_tree_view_store_finalize;
}

static void sediff_tree_view_store_tree_model_init(GtkTreeModelIface *iface)
{
	iface->get_flags = sediff_tree_view_store_get_flags;
	iface->get_n_columns = sediff_tree_view_store_get_n_columns;
	iface->get_column_type = sediff_tree_view_store_get_column_type;
	iface->get_iter = sediff_tree_view_store_get_iter;
	iface->get_path = sediff_tree_view_store_get_path;
	iface->get_value = sediff_tree_view_store_get_value;
  	iface->iter_next = sediff_tree_view_store_iter_next;
	iface->iter_children = sediff_tree_view_store_iter_children;
	iface->iter_has_child = sediff_tree_view_store_iter_has_child;
	iface->iter_n_children = sediff_tree_view_store_iter_n_children;
	iface->iter_nth_child = sediff_tree_view_store_iter_nth_child;
	iface->iter_parent = sediff_tree_view_store_iter_parent;
}

static void sediff_tree_view_store_init(SEDiffTreeViewStore *store)
{
	store->n_columns       = SEDIFF_NUM_COLUMNS;

	store->column_types[0] = G_TYPE_STRING;   /* SEDIFF_LABEL_COLUMN  */
	store->column_types[1] = G_TYPE_POINTER;  /* SEDIFF_HIDDEN_COLUMN */
	
	g_assert (SEDIFF_NUM_COLUMNS == 2);
	
	store->num_rows = 0;	
	store->stamp = g_random_int();  /* Random int to check whether an iter belongs to our model */
}

static void sediff_tree_view_store_finalize(GObject *object)
{	
	SEDiffTreeViewStore *store = SEDIFF_TREE_STORE(object); 
	/* Free all memory */
  	if (store->diff_results)
  		apol_free_diff_result(1, store->diff_results);

	(*parent_class->finalize)(object);
}

static GtkTreeModelFlags sediff_tree_view_store_get_flags(GtkTreeModel *tree_model)
{
	g_return_val_if_fail(SEDIFF_IS_TREE_STORE(tree_model), 0);
	return GTK_TREE_MODEL_ITERS_PERSIST | GTK_TREE_MODEL_LIST_ONLY;
}

static gint sediff_tree_view_store_get_n_columns(GtkTreeModel *tree_model)
{
	return SEDIFF_TREE_STORE(tree_model)->n_columns;
}

static GType sediff_tree_view_store_get_column_type(GtkTreeModel *tree_model, gint index)
{
	g_return_val_if_fail(SEDIFF_IS_TREE_STORE(tree_model), G_TYPE_INVALID);
	g_return_val_if_fail(index < SEDIFF_TREE_STORE(tree_model)->n_columns && index >= 0, G_TYPE_INVALID);
	
	return SEDIFF_TREE_STORE(tree_model)->column_types[index];
}

static gboolean sediff_tree_view_store_get_iter(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreePath *path)
{
	gint i, depth;
	SEDiffTreeViewStore *store;
	
	store = (SEDiffTreeViewStore*)tree_model;
	g_return_val_if_fail(store->diff_results != NULL, FALSE);
		
	g_return_val_if_fail(SEDIFF_IS_TREE_STORE(tree_model), FALSE);
	g_return_val_if_fail(gtk_tree_path_get_depth (path) > 0, FALSE);
	
	depth = gtk_tree_path_get_depth(path);
	/* we do not allow children */
  	g_assert(depth == 1); /* depth 1 = top level; a list only has top level nodes and no children */
  	
	i = gtk_tree_path_get_indices(path)[0];
	if (i >= store->num_rows)
		return FALSE;
		
	iter->stamp = store->stamp;
	iter->user_data = GINT_TO_POINTER(i);

	return TRUE;
}

static GtkTreePath *sediff_tree_view_store_get_path(GtkTreeModel *tree_model,
					    	    GtkTreeIter *iter)
{
	GtkTreePath *retval;
	SEDiffTreeViewStore *store;

	store = (SEDiffTreeViewStore*)tree_model;
	g_return_val_if_fail(SEDIFF_IS_TREE_STORE(tree_model), NULL);
	g_return_val_if_fail(iter->stamp == store->stamp, NULL);

	retval = gtk_tree_path_new();
	gtk_tree_path_append_index(retval, GPOINTER_TO_INT(iter->user_data));
	return retval;
}

static void sediff_tree_view_store_get_value(GtkTreeModel *tree_model, GtkTreeIter *iter,
				     	     gint column, GValue *value)
{
	SEDiffTreeViewStore *store;
	int indx;
	apol_diff_result_t *diff_results;
	
	store = (SEDiffTreeViewStore*)tree_model;
	g_return_if_fail(store->diff_results != NULL);
	g_return_if_fail(SEDIFF_IS_TREE_STORE(tree_model));
	g_return_if_fail(iter->stamp == store->stamp);
	g_return_if_fail(column < store->n_columns);
	diff_results = store->diff_results;
	
	g_value_init(value, SEDIFF_TREE_STORE(tree_model)->column_types[column]);
	
	if (column == SEDIFF_HIDDEN_COLUMN) {
		g_value_set_pointer(value, diff_results);		
	} else if (column == SEDIFF_LABEL_COLUMN) {
		indx = GPOINTER_TO_INT(iter->user_data);
		g_assert(indx < store->num_rows);
		g_value_set_string(value, diff_labels[indx]);	
	} else {
		g_return_if_reached();
	}
}

static gboolean sediff_tree_view_store_iter_next(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	SEDiffTreeViewStore *store;
	int i;

	store = (SEDiffTreeViewStore*)tree_model;
	g_return_val_if_fail(store->diff_results != NULL, FALSE);
	g_return_val_if_fail(SEDIFF_IS_TREE_STORE(tree_model), FALSE);
	g_return_val_if_fail(iter->stamp == store->stamp, FALSE);

	i = GPOINTER_TO_INT(iter->user_data) + 1;

	iter->user_data = GINT_TO_POINTER(i);

	return i < store->num_rows;
}

static gboolean sediff_tree_view_store_iter_children(GtkTreeModel *tree_model, GtkTreeIter *iter,
						     GtkTreeIter *parent)
{
	SEDiffTreeViewStore *store;

	if (parent)
		return FALSE;
	g_return_val_if_fail(SEDIFF_IS_TREE_STORE(tree_model), FALSE);
	store = (SEDiffTreeViewStore*)tree_model;
	g_return_val_if_fail(store->diff_results != NULL, FALSE);

	if (store->num_rows) {
		iter->stamp = store->stamp;
		iter->user_data = GINT_TO_POINTER(0);
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean sediff_tree_view_store_iter_has_child(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	return FALSE;
}

static gint sediff_tree_view_store_iter_n_children(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	SEDiffTreeViewStore *store;
	
	g_return_val_if_fail(SEDIFF_IS_TREE_STORE(tree_model), -1);
	store = (SEDiffTreeViewStore*)tree_model;
	g_return_val_if_fail(store->diff_results != NULL, 0);
	if (iter == NULL)
		return store->num_rows;

	return 0;
}

static gboolean sediff_tree_view_store_iter_nth_child(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *parent,
					 	      gint n)
{
	SEDiffTreeViewStore *store = (SEDiffTreeViewStore*)tree_model;
	if (!store)
		return FALSE;
	g_return_val_if_fail(store->diff_results != NULL, FALSE);

	if (parent)
		return FALSE;

	if (n < store->num_rows) {
		iter->stamp = store->stamp;
		iter->user_data = GINT_TO_POINTER(n);
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean sediff_tree_view_store_iter_parent(GtkTreeModel *tree_model, GtkTreeIter *iter,
					   	   GtkTreeIter *child)
{
	return FALSE;
}

static void sediff_tree_store_append_item(SEDiffTreeViewStore *store, const gchar *name)
{
	GtkTreeIter   iter;
	GtkTreePath  *path;
	guint         pos;
	
	g_return_if_fail(SEDIFF_TREE_STORE(store));
	g_return_if_fail(name != NULL);
	
	pos = store->num_rows;
	store->num_rows++;
	iter.stamp = store->stamp;
	/* inform the tree view and other interested objects
	 * (e.g. tree row references) that we have inserted
	 * a new row, and where it was inserted */
	path = gtk_tree_path_new();
	gtk_tree_path_append_index(path, pos);
	sediff_tree_view_store_get_iter(GTK_TREE_MODEL(store), &iter, path);
	gtk_tree_model_row_inserted(GTK_TREE_MODEL(store), path, &iter);
	gtk_tree_path_free(path);
}
/* End of static funtion prototypes */

/* Start of exported function prototypes */
GType sediff_tree_view_store_get_type(void)
{
	static GType store_type = 0;

	if (!store_type)
	{
		static const GTypeInfo sediff_tree_store_info = {
			sizeof(SEDiffTreeViewStoreClass),
			NULL,
			NULL,
			(GClassInitFunc)sediff_tree_view_store_class_init,
			NULL,
			NULL,
			sizeof (SEDiffTreeViewStore),
			0,
			(GInstanceInitFunc)sediff_tree_view_store_init,
		};

		static const GInterfaceInfo tree_model_info = {
			(GInterfaceInitFunc)sediff_tree_view_store_tree_model_init,
			NULL,
			NULL
		};

		store_type = g_type_register_static (G_TYPE_OBJECT, 
						     "SEDiffTreeViewStore",
						     &sediff_tree_store_info, 
						     0);

		g_type_add_interface_static(store_type,
					    GTK_TYPE_TREE_MODEL,
					    &tree_model_info);
	}

	return store_type;
}

SEDiffTreeViewStore *sediff_tree_store_new(void)
{
	SEDiffTreeViewStore *store;

	store = g_object_new(SEDIFF_TYPE_TREE_STORE, NULL);
	g_assert( store != NULL );

	return store;
}

int sediff_tree_store_populate(SEDiffTreeViewStore *store)
{
	int i;

	g_return_val_if_fail(store != NULL, -1);
	for (i = 0; diff_labels[i] != NULL; i++) {
		sediff_tree_store_append_item(store, diff_labels[i]);
	}
	
	return 0;
}

int seaudit_tree_store_iter_to_idx(SEDiffTreeViewStore *store, GtkTreeIter *iter)
{
	g_return_val_if_fail(iter->stamp == store->stamp, -1);
	return GPOINTER_TO_INT(iter->user_data);
}
/* End of exported function prototypes */
