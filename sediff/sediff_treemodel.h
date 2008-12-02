/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 28, 2004
 */
 
#ifndef _SEDIFF_TREE_MODEL_H
#define _SEDIFF_TREE_MODEL_H

#include <poldiff.h>
#include <gtk/gtk.h>
#include <glib.h>

/* Some boilerplate GObject defines. 'klass' is used
 * instead of 'class', because 'class' is a C++ keyword */
#define SEDIFF_TYPE_TREE_STORE            (sediff_tree_view_store_get_type())
#define SEDIFF_TREE_STORE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEDIFF_TYPE_TREE_STORE, SEDiffTreeViewStore))
#define SEDIFF_TREE_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  SEDIFF_TYPE_TREE_STORE, SEDiffTreeViewStoreClass))
#define SEDIFF_IS_TREE_STORE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEDIFF_TYPE_TREE_STORE))
#define SEDIFF_IS_TREE_STORE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  SEDIFF_TYPE_TREE_STORE))
#define SEDIFF_TREE_STORE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  SEDIFF_TYPE_TREE_STORE, SEDiffTreeViewStoreClass))

/* defines for the sediff options */
#define OPT_CLASSES 		0
#define OPT_TYPES 		1
#define OPT_ROLES		2
#define OPT_USERS		3
#define OPT_BOOLEANS 		4
#define OPT_SIDS 		5
#define OPT_TE_RULES		6
#define OPT_RBAC_RULES		7
#define OPT_CONDITIONALS	8

/* The data columns that we export via the tree model interface */
enum
{
  SEDIFF_LABEL_COLUMN = 0,
  SEDIFF_HIDDEN_COLUMN,
  SEDIFF_NUM_COLUMNS
};

/* SEDiffTreeViewStore: This structure contains everything we need for our
 *             model implementation. It is crucial that 'parent' is the 
 *	       first member of the structure.                                          
 */
typedef struct _SEDiffTreeViewStore
{
	GObject parent;
	apol_diff_result_t *diff_results; /* Reference to the diff results */
	guint num_rows;    		  /* Number of rows */
	gint stamp;			  /* Random integer to check whether an iter belongs to our model */
	/* These two fields are not absolutely necessary, but they  */
	/* speed things up a bit in our get_value implementation    */
	gint            n_columns;
	GType           column_types[SEDIFF_NUM_COLUMNS];
} SEDiffTreeViewStore;

/* SEDiffTreeViewStoreClass: custom GObject */
struct _SEDiffTreeViewStoreClass
{
	GObjectClass parent_class;
} SEDiffTreeViewStoreClass;

/* Exported function prototypes */
SEDiffTreeViewStore *sediff_tree_store_new(void);
int sediff_tree_store_iter_to_idx(SEDiffTreeViewStore *store, GtkTreeIter *iter);
GType sediff_tree_view_store_get_type(void);
int sediff_tree_store_populate(SEDiffTreeViewStore *store);

#endif 
 
