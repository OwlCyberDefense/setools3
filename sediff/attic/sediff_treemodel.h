/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 28, 2004
 */
 
#ifndef _SEDIFF_TREE_MODEL_H
#define _SEDIFF_TREE_MODEL_H

#include <gtk/gtk.h>
#include <poldiff.h>

/* defines for the sediff tree options */
#define OPT_SUMMARY             0

#define OPT_CLASSES 		1
#define OPT_CLASSES_ADD         2
#define OPT_CLASSES_REM         3
#define OPT_CLASSES_CHG         4

#define OPT_PERMISSIONS         5
#define OPT_PERMISSIONS_ADD     6
#define OPT_PERMISSIONS_REM     7

#define OPT_COMMON_PERMS        8
#define OPT_COMMON_PERMS_ADD    9
#define OPT_COMMON_PERMS_REM   10
#define OPT_COMMON_PERMS_CHG   11
 
#define OPT_TYPES 	       12
#define OPT_TYPES_ADD          13
#define OPT_TYPES_REM          14
#define OPT_TYPES_CHG          15

#define OPT_ATTRIBUTES         16
#define OPT_ATTRIBUTES_ADD     17
#define OPT_ATTRIBUTES_REM     18
#define OPT_ATTRIBUTES_CHG     19
#define OPT_ATTRIBUTES_CHG_ADD 20
#define OPT_ATTRIBUTES_CHG_REM 21

#define OPT_ROLES	       22
#define OPT_ROLES_ADD          23
#define OPT_ROLES_REM          24
#define OPT_ROLES_CHG          25
#define OPT_ROLES_CHG_ADD      26
#define OPT_ROLES_CHG_REM      27

#define OPT_USERS	       28
#define OPT_USERS_ADD          29 
#define OPT_USERS_REM          30 
#define OPT_USERS_CHG          31

#define OPT_BOOLEANS 	       32
#define OPT_BOOLEANS_ADD       33 
#define OPT_BOOLEANS_REM       34 
#define OPT_BOOLEANS_CHG       35

#define OPT_ROLE_ALLOWS        36 
#define OPT_ROLE_ALLOWS_ADD    37
#define OPT_ROLE_ALLOWS_REM    38 
#define OPT_ROLE_ALLOWS_CHG    39

#define OPT_ROLE_TRANS         40 
#define OPT_ROLE_TRANS_ADD     41
#define OPT_ROLE_TRANS_ADD_TYPE 42  
#define OPT_ROLE_TRANS_REM     43 
#define OPT_ROLE_TRANS_REM_TYPE 44
#define OPT_ROLE_TRANS_CHG     45

#define OPT_TE_RULES	       46
#define OPT_TE_RULES_ADD       47
#define OPT_TE_RULES_ADD_TYPE  48
#define OPT_TE_RULES_REM       49
#define OPT_TE_RULES_REM_TYPE  50
#define OPT_TE_RULES_CHG       51

#define OPT_CONDITIONALS       52
#define OPT_CONDITIONALS_ADD   53
#define OPT_CONDITIONALS_REM   54
#define OPT_CONDITIONALS_CHG   55

#define OPT_NUM_DIFF_NODES 56

/* The data columns that we export via the tree model interface */
enum
{
  SEDIFF_LABEL_COLUMN = 0,
  SEDIFF_HIDDEN_COLUMN,
  SEDIFF_NUM_COLUMNS
};

GtkWidget *sediff_create_view_and_model(ap_single_view_diff_t *svd);
int sediff_get_model_option_iter(GtkTreeModel *model,GtkTreeIter *parent,GtkTreeIter *child, int opt);
int sediff_get_current_treeview_selected_row(GtkTreeView *tree_view);
#endif 
 
