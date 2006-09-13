/**
 *  @file sediff_treemodel.h
 *  Header for a tree from which the user can show the results of a
 *  particular diff.
 *
 *  @author Don Patterson don.patterson@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2004-2006 Tresys Technology, LLC
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
#ifndef SEDIFF_TREE_MODEL_H
#define SEDIFF_TREE_MODEL_H

#include <gtk/gtk.h>
#include <poldiff/poldiff.h>

/* defines for the sediff tree options */
#define OPT_SUMMARY             0

#define OPT_CLASSES		1
#define OPT_CLASSES_ADD         2
#define OPT_CLASSES_REM         3
#define OPT_CLASSES_MOD         4

#define OPT_PERMISSIONS         5
#define OPT_PERMISSIONS_ADD     6
#define OPT_PERMISSIONS_REM     7

#define OPT_COMMON_PERMS        8
#define OPT_COMMON_PERMS_ADD    9
#define OPT_COMMON_PERMS_REM   10
#define OPT_COMMON_PERMS_MOD   11

#define OPT_TYPES	       12
#define OPT_TYPES_ADD          13
#define OPT_TYPES_REM          14
#define OPT_TYPES_MOD          15

#define OPT_ATTRIBUTES         16
#define OPT_ATTRIBUTES_ADD     17
#define OPT_ATTRIBUTES_REM     18
#define OPT_ATTRIBUTES_MOD     19
#define OPT_ATTRIBUTES_MOD_ADD 20
#define OPT_ATTRIBUTES_MOD_REM 21

#define OPT_ROLES	       22
#define OPT_ROLES_ADD          23
#define OPT_ROLES_REM          24
#define OPT_ROLES_MOD          25
#define OPT_ROLES_MOD_ADD      26
#define OPT_ROLES_MOD_REM      27

#define OPT_USERS	       28
#define OPT_USERS_ADD          29
#define OPT_USERS_REM          30
#define OPT_USERS_MOD          31

#define OPT_BOOLEANS	       32
#define OPT_BOOLEANS_ADD       33
#define OPT_BOOLEANS_REM       34
#define OPT_BOOLEANS_MOD       35

#define OPT_ROLE_ALLOWS        36
#define OPT_ROLE_ALLOWS_ADD    37
#define OPT_ROLE_ALLOWS_REM    38
#define OPT_ROLE_ALLOWS_MOD    39

#define OPT_ROLE_TRANS         40
#define OPT_ROLE_TRANS_ADD     41
#define OPT_ROLE_TRANS_ADD_TYPE 42
#define OPT_ROLE_TRANS_REM     43
#define OPT_ROLE_TRANS_REM_TYPE 44
#define OPT_ROLE_TRANS_MOD     45

#define OPT_TE_RULES	       46
#define OPT_TE_RULES_ADD       47
#define OPT_TE_RULES_ADD_TYPE  48
#define OPT_TE_RULES_REM       49
#define OPT_TE_RULES_REM_TYPE  50
#define OPT_TE_RULES_MOD       51

#define OPT_CONDITIONALS       52
#define OPT_CONDITIONALS_ADD   53
#define OPT_CONDITIONALS_REM   54
#define OPT_CONDITIONALS_MOD   55

#define OPT_AV_RULES	       56
#define OPT_AV_RULES_ADD       57
#define OPT_AV_RULES_REM       58
#define OPT_AV_RULES_MOD       59
#define OPT_NUM_DIFF_NODES 60

/* The data columns that we export via the tree model interface */
enum
{
  SEDIFF_LABEL_COLUMN = 0,
  SEDIFF_HIDDEN_COLUMN,
  SEDIFF_NUM_COLUMNS
};

GtkWidget *sediff_create_view_and_model(poldiff_t *diff);
int sediff_get_model_option_iter(GtkTreeModel *model,GtkTreeIter *parent,GtkTreeIter *child, int opt);
int sediff_get_current_treeview_selected_row(GtkTreeView *tree_view);
#endif
