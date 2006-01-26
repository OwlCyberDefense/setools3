/* Copyright (C) 2005-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr kcarr@tresys.com
 * Date:   June 14, 2005
 */

#ifndef SEDIFF_RENAME_TYPES_H
#define SEDIFF_RENAME_TYPES_H

#define SEDIFF_RENAME_POLICY_ONE_COLUMN 0
#define SEDIFF_RENAME_POLICY_TWO_COLUMN 1 
#define SEDIFF_RENAME_NUM_COLUMNS       2

#include "sediff_gui.h"
#include "poldiff.h"
#include <glade/glade.h>
#include <gtk/gtk.h>

typedef struct sediff_rename_types {
	GtkTreeView *view;
	GtkListStore *store;
	GtkCombo *p1_combo;
	GtkCombo *p2_combo;
	GtkWindow *window;
	GladeXML *xml;
	struct sediff_app *sediff_app;
	ap_diff_rename_t *renamed_types;
} sediff_rename_types_t;

sediff_rename_types_t* sediff_rename_types_window_new(struct sediff_app *sediff_app);
void sediff_rename_types_window_display(sediff_rename_types_t *rename_types);
void sediff_rename_types_window_unref_members(sediff_rename_types_t *rename_types);


#endif
