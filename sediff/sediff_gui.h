/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 28, 2004
 */
 
#ifndef SEDIFF_GUI_H
#define SEDIFF_GUI_H

#include "sediff_treemodel.h"
#include <gtk/gtk.h>
#include <glade/glade.h>

typedef struct sediff_app {
	GtkWindow *window;		/* the main window */
	GtkWindow *open_dlg;
	GladeXML *window_xml;
	GladeXML *open_dlg_xml;
	GtkWidget *tree_view;	
	GtkTextBuffer *policy1_text;
	GtkTextBuffer *policy2_text;
	GList *callbacks;
	gint progress_completed;
	GtkTextBuffer *classes_buffer;
	GtkTextBuffer *types_buffer;
	GtkTextBuffer *roles_buffer;
	GtkTextBuffer *users_buffer;
	GtkTextBuffer *booleans_buffer;
	GtkTextBuffer *sids_buffer;
	GtkTextBuffer *te_buffer;
	GtkTextBuffer *rbac_buffer;
	GtkTextBuffer *cond_buffer;

	GtkTextBuffer *classes_buffer2;
	GtkTextBuffer *types_buffer2;
	GtkTextBuffer *roles_buffer2;
	GtkTextBuffer *users_buffer2;
	GtkTextBuffer *booleans_buffer2;
	GtkTextBuffer *sids_buffer2;
	GtkTextBuffer *te_buffer2;
	GtkTextBuffer *rbac_buffer2;
	GtkTextBuffer *cond_buffer2;
	

} sediff_app_t;

#endif
