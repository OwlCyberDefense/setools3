/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date : January 22, 2004
 *
 */

#include <gtk/gtk.h>
#include <glade/glade.h>
#include <libapol/util.h>
#include "auditlog.h"
#include "filtered_view.h"

#ifndef SEAUDIT_SEAUDIT_WINDOW_H
#define SEAUDIT_SEAUDIT_WINDOW_H

typedef struct seaudit_window {
	GtkWindow *window;
	GladeXML *xml;
	GList *views;
	GtkNotebook *notebook;
} seaudit_window_t;

seaudit_window_t* seaudit_window_create(audit_log_t *log, bool_t *column_visibility);
void seaudit_window_add_new_view(seaudit_window_t *window, audit_log_t *log, bool_t *column_visibility, const char *view_name);
seaudit_filtered_view_t* seaudit_window_get_current_view(seaudit_window_t *window);
void seaudit_window_filter_views(seaudit_window_t *window);

#endif
