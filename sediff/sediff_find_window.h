/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Brandon Whalen bwhalen@tresys.com
 * Date:   August 8, 2005
 */

#ifndef SEDIFF_FIND_WINDOW_H
#define SEDIFF_FIND_WINDOW_H

#include "sediff_gui.h"
#include <glade/glade.h>
#include <gtk/gtk.h>


typedef struct sediff_find_window {
	gint start_offset;
	gint end_offset;
	GtkWindow *window;
	GladeXML *xml;
	struct sediff_app *sediff_app;
} sediff_find_window_t;

sediff_find_window_t *sediff_find_window_new(struct sediff_app *sediff_app);
void sediff_find_window_display(sediff_find_window_t *find_window);
void sediff_find_window_reset_idx(sediff_find_window_t *find_window);

#endif
