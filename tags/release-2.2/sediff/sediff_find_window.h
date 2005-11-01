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
	gint start_offset;     /* the offset to start searching from if searching up
				  and the start of the offset to select from*/
	gint end_offset;       /* the offset to start searching from if searching down
				  and the offset to end selecting from */
	GtkWindow *window;     /* the main window */
	GladeXML *xml;         /* xml pointer so we can grab needed widgets */
	struct sediff_app *sediff_app;  /* a back pointer to the sediff app so we can grab some widgets */
} sediff_find_window_t;

/* generate a new find window */
sediff_find_window_t *sediff_find_window_new(struct sediff_app *sediff_app);
/* display the find window on the screen */
void sediff_find_window_display(sediff_find_window_t *find_window);
/* reset the idx used by find window to start searches, must do this whenever 
   changing the textview displayed to the user */
void sediff_find_window_reset_idx(sediff_find_window_t *find_window);

#endif
