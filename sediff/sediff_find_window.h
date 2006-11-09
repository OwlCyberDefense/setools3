/**
 *  @file sediff_find_window.h
 *  Headers for displaying a find dialog.
 *
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

#ifndef SEDIFF_FIND_WINDOW_H
#define SEDIFF_FIND_WINDOW_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "sediff_gui.h"
#include <glade/glade.h>
#include <gtk/gtk.h>

typedef struct sediff_find_window
{
	gint start_offset;	       /* the offset to start searching from if searching up
				        * and the start of the offset to select from */
	gint end_offset;	       /* the offset to start searching from if searching down
				        * and the offset to end selecting from */
	GtkWindow *window;	       /* the main window */
	GladeXML *xml;		       /* xml pointer so we can grab needed widgets */
	struct sediff_app *sediff_app; /* a back pointer to the sediff app so we can grab some widgets */
} sediff_find_window_t;

/* generate a new find window */
sediff_find_window_t *sediff_find_window_new(struct sediff_app *sediff_app);
/* display the find window on the screen */
void sediff_find_window_display(sediff_find_window_t * find_window);
/* reset the idx used by find window to start searches, must do this whenever
   changing the textview displayed to the user */
void sediff_find_window_reset_idx(sediff_find_window_t * find_window);

#ifdef	__cplusplus
}
#endif

#endif
