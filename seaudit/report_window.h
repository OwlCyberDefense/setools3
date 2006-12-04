/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information 
 *
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 01, 2004
 *
 */

#ifndef SEAUDIT_REPORT_WINDOW_H
#define SEAUDIT_REPORT_WINDOW_H

#include "report.h"
#include "seaudit_window.h"
#include "preferences.h"
#include <glib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

/* This structure is used to encapsulate settings for instances of the 
 * report_window object. SEAudit will remember any settings the user  
 * has made to the report dialog since initialization.  
 */
typedef struct report_window
{
	bool_t use_entire_log;
	GtkWindow *window;	       /* refers to the GTK widget */
	seaudit_window_t *parent;      /* refers to the seaudit parent window */
	GladeXML *xml;
	GString *window_title;
	seaudit_report_t *report_info; /* options to pass to seaudit-report generation object */
	audit_log_t *entire_log;
} report_window_t;

/* Function: report_window_create()
 * Description: This function creates an instance of the report window object.
 * Arguments: 3
 * 	- seaudit_window - a pointer to a seaudit_window_t. This cannot be NULL.
 *	- seaudit_conf (optional) - a pointer to seaudit config file data. This
 *		is used if we want the report tool to default to use a config 
 *		file and/or stylesheet file other than the system defaults. If 
 *		this data is not available to to report tool, it will always 
 *		attempt to use the system defaults. If this argument is NULL, it
 *		will not attempt to use the settings from the seaudit config file.
 *	- title(optional) - string for the window title.
 */
report_window_t *report_window_create(seaudit_window_t * seaudit_window, seaudit_conf_t * seaudit_conf, const char *title);

/* Function: report_window_destroy()
 * Description: This function destroys an instance of the report window object.
 * Arguments: 1
 * 	- report_window - a pointer to a report_window struct.
 */
void report_window_destroy(report_window_t * report_window);

/* Function: report_window_display()
 * Description: This function displays the report dialog from the GUI. SEAudit 
 * 	will remember any settings the user has made to the report dialog since 
 *	it was initially created and will configure the options on the dialog
 *	accordingly.
 * Arguments: 1
 * 	- report_window - a pointer to a report_window struct.
 */
void report_window_display(report_window_t * report_window);

#endif
