/**
 *  @file sediff_progress.c
 *  Routines to show a progress dialog, indicating that sediff is
 *  doing something.
 *
 *  @author Don Patterson don.patterson@tresys.com
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

#include "sediff_progress.h"

#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gprintf.h>

struct sediff_progress {
	GtkWidget *progress;
	GtkWidget *label1, *label2;
};

void sediff_progress_show(sediff_app_t *app, const char *title)
{
        sediff_progress_t *p;
	if (app->progress == NULL) {
		GtkWidget *vbox;
		GdkCursor *cursor;
		p = g_malloc(sizeof(sediff_progress_t));
		app->progress = p;
		p->progress = gtk_window_new(GTK_WINDOW_TOPLEVEL);
		gtk_window_set_modal(GTK_WINDOW(p->progress), TRUE);
		gtk_window_set_transient_for(GTK_WINDOW(p->progress), app->window);
		gtk_window_set_default_size(GTK_WINDOW(p->progress), 300, 100);
		vbox = gtk_vbox_new(FALSE, 2);
		gtk_container_add(GTK_CONTAINER(p->progress), vbox);
		p->label1 = gtk_label_new(title);
		gtk_container_add(GTK_CONTAINER(vbox), p->label1);
		p->label2 = gtk_label_new(NULL);
		gtk_container_add(GTK_CONTAINER(vbox), p->label2);
		gtk_widget_show(p->label1);
		gtk_widget_show(p->label2);
		gtk_widget_show(vbox);
		gtk_widget_show(p->progress);
		cursor = gdk_cursor_new(GDK_WATCH);
		gdk_window_set_cursor(p->progress->window, cursor);
		gdk_cursor_unref(cursor);
	}
	else {
		p = app->progress;
		gtk_label_set_text(GTK_LABEL(p->label1), title);
		gtk_label_set_text(GTK_LABEL(p->label2), "");
		gtk_widget_show(p->progress);
		gtk_window_deiconify(GTK_WINDOW(p->progress));
	}
	gtk_window_set_title(GTK_WINDOW(p->progress), title);
}

void sediff_progress_hide(sediff_app_t *app)
{
	if (app != NULL && app->progress != NULL) {
		gtk_widget_hide(app->progress->progress);
	}
}

void sediff_progress_destroy(sediff_app_t *app)
{
	if (app != NULL && app->progress != NULL) {
		gtk_widget_hide(app->progress->progress);
		gtk_widget_destroy(app->progress->progress);
	}
}

static void sediff_progress_update_label(sediff_app_t *app, const char *fmt, va_list va_args)
{
	gchar *s = NULL;
	g_vasprintf(&s, fmt, va_args);
	gtk_label_set_text(GTK_LABEL(app->progress->label2), s);
	free(s);
	while (gtk_events_pending ())
		gtk_main_iteration ();
}

void sediff_progress_message(sediff_app_t *app, const char *title, const char *message)
{
	sediff_progress_show(app, title);
	gtk_label_set_text(GTK_LABEL(app->progress->label2), message);
	while (gtk_events_pending ())
		gtk_main_iteration ();
}

void sediff_progress_poldiff_handle_func(void *arg, poldiff_t *diff, int level, const char *fmt, va_list va_args)
{
	sediff_app_t *app = (sediff_app_t *) arg;
	if (app->progress != NULL) {
		sediff_progress_update_label(app, fmt, va_args);
	}
}

void sediff_progress_apol_handle_func(apol_policy_t *p, int level, const char *fmt, va_list argp)
{
	if (p != NULL) {
		sediff_app_t *app = (sediff_app_t *) p->msg_callback_arg;
		if (app->progress != NULL) {
			sediff_progress_update_label(app, fmt, argp);
		}
	}
}
