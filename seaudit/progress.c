/**
 *  @file
 *  Routines to show a progress dialog, indicating that the
 *  application is doing something.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include "progress.h"
#include "utilgui.h"

#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gprintf.h>

struct progress
{
	toplevel_t *top;
	GtkWidget *progress;
	GtkWidget *label1, *label2;
	char *s;
	int done;
	GCond *cond;
	GMutex *mutex;
};

progress_t *progress_create(toplevel_t * top)
{
	progress_t *p;
	GtkWidget *vbox;

	if ((p = calloc(1, sizeof(*p))) == NULL) {
		return NULL;
	}
	p->top = top;
	p->progress = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_modal(GTK_WINDOW(p->progress), TRUE);
	gtk_window_set_transient_for(GTK_WINDOW(p->progress), toplevel_get_window(top));
	gtk_window_set_default_size(GTK_WINDOW(p->progress), 300, 100);
	vbox = gtk_vbox_new(FALSE, 2);
	gtk_container_add(GTK_CONTAINER(p->progress), vbox);
	p->label1 = gtk_label_new(NULL);
	gtk_container_add(GTK_CONTAINER(vbox), p->label1);
	p->label2 = gtk_label_new(NULL);
	gtk_container_add(GTK_CONTAINER(vbox), p->label2);
	gtk_widget_show(p->label1);
	gtk_widget_show(p->label2);
	gtk_widget_show(vbox);
	util_cursor_wait(p->progress);
	p->cond = g_cond_new();
	p->mutex = g_mutex_new();
	return p;
}

void progress_destroy(progress_t ** progress)
{
	if (progress != NULL && *progress != NULL) {
		free((*progress)->s);
		g_cond_free((*progress)->cond);
		g_mutex_free((*progress)->mutex);
		free(*progress);
		*progress = NULL;
	}
}

void progress_show(progress_t * progress, const char *title)
{
	gtk_label_set_text(GTK_LABEL(progress->label1), title);
	gtk_label_set_text(GTK_LABEL(progress->label2), "");
	gtk_widget_show(progress->progress);
	gtk_window_deiconify(GTK_WINDOW(progress->progress));
	gtk_window_set_title(GTK_WINDOW(progress->progress), title);
	progress->done = 0;
}

void progress_hide(progress_t * progress)
{
	gtk_widget_hide(progress->progress);
}

int progress_wait(progress_t * progress)
{
	GTimeVal wait_time = { 0, 50000 };
	g_mutex_lock(progress->mutex);
	while (!progress->done) {
		g_cond_timed_wait(progress->cond, progress->mutex, &wait_time);
		if (progress->s != NULL) {
			gtk_label_set_text(GTK_LABEL(progress->label2), progress->s);
			free(progress->s);
			progress->s = NULL;
		}
		while (gtk_events_pending())
			gtk_main_iteration();
	}
	g_mutex_unlock(progress->mutex);
	if (progress->done < 0) {
		toplevel_ERR(progress->top, GTK_LABEL(progress->label2)->label);
		return progress->done;
	} else if (progress->done > 1) {
		toplevel_WARN(progress->top, GTK_LABEL(progress->label2)->label);
		return progress->done - 1;
	} else {
		progress->done = 0;
		return 0;
	}
}

void progress_done(progress_t * progress)
{
	g_mutex_lock(progress->mutex);
	progress->done = 1;
	g_cond_signal(progress->cond);
	g_mutex_unlock(progress->mutex);
}

void progress_warn(progress_t * progress, char *reason, ...)
{
	gchar *s;
	va_list ap;
	g_mutex_lock(progress->mutex);
	if (reason != NULL) {
		va_start(ap, reason);
		g_vasprintf(&s, reason, ap);
		free(progress->s);
		progress->s = s;
		va_end(ap);
	}
	progress->done = 2;
	g_cond_signal(progress->cond);
	g_mutex_unlock(progress->mutex);
}

void progress_abort(progress_t * progress, char *reason, ...)
{
	gchar *s;
	va_list ap;
	g_mutex_lock(progress->mutex);
	if (reason != NULL) {
		va_start(ap, reason);
		g_vasprintf(&s, reason, ap);
		free(progress->s);
		progress->s = s;
		va_end(ap);
	}
	progress->done = -1;
	g_cond_signal(progress->cond);
	g_mutex_unlock(progress->mutex);
}

static void progress_update_label(progress_t * progress, const char *fmt, va_list va_args)
{
	gchar *s = NULL;
	g_vasprintf(&s, fmt, va_args);
	g_mutex_lock(progress->mutex);
	free(progress->s);
	progress->s = s;
	g_cond_signal(progress->cond);
	g_mutex_unlock(progress->mutex);
}

void progress_update(progress_t * progress, char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	progress_update_label(progress, fmt, ap);
	va_end(ap);
}

void progress_seaudit_handle_func(void *arg, seaudit_log_t * log __attribute__ ((unused)), int level
				  __attribute__ ((unused)), const char *fmt, va_list va_args)
{
	progress_t *progress = arg;
	progress_update_label(progress, fmt, va_args);
}

void progress_apol_handle_func(void *varg, const apol_policy_t * p __attribute__ ((unused)), int level
			       __attribute__ ((unused)), const char *fmt, va_list argp)
{
	progress_t *progress = varg;
	progress_update_label(progress, fmt, argp);
}
