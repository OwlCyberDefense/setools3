/*
 * Author: Kevin Carr <kcarr@tresys.com
 * Date: October 15, 2003
 *
 * callbacks.h
 *
 * this file contains the definitions of all the signal handler functions
 * for GUI events
 */

#include <gtk/gtk.h>

#ifndef SEAUDIT_GUI_CALLBACKS_H
#define SEAUDIT_GUI_CALLBACKS_H

void on_open_policy_activate (GtkWidget *widget, gpointer user_data);
void on_open_audit_log_activate (GtkWidget *widget, gpointer user_data);
void on_quit_activate (GtkWidget *widget, gpointer user_data);
void on_about_seaudit_activate (GtkWidget *widget, gpointer user_data);
#endif
