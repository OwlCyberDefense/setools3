/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: October 15, 2003
 *
 * callbacks.c
 *
 * this file contains the implementation of callbacks.h
 */

#include "callbacks.h"
#include "appstruct.h"

extern app_t *app_struct;

void on_open_policy_activate (GtkWidget *widget, gpointer user_data)
{
	if (app_struct->policy)
		app_struct_policy_close(app_struct);
	// gtk open file browser and get new policy file
}

void on_open_audit_log_activate (GtkWidget *widget, gpointer user_data)
{
	if (app_struct->log)
		app_struct_audit_log_close(app_struct);
	// gtk open file browser and get new log file
}

void on_quit_activate (GtkWidget *widget, gpointer user_data)
{
	gtk_exit(0);
}

void on_about_seaudit_activate (GtkWidget *widget, gpointer user_data)
{
	// gtk open new window and display version and such

}
