/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: December 31, 2003
 * Modified: don.patterson@tresys.com 10-2004
 */

#include <gtk/gtk.h>
#include <glade/glade.h>
#include "auditlog.h"

#ifndef SEAUDIT_PREFERENCES_H
#define SEAUDIT_PREFERENCES_H

/* interval in seconds */
#define DEFAULT_LOG_UPDATE_INTERVAL 1000

typedef struct seaudit_conf
{
	char **recent_log_files;
	int num_recent_log_files;
	char **recent_policy_files;
	int num_recent_policy_files;
	char *default_policy_file;
	char *default_log_file;
	bool_t column_visibility[NUM_FIELDS];
	bool_t real_time_log;
	int real_time_interval;
	char *default_seaudit_report_config_file;
	char *default_seaudit_report_css_file;
} seaudit_conf_t;

int load_seaudit_conf_file(seaudit_conf_t * conf_file);
int save_seaudit_conf_file(seaudit_conf_t * conf_file);
void free_seaudit_conf(seaudit_conf_t * conf_file);
int add_path_to_recent_log_files(const char *path, seaudit_conf_t * conf_file);
int add_path_to_recent_policy_files(const char *path, seaudit_conf_t * conf_file);
int set_seaudit_conf_default_policy(seaudit_conf_t * conf_file, const char *filename);
int set_seaudit_conf_default_log(seaudit_conf_t * conf_file, const char *filename);

/* load the preferences window */
void on_preferences_activate(GtkWidget * widget, GdkEvent * event, gpointer callback_data);

#endif
