/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *         Kevin Carr <kcarr@tresys.com>
 *         Jeremy Stitz <jstitz@tresys.com>
 */

#ifndef SEAUDIT_H
#define SEAUDIT_H

#include "auditlog.h"
#include "auditlogmodel.h"
#include "seaudit_window.h"
#include "filter_window.h"
#include "preferences.h"
#include "report_window.h"
#include <libapol/policy.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <assert.h>

#ifndef STR_SIZE
        #define STR_SIZE  8192
#endif

#ifndef TIME_SIZE
        #define TIME_SIZE 64
#endif

#ifndef DEFAULT_LOG
	#define DEFAULT_LOG "/var/log/messages"
#endif

#ifndef INSTALL_LIBDIR
        #define INSTALL_LIBDIR "/usr/share/setools"
#endif

typedef struct seaudit {
	policy_t *cur_policy;
	audit_log_t *cur_log;
	seaudit_window_t *window;
	GtkTextBuffer *policy_text;
	GList *callbacks;
	FILE *log_file_ptr;
	bool_t real_time_state;
	guint timeout_key;
	seaudit_conf_t seaudit_conf;
	GString *policy_file;
	GString *audit_log_file;
	bool_t column_visibility_changed;
	report_window_t *report_window;
} seaudit_t;

extern seaudit_t *seaudit_app;
#define SEAUDIT_VIEW_EXT ".vw"
#define SEAUDIT_FILTER_EXT ".ftr"

seaudit_t *seaudit_init(void);
void seaudit_destroy(seaudit_t *seaudit_app);
int seaudit_open_policy(seaudit_t *seaudit_app, const char *filename);
int seaudit_open_log_file(seaudit_t *seaudit_app, const char *filename);
void seaudit_update_status_bar(seaudit_t *seaudit);

/* Functions related to exporting log files */

void seaudit_save_log_file(bool_t selected_only);
int  seaudit_write_log_file(const audit_log_view_t *log_view, const char *filename);
audit_log_view_t* seaudit_get_current_audit_log_view();
void generate_message_header(char *message_header, audit_log_t *audit_log, struct tm *date_stamp, int host);
void write_avc_message_to_file(FILE *log_file, const avc_msg_t *message, const char *message_header, audit_log_t *audit_log);
void write_load_policy_message_to_file(FILE *log_file, const load_policy_msg_t *message, const char *message_header);
void write_boolean_message_to_file(FILE *log_file, const boolean_msg_t *message, const char *message_header, audit_log_t *audit_log);
void seaudit_window_view_entire_message_in_textbox(int *tree_item_idx);
void seaudit_on_export_selection_activated(void);

#endif
