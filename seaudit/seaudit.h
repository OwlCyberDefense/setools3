/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *         Kevin Carr <kcarr@tresys.com>
 */

#ifndef SEAUDIT_H
#define SEAUDIT_H

#include "auditlog.h"
#include "auditlogmodel.h"
#include "filter_window.h"
#include "preferences.h"
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

/* DEFAULT_POLICY and DEFAULT_LOG should be defined in the make environment */
#ifndef DEFAULT_POLICY
	#define DEFAULT_POLICY "/etc/security/selinux/src/policy.conf"
#endif

#ifndef DEFAULT_LOG
	#define DEFAULT_LOG "/var/log/messages"
#endif

#ifndef INSTALL_LIBDIR
        #define INSTALL_LIBDIR "/usr/lib/apol"
#endif

typedef void(*seaudit_callback_t)(void *user_data);

typedef struct registered_callback {
	seaudit_callback_t function;
	void *user_data;
	unsigned int type;

/* callback types */
#define POLICY_LOADED_CALLBACK   0
#define LOG_LOADED_CALLBACK      1
#define LOG_FILTERED_CALLBACK    2

/* signal types */
#define POLICY_LOADED_SIGNAL POLICY_LOADED_CALLBACK
#define LOG_LOADED_SIGNAL    LOG_LOADED_CALLBACK
#define LOG_FILTERED_SIGNAL  LOG_FILTERED_CALLBACK
} registered_callback_t;


typedef struct seaudit_window {
	GtkWindow *window;
	GladeXML *xml;
	GList *views;
	GtkNotebook *notebook;
} seaudit_window_t;

seaudit_window_t* seaudit_window_create(audit_log_t *log, bool_t column_visibility[]);
void seaudit_window_add_new_view(seaudit_window_t *window, audit_log_t *log, bool_t column_visibility[], const char *view_name);
top_filters_view_t* seaudit_window_get_current_view(seaudit_window_t *window);
void seaudit_window_filter_views(seaudit_window_t *window);

typedef struct seaudit {
	policy_t *cur_policy;
	audit_log_t *cur_log;
	seaudit_window_t *window;
	GtkTextBuffer *policy_text;
	GList *callbacks;
	FILE *log_file_ptr;
/* interval in milli seconds */
#define LOG_UPDATE_INTERVAL 1000
	guint timeout_key;
	seaudit_conf_t seaudit_conf;
	GString *policy_file;
	GString *audit_log_file;
	bool_t column_visibility_changed;
} seaudit_t;

extern seaudit_t *seaudit_app;

seaudit_t *seaudit_init(void);
void seaudit_destroy(seaudit_t *seaudit_app);
int seaudit_open_policy(const char *filename);
int seaudit_open_log_file(const char *filename);

/* callback and signal handling for seaudit events */
int seaudit_callback_register(seaudit_callback_t function, void *user_data, unsigned int type);
void seaudit_callback_remove(seaudit_callback_t function, void *user_data, unsigned int type);
void seaudit_callbacks_free(void);
void seaudit_callback_signal_emit(unsigned int type);

#define policy_load_callback_register(function, user_data) seaudit_callback_register(function, user_data, POLICY_LOADED_CALLBACK)
#define policy_load_callback_remove(function, user_data) seaudit_callback_remove(function, user_data, POLICY_LOADED_CALLBACK) 
#define policy_load_signal_emit() seaudit_callback_signal_emit(POLICY_LOADED_SIGNAL)
#define log_load_callback_register(function, user_data) seaudit_callback_register(function, user_data, LOG_LOADED_CALLBACK)
#define log_load_callback_remove(function, user_data) seaudit_callback_remove(function, user_data, LOG_LOADED_CALLBACK) 
#define log_load_signal_emit() seaudit_callback_signal_emit(LOG_LOADED_SIGNAL)
#define log_filtered_callback_register(function, user_data) seaudit_callback_register(function, user_data, LOG_FILTERED_CALLBACK)
#define log_filtered_callback_remove(function, user_data) seaudit_callback_remove(function, user_data, LOG_FILTERED_CALLBACK) 
#define log_filtered_signal_emit() seaudit_callback_signal_emit(LOG_FILTERED_SIGNAL)

#endif
