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

typedef struct seaudit_conf {
	char **recent_log_files;
	int num_recent_log_files;
	char **recent_policy_files;
	int num_recent_policy_files;
	char *default_policy_file;
	char *default_log_file;
  	bool_t column_visibility[NUM_FIELDS];
	bool_t real_time_log;
/* interval in milli seconds */
#define LOG_UPDATE_INTERVAL 1000
	guint timeout_key;
} seaudit_conf_t;

typedef struct seaudit {
	policy_t *cur_policy;
	SEAuditLogStore *log_store;
	GladeXML *top_window_xml;
	GtkWindow *top_window;
	filters_t *filters;
	GtkTextBuffer *policy_text;
	GList *callbacks;
	FILE *log_file_ptr;
	seaudit_conf_t seaudit_conf;
	GString *policy_file;
	GString *audit_log_file;
	bool_t column_visibility_changed;
} seaudit_t;

extern seaudit_t *seaudit_app;


typedef struct user_data_items {
	void *user_data_1;
	void *user_data_2;
} user_data_items_t;

seaudit_t *seaudit_init(void);
void seaudit_destroy(seaudit_t *seaudit_app);
int seaudit_open_policy(seaudit_t *seaudit, const char *filename);
int seaudit_open_log_file(seaudit_t *seaudit, const char *filename);

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

/* utils */
void show_wait_cursor(GtkWidget *widget);
void clear_wait_cursor(GtkWidget *widget);
void message_display(GtkWindow *parent, GtkMessageType msg_type, const char *msg);
void update_status_bar(void *user_data);

#endif
