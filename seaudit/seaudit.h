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
#include "seaudit_window.h"
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
int seaudit_open_policy(seaudit_t *seaudit_app, const char *filename);
int seaudit_open_log_file(seaudit_t *seaudit_app, const char *filename);



#endif
