/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information 
 *
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 3, 2004
 */

/* This is the interface for processing SELinux audit logs and/or seaudit views
 * to generate concise reports containing standard information as well as 
 * customized information using seaudit views. Reports are rendered in either
 * HTML or plain text. Future support will provide rendering into XML. The 
 * HTML report can be formatted by providing an alternate stylesheet file
 * or by configuring the default stylesheet. 
 */
 
#ifndef SEAUDIT_REPORT_H
#define SEAUDIT_REPORT_H

#include "../libapol/util.h"
#include "../libseaudit/parse.h"
#include "../libseaudit/auditlog_view.h"

#define CONFIG_FILE "seaudit-report.conf"
#define STYLESHEET_FILE "seaudit-report.css"

typedef struct seaudit_report {
	bool_t stdin;
	bool_t html;
	bool_t use_stylesheet;
	bool_t malformed;
	char *configPath;
	char *outFile;
	char *stylesheet_file;
	char **logfiles;
	int num_logfiles;
	audit_log_t *log;		/* This holds all of the log messages, which we're interested in */
	audit_log_view_t *log_view; 	/* This holds a reference to an seaudit view to filter messages */
} seaudit_report_t;

int seaudit_report_add_outFile_path(const char *file, seaudit_report_t *seaudit_report); 
int seaudit_report_add_configFile_path(const char *file, seaudit_report_t *seaudit_report);
int seaudit_report_add_stylesheet_path(const char *file, seaudit_report_t *seaudit_report);
int seaudit_report_add_logfile_to_list(seaudit_report_t *seaudit_report, const char *file);
int seaudit_report_load_audit_messages_from_log_file(seaudit_report_t *seaudit_report);
int seaudit_report_search_dflt_config_file(seaudit_report_t *seaudit_report);
int seaudit_report_search_dflt_stylesheet(seaudit_report_t *seaudit_report);
int seaudit_report_generate_report(seaudit_report_t *seaudit_report);
void seaudit_report_destroy(seaudit_report_t *seaudit_report);
seaudit_report_t *seaudit_report_create();

#endif
