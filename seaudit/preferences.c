/**
 *  @file
 *  Implementation of the storage class preferences_t.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "preferences.h"

#include <apol/util.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/** default frequency, in milliseconds, to poll log file for changes */
#define DEFAULT_LOG_UPDATE_INTERVAL 1000

/** maximum number of recent log files and recent policy files to remember */
#define MAX_RECENT_ENTRIES 5

/** name of the user's seaudit personal preferences file */
#define USER_SEAUDIT_CONF ".seaudit"

/** name of the system seaudit preference file */
#define SYSTEM_SEAUDIT_CONF "dot_seaudit"

struct visible_field
{
	preference_field_e id;
	const char *field;
	int visible;
};

static const struct visible_field default_visible_fields[] = {
	{HOST_FIELD, "host_field", 1},
	{MESSAGE_FIELD, "msg_field", 1},
	{DATE_FIELD, "date_field", 1},
	{SUSER_FIELD, "src_usr_field", 0},
	{SROLE_FIELD, "src_role_field", 0},
	{STYPE_FIELD, "src_type_field", 1},
	{TUSER_FIELD, "tgt_usr_field", 0},
	{TROLE_FIELD, "tgt_role_field", 0},
	{TTYPE_FIELD, "tgt_type_field", 1},
	{OBJCLASS_FIELD, "obj_class_field", 1},
	{PERM_FIELD, "perm_field", 1},
	{EXECUTABLE_FIELD, "exe_field", 1},
	{COMMAND_FIELD, "comm_field", 1},
	{PID_FIELD, "pid_field", 0},
	{INODE_FIELD, "inode_field", 0},
	{PATH_FIELD, "path_field", 0},
	{OTHER_FIELD, "other_field", 1}
};

static size_t num_visible_fields = sizeof(default_visible_fields) / sizeof(default_visible_fields[0]);

struct preferences
{
	/** path to default system log file */
	char *log;
	/** path to default policy */
	apol_policy_path_t *policy;
	/** default path when writing reports */
	char *report;
	/** default path to the stylesheet, used during report writing */
	char *stylesheet;
	/** vector of paths (strings) to recently opened log files */
	apol_vector_t *recent_log_files;
	/** vector of apol_policy_path_t objects to recently opened
            policies */
	apol_vector_t *recent_policy_files;
	/** non-zero if seaudit should poll the log file for changes */
	int real_time_log;
	/** frequency, in milliesconds, to poll log file */
	int real_time_interval;
	struct visible_field *fields;
};

void preferences_apol_policy_path_free(void *elem)
{
	apol_policy_path_t *path = elem;
	apol_policy_path_destroy(&path);
}

/**
 * Parse the old-style recent policies list (a ':' separated list of
 * paths) into the recent_policy_files field.
 */
static int preferences_parse_old_recent_files(preferences_t * prefs, const char *s)
{
	apol_vector_t *v = NULL;
	size_t i;
	char *base;
	apol_policy_path_t *path;
	int error = 0;

	if ((v = apol_str_split(s, ":")) == NULL) {
		error = errno;
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		base = apol_vector_get_element(v, i);
		if ((path = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, base, NULL)) == NULL ||
		    apol_vector_append(prefs->recent_policy_files, path) < 0) {
			error = errno;
			apol_policy_path_destroy(&path);
			goto cleanup;
		}
	}

      cleanup:
	apol_vector_destroy(&v);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

/**
 * Parse the new recent policy files, which now spans across multiple
 * lines.
 */
static int preferences_parse_new_recent_files(preferences_t * prefs, FILE * f, int num_files)
{
	int count;
	for (count = 0; count < num_files; count++) {
		char *var_name, *value = NULL;
		apol_policy_path_t *p = NULL;
		if (asprintf(&var_name, "RECENT_POLICY_PATH_%d", count) < 0) {
			return -1;
		}
		value = apol_config_get_var(var_name, f);
		free(var_name);
		if (value == NULL ||
		    (p = apol_policy_path_create_from_string(value)) == NULL ||
		    apol_vector_append(prefs->recent_policy_files, p) < 0) {
			free(value);
			apol_policy_path_destroy(&p);
			return -1;
		}
		free(value);
	}
	return 0;
}

preferences_t *preferences_create(void)
{
	preferences_t *prefs = NULL;
	FILE *file = NULL;
	char *path = NULL, *value;
	apol_vector_t *v = NULL;
	size_t i, j;
	int error = 0;

	if ((prefs = calloc(1, sizeof(*prefs))) == NULL ||
	    (prefs->log = strdup("")) == NULL ||
	    (prefs->report = strdup("")) == NULL ||
	    (prefs->stylesheet = strdup("")) == NULL ||
	    (prefs->recent_log_files = apol_vector_create(free)) == NULL ||
	    (prefs->recent_policy_files = apol_vector_create(preferences_apol_policy_path_free)) == NULL ||
	    (prefs->fields = calloc(num_visible_fields, sizeof(struct visible_field))) == NULL) {
		error = errno;
		goto cleanup;
	}
	prefs->real_time_interval = DEFAULT_LOG_UPDATE_INTERVAL;
	memcpy(prefs->fields, default_visible_fields, num_visible_fields * sizeof(struct visible_field));
	path = apol_file_find_user_config(USER_SEAUDIT_CONF);
	if (!path) {
		if ((path = apol_file_find_path(SYSTEM_SEAUDIT_CONF)) == NULL) {
			return prefs;
		}
	}
	if ((file = fopen(path, "r")) == NULL) {
		error = errno;
		goto cleanup;
	}
	if ((value = apol_config_get_var("DEFAULT_LOG_FILE", file)) != NULL) {
		free(prefs->log);
		prefs->log = value;
	}
	if ((value = apol_config_get_var("DEFAULT_POLICY_FILE", file)) != NULL) {
		apol_policy_path_destroy(&prefs->policy);
		if (apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, value, NULL) == NULL) {
			error = errno;
			free(value);
			goto cleanup;
		}
		free(value);
	}
	if ((value = apol_config_get_var("DEFAULT_POLICY_PATH", file)) != NULL) {
		apol_policy_path_destroy(&prefs->policy);
		if ((prefs->policy = apol_policy_path_create_from_string(value)) == NULL) {
			error = errno;
			free(value);
			goto cleanup;
		}
		free(value);
	}
	if ((value = apol_config_get_var("DEFAULT_REPORT_CONFIG_FILE", file)) != NULL) {
		free(prefs->report);
		prefs->report = value;
	}
	if ((value = apol_config_get_var("DEFAULT_REPORT_CSS_FILE", file)) != NULL) {
		free(prefs->stylesheet);
		prefs->stylesheet = value;
	}
	if ((value = apol_config_get_var("RECENT_LOG_FILES", file)) == NULL || (v = apol_str_split(value, ":")) == NULL) {
		error = errno;
		free(value);
		goto cleanup;
	}
	free(value);
	apol_vector_destroy(&prefs->recent_log_files);
	prefs->recent_log_files = v;

	/* test if there exists the new recent list that contains
	 * module filenames */
	if ((value = apol_config_get_var("RECENT_POLICY_PATH_FILES", file)) != NULL) {
		if (preferences_parse_new_recent_files(prefs, file, atoi(value)) < 0) {
			error = errno;
			free(value);
			goto cleanup;
		}
	} else {
		/* use older style that could only handle monolithic policies */
		if ((value = apol_config_get_var("RECENT_POLICY_FILES", file)) == NULL
		    || preferences_parse_old_recent_files(prefs, value) < 0) {
			error = errno;
			free(value);
			goto cleanup;
		}
	}
	free(value);

	if ((value = apol_config_get_var("LOG_COLUMNS_HIDDEN", file)) == NULL || (v = apol_str_split(value, ":")) == NULL) {
		error = errno;
		goto cleanup;
	}
	for (j = 0; j < num_visible_fields; j++) {
		prefs->fields[j].visible = 1;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		char *s = apol_vector_get_element(v, i);
		for (j = 0; j < num_visible_fields; j++) {
			if (strcmp(s, prefs->fields[j].field) == 0) {
				prefs->fields[j].visible = 0;
				break;
			}
		}
	}
	free(value);
	apol_vector_destroy(&v);
	value = apol_config_get_var("REAL_TIME_LOG_MONITORING", file);
	if (value != NULL && value[0] != '0') {
		prefs->real_time_log = 1;
	}
	free(value);
	value = apol_config_get_var("REAL_TIME_LOG_UPDATE_INTERVAL", file);
	if (value != NULL) {
		prefs->real_time_interval = atoi(value);
	}
	free(value);
      cleanup:
	free(path);
	if (file != NULL) {
		fclose(file);
	}
	if (error != 0) {
		preferences_destroy(&prefs);
		errno = error;
		return NULL;
	}
	return prefs;
}

void preferences_destroy(preferences_t ** prefs)
{
	if (prefs != NULL && *prefs != NULL) {
		free((*prefs)->log);
		apol_policy_path_destroy(&(*prefs)->policy);
		free((*prefs)->report);
		free((*prefs)->stylesheet);
		apol_vector_destroy(&(*prefs)->recent_log_files);
		apol_vector_destroy(&(*prefs)->recent_policy_files);
		free((*prefs)->fields);
		free(*prefs);
		*prefs = NULL;
	}
}

int preferences_write_to_conf_file(preferences_t * prefs)
{
	FILE *file = NULL;
	char *home, *conf_file = NULL, *value;
	apol_vector_t *hidden_fields = NULL;
	size_t i;
	int retval = 0, error = 0;

	/* we need to open ~/.seaudit */
	home = getenv("HOME");
	if (!home) {
		error = EBADRQC;
		goto cleanup;
	}
	if (asprintf(&conf_file, "%s/%s", home, USER_SEAUDIT_CONF) < 0) {
		error = errno;
		goto cleanup;
	}

	if ((file = fopen(conf_file, "w")) == NULL) {
		error = errno;
		goto cleanup;
	}

	fprintf(file, "# configuration file for seaudit - an audit log tool for Security Enhanced Linux.\n");
	fprintf(file, "# this file is auto-generated\n\n");

	if (strcmp(prefs->log, "") != 0) {
		fprintf(file, "DEFAULT_LOG_FILE %s\n", prefs->log);
	}
	if (prefs->policy != NULL) {
		value = apol_policy_path_to_string(prefs->policy);
		if (value == NULL) {
			error = errno;
			goto cleanup;
		}
		fprintf(file, "DEFAULT_POLICY_PATH %s\n", value);
		free(value);
	}
	if (strcmp(prefs->report, "") != 0) {
		fprintf(file, "DEFAULT_REPORT_CONFIG_FILE %s\n", prefs->report);
	}
	if (strcmp(prefs->stylesheet, "") != 0) {
		fprintf(file, "DEFAULT_REPORT_CSS_FILE %s\n", prefs->stylesheet);
	}
	if ((value = apol_str_join(prefs->recent_log_files, ":")) == NULL) {
		error = errno;
		goto cleanup;
	}
	fprintf(file, "RECENT_LOG_FILES %s\n", value);
	free(value);

	fprintf(file, "RECENT_POLICY_PATH_FILES %zd\n", apol_vector_get_size(prefs->recent_policy_files));
	for (i = 0; i < apol_vector_get_size(prefs->recent_policy_files); i++) {
		apol_policy_path_t *p = apol_vector_get_element(prefs->recent_policy_files, i);
		if ((value = apol_policy_path_to_string(p)) == NULL) {
			error = errno;
			goto cleanup;
		}
		fprintf(file, "RECENT_POLICY_PATH_%zd %s\n", i, value);
		free(value);
	}

	if ((hidden_fields = apol_vector_create(NULL)) == NULL) {
		error = errno;
		goto cleanup;
	}
	for (i = 0; i < num_visible_fields; i++) {
		if (!prefs->fields[i].visible && apol_vector_append(hidden_fields, (char *)prefs->fields[i].field) < 0) {
			error = errno;
			goto cleanup;
		}
	}
	if ((value = apol_str_join(hidden_fields, ":")) == NULL) {
		error = errno;
		goto cleanup;
	}
	fprintf(file, "LOG_COLUMNS_HIDDEN %s\n", value);
	free(value);
	fprintf(file, "REAL_TIME_LOG_MONITORING %d\n", prefs->real_time_log);
	fprintf(file, "REAL_TIME_LOG_UPDATE_INTERVAL %d\n", prefs->real_time_interval);
	retval = 0;
      cleanup:
	free(conf_file);
	apol_vector_destroy(&hidden_fields);
	if (file != NULL) {
		fclose(file);
	}
	errno = error;
	return retval;
}

int preferences_is_column_visible(preferences_t * prefs, preference_field_e id)
{
	size_t i;
	for (i = 0; i < num_visible_fields; i++) {
		if (prefs->fields[i].id == id) {
			return prefs->fields[i].visible;
		}
	}
	assert(0);
	return -1;
}

void preferences_set_column_visible(preferences_t * prefs, preference_field_e id, int visible)
{
	size_t i;
	for (i = 0; i < num_visible_fields; i++) {
		if (prefs->fields[i].id == id) {
			prefs->fields[i].visible = visible;
			return;
		}
	}
	assert(0);
}

int preferences_set_log(preferences_t * prefs, const char *log)
{
	char *s;
	if ((s = strdup(log)) == NULL) {
		return -1;
	}
	free(prefs->log);
	prefs->log = s;
	return 0;
}

const char *preferences_get_log(preferences_t * prefs)
{
	return prefs->log;
}

int preferences_set_policy(preferences_t * prefs, const apol_policy_path_t * policy)
{
	apol_policy_path_t *new_policy;
	if ((new_policy = apol_policy_path_create_from_policy_path(policy)) == NULL) {
		return -1;
	}
	apol_policy_path_destroy(&prefs->policy);
	prefs->policy = new_policy;
	return 0;
}

const apol_policy_path_t *preferences_get_policy(preferences_t * prefs)
{
	return prefs->policy;
}

int preferences_set_report(preferences_t * prefs, const char *report)
{
	char *s;
	if ((s = strdup(report)) == NULL) {
		return -1;
	}
	free(prefs->report);
	prefs->report = s;
	return 0;
}

const char *preferences_get_report(preferences_t * prefs)
{
	return prefs->report;
}

int preferences_set_stylesheet(preferences_t * prefs, const char *stylesheet)
{
	char *s;
	if ((s = strdup(stylesheet)) == NULL) {
		return -1;
	}
	free(prefs->stylesheet);
	prefs->stylesheet = s;
	return 0;
}

const char *preferences_get_stylesheet(preferences_t * prefs)
{
	return prefs->stylesheet;
}

void preferences_set_real_time_at_startup(preferences_t * prefs, int startup)
{
	prefs->real_time_log = startup;
}

int preferences_get_real_time_at_startup(preferences_t * prefs)
{
	return prefs->real_time_log;
}

void preferences_set_real_time_interval(preferences_t * prefs, int interval)
{
	if (interval <= 0) {
		prefs->real_time_interval = 0;
	} else {
		prefs->real_time_interval = interval;
	}
}

int preferences_get_real_time_interval(preferences_t * prefs)
{
	return prefs->real_time_interval;
}

/**
 * Add an entry to a vector, discarding the oldest entry if the vector
 * size is too large.
 */
static int prefs_add_recent_vector(apol_vector_t * v, const char *entry)
{
	size_t i;
	char *s;
	if (apol_vector_get_index(v, (void *)entry, apol_str_strcmp, NULL, &i) == 0) {
		return 0;
	}
	if ((s = strdup(entry)) == NULL || apol_vector_append(v, s) < 0) {
		int error = errno;
		free(s);
		errno = error;
		return -1;
	}
	if (apol_vector_get_size(v) >= MAX_RECENT_ENTRIES) {
		s = apol_vector_get_element(v, 0);
		free(s);
		return apol_vector_remove(v, 0);
	}
	return 0;
}

int preferences_add_recent_log(preferences_t * prefs, const char *log)
{
	return prefs_add_recent_vector(prefs->recent_log_files, log);
}

apol_vector_t *preferences_get_recent_logs(preferences_t * prefs)
{
	return prefs->recent_log_files;
}

static int preferences_policy_path_compare(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	return apol_policy_path_compare((const apol_policy_path_t *)a, (const apol_policy_path_t *)b);
}

int preferences_add_recent_policy(preferences_t * prefs, const apol_policy_path_t * policy)
{
	size_t i;
	apol_policy_path_t *p = NULL;
	if (apol_vector_get_index(prefs->recent_policy_files, policy, preferences_policy_path_compare, NULL, &i) == 0) {
		return 0;
	}
	if ((p = apol_policy_path_create_from_policy_path(policy)) == NULL || apol_vector_append(prefs->recent_policy_files, p) < 0) {
		int error = errno;
		apol_policy_path_destroy(&p);
		errno = error;
		return -1;
	}
	if (apol_vector_get_size(prefs->recent_policy_files) >= MAX_RECENT_ENTRIES) {
		p = apol_vector_get_element(prefs->recent_policy_files, 0);
		apol_policy_path_destroy(&p);
		return apol_vector_remove(prefs->recent_policy_files, 0);
	}
	return 0;
}

apol_vector_t *preferences_get_recent_policies(preferences_t * prefs)
{
	return prefs->recent_policy_files;
}
