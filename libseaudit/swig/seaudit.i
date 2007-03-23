/**
 * @file
 * SWIG declarations for libseaudit.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

%module seaudit

#define __attribute__(x)

%{
#include "../include/seaudit/avc_message.h"
#include "../include/seaudit/bool_message.h"
#include "../include/seaudit/filter.h"
#include "../include/seaudit/load_message.h"
#include "../include/seaudit/log.h"
#include "../include/seaudit/message.h"
#include "../include/seaudit/model.h"
#include "../include/seaudit/parse.h"
#include "../include/seaudit/report.h"
#include "../include/seaudit/sort.h"
#include "../include/seaudit/util.h"
#include <time.h>
%}

%include exception.i

%typedef unsigned long size_t;

/* from apol wrapper */
%{
	typedef struct apol_vector apol_string_vector_t;
%}
%typedef struct apol_vector apol_string_vector_t;

#ifdef SWIGPYTHON
%typemap(in) FILE * {
	if (!PyFile_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "Need a file!");
		return NULL;
	}
	$1 = PyFile_AsFile($input);
}
#endif

/* from <time.h> */
%{
	typedef struct tm tm_t;
%}
typedef struct tm {
	int tm_sec;   /* seconds */
	int tm_min;   /* minutes */
	int tm_hour;  /* hours */
	int tm_mday;  /* day of the month */
	int tm_mon;   /* month */
	int tm_year;  /* year */
	int tm_wday;  /* day of the week */
	int tm_yday;  /* day in the year */
	int tm_isdst; /* daylight saving time */
} tm_t;
%extend tm_t {
	tm_t() {
		struct tm *t;
		t = calloc(1, sizeof(struct tm));
		if (!t) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return t;
	};
	~tm_t() {
		free(self);
	}
	/* use default accessor style for the rest */
};

const char *libseaudit_get_version(void);

/* seaudit log */
typedef enum seaudit_log_type
{
	SEAUDIT_LOG_TYPE_INVALID = 0,
	SEAUDIT_LOG_TYPE_SYSLOG,
	SEAUDIT_LOG_TYPE_AUDITD
} seaudit_log_type_e;
typedef struct seaudit_log {} seaudit_log_t;
%extend seaudit_log_t {
	seaudit_log_t() {
		seaudit_log_t *slog;
		/* Using default callback for now */
		slog = seaudit_log_create(NULL, NULL);
		if (!slog) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return slog;
	};
	~seaudit_log_t() {
		seaudit_log_destroy(&self);
	};
	%newobject get_users();
	apol_vector_t *get_users() {
		apol_vector_t *v;
		v = seaudit_log_get_users(self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return v;
	};
	%newobject get_roles();
	apol_vector_t *get_roles() {
		apol_vector_t *v;
		v = seaudit_log_get_roles(self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return v;
	};
	%newobject get_types();
	apol_vector_t *get_types() {
		apol_vector_t *v;
		v = seaudit_log_get_types(self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return v;
	};
	%newobject get_classes();
	apol_vector_t *get_classes() {
		apol_vector_t *v;
		v = seaudit_log_get_classes(self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return v;
	};
};

/* seaudit message */
typedef enum seaudit_message_type
{
	SEAUDIT_MESSAGE_TYPE_INVALID = 0,
	SEAUDIT_MESSAGE_TYPE_BOOL,
	SEAUDIT_MESSAGE_TYPE_AVC,
	SEAUDIT_MESSAGE_TYPE_LOAD
} seaudit_message_type_e;
typedef struct seaudit_message {} seaudit_message_t;
%extend seaudit_message_t {
	seaudit_message_t(void *x) {
		return (seaudit_message_t*)x;
	};
	~seaudit_message_t() {
		/* no op */
		return;
	};
	seaudit_message_type_e get_type() {
		seaudit_message_type_e te;
		(void)seaudit_message_get_data(self, &te);
		return te;
	};
	void *get_data() {
		seaudit_message_type_e te;
		return seaudit_message_get_data(self, &te);
	};
	const tm_t *get_time() {
		return seaudit_message_get_time(self);
	}
	%newobject to_string();
	char *to_string() {
		char *str;
		str = seaudit_message_to_string(self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	%newobject to_string_html();
	char *to_string_html() {
		char *str;
		str = seaudit_message_to_string_html(self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
	%newobject to_misc_string();
	char *to_misc_string() {
		char *str;
		str = seaudit_message_to_misc_string(self);
		if (!str) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return str;
	};
};

/* seaudit load message */
typedef struct seaudit_load_message {} seaudit_load_message_t;
%extend seaudit_load_message_t {
	seaudit_load_message_t(void *msg) {
		return (seaudit_load_message_t*)msg;
	};
	~seaudit_load_message_t() {
		/* no op */
		return;
	};
};

/* seaudit bool message */
typedef struct seaudit_bool_message {} seaudit_bool_message_t;
%extend seaudit_bool_message_t {
	seaudit_bool_message_t(void *msg) {
		return (seaudit_bool_message_t*)msg;
	};
	~seaudit_bool_message_t() {
		/* no op */
		return;
	};
};

/* seaudit avc message */
typedef enum seaudit_avc_message_type
{
	SEAUDIT_AVC_UNKNOWN = 0,
	SEAUDIT_AVC_DENIED,
	SEAUDIT_AVC_GRANTED
} seaudit_avc_message_type_e;
typedef struct seaudit_avc_message {} seaudit_avc_message_t;
%extend seaudit_avc_message_t {
	seaudit_avc_message_t(void *msg) {
		return (seaudit_avc_message_t*)msg;
	};
	~seaudit_avc_message_t() {
		/* no op */
		return;
	};
	seaudit_avc_message_type_e get_message_type() {
		return seaudit_avc_message_get_message_type(self);
	};
	long get_timestamp_nano() {
		return seaudit_avc_message_get_timestamp_nano(self);
	};
	const char *get_source_user() {
		return seaudit_avc_message_get_source_user(self);
	};
	const char *get_source_role() {
		return seaudit_avc_message_get_source_role(self);
	};
	const char *get_source_type() {
		return seaudit_avc_message_get_source_type(self);
	};
	const char *get_target_user() {
		return seaudit_avc_message_get_target_user(self);
	};
	const char *get_target_role() {
		return seaudit_avc_message_get_target_role(self);
	};
	const char *get_target_type() {
		return seaudit_avc_message_get_target_type(self);
	};
	const char *get_object_class() {
		return seaudit_avc_message_get_object_class(self);
	};
	const apol_vector_t *get_perm() {
		return seaudit_avc_message_get_perm(self);
	};
	const char *get_exe() {
		return seaudit_avc_message_get_exe(self);
	};
	const char *get_comm() {
		return seaudit_avc_message_get_comm(self);
	};
	int get_pid() {
		return (int)seaudit_avc_message_get_pid(self);
	};
	long get_inode() {
		return (long)seaudit_avc_message_get_inode(self);
	};
	const char *get_path() {
		return seaudit_avc_message_get_path(self);
	};
	const char *get_dev() {
		return seaudit_avc_message_get_dev(self);
	};
	const char *get_netif() {
		return seaudit_avc_message_get_netif(self);
	};
	const char *get_laddr() {
		return seaudit_avc_message_get_laddr(self);
	};
	int get_lport() {
		return seaudit_avc_message_get_lport(self);
	};
	const char *get_faddr() {
		return seaudit_avc_message_get_faddr(self);
	};
	int get_fport() {
		return seaudit_avc_message_get_fport(self);
	};
	const char *get_saddr() {
		return seaudit_avc_message_get_saddr(self);
	};
	int get_sport() {
		return seaudit_avc_message_get_sport(self);
	};
	const char *get_daddr() {
		return seaudit_avc_message_get_daddr(self);
	};
	int get_dport() {
		return seaudit_avc_message_get_dport(self);
	};
	int get_key() {
		return seaudit_avc_message_get_key(self);
	};
	int get_cap() {
		return seaudit_avc_message_get_cap(self);
	};
};

int seaudit_log_parse(seaudit_log_t * log, FILE * syslog);

/* seaudit filter */
typedef enum seaudit_filter_match
{
	SEAUDIT_FILTER_MATCH_ALL = 0,
	SEAUDIT_FILTER_MATCH_ANY
} seaudit_filter_match_e;
typedef enum seaudit_filter_visible
{
	SEAUDIT_FILTER_VISIBLE_SHOW = 0,
	SEAUDIT_FILTER_VISIBLE_HIDE
} seaudit_filter_visible_e;
typedef enum seaudit_filter_date_match
{
	SEAUDIT_FILTER_DATE_MATCH_BEFORE = 0,
	SEAUDIT_FILTER_DATE_MATCH_AFTER,
	SEAUDIT_FILTER_DATE_MATCH_BETWEEN
} seaudit_filter_date_match_e;
typedef struct seaudit_filter {} seaudit_filter_t;
%extend seaudit_filter_t {
	seaudit_filter_t(char *name = NULL) {
		seaudit_filter_t *sf = seaudit_filter_create(name);
		if (!sf) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return sf;
	};
	seaudit_filter_t(seaudit_filter_t *in) {
		seaudit_filter_t *sf = seaudit_filter_create_from_filter(in);
		if (!sf) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return sf;
	};
//	seaudit_filter_t(char *path) {
//		seaudit_filter_t *sf = seaudit_filter_create_from_file(path);
//		if (!sf) {
//			SWIG_exception(SWIG_MemoryError, "Out of memory");
//		}
//	fail:
//		return sf;
//	};
	seaudit_filter_t(void *x) {
		return (seaudit_filter_t*)x;
	};
	~seaudit_filter_t() {
		seaudit_filter_destroy(&self);
	};
	void save(char *path) {
		if (seaudit_filter_save_to_file(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not save filter");
		}
	fail:
		return;
	};
	void set_match(seaudit_filter_match_e match) {
		if (seaudit_filter_set_match(self, match)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter matching method");
		}
	fail:
		return;
	}
	seaudit_filter_match_e get_match() {
		return seaudit_filter_get_match(self);
	};
	void set_name(char *name) {
		if (seaudit_filter_set_name(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter name");
		}
	fail:
		return;
	};
	const char *get_name() {
		return seaudit_filter_get_name(self);
	};
	void set_description(char *description) {
		if (seaudit_filter_set_description(self, description)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter description");
		}
	fail:
		return;
	};
	const char *get_description() {
		return seaudit_filter_get_description(self);
	};
	void set_source_user(apol_string_vector_t *v) {
		if (seaudit_filter_set_source_user(self, (apol_vector_t*)v)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set source user list for filter");
		}
	fail:
		return;
	};
	const apol_string_vector_t *get_source_user() {
		return seaudit_filter_get_source_user(self);
	};
};

/* seaudit model */
typedef struct seaudit_model {} seaudit_model_t;
%extend seaudit_model_t {
	seaudit_model_t(char *name = NULL, seaudit_log_t *slog = NULL) {
		seaudit_model_t *smod = seaudit_model_create(name, slog);
		if (!smod) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return smod;
	};
	seaudit_model_t(seaudit_model_t *in) {
		seaudit_model_t *smod = seaudit_model_create_from_model(in);
		if (!smod) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return smod;
	};
	seaudit_model_t(char *path) {	
		seaudit_model_t *smod = seaudit_model_create_from_file(path);
		if (!smod) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return smod;
	}
	~seaudit_model_t() {
		seaudit_model_destroy(&self);
	};
	void save(char *path) {
		if (seaudit_model_save_to_file(self, path)) {
			SWIG_exception(SWIG_RuntimeError, "Could not save seaudit model");
		}
	fail:
		return;
	}
	const char *get_name() {
		return seaudit_model_get_name(self);
	};
	void set_name(char *name) {
		if (seaudit_model_set_name(self, name)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set model name");
		}
	fail:
		return;
	};
	void append_log(seaudit_log_t *slog) {
		if (seaudit_model_append_log(self, slog)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append log to model");
		}
	fail:
		return;
	};
	void append_filter(seaudit_filter_t *filter) {
		if (seaudit_model_append_filter(self, filter)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append filter to model");
		}
	fail:
		return;
	};
	const apol_vector_t *get_filters() {
		return seaudit_model_get_filters(self);
	};
	%delobject remove_filter();
	void remove_filter(seaudit_filter_t *filter) {
		if (seaudit_model_remove_filter(self, filter)) {
			SWIG_exception(SWIG_ValueError, "Could not remove filter");
		}
	fail:
		return;
	};
	void set_filter_match(seaudit_filter_match_e match) {
		if (seaudit_model_set_filter_match(self, match)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter matching method for model");
		}
	fail:
		return;
	};
	seaudit_filter_match_e get_filter_match() {
		return seaudit_model_get_filter_match(self);
	};
	void set_filter_visible(seaudit_filter_visible_e vis) {
		if (seaudit_model_set_filter_visible(self, vis)) {
			SWIG_exception(SWIG_RuntimeError, "Could not set filter visibility for model");
		}
	fail:
		return;
	};
	seaudit_filter_visible_e get_filter_visible() {
		return seaudit_model_get_filter_visible(self);
	};
	void append_sort(seaudit_sort_t *ssort) {
		if (seaudit_model_append_sort(self, ssort)) {
			SWIG_exception(SWIG_RuntimeError, "Could not append sort to model");
		}
	fail:
		return;
	};
	void clear_sorts() {
		if (seaudit_model_clear_sorts(self)) {
			SWIG_exception(SWIG_RuntimeError, "Could not clear model sorting criteria");
		}
	fail:
		return;
	};
	int is_changed() {
		return seaudit_model_is_changed(self);
	};
	%newobject get_messages();
	apol_vector_t *get_messages(seaudit_log_t *slog) {
		apol_vector_t *v = seaudit_model_get_messages(slog, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return v;
	};
	%newobject get_malformed_messages();
	apol_vector_t *get_malformed_messages(seaudit_log_t *slog) {
		apol_vector_t *v = seaudit_model_get_malformed_messages(slog, self);
		if (!v) {
			SWIG_exception(SWIG_MemoryError, "Out of memory");
		}
	fail:
		return v;
	};
	size_t get_num_allows(seaudit_log_t *slog) {
		return seaudit_model_get_num_allows(slog, self);
	};
	size_t get_num_denies(seaudit_log_t *slog) {
		return seaudit_model_get_num_denies(slog, self);
	};
	size_t get_num_bools(seaudit_log_t *slog) {
		return seaudit_model_get_num_bools(slog, self);
	};
	size_t get_num_loads(seaudit_log_t *slog) {
		return seaudit_model_get_num_loads(slog, self);
	};
};

//TODO
//%include "../include/seaudit/filter.h"
%include "../include/seaudit/report.h"
%include "../include/seaudit/sort.h"
