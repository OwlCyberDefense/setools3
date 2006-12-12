/**
 *  @file seaudit_internal.h
 *  Protected interface seaudit library.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#ifndef SEAUDIT_SEAUDIT_INTERNAL_H
#define SEAUDIT_SEAUDIT_INTERNAL_H

#include <config.h>

#include <seaudit/avc_message.h>
#include <seaudit/bool_message.h>
#include <seaudit/filter.h>
#include <seaudit/load_message.h>
#include <seaudit/log.h>
#include <seaudit/message.h>
#include <seaudit/model.h>
#include <seaudit/sort.h>

#include <apol/bst.h>
#include <apol/vector.h>

#include <libxml/uri.h>

#define FILTER_FILE_FORMAT_VERSION "1.3"

/*************** master seaudit log object (defined in log.c) ***************/

struct seaudit_log
{
	/** vector of seaudit_message_t pointers */
	apol_vector_t *messages;
	/** vector of strings, corresponding to log messages that did
	 * not parse cleanly */
	apol_vector_t *malformed_msgs;
	/** vector of seaudit_model_t that are watching this log */
	apol_vector_t *models;
	apol_bst_t *types, *classes, *roles, *users;
	apol_bst_t *perms, *hosts, *bools;
	seaudit_log_type_e logtype;
	seaudit_handle_fn_t fn;
	void *handle_arg;
	/** non-zero if tzset() has been called */
	int tz_initialized;
	/** non-zero if the parser is in the middle of a line */
	int next_line;
};

/**
 * Notify a log that model is now watching it.
 *
 * @param log Log to append model.
 * @param model Model that is watching.
 *
 * @return 0 on success, < 0 on error.
 */
int log_append_model(seaudit_log_t * log, seaudit_model_t * model);

/**
 * Notify a log that model is no longer watching it.
 *
 * @param log Log to append model.
 * @param model Model that stopped watching.
 */
void log_remove_model(seaudit_log_t * log, seaudit_model_t * model);

/**
 * Get a vector of all messages from this seaudit log object.
 *
 * @param log Log object containing messages.
 *
 * @return Vector of seaudit_message_t pointers.  Do not free() or
 * otherwise modify this vector or its contents.
 */
apol_vector_t *log_get_messages(seaudit_log_t * log);

/**
 * Get a vector of all malformed messages from this seaudit log
 * object.  These are SELinux messages that did not parse cleanly for
 * some reason.  They will be returned in the same order in which they
 * were read from the log file.
 *
 * @param log Log object containing malformed messages.
 *
 * @return Vector of strings.  Do not free() or otherwise modify this
 * vector or its contents.
 */
apol_vector_t *log_get_malformed_messages(seaudit_log_t * log);

/*************** messages (defined in message.c) ***************/

struct seaudit_message
{
	/** when this message was generated */
	struct tm *date_stamp;
	/** pointer into log->host for the hostname that generated
	 * this message, or NULL if none found */
	char *host;
	/** type of message this really is */
	seaudit_message_type_e type;
	/** fake polymorphism by having a union of possible subclasses */
	union
	{
		seaudit_avc_message_t *avc;
		seaudit_bool_message_t *bool;
		seaudit_load_message_t *load;
	} data;
};

/**
 * Allocate a new seaudit message, append the message to the log, and
 * return the message.
 *
 * @param log Log to which append the message.
 * @param type Message type for the newly constructed message.
 *
 * @return A newly allocated message.  The caller must not free the
 * value.
 */
seaudit_message_t *message_create(seaudit_log_t * log, seaudit_message_type_e type);

/**
 * Deallocate all space associated with a message, recursing into the
 * message's data field.
 *
 * @param msg If not NULL, message to free.
 */
void message_free(void *msg);

/*************** avc messages (defined in avc_message.c) ***************/

typedef enum seaudit_avc_message_class
{
	SEAUDIT_AVC_DATA_INVALID = 0,
	SEAUDIT_AVC_DATA_MALFORMED,
	SEAUDIT_AVC_DATA_IPC,
	SEAUDIT_AVC_DATA_CAP,	       /* capability */
	SEAUDIT_AVC_DATA_FS,
	SEAUDIT_AVC_DATA_NET,
} seaudit_avc_message_class_e;

/**
 * Definition of an avc message.  Note that unless stated otherwise,
 * character pointers are into the message's log's respective BST.
 */
struct seaudit_avc_message
{
	seaudit_avc_message_type_e msg;
	seaudit_avc_message_class_e avc_type;
	/** executable and path - free() this */
	char *exe;
	/** command - free() this */
	char *comm;
	/** path of the OBJECT - free() this */
	char *path;
	/** device for the object - free() this */
	char *dev;
	/** network interface - free() this */
	char *netif;
	/** free() this */
	char *laddr;
	/** free() this */
	char *faddr;
	/** source address - free() this */
	char *saddr;
	/** destination address - free() this */
	char *daddr;
	/** free() this */
	char *name;
	/** free() this */
	char *ipaddr;
	/** source context's user */
	char *suser;
	/** source context's role */
	char *srole;
	/** source context's type */
	char *stype;
	/** target context's user */
	char *tuser;
	/** target context's role */
	char *trole;
	/** target context's type */
	char *ttype;
	/** target class */
	char *tclass;
	/** audit header timestamp (seconds) */
	time_t tm_stmp_sec;
	/** audit header timestamp (nanoseconds) */
	long tm_stmp_nano;
	/** audit header serial number */
	unsigned int serial;
	/** pointers into log->perms BST (hence char *) */
	apol_vector_t *perms;
	/** key for an IPC call */
	int key;
	int is_key;
	/** process capability (corresponds with class 'capability') */
	int capability;
	int is_capability;
	/** inode of the object */
	unsigned long inode;
	int is_inode;
	/** source port */
	int source;
	/** destination port */
	int dest;
	int lport;
	int fport;
	int port;
	/** source sid */
	unsigned int src_sid;
	int is_src_sid;
	/** target sid */
	unsigned int tgt_sid;
	int is_tgt_sid;
	/** process ID of the subject */
	unsigned int pid;
	int is_pid;
};

/**
 * Allocate and return a new seaudit AVC message.
 *
 * @return A newly allocated AVC message.  The caller must not call
 * avc_message_free() upon the returned value afterwards.
 */
seaudit_avc_message_t *avc_message_create(void);

/**
 * Deallocate all space associated with an AVC message.
 *
 * @param msg If not NULL, message to free.
 */
void avc_message_free(seaudit_avc_message_t * avc);

/**
 * Given an avc message, allocate and return a string that
 * approximates the message as it had appeared within the log file.
 *
 * @param avc Message whose string representation to get.
 * @param date Date and time when message was generated.
 * @param host Hostname that generated message.
 *
 * @return String representation for message, or NULL upon error.  The
 * caller is responsible for free()ing the string afterwards.
 */
char *avc_message_to_string(seaudit_avc_message_t * avc, const char *date, const char *host);

/**
 * Given an avc change message, allocate and return a string,
 * formatted in HTML, that approximates the message as it had appeared
 * within the log file.
 *
 * @param avc Message whose string representation to get.
 * @param date Date and time when message was generated.
 * @param host Hostname that generated message.
 *
 * @return String representation for message, or NULL upon error.  The
 * caller is responsible for free()ing the string afterwards.
 */
char *avc_message_to_string_html(seaudit_avc_message_t * avc, const char *date, const char *host);

/**
 * Given an avc change message, allocate and return a string that
 * gives miscellaneous info (e.g., ports, IP addresses).
 *
 * @param avc Message from which to get miscellaneous information.
 *
 * @return Miscellaneous message string representation, or NULL upon
 * error.  The caller is responsible for free()ing the string
 * afterwards.
 */
char *avc_message_to_misc_string(seaudit_avc_message_t * avc);

/*************** bool messages (defined in bool_message.c) ***************/

typedef struct seaudit_bool_message_change
{
	/** pointer into log's bools BST */
	char *bool;
	/** new value for the boolean */
	int value;
} seaudit_bool_message_change_t;

struct seaudit_bool_message
{
	/** vector of seaudit_bool_change_t pointers; vector owns objects. */
	apol_vector_t *changes;
};

/**
 * Allocate and return a new seaudit boolean change message.
 *
 * @return A newly allocated boolean change message.  The caller must
 * not call bool_message_free() upon the returned value afterwards.
 */
seaudit_bool_message_t *bool_message_create(void);

/**
 * Append a boolean change to a particular boolean message.  This will
 * add the boolean name to the log's BST as needed.
 *
 * @param log Log containing boolean name BST.
 * @param bool Boolean message to change.
 * @param name Name of the boolean that was changed.  This function
 * will dup the incoming name.
 * @param value New value for the boolean.
 *
 * @return 0 on success, < 0 on error.
 */
int bool_change_append(seaudit_log_t * log, seaudit_bool_message_t * bool, char *name, int value);

/**
 * Deallocate all space associated with a boolean change message.
 *
 * @param msg If not NULL, message to free.
 */
void bool_message_free(seaudit_bool_message_t * bool);

/**
 * Given a boolean change message, allocate and return a string that
 * approximates the message as it had appeared within the log file.
 *
 * @param bool Message whose string representation to get.
 * @param date Date and time when message was generated.
 * @param host Hostname that generated message.
 *
 * @return String representation for message, or NULL upon error.  The
 * caller is responsible for free()ing the string afterwards.
 */
char *bool_message_to_string(seaudit_bool_message_t * bool, const char *date, const char *host);

/**
 * Given a boolean change message, allocate and return a string,
 * formatted in HTML, that approximates the message as it had appeared
 * within the log file.
 *
 * @param bool Message whose string representation to get.
 * @param date Date and time when message was generated.
 * @param host Hostname that generated message.
 *
 * @return String representation for message, or NULL upon error.  The
 * caller is responsible for free()ing the string afterwards.
 */
char *bool_message_to_string_html(seaudit_bool_message_t * bool, const char *date, const char *host);

/**
 * Given a boolean change message, allocate and return a string that
 * gives miscellaneous info (i.e., list of boolean names and their new
 * values.)
 *
 * @param bool Message from which to get miscellaneous information.
 *
 * @return Miscellaneous message string representation, or NULL upon
 * error.  The caller is responsible for free()ing the string
 * afterwards.
 */
char *bool_message_to_misc_string(seaudit_bool_message_t * bool);

/*************** load messages (defined in load_message.c) ***************/

struct seaudit_load_message
{
	unsigned int users;	       /* number of users */
	unsigned int roles;	       /* number of roles */
	unsigned int types;	       /* number of types */
	unsigned int classes;	       /* number of classes */
	unsigned int rules;	       /* number of rules */
	unsigned int bools;	       /* number of bools */
	char *binary;		       /* path for binary that was loaded */
};

/**
 * Allocate and return a new seaudit policy load message.
 *
 * @return A newly allocated policy load message.  The caller must
 * not call load_message_free() upon the returned value afterwards.
 */
seaudit_load_message_t *load_message_create(void);

/**
 * Deallocate all space associated with a policy load message.
 *
 * @param msg If not NULL, message to free.
 */
void load_message_free(seaudit_load_message_t * msg);

/**
 * Given a load message, allocate and return a string that
 * approximates the message as it had appeared within the log file.
 *
 * @param load Message whose string representation to get.
 * @param date Date and time when message was generated.
 * @param host Hostname that generated message.
 *
 * @return String representation for message, or NULL upon error.  The
 * caller is responsible for free()ing the string afterwards.
 */
char *load_message_to_string(seaudit_load_message_t * load, const char *date, const char *host);

/**
 * Given a load message, allocate and return a string, formatted in
 * HTML, that approximates the message as it had appeared within the
 * log file.
 *
 * @param load Message whose string representation to get.
 * @param date Date and time when message was generated.
 * @param host Hostname that generated message.
 *
 * @return String representation for message, or NULL upon error.  The
 * caller is responsible for free()ing the string afterwards.
 */
char *load_message_to_string_html(seaudit_load_message_t * load, const char *date, const char *host);

/**
 * Given a load message, allocate and return a string that gives
 * miscellaneous info (e.g., number of types in the new policy).
 *
 * @param load Message from which to get miscellaneous information.
 *
 * @return Miscellaneous message string representation, or NULL upon
 * error.  The caller is responsible for free()ing the string
 * afterwards.
 */
char *load_message_to_misc_string(seaudit_load_message_t * load);

/*************** model functions (defined in model.h) ***************/

/**
 * Notify a model to stop watching a log.
 *
 * @param model Model to notify.
 * @param log Log to stop watching.
 */
void model_remove_log(seaudit_model_t * model, seaudit_log_t * log);

/**
 * Notify a model that a log has been changed; the model will need to
 * recalculate its messages.
 *
 * @param model Model to notify.
 * @param log Log that has been changed.
 */
void model_notify_log_changed(seaudit_model_t * model, seaudit_log_t * log);

/**
 * Notify a model that a filter has been changed; the model will need
 * to recalculate its messages.
 *
 * @param model Model to notify.
 * @param filter Filter that has been changed.
 */
void model_notify_filter_changed(seaudit_model_t * model, seaudit_filter_t * filter);

/*************** filter functions (defined in filter.c) ***************/

typedef int (filter_read_func) (seaudit_filter_t * filter, const xmlChar * ch);

struct filter_parse_state
{
    /** vector of filters created, appended to by <filter> tags;
        caller must destroy this */
	apol_vector_t *filters;
    /** string from name attribute in a <view> tag; caller must free()
        this */
	char *view_name;
    /** value from match attribute in a <view> tag */
	seaudit_filter_match_e view_match;
    /** value form show attribute in a <view> tag */
	seaudit_filter_visible_e view_visible;

    /****
        The following are to be considered private data and may only
        be used by filter.c.
    ****/
    /** the most recently read string that was not part of a tag */
	xmlChar *cur_string;
	int warnings;
    /** filter currently being parsed, set by most recent <filter> tag */
	seaudit_filter_t *cur_filter;
    /** pointer to a filter parsing function, set by <criteria> tag */
	filter_read_func *cur_filter_read;
};

/**
 * Link a model to a filter.  Whenever the filter changes, it should
 * call model_notify_filter_changed(); that way the model will
 * recalculate itself.
 *
 * @param filter Filter to be watched.
 * @param model Model that is watching.
 */
void filter_set_model(seaudit_filter_t * filter, seaudit_model_t * model);

/**
 * Given a filter and a message, return non-zero if the msg is
 * accepted by the filter according to the filter's criteria.  If the
 * filter does not have enough information to decide (because the
 * message is incomplete) then this should return 0.
 *
 * @param filter Filter to apply.
 * @param msg Message to check.
 *
 * @return Non-zero if message is accepted, 0 if not.
 */
int filter_is_accepted(seaudit_filter_t * filter, const seaudit_message_t * msg);

/**
 * Parse the given XML file and fill in the passed in struct.  The
 * caller must create the struct and the vector within.  Upon return,
 * the caller must destroy the vector and free view_name.
 *
 * @param state An initialized state struct for parsing.
 * @param filename Name of XML file to parse.
 *
 * @return 0 on success, > 0 if parse warnings, < 0 on error.
 */
int filter_parse_xml(struct filter_parse_state *state, const char *filename);

/**
 * Append the given filter's values, in XML format, to a file handler.
 * This includes the filter's name and criteria.
 *
 * @param filter Filter to save.
 * @param file File to which write.
 *
 * @see seaudit_filter_create_from_file()
 */
void filter_append_to_file(seaudit_filter_t * filter, FILE * file, int tabs);

/*************** sort functions (defined in sort.c) ***************/

/**
 * Create and return a new sort object, initialized with the data from
 * an existing sort object.  The new sort object will not be attached
 * to any models.
 *
 * @param sort Sort object to clone.
 *
 * @return A cloned sort object, or NULL upon error.  The caller is
 * responsible for calling seaudit_sort_destroy() afterwards.
 */
seaudit_sort_t *sort_create_from_sort(const seaudit_sort_t * sort);

/**
 * Create and return a new sort object based upon the name of the sort
 * (as returned by sort_get_name()).  The new sort object will not be
 * attached to any models.
 *
 * @param name Name of the type of sort to create.
 * @param direction Direction to sort, non-negative for ascending,
 * negative for descending.
 *
 * @return A new sort object, or NULL upon error.  The caller is
 * responsible for calling seaudit_sort_destroy() afterwards.
 */
seaudit_sort_t *sort_create_from_name(const char *name, int direction);

/**
 * Given a sort object and a message, return non-zero if this sort
 * object could operate on the message, 0 if not.  (Messages may have
 * incomplete information due to parser warnings.)
 *
 * @param sort Sort object to query.
 * @param msg Message to check.
 *
 * @return Non-zero if sort supports the message, 0 if not.
 */
int sort_is_supported(seaudit_sort_t * sort, const seaudit_message_t * msg);

/**
 * Invoke a sort object's comparison function.
 *
 * @param sort Sort object that contains a comparator.
 * @param m1 First message to compare.
 * @param m2 Second message to compare.
 *
 * @return 0 if the messages are equivalent, < 0 if a is first, > 0 if
 * b is first.
 */
int sort_comp(seaudit_sort_t * sort, const seaudit_message_t * a, const seaudit_message_t * b);

/**
 * Return the type of sort this sort object is.  The name is valid for
 * sort_create_from_name()'s first parameter.
 *
 * @param sort Sort object to query.
 *
 * @return Type of sort this object is.
 */
const char *sort_get_name(seaudit_sort_t * sort);

/**
 * Return the sort direction for a sort object.
 *
 * @param sort Sort object to query.
 *
 * @return Non-negative for ascending, negative for descending.
 */
int sort_get_direction(seaudit_sort_t * sort);

/*************** error handling code (defined in log.c) ***************/

#define SEAUDIT_MSG_ERR  1
#define SEAUDIT_MSG_WARN 2
#define SEAUDIT_MSG_INFO 3

/**
 * Write a message to the callback stored within a seaudit_log_t
 * handler.  If the msg_callback field is empty then suppress the
 * message.
 *
 * @param log Error reporting handler.  If NULL then write message to
 * stderr.
 * @param level Severity of message, one of SEAUDIT_MSG_ERR,
 * SEAUDIT_MSG_WARN, or SEAUDIT_MSG_INFO.
 * @param fmt Format string to print, using syntax of printf(3).
 */
extern void seaudit_handle_msg(seaudit_log_t * log, int level, const char *fmt, ...);

__attribute__ ((format(printf, 3, 4)))
extern void seaudit_handle_msg(seaudit_log_t * log, int level, const char *fmt, ...);

#undef ERR
#undef WARN
#undef INFO

#define ERR(handle, format, ...) seaudit_handle_msg(handle, SEAUDIT_MSG_ERR, format, __VA_ARGS__)
#define WARN(handle, format, ...) seaudit_handle_msg(handle, SEAUDIT_MSG_WARN, format, __VA_ARGS__)
#define INFO(handle, format, ...) seaudit_handle_msg(handle, SEAUDIT_MSG_INFO, format, __VA_ARGS__)

#endif
