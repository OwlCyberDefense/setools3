/**
 *  @file
 *  Implementation for the audit log parser.
 *
 *  @author Meggan Whalen mwhalen@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "seaudit_internal.h"
#include <seaudit/parse.h>
#include <apol/util.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ALT_SYSCALL_STRING "msg=audit("	/* should contain SYSCALL_STRING */
#define AUDITD_MSG "type="
#define AVCMSG " avc: "
#define BOOLMSG "committed booleans"
#define LOADMSG " security: "
#define NUM_TIME_COMPONENTS 3
#define OLD_LOAD_POLICY_STRING "loadingpolicyconfigurationfrom"
#define PARSE_NUM_CONTEXT_FIELDS 3
#define PARSE_NUM_SYSCALL_FIELDS 3
#define SYSCALL_STRING "audit("

/**
 * Given a line from an audit log, create and return a vector of
 * tokens from that line.  The caller is responsible for calling
 * apol_vector_destroy() upon that vector.  Note that this function
 * will modify the passed in line.
 */
static int get_tokens(seaudit_log_t * log, char *line, apol_vector_t ** tokens)
{
	char *line_ptr, *next;
	*tokens = NULL;
	int error = 0;

	if ((*tokens = apol_vector_create(NULL)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	line_ptr = line;
	/* Tokenize line while ignoring any adjacent whitespace chars. */
	while ((next = strsep(&line_ptr, " ")) != NULL) {
		if (strcmp(next, "") && !apol_str_is_only_white_space(next)) {
			if (apol_vector_append(*tokens, next) < 0) {
				error = errno;
				ERR(log, "%s", strerror(error));
				goto cleanup;
			}
		}
	}
      cleanup:
	if (error != 0) {
		apol_vector_destroy(tokens);
		errno = error;
		return -1;
	}
	return 0;
}

/**
 * Given a line, determine what type of audit message it is.
 */
static seaudit_message_type_e is_selinux(char *line)
{
	if (strstr(line, BOOLMSG) && (strstr(line, "kernel") || strstr(line, AUDITD_MSG)))
		return SEAUDIT_MESSAGE_TYPE_BOOL;
	else if (strstr(line, LOADMSG) && (strstr(line, "kernel") || strstr(line, AUDITD_MSG)))
		return SEAUDIT_MESSAGE_TYPE_LOAD;
	else if (strstr(line, AVCMSG) && (strstr(line, "kernel") || strstr(line, AUDITD_MSG)))
		return SEAUDIT_MESSAGE_TYPE_AVC;
	else
		return SEAUDIT_MESSAGE_TYPE_INVALID;
}

/**
 * Fill in the date_stamp field of a message.  If the stamp was not
 * already allocated space then do it here.
 *
 * @return 0 on success, > 0 on warning, < 0 on error.
 */
static int insert_time(seaudit_log_t * log, apol_vector_t * tokens, size_t * position, seaudit_message_t * msg)
{
	char *t = NULL;
	size_t i, length = 0;
	int error;
	extern int daylight;

	if (*position + NUM_TIME_COMPONENTS >= apol_vector_get_size(tokens)) {
		WARN(log, "%s", "Not enough tokens for time.");
		return 1;
	}
	for (i = 0; i < NUM_TIME_COMPONENTS; i++) {
		length += strlen((char *)apol_vector_get_element(tokens, i + *position));
	}

	/* Increase size for terminating string char and whitespace within. */
	length += NUM_TIME_COMPONENTS;
	if ((t = (char *)calloc(1, length)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}

	for (i = 0; i < NUM_TIME_COMPONENTS; i++) {
		if (i > 0) {
			strcat(t, " ");
		}
		strcat(t, (char *)apol_vector_get_element(tokens, *position));
		(*position)++;
	}

	if (!msg->date_stamp) {
		if ((msg->date_stamp = (struct tm *)calloc(1, sizeof(struct tm))) == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			free(t);
			errno = error;
			return -1;
		}
	}

	if (strptime(t, "%b %d %T", msg->date_stamp) != NULL) {
		/* set year to 1900 since we know no valid logs were
		 * generated.  this will tell us that the msg does not
		 * really have a year */
		msg->date_stamp->tm_isdst = 0;
		msg->date_stamp->tm_year = 0;
	}
	free(t);
	return 0;
}

/**
 * Fill in the host field of a message.
 *
 * @return 0 on success, > 0 on warning, < 0 on error.
 */
static int insert_hostname(seaudit_log_t * log, apol_vector_t * tokens, size_t * position, seaudit_message_t * msg)
{
	char *s, *host;
	if (*position >= apol_vector_get_size(tokens)) {
		WARN(log, "%s", "Not enough tokens for hostname.");
		return 1;
	}
	s = apol_vector_get_element(tokens, *position);
	/* Make sure this is not the kernel string identifier, which
	 * may indicate that the hostname is empty. */
	if (strstr(s, "kernel")) {
		msg->host = NULL;
		return 1;
	}
	(*position)++;
	if ((host = strdup(s)) == NULL || apol_bst_insert_and_get(log->hosts, (void **)&host, NULL) < 0) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	msg->host = host;
	return 0;
}

static int insert_standard_msg_header(seaudit_log_t * log, apol_vector_t * tokens, size_t * position, seaudit_message_t * msg)
{
	int ret = 0;
	if ((ret = insert_time(log, tokens, position, msg)) != 0) {
		return ret;
	}
	if ((ret = insert_hostname(log, tokens, position, msg)) != 0) {
		return ret;
	}
	return ret;
}

/**
 * Parse the object manager that generated this audit message.
 */
static int insert_manager(seaudit_log_t * log, seaudit_message_t * msg, const char *manager)
{
	char *m;
	if ((m = strdup(manager)) == NULL || apol_bst_insert_and_get(log->managers, (void **)&m, NULL) < 0) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	msg->manager = m;
	return 0;
}

/**
 * Parse a context (user:role:type).  For each of the pieces, add them
 * to the log's BSTs.  Set reference pointers to those strings.
 */
static int parse_context(seaudit_log_t * log, char *token, char **user, char **role, char **type)
{
	size_t i = 0;
	char *fields[PARSE_NUM_CONTEXT_FIELDS], *s;
	int error;

	*user = *role = *type = NULL;
	while (i < PARSE_NUM_CONTEXT_FIELDS && (fields[i] = strsep(&token, ":")) != NULL) {
		i++;
	}
	if (i != PARSE_NUM_CONTEXT_FIELDS) {
		WARN(log, "%s", "Not enough tokens for context.");
		return 1;
	}

	if ((s = strdup(fields[0])) == NULL || apol_bst_insert_and_get(log->users, (void **)&s, NULL) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	*user = s;

	if ((s = strdup(fields[1])) == NULL || apol_bst_insert_and_get(log->roles, (void **)&s, NULL) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	*role = s;

	if ((s = strdup(fields[2])) == NULL || apol_bst_insert_and_get(log->types, (void **)&s, NULL) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	*type = s;

	return 0;
}

/******************** AVC message parsing ********************/

/**
 * Given a token, determine if it is the new AVC header or not.
 */
static int avc_msg_is_token_new_audit_header(char *token)
{
	return (strstr(token, SYSCALL_STRING) ? 1 : 0);
}

/**
 * If the given token begins with prefix, then set reference pointer
 * result to everything following prefix and return 1.  Otherwise
 * return 0.
 */
static int avc_msg_is_prefix(char *token, char *prefix, char **result)
{
	size_t i = 0, length;

	length = strlen(prefix);
	if (strlen(token) < length)
		return 0;

	for (i = 0; i < length; i++) {
		if (token[i] != prefix[i]) {
			return 0;
		}
	}

	*result = token + length;
	return 1;
}

/**
 * Beginning with element *position, fill in the given avc message
 * with all permissions found.  Afterwards update *position to point
 * to the next unprocessed token.  Permissions should start and end
 * with braces and if not, then this is invalid.
 *
 * @return 0 on success, > 0 on warning, < 0 on error.
 */
static int avc_msg_insert_perms(seaudit_log_t * log, apol_vector_t * tokens, size_t * position, seaudit_avc_message_t * avc)
{
	char *s, *perm;
	int error;
	if ((s = apol_vector_get_element(tokens, *position)) == NULL || strcmp(s, "{") != 0) {
		WARN(log, "%s", "Expected an opening brace while parsing permissions.");
		return 1;
	}
	(*position)++;

	while (*position < apol_vector_get_size(tokens)) {
		s = apol_vector_get_element(tokens, *position);
		assert(s != NULL);
		(*position)++;
		if (strcmp(s, "}") == 0) {
			return 0;
		}

		if ((perm = strdup(s)) == NULL ||
		    apol_bst_insert_and_get(log->perms, (void **)&perm, NULL) < 0 || apol_vector_append(avc->perms, perm) < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}

	/* if got here, then message is too short */
	WARN(log, "%s", "Expected a closing brace while parsing permissions.");
	return 1;
}

static int avc_msg_insert_syscall_info(seaudit_log_t * log, char *token, seaudit_message_t * msg, seaudit_avc_message_t * avc)
{
	size_t length, header_len = 0, i = 0;
	char *fields[PARSE_NUM_SYSCALL_FIELDS];
	char *time_str = NULL;
	time_t temp;

	length = strlen(token);

	/* Chop off the ':' at the end of the syscall info token */
	if (token[length - 1] == ':') {
		token[length - 1] = '\0';
		length--;
	}
	/* Chop off the ')' at the end of the syscall info token */
	if (token[length - 1] == ')') {
		token[length - 1] = '\0';
		length--;
	}
	header_len = strlen(SYSCALL_STRING);

	/* Check to see if variations on syscall header exist */
	if (strstr(token, ALT_SYSCALL_STRING)) {
		header_len = strlen(ALT_SYSCALL_STRING);
	}

	time_str = token + header_len;
	/* Parse seconds.nanoseconds:serial */
	while (i < PARSE_NUM_SYSCALL_FIELDS && (fields[i] = strsep(&time_str, ".:")) != NULL) {
		i++;
	}

	if (i != PARSE_NUM_SYSCALL_FIELDS) {
		WARN(log, "%s", "Not enough fields for syscall info.");
		return 1;
	}

	temp = (time_t) atol(fields[0]);
	avc->tm_stmp_sec = temp;
	avc->tm_stmp_nano = atoi(fields[1]);
	avc->serial = atoi(fields[2]);

	if (msg->date_stamp == NULL) {
		if ((msg->date_stamp = (struct tm *)malloc(sizeof(struct tm))) == NULL) {
			int error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}
	localtime_r(&temp, msg->date_stamp);
	return 0;
}

static int avc_msg_insert_access_type(seaudit_log_t * log, char *token, seaudit_avc_message_t * avc)
{
	if (strcmp(token, "granted") == 0) {
		avc->msg = SEAUDIT_AVC_GRANTED;
		return 0;
	} else if (strcmp(token, "denied") == 0) {
		avc->msg = SEAUDIT_AVC_DENIED;
		return 0;
	}
	WARN(log, "%s", "No AVC message type found, assuming it was a denial.");
	avc->msg = SEAUDIT_AVC_DENIED;
	return 1;
}

static int avc_msg_insert_scon(seaudit_log_t * log, seaudit_avc_message_t * avc, char *tmp)
{
	char *user, *role, *type;
	int retval;
	if (tmp == NULL) {
		WARN(log, "%s", "Invalid source context.");
		return 1;
	}
	retval = parse_context(log, tmp, &user, &role, &type);
	if (retval != 0) {
		return retval;
	}
	avc->suser = user;
	avc->srole = role;
	avc->stype = type;
	return 0;
}

static int avc_msg_insert_tcon(seaudit_log_t * log, seaudit_avc_message_t * avc, char *tmp)
{
	char *user, *role, *type;
	int retval;
	if (tmp == NULL) {
		WARN(log, "%s", "Invalid target context.");
		return 1;
	}
	retval = parse_context(log, tmp, &user, &role, &type);
	if (retval != 0) {
		return retval;
	}
	avc->tuser = user;
	avc->trole = role;
	avc->ttype = type;
	return 0;
}

static int avc_msg_insert_tclass(seaudit_log_t * log, seaudit_avc_message_t * avc, char *tmp)
{
	char *tclass;
	if ((tclass = strdup(tmp)) == NULL || apol_bst_insert_and_get(log->classes, (void **)&tclass, NULL) < 0) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	avc->tclass = tclass;
	return 0;
}

static int avc_msg_insert_string(seaudit_log_t * log, char *src, char **dest)
{
	if ((*dest = strdup(src)) == NULL) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	return 0;
}

/**
 * Removes quotes from a string, this is currently to remove quotes
 * from the command argument.
 */
static int avc_msg_remove_quotes_insert_string(seaudit_log_t * log, char *src, char **dest)
{
	size_t i, j, l;

	l = strlen(src);
	/* see if there are any quotes to begin with if there aren't
	 * just run insert string */
	if (src[0] == '\"' && l > 0 && src[l - 1] == '\"') {
		if ((*dest = calloc(1, l + 1)) == NULL) {
			int error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
		for (i = 0, j = 0; i < l; i++) {
			if (src[i] != '\"') {
				(*dest)[j] = src[i];
				j++;
			}
		}
		return 0;
	} else
		return avc_msg_insert_string(log, src, dest);
}

/**
 * If there is exactly one equal sign in orig_token then return 1.
 * Otherwise return 0.
 */
static int avc_msg_is_valid_additional_field(char *orig_token)
{
	char *first_eq = strchr(orig_token, '=');

	if (first_eq == NULL) {
		return 0;
	}
	if (strchr(first_eq + 1, '=') != NULL) {
		return 0;
	}
	return 1;
}

static int avc_msg_reformat_path(seaudit_log_t * log, seaudit_avc_message_t * avc, char *token)
{
	int error;
	if (avc->path == NULL) {
		if ((avc->path = strdup(token)) == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
	} else {
		size_t len = strlen(avc->path) + strlen(token) + 2;
		char *s = realloc(avc->path, len);
		if (s == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
		avc->path = s;
		strcat(avc->path, " ");
		strcat(avc->path, token);
	}
	return 0;
}

/**
 * Parse the remaining tokens of an AVC message, filling as much
 * information as possible.
 *
 * @return 0 on success, > 0 if warnings, < 0 on error
 */
static int avc_msg_insert_additional_field_data(seaudit_log_t * log, apol_vector_t * tokens, seaudit_avc_message_t * avc,
						size_t * position)
{
	char *token, *v;
	int retval, has_warnings = 0;

	avc->avc_type = SEAUDIT_AVC_DATA_FS;
	for (; (*position) < apol_vector_get_size(tokens); (*position)++) {
		token = apol_vector_get_element(tokens, (*position));
		v = NULL;
		if (strcmp(token, "") == 0) {
			break;
		}

		if (!avc->is_pid && avc_msg_is_prefix(token, "pid=", &v)) {
			avc->pid = atoi(v);
			avc->is_pid = 1;
			continue;
		}

		if (!avc->exe && avc_msg_is_prefix(token, "exe=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->exe) < 0) {
				return -1;
			}
			continue;
		}

		if (!avc->comm && avc_msg_is_prefix(token, "comm=", &v)) {
			if (avc_msg_remove_quotes_insert_string(log, v, &avc->comm) < 0) {
				return -1;
			}
			continue;
		}

		/* Gather all tokens located after the path=XXXX token
		 * until we encounter a valid additional field.  This
		 * is because a path name file name may be seperated
		 * by whitespace.  Look ahead at the next token, but we
		 * make sure not to access memory beyond the total
		 * number of tokens. */
		if (!avc->path && avc_msg_is_prefix(token, "path=", &v)) {
			if (avc_msg_reformat_path(log, avc, v) < 0) {
				return -1;
			}
			while (*position + 1 < apol_vector_get_size(tokens)) {
				token = apol_vector_get_element(tokens, *position + 1);
				if (avc_msg_is_valid_additional_field(token)) {
					break;
				}
				(*position)++;
				if (avc_msg_reformat_path(log, avc, token) < 0) {
					return -1;
				}
			}
			continue;
		}

		if (!avc->name && avc_msg_is_prefix(token, "name=", &v)) {
			if (avc_msg_remove_quotes_insert_string(log, v, &avc->name) < 0) {
				return -1;
			}
			continue;
		}

		if (!avc->dev && avc_msg_is_prefix(token, "dev=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->dev) < 0) {
				return -1;
			}
			continue;
		}

		if (!avc->saddr && avc_msg_is_prefix(token, "saddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->saddr) < 0) {
				return -1;
			}
			continue;
		}

		if (!avc->source && (avc_msg_is_prefix(token, "source=", &v) || avc_msg_is_prefix(token, "src=", &v))) {
			avc->source = atoi(v);
			continue;
		}

		if (!avc->daddr && avc_msg_is_prefix(token, "daddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->daddr)) {
				return -1;
			}
			continue;
		}

		if (!avc->dest && avc_msg_is_prefix(token, "dest=", &v)) {
			avc->dest = atoi(v);
			continue;
		}

		if (!avc->netif && avc_msg_is_prefix(token, "netif=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->netif)) {
				return -1;
			}
			avc->avc_type = SEAUDIT_AVC_DATA_NET;
			continue;
		}

		if (!avc->laddr && avc_msg_is_prefix(token, "laddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->laddr)) {
				return -1;
			}
			continue;
		}

		if (!avc->lport && avc_msg_is_prefix(token, "lport=", &v)) {
			avc->lport = atoi(v);
			avc->avc_type = SEAUDIT_AVC_DATA_NET;
			continue;
		}

		if (!avc->faddr && avc_msg_is_prefix(token, "faddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->faddr)) {
				return -1;
			}
			continue;
		}

		if (!avc->fport && avc_msg_is_prefix(token, "fport=", &v)) {
			avc->fport = atoi(v);
			continue;
		}

		if (!avc->port && avc_msg_is_prefix(token, "port=", &v)) {
			avc->port = atoi(v);
			avc->avc_type = SEAUDIT_AVC_DATA_NET;
			continue;
		}

		if (!avc->is_src_sid && avc_msg_is_prefix(token, "ssid=", &v)) {
			avc->src_sid = (unsigned int)strtoul(v, NULL, 10);
			avc->is_src_sid = 1;
			continue;
		}

		if (!avc->is_tgt_sid && avc_msg_is_prefix(token, "tsid=", &v)) {
			avc->tgt_sid = (unsigned int)strtoul(v, NULL, 10);
			avc->is_tgt_sid = 1;
			continue;
		}

		if (!avc->is_capability && avc_msg_is_prefix(token, "capability=", &v)) {
			avc->capability = atoi(v);
			avc->is_capability = 1;
			avc->avc_type = SEAUDIT_AVC_DATA_CAP;
			continue;
		}

		if (!avc->is_key && avc_msg_is_prefix(token, "key=", &v)) {
			avc->key = atoi(v);
			avc->is_key = 1;
			avc->avc_type = SEAUDIT_AVC_DATA_IPC;
			continue;
		}

		if (!avc->is_inode && avc_msg_is_prefix(token, "ino=", &v)) {
			avc->inode = strtoul(v, NULL, 10);
			avc->is_inode = 1;
			continue;
		}

		if (!avc->ipaddr && avc_msg_is_prefix(token, "ipaddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->ipaddr)) {
				return -1;
			}
			continue;
		}

		if (!avc->suser && avc_msg_is_prefix(token, "scontext=", &v)) {
			retval = avc_msg_insert_scon(log, avc, v);
			if (retval < 0) {
				return retval;
			} else if (retval > 0) {
				has_warnings = 1;
			}
			continue;
		}

		if (!avc->tuser && avc_msg_is_prefix(token, "tcontext=", &v)) {
			retval = avc_msg_insert_tcon(log, avc, v);
			if (retval < 0) {
				return retval;
			} else if (retval > 0) {
				has_warnings = 1;
			}
			continue;
		}

		if (!avc->tclass && avc_msg_is_prefix(token, "tclass=", &v)) {
			if (avc_msg_insert_tclass(log, avc, v) < 0) {
				return -1;
			}
			continue;
		}
		/* found a field that this parser did not understand,
		 * so flag the entire message as a warning */
		has_warnings = 1;
	}

	/* can't have both a sid and a context */
	if ((avc->is_src_sid && avc->suser) || (avc->is_tgt_sid && avc->tuser)) {
		has_warnings = 1;
	}

	if (!avc->tclass) {
		has_warnings = 1;
	}

	if (has_warnings) {
		avc->avc_type = SEAUDIT_AVC_DATA_MALFORMED;
	}

	return has_warnings;
}

static int avc_parse(seaudit_log_t * log, apol_vector_t * tokens)
{
	seaudit_message_t *msg;
	seaudit_avc_message_t *avc;
	seaudit_message_type_e type;
	int ret, has_warnings = 0;
	size_t position = 0, num_tokens = apol_vector_get_size(tokens);
	char *token, *t;

	if ((msg = message_create(log, SEAUDIT_MESSAGE_TYPE_AVC)) == NULL) {
		return -1;
	}
	avc = seaudit_message_get_data(msg, &type);

	token = apol_vector_get_element(tokens, position);

	/* Check for new auditd log format */
	if (strstr(token, AUDITD_MSG)) {
		position++;
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for audit header.");
			return 1;
		}
		log->logtype = SEAUDIT_LOG_TYPE_AUDITD;
		token = apol_vector_get_element(tokens, position);
	}

	/* Insert the audit header if it exists */
	if (avc_msg_is_token_new_audit_header(token)) {
		ret = avc_msg_insert_syscall_info(log, token, msg, avc);
		if (ret < 0) {
			return ret;
		} else if (ret > 0) {
			has_warnings = 1;
		} else {
			position++;
			if (position >= num_tokens) {
				WARN(log, "%s", "Not enough tokens for new audit header.");
				return 1;
			}
			token = apol_vector_get_element(tokens, position);
		}
	} else {
		ret = insert_standard_msg_header(log, tokens, &position, msg);
		if (ret < 0) {
			return ret;
		} else if (ret > 0) {
			has_warnings = 1;
		}
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for new audit header.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);

		/* for now, only let avc messages set their object
		 * manager */
		if ((t = strrchr(token, ':')) == NULL) {
			WARN(log, "%s", "Expeceted to find an object manager here.");
			has_warnings = 1;
			/* Hold the position */
		} else {
			*t = '\0';
			if ((ret = insert_manager(log, msg, token)) < 0) {
				return ret;
			}
			position++;
			if (position >= num_tokens) {
				WARN(log, "%s", "Not enough tokens for new audit header.");
				return 1;
			}
			token = apol_vector_get_element(tokens, position);
		}

		/* new style audit messages can show up in syslog
		 * files starting with FC5. This means that both the
		 * old kernel: header and the new audit header might
		 * be present. So, here we check again for the audit
		 * message.
		 */
		if (avc_msg_is_token_new_audit_header(token)) {
			ret = avc_msg_insert_syscall_info(log, token, msg, avc);
			if (ret < 0) {
				return ret;
			} else if (ret > 0) {
				has_warnings = 1;
			} else {
				position++;
				if (position >= num_tokens) {
					WARN(log, "%s", "Not enough tokens for new audit header.");
					return 1;
				}
				token = apol_vector_get_element(tokens, position);
			}
		}
	}

	/* Make sure the following token is the string "avc:" */
	if (strcmp(token, "avc:") != 0) {
		/* Hold the position */
		has_warnings = 1;
		WARN(log, "%s", "Expected an avc: token here.");
	} else {
		position++;
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for new audit header.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);
	}

	/* Insert denied or granted */
	if (avc_msg_insert_access_type(log, token, avc)) {
		has_warnings = 1;
	} else {
		position++;
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for new audit header.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);
	}

	/* Insert perm(s) */
	ret = avc_msg_insert_perms(log, tokens, &position, avc);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		has_warnings = 1;
	}
	if (position >= num_tokens) {
		WARN(log, "%s", "Message appears to be truncated.");
		return 1;
	}
	token = apol_vector_get_element(tokens, position);

	if (strcmp(token, "for") != 0) {
		/* Hold the position */
		has_warnings = 1;
		WARN(log, "%s", "Expected a 'for' token here.");
	} else {
		position++;
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for new audit header.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);
	}

	/* At this point we have a valid message, for we have gathered
	 * all of the standard fields so insert anything else.  If
	 * nothing else is left, the message is still considered
	 * valid. */
	ret = avc_msg_insert_additional_field_data(log, tokens, avc, &position);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		has_warnings = 1;
	}

	return has_warnings;
}

/******************** boolean parsing ********************/

static int boolean_msg_insert_bool(seaudit_log_t * log, seaudit_bool_message_t * bool, char *token)
{
	size_t len = strlen(token);
	int value;

	/* Strip off ending comma */
	if (token[len - 1] == ',') {
		token[len - 1] = '\0';
		len--;
	}

	if (token[len - 2] != ':') {
		WARN(log, "%s", "Boolean change was not in correct format.");
		return 1;
	}

	if (token[len - 1] == '0')
		value = 0;
	else if (token[len - 1] == '1')
		value = 1;
	else {
		WARN(log, "%s", "Invalid new boolean value.");
		return 1;
	}

	token[len - 2] = '\0';

	return bool_change_append(log, bool, token, value);
}

static int bool_parse(seaudit_log_t * log, apol_vector_t * tokens)
{
	seaudit_message_t *msg;
	seaudit_bool_message_t *bool;
	seaudit_message_type_e type;
	int ret, has_warnings = 0, next_line = log->next_line;
	size_t position = 0, num_tokens = apol_vector_get_size(tokens);
	char *token;

	if (log->next_line) {
		/* still processing a boolean change message, so don't
		 * create a new one */
		size_t num_messages = apol_vector_get_size(log->messages);
		assert(num_messages > 0);
		msg = apol_vector_get_element(log->messages, num_messages - 1);
		log->next_line = 0;
	} else {
		if ((msg = message_create(log, SEAUDIT_MESSAGE_TYPE_BOOL)) == NULL) {
			return -1;
		}
	}
	bool = seaudit_message_get_data(msg, &type);

	ret = insert_standard_msg_header(log, tokens, &position, msg);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		has_warnings = 1;
	}
	if (position >= num_tokens) {
		WARN(log, "%s", "Not enough tokens for boolean change.");
		return 1;
	}
	token = apol_vector_get_element(tokens, position);

	/* Make sure the following token is the string "kernel:" */
	if (!strstr(token, "kernel:")) {
		WARN(log, "%s", "Expected to see kernel here.");
		has_warnings = 1;
		/* Hold the position */
	} else {
		if ((ret = insert_manager(log, msg, "kernel")) < 0) {
			return ret;
		}
		position++;
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for boolean change.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);
	}

	if (!next_line) {
		if (!strstr(token, "security:")) {
			WARN(log, "%s", "Expected to see security here.");
			has_warnings = 1;
			/* Hold the position */
		} else {
			position++;
			if (position >= num_tokens) {
				WARN(log, "%s", "Not enough tokens for boolean change.");
				return 1;
			}
			token = apol_vector_get_element(tokens, position);
		}

		if (!strstr(token, "committed")) {
			WARN(log, "%s", "Expected to see committed here.");
			has_warnings = 1;
			/* Hold the position */
		} else {
			position++;
			if (position >= num_tokens) {
				WARN(log, "%s", "Not enough tokens for boolean change.");
				return 1;
			}
			token = apol_vector_get_element(tokens, position);
		}

		if (!strstr(token, "booleans")) {
			WARN(log, "%s", "Expected to see booleans here.");
			has_warnings = 1;
			/* Hold the position */
		} else {
			position++;
			if (position >= num_tokens) {
				WARN(log, "%s", "Not enough tokens for boolean change.");
				return 1;
			}
			token = apol_vector_get_element(tokens, position);
		}

		if (!strstr(token, "{")) {
			WARN(log, "%s", "Expected to see '{' here.");
			has_warnings = 1;
			/* Hold the position */
		} else {
			position++;
			if (position >= num_tokens) {
				WARN(log, "%s", "Not enough tokens for boolean change.");
				return 1;
			}
			token = apol_vector_get_element(tokens, position);
		}
	}

	/* keep parsing until a closing brace is found.  if end of
	 * tokens is reached, then keep parsing the next line */
	while (position < num_tokens) {
		token = apol_vector_get_element(tokens, position);
		position++;

		if (!strcmp(token, "}")) {
			if (position < num_tokens) {
				WARN(log, "%s", "Excess tokens after closing brace");
				has_warnings = 1;
			}
			return has_warnings;
		}

		ret = boolean_msg_insert_bool(log, bool, token);
		if (ret < 0) {
			return ret;
		} else if (ret > 0) {
			has_warnings = 1;
		}
	}

	/* did not find a closing brace yet */
	log->next_line = 1;
	return has_warnings;
}

/******************** policy load parsing ********************/

/**
 * Determine if a series of tokens represents the older style of a
 * policy load.
 *
 * @return 0 if not older style, 1 if it is the older style, < 0 on
 * error.  If it is the older style, then increment reference pointer
 * position to point to the next unprocessed token.
 */
static int load_policy_msg_is_old_load_policy_string(seaudit_log_t * log, apol_vector_t * tokens, size_t * position)
{
	size_t i, length = 0;
	int rt;
	char *tmp = NULL;
	if (*position + 4 >= apol_vector_get_size(tokens)) {
		return 0;
	}

	for (i = 0; i < 4; i++) {
		length += strlen((char *)apol_vector_get_element(tokens, i + *position));
	}

	if ((tmp = (char *)calloc(length + 1, sizeof(char))) == NULL) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}

	for (i = 0; i < 4; i++) {
		strcat(tmp, (char *)apol_vector_get_element(tokens, i + *position));
	}

	rt = strcmp(tmp, OLD_LOAD_POLICY_STRING);
	free(tmp);

	if (rt == 0) {
		*position += 4;
		return 1;
	} else
		return 0;
}

static void load_policy_msg_get_policy_components(seaudit_load_message_t * load, apol_vector_t * tokens, size_t * position)
{
	char *arg = apol_vector_get_element(tokens, *position);
	char *endptr;
	unsigned int val = (unsigned int)strtoul(arg, &endptr, 10);
	if (*endptr != '\0') {
		/* found a key-value pair where the key is not a
		 * number, so skip this */
		(*position)++;
		return;
	}
	char *id = apol_vector_get_element(tokens, *position + 1);
	assert(id != NULL && arg != NULL);
	if (load->classes == 0 && strstr(id, "classes")) {
		load->classes = val;
	} else if (load->rules == 0 && strstr(id, "rules")) {
		load->rules = val;
	} else if (load->users == 0 && strstr(id, "users")) {
		load->users = val;
	} else if (load->roles == 0 && strstr(id, "roles")) {
		load->roles = val;
	} else if (load->types == 0 && strstr(id, "types")) {
		load->types = val;
	} else if (load->bools == 0 && strstr(id, "bools")) {
		load->bools = val;
	}
	*position += 2;
}

static int load_parse(seaudit_log_t * log, apol_vector_t * tokens)
{
	seaudit_message_t *msg;
	seaudit_load_message_t *load;
	seaudit_message_type_e type;
	int ret, error, has_warnings = 0;
	size_t position = 0, num_tokens = apol_vector_get_size(tokens);
	char *token;

	if (log->next_line) {
		/* still processing a load message, so don't create a
		 * new one */
		size_t num_messages = apol_vector_get_size(log->messages);
		assert(num_messages > 0);
		msg = apol_vector_get_element(log->messages, num_messages - 1);
		log->next_line = 0;
	} else {
		if ((msg = message_create(log, SEAUDIT_MESSAGE_TYPE_LOAD)) == NULL) {
			return -1;
		}
	}
	load = seaudit_message_get_data(msg, &type);

	ret = insert_standard_msg_header(log, tokens, &position, msg);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		has_warnings = 1;
	}
	if (position >= num_tokens) {
		WARN(log, "%s", "Not enough tokens for policy load.");
		return 1;
	}
	token = apol_vector_get_element(tokens, position);

	if (strcmp(token, "invalidating") == 0) {
		WARN(log, "%s", "Got an unexpected invalidating message.");
		return 1;
	}

	if (position + 1 >= num_tokens) {
		WARN(log, "%s", "Not enough tokens for policy load.");
		return 1;
	}
	if (strcmp((char *)apol_vector_get_element(tokens, position + 1), "bools") == 0) {
		WARN(log, "%s", "Got an unexpected bools message.");
		return 1;
	}

	/* Check the following token for the string "kernel:" */
	if (!strstr(token, "kernel:")) {
		WARN(log, "%s", "Expected to see kernel here.");
		has_warnings = 1;
		/* Hold the position */
	} else {
		if ((ret = insert_manager(log, msg, "kernel")) < 0) {
			return ret;
		}
		position++;
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for policy load.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);
	}

	if (strcmp(token, "security:")) {
		WARN(log, "%s", "Expected to see security here.");
		has_warnings = 1;
		/* Hold the position */
	} else {
		position++;
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for policy load.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);
	}

	ret = load_policy_msg_is_old_load_policy_string(log, tokens, &position);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for policy load.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);
		if ((load->binary = strdup(token)) == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
		log->next_line = 1;
	} else {
		while (position < num_tokens) {
			load_policy_msg_get_policy_components(load, tokens, &position);
		}
		/* Check to see if we have gathered ALL policy
		 * components. If not, we need to load the next
		 * line. */
		if (load->classes == 0 || load->rules == 0 || load->users == 0 || load->roles == 0 || load->types == 0) {
			log->next_line = 1;
		}
	}
	return has_warnings;
}

/**
 * Parse a single nul-terminated line from an selinux audit log.
 */
static int seaudit_log_parse_line(seaudit_log_t * log, char *line)
{
	char *orig_line = NULL;
	seaudit_message_t *prev_message;
	seaudit_message_type_e is_sel, prev_message_type;
	apol_vector_t *tokens = NULL;
	int retval = -1, retval2, has_warnings = 0, error = 0;
	size_t offset = 0, i;

	is_sel = is_selinux(line);
	if (log->next_line) {
		prev_message = apol_vector_get_element(log->messages, apol_vector_get_size(log->messages) - 1);
		seaudit_message_get_data(prev_message, &prev_message_type);
		if (!(is_sel == SEAUDIT_MESSAGE_TYPE_INVALID && prev_message_type == SEAUDIT_MESSAGE_TYPE_BOOL) &&
		    !(is_sel == SEAUDIT_MESSAGE_TYPE_LOAD && prev_message_type == SEAUDIT_MESSAGE_TYPE_LOAD)) {
			WARN(log, "%s", "Parser was in the middle of a line, but next message was not the correct format.");
			has_warnings = 1;
			log->next_line = 0;
		} else {
			is_sel = prev_message_type;
		}
	}
	if (is_sel == SEAUDIT_MESSAGE_TYPE_INVALID) {
		/* unknown line, so ignore it */
		return 0;
	}

	if ((orig_line = strdup(line)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	if (get_tokens(log, line, &tokens) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}

	switch (is_sel) {
	case SEAUDIT_MESSAGE_TYPE_AVC:
		retval2 = avc_parse(log, tokens);
		break;
	case SEAUDIT_MESSAGE_TYPE_BOOL:
		retval2 = bool_parse(log, tokens);
		break;
	case SEAUDIT_MESSAGE_TYPE_LOAD:
		retval2 = load_parse(log, tokens);
		break;
	default:
		/* should never get here */
		assert(0);
		errno = EINVAL;
		retval2 = -1;
	}
	if (retval2 < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	} else if (retval2 > 0) {
		if (apol_vector_append(log->malformed_msgs, orig_line) < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
		orig_line = NULL;
		has_warnings = 1;
	}

	retval = 0;
      cleanup:
	free(orig_line);
	apol_vector_destroy(&tokens);
	if (retval < 0) {
		errno = error;
		return -1;
	}
	return has_warnings;
}

/******************** public functions below ********************/

int seaudit_log_parse(seaudit_log_t * log, FILE * syslog)
{
	FILE *audit_file = syslog;
	char *line = NULL;
	int retval = -1, retval2, has_warnings = 0, error = 0;
	size_t line_size = 0, i;

	if (log == NULL || syslog == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		error = EINVAL;
		goto cleanup;
	}

	if (!log->tz_initialized) {
		tzset();
		log->tz_initialized = 1;
	}

	clearerr(audit_file);

	while (1) {
		if (getline(&line, &line_size, audit_file) < 0) {
			error = errno;
			if (!feof(audit_file)) {
				ERR(log, "%s", strerror(error));
				goto cleanup;
			}
			break;
		}
		apol_str_trim(line);
		retval2 = seaudit_log_parse_line(log, line);
		if (retval2 < 0) {
			error = errno;
			goto cleanup;
		} else if (retval2 > 0) {
			has_warnings = 1;
		}
	}

	retval = 0;
      cleanup:
	free(line);
	for (i = 0; i < apol_vector_get_size(log->models); i++) {
		seaudit_model_t *m = apol_vector_get_element(log->models, i);
		model_notify_log_changed(m, log);
	}
	if (retval < 0) {
		errno = error;
		return -1;
	}
	if (has_warnings) {
		WARN(log, "%s", "Audit log was parsed, but there were one or more invalid message found within it.");
	}
	return has_warnings;
}

int seaudit_log_parse_buffer(seaudit_log_t * log, const char *buffer, const size_t bufsize)
{
	const char *s;
	char *line = NULL, *l;
	int retval = -1, retval2, has_warnings = 0, error = 0;
	size_t offset = 0, line_size, i;

	if (log == NULL || buffer == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		error = EINVAL;
		goto cleanup;
	}

	if (!log->tz_initialized) {
		tzset();
		log->tz_initialized = 1;
	}

	while (offset < bufsize) {
		/* create a new string up to the first newline or end of
		 * buffer, whichever comes first */
		for (s = buffer + offset; s < buffer + bufsize && *s != '\n'; s++) ;
		line_size = s - (buffer + offset);
		assert(line_size > 0);
		if ((l = realloc(line, line_size + 1)) == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
		line = l;
		memcpy(line, buffer + offset, line_size);
		line[line_size] = '\0';
		offset += line_size;
		if (s < buffer + bufsize) {
			/* this branch can only be true if not at end of file */
			assert(*s == '\n');
			offset++;
		}
		apol_str_trim(line);
		retval2 = seaudit_log_parse_line(log, line);
		if (retval2 < 0) {
			error = errno;
			goto cleanup;
		} else if (retval2 > 0) {
			has_warnings = 1;
		}
	}

	retval = 0;
      cleanup:
	free(line);
	for (i = 0; i < apol_vector_get_size(log->models); i++) {
		seaudit_model_t *m = apol_vector_get_element(log->models, i);
		model_notify_log_changed(m, log);
	}
	if (retval < 0) {
		errno = error;
		return -1;
	}
	if (has_warnings) {
		WARN(log, "%s", "Audit log was parsed, but there were one or more invalid message found within it.");
	}
	return has_warnings;
}
