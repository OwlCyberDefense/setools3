/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mbrown@tresys.com
 * Date: October 3, 2003
 * Modified 3/26/2004 <don.patterson@tresys.com>
 *
 * This file contains the implementation of the parse.h
 *
 */

#include "parse.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>

#define MEMORY_BLOCK_MAX_SIZE 256
#define NUM_POLICY_COMPONENTS 5
#define NUM_TIME_COMPONENTS 3
#define OLD_LOAD_POLICY_STRING "loadingpolicyconfigurationfrom"
#define AVCMSG " avc: "
#define LOADMSG " security: "
#define BOOLMSG " committed booleans "
#define HEADER_STRING "audit"
#define PARSE_AVC_MSG 1
#define PARSE_LOAD_MSG 2
#define PARSE_BOOL_MSG 3
#define PARSE_NON_SELINUX -1
#define PARSE_NUM_CONTEXT_FIELDS 3
#define PARSE_NOT_MATCH -1
#define PARSE_LOAD_NEXT_LINE 5
#define PARSE_LOAD_FALSE_POS 6

static int get_tokens(char *line, int msgtype, audit_log_t *log, FILE *audit_file, msg_t **msg);

static int is_selinux(char *line) 
{
	assert(line != NULL);
	if (strstr(line, LOADMSG)) {
		return PARSE_LOAD_MSG;
	} else if (strstr(line, AVCMSG))
		return PARSE_AVC_MSG;
	else 
		return PARSE_NON_SELINUX;
}

static int avc_msg_is_token_new_audit_header(char *token) 
{
	assert(token != NULL);
	if (strstr(token, HEADER_STRING)) 
		return TRUE;
	else 
		return FALSE;
}

static int get_line(FILE *audit_file , char **dest)
{
	char *line = NULL;
	int length = 0;
	char c = '\0';
	int i = 0;
	
	assert(audit_file != NULL && dest != NULL);
	while ((c = fgetc(audit_file)) != EOF) {
		if (i < length - 1) {
			line[i] = c;
		} else {
			length += MEMORY_BLOCK_MAX_SIZE;
			if ((line = (char*) realloc(line, length * sizeof(char))) == NULL){
				return PARSE_MEMORY_ERROR;
			}
			line[i] = c;
		}

		if (c == '\n') {
			line[i+1] = '\0';
			*dest = *(&line);
			return PARSE_SUCCESS;
		}
		i++;
	}

	if (i > 0){
		if (i < length - 1){
			line[i] = '\0';
			*dest = *(&line);
		} else {
			length += MEMORY_BLOCK_MAX_SIZE;
			if ((line = (char*) realloc(line, length * sizeof(char))) == NULL){
				return PARSE_MEMORY_ERROR;
			}
			line[i] = '\0';
			*dest = *(&line);
		}
	}
	
	return PARSE_SUCCESS;
}


static int avc_msg_is_prefix(char *token, char *prefix, char **result)
{
	bool_t is_match = TRUE;
	int i = 0, length;
	
	assert(token != NULL && prefix != NULL);
	length = strlen(prefix);
	if (strlen(token) < length)
		return FALSE;

	for (i = 0; i < length; i++){
		if (token[i] != prefix[i]){
			is_match = FALSE;
			break;
		}
	}
	if (!is_match)
		return FALSE;
	
	/* Set the result to all text after the prefix. */
	*result = &token[length];
	return TRUE;
}

static int avc_msg_insert_perms(char **tokens, msg_t *msg, audit_log_t *log, int *position, int num_tokens)
{
	int i = 0, num_perms = 0, id = 0, start_pos;
	
	assert(tokens != NULL && msg != NULL && log != NULL && *position >= 0);
	if (strcmp(tokens[*position], "{")) {
		return PARSE_INVALID_MSG_WARN;
	}

	(*position)++;
	start_pos = *position;
	for (i = *position; i < num_tokens && (strcmp(tokens[i], "}") != 0); i++) {
		num_perms++;
		(*position)++;
	}
	
	if (i == num_tokens)
		return PARSE_INVALID_MSG_WARN;

	msg->msg_data.avc_msg->num_perms = num_perms;

	if ((msg->msg_data.avc_msg->perms = (int*) malloc(num_perms * sizeof(int))) == NULL){
		return PARSE_MEMORY_ERROR;
	}

	for (i = 0 ; i < num_perms ; i++) {
		if(audit_log_add_perm(log, tokens[i + start_pos], &id) == -1)
			return PARSE_MEMORY_ERROR;
		msg->msg_data.avc_msg->perms[i] = id;
	}
	return PARSE_SUCCESS;
}


static int insert_time(char **tokens, msg_t *msg, int *position)
{
	char *time = NULL;
	int i, length = 0;
	
	assert(tokens != NULL && msg != NULL && *position >= 0);
	for (i = (*position); i < NUM_TIME_COMPONENTS; i++) {
		length += strlen(tokens[i]);
	}
	
	/* Increase size for terminating string char and whitespace within. */
	length += 1 + (NUM_TIME_COMPONENTS - 1); 
	if ((time = (char*) malloc(length * (sizeof(char)))) == NULL)
			return PARSE_MEMORY_ERROR;
	
	strcpy(time, tokens[*position]);	
	time = strcat(time, " ");
	(*position)++;
	time = strcat(time, tokens[*position]);
	time = strcat(time, " " );
	(*position)++;
	time = strcat(time, tokens[*position]);
   
	if (!msg->date_stamp) {
		if ((msg->date_stamp = (struct tm*) malloc(sizeof(struct tm))) == NULL)
			return PARSE_MEMORY_ERROR;
	}

	if (!strptime(time, "%b %d %T", msg->date_stamp)) {    
		free(time); 
		return PARSE_INVALID_MSG_WARN;
	   
	} else {
		free(time);
		/* random year to make mktime happy */
		msg->date_stamp->tm_year = 2000 - 1900;
		return PARSE_SUCCESS;
	}
	
}

static int avc_msg_insert_access_type(char *token, msg_t *msg) 
{
	assert(token != NULL && msg != NULL);
	if (strcmp(token, "granted") == 0) {
		msg->msg_data.avc_msg->msg = AVC_GRANTED;
		return PARSE_SUCCESS;
	} else if (strcmp(token, "denied") == 0) {
		msg->msg_data.avc_msg->msg = AVC_DENIED;
		return PARSE_SUCCESS;
	} else
		return PARSE_INVALID_MSG_WARN;     
}

static int avc_msg_insert_capability(msg_t *msg, char **tmp)
{
	assert(msg != NULL && tmp != NULL && *tmp != NULL);		
	msg->msg_data.avc_msg->capability = atoi(*tmp);
	msg->msg_data.avc_msg->is_capability = TRUE;
	
	return PARSE_SUCCESS;
}


static int avc_msg_insert_ino(msg_t *msg, char **tmp)
{
	assert(msg != NULL && tmp != NULL && *tmp != NULL);
	msg->msg_data.avc_msg->inode = atoi(*tmp);
	msg->msg_data.avc_msg->is_inode = TRUE;
	return PARSE_SUCCESS;
}

static int avc_msg_insert_key(msg_t *msg, char **tmp)
{
	assert(msg != NULL && tmp != NULL && *tmp != NULL);		
	msg->msg_data.avc_msg->key = atoi(*tmp);
	msg->msg_data.avc_msg->is_key = TRUE;
	return PARSE_SUCCESS;
}

static int avc_msg_insert_tclass(msg_t *msg, char **tmp, audit_log_t *log)
{
	int id = -1;
	
	assert(msg != NULL && tmp != NULL && *tmp != NULL && log != NULL);
	if (audit_log_add_obj(log, *tmp, &id) == -1)
		return PARSE_MEMORY_ERROR;
	msg->msg_data.avc_msg->obj_class = id;
	
	return PARSE_SUCCESS;
}

static int parse_context(char *token, char *user, char *role, char *type)
{
	/* Parse user:role:type */
	int i = 0;
	char *fields[PARSE_NUM_CONTEXT_FIELDS];

	assert(token != NULL);
        while ((fields[i] = strsep(&token, ":")) != NULL && i < PARSE_NUM_CONTEXT_FIELDS) {
		i++;       	       	
        }

	if (i != PARSE_NUM_CONTEXT_FIELDS)
		return -1;

	strcpy(user, fields[0]);
	strcpy(role, fields[1]);
	strcpy(type, fields[2]);
	return PARSE_SUCCESS;
       
}

static int avc_msg_insert_tcon(msg_t *msg, char **tmp, audit_log_t *log)
{
	char *user = NULL, *role = NULL, *type = NULL;
	int id = -1, length;

	assert(msg != NULL && tmp != NULL && *tmp != NULL && log != NULL);
	if (*tmp != NULL) {
		length = strlen(*tmp) + 1;
		if ((user = (char*) malloc(length * (sizeof(char)))) == NULL)
			return PARSE_MEMORY_ERROR;
		if ((role = (char*) malloc(length * (sizeof(char)))) == NULL){
			free(user);
			return PARSE_MEMORY_ERROR;
		}
		if ((type = (char*) malloc(length * (sizeof(char)))) == NULL){
			free(user);
			free(role);
			return PARSE_MEMORY_ERROR;
		}
		if (parse_context(*tmp, user, role, type) < 0){
			free(user);
			free(role);
			free(type);
			return PARSE_MALFORMED_MSG_WARN;			
		}
		if (audit_log_add_user(log, user, &id) == -1){
			free(user);
			free(role);
			free(type);
			return PARSE_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->tgt_user = id;

		if (audit_log_add_role(log, role, &id) == -1){
			free(user);
			free(role);
			free(type);
			return PARSE_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->tgt_role = id;

		if (audit_log_add_type(log, type, &id) == -1){
			free(user);
			free(role);
			free(type);
			return PARSE_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->tgt_type = id;
	       
		free(user);
		free(role);
		free(type);
		return PARSE_SUCCESS;
	} else
		return PARSE_NOT_MATCH;
}

static int avc_msg_insert_scon(msg_t *msg, char **tmp, audit_log_t *log)
{
	char *user = NULL, *role = NULL, *type = NULL;
	int id = -1, length;

	assert(msg != NULL && tmp != NULL && *tmp != NULL && log != NULL);
	if (*tmp != NULL) {
		length = strlen(*tmp) + 1;
		if ((user = (char*) malloc(length * (sizeof(char)))) == NULL)
			return PARSE_MEMORY_ERROR;
		if ((role = (char*) malloc(length * (sizeof(char)))) == NULL){
			free(user);
			return PARSE_MEMORY_ERROR;
		}
		if ((type = (char*) malloc(length * (sizeof(char)))) == NULL){
			free(user);
			free(role);
			return PARSE_MEMORY_ERROR;
		}

		if (parse_context(*tmp, user, role, type) < 0) {
			free(user);
			free(role);
			free(type);
			return PARSE_MALFORMED_MSG_WARN;
		}

		if (audit_log_add_user(log, user, &id) == -1){
			free(user);
			free(role);
			free(type);
			return PARSE_MEMORY_ERROR;
		}

		msg->msg_data.avc_msg->src_user = id;

		if (audit_log_add_role(log, role, &id) == -1) {
			free(user);
			free(role);
			free(type);
			return PARSE_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->src_role = id;

		if (audit_log_add_type(log, type, &id) == -1){
			free(user);
			free(role);
			free(type);
			return PARSE_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->src_type = id;
	       
		free(user);
		free(role);
		free(type);
		return PARSE_SUCCESS;
	} else
		return PARSE_NOT_MATCH;
}

static int avc_msg_insert_string(char **dest, char **src)
{
	assert(dest != NULL && src != NULL && *src != NULL);
	if ((*dest = (char*) malloc((strlen(*src) + 1) *sizeof(char))) == NULL)
		return PARSE_MEMORY_ERROR;
	strcpy(*dest, *src);
	
	return PARSE_SUCCESS;
}

static int insert_hostname(audit_log_t *log, char **tokens, msg_t *msg, int *position)
{
        int id;
	
	assert(log != NULL && tokens != NULL && msg != NULL && *position >= 0);
        if (audit_log_add_host(log, tokens[*position], &id) == -1)
                return PARSE_MEMORY_ERROR;
        else {
                msg->host = id;
                return PARSE_SUCCESS;
        }
}

static int avc_msg_insert_int(int *dest, char **src)
{
	assert(dest != NULL && src != NULL && *src != NULL);		
	*dest = atoi(*src);
	return PARSE_SUCCESS;
}

static int avc_msg_is_valid_additional_field(char *orig_token)
{
	int count = 0;
	char *token_copy = NULL, *token = NULL;
					
	assert(orig_token != NULL);
	/* Make a copy of the given token argument, so we don't modify it. */
	if ((token_copy = strdup(orig_token)) == NULL)
		return PARSE_MEMORY_ERROR;
	token = token_copy;
					
	while (strsep(&token, "=") != NULL) {
	       	count++;
        }
        free(token_copy);
        
	if (count == 2) 
		return TRUE;
	else 
		return FALSE;

}

static int avc_msg_reformat_path_field_string(char *new_token, char *start_token, char **path_str)
{
	int length;
			
	assert(new_token != NULL && start_token != NULL);
	if (*path_str == NULL) {
		if ((*path_str = (char*) malloc((strlen(start_token) + 1) * sizeof(char))) == NULL) {
			return PARSE_MEMORY_ERROR;
		}
		/* Append the start token */
        	strcpy(*path_str, start_token);
	} 
	
	/* Add 2 to concatenate the whitespace char and the terminating string char. */
	length = strlen(*path_str) + strlen(new_token) + 2;
	if ((*path_str = (char*) realloc(*path_str, length * sizeof(char))) == NULL) {
		return PARSE_MEMORY_ERROR;;
	}
	*path_str = strcat(*path_str, " ");	
	*path_str = strcat(*path_str, new_token);
		
	return PARSE_SUCCESS;
}

static int avc_msg_insert_additional_field_data(char **tokens, msg_t *msg, audit_log_t *log, int *position, int num_tokens)
{
	int i = 0, is_valid, end_fname_idx = 0;
	char *field_value = NULL, *path_str = NULL;
	int found[AVC_NUM_FIELDS];
	int return_val = PARSE_SUCCESS;

	assert(tokens != NULL && msg != NULL && log != NULL && position >= 0 && num_tokens > 0);
	for (i = 0; i < AVC_NUM_FIELDS; i++)
		found[i] = PARSE_NOT_MATCH;

	msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_FS;

	for (i = (*position); i < num_tokens && strcmp(*(&tokens[i]), "") != 0; i++) {
		if (found[AVC_PID_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "pid=", &field_value) != FALSE) {
			found[AVC_PID_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->pid, &field_value);
			if (found[AVC_PID_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_EXE_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "exe=", &field_value) != FALSE) {
			found[AVC_EXE_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->exe, &field_value);
			if (found[AVC_EXE_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		
		if (found[AVC_COMM_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "comm=", &field_value) != FALSE) {
			found[AVC_COMM_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->comm, &field_value);
			if (found[AVC_COMM_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		if (found[AVC_PATH_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "path=", &field_value) != FALSE) {
			/* Gather all tokens located after the path=XXXX token until we encounter a valid additional field. 
			 * This is because a path name file name may be seperated by whitespace. Look ahead at the next 
			 * token, but we make sure not to access memory beyond the total number of tokens. */
			end_fname_idx = i + 1;
			while (end_fname_idx < num_tokens) {
				if ((is_valid = avc_msg_is_valid_additional_field(*(&tokens[end_fname_idx]))) == PARSE_MEMORY_ERROR) {
					return PARSE_MEMORY_ERROR;
				} 
				
				if (is_valid) 
					break;	
					
				avc_msg_reformat_path_field_string(*(&tokens[end_fname_idx]), *(&tokens[i]), &path_str);
				end_fname_idx++; 
			}
							
			if (path_str != NULL) {
				found[AVC_PATH_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->path, &path_str);
				free(path_str);
				/* Move the position to the last file name item. */
				i = end_fname_idx - 1;
			} else 
				found[AVC_PATH_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->path, &field_value);
				
			if (found[AVC_PATH_FIELD] == PARSE_MEMORY_ERROR){
				return PARSE_MEMORY_ERROR;
			}
		}

		if (found[AVC_NAME_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "name=", &field_value) != FALSE) {
			found[AVC_NAME_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->name, &field_value);
			if (found[AVC_NAME_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

       
		if (found[AVC_DEV_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "dev=", &field_value) != FALSE) {
			found[AVC_DEV_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->dev, &field_value);
			if (found[AVC_DEV_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_SADDR_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "saddr=", &field_value) != FALSE) {
			found[AVC_SADDR_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->saddr, &field_value);
			if (found[AVC_SADDR_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_SOURCE_FIELD] == PARSE_NOT_MATCH && 
		    (avc_msg_is_prefix(*(&tokens[i]), "source=", &field_value) != FALSE || 
		     avc_msg_is_prefix(*(&tokens[i]), "src=", &field_value) != FALSE)) {
			found[AVC_SOURCE_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->source, &field_value);
			if (found[AVC_SOURCE_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_DADDR_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "daddr=", &field_value) != FALSE) {
			found[AVC_DADDR_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->daddr, &field_value);
			if (found[AVC_DADDR_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_DEST_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "dest=", &field_value) != FALSE) {
			found[AVC_DEST_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->dest, &field_value);
			if (found[AVC_DEST_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		
		if (found[AVC_NETIF_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "netif=", &field_value) != FALSE) {
			found[AVC_NETIF_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->netif, &field_value);
			if (found[AVC_NETIF_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			if (found[AVC_NETIF_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_LADDR_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "laddr=", &field_value) != FALSE) {
			found[AVC_LADDR_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->laddr, &field_value);
			if (found[AVC_LADDR_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_LPORT_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "lport=", &field_value) != FALSE) {
			found[AVC_LPORT_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->lport, &field_value);
			if (found[AVC_LPORT_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			else if (found[AVC_LPORT_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_FADDR_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "faddr=", &field_value) != FALSE) {
			found[AVC_FADDR_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->faddr, &field_value);
			if (found[AVC_FADDR_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_FPORT_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "fport=", &field_value) != FALSE) {
			found[AVC_FPORT_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->fport, &field_value);
			if (found[AVC_FPORT_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_PORT_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "port=", &field_value) != FALSE) {
			found[AVC_PORT_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->port, &field_value);
			if (found[AVC_PORT_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			else if (found[AVC_PORT_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		
		if (found[AVC_SRC_SID_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "ssid=", &field_value) != FALSE) {
			found[AVC_SRC_SID_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->src_sid, &field_value);
			if (found[AVC_SRC_SID_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
	
		if (found[AVC_TGT_SID_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "tsid=", &field_value) != FALSE) {
			found[AVC_TGT_SID_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->tgt_sid , &field_value);
			if (found[AVC_TGT_SID_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		
		if (found[AVC_CAPABILITY_FIELD] == PARSE_NOT_MATCH &&
		    avc_msg_is_prefix(*(&tokens[i]), "capability=", &field_value) != FALSE) {
			found[AVC_CAPABILITY_FIELD] = avc_msg_insert_capability(msg, &field_value);
			if (found[AVC_CAPABILITY_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_CAP;
			else if (found[AVC_CAPABILITY_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_KEY_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "key=", &field_value) != FALSE) {
			found[AVC_KEY_FIELD] = avc_msg_insert_key(msg, &field_value);
			if (found[AVC_KEY_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_IPC;
			else if (found[AVC_KEY_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_INODE_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "ino=", &field_value) != FALSE) {
			found[AVC_INODE_FIELD] = avc_msg_insert_ino(msg, &field_value);
			if (found[AVC_INODE_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
	  
		if (found[AVC_SRC_USER_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "scontext=", &field_value) != FALSE){
			found[AVC_SRC_USER_FIELD] = avc_msg_insert_scon(msg, &field_value, log);
			if (found[AVC_SRC_USER_FIELD] == PARSE_MALFORMED_MSG_WARN) {
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
				return_val = PARSE_MALFORMED_MSG_WARN;
			}
			if (found[AVC_SRC_USER_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
	      		
		if (found[AVC_TGT_USER_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "tcontext=", &field_value) != FALSE){
			found[AVC_TGT_USER_FIELD] = avc_msg_insert_tcon(msg, &field_value, log);
			if (found[AVC_SRC_USER_FIELD] == PARSE_MALFORMED_MSG_WARN) {
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
				return_val = PARSE_MALFORMED_MSG_WARN;
			}
			if (found[AVC_TGT_USER_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
	       
		if (found[AVC_OBJ_CLASS_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "tclass=", &field_value) != FALSE){
			found[AVC_OBJ_CLASS_FIELD] = avc_msg_insert_tclass(msg, &field_value, log);
			if (found[AVC_OBJ_CLASS_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		if (field_value == NULL){
			msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
			return_val = PARSE_MALFORMED_MSG_WARN;
		}
		field_value = NULL;
		(*position)++;
	}

	if (found[AVC_SRC_SID_FIELD] == PARSE_NOT_MATCH && found[AVC_SRC_USER_FIELD] == PARSE_NOT_MATCH){
		msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
		return PARSE_MALFORMED_MSG_WARN;
	}
	
	if (found[AVC_TGT_SID_FIELD] == PARSE_NOT_MATCH && found[AVC_TGT_USER_FIELD] == PARSE_NOT_MATCH){
		msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
		return PARSE_MALFORMED_MSG_WARN;
	}
	
	if (found[AVC_OBJ_CLASS_FIELD] == PARSE_NOT_MATCH){
		msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
		return PARSE_MALFORMED_MSG_WARN;
	}
	       
	return return_val;
}

static int insert_standard_msg_header(char **tokens, msg_t *msg, audit_log_t *log, int *position)
{
	int result;
	
	assert(tokens != NULL && msg != NULL && log != NULL && position >= 0);
	/* Insert time */
	result = insert_time(tokens, msg, position);
	if (result != PARSE_SUCCESS) {
		return result;
	}

	(*position)++;
	/* Insert hostname */
	result = insert_hostname(log, tokens, msg, position);
	if (result != PARSE_SUCCESS) {
	        return result;
	}
	
	return PARSE_SUCCESS;
}

static int avc_msg_insert_field_data(char **tokens, msg_t *msg, audit_log_t *log, int num_tokens)
{
	int result, position = 0;
	
	assert(tokens != NULL && msg != NULL && log != NULL && num_tokens > 0);
	result = insert_standard_msg_header(*(&tokens), msg, log, &position);
	if (result != PARSE_SUCCESS) {
		return result;
	}	
	
	/* Make sure the following token is the string "kernel:" */
	position++;
	if (strcmp(*(&tokens[position]), "kernel:") != 0)
		return PARSE_INVALID_MSG_WARN;
	
	position++;
	/* Skip the audit header token, if it exists. */
	if (avc_msg_is_token_new_audit_header(*(&tokens[position])))
		position++;
	
	/* Make sure the following token is the string "avc:" */
	if (strcmp(*(&tokens[position]), "avc:") != 0)
		return PARSE_INVALID_MSG_WARN;
	
	position++;				
	/* Insert denied or granted */
	result = avc_msg_insert_access_type(*(&tokens[position]), msg);
	if (result != PARSE_SUCCESS) {
		return result;
	}
	
	position++;
	/* Insert perm(s) */
	result = avc_msg_insert_perms(tokens, msg, log, &position, num_tokens);
	if (result != PARSE_SUCCESS) {
		return result;
	}
      	
      	position++;
	if (strcmp(tokens[position], "for") != 0)
		return PARSE_INVALID_MSG_WARN;
	
	position++;
	/* Insert everything else */
	result =  avc_msg_insert_additional_field_data(tokens, msg, log, &position, num_tokens);
	
	return result;
}

static int load_policy_msg_is_old_load_policy_string(char **tokens, int *tmp_position)
{
	int i, rt, length = 0;
	char *tmp = NULL;
	 
	assert(tokens != NULL && *tmp_position >= 0);
	for (i = 0 ; i < 4 ; i++)
		length += strlen(tokens[(*tmp_position) + i]);

	if ((tmp = (char*) malloc((length + 1) * sizeof(char))) == NULL) {
		return PARSE_MEMORY_ERROR;
	}
	/* Must inititialize the string before we can concatenate. */
	tmp[0] = '\0';
       
	for (i = 0; i < 4; i++){
		tmp = strcat(tmp, tokens[*tmp_position]);
		(*tmp_position)++;
	}

	rt = strcmp(tmp, OLD_LOAD_POLICY_STRING);
	free(tmp);
	
	if (rt == 0)
		return TRUE;
	else 
		return FALSE;
}

static int load_policy_msg_insert_field_data(char **tokens, msg_t **msg, FILE *audit_file, audit_log_t *log)
{
	char *next_line = NULL;
	int length = 0, position = 0, tmp_position;
	int i, result;
	bool_t found[NUM_POLICY_COMPONENTS];
	
	assert(tokens != NULL && msg != NULL && *msg != NULL && log != NULL && audit_file != NULL);
	for (i = 0 ; i < NUM_POLICY_COMPONENTS ; i++)
		found[i] = FALSE;

	result = insert_standard_msg_header(*(&tokens), *msg, log, &position);
	if (result != PARSE_SUCCESS) {
		return result;
	}
	
	position++;		
	if (strcmp(tokens[position], "invalidating") == 0) {
		return PARSE_LOAD_FALSE_POS;
	}

	if (strcmp(tokens[position + 1], "bools") == 0) {
		return PARSE_LOAD_FALSE_POS;
	}
	
	/* Make sure the following token is the string "kernel:" */
	if (strcmp(*(&tokens[position]), "kernel:") != 0)
		return PARSE_INVALID_MSG_WARN;
	
	position++;	
	if (strcmp(tokens[position], "security:"))
		return PARSE_INVALID_MSG_WARN;
	
	position++;
	tmp_position = position;		
	if (load_policy_msg_is_old_load_policy_string(*(&tokens), &tmp_position)) {
		position = tmp_position++;
		length = strlen(tokens[position]) + 1;

		if (((*msg)->msg_data.load_policy_msg->binary = (char*) malloc(length * sizeof(char))) == NULL) {
			return PARSE_MEMORY_ERROR;
		}
		strcpy((*msg)->msg_data.load_policy_msg->binary, tokens[position]);
		
		if (get_line(audit_file, &next_line) == PARSE_MEMORY_ERROR){
			free((*msg)->msg_data.load_policy_msg->binary);
			return PARSE_MEMORY_ERROR;
		}
		if (next_line == NULL){
			return PARSE_INVALID_MSG_WARN;
		}
		result = get_tokens(next_line, 2, log, audit_file, msg);
		free(next_line);
		if (result != PARSE_SUCCESS)
			return result;
			
	      
		return PARSE_LOAD_NEXT_LINE;
	}

	if (strcmp(tokens[position + 1], "classes,") == 0){
		found[3] = TRUE;
		(*msg)->msg_data.load_policy_msg->classes = atoi(tokens[position]); 
	}

	if (strcmp(tokens[position + 3], "rules") == 0){
		found[4] = TRUE;
		(*msg)->msg_data.load_policy_msg->rules = atoi(tokens[position + 2]); 
	}
	if (found[3] && found[4]){
		if ((*msg)->msg_data.load_policy_msg->users != 0)
			return PARSE_SUCCESS;
		else
			return PARSE_INVALID_MSG_WARN;
	}
	if ((*msg)->msg_data.load_policy_msg->types != 0)
		return PARSE_INVALID_MSG_WARN;

	if (strcmp(tokens[position + 1], "users,") == 0){
		found[0] = TRUE;
		(*msg)->msg_data.load_policy_msg->users = atoi(tokens[position]);
	}

	if (strcmp(tokens[position + 3], "roles,") == 0){
		found[1] = TRUE;
		(*msg)->msg_data.load_policy_msg->roles = atoi(tokens[position + 2]);
	}

	if (strcmp(tokens[position + 5], "types") == 0){
		found[2] = TRUE;
		(*msg)->msg_data.load_policy_msg->types = atoi(tokens[position + 4]); 
	}

	if (!found[0] || !found[1] || !found[2]){
		return PARSE_INVALID_MSG_WARN;
	}
	else {
		if (get_line(audit_file, &next_line) == PARSE_MEMORY_ERROR){
			return PARSE_MEMORY_ERROR;
		}

		if (next_line == NULL) {
			return PARSE_INVALID_MSG_WARN;
		}
	
		result = get_tokens(next_line, PARSE_LOAD_MSG, log, audit_file, msg);
		free(next_line);
		if(result != PARSE_SUCCESS)
			return result;
		return PARSE_LOAD_NEXT_LINE;
	}
}

static int get_bool(char *token, int *bool, bool_t *val, audit_log_t *log)
{
        int len;

        len = strlen(token);

	/* Strip off ending comma */
        if (token[len - 1] == ','){
                token[len - 1] = '\0';
                len--;
        }

        if (token[len - 2] != ':')
                return PARSE_INVALID_MSG_WARN;

        if (token[len] == '0')
                *val = FALSE;
        else if (token[len] == '1')
                *val = TRUE;
        else
                return PARSE_INVALID_MSG_WARN;

        token[len - 2] = '\0';

        if (audit_log_add_bool(log, token, bool) == -1)
                return PARSE_MEMORY_ERROR;
 
        return PARSE_SUCCESS;
}

static int boolean_msg_insert_field_data(char **tokens, msg_t **msg, audit_log_t *log, int num_tokens)
{
        int result, i, num_bools = 0, bool, start_bools_pos;
	int *booleans = NULL, position = 0;
	bool_t *values = NULL, val;
	
	assert(tokens != NULL && msg != NULL && *msg != NULL && log != NULL);
	result = insert_standard_msg_header(*(&tokens), *msg, log, &position);
	if (result != PARSE_SUCCESS) {
		return result;
	}
	
	/* Make sure the following token is the string "kernel:" */
	if (strcmp(*(&tokens[++position]), "kernel:") != 0)
		return PARSE_INVALID_MSG_WARN;		
	if(strcmp(tokens[++position], "security:"))
	        return PARSE_INVALID_MSG_WARN;
	if(strcmp(tokens[++position], "committed"))
	        return PARSE_INVALID_MSG_WARN;
	if(strcmp(tokens[++position], "booleans"))
	        return PARSE_INVALID_MSG_WARN;
	if(strcmp(tokens[++position], "{"))
	        return PARSE_INVALID_MSG_WARN;

	position++;
	start_bools_pos = position;
	for (i = position; i < num_tokens && (strcmp(tokens[i], "}") != 0); i++) {
		num_bools++;
		position++;
	}
	if (i == num_tokens){
	  return PARSE_INVALID_MSG_WARN;
	}

	if (num_bools == 0){
	         return PARSE_INVALID_MSG_WARN;
	}

	if ((booleans = (int*) malloc(num_bools * sizeof(int))) == NULL) {
		return PARSE_MEMORY_ERROR;
	}
	if ((values = (bool_t*) malloc(num_bools * sizeof(bool_t))) == NULL) {
	        free(booleans);
		return PARSE_MEMORY_ERROR;
	}

	for (i = 0; i < num_bools; i++){
		result = get_bool(tokens[i + start_bools_pos], &bool, &val, log);
		if (result != PARSE_SUCCESS){
		        free(booleans);
		        free(values);
		        return result;
		}
		booleans[i] = bool;
		values[i] = val;
	}
	(*msg)->msg_data.boolean_msg->num_bools = num_bools;
	(*msg)->msg_data.boolean_msg->booleans = booleans;
	(*msg)->msg_data.boolean_msg->values = values;

        return PARSE_SUCCESS;
}

static int free_field_tokens(char **fields, int num_tokens)
{
	int i;
	
	if (fields != NULL) {
		for (i = 0; i < num_tokens; i++)
			free(fields[i]);
		free(fields);
		fields = NULL;
	}
	return 0;
}

static int get_tokens(char *line, int msgtype, audit_log_t *log, FILE *audit_file, msg_t **msg)
{
	char *tokens = NULL, *tmp = NULL;
	char **fields = NULL;
	int idx = 0, num_tokens = 0;
	int result = -1, length = 0;

	assert(msg != NULL && log != NULL && audit_file != NULL);
	tokens = line;
	length = strlen(tokens);
	
	/* Trim any trailing whitespace. */
	while (!ispunct(tokens[length - 1]) && !isalnum(tokens[length - 1])){
		tokens[length - 1] = '\0';
		length -=1;
	}

	/* Tokenize line while ignoring any adjacent whitespace chars. */ 
        while ((tmp = strsep(&tokens, " ")) != NULL) {
	       	if (strcmp(tmp, "") && !str_is_only_white_space(tmp)) {
	       		num_tokens++;
	         	if ((fields = (char**)realloc(fields, num_tokens * sizeof(char*))) == NULL) {
				return PARSE_MEMORY_ERROR;
			}
			if((fields[idx] = (char*)malloc((strlen(tmp) + 1) * sizeof(char))) == NULL) {
				/* Free all tokens up to the previous token, which is number of tokens - 1. */
				free_field_tokens(*(&fields), num_tokens - 1);	
				return PARSE_MEMORY_ERROR;
			}
			strcpy(fields[idx], tmp);
			idx++;
       	       	}
        }

	if (msgtype == PARSE_BOOL_MSG) {
	        *msg = boolean_msg_create();
	        result = boolean_msg_insert_field_data(fields, msg, log, num_tokens);
		if (result == PARSE_INVALID_MSG_WARN || result == PARSE_MEMORY_ERROR) {
			msg_destroy(*msg); 
			*msg = NULL;
			free_field_tokens(*(&fields), num_tokens);
			return result;
		} else {
			if (audit_log_add_msg(log, *msg) == -1){
				free_field_tokens(*(&fields), num_tokens);				
				return PARSE_MEMORY_ERROR;
			}       
			*msg = NULL;
	        }      
	} else if (msgtype == PARSE_AVC_MSG) {
       		*msg = avc_msg_create();
		result = avc_msg_insert_field_data(fields, *msg, log, num_tokens);
		if (result == PARSE_INVALID_MSG_WARN || result == PARSE_MEMORY_ERROR) {
			msg_destroy(*msg); 
			*msg = NULL;
			free_field_tokens(*(&fields), num_tokens);
			return result;
		} else {
			if (audit_log_add_msg(log, *msg) == -1){
				free_field_tokens(*(&fields), num_tokens);				
				return PARSE_MEMORY_ERROR;
			}
			*msg = NULL;
		}
	} else if (msgtype == PARSE_LOAD_MSG) {
		if (*msg == NULL){
			*msg = load_policy_msg_create();
		}
		
		result = load_policy_msg_insert_field_data(fields, msg, audit_file, log);
		if (result == PARSE_MEMORY_ERROR || result == PARSE_INVALID_MSG_WARN || result == PARSE_LOAD_FALSE_POS) {
			msg_destroy(*msg);
			*msg = NULL;
			free_field_tokens(*(&fields), num_tokens);
			return result;
		} else if (result == PARSE_SUCCESS) {
			if (audit_log_add_msg(log, *msg) == -1) {
				free_field_tokens(*(&fields), num_tokens);
				return PARSE_MEMORY_ERROR;
			}
			*msg = NULL;
		}
	} else {
		fprintf(stderr, "Invalid message type provided: %d\n", msgtype);
	}
	free_field_tokens(*(&fields), num_tokens);
	
	return result;
}


int parse_audit(FILE *syslog, audit_log_t *log)
{
	FILE *audit_file = syslog;
	msg_t *msg = NULL;
	char *line = NULL;
	int is_sel = -1, result = 0, selinux_msg = 0, rt;

	assert(log != NULL);
	if (audit_file == NULL)
		return PARSE_NO_PARSE;
       
	clearerr(audit_file);
	if (feof(audit_file))
		return PARSE_NO_PARSE;

	if (get_line(audit_file, &line) == PARSE_MEMORY_ERROR) {
		return PARSE_MEMORY_ERROR;
	}

	while (line != NULL) {
     		is_sel = is_selinux(line);
		if (is_sel != PARSE_NON_SELINUX) {
			rt = get_tokens(line, is_sel, log, audit_file, &msg);
			if (rt == PARSE_INVALID_MSG_WARN && result != PARSE_BOTH_MSG_WARN){
			        if (result == PARSE_MALFORMED_MSG_WARN)
			                result = PARSE_BOTH_MSG_WARN;
			        else
			                result = PARSE_INVALID_MSG_WARN;
			}
			if (rt == PARSE_MALFORMED_MSG_WARN && result != PARSE_BOTH_MSG_WARN){
			        if (result == PARSE_INVALID_MSG_WARN)
			                result = PARSE_BOTH_MSG_WARN;
			        else
			                result = PARSE_MALFORMED_MSG_WARN;
			}
			if (rt == PARSE_MEMORY_ERROR){
				return rt;
			}
			if (rt != PARSE_LOAD_FALSE_POS && rt != PARSE_INVALID_MSG_WARN)
				selinux_msg++;
		}
		free(line);
		line = NULL;
		if (get_line(audit_file, &line) == PARSE_MEMORY_ERROR) {
			return PARSE_MEMORY_ERROR;
		}
	}

       	if(selinux_msg == 0)
		return PARSE_NO_SELINUX_ERROR;
	else
		return result;
}














