/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mbrown@tresys.com
 * Date: October 3, 2003
 *
 * This file contains the implementation of the parse.h
 *
 */

#include "parse.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define AVCMSG " avc: "
#define LOADMSG " security: "
#define BOOLMSG " committed booleans "
#define PARSE_NUM_FIELDS 35
#define PARSE_MAX_MSG_LEN 256
#define PARSE_PERM_START 7
#define PARSE_AVC_MSG 1
#define PARSE_LOAD_MSG 2
#define PARSE_BOOL_MSG 3
#define PARSE_NON_SELINUX -1
#define PARSE_NUM_CONTEXT_FIELDS 3
#define OLD_LOAD_HEADER_LEN 31
#define PARSE_MSG_AFTER_HEADER 6
#define PARSE_BINARY_POSITION 10
#define PARSE_NOT_MATCH -1
#define PARSE_LOAD_NEXT_LINE 6
#define PARSE_LOAD_FALSE_POS 7
#define PARSE_AVC_AFTER_FOR 10
#define PARSE_HOST_POSITION 3
#define PARSE_BOOL_SECURITY_POSITION 5
#define PARSE_BOOL_START_BOOLS 9

static int is_selinux(char *line) 
{
	if (strstr(line, LOADMSG)) {
	        if (strstr(line, BOOLMSG))
	                return PARSE_BOOL_MSG;
	        else
		        return PARSE_LOAD_MSG;
	} else if (strstr(line, AVCMSG))
		return PARSE_AVC_MSG;
	else 
		return PARSE_NON_SELINUX;
}

static int get_line(FILE *audit_file , char **dest)
{
	char *line = NULL;
	int length = 0;
	char c = '\0';
	int i = 0;

	while ((c = fgetc(audit_file)) != EOF) {
		if (i < length - 1) {
			line[i] = c;
		} else {
			length += PARSE_MAX_MSG_LEN;
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
			length += PARSE_MAX_MSG_LEN;
			if ((line = (char*) realloc(line, length * sizeof(char))) == NULL){
				return PARSE_MEMORY_ERROR;
			}
			line[i] = '\0';
			*dest = *(&line);
		}
	}
	
	return PARSE_SUCCESS;
}


static char *is_prefix(char *token, char *prefix)
{
	bool_t is_match = TRUE;
	int i = 0;
	int length;
	length = strlen(prefix);

	if (strlen(token) < length)
		return NULL;

	for (i = 0 ; i < length ; i++){
		if (token[i] != prefix[i]){
			is_match = FALSE;
			break;
		}
	}
	if (!is_match)
		return NULL;
	else
		return &token[length];
}

static int insert_perms(char **tokens, msg_t *msg, audit_log_t *log)
{
	int i = 0;
	int num_perms = 0;
	int id = 0;

	if (strcmp(tokens[PARSE_PERM_START], "{")) {
		return PARSE_INVALID_MSG_WARN;
	}

	for (i = PARSE_PERM_START + 1 ; i < PARSE_NUM_FIELDS && (strcmp(tokens[i], "}") != 0) ; i++) {
		num_perms++;
	}
	if (i == PARSE_NUM_FIELDS)
		return PARSE_INVALID_MSG_WARN;

	msg->msg_data.avc_msg->num_perms = num_perms;

	if ((msg->msg_data.avc_msg->perms = (int*) malloc(num_perms * sizeof(int))) == NULL){
		return PARSE_MEMORY_ERROR;
	}

	for (i = 0 ; i < num_perms ; i++) {
		if(audit_log_add_perm(log, tokens[i+ (PARSE_PERM_START +1)], &id) == -1)
			return PARSE_MEMORY_ERROR;
		msg->msg_data.avc_msg->perms[i] = id;
	}
	return PARSE_SUCCESS;
}


static int insert_time(char **tokens, msg_t *msg)
{
	char *time = NULL;
	time = strcat(tokens[0], " ");
	time = strcat(time, tokens[1]);
	time = strcat(time, " " );
	time = strcat(time, tokens[2]);
   
	if (!msg->date_stamp) {
		if ((msg->date_stamp = (struct tm*) malloc(sizeof(struct tm))) == NULL)
			return PARSE_MEMORY_ERROR;
	}

	if (!strptime(time, "%b %d %T", msg->date_stamp)) {     
		return PARSE_INVALID_MSG_WARN;
	   
	} else {
		/* random year to make mktime happy */
		msg->date_stamp->tm_year = 2000 - 1900;
		return PARSE_SUCCESS;
	}
	
}

static int insert_avc_type(char *token, msg_t *msg) 
{
	if (strcmp(token, "granted") == 0) {
		msg->msg_data.avc_msg->msg = AVC_GRANTED;
		return PARSE_SUCCESS;
	} else if (strcmp(token, "denied") == 0) {
		msg->msg_data.avc_msg->msg = AVC_DENIED;
		return PARSE_SUCCESS;
	} else
		return PARSE_INVALID_MSG_WARN;     
}


static int insert_capability(char *token, msg_t *msg, char **tmp)
{
	*tmp = is_prefix(token , "capability=");
	if (*tmp != NULL) {		
		msg->msg_data.avc_msg->capability = atoi(*tmp);
		msg->msg_data.avc_msg->is_capability = TRUE;
		return PARSE_SUCCESS;
	} else
		return PARSE_NOT_MATCH;
}


static int insert_ino(char *token, msg_t *msg, char **tmp)
{
	*tmp = is_prefix(token, "ino=");
	if (*tmp != NULL) {
		msg->msg_data.avc_msg->inode = atoi(*tmp);
		msg->msg_data.avc_msg->is_inode = TRUE;
		return PARSE_SUCCESS;
	} else
		return PARSE_NOT_MATCH;
}

static int insert_key(char *token, msg_t *msg, char **tmp)
{
	*tmp = is_prefix(token, "key=");
	if (*tmp != NULL) {		
		msg->msg_data.avc_msg->key = atoi(*tmp);
		msg->msg_data.avc_msg->is_key = TRUE;
		return PARSE_SUCCESS;
	} else
		return PARSE_NOT_MATCH;
}

static int insert_tclass(char *token, msg_t *msg, char **tmp, audit_log_t *log)
{
	int id = -1;
	*tmp = is_prefix(token, "tclass=");
	if (*tmp != NULL) {
		if (audit_log_add_obj(log, *tmp, &id) == -1)
			return PARSE_MEMORY_ERROR;
		msg->msg_data.avc_msg->obj_class = id;
		return PARSE_SUCCESS;
	} else 
		return PARSE_NOT_MATCH;

}

static int parse_context(char *token, char *user, char *role, char *type)
{
/* scontex= or tcontext= will already be removed so i am left with user:role:type */

	int i = 0;
	char *fields[PARSE_NUM_CONTEXT_FIELDS];

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

static int insert_tcon(char *token, msg_t *msg, char **tmp, audit_log_t *log)
{
	char *user = NULL;
	char *role = NULL;
	char *type = NULL;
	int id = -1;
	int length;

	*tmp = is_prefix(token, "tcontext=");
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

static int insert_scon(char *token, msg_t *msg, char **tmp, audit_log_t *log)
{
	char *user = NULL;
	char *role = NULL;
	char *type = NULL;
	int id = -1;
	int length;

	*tmp = is_prefix(token, "scontext=");
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

static int insert_string(char *token, char *type, char **dest, char **src)
{
	*src = is_prefix(token, type);
	if (*src != NULL) {

		if ((*dest = (char*) malloc((strlen(*src) + 1) *sizeof(char))) == NULL)
			return PARSE_MEMORY_ERROR;

		strcpy(*dest, *src);
		return PARSE_SUCCESS;
	} else
		return PARSE_NOT_MATCH;

}

static int insert_hostname(audit_log_t *log, char **tokens, msg_t *msg)
{
        int id;

        if (audit_log_add_host(log, tokens[PARSE_HOST_POSITION], &id) == -1)
                return PARSE_MEMORY_ERROR;
        else{
                msg->host = id;
                return PARSE_SUCCESS;
        }
}

static int insert_int(char *token, char *type, int *dest, char **src)
{
	*src = is_prefix(token, type);
	if (*src != NULL) {		
		*dest = atoi(*src);
		return PARSE_SUCCESS;
	} else
		return PARSE_NOT_MATCH;

}

static int search_tokens(char **tokens, msg_t *msg , audit_log_t *log)
{
	int i = 0;
	char *result = NULL;
	int found[AVC_NUM_FIELDS];
	int return_val = PARSE_SUCCESS;

	for (i = 0 ; i < AVC_NUM_FIELDS ; i++)
		found[i] = PARSE_NOT_MATCH;

	msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_FS;

	for (i = PARSE_AVC_AFTER_FOR + msg->msg_data.avc_msg->num_perms ; i < PARSE_NUM_FIELDS && strcmp(*(&tokens[i]), "") != 0 ; i++) {
		if (found[AVC_PID_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_PID_FIELD] = insert_int(*(&tokens[i]), "pid=", &msg->msg_data.avc_msg->pid, &result);
			if (found[AVC_PID_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_EXE_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_EXE_FIELD] = insert_string(*(&tokens[i]), "exe=", &msg->msg_data.avc_msg->exe, &result);
			if (found[AVC_EXE_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		
		if (found[AVC_COMM_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_COMM_FIELD] = insert_string(*(&tokens[i]), "comm=", &msg->msg_data.avc_msg->comm, &result);
			if (found[AVC_COMM_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		if (found[AVC_PATH_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_PATH_FIELD] = insert_string(*(&tokens[i]), "path=", &msg->msg_data.avc_msg->path, &result);
			if (found[AVC_PATH_FIELD] == PARSE_MEMORY_ERROR){
				return PARSE_MEMORY_ERROR;
			}
		}

		if (found[AVC_NAME_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_NAME_FIELD] = insert_string(*(&tokens[i]), "name=", &msg->msg_data.avc_msg->name, &result);
			if (found[AVC_NAME_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

       
		if (found[AVC_DEV_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_DEV_FIELD] = insert_string(*(&tokens[i]), "dev=", &msg->msg_data.avc_msg->dev, &result);
			if (found[AVC_DEV_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_SADDR_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_SADDR_FIELD] = insert_string(*(&tokens[i]), "saddr=", &msg->msg_data.avc_msg->saddr, &result);
			if (found[AVC_SADDR_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_SOURCE_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_SOURCE_FIELD] = insert_int(*(&tokens[i]), "source=", &msg->msg_data.avc_msg->source, &result);
			if (found[AVC_SOURCE_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_DADDR_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_DADDR_FIELD] = insert_string(*(&tokens[i]), "daddr=", &msg->msg_data.avc_msg->daddr, &result);
			if (found[AVC_DADDR_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_DEST_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_DEST_FIELD] = insert_int(*(&tokens[i]), "dest=", &msg->msg_data.avc_msg->dest, &result);
			if (found[AVC_DEST_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		
		if (found[AVC_NETIF_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_NETIF_FIELD] = insert_string(*(&tokens[i]), "netif=", &msg->msg_data.avc_msg->netif, &result);
			if (found[AVC_NETIF_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			if (found[AVC_NETIF_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_LADDR_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_LADDR_FIELD] = insert_string(*(&tokens[i]), "laddr=", &msg->msg_data.avc_msg->laddr, &result);
			if (found[AVC_LADDR_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_LPORT_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_LPORT_FIELD] = insert_int(*(&tokens[i]), "lport=", &msg->msg_data.avc_msg->lport, &result);
			if (found[AVC_LPORT_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			else if (found[AVC_LPORT_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_FADDR_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_FADDR_FIELD] = insert_string(*(&tokens[i]), "faddr=", &msg->msg_data.avc_msg->faddr, &result);
			if (found[AVC_FADDR_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_FPORT_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_FPORT_FIELD] = insert_int(*(&tokens[i]), "fport=", &msg->msg_data.avc_msg->fport, &result);
			if (found[AVC_FPORT_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_PORT_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_PORT_FIELD] = insert_int(*(&tokens[i]), "port=", &msg->msg_data.avc_msg->port, &result);
			if (found[AVC_PORT_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			else if (found[AVC_PORT_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_CAPABILITY_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_CAPABILITY_FIELD] = insert_capability(*(&tokens[i]), msg, &result);
			if (found[AVC_CAPABILITY_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_CAP;
			else if (found[AVC_CAPABILITY_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_KEY_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_KEY_FIELD] = insert_key(*(&tokens[i]), msg, &result);
			if (found[AVC_KEY_FIELD] == PARSE_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_IPC;
			else if (found[AVC_KEY_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_INODE_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_INODE_FIELD] = insert_ino(*(&tokens[i]), msg, &result);
			if (found[AVC_INODE_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
	  
		if (found[AVC_SRC_USER_FIELD] == PARSE_NOT_MATCH && result == NULL){
			found[AVC_SRC_USER_FIELD] = insert_scon(*(&tokens[i]), msg, &result, log);
			if (found[AVC_SRC_USER_FIELD] == PARSE_MALFORMED_MSG_WARN) {
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
				return_val = PARSE_MALFORMED_MSG_WARN;
			}
			if (found[AVC_SRC_USER_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
	      
		if (found[AVC_SRC_SID_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_SRC_SID_FIELD] = insert_int(*(&tokens[i]), "ssid=", &msg->msg_data.avc_msg->src_sid, &result);
			if (found[AVC_SRC_SID_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		
		if (found[AVC_TGT_USER_FIELD] == PARSE_NOT_MATCH && result == NULL){
			found[AVC_TGT_USER_FIELD] = insert_tcon(*(&tokens[i]), msg, &result, log);
			if (found[AVC_SRC_USER_FIELD] == PARSE_MALFORMED_MSG_WARN) {
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
				return_val = PARSE_MALFORMED_MSG_WARN;
			}
			if (found[AVC_TGT_USER_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}

		if (found[AVC_TGT_SID_FIELD] == PARSE_NOT_MATCH && result == NULL) {
			found[AVC_TGT_SID_FIELD] = insert_int(*(&tokens[i]) , "tsid=", &msg->msg_data.avc_msg->tgt_sid , &result);
			if (found[AVC_TGT_SID_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
	       
		if (found[AVC_OBJ_CLASS_FIELD] == PARSE_NOT_MATCH && result == NULL){
			found[AVC_OBJ_CLASS_FIELD] = insert_tclass(*(&tokens[i]), msg, &result, log);
			if (found[AVC_OBJ_CLASS_FIELD] == PARSE_MEMORY_ERROR)
			    return PARSE_MEMORY_ERROR;
		}
		if (result == NULL){
			msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
			return_val = PARSE_MALFORMED_MSG_WARN;
		}
		result = NULL;
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



static int create_avc(char **tokens, msg_t *msg, audit_log_t *log)
{
	int result;
/*   Insert time */

	result = insert_time(*(&tokens), msg);
	if (result != PARSE_SUCCESS) {
		return result;
	}

/*   Insert hostname */
	result = insert_hostname(log, *(&tokens), msg);
	if (result != PARSE_SUCCESS) {
	        return result;
	}

/*   Insert denied or granted    */
	result = insert_avc_type(*(&tokens[PARSE_MSG_AFTER_HEADER]), msg);
	if (result != PARSE_SUCCESS ) {
		return result;
	}

/* insert perm(s) */
	result = insert_perms(tokens, msg, log);
	if (result != PARSE_SUCCESS) {
		return result;
	}
      
	if (strcmp(tokens[PARSE_PERM_START + msg->msg_data.avc_msg->num_perms + 2], "for") != 0)
		return PARSE_INVALID_MSG_WARN;

/*    Insert everything else    */

	result =  search_tokens(tokens, msg, log);

	return result;
}

static int get_tokens(char *line, int msgtype, audit_log_t *log, FILE *audit_file, msg_t **msg);

static int create_load(char **tokens, msg_t **msg, FILE *audit_file, audit_log_t *log)
{
	char *next_line = NULL;
	char old_load[OLD_LOAD_HEADER_LEN];
	char *tmp = NULL;
	int length = 0;
	int i=0;
	int result;
	bool_t found[5];


	if (strcmp(tokens[5], "security:"))
		return PARSE_INVALID_MSG_WARN;

	for (i = 0 ; i < 5 ; i++)
		found[i] = FALSE;

	result = insert_time(*(&tokens), *msg);
	if (result != PARSE_SUCCESS) {
		return result;
	}

	result = insert_hostname(log, *(&tokens), *msg);
	if (result != PARSE_SUCCESS) {
	        return result;
	}

	if (strcmp(tokens[PARSE_MSG_AFTER_HEADER], "invalidating") == 0) {
		return PARSE_LOAD_FALSE_POS;
	}
 

	if (strcmp(tokens[PARSE_MSG_AFTER_HEADER + 1], "bools") == 0) {
		return PARSE_LOAD_FALSE_POS;
	}

	strcpy(old_load, "loadingpolicyconfigurationfrom");

	for (i = 0 ; i < 4 ; i++)
		length += strlen(tokens[PARSE_MSG_AFTER_HEADER + i]);

	
	if ((tmp = (char*) malloc((length + 1) * sizeof(char))) == NULL) {
		return PARSE_MEMORY_ERROR;
	}

	tmp[0] = '\0';
       
	for (i = 0 ; i < 4 ; i ++){
		tmp = strcat(tmp, tokens[PARSE_MSG_AFTER_HEADER+i]);
	}

	if (strcmp( tmp, old_load ) == 0) {
		free(tmp);
		length = strlen(tokens[PARSE_BINARY_POSITION]) + 1;

		if (((*msg)->msg_data.load_policy_msg->binary = (char*) malloc(length * sizeof(char))) == NULL) {
			return PARSE_MEMORY_ERROR;
		}
		strcpy((*msg)->msg_data.load_policy_msg->binary, tokens[PARSE_BINARY_POSITION]);
		
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
	free(tmp);

	if (strcmp(tokens[PARSE_MSG_AFTER_HEADER+1], "classes,") == 0){
		found[3] = TRUE;
		(*msg)->msg_data.load_policy_msg->classes = atoi(tokens[PARSE_MSG_AFTER_HEADER]); 
	}

	if (strcmp(tokens[PARSE_MSG_AFTER_HEADER+3], "rules") == 0){
		found[4] = TRUE;
		(*msg)->msg_data.load_policy_msg->rules = atoi(tokens[PARSE_MSG_AFTER_HEADER +2]); 
	}
	if (found[3] && found[4]){
		if ((*msg)->msg_data.load_policy_msg->users != 0)
			return PARSE_SUCCESS;
		else
			return PARSE_INVALID_MSG_WARN;
	}
	if ((*msg)->msg_data.load_policy_msg->types != 0)
		return PARSE_INVALID_MSG_WARN;




	if (strcmp(tokens[PARSE_MSG_AFTER_HEADER+1], "users,") == 0){
		found[0] = TRUE;
		(*msg)->msg_data.load_policy_msg->users = atoi(tokens[PARSE_MSG_AFTER_HEADER]);
	}

	if (strcmp(tokens[PARSE_MSG_AFTER_HEADER+3], "roles,") == 0){
		found[1] = TRUE;
		(*msg)->msg_data.load_policy_msg->roles = atoi(tokens[PARSE_MSG_AFTER_HEADER +2]);
	}

	if (strcmp(tokens[PARSE_MSG_AFTER_HEADER+5], "types") == 0){
		found[2] = TRUE;
		(*msg)->msg_data.load_policy_msg->types = atoi(tokens[PARSE_MSG_AFTER_HEADER +4]); 
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

        if (token[len - 1] == ','){
                token[len - 1] = '\0';
                len--;
        }

        if (token[len - 2] != ':')
                return PARSE_INVALID_MSG_WARN;

        if (token[len-1] == '0')
                *val = FALSE;
        else if (token[len-1] == '1')
                *val = TRUE;
        else
                return PARSE_INVALID_MSG_WARN;

        token[len - 2] = '\0';

        if (audit_log_add_bool(log, token, bool) == -1)
                return PARSE_MEMORY_ERROR;
 
        return PARSE_SUCCESS;
}

static int create_boolean(char **tokens, msg_t **msg, audit_log_t *log)
{
        int result;
	int i;
	int num_bools = 0;
	int *booleans = NULL;
	bool_t *values = NULL;
	int bool;
	bool_t val;


	if(strcmp(tokens[PARSE_BOOL_SECURITY_POSITION], "security:"))
	        return PARSE_INVALID_MSG_WARN;
	if(strcmp(tokens[PARSE_BOOL_SECURITY_POSITION + 1], "committed"))
	        return PARSE_INVALID_MSG_WARN;
	if(strcmp(tokens[PARSE_BOOL_SECURITY_POSITION + 2], "booleans"))
	        return PARSE_INVALID_MSG_WARN;
	if(strcmp(tokens[PARSE_BOOL_START_BOOLS - 1], "{"))
	        return PARSE_INVALID_MSG_WARN;

	result = insert_time(*(&tokens), *msg);
	if (result != PARSE_SUCCESS) {
		return result;
	}

	result = insert_hostname(log, *(&tokens), *msg);
	if (result != PARSE_SUCCESS) {
	        return result;
	}


	for (i = PARSE_BOOL_START_BOOLS ; i < PARSE_NUM_FIELDS && (strcmp(tokens[i], "}") != 0) ; i++) {
		num_bools++;
	}
	if (i == PARSE_NUM_FIELDS){
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
		result = get_bool(tokens[i + PARSE_BOOL_START_BOOLS], &bool, &val, log);
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

static int get_tokens(char *line, int msgtype, audit_log_t *log, FILE *audit_file, msg_t **msg)
{
	char *tokens = NULL;
	int i = 0;
	char *fields[PARSE_NUM_FIELDS];
	char *tmp = NULL;
	int result = -1;
	int length = 0;

	for (i = 0 ; i < PARSE_NUM_FIELDS ; i++) {
		if ((fields[i] = (char*) malloc((strlen(line) + 1) * sizeof(char))) == NULL) {
			for ( i = i-1 ; i >= 0 ; i--)
				free(fields[i]);
			return PARSE_MEMORY_ERROR;
		}
		strcpy(fields[i], "");
	}

	tokens = line;

	length = strlen(tokens);
	while (!ispunct(tokens[length - 1]) && !isalnum(tokens[length - 1])){
		tokens[length - 1] = '\0';
		length -=1;
	}

	i = 0;
        while ((tmp = strsep(&tokens, " ")) != NULL && i < PARSE_NUM_FIELDS) {
	       	if (strcmp(tmp, "")) {
     	       		strcpy(fields[i], tmp);
       	       		i++;
       	       	}
        }

	if (i == PARSE_NUM_FIELDS) {
		for (i = 0 ; i < PARSE_NUM_FIELDS ; i++){
			if (fields != NULL)
				free(fields[i]);
		}
		return PARSE_INVALID_MSG_WARN;
	}


	if (msgtype == PARSE_BOOL_MSG) {
	        *msg = boolean_msg_create();
	        result = create_boolean(fields, msg, log);
		if (result == PARSE_INVALID_MSG_WARN || result == PARSE_MEMORY_ERROR) {
			msg_destroy(*msg); 
			*msg = NULL;
			for (i = 0 ; i < PARSE_NUM_FIELDS ; i++) {
				if (fields != NULL)
					free(fields[i]);
			}
			return result;
		} else {
			if (audit_log_add_msg(log, *msg) == -1){
				for (i = 0 ; i < PARSE_NUM_FIELDS ; i++) {
					if (fields != NULL)
						free(fields[i]);
				}				
				return PARSE_MEMORY_ERROR;
			}       
			*msg = NULL;
	        }      
	} else if (msgtype == PARSE_AVC_MSG) {
       		*msg = avc_msg_create();
		result = create_avc(fields, *msg, log);
		if (result == PARSE_INVALID_MSG_WARN || result == PARSE_MEMORY_ERROR) {
			msg_destroy(*msg); 
			*msg = NULL;
			for (i = 0 ; i < PARSE_NUM_FIELDS ; i++) {
				if (fields != NULL)
					free(fields[i]);
			}
			return result;
		} else {
			if (audit_log_add_msg(log, *msg) == -1){
				for (i = 0 ; i < PARSE_NUM_FIELDS ; i++) {
					if (fields != NULL)
						free(fields[i]);
				}				
				return PARSE_MEMORY_ERROR;
			}
			*msg = NULL;
		}
	} else if (msgtype == PARSE_LOAD_MSG) {
		if (*msg == NULL){
			*msg = load_policy_msg_create();
		}
		
		result = create_load(fields, msg, audit_file, log);
		if (result == PARSE_MEMORY_ERROR || result == PARSE_INVALID_MSG_WARN || result == PARSE_LOAD_FALSE_POS) {
			msg_destroy(*msg);
			*msg = NULL;
			for (i = 0 ; i < PARSE_NUM_FIELDS ; i++){
				if (fields != NULL)
					free(fields[i]);
			}
			return result;
		} else if (result == PARSE_SUCCESS) {
			if (audit_log_add_msg(log, *msg) == -1) {
				for (i = 0 ; i < PARSE_NUM_FIELDS ; i++) {
					if (fields != NULL)
						free(fields[i]);
				}
				return PARSE_MEMORY_ERROR;
			}
			*msg = NULL;
		}
	}
	
	for (i = 0 ; i < PARSE_NUM_FIELDS ; i++){
		if (fields != NULL)
			free(fields[i]);
	}
	return result;
}


int parse_audit(FILE *syslog, audit_log_t *log)
{
	FILE *audit_file = syslog;
	char *line = NULL;
	int is_sel = -1;
	msg_t *msg = NULL;
	int result = 0;
	int selinux_msg = 0;
	int tmp;

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
			tmp = get_tokens(line, is_sel, log, audit_file, &msg);
			if (tmp == PARSE_INVALID_MSG_WARN && result != PARSE_BOTH_MSG_WARN){
			        if (result == PARSE_MALFORMED_MSG_WARN)
			                result = PARSE_BOTH_MSG_WARN;
			        else
			                result = PARSE_INVALID_MSG_WARN;
			}
			if (tmp == PARSE_MALFORMED_MSG_WARN && result != PARSE_BOTH_MSG_WARN){
			        if (result == PARSE_INVALID_MSG_WARN)
			                result = PARSE_BOTH_MSG_WARN;
			        else
			                result = PARSE_MALFORMED_MSG_WARN;
			}
			if (tmp == PARSE_MEMORY_ERROR){
				return tmp;
			}
			if (tmp != PARSE_LOAD_FALSE_POS && tmp != PARSE_INVALID_MSG_WARN)
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














