/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 * Date: February 06, 2004
 *
 * This file contains the implementation of filter_criteria.h
 *
 * filter_criteria.c
 */

#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <fnmatch.h>
#include <libxml/uri.h>
#include "filter_criteria.h"
#include "auditlog.h"
#include "sort.h"

typedef struct strs_criteria {
	char **strs;
	int num_strs;
	int *indexes;
} strs_criteria_t;

typedef strs_criteria_t type_criteria_t;
typedef strs_criteria_t role_criteria_t;
typedef strs_criteria_t user_criteria_t;
typedef strs_criteria_t class_criteria_t;

typedef struct glob_criteria {
	char *globex;
} glob_criteria_t;

typedef glob_criteria_t exe_criteria_t;
typedef glob_criteria_t path_criteria_t;
typedef glob_criteria_t ipaddr_criteria_t;
typedef glob_criteria_t host_criteria_t;
typedef glob_criteria_t comm_criteria_t;

typedef struct msg_criteria {
	int val;	/* AVC_DENIED or AVC_GRANTED */
} msg_criteria_t;

typedef struct ports_criteria {
	int val;
} ports_criteria_t;

typedef struct netif_criteria {
	char *netif;
} netif_criteria_t;

typedef struct date_time_criteria {
	struct tm *start;
	struct tm *end;
	int option;
} date_time_criteria_t;


const char *netif_criteria_get_str(seaudit_criteria_t *criteria)
{
	netif_criteria_t *netif_criteria;
	
	if (!criteria)
		return NULL;
	netif_criteria = (netif_criteria_t*)criteria->data;
	return (const char*)netif_criteria->netif;
}

const char *glob_criteria_get_str(seaudit_criteria_t *criteria)
{
	glob_criteria_t *glob_criteria;
	
	if (!criteria)
		return NULL;
	glob_criteria = (glob_criteria_t*)criteria->data;
	return (const char*)glob_criteria->globex;
}

const char **strs_criteria_get_strs(seaudit_criteria_t *criteria, int *size)
{
	strs_criteria_t *strs_criteria;

	if (!criteria)
		return NULL;

	strs_criteria = (strs_criteria_t*)criteria->data;
	*size = strs_criteria->num_strs;
	return (const char**)strs_criteria->strs;
}

int ports_criteria_get_val(seaudit_criteria_t *criteria)
{
	ports_criteria_t *ports_criteria;
	
	if (!criteria)
		return -1;
	ports_criteria = (ports_criteria_t*)criteria->data;
	assert(ports_criteria);
	return ports_criteria->val;
}

const struct tm *date_time_criteria_get_date(seaudit_criteria_t *criteria, bool_t start)
{
	date_time_criteria_t *dtc = NULL;
	if (!criteria || !criteria->data)
		return NULL;
	dtc = (date_time_criteria_t *)criteria->data;
	if (start)
		return (const struct tm*)dtc->start;
	else
		return (const struct tm*)dtc->end;
}

int date_time_criteria_get_option(seaudit_criteria_t *criteria)
{
	date_time_criteria_t *dtc = NULL;
	if (!criteria || !criteria->data)
		return 0;
	dtc = (date_time_criteria_t *)criteria->data;
	return dtc->option;
}

static bool_t date_time_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	date_time_criteria_t *dt_criteria;
	int rt;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;
	dt_criteria = (date_time_criteria_t *)criteria->data;

	rt = date_time_compare(dt_criteria->start, msg->date_stamp);
	if (dt_criteria->option == FILTER_CRITERIA_DT_OPTION_BEFORE) {
		return   rt > 0 ? TRUE : FALSE;
	} else if (dt_criteria->option == FILTER_CRITERIA_DT_OPTION_AFTER) {
		return   rt < 0 ? TRUE : FALSE;
	} else {
		if (rt > 0)
			return FALSE;
		rt = date_time_compare(dt_criteria->end, msg->date_stamp);
		return rt < 0 ? FALSE : TRUE;
	}
}

static void date_time_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	date_time_criteria_t *dt_criteria;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	dt_criteria = (date_time_criteria_t*)criteria->data;
	if (tabs < 0) 
		tabs = 0;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"date_time\">\n");
	str_xml = xmlCharStrdup(asctime(dt_criteria->start));
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%s</item>\n", escaped);
	free(escaped);
	free(str_xml);
	str_xml = xmlCharStrdup(asctime(dt_criteria->end));
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%s</item>\n", escaped);
	free(escaped);
	free(str_xml);
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%d</item>\n", dt_criteria->option);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

int msg_criteria_get_val(seaudit_criteria_t *criteria)
{
	msg_criteria_t *msg_criteria;
	
	if (!criteria)
		return -1;
	msg_criteria = (msg_criteria_t*)criteria->data;
	assert(msg_criteria);
	return msg_criteria->val;
}

static bool_t netif_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	netif_criteria_t *netif_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	netif_criteria = (netif_criteria_t*)criteria->data;
	if (!netif_criteria->netif || !msg->msg_data.avc_msg->netif)
		return FALSE;
	return strcmp(netif_criteria->netif, msg->msg_data.avc_msg->netif) == 0 ? TRUE : FALSE;
}

static void netif_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	netif_criteria_t *netif_criteria;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	netif_criteria = (netif_criteria_t*)criteria->data;
	if (tabs < 0) 
		tabs = 0;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	str_xml = xmlCharStrdup(netif_criteria->netif);
	escaped = xmlURIEscapeStr(str_xml, NULL);
	fprintf(stream, "<criteria type=\"netif\">\n");
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%s</item>\n", escaped);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
	free(escaped);
	free(str_xml);
}

static bool_t ports_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	ports_criteria_t *ports_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	ports_criteria = (ports_criteria_t*)criteria->data;
	if (ports_criteria->val == msg->msg_data.avc_msg->port)
		return TRUE;
	if (ports_criteria->val == msg->msg_data.avc_msg->source)
		return TRUE;
	if (ports_criteria->val == msg->msg_data.avc_msg->dest)
		return TRUE;
	if (ports_criteria->val == msg->msg_data.avc_msg->fport)
		return TRUE;
	if (ports_criteria->val == msg->msg_data.avc_msg->lport)
		return TRUE;
	return FALSE;
}

static void ports_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	ports_criteria_t *ports_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	if (tabs < 0)
		tabs = 0;
	ports_criteria = (ports_criteria_t*)criteria->data;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"port\">\n");
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%d</item>\n", ports_criteria->val);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

static bool_t msg_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	msg_criteria_t *msg_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	msg_criteria = (msg_criteria_t*)criteria->data;
	if (msg_criteria->val == msg->msg_data.avc_msg->msg)
		return TRUE;
	return FALSE;
}

static void msg_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	msg_criteria_t *msg_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	if (tabs < 0)
		tabs = 0;
	msg_criteria = (msg_criteria_t*)criteria->data;

	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"msg\">\n");
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%d</item>\n", msg_criteria->val);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

static bool_t ipaddr_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	ipaddr_criteria_t *ipaddr_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	ipaddr_criteria = (ipaddr_criteria_t*)criteria->data;
	if (!ipaddr_criteria->globex)
		return FALSE;
	if (msg->msg_data.avc_msg->saddr)
		if (fnmatch(ipaddr_criteria->globex, msg->msg_data.avc_msg->saddr, 0) == 0)
			return TRUE;
	if (msg->msg_data.avc_msg->daddr)
		if (fnmatch(ipaddr_criteria->globex, msg->msg_data.avc_msg->daddr, 0) == 0)
			return TRUE;
	if (msg->msg_data.avc_msg->faddr)
		if (fnmatch(ipaddr_criteria->globex, msg->msg_data.avc_msg->faddr, 0) == 0)
			return TRUE;
	if (msg->msg_data.avc_msg->laddr)
		if (fnmatch(ipaddr_criteria->globex, msg->msg_data.avc_msg->laddr, 0) == 0)
			return TRUE;
	return FALSE;
}

static void ipaddr_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	ipaddr_criteria_t *ipaddr_criteria;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	if (tabs < 0)
		tabs = 0;
	ipaddr_criteria = (ipaddr_criteria_t*)criteria->data;
	str_xml = xmlCharStrdup(ipaddr_criteria->globex); 
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"ipaddr\">\n");
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%s</item>\n", escaped);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
	free(escaped);
	free(str_xml);
}

static bool_t host_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	host_criteria_t *host_criteria;
	const char *host;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	host_criteria = (host_criteria_t*)criteria->data;
	host = audit_log_get_host(log, msg->host);
	if (!host)
		return FALSE;
	return (fnmatch(host_criteria->globex, host, 0)==0);
}

static void host_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	host_criteria_t *host_criteria;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	if (tabs < 0)
		tabs = 0;
	host_criteria = (host_criteria_t*)criteria->data;
	str_xml = xmlCharStrdup(host_criteria->globex);
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"host\">\n");
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%s</item>\n", escaped);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
	free(escaped);
	free(str_xml);
}

static bool_t comm_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)  
{ 
	comm_criteria_t *comm_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL || !msg->msg_data.avc_msg->comm)
		return FALSE;

	comm_criteria = (comm_criteria_t*)criteria->data;
	if (!comm_criteria->globex)
		return FALSE;
	if (fnmatch(comm_criteria->globex, msg->msg_data.avc_msg->comm, 0) == 0)
		return TRUE;
	return FALSE;
} 

static void comm_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	comm_criteria_t *comm_criteria;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	comm_criteria = (comm_criteria_t*)criteria->data;
	str_xml = xmlCharStrdup(comm_criteria->globex);
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"comm\">\n");
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%s</item>\n", escaped);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
	free(escaped);
	free(str_xml);
}

static bool_t exe_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)  
{ 
	exe_criteria_t *exe_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL || !msg->msg_data.avc_msg->exe)
		return FALSE;

	exe_criteria = (exe_criteria_t*)criteria->data;
	if (!exe_criteria->globex)
		return FALSE;
	if (fnmatch(exe_criteria->globex, msg->msg_data.avc_msg->exe, 0) == 0)
		return TRUE;
	return FALSE;
} 

static void exe_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	exe_criteria_t *exe_criteria;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	exe_criteria = (exe_criteria_t*)criteria->data;
	str_xml = xmlCharStrdup(exe_criteria->globex);
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"exe\">\n");
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%s</item>\n", escaped);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
	free(escaped);
	free(str_xml);
}

static bool_t path_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)  
{ 
	path_criteria_t *path_criteria;

	if (msg == NULL || criteria == NULL || criteria->data == NULL || !msg->msg_data.avc_msg->path)
		return FALSE;

	path_criteria = (path_criteria_t*)criteria->data;
	if (!path_criteria->globex)
		return FALSE;
	if (fnmatch(path_criteria->globex, msg->msg_data.avc_msg->path, 0) == 0)
		return TRUE;
	return FALSE;
} 

static void path_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	path_criteria_t *path_criteria;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	path_criteria = (path_criteria_t*)criteria->data;
	str_xml = xmlCharStrdup(path_criteria->globex);
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"path\">\n");
	for (i = 0; i < tabs+1; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<item>%s</item>\n", escaped);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
	free(escaped);
	free(str_xml);
}

static bool_t src_user_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i;
	user_criteria_t *user_criteria;
	const char *user;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	user = audit_log_get_user(log, msg->msg_data.avc_msg->src_user);
	if (!user)
		return FALSE;
	user_criteria = (user_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < user_criteria->num_strs; i++)
			user_criteria->indexes[i] = audit_log_get_user_idx(log, user_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < user_criteria->num_strs; i++) { 
		if (user_criteria->indexes[i] == -1)
			if (fnmatch(user_criteria->strs[i], user, 0) == 0)
				return TRUE;			
		if (user_criteria->indexes[i] == msg->msg_data.avc_msg->src_user)
			return TRUE; 
	} 
	return FALSE;
}

static void strs_criteria_print(strs_criteria_t *strs_criteria, FILE *stream, int tabs)
{
	int i, j;
	xmlChar *escaped;
	xmlChar *str_xml;

	if (!strs_criteria)
		return;
	for (i = 0; i < strs_criteria->num_strs; i++) {
		str_xml = xmlCharStrdup(strs_criteria->strs[i]);
		escaped = xmlURIEscapeStr(str_xml, NULL);
		for (j = 0; j < tabs; j++)
			fprintf(stream, "\t");
		fprintf(stream, "<item>%s</item>\n", escaped);
		free(escaped);
		free(str_xml);
	}
}

static void src_user_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	user_criteria_t *user_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	user_criteria = (user_criteria_t*)criteria->data;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"src_user\">\n");
	strs_criteria_print(user_criteria, stream, tabs+1);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

static bool_t tgt_user_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i;
	user_criteria_t *user_criteria;
	const char *user;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	user = audit_log_get_user(log, msg->msg_data.avc_msg->tgt_user);
	if (!user)
		return FALSE;
	user_criteria = (user_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < user_criteria->num_strs; i++)
			user_criteria->indexes[i] = audit_log_get_user_idx(log, user_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < user_criteria->num_strs; i++) { 
		if (user_criteria->indexes[i] == -1)
			if (fnmatch(user_criteria->strs[i], user, 0) == 0)
				return TRUE;
		if (user_criteria->indexes[i] == msg->msg_data.avc_msg->tgt_user)
			return TRUE; 
	} 
	return FALSE;
}

static void tgt_user_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	user_criteria_t *user_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	user_criteria = (user_criteria_t*)criteria->data;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"tgt_user\">\n");
	strs_criteria_print(user_criteria, stream, tabs+1);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

static bool_t src_role_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i; 
	role_criteria_t *role_criteria;
	const char *role;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	role = audit_log_get_role(log, msg->msg_data.avc_msg->src_role);
	if (!role)
		return FALSE;
	role_criteria = (role_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < role_criteria->num_strs; i++)
			role_criteria->indexes[i] = audit_log_get_role_idx(log, role_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < role_criteria->num_strs; i++) { 
		if (role_criteria->indexes[i] == -1)
			if (fnmatch(role_criteria->strs[i], role, 0) == 0)
				return TRUE;		       
		if (role_criteria->indexes[i] == msg->msg_data.avc_msg->src_role) 
			return TRUE; 
	} 
	return FALSE;
}

static void src_role_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	role_criteria_t *role_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	role_criteria = (role_criteria_t*)criteria->data;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"src_role\">\n");
	strs_criteria_print(role_criteria, stream, tabs+1);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

static bool_t tgt_role_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i; 
	role_criteria_t *role_criteria;
	const char *role;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	role = audit_log_get_role(log, msg->msg_data.avc_msg->tgt_role);
	if (!role)
		return FALSE;
	role_criteria = (role_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < role_criteria->num_strs; i++)
			role_criteria->indexes[i] = audit_log_get_role_idx(log, role_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < role_criteria->num_strs; i++) { 
		if (role_criteria->indexes[i] == -1)
			if (fnmatch(role_criteria->strs[i], role, 0) == 0)
				return TRUE;
		if (role_criteria->indexes[i] == msg->msg_data.avc_msg->tgt_role) 
			return TRUE; 
	} 
	return FALSE;
}

static void tgt_role_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	role_criteria_t *role_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	role_criteria = (role_criteria_t*)criteria->data;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"tgt_role\">\n");
	strs_criteria_print(role_criteria, stream, tabs+1);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

static bool_t src_type_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i; 
	type_criteria_t *type_criteria;
	const char *type;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	type = audit_log_get_type(log, msg->msg_data.avc_msg->src_type);
	if (!type)
		return FALSE;
	type_criteria = (type_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < type_criteria->num_strs; i++)
			type_criteria->indexes[i] = audit_log_get_type_idx(log, type_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < type_criteria->num_strs; i++) { 
		if (type_criteria->indexes[i] == -1)
			if (fnmatch(type_criteria->strs[i], type, 0) == 0)
				return TRUE;
		if (type_criteria->indexes[i] == msg->msg_data.avc_msg->src_type)
			return TRUE;
	} 
	return FALSE;
}

static void src_type_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	type_criteria_t *type_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	type_criteria = (type_criteria_t*)criteria->data;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"src_type\">\n");
	strs_criteria_print(type_criteria, stream, tabs+1);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

static bool_t tgt_type_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log)
{
	int i; 
	type_criteria_t *type_criteria;
	const char *type;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	type = audit_log_get_type(log, msg->msg_data.avc_msg->tgt_type);
	if (!type)
		return FALSE;
	type_criteria = (type_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < type_criteria->num_strs; i++)
			type_criteria->indexes[i] = audit_log_get_type_idx(log, type_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < type_criteria->num_strs; i++) { 
		if (type_criteria->indexes[i] == -1)
			if (fnmatch(type_criteria->strs[i], type, 0) == 0)
				return TRUE;
		if (type_criteria->indexes[i] == msg->msg_data.avc_msg->tgt_type)
			return TRUE;
	} 
	return FALSE;
}

static void tgt_type_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	type_criteria_t *type_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	type_criteria = (type_criteria_t*)criteria->data;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"tgt_type\">\n");
	strs_criteria_print(type_criteria, stream, tabs+1);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

static bool_t class_criteria_action(msg_t *msg, seaudit_criteria_t *criteria, audit_log_t *log) 
{ 
	int i; 
	class_criteria_t *class_criteria;
	const char *class;

	if (msg == NULL || criteria == NULL || criteria->data == NULL)
		return FALSE;

	class = audit_log_get_obj(log, msg->msg_data.avc_msg->obj_class);
	if (!class)
		return FALSE;
	class_criteria = (class_criteria_t*)criteria->data;
	if (criteria->dirty == TRUE) {
		for (i = 0; i < class_criteria->num_strs; i++)
			class_criteria->indexes[i] = audit_log_get_obj_idx(log, class_criteria->strs[i]);
	}
	criteria->dirty = FALSE;
	for (i = 0; i < class_criteria->num_strs; i++) { 
		if (class_criteria->indexes[i] == -1)
			if (fnmatch(class_criteria->strs[i], class, 0) == 0)
				return TRUE;
		if (class_criteria->indexes[i] == msg->msg_data.avc_msg->obj_class) 
			return TRUE; 
	} 
	return FALSE;	
} 

static void class_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	class_criteria_t *class_criteria;
	int i;

	if (criteria == NULL || criteria->data == NULL || stream == NULL)
		return;

	class_criteria = (class_criteria_t*)criteria->data;
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "<criteria type=\"obj_class\">\n");
	strs_criteria_print(class_criteria, stream, tabs+1);
	for (i = 0; i < tabs; i++)
		fprintf(stream, "\t");
	fprintf(stream, "</criteria>\n");
}

/*
 * create the container struct */
static seaudit_criteria_t* criteria_create(void)
{
	seaudit_criteria_t *new;

	new = (seaudit_criteria_t*)malloc(sizeof(seaudit_criteria_t));
	if (new == NULL) 
		return NULL;
	memset(new, 0, sizeof(seaudit_criteria_t));
	return new;
}

/*
 * destroy the entire criteria */
void seaudit_criteria_destroy(seaudit_criteria_t *ftr) 
{
	if (ftr == NULL)
		return;
	if (ftr->destroy)
		ftr->destroy(ftr);
	free(ftr);
	return;
}


void seaudit_criteria_print(seaudit_criteria_t *criteria, FILE *stream, int tabs)
{
	if (!criteria || !stream)
		return;
	if (criteria->print)
		criteria->print(criteria, stream, tabs);

}

static void strs_criteria_destroy(strs_criteria_t *strs_criteria)
{
	int i;

	if (strs_criteria->indexes)
		free(strs_criteria->indexes);
	if (strs_criteria->strs) {
		for (i = 0; i < strs_criteria->num_strs; i++) {
			if (strs_criteria->strs[i])
				free(strs_criteria->strs[i]);
		}
		free(strs_criteria->strs);
	}
	free(strs_criteria);	
}

static strs_criteria_t *strs_criteria_create(char **strs, int num_strs)
{
	strs_criteria_t *d;
	int i;

	d = (strs_criteria_t*)malloc(sizeof(strs_criteria_t));
	if (!d) {
		goto bad;
	}
	memset(d, 0, sizeof(type_criteria_t));
	/* alloc strs and deep copy */
	d->strs = (char**)calloc(num_strs, sizeof(char*));
	if (!d->strs) {
		goto bad;
	}
	for (i = 0; i < num_strs; i++) {
		d->strs[i] = strdup(strs[i]);
		if (!d->strs[i])
			goto bad;
	}
	/* alloc indexes */
	d->indexes = (int*)malloc(sizeof(int) * num_strs);
	if (!d->indexes)
		goto bad;
	d->num_strs = num_strs;
	return d;
 bad:
	if (d) {
		if (d->indexes)
			free(d->indexes);
		if (d->strs) {
			for (i = 0; i < num_strs; i++)
				if (d->strs[i])
					free(d->strs[i]);
			free(d->strs);
		}
		free(d);
	}
	return NULL;
}

static void type_criteria_destroy(seaudit_criteria_t* ftr)
{
	type_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (type_criteria_t*)ftr->data;
	strs_criteria_destroy(d);
	return;
}

seaudit_criteria_t* src_type_criteria_create(char **types, int num_types)
{
        seaudit_criteria_t *new_criteria;
	type_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(types, num_types);

	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &src_type_criteria_action; 
	new_criteria->print = &src_type_criteria_print;
	new_criteria->destroy = &type_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

seaudit_criteria_t* tgt_type_criteria_create(char **types, int num_types)
{
        seaudit_criteria_t *new_criteria;
	type_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(types, num_types);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &tgt_type_criteria_action; 
	new_criteria->print = &tgt_type_criteria_print;
	new_criteria->destroy = &type_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

static void role_criteria_destroy(seaudit_criteria_t* ftr)
{
	role_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (role_criteria_t*)ftr->data;
	strs_criteria_destroy(d);
	return;
}

seaudit_criteria_t* src_role_criteria_create(char **roles, int num_roles)
{
        seaudit_criteria_t *new_criteria;
	role_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(roles, num_roles);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &src_role_criteria_action; 
	new_criteria->print = &src_role_criteria_print;
	new_criteria->destroy = &role_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

seaudit_criteria_t* tgt_role_criteria_create(char **roles, int num_roles)
{
        seaudit_criteria_t *new_criteria;
	role_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(roles, num_roles);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &tgt_role_criteria_action; 
	new_criteria->print = &tgt_role_criteria_print;
	new_criteria->destroy = &role_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

static void user_criteria_destroy(seaudit_criteria_t* ftr)
{
	user_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (user_criteria_t*)ftr->data;
	strs_criteria_destroy(d);
	return;
}

seaudit_criteria_t* src_user_criteria_create(char **users, int num_users)
{
        seaudit_criteria_t *new_criteria;
	user_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(users, num_users);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &src_user_criteria_action; 
	new_criteria->print = &src_user_criteria_print;
	new_criteria->destroy = &user_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

seaudit_criteria_t* tgt_user_criteria_create(char **users, int num_users)
{
        seaudit_criteria_t *new_criteria;
	user_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(users, num_users);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &tgt_user_criteria_action; 
	new_criteria->print = &tgt_user_criteria_print;
	new_criteria->destroy = &user_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}


static void class_criteria_destroy(seaudit_criteria_t* ftr)
{
	class_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (class_criteria_t*)ftr->data;
	strs_criteria_destroy(d);
	return;
}

seaudit_criteria_t* class_criteria_create(char **classes, int num_classes)
{
        seaudit_criteria_t *new_criteria;
	class_criteria_t *d;

	new_criteria = criteria_create();
	if (!new_criteria)
		return NULL;
	d = strs_criteria_create(classes, num_classes);
	if (!d) {
		seaudit_criteria_destroy(new_criteria);
		return NULL;
	}
	
	/* set container variables */
	new_criteria->msg_types |= AVC_MSG;
	new_criteria->criteria_act = &class_criteria_action; 
	new_criteria->print = &class_criteria_print;
	new_criteria->destroy = &class_criteria_destroy; 
	new_criteria->data = d; 
	new_criteria->dirty = TRUE;
	return new_criteria;
}

/*
 * destroy the exe criteria, not the container struct */
static void comm_criteria_destroy(seaudit_criteria_t *ftr)
{
	comm_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (comm_criteria_t*)ftr->data;
	if (d->globex)
		free(d->globex);
	free(d);
	return;
}

/*
 * create the entire exe criteria */
seaudit_criteria_t* comm_criteria_create(const char* comm)
{
        seaudit_criteria_t *new;
	comm_criteria_t *d;
	int i;

	d = (comm_criteria_t*)malloc(sizeof(comm_criteria_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(comm_criteria_t));
	i = strlen(comm);
	d->globex = (char*)malloc(sizeof(char) * (i+1));
	if (d->globex == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &comm_criteria_action; 
	new->print = &comm_criteria_print;
	new->destroy = &comm_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	strcpy(d->globex, comm);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->globex)
			free(d->globex);
		free(d);
	}
	return NULL;
}

/*
 * destroy the exe criteria, not the container struct */
static void exe_criteria_destroy(seaudit_criteria_t *ftr)
{
	exe_criteria_t *d;

	if (ftr == NULL || ftr->data == NULL)
		return;
	d = (exe_criteria_t*)ftr->data;
	if (d->globex)
		free(d->globex);
	free(d);
	return;
}

/*
 * create the entire exe criteria */
seaudit_criteria_t* exe_criteria_create(const char* exe)
{
        seaudit_criteria_t *new;
	exe_criteria_t *d;
	int i;

	d = (exe_criteria_t*)malloc(sizeof(exe_criteria_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(exe_criteria_t));
	i = strlen(exe);
	d->globex = (char*)malloc(sizeof(char) * (i+1));
	if (d->globex == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &exe_criteria_action; 
	new->print = &exe_criteria_print;
	new->destroy = &exe_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	strcpy(d->globex, exe);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->globex)
			free(d->globex);
		free(d);
	}
	return NULL;
}

static void netif_criteria_destroy(seaudit_criteria_t *ftr) 
{
	netif_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (netif_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->netif != NULL)
		free(d->netif);
	free(d);
	return;
}

seaudit_criteria_t* netif_criteria_create(const char *netif)
{
        seaudit_criteria_t *new;
	netif_criteria_t *d;
	int i;
	d = (netif_criteria_t*)malloc(sizeof(netif_criteria_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(netif_criteria_t));
	i = strlen(netif);
	d->netif = (char*)malloc(sizeof(char) * (i+1));
	if (d->netif == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &netif_criteria_action; 
	new->print = &netif_criteria_print;
	new->destroy = &netif_criteria_destroy;
	new->data = d; 
	/* set criteria variables */
	strcpy(d->netif, netif);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->netif)
			free(d->netif);
		free(d);
	}
	return NULL;
}

static void ipaddr_criteria_destroy(seaudit_criteria_t *ftr)
{
	ipaddr_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (ipaddr_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->globex != NULL)
		free(d->globex);
	free(d);
	return;
}

seaudit_criteria_t* ipaddr_criteria_create(const char *ipaddr)
{
        seaudit_criteria_t *new;
	ipaddr_criteria_t *d;
	int i;
	d = (ipaddr_criteria_t*)malloc(sizeof(ipaddr_criteria_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(ipaddr_criteria_t));
	i = strlen(ipaddr);
	d->globex = (char*)malloc(sizeof(char) * (i+1));
	if (d->globex == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &ipaddr_criteria_action; 
	new->print = &ipaddr_criteria_print;
	new->destroy = &ipaddr_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	strcpy(d->globex, ipaddr);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->globex)
			free(d->globex);
		free(d);
	}
	return NULL;
}

static void host_criteria_destroy(seaudit_criteria_t *ftr)
{
	host_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (host_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->globex != NULL)
		free(d->globex);
	free(d);	
}

seaudit_criteria_t* host_criteria_create(const char *hostname)
{
        seaudit_criteria_t *new;
	host_criteria_t *d;
	int i;
	d = (host_criteria_t*)malloc(sizeof(host_criteria_t));
	if (d == NULL) 
		goto bad;
	memset(d, 0, sizeof(host_criteria_t));
	i = strlen(hostname);
	d->globex = (char*)malloc(sizeof(char) * (i+1));
	if (d->globex == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) {
		goto bad;
	}
	/* set container variables */
	new->msg_types |= AVC_MSG | LOAD_POLICY_MSG | BOOLEAN_MSG;
	new->criteria_act = &host_criteria_action; 
	new->print = &host_criteria_print;
	new->destroy = &host_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	strcpy(d->globex, hostname);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->globex)
			free(d->globex);
		free(d);
	}
	return NULL;
}

static void path_criteria_destroy(seaudit_criteria_t *ftr)
{
	path_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (path_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	if (d->globex != NULL)
		free(d->globex);
	free(d);
	return;
}

/*
 * create the entire path criteria */
seaudit_criteria_t* path_criteria_create(const char *path)
{
        seaudit_criteria_t *new;
	path_criteria_t *d;
	int i;
	d = (path_criteria_t*)malloc(sizeof(path_criteria_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(path_criteria_t));
	i = strlen(path);
	d->globex = (char*)malloc(sizeof(char) * (i+1));
	if (d->globex == NULL) 
		goto bad;
	new = criteria_create();
	if (new == NULL) 
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &path_criteria_action; 
	new->print = &path_criteria_print;
	new->destroy = &path_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	strcpy(d->globex, path);
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		if (d->globex)
			free(d->globex);
		free(d);
	}
	return NULL;
}

static void ports_criteria_destroy(seaudit_criteria_t *ftr)
{
	ports_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (ports_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

seaudit_criteria_t* ports_criteria_create(int port)
{
        seaudit_criteria_t *new;
	ports_criteria_t *d;
	d = (ports_criteria_t*)malloc(sizeof(ports_criteria_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(ports_criteria_t));
	new = criteria_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &ports_criteria_action; 
	new->print = &ports_criteria_print;
	new->destroy = &ports_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	d->val = port;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

static void msg_criteria_destroy(seaudit_criteria_t *ftr)
{
	msg_criteria_t *d;
	if (ftr == NULL)
		return;
	d = (msg_criteria_t*)ftr->data;
	if (d == NULL)
		return;
	free(d);
	return;
}

static void date_time_criteria_destroy(seaudit_criteria_t *ftr)
{
	date_time_criteria_t *d;

	if (ftr == NULL)
		return;

	d = (date_time_criteria_t*)ftr->data;
	if (d == NULL)
		return;

	free(d->start);
	free(d->end);
	free(d);
	return;
}

/* 
 *  Create a date/time filter with the given start time, end time, and matching
 *  option.
 */
seaudit_criteria_t* date_time_criteria_create(struct tm *start, struct tm *end, int option)
{
	seaudit_criteria_t *rt = NULL;
	date_time_criteria_t *d = NULL;
	
	if (option != FILTER_CRITERIA_DT_OPTION_BETWEEN &&
		option != FILTER_CRITERIA_DT_OPTION_AFTER &&
		option != FILTER_CRITERIA_DT_OPTION_BEFORE)
		return NULL;	/* invalid option */

	/* malloc new date criteria */
	d = (date_time_criteria_t*)calloc(1, sizeof(date_time_criteria_t));
	if (d == NULL)
		goto bad;
	d->start = (struct tm *)calloc(1, sizeof(struct tm));
	if (d->start == NULL)
		goto bad;
	d->end = (struct tm *)calloc(1, sizeof(struct tm));
	if (d->end == NULL)
		goto bad;

	/* set the criteria */
	*(d->start) = *start;
	*(d->end) = *end;
	d->option = option;

	/* create container filter */
	rt = criteria_create();
	if (rt == NULL)
		goto bad;
	rt->msg_types = AVC_MSG | LOAD_POLICY_MSG | BOOLEAN_MSG;
	rt->criteria_act = &date_time_criteria_action;
	rt->print = &date_time_criteria_print;
	rt->destroy = &date_time_criteria_destroy;
	rt->data = d;
	return rt;

bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d->start);
		free(d->end);
		free(d);
	}
	if (rt)
		seaudit_criteria_destroy(rt);
	return NULL;
}

seaudit_criteria_t* msg_criteria_create(int msg)
{
        seaudit_criteria_t *new;
	msg_criteria_t *d;
	d = (msg_criteria_t*)malloc(sizeof(msg_criteria_t));
	if (d == NULL)
		goto bad;
	memset(d, 0, sizeof(msg_criteria_t));
	new = criteria_create();
	if (new == NULL)
		goto bad;
	/* set container variables */
	new->msg_types |= AVC_MSG;
	new->criteria_act = &msg_criteria_action; 
	new->print = &msg_criteria_print;
	new->destroy = &msg_criteria_destroy; 
	new->data = d; 
	/* set criteria variables */
	d->val = msg;
	return new;
bad:
	fprintf(stdout, "Out of memory");
	if (d) {
		free(d);
	}
	return NULL;
}

