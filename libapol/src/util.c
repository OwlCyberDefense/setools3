#include <config.h>

#include <apol/util.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

/****************************************
 * generic linked list functions
 *
 */

/* create a new initialize list */
llist_t *ll_new(void)
{
	llist_t *ll = NULL;

	ll = (llist_t *)malloc(sizeof(llist_t));
	if (ll == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	ll->head = ll->tail = NULL;
	ll->num = 0;
	return ll;
}

/* frees a node; caller must provide an appropriate
 * free_data() function that can free assoicated data pointers
 * Returns a pointer the n->next.
 */
llist_node_t *ll_node_free(llist_node_t *n, void(*free_data)(void *))
{
	llist_node_t *r;
	if(n == NULL)
		return NULL;
	assert(free_data != NULL);
	(*free_data)(n->data);
	r = n->next;
	free(n);
	return r;
}

/* frees an entire list...caller must provide an appropriate
 * free_data() function that can free assoicated data pointers
 */
void ll_free(llist_t *ll, void (*free_data)(void *))
{
	llist_node_t *n;
	if(ll == NULL)
		return;
	for(n = ll->head; n != NULL;) {
		n = ll_node_free(n, free_data);
	}
	free(ll);
	return;
}
/* removes a node from list..caller must free the node
 * separately using ll_node_free */
int ll_unlink_node(llist_t *ll, llist_node_t *n)
{
	if(n == NULL || ll == NULL)
		return -1;
	if(n->prev == NULL) { /* deleting head node */
		ll->head = n->next;
		if(ll->head != NULL) {
			ll->head->prev = NULL;
			if(ll->head->next != NULL)
				ll->head->next->prev = ll->head;
		}
	}
	else {
		llist_node_t *p;
		p = n->prev;
		p->next = n->next;
		if(p->next != NULL)
			p->next->prev = p;
	}
	if(ll->tail == n)
		ll->tail = n->prev;
	(ll->num)--;
	return 0;
}


/* insert after provided node */
int ll_insert_data(llist_t *ll, llist_node_t *n, void *data)
{
	llist_node_t *newnode;
	if(data == NULL || ll == NULL)
		return -1;

	newnode = (llist_node_t *)malloc(sizeof (llist_node_t));
	if(newnode == NULL) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	newnode->data = data;

	if(n == NULL) {
		assert(ll->head == NULL && ll->tail == NULL && ll->num == 0); /* inserting after null means empty list */
		ll->head = ll->tail = newnode;
		newnode->next = NULL;
		newnode->prev = NULL;
		ll->num = 1;
	}
	else {
		if(n->next == NULL)
			ll->tail = newnode;
		else
			n->next->prev = newnode;
		newnode->next = n->next;
		newnode->prev = n;
		n->next = newnode;
		(ll->num)++;
	}
	return 0;
}

/* appends new item to end of list */
int ll_append_data(llist_t *ll, void *data)
{
	if(ll == NULL)
		return -1;
	return ll_insert_data(ll, ll->tail, data);
}

/* end of of link list functions
 *************************************************************/

int add_i_to_a(int i, int *cnt, int **a)
{
	if(cnt == NULL || a == NULL)
		return -1;

	/* FIX: This is not very elegant! We use an array that we
	 * grow as new int are added to an array.  But rather than be smart
	 * about it, for now we realloc() the array each time a new int is added! */
	if(*a != NULL)
		*a = (int *) realloc(*a, (*cnt + 1) * sizeof(int));
	else /* empty list */ {
		*cnt = 0;
		*a = (int *) malloc(sizeof(int));
	}
	if(*a == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	(*a)[*cnt] = i;
	(*cnt)++;
	return 0;
}

/* See if provided integer is in the provided integer array; if found return
 * the index for a, otherwise return -1 */
int find_int_in_array(int i, const int *a, int a_sz)
{
	int j;
	if(a == NULL  || a_sz < 1)
		return -1;
	for(j = 0; j < a_sz; j++) {
		if(a[j] == i)
			return j;
	}
	return -1;
}

int int_compare(const void *aptr, const void *bptr)
{
	int *a = (int*)aptr;
	int *b = (int*)bptr;

	assert(a);
	assert(b);

	if (*a < *b)
		return -1;
	if (*a > *b)
		return 1;
	return 0;
}

/******************** new stuff here ********************/

/**
 * @file util.c
 *
 * Implementation of utility functions.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

/* these are needed for nodecons and IPv4 and IPv6 */
#include <qpol/policy_query.h>
#include <qpol/nodecon_query.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>    /* needed for portcon's protocol */

/* The following should be defined in the make environment */
#ifndef LIBAPOL_VERSION_STRING
	#define LIBAPOL_VERSION_STRING "UNKNOWN"
#endif

const char* libapol_get_version(void)
{
	return LIBAPOL_VERSION_STRING;
}

int apol_str_to_internal_ip(const char *str, uint32_t ip[4])
{
	bool_t ipv4 = FALSE;
	bool_t ipv6 = FALSE;

	if (!str || !ip) {
		errno = EINVAL;
		return -1;
	}

	ip[0] = ip[1] = ip[2] = ip[3] = 0;

	if (strchr(str, '.'))
		ipv4 = TRUE;

	if (strchr(str, ':'))
		ipv6 = TRUE;

	if (ipv4 == ipv6) {
		errno = EINVAL;
		return -1;
	}

        if (ipv4) {
                unsigned char *p = (unsigned char *) &(ip[0]);
                int seg = 0;
                uint32_t val = 0; /* value of current segment of address */
                size_t len = strlen(str), i;
                for (i = 0; i <= len; i++) {
                        if (str[i] == '.' || str[i] == '\0') {
                                if (val < 0 || val > 255) {
                                        errno = EINVAL;
                                        return -1;
                                }

                                p[seg] = (unsigned char) (0xff & val);
                                seg++;
                                val = 0;
                                if (seg == 4)
                                        break;
                        } else if (isdigit(str[i])) {
                                char tmp[2] = {str[i], 0};
                                val = val * 10 + atoi(tmp);
                        } else {
                                errno = EINVAL;
                                return -1;
                        }
                }
        }
        else {
                struct in6_addr addr;
                if (inet_pton(AF_INET6, str, &addr) <= 0) {
                        return -1;
                }
                memcpy(ip, addr.s6_addr32, 16);
	}

	return ipv4 ? QPOL_IPV4 : QPOL_IPV6;
}

const char *apol_objclass_to_str(uint32_t objclass)
{
        switch (objclass) {
        case QPOL_CLASS_BLK_FILE:  return "block";
        case QPOL_CLASS_CHR_FILE:  return "char";
        case QPOL_CLASS_DIR:       return "dir";
        case QPOL_CLASS_FIFO_FILE: return "fifo";
        case QPOL_CLASS_FILE:      return "file";
        case QPOL_CLASS_LNK_FILE:  return "link";
        case QPOL_CLASS_SOCK_FILE: return "sock";
        case QPOL_CLASS_ALL:       return "any";
        }
        return NULL;
}

const char *apol_protocol_to_str(uint8_t protocol)
{
	switch (protocol) {
	case IPPROTO_TCP: return "tcp";
	case IPPROTO_UDP: return "udp";
	default:
		return NULL;
	}
}

const char *apol_fs_use_behavior_to_str(uint32_t behavior)
{
	switch (behavior) {
	case QPOL_FS_USE_XATTR: return "fs_use_xattr";
	case QPOL_FS_USE_TASK:  return "fs_use_task";
	case QPOL_FS_USE_TRANS: return "fs_use_trans";
	case QPOL_FS_USE_GENFS: return "fs_use_genfs";
	case QPOL_FS_USE_NONE:  return "fs_use_none";
	case QPOL_FS_USE_PSID:  return "fs_use_psid";
	}
	return NULL;
}

int apol_str_to_fs_use_behavior(const char *behavior)
{
	if (strcmp(behavior, "fs_use_xattr") == 0) {
		return QPOL_FS_USE_XATTR;
	}
	else if (strcmp(behavior, "fs_use_task") == 0) {
		return QPOL_FS_USE_TASK;
	}
	else if (strcmp(behavior, "fs_use_trans") == 0) {
		return QPOL_FS_USE_TRANS;
	}
	else if (strcmp(behavior, "fs_use_genfs") == 0) {
		return QPOL_FS_USE_GENFS;
	}
	else if (strcmp(behavior, "fs_use_none") == 0) {
		return QPOL_FS_USE_NONE;
	}
	else if (strcmp(behavior, "fs_use_psid") == 0) {
		return QPOL_FS_USE_PSID;
	}
	return -1;
}

const char *apol_rule_type_to_str(uint32_t rule_type)
{
	switch (rule_type) {
	case QPOL_RULE_ALLOW: return "allow";
	case QPOL_RULE_NEVERALLOW: return "neverallow";
	case QPOL_RULE_AUDITALLOW: return "auditallow";
	case QPOL_RULE_DONTAUDIT: return "dontaudit";
	case QPOL_RULE_TYPE_TRANS: return "type_transition";
	case QPOL_RULE_TYPE_CHANGE: return "type_change";
	case QPOL_RULE_TYPE_MEMBER: return "type_member";
	}
	return NULL;
}

const char *apol_cond_expr_type_to_str(uint32_t expr_type)
{
	switch (expr_type) {
	case QPOL_COND_EXPR_BOOL: return "";
	case QPOL_COND_EXPR_NOT: return "!";
	case QPOL_COND_EXPR_OR: return "||";
	case QPOL_COND_EXPR_AND: return "&&";
	case QPOL_COND_EXPR_XOR: return "^";
	case QPOL_COND_EXPR_EQ: return "==";
	case QPOL_COND_EXPR_NEQ: return "!=";
	}
	return NULL;
}

char* apol_file_find(const char *file_name)
{
	char *file = NULL, *var = NULL, *dir = NULL;
	size_t filesz;
	int rt;

	if(file_name == NULL)
		return NULL;

	/* 1. check current directory */
	filesz = strlen(file_name) + 4;
	file = (char *)malloc(filesz);
	if(file == NULL) {
		return NULL;
	}
	sprintf(file, "./%s", file_name);
	rt = access(file, R_OK);
	if(rt == 0) {
		dir = (char *)malloc(4);
		if(dir == NULL) {
			return NULL;
		}
		sprintf(dir, ".");
		free(file);
		return dir;
	}
	free(file);

	/* 2. check environment variable */
	var = getenv(APOL_ENVIRON_VAR_NAME);
	if(!(var == NULL)) {
		filesz = strlen(var) + strlen(file_name) + 2;
		file = (char *)malloc(filesz);
		if(file == NULL) {
			return NULL;
		}
		sprintf(file, "%s/%s", var, file_name);
		rt = access(file, R_OK);
		if(rt == 0) {
			dir = (char *)malloc(strlen(var) + 1);
			if(dir == NULL) {
				return NULL;
			}
			sprintf(dir, var);
			free(file);
			return dir;
		}
	}

	/* 3. installed directory */
	filesz = strlen(APOL_INSTALL_DIR) + strlen(file_name) + 2;
	file = (char *)malloc(filesz);
	if(file == NULL) {
		return NULL;
	}
	sprintf(file, "%s/%s", APOL_INSTALL_DIR, file_name);
	rt = access(file, R_OK);
	if(rt == 0) {
		dir = (char *)malloc(strlen(APOL_INSTALL_DIR) +1);
		if(dir == NULL) {
			return NULL;
		}
		sprintf(dir, APOL_INSTALL_DIR);
		free(file);
		return dir;
	}

	/* 4. help install directory */
	filesz = strlen(APOL_HELP_DIR) + strlen(file_name) + 2;
	file = (char *)malloc(filesz);
	if(file == NULL) {
		return NULL;
	}
	sprintf(file, "%s/%s", APOL_HELP_DIR, file_name);
	rt = access(file, R_OK);
	if(rt == 0) {
		dir = (char *)malloc(strlen(APOL_HELP_DIR) +1);
		if(dir == NULL) {
			return NULL;
		}
		sprintf(dir, APOL_HELP_DIR);
		free(file);
		return dir;
	}

	/* 5. Didn't find it! */
	free(file);
	return NULL;
}

char* apol_file_find_user_config(const char *file_name)
{
	char *dir, *path, *tmp;
	int rt;

	tmp = getenv("HOME");
	if (tmp) {
		dir = malloc(sizeof(char) * (1+strlen(tmp)));
		if (!dir) {
			return NULL;
		}
		dir = strcpy(dir, tmp);
		path = malloc(sizeof(char) * (2+strlen(dir)+strlen(file_name)));
		if (!path) {
			return NULL;
		}
		path = strcpy(path, dir);
		path = strcat(path, "/");
		path = strcat(path, file_name);
		rt = access(path, R_OK);
		if (rt == 0) {
			free(path);
			return dir;
		} else {
			free(path);
			free(dir);
		}
	}
	return NULL;
}

int apol_file_read_to_buffer(const char *fname, char **buf, size_t *len)
{
	FILE *file = NULL;
	const size_t BUF_SIZE = 1024;
	size_t size = 0, r;
	char *bufp, *b;

	assert(*buf == NULL);
	assert(len);
	*len = 0;
	while (1) {
		size += BUF_SIZE;
		r = 0;
		b = (char*)realloc(*buf, size * sizeof(char));
		if (b == NULL) {
			free(*buf);
			*buf = NULL;
			*len = 0;
			if (file)
				fclose(file);
			return -1;
		}
		*buf = b;
		if (!file) {
			file = fopen(fname, "rb");
			if (!file) {
				free(*buf);
				*buf = NULL;
				*len = 0;
				return -1;
			}
		}
		bufp = &((*buf)[size - BUF_SIZE]);
		r = fread(bufp, sizeof(char), BUF_SIZE, file);
		*len += r;
		if (r < BUF_SIZE) {
			if (feof(file)) {
				fclose(file);
				break;
			} else {
				free(*buf);
				*buf = NULL;
				*len = 0;
				fclose(file);
				return -1;
			}
		}
	}
	return 0;
}

char *apol_config_get_var(const char *var, FILE *fp)
{
	char line[LINE_SZ], t1[LINE_SZ], t2[LINE_SZ], *result = NULL;
	char *line_ptr = NULL;

	if (var == NULL)
		return NULL;

	rewind(fp);
	while (fgets(line, LINE_SZ, fp) != NULL) {
		line_ptr = &line[0];
		if (apol_str_trim(&line_ptr) != 0)
			return NULL;
		if (line[0] == '#' || sscanf(line, "%s %[^\n]", t1, t2) != 2 || strcasecmp(var, t1) != 0) {
			continue;
		}
		else {
			result = (char *)malloc(sizeof(char) * (strlen(t2) + 1));
			if (result == NULL) {
				return NULL;
			} else {
				strcpy(result, t2);
				return result;
			}
		}
	}
	return NULL;
}

char **apol_config_get_varlist(const char *var, FILE *file, size_t *list_sz)
{
	char *values = NULL, *token;
	char **results = NULL, **ptr = NULL;
	int rt = -1;

	assert(var != NULL || file != NULL || list_sz != NULL);
	*list_sz = 0;
	if ((values = apol_config_get_var(var, file)) == NULL) {
		goto cleanup;
	}
	while ((token = strsep(&values, ":")) != NULL) {
		if (strcmp(token, "") && !apol_str_is_only_white_space(token)) {
			ptr = (char**)realloc(results, sizeof(char*) * (*list_sz + 1));
			if (ptr == NULL) {
				goto cleanup;
			}
			results = ptr;
			(*list_sz)++;
			if ((results[(*list_sz) - 1] = strdup(token)) == NULL) {
				goto cleanup;
			}
		}
	}
	rt = 0;
 cleanup:
	free(values);
	if (rt < 0) {
		size_t i;
		for (i = 0; i < *list_sz; i++) {
			free(results[i]);
		}
		free(results);
		*list_sz = 0;
		results = NULL;
	}
	return results;
}


char *apol_config_varlist_to_str(const char **list, size_t size)
{
	char *val;
	size_t i;

	if (list == NULL)
		return NULL;
	val = (char*)malloc(sizeof(char) * (2+strlen(list[0])));
	if (val == NULL) {
		return NULL;
	}
	val = strcpy(val, list[0]);
	val = strcat(val, ":");
	for (i = 1; i < size; i++) {
		char *v = realloc(val, 2 + strlen(val) + strlen(list[i]));
		if (val == NULL) {
			free(val);
			return NULL;
		}
		val = v;
		val = strcat(val, list[i]);
		val = strcat(val, ":");
	}
	return val;
}

/**
 * Given a string, if the string begins with whitespace then allocate
 * a new string that does not contain those whitespaces.  The caller
 * is responsible for free()ing the resulting pointer.  The original
 * string is free()d.
 *
 * @param str Reference to a dynamically allocated string.
 *
 * @return 0 on success, < 0 on out of memory.
 */
static int trim_leading_whitespace(char **str)
{
	size_t length, idx = 0, i;
	char *tmp = NULL;

	assert(str && *str != NULL);
	length = strlen(*str);
	if ((tmp = strdup(*str)) == NULL) {
		return -1;
	}
	/* Get index of first non-whitespace char in the duplicate string. */
	while (idx < length && isspace(tmp[idx]))
		idx++;

	if (idx && idx != length) {
		for (i = 0; idx < length; i++, idx++) {
			(*str)[i] = tmp[idx];
		}
		assert(i <= length);
		(*str)[i] = '\0';
	}
	free(tmp);
	return 0;
}

/**
 * Given a mutable string, replace trailing whitespace characters with
 * \0 characters.
 *
 * @param str Reference to a mutable string.
 */
static void trim_trailing_whitespace(char **str)
{
	size_t length;
	assert(str && *str != NULL);
	length = strlen(*str);
	while (length > 0 && isspace((*str)[length - 1])){
		(*str)[length - 1] = '\0';
		length--;
	}
}

int apol_str_trim(char **str)
{
	assert(str && *str != NULL);
	if (trim_leading_whitespace(str) < 0)
		return -1;
	trim_trailing_whitespace(str);
	return 0;
}

int apol_str_append(char **tgt, size_t *tgt_sz, const char *str)
{
	size_t str_len;
	if (str == NULL || (str_len = strlen(str)) == 0)
		return 0;
	if (tgt == NULL)
		return -1;
	str_len++;
	/* target is currently empty */
	if (*tgt == NULL || *tgt_sz == 0) {
		*tgt = (char *)malloc(str_len);
		if (*tgt == NULL) {
			*tgt_sz = 0;
			return -1;
		}
		*tgt_sz = str_len;
		strcpy(*tgt, str);
		return 0;
	} else {
		/* tgt has some memory */
		char *t = (char *)realloc(*tgt, *tgt_sz + str_len);
		if (t == NULL) {
			free(*tgt);
			*tgt = NULL;
			*tgt_sz = 0;
			return -1;
		}
		*tgt = t;
		*tgt_sz += str_len;
		strcat(*tgt, str);
		return 0;
	}
}

int apol_str_is_only_white_space(const char *str)
{
	size_t len, i;
	if (str == NULL)
		return 0;
	len = strlen(str);
	for(i = 0; i < len; i++) {
		if (!isspace(str[i]))
			return 0;
	}
	return 1;
}

int apol_str_strcmp(const void *a, const void *b, void *unused __attribute__ ((unused)) )
{
	return strcmp((const char*)a, (const char *)b);
}
