/* Copyright (C) 2001-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* util.c */

/* Utility functions */

#include "util.h"
#include "policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

/* convert from string to intger "bool" */
bool_t getbool(const char *str) 
{
	if(strcmp("0", str) == 0)
		return FALSE;
	else
		return TRUE;
}

/* trim trailing and leading whitespace */
int trim_string(char **str)
{	
	assert(str && *str != NULL);
	if (trim_leading_whitespace(str) != 0)
		return -1;
	trim_trailing_whitespace(str);
	return 0;	
}

/* Checks for leading whitespace and if whitespace is found, it will replace
 * the string to exclude leading whitespace chars. */
int trim_leading_whitespace(char **str)
{
	int length, idx = 0, i;
	char *tmp = NULL;
		
	assert(str && *str != NULL);
	/* Get the length of the original string */
	length = strlen(*str);
	/* Create a duplicate of the original string */
	if ((tmp = strdup(*str)) == NULL) {
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}
	/* Get index of first non-whitespace char in the duplicate string. */
	while (idx < length && isspace(tmp[idx]))
		idx++;
				
	/* Replace the string if leading whitespace found. */
	if (idx && idx != length) {
		/* Starting from the index of the first non-whitespace char 
		 * in our tmp string, replace the original string starting 
		 * from its' first index. The end result will be that
		 * we have changed the original string so that it does
		 * not contain any leading whitespace. */
		for (i = 0; idx < length; i++) {	
			(*str)[i] = tmp[idx];
			idx++;
		}
		assert(i <= length);
		(*str)[i] = '\0';
	}
	free(tmp);
	/* else, no leading whitespace found */
	return 0;	
}

/* replace trailing whitespace chars with \0 */
void trim_trailing_whitespace(char **str)
{
	int length;
	
	assert(str && *str != NULL);
	length = strlen(*str);
	/* Trim any trailing whitespace. */
	while (length > 0 && isspace((*str)[length - 1])){
		(*str)[length - 1] = '\0';
		length -=1;
	}
}
			
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
 

int init_rules_bool(bool_t include_audit, rules_bool_t *rules_b, policy_t *policy)
{
	if(rules_b == NULL)
		return -1;
	rules_b->access = (bool_t *)malloc(policy->num_av_access * sizeof(bool_t));
	if(rules_b->access == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(rules_b->access, 0, policy->num_av_access * sizeof(bool_t));
	rules_b->ac_cnt = 0;
	
	rules_b->ttrules = (bool_t *)malloc(policy->num_te_trans * sizeof(bool_t));
	if(rules_b->ttrules == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(rules_b->ttrules, 0, policy->num_te_trans * sizeof(bool_t));
	rules_b->tt_cnt = 0;
	
	rules_b->clone = (bool_t *)malloc(policy->rule_cnt[RULE_CLONE] * sizeof(bool_t));
	if(rules_b->clone == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}	
	memset(rules_b->clone, 0, policy->rule_cnt[RULE_CLONE] * sizeof(bool_t));
	rules_b->cln_cnt = 0;
	
	if(include_audit) {
		rules_b->audit = (bool_t *)malloc(policy->num_av_audit * sizeof(bool_t));	
		if(rules_b->audit == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}	
		memset(rules_b->audit, 0, policy->num_av_audit * sizeof(bool_t));
		rules_b->au_cnt = 0;
	}
	else
		rules_b->audit = NULL;	
	
	return 0;
}

/* 20050106 Added roles to argument list since I may want to create 
 * this with either the number of rules or the number of roles 
 */

int init_rbac_bool(rbac_bool_t *b, policy_t *policy, bool_t roles) 
{
	if(b == NULL)
		return -1;
		
	b->allow = (bool_t *)malloc(roles? policy->num_roles : policy->num_role_allow * sizeof(bool_t));
	if(b->allow == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(b->allow, 0, roles? policy->num_roles : policy->num_role_allow * sizeof(bool_t));
	b->a_cnt = 0;
	
	b->trans = (bool_t *)malloc(roles? policy->num_roles : policy->num_role_trans * sizeof(bool_t));
	if(b->trans == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(b->trans, 0, roles? policy->num_roles : policy->num_role_trans * sizeof(bool_t));
	b->t_cnt = 0;
	
	return 0;
}

/* make the boolean array TRUE for all entries */
int all_true_rules_bool(rules_bool_t *rules_b, policy_t *policy)
{
	if(rules_b == NULL)
		return -1;
	
	assert(rules_b->access != NULL);
	memset(rules_b->access, 1, policy->num_av_access * sizeof(bool_t));
	rules_b->ac_cnt = policy->num_av_access;
	
	assert(rules_b->ttrules != NULL);
	memset(rules_b->ttrules, 1, policy->num_te_trans * sizeof(bool_t));
	rules_b->tt_cnt = policy->num_te_trans;
	
	assert(rules_b->clone != NULL);
	memset(rules_b->clone, 1, policy->rule_cnt[RULE_CLONE] * sizeof(bool_t));
	rules_b->cln_cnt = policy->rule_cnt[RULE_CLONE];
	
	if(rules_b->audit != NULL) {
		memset(rules_b->audit, 1, policy->num_av_audit * sizeof(bool_t));
		rules_b->au_cnt = policy->num_av_audit;
	}
	
	return 0;
}


/* make the boolean array FALSE for all entries */
int all_false_rules_bool(rules_bool_t *rules_b, policy_t *policy)
{
	if(rules_b == NULL)
		return -1;
	
	assert(rules_b->access != NULL);
	memset(rules_b->access, 0, policy->num_av_access * sizeof(bool_t));
	rules_b->ac_cnt = policy->num_av_access;
	
	assert(rules_b->ttrules != NULL);
	memset(rules_b->ttrules, 0, policy->num_te_trans * sizeof(bool_t));
	rules_b->tt_cnt = policy->num_te_trans;
	
	assert(rules_b->clone != NULL);
	memset(rules_b->clone, 0, policy->rule_cnt[RULE_CLONE] * sizeof(bool_t));
	rules_b->cln_cnt = policy->rule_cnt[RULE_CLONE];
	
	if(rules_b->audit != NULL) {
		memset(rules_b->audit, 0, policy->num_av_audit * sizeof(bool_t));
		rules_b->au_cnt = policy->num_av_audit;
	}
	
	return 0;
}


int all_true_rbac_bool(rbac_bool_t *b, policy_t *policy)
{
	if(b == NULL)
		return -1;
	
	assert(b->allow != NULL);
	memset(b->allow, 1, policy->num_role_allow* sizeof(bool_t));
	b->a_cnt = policy->num_role_allow;
	
	assert(b->trans != NULL);
	memset(b->trans, 1, policy->num_role_trans * sizeof(bool_t));
	b->t_cnt = policy->num_role_trans;
	
	return 0;
}

int free_rules_bool(rules_bool_t *rules_b)
{
	if(rules_b == NULL)
		return 0;
		
	if(rules_b->access != NULL)
		free(rules_b->access);
	if(rules_b->audit != NULL)
		free(rules_b->audit);
	if(rules_b->ttrules != NULL)
		free(rules_b->ttrules);
	if(rules_b->clone != NULL)
		free(rules_b->clone);
	return 0;
}

int free_rbac_bool(rbac_bool_t *b)
{
	if(b == NULL)
		return 0;
		
	if(b->allow != NULL)
		free(b->allow);
	if(b->trans != NULL)
		free(b->trans);

	return 0;
}


char* uppercase(const char *instr, char *outstr) 
{
	int i;
	if(instr == NULL || outstr == NULL)
		return NULL;
		
	for(i = 0; i < strlen(instr); i++) {
		outstr[i] = toupper(instr[i]);
	}
	outstr[i] = '\0';
	return outstr;
}


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

int add_uint_to_a(uint32_t i, uint32_t *cnt, uint32_t **a)
{
        if(cnt == NULL || a == NULL)
                return -1;

        /* FIX: This is not very elegant! We use an array that we
         * grow as new int are added to an array.  But rather than be smart
         * about it, for now we realloc() the array each time a new int is added! */
        if(*a != NULL) {
                *a = (uint32_t *) realloc(*a, (*cnt + 1) * sizeof(uint32_t));
        } else /* empty list */ {
                *cnt = 0;
                *a = (uint32_t *) malloc(sizeof(uint32_t));
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

/* add an integer to provided array */
int add_int_to_array(int i, int *a, int num, int a_sz)
{
	if(a == NULL || num >= a_sz) 
		return -1;
	a[num] = i;
	return 0;
}

/* copy the array of ints */
int copy_int_array(int **dest, int *src, int len)
{
	if (!src || len <= 0)
		return -1;
	*dest = (int*)malloc(sizeof(int) * len);
	if (!*dest) {
		fprintf(stderr, "Memory error\n");
		return -1;
	}
	memcpy(*dest, src, len * sizeof(int));
	return 0;
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

bool_t is_name_in_list(const char *name, 
			ta_item_t *list,
			policy_t  *policy)
{
	ta_item_t *ptr;
	bool_t rt;

	if((name == NULL && list == NULL) || policy == NULL )
		return 0;

	for(ptr = list; ptr != NULL; ptr = ptr->next) {
		switch(ptr->type) {
		case IDX_TYPE:
			rt = (strcmp(name, policy->types[ptr->idx].name) == 0);
			break;
		case IDX_ATTRIB:
			rt = (strcmp(name, policy->attribs[ptr->idx].name) == 0);		
			break;
		case IDX_ROLE:
			rt = (strcmp(name, policy->roles[ptr->idx].name) == 0);
			break;
		case IDX_PERM:
			rt = (strcmp(name, policy->perms[ptr->idx]) == 0);
			break;
		case IDX_COMMON_PERM:
			rt = (strcmp(name, policy->common_perms[ptr->idx].name) == 0);
			break;
		case IDX_OBJ_CLASS:
			rt = (strcmp(name, policy->obj_classes[ptr->idx].name) == 0);
			break;
		default:
			continue;
		}
		if(rt)
			return rt;
	}
	return 0;
}


/************************************************
 * functions relating to managing config files
 */
 
/* Test whether a given string is only white space */
unsigned char str_is_only_white_space(const char *str)
{
	size_t len;
	int i;
	if(str == NULL)
		return TRUE;
	len = strlen(str);
	for(i = 0; i < len; i++) {
		if(!isspace(str[i]))
			return FALSE;
	} 
	return TRUE;
} 

const char* libapol_get_version(void)
{
	return LIBAPOL_VERSION_STRING;
}

/* Find the file specified using our built-in search order for sysem config files.
 * This function returns a string of the directory; caller
 * must free the returned string.
 */
char* find_file(const char *file_name)
{
	char *file = NULL, *var = NULL, *dir = NULL;
	int filesz;
	int rt;
	
	if(file_name == NULL)
		return NULL;
		
	/* 1. check current directory */
	filesz = strlen(file_name) + 4;
	file = (char *)malloc(filesz);
	if(file == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}	
	sprintf(file, "./%s", file_name);
	rt = access(file, R_OK);
	if(rt == 0) {
		dir = (char *)malloc(4);
		if(dir == NULL) {
			fprintf(stderr, "out of memory");
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
			fprintf(stderr, "out of memory");
			return NULL;
		}	
		sprintf(file, "%s/%s", var, file_name);	
		rt = access(file, R_OK);
		if(rt == 0) {
			dir = (char *)malloc(strlen(var) + 1);
			if(dir == NULL) {
				fprintf(stderr, "out of memory");
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
		fprintf(stderr, "out of memory");
		return NULL;
	}	
	sprintf(file, "%s/%s", APOL_INSTALL_DIR, file_name);
	rt = access(file, R_OK);
	if(rt == 0) {
		dir = (char *)malloc(strlen(APOL_INSTALL_DIR) +1);
		if(dir == NULL) {
			fprintf(stderr, "out of memory");
			return NULL;
		}
		sprintf(dir, APOL_INSTALL_DIR);
		free(file);
		return dir;	
	}
	
	/* 4. Didn't find it! */
	free(file);		
	return NULL;		
}

/* 
 * This function looks in the users home directory  */
char* find_user_config_file(const char *file_name)
{
	char *dir, *path, *tmp;
	int rt; 

	tmp = getenv("HOME");
	if (tmp) {
		dir = malloc(sizeof(char) * (1+strlen(tmp)));
		if (!dir) {
			fprintf(stderr, "out of memory");
			return NULL;
		}
		dir = strcpy(dir, tmp);
		path = malloc(sizeof(char) * (2+strlen(dir)+strlen(file_name)));
		if (!path) {
			fprintf(stderr, "out of memory");
			return NULL;
		}
		path = strcpy(path, dir);
		path = strcat(path, "/");
		path = strcat(path, file_name);
		rt = access(path, R_OK);
		if(rt == 0) {
			free(path);
			return dir;		
		} else {
			free(path);
			free(dir);
		}
	}
	return NULL;
}

/* get the value for the config var provided from the config file
 * caller must free returned string */
char *get_config_var(const char *var, FILE *fp)
{
	char line[LINE_SZ], t1[LINE_SZ], t2[LINE_SZ], *result = NULL;
	char *line_ptr = NULL;
			
	if(var == NULL)
		return NULL;
		
	rewind(fp);
	while(fgets(line, LINE_SZ, fp) != NULL) {
		line_ptr = &line[0];
		if (trim_string(&line_ptr) != 0)
			return NULL;
		if (line[0] == '#' || sscanf(line, "%s %[^\n]", t1, t2) != 2 || strcasecmp(var, t1) != 0) {
			continue;
		}
		else {
			result = (char *)malloc(sizeof(char) * (strlen(t2) + 1));
			if (result == NULL) {
				fprintf(stderr, "out of memory\n");
				return NULL;
			} else {
				strcpy(result, t2);
				return result;
			}
		}
	}                                           
	return NULL;
}

char *config_var_list_to_string(const char **list, int size)
{
	char *val;
	int i;
	
	if (size <= 0 || list == NULL)
		return NULL;
	val = (char*)malloc(sizeof(char) * (2+strlen(list[0])));
	if (val == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	val = strcpy(val, list[0]);
	val = strcat(val, ":");
	for (i = 1; i < size; i++) {
		val = realloc(val, sizeof(char) * (2 + strlen(val) + strlen(list[i])));
		if (val == NULL) {
			fprintf(stderr, "out of memory");
			return NULL;
		}
		val = strcat(val, list[i]);
		val = strcat(val, ":");
	}
	return val;
}

char **get_config_var_list(const char *var, FILE *file, int *list_sz)
{
	char *values, *token;
	char **results = NULL, **ptr = NULL;
	int i; 
	
	assert(var != NULL || file != NULL || list_sz != NULL);
	*list_sz = 0;
	values = get_config_var(var, file);
	if (values != NULL) {
		while ((token = strsep(&values, ":")) != NULL) {
		       	if (strcmp(token, "") && !str_is_only_white_space(token)) {
		       		ptr = (char**)realloc(results, sizeof(char*) * (*list_sz + 1));
				if (ptr == NULL) {
					fprintf(stderr, "Out of memory.\n");
					free(values);
					/* If realloc fails, it will not free the 
					 * original pointer, so we handle this here. */
					if (results) {
						for (i = 0; i < *list_sz; i++) 
							free(results[i]);
						free(results);
					}
					return NULL;
				}
				results = ptr;
				(*list_sz)++;
				/* Add 1 to include enough space for terminating null char */
				results[(*list_sz) - 1] = (char*)malloc(sizeof(char) * (1 + strlen(token)));
				if (results[(*list_sz) - 1] == NULL) {
					fprintf(stderr, "Out of memory.\n");
					free(values);
					if (results) {
						/* Free list up to the previous list item */
						for (i = 0; i < *list_sz; i++) 
							free(results[i]);
						free(results);
					}
					return NULL;
				}
				strcpy(results[(*list_sz) - 1], token);
	       	       	}
	        }
		free(values);
	}
	return results;
}

/* append a string to an existing string, expanding the target string if 
 * necessary.  Call must free the target string.  Make tgt == NULL if 
 * this is first use.
 */
int append_str(char **tgt, int *tgt_sz, const char *str)
{
	int str_len;
	if(str == NULL || (str_len = strlen(str)) == 0)
		return 0;
	if(tgt == NULL)
		return -1;
	str_len++;
	/* target is currently empty */
	if(*tgt == NULL) {
		*tgt = (char *)malloc(str_len);
		*tgt_sz = str_len;
		strcpy(*tgt, str);
		return 0;
	} else {
	/* tgt has some memory */
		*tgt = (char *)realloc(*tgt, *tgt_sz + str_len);
		if(*tgt == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		*tgt_sz += str_len;
	}
	strcat(*tgt, str);
	return 0;	
}

/* allocate a buffer with contents of the file.  the caller must free
 * the buffer afterwards. */
int read_file_to_buffer(const char *fname, char **buf, int *len)
{
	FILE *file = NULL;
	const int BUF_SIZE = 1024;
	size_t size = 0, r;
	char *bufp;
	
	assert(*buf == NULL);
	assert(len);
	*len = 0;
	while (1) {
		size += BUF_SIZE;
		r = 0;
		*buf = (char*)realloc(*buf, size * sizeof(char));
		if (!*buf) {
			if (file)
				fclose(file);
			return -1;
		}
		if (!file) {
			file = fopen(fname, "r");
			if (!file) {
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
				fprintf(stderr, strerror(ferror(file)));
				fclose(file);
				return -1;
			}
		}
	}
	return 0;
}


int str_to_internal_ip(const char *str, uint32_t ip[4])
{
	int len = 0, i, retv;
	int seg = 0;
	uint32_t val = 0; /* value of current segment of address */
	bool_t ipv4 = FALSE;
	bool_t ipv6 = FALSE;
	char tmp[6] = {'0', 'x', '\0', '\0', '\0', '\0'};
	int seg_cnt = 0; /* for counting number of segments in ipv6 addr */

	if (!str || !ip) {
		errno = EINVAL;
		return -1;
	}

	len = strlen(str);
	ip[0] = ip[1] = ip[2] = ip[3] = 0;

	if (strchr(str, '.'))
		ipv4 = TRUE;

	if (strchr(str, ':'))
		ipv6 = TRUE;

	if (ipv4 == ipv6) {
		errno = EINVAL;
		return -1;
	}

	if (ipv6) {
		for (i = 0; i < len; i++) {
			if (str[i] == ':')
				seg_cnt++;
		}
	}

	for (i = 0; i <= len; i++) {
		if (ipv4) {
			if (str[i] == '.' || str[i] == '\0') {
				ip[3] |= ((0x000000ff & val) << (8 * (3 - seg)));
				seg++;
				val = 0;
				if (seg == 4)
					break;
			} else if (isdigit(str[i])) {
				tmp[4] = str[i];
				retv = atoi(&(tmp[4]));
				val *= 10;
				val += retv;
			}
		} else if (ipv6) {
			if (str[i] == ':' || str[i] == '\0') {
				ip[seg/2] |= ((0x0000ffff & val) << (16 * (1 - seg % 2)));
				seg++;
				val = 0;
				if (i + 1 < len && str[i+1] == ':') {
					seg += 8 - seg_cnt;
					i++;
				}
				if (seg == 8)
					break;
			} else if (isxdigit(str[i])) {
				tmp[2] = str[i];
				retv = strtol(tmp, NULL, 16);
				val = val << 4;
				val += retv;
			}
		}
	}

	return ipv4?AP_IPV4:AP_IPV6;
}

