/**
 *  @file policy.c
 *  Defines the public interface the QPol policy.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
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

#include "debug.h"
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <asm/types.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <glob.h>
#include <limits.h>
#include <errno.h>

#include <sepol/debug.h>
#include <sepol/handle.h>
#include <sepol/policydb/flask_types.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb.h>
#include <sepol/module.h>

#include <selinux/selinux.h>

#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include <qpol/expand.h>
#include <qpol/cond_query.h>
#include <qpol/constraint_query.h>
#include <qpol/class_perm_query.h>
#include <qpol/fs_use_query.h>
#include "queue.h"

/* redefine input so we can read from a string */
/* borrowed from O'Reilly lex and yacc pg 157 */
char *qpol_src_originalinput;
char *qpol_src_input;
char *qpol_src_inputptr;/* current position in qpol_src_input */
char *qpol_src_inputlim;/* end of data */

extern void init_scanner(void);
extern int yyparse(void);
extern void init_parser(int);
extern queue_t id_queue;
extern unsigned int policydb_errors;
extern unsigned long policydb_lineno;
extern char source_file[];
extern policydb_t *policydbp;
extern int mlspol;

/* Error TEXT definitions for decoding the above error definitions. */
#define TEXT_BIN_POL_FILE_DOES_NOT_EXIST	"Could not locate a default binary policy file."
#define TEXT_SRC_POL_FILE_DOES_NOT_EXIST	"Could not locate default source policy file."
#define TEXT_BOTH_POL_FILE_DO_NOT_EXIST		"Could not locate a default source policy or binary file."
#define TEXT_POLICY_INSTALL_DIR_DOES_NOT_EXIST	"The default policy install directory does not exist."
#define TEXT_READ_POLICY_FILE_ERROR		"Cannot read default policy file."
#define TEXT_INVALID_SEARCH_OPTIONS		"Invalid search options provided to find_default_policy_file()."
#define TEXT_GENERAL_ERROR_TEXT			"Error in find_default_policy_file()."

/* use 8k line size */
#define LINE_SZ 8192
#define BUF_SZ 240

#undef FALSE
#define FALSE   0
#undef TRUE
#define TRUE    1
typedef unsigned char bool_t;

/* buffer for reading from file */
typedef struct fbuf {
        char    *buf;
        size_t  sz;
        int     err;
} qpol_fbuf_t;

static void qpol_handle_route_to_callback(void *varg __attribute__((unused)), qpol_handle_t *qh, int level, const char *fmt, va_list va_args)
{
	if (!qh || !(qh->fn)) {
		vfprintf(stderr, fmt, va_args);
		fprintf(stderr, "\n");
		return;
	}

	qh->fn(qh->varg, qh, level, fmt, va_args);
}

static void sepol_handle_route_to_callback(void *varg, sepol_handle_t *sh, const char *fmt, ...)
{
	va_list ap;
	qpol_handle_t *qh = varg;

	if (!sh) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		return;
	}

	va_start(ap, fmt);
	qpol_handle_route_to_callback(NULL, qh, sepol_msg_get_level(sh), fmt, ap);
	va_end(ap);
}

void qpol_handle_msg(qpol_handle_t *handle, int level, const char *fmt, ...)
{
	va_list ap;

	if (!handle) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		return;
	}

	va_start(ap, fmt);
	qpol_handle_route_to_callback(handle->varg, handle, level, fmt, ap);
	va_end(ap);
}

static void qpol_handle_default_callback(void *varg, qpol_handle_t *handle, int level, const char *fmt, va_list va_args)
{
	switch (level) {
		case QPOL_MSG_INFO:
			{
				/* by default ignore info messages */
				return;
			}
		case QPOL_MSG_WARN:
			{
				fprintf(stderr, "WARNING: ");
				break;
			}
		case QPOL_MSG_ERR:
		default:
			{
				fprintf(stderr, "ERROR: ");
				break;
			}
	}

	vfprintf(stderr, fmt, va_args);
	fprintf(stderr, "\n");
}

static int read_source_policy(qpol_handle_t *handle, policydb_t *p, char *progname)
{
	if ((id_queue = queue_create()) == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		return -1;
	}

	policydbp = p;
	mlspol = p->mls;

	init_scanner();
	init_parser(1);
	if (yyparse() || policydb_errors) {
		ERR(handle, "%s:  error(s) encountered while parsing configuration\n", progname);
		queue_destroy(id_queue);
		id_queue = NULL;
		errno = EIO;
		return -1;
	}
	/* rewind the pointer */
	qpol_src_inputptr = qpol_src_originalinput;
	init_parser(2);
	source_file[0] = '\0';
	if (yyparse() || policydb_errors) {
		ERR(handle, "%s:  error(s) encountered while parsing configuration\n", progname);
		queue_destroy(id_queue);
		id_queue = NULL;
		errno = EIO;
		return -1;
	}
	queue_destroy(id_queue);
	id_queue = NULL;
	if (policydb_errors) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static int qpol_init_fbuf(qpol_fbuf_t **fb)
{
        if(fb == NULL)
                return -1;
        *fb = (qpol_fbuf_t *)malloc(sizeof(qpol_fbuf_t));
        if(*fb == NULL)
                return -1;
        (*fb)->buf = NULL;
        (*fb)->sz = 0;
        (*fb)->err = 0;
        return 0;
}

static void qpol_free_fbuf(qpol_fbuf_t **fb)
{
        if(*fb == NULL)
                return;
        if((*fb)->sz > 0 && (*fb)->buf != NULL)
                free((*fb)->buf);
        free(*fb);
        return;
}

static void *qpol_read_fbuf(qpol_fbuf_t *fb, size_t bytes,  FILE *fp)
{
        size_t sz;

        assert(fb != NULL && fp != NULL);
        assert(!(fb->sz > 0 && fb->buf == NULL));

        if(fb->sz == 0) {
                fb->buf = (char *)malloc(bytes + 1);
                fb->sz = bytes + 1;
        }
        else if(bytes+1 > fb->sz) {
                fb->buf = (char *)realloc(fb->buf, bytes+1);
                fb->sz = bytes + 1;
        }

        if(fb->buf == NULL) {
                fb->err = -1;
                return NULL;
        }

        sz = fread(fb->buf, bytes, 1, fp);
        if(sz != 1) {
                fb->err = -3;
                return NULL;
        }
        fb->err = 0;
        return fb->buf;
}

/* returns the version number of the binary policy
 * will return the file rewound.
 *
 * return codes:
 *      N       success - policy version returned
 *      -1      general error
 *      -2      wrong magic # for file
 *      -3      problem reading file
 */
int qpol_binpol_version(FILE *fp)
{
        __u32  *buf;
        int rt, len;
        qpol_fbuf_t *fb;

        if (fp == NULL)
                return -1;

        if(qpol_init_fbuf(&fb) != 0)
                return -1;

        /* magic # and sz of policy string */
        buf = qpol_read_fbuf(fb, sizeof(__u32)*2, fp);
        if (buf == NULL) { rt = fb->err; goto err_return; }
        buf[0] = le32_to_cpu(buf[0]);
        if (buf[0] != SELINUX_MAGIC) { rt = -2; goto err_return; }

        len = le32_to_cpu(buf[1]);
        if(len < 0) { rt = -3; goto err_return; }
        /* skip over the policy string */
        if(fseek(fp, sizeof(char)*len, SEEK_CUR) != 0) { rt = -3; goto err_return; }

        /* Read the version, config, and table sizes. */
        buf = qpol_read_fbuf(fb, sizeof(__u32) * 1, fp);
        if(buf == NULL) { rt = fb->err; goto err_return; }
        buf[0] = le32_to_cpu(buf[0]);

        rt = buf[0];
err_return:
        rewind(fp);
        qpol_free_fbuf(&fb);
        return rt;
}

static bool_t qpol_is_file_binpol(FILE *fp)
{
        size_t sz;
        __u32 ubuf;
        bool_t rt;

	sz = fread(&ubuf, sizeof(__u32), 1, fp);

        if(sz != 1)
                rt = FALSE; /* problem reading file */

        ubuf = le32_to_cpu(ubuf);
        if(ubuf == SELINUX_MAGIC)
                rt = TRUE;
        else
                rt = FALSE;
	rewind(fp);
        return rt;
}

/* returns an error string based on a return error */
const char* qpol_find_default_policy_file_strerr(int err)
{
	switch(err) {
	case BIN_POL_FILE_DOES_NOT_EXIST:
		return TEXT_BIN_POL_FILE_DOES_NOT_EXIST;
	case SRC_POL_FILE_DOES_NOT_EXIST:
		return TEXT_SRC_POL_FILE_DOES_NOT_EXIST;
	case POLICY_INSTALL_DIR_DOES_NOT_EXIST:
		return TEXT_POLICY_INSTALL_DIR_DOES_NOT_EXIST;
	case BOTH_POL_FILE_DO_NOT_EXIST:
		return TEXT_BOTH_POL_FILE_DO_NOT_EXIST;
	case INVALID_SEARCH_OPTIONS:
		return TEXT_INVALID_SEARCH_OPTIONS;
	default:
		return TEXT_GENERAL_ERROR_TEXT;
	}
}

static bool_t is_binpol_valid(qpol_handle_t *handle, const char *policy_fname, const char *version)
{
	FILE *policy_fp = NULL;
	int ret_version;

	assert(policy_fname != NULL && version != NULL);
	policy_fp = fopen(policy_fname, "r");
	if (policy_fp == NULL) {
		ERR(handle, "Could not open policy %s", policy_fname);
		return FALSE;
	}
	if(!qpol_is_file_binpol(policy_fp)) {
		fclose(policy_fp);
		return FALSE;
	}
	ret_version = qpol_binpol_version(policy_fp);
	fclose(policy_fp);
	if (ret_version != atoi(version))
		return FALSE;

	return TRUE;
}

static int search_for_policyfile_with_ver(qpol_handle_t *handle, const char *binpol_install_dir, char **policy_path_tmp, const char *version)
{
	glob_t glob_buf;
	struct stat fstat;
	int len, i, num_matches = 0, rt;
	char *pattern = NULL;

	assert(binpol_install_dir != NULL && policy_path_tmp && version != NULL);
	/* a. allocate pattern string to use for our call to glob() */
	len = strlen(binpol_install_dir) + 2;
	if((pattern = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		return GENERAL_ERROR;
	}
	sprintf(pattern, "%s.*", binpol_install_dir);

	/* Call glob() to get a list of filenames matching pattern. */
	glob_buf.gl_offs = 1;
	glob_buf.gl_pathc = 0;
	rt = glob(pattern, GLOB_DOOFFS, NULL, &glob_buf);
	if (rt != 0 && rt != GLOB_NOMATCH) {
		ERR(handle, "Error globbing %s.*", binpol_install_dir);
		perror("search_for_policyfile_with_ver");
		return GENERAL_ERROR;
	}
	num_matches = glob_buf.gl_pathc;
	for (i = 0; i < num_matches; i++) {
		char *path = glob_buf.gl_pathv[i + glob_buf.gl_offs];
		if (stat(path, &fstat) != 0) {
			globfree(&glob_buf);
			free(pattern);
			perror("search_for_policyfile_with_ver");
			return GENERAL_ERROR;
		}
		/* skip directories */
		if (S_ISDIR(fstat.st_mode))
			continue;
		if (is_binpol_valid(handle, path, version)) {
			len = strlen(path) + 1;
			if((*policy_path_tmp = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
				ERR(handle, "%s", strerror(ENOMEM));
				globfree(&glob_buf);
				free(pattern);
				return GENERAL_ERROR;
			}
			strcpy(*policy_path_tmp, path);
		}
	}
	free(pattern);
	globfree(&glob_buf);
	return 0;
}

static int search_for_policyfile_with_highest_ver(qpol_handle_t *handle, const char *binpol_install_dir, char **policy_path_tmp)
{
	glob_t glob_buf;
	struct stat fstat;
	int len, i, num_matches = 0, rt;
	char *pattern = NULL;

	assert(binpol_install_dir != NULL && policy_path_tmp);
	/* a. allocate pattern string */
	len = strlen(binpol_install_dir) + 2;
	if((pattern = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		return GENERAL_ERROR;
	}
	sprintf(pattern, "%s*", binpol_install_dir);
	glob_buf.gl_offs = 0;
	glob_buf.gl_pathc = 0;
	/* Call glob() to get a list of filenames matching pattern */
	rt = glob(pattern, GLOB_DOOFFS, NULL, &glob_buf);
	if (rt != 0 && rt != GLOB_NOMATCH) {
		ERR(handle, "Error globbing %s.*", binpol_install_dir);
		perror("search_for_policyfile_with_highest_ver");
		return GENERAL_ERROR;
	}
	num_matches = glob_buf.gl_pathc;
	for (i = 0; i < num_matches; i++) {
		char *path = glob_buf.gl_pathv[i + glob_buf.gl_offs];
		if (stat(path, &fstat) != 0) {
			globfree(&glob_buf);
			free(pattern);
			perror("search_for_policyfile_with_highest_ver");
			return GENERAL_ERROR;
		}
		/* skip directories */
		if (S_ISDIR(fstat.st_mode))
			continue;

		if (*policy_path_tmp != NULL && strcmp(path, *policy_path_tmp) > 0) {
			free(*policy_path_tmp);
			*policy_path_tmp = NULL;
		} else if (*policy_path_tmp != NULL) {
			continue;
		}
		len = strlen(path) + 1;
		if((*policy_path_tmp = (char *)malloc(sizeof(char) * (len+1))) == NULL) {
			ERR(handle, "%s", strerror(ENOMEM));
			globfree(&glob_buf);
			free(pattern);
			return GENERAL_ERROR;
		}
		strcpy(*policy_path_tmp, path);
	}
	free(pattern);
	globfree(&glob_buf);

	return 0;
}

static int search_binary_policy_file(qpol_handle_t *handle, char **policy_file_path)
{
	int ver;
	int rt = 0;
	char *version = NULL, *policy_path_tmp = NULL;
	bool_t is_valid;

	/* A. Get the path for the currently loaded policy version. */
	/* Get the version number */
	ver = security_policyvers();
	if (ver < 0) {
		ERR(handle, "%s", "Error getting policy version.");
		return GENERAL_ERROR;
	}
	/* Store the version number into string */
	if ((version = (char *)malloc(sizeof(char) * LINE_SZ)) == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		return GENERAL_ERROR;
	}
	snprintf(version, LINE_SZ - 1, "%d", ver);
	assert(version);
	if ((policy_path_tmp = (char *)malloc(sizeof(char) * PATH_MAX)) == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		free(version);
		return GENERAL_ERROR;
	}
	snprintf(policy_path_tmp, PATH_MAX - 1, "%s%s%s", selinux_binary_policy_path(),
		"." , version);
	assert(policy_path_tmp);
	/* B. make sure the actual binary policy version matches the policy version.
	 * If it does not, then search the policy install directory for a binary file
	 * of the correct version. */
	is_valid = is_binpol_valid(handle, policy_path_tmp, version);
	if (!is_valid) {
		free(policy_path_tmp);
		policy_path_tmp = NULL;
		rt = search_for_policyfile_with_ver(handle, selinux_binary_policy_path(), &policy_path_tmp, version);
	}
	if (version) free(version);
	if (rt == GENERAL_ERROR)
		return GENERAL_ERROR;

	/* C. If we have not found a valid binary policy file,
	 * then try to use the highest version we find. */
	if (!policy_path_tmp) {
		rt = search_for_policyfile_with_highest_ver(handle, selinux_binary_policy_path(), &policy_path_tmp);
		if (rt == GENERAL_ERROR)
			return GENERAL_ERROR;
	}
	/* If the following case is true, then we were not able to locate a binary
	 * policy within the policy install dir */
	if (!policy_path_tmp) {
		return BIN_POL_FILE_DOES_NOT_EXIST;
	}
	/* D. Set the policy file path */
	if((*policy_file_path = (char *)malloc(sizeof(char) * (strlen(policy_path_tmp)+1))) == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		return GENERAL_ERROR;
	}
	strcpy(*policy_file_path, policy_path_tmp);
	free(policy_path_tmp);
	assert(*policy_file_path);

	return FIND_DEFAULT_SUCCESS;
}

static int search_policy_src_file(qpol_handle_t *handle, char **policy_file_path)
{
	int rt;
	char *path = NULL;

	/* Check if the default policy source file exists. */
	if ((path = (char *)malloc(sizeof(char) * PATH_MAX)) == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		return GENERAL_ERROR;
	}
	snprintf(path, PATH_MAX - 1, "%s/src/policy/policy.conf",
		 selinux_policy_root());
	assert(path != NULL);
	rt = access(path, F_OK);
	if (rt != 0) {
		free(path);
		return SRC_POL_FILE_DOES_NOT_EXIST;
	}
	if ((*policy_file_path = (char *)malloc(sizeof(char) * (strlen(path)+1))) == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		free(path);
		return GENERAL_ERROR;
	}
	strcpy(*policy_file_path, path);
	free(path);

	return FIND_DEFAULT_SUCCESS;
}

int qpol_find_default_policy_file(unsigned int search_opt, char **policy_file_path)
{
	int rt, src_not_found = 0;
	qpol_handle_t *handle = NULL;
	assert(policy_file_path != NULL);

	/* Try default source policy first as a source
	 * policy contains more useful information. */
	if (search_opt & QPOL_TYPE_SOURCE) {
		rt = search_policy_src_file(handle, policy_file_path);
		if (rt == FIND_DEFAULT_SUCCESS) {
			return FIND_DEFAULT_SUCCESS;
		}
		/* Only continue if a source policy couldn't be found. */
		if (rt != SRC_POL_FILE_DOES_NOT_EXIST) {
			return rt;
		}
		src_not_found = 1;
	}

	/* Try a binary policy */
        if (search_opt & QPOL_TYPE_BINARY) {
		rt = search_binary_policy_file(handle, policy_file_path);
		if (rt == BIN_POL_FILE_DOES_NOT_EXIST && src_not_found) {
			return BOTH_POL_FILE_DO_NOT_EXIST;
		}
		return rt;
	}
	/* Only get here if invalid search options was provided. */
	return INVALID_SEARCH_OPTIONS;
}

static int infer_policy_version(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	qpol_class_t *obj_class = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_fs_use_t *fsuse = NULL;
	uint32_t behavior = 0;
	size_t nvtrans = 0, fsusexattr = 0;

	if (!handle || !policy) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	if (db->policyvers) {
		/* version already set */
		return STATUS_SUCCESS;
	}

	/* check fs_use for xattr and psid */
	qpol_policy_get_fs_use_iter(handle, policy, &iter);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_iterator_get_item(iter, (void**)&fsuse);
		qpol_fs_use_get_behavior(handle, policy, fsuse, &behavior);
		/* not possible to have xattr and psid in same policy */
		if (behavior == QPOL_FS_USE_XATTR) {
			fsusexattr = 1;
			break;
		} else if (behavior == QPOL_FS_USE_PSID) {
			qpol_iterator_destroy(&iter);
			db->policyvers = 12;
			return STATUS_SUCCESS;
		}
	}
	qpol_iterator_destroy(&iter);

	/* 19 & 20 : mls and validatetrans statements added */
	qpol_policy_get_validatetrans_iter(handle, policy, &iter);
	qpol_iterator_get_size(iter, &nvtrans);
	qpol_iterator_destroy(&iter);
	if (db->mls || nvtrans) {
		db->policyvers = 19;
	}
	/* 18 : the netlink_audit_socket class added */
	else if (!qpol_policy_get_class_by_name(handle, policy, "netlink_audit_socket", &obj_class)) {
		db->policyvers = 18;
	}
	/* 17 : IPv6 nodecon statements added */
	else if (db->ocontexts[OCON_NODE6]) {
		db->policyvers = 17;
	}
	/* 16 : conditional policy added */
	else if (db->p_bool_val_to_name[0]) {
		db->policyvers = 16;
	}
	/* 15 */
	else if (fsusexattr) {
		db->policyvers = 15;
	}
	/* 12 */
	else {
		db->policyvers = 12;
	}

	return STATUS_SUCCESS;
}

int qpol_open_policy_from_file(const char *path, qpol_policy_t **policy, qpol_handle_t **handle, qpol_handle_callback_fn_t fn, void *varg)
{
	int error = 0, retv = -1;
	FILE *infile = NULL;
	sepol_policy_file_t *pfile = NULL;
	int fd = 0;
	struct stat sb;

	if (policy != NULL)
		*policy = NULL;

	if (handle != NULL)
		*handle = NULL;

	if (path == NULL || policy == NULL || handle == NULL) {
		/* handle passed as NULL here as it has yet to be created */
		ERR(NULL, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!(*handle = calloc(1, sizeof(qpol_handle_t)))) {
		error = errno;
		ERR(NULL, "%s", strerror(error));
		errno = error;
		return -1;
	}
	(*handle)->sh = sepol_handle_create();
	if ((*handle)->sh == NULL) {
		error = errno;
		ERR(*handle, "%s", strerror(error));
		errno = error;
		return -1;
	}

	if (fn) {
		(*handle)->fn = fn;
		(*handle)->varg = varg;
	} else {
		(*handle)->fn = qpol_handle_default_callback;
	}
	sepol_msg_set_callback((*handle)->sh, sepol_handle_route_to_callback, (*handle));

	if (!(*policy = calloc(1, sizeof(qpol_policy_t)))) {
		error = errno;
		goto err;
	}

	if (sepol_policydb_create(&((*policy)->p))) {
		error = errno;
		goto err;
	}

	if (sepol_policy_file_create(&pfile)) {
		error = errno;
		goto err;
	}

	infile = fopen(path,  "rb");
	if (infile == NULL) {
		error = errno;
		goto err;
	}

	sepol_policy_file_set_handle(pfile, (*handle)->sh);

	if (qpol_is_file_binpol(infile)) {
		retv = QPOL_POLICY_KERNEL_BINARY;
		sepol_policy_file_set_fp(pfile, infile);
		if (sepol_policydb_read((*policy)->p, pfile)) {
			error = EIO;
			goto err;
		}
		if (qpol_policy_extend(*handle, *policy)) {
			error = errno;
			goto err;
		}
	} else {
		retv = QPOL_POLICY_KERNEL_SOURCE;
		fd = fileno(infile);
		if (fd < 0) {
			error = errno;
			goto err;
		}
		if (fstat(fd, &sb) < 0) {
			error = errno;
			ERR(*handle, "Can't stat '%s':	%s\n",
					path, strerror(errno));
			goto err;
		}
		qpol_src_input = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (qpol_src_input == MAP_FAILED) {
			error = errno;
			ERR(*handle, "Can't map '%s':  %s\n",
					path, strerror(errno));

			goto err;
		}
		qpol_src_inputptr = qpol_src_input;
		qpol_src_inputlim = &qpol_src_inputptr[sb.st_size-1];
		qpol_src_originalinput = qpol_src_input;

		if (read_source_policy(*handle, &(*policy)->p->p, "libqpol") < 0) {
			error = errno;
			goto err;
		}

		(*policy)->p->p.policy_type = POLICY_BASE;
		/* link the source */
		INFO(*handle, "%s", "Linking source policy.");
		if (sepol_link_modules((*handle)->sh, (*policy)->p, NULL, 0, 0)) {
			error = EIO;
			goto err;
		}
		avtab_destroy(&((*policy)->p->p.te_avtab));
		avtab_destroy(&((*policy)->p->p.te_cond_avtab));
		avtab_init(&((*policy)->p->p.te_avtab));
		avtab_init(&((*policy)->p->p.te_cond_avtab));

		/* expand :) */
		if (qpol_expand_module(*handle, *policy)) {
			error = errno;
			goto err;
		}

		if (infer_policy_version(*handle, *policy)) {
			error = errno;
			goto err;
		}
		if (qpol_policy_extend(*handle, *policy)) {
			error = errno;
			goto err;
		}
	}

	fclose(infile);
	sepol_policy_file_free(pfile);
	return retv;

err:
	qpol_handle_destroy(handle);
	*handle = NULL;
	sepol_policydb_free((*policy)->p);
	*policy = NULL;
	sepol_policy_file_free(pfile);
	if (infile)
		fclose(infile);
	errno = error;
	return -1;
}

int qpol_open_policy_from_memory(qpol_policy_t **policy, const char *filedata, int size,
				 qpol_handle_t **handle, qpol_handle_callback_fn_t fn, void *varg)
{
	int error = 0;
	if (policy == NULL || filedata == NULL)
		return -1;
	*policy = NULL;

	if (!(*handle = calloc(1, sizeof(qpol_handle_t)))) {
		error = errno;
		ERR(NULL, "%s", strerror(error));
		errno = error;
		return -1;
	}
	(*handle)->sh = sepol_handle_create();
	if ((*handle)->sh == NULL) {
		error = errno;
		ERR(*handle, "%s", strerror(error));
		errno = error;
		return -1;
	}

	sepol_msg_set_callback((*handle)->sh, sepol_handle_route_to_callback, (*handle));
	if (fn) {
		(*handle)->fn = fn;
		(*handle)->varg = varg;
	} else {
		(*handle)->fn = qpol_handle_default_callback;
	}

	if (!(*policy = calloc(1, sizeof(qpol_policy_t)))) {
		error = errno;
		goto err;
	}

	if (sepol_policydb_create(&((*policy)->p))) {
		error = errno;
		goto err;
	}

	qpol_src_input = (char *)filedata;
	qpol_src_inputptr = qpol_src_input;
	qpol_src_inputlim = &qpol_src_inputptr[size-1];
	qpol_src_originalinput = qpol_src_input;

	/* read in source */
	if (read_source_policy(*handle, &(*policy)->p->p, "parse") < 0)
		exit(1);

	/* link the source */
	INFO(*handle, "%s", "Linking source policy.");
	if (sepol_link_modules((*handle)->sh, (*policy)->p, NULL, 0, 0)) {
		error = EIO;
		goto err;
	}
	avtab_destroy(&((*policy)->p->p.te_avtab));
	avtab_destroy(&((*policy)->p->p.te_cond_avtab));
	avtab_init(&((*policy)->p->p.te_avtab));
	avtab_init(&((*policy)->p->p.te_cond_avtab));

	/* expand :) */
	if (qpol_expand_module(*handle, *policy)) {
		error = errno;
		goto err;
	}

	return 0;
err:
	sepol_policydb_free((*policy)->p);
	free(*policy);
	*policy = NULL;
	qpol_handle_destroy(handle);
	*handle = NULL;
	errno = error;
	return -1;

}

void qpol_policy_destroy(qpol_policy_t **policy)
{
	if (policy == NULL) {
		errno = EINVAL;
	}
	else if (*policy != NULL) {
		sepol_policydb_free((*policy)->p);
		qpol_extended_image_destroy(&((*policy)->ext));
		free(*policy);
		*policy = NULL;
	}
}

void qpol_handle_destroy(qpol_handle_t **handle)
{
	if (handle == NULL) {
		errno = EINVAL;
	}
	else if (*handle != NULL) {
		sepol_handle_destroy((*handle)->sh);
		free(*handle);
		*handle = NULL;
	}
}

int qpol_policy_reevaluate_conds(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	cond_node_t *cond = NULL;
	cond_av_list_t *list_ptr = NULL;

	if (!handle || !policy) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	for (cond = db->cond_list; cond; cond = cond->next) {
		/* evaluate cond */
		cond->cur_state = cond_evaluate_expr(db, cond->expr);
		if (cond->cur_state < 0) {
			ERR(handle, "Error evaluating conditional: %s", strerror(EILSEQ));
			errno = EILSEQ;
			return STATUS_ERR;
		}

		/* walk true list */
		for (list_ptr = cond->true_list; list_ptr; list_ptr = list_ptr->next) {
			/* field not used (except by write),
			 * now storing list and enabled flags */
			if (cond->cur_state)
				list_ptr->node->merged |= QPOL_COND_RULE_ENABLED;
			else
				list_ptr->node->merged &= ~(QPOL_COND_RULE_ENABLED);
		}

		/* walk false list */
		for (list_ptr = cond->false_list; list_ptr; list_ptr = list_ptr->next) {
			/* field not used (except by write),
			 * now storing list and enabled flags */
			if (!cond->cur_state)
				list_ptr->node->merged |= QPOL_COND_RULE_ENABLED;
			else
				list_ptr->node->merged &= ~(QPOL_COND_RULE_ENABLED);
		}
	}

	return STATUS_SUCCESS;
}
