/* 
 *  Copyright (C) 2003-2004 Tresys Technology, LLC
 *  see file 'COPYING' for use and warranty information
 *
 */

/* 
 *  Author: Jeremy Stitz <jstitz@tresys.com>
 *          Kevin Carr <kcarr@tresys.com>
 *    Date: January 14, 2004
 */

/* 
 *  Header file for replcon
 */

#ifndef REPLCON_H
#define REPLCON_H

/* SE Linux includes*/
#include <selinux/selinux.h>
#include <selinux/context.h>
/* libapol includes */
#include <util.h>
/* standard library includes */
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
/* command line parsing commands */
#define _GNU_SOURCE
#include <getopt.h>
/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>

/* REPLCON_VERSION_NUM should be defined in the make environment */
#ifndef REPLCON_VERSION_NUM
	#define REPLCON_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2003-2004 Tresys Technology, LLC"

#define DEBUG 0
#define NUM_OBJECT_CLASSES 8
#define MAX_INPUT_SIZE 1024
#define NFTW_FLAGS FTW_MOUNT | FTW_PHYS
#define NFTW_DEPTH 1024

/* Data Structures */
typedef enum replcon_classes{  
	NORM_FILE,
	DIR, 
	LNK_FILE, 
	CHR_FILE, 
	BLK_FILE, 
	SOCK_FILE, 
	FIFO_FILE, 
	ALL_FILES
} replcon_classes_t;

const char *replcon_object_classes[] = {"file", "dir", "lnk_file", "chr_file", "blk_file", "sock_file", "fifo_file", "all_files"};

typedef struct replcon_context_pair{
	context_t old_context;
	context_t new_context;
} replcon_context_pair_t;

bool_t replcon_context_equal(context_t a, context_t b);

typedef struct replcon_info{
	bool_t recursive;
	bool_t verbose;
	bool_t quiet;
	bool_t stdin;
	replcon_classes_t *obj_classes;
	int num_classes;
	replcon_context_pair_t *pairs;
	int num_pairs;
	char **locations;
	int num_locations;
} replcon_info_t;

replcon_info_t replcon_info;

void replcon_info_init(replcon_info_t *info);
void replcon_info_free(replcon_info_t *info);
bool_t replcon_info_add_object_class(replcon_info_t *info, const char *class_str);
bool_t replcon_info_has_object_class(replcon_info_t *info, replcon_classes_t class_id);
bool_t replcon_info_add_context_pair(replcon_info_t *info, const char *old, const char *new);
bool_t replcon_info_add_location(replcon_info_t *info, const char *loc);

/* Function Prototypes */
void replcon_usage(const char *program_name, int brief);
void replcon_remove_new_line_char(char *input);
int replcon_is_valid_object_class(const char *class_name);
int replcon_get_file_class(const struct stat *statptr);
int replcon_change_context(const char *filename, const struct stat *statptr, int fileflags, struct FTW *pfwt);
bool_t replcon_is_valid_context_format(const char *context_str);
bool_t replace_context(const char *file, security_context_t new_con);
void replcon_stat_file_replace_context(const char *filename);
#endif
