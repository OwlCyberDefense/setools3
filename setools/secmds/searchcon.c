/*
 *  Copyright (C) 2003-2004 Tresys Technology, LLC
 *  see file 'COPYING' for use and warranty information
 *
 */

/*
 *  Authors: Terrence Mitchem <tmitchem@tresys.com>
 *	     Karl Macmillan <kmacmillan@tresys.com>
 *
 *  searchcon: a tool for searching SELinux filesystem databases
 */

/* SE Linux includes*/
#include <selinux/selinux.h>
#include <selinux/context.h>
/* standard library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
#define _GNU_SOURCE
#include <getopt.h>
/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>
#include <mntent.h>
/* AVL Tree Handling */
#include <avl-util.h>
#include <policy.h>

#include <fsdata.h>

/* LISTCON_VERSION_NUM should be defined in the make environment */
#ifndef SEARCHCON_VERSION_NUM
#define SEARCHCON_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004 Tresys Technology, LLC"

static struct option const longopts[] =
{
  {"filename", required_argument, NULL, 'f'},
  {"type", required_argument, NULL, 't'},
  {"user", required_argument, NULL, 'u'},
  {"path", required_argument, NULL, 'p'},
  {"list", no_argument, NULL, 'l'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};


void usage(const char *program_name, int brief)
{
	printf("%s (listcon ver. %s)\n\n", COPYRIGHT_INFO, SEARCHCON_VERSION_NUM);
	printf("Usage: %s [OPTIONS]\n", program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Print requested information about an SELinux policy.\n\
  -f filename, --filename=filename 	The snapshot file to use\n\
  -t type, --type=typename   		The name of the type to search for\n\
  -u user, --user=username   		The name of the user to search for\n\
  -p path, --path=pathname   		The path or path fragment to search for\n\
  -l, --list				List types in thew snapshot\n\
", stdout);
fputs("\n\
  -h, --help                 display this help and exit\n\
  -v, --version              output version information and exit\n\
", stdout);
	return;
}


int sefs_search_type(sefs_filesystem_data_t * fsd, char * tname)
{
	int i = 0, j = 0, idx = 0;
	sefs_typeinfo_t * typeinfo = NULL;
	sefs_fileinfo_t * fileinfo = NULL;
	char * pathname = NULL;

	if (fsd == NULL) {
		fprintf(stderr, "fsd is null\n");
		return(-1);
	}

	if (tname == NULL) {
		fprintf(stderr, "typename is null\n");
		return(-1);
	}

	idx = avl_get_idx(tname, &(fsd->typetree));

	if (idx == -1)
		return(0);

	typeinfo = &(fsd->types[idx]);

	for (i = 0; i <= typeinfo->numpaths; i++) {
		fileinfo = &(fsd->paths[typeinfo->pathitems[i]]);
		
		for (j = 0; j < fileinfo->numpaths; j++) {
			pathname = fileinfo->pathnames[j];
			printf("%s\n", pathname);
		}
	}

	return(1);
}


int sefs_search_user(sefs_filesystem_data_t * fsd, char * uname)
{
	int i = 0, j = 0;
	sefs_fileinfo_t * fileinfo = NULL;
	const char * u = NULL;
	char * pathname = NULL;
	int match = 0;


	if (fsd == NULL) {
		fprintf(stderr, "fsd is null\n");
		return(-1);
	}

	for (i = 0; i < fsd->numpaths; i++) {
		fileinfo = &(fsd->paths[i]);
		u = context_user_get(fileinfo->context);

		if (u == NULL) continue;

		if (strcmp(uname, u) == 0) {
			match = 1;
			for (j = 0; j < fileinfo->numpaths; j++) {
				pathname = fileinfo->pathnames[j];
				printf("%s\n", pathname);
			}
		}
	}

	return(match);
}


int sefs_list_types(sefs_filesystem_data_t * fsd)
{
	int i = 0;

	for (i = 0; i < fsd->numtypes; i++) {
		printf("%s\n", fsd->types[i].setypename);
	}

	return(1);
}


int main(int argc, char **argv, char **envp)
{
	char *filename = NULL, *tname = NULL, *uname = NULL, *path = NULL;
	int optc = 0, rc = 0, list = 0;
	sefs_filesystem_data_t fsdata;
	
	while ((optc = getopt_long (argc, argv, "f:t:u:p:lhv", longopts, NULL)) != -1)  {
		switch (optc) {
	  	case 'f': /* snapshot file */
	  		filename = optarg;
	  		break;
		case 't': /* type */
	  		tname = optarg;
	  		break;
		case 'u': /* user */
	  		uname = optarg;
	  		break;
		case 'p': /* path */
	  		path = optarg;
	  		break;
		case 'l': /* path */
	  		list = 1;
	  		break;
		case 'h': /* help */
	  		usage(argv[0], 0);
	  		exit(0);
		case 'v': /* version */
	  		printf("\n%s (searchcon ver. %s)\n\n", COPYRIGHT_INFO, SEARCHCON_VERSION_NUM);
	  		exit(0);
		default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}
	
	if (filename == NULL) {
		fprintf(stderr, "\n-f|--filename is required\n\n");
		usage(argv[0], 0);
		return(-1);
	}
	
	if ((tname == NULL) && (uname == NULL) && (path == NULL) && !list) {
		fprintf(stderr, "\nYou must specify one of -t|-u|-p\n\n");
		usage(argv[0], 0);
		return(-1);
	}
	
	if (sefs_filesystem_data_init(&fsdata) == -1) {
		fprintf(stderr, "sefs_filesystem_data_init failed\n");
		return(-1);
	}
	
	if (sefs_filesystem_data_load(&fsdata, filename) == -1) {
		fprintf(stderr, "sefs_filesystem_data_load failed\n");
		return(-1);
	}
	
	if (sefs_filesystem_data_index(&fsdata) == -1) {
		fprintf(stderr, "sefs_filesystem_data_index failed\n");
		return(-1);
	}

	if (list) {
		if (sefs_list_types(&fsdata) == -1) {
			fprintf(stderr, "list_types() returned error\n");
			return(-1);
		}
		return(0);
	}

	if (uname != NULL) {
		rc = sefs_search_user(&fsdata, uname);

		switch(rc) {
		case -1:
			fprintf(stderr, "search_type() returned an error\n");
			return(-1);
		case 0:
			fprintf(stderr, "user was not found\n");
			return(-1);
		default:
			break;
		}

		return(0);
	}

	if (tname != NULL) {
		rc = sefs_search_type(&fsdata, tname);

		switch(rc) {
		case -1:
			fprintf(stderr, "search_type() returned an error\n");
			return(-1);
		case 0:
			fprintf(stderr, "type was not found\n");
			return(-1);
		default:
			break;
		}

		return(0);
	}


	return(0);


}
