/*
 *  Copyright (C) 2003-2005 Tresys Technology, LLC
 *  see file 'COPYING' for use and warranty information
 *
 *  indexcon: a tool for indexing the security contexts of filesystem entities
 */

/* libsefs */
#include <fsdata.h>
/* standard library includes */
#include <stdio.h>
#include <stdlib.h>
/* command line parsing commands */
#define _GNU_SOURCE
#include <getopt.h>

/* INDEXCON_VERSION_NUM should be defined in the make environment */
#ifndef INDEXCON_VERSION_NUM
#define INDEXCON_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2003-2005 Tresys Technology, LLC"

static struct option const longopts[] =
{
  {"directory", required_argument, NULL, 'd'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};


void usage(const char *program_name, int brief)
{
	printf("%s (indexcon ver. %s)\n\n", COPYRIGHT_INFO, INDEXCON_VERSION_NUM);
	printf("Usage: %s <filename> [OPTIONS]\n", program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fprintf(stdout, "\n\
Index SELinux contexts on the filesystem\n\
  -d directory, --directory=directory 	Start scanning at directory\n\
  -h, --help                 display this help and exit\n\
  -v, --version              output version information and exit\n");
	return;
}


int main(int argc, char **argv, char **envp)
{
	char *outfilename = NULL, *dir = "/";
	int optc = 0;
	sefs_filesystem_db_t fsdata;

	fsdata.fsdh = NULL;
	fsdata.dbh = NULL;

	while ((optc = getopt_long (argc, argv, "d:hv", longopts, NULL)) != -1)  {
		switch (optc) {
	  	case 'd': /* directory */
	  		dir = optarg;
	  		break;
		case 'h': /* help */
	  		usage(argv[0], 0);
	  		exit(0);
		case 'v': /* version */
	  		printf("\n%s (indexcon ver. %s)\n\n", COPYRIGHT_INFO, INDEXCON_VERSION_NUM);
	  		exit(0);
		default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}
	if (argc - optind > 1 || argc - optind < 1) {
		usage(argv[0], 1);
		exit(1);
	} else 
		outfilename = argv[optind];

	if (outfilename == NULL) {
		usage(argv[0], 1);
		exit(1);
	}
	
	if (sefs_filesystem_db_populate(&fsdata,dir) == -1) {
		fprintf(stderr, "fsdata_init failed\n");
		return -1;
	}
	if (sefs_filesystem_db_save(&fsdata, outfilename) != 0) {
		fprintf(stderr, "Error writing path database\n");
		return -1;
	}
	sefs_filesystem_db_close(&fsdata);

	return 0;	
}


