/**
 * @file
 * Command-line program that builds a SQLite3 database of file
 * contexts.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *  indexcon: a tool for indexing the security contexts of filesystem entities
 */

#include <config.h>

#include <sefs/fsdata.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2007 Tresys Technology, LLC"

static struct option const longopts[] = {
	{"directory", required_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

void usage(const char *program_name, int brief)
{
	printf("Usage: %s FILE [OPTIONS]\n\n", program_name);
	if (brief) {
		printf("\tTry %s --help for more help.\n\n", program_name);
		return;
	}
	printf("Index SELinux contexts on the filesystem.\n\n");
	printf("  -d DIR, --directory=DIR  start scanning at directory DIR\n");
	printf("  -h, --help               print this help text and exit\n");
	printf("  -v, --version            print version information and exit\n\n");
}

int main(int argc, char **argv, char **envp)
{
	char *outfilename = NULL, *dir = "/";
	int optc = 0, rt;
	sefs_filesystem_db_t fsdata;

	fsdata.fsdh = NULL;
	fsdata.dbh = NULL;

	while ((optc = getopt_long(argc, argv, "d:hv", longopts, NULL)) != -1) {
		switch (optc) {
		case 'd':	       /* directory */
			dir = optarg;
			break;
		case 'h':	       /* help */
			usage(argv[0], 0);
			exit(0);
		case 'v':	       /* version */
			printf("indexcon %s\n%s\n", VERSION, COPYRIGHT_INFO);
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
	rt = sefs_filesystem_db_populate(&fsdata, dir);
	if (rt == -1) {
		fprintf(stderr, "Error populating database.\n");
		return -1;
	} else if (rt == SEFS_NOT_A_DIR_ERROR) {
		fprintf(stderr, "The pathname %s is not a directory.\n", dir);
		return -1;
	} else if (rt == SEFS_DIR_ACCESS_ERROR) {
		fprintf(stderr, "You do not have permission to read the directory %s.\n", dir);
		return -1;
	}

	if (sefs_filesystem_db_save(&fsdata, outfilename) != 0) {
		fprintf(stderr, "Error creating index file.\n");
		return -1;
	}
	sefs_filesystem_db_close(&fsdata);

	return 0;
}
