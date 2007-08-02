/**
 * @file
 *
 * Command-line program that builds a libsefs database of file
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

#include <sefs/db.hh>
#include <sefs/filesystem.hh>

using namespace std;

#include <iostream>
#include <getopt.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2007 Tresys Technology, LLC"

static struct option const longopts[] = {
	{"directory", required_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{NULL, 0, NULL, 0}
};

static void usage(const char *program_name, bool brief)
{
	cout << "Usage: " << program_name << " FILE [OPTIONS]" << endl << endl;
	if (brief)
	{
		cout << "\tTry " << program_name << " --help for more help." << endl << endl;
		return;
	}
	cout << "Index SELinux contexts on the filesystem." << endl;
	cout << endl;
	cout << "  -d DIR, --directory=DIR  start scanning at directory DIR (default \"/\")" << endl;
	cout << "  -h, --help               print this help text and exit" << endl;
	cout << "  -V, --version            print version information and exit" << endl;
}

int main(int argc, char *argv[])
{
	int optc;

	char *outfilename = NULL, *dir = "/";

	while ((optc = getopt_long(argc, argv, "d:hV", longopts, NULL)) != -1)
	{
		switch (optc)
		{
		case 'd':	       // starting directory
			dir = optarg;
			break;
		case 'h':
			usage(argv[0], false);
			exit(0);
		case 'V':
			cout << "indexcon " << VERSION << endl << COPYRIGHT_INFO << endl;
			exit(0);
		default:
			usage(argv[0], true);
			exit(1);
		}
	}
	if (argc - optind > 1 || argc - optind < 1)
	{
		usage(argv[0], true);
		exit(1);
	}
	else
	{
		outfilename = argv[optind];
	}

	if (outfilename == NULL)
	{
		usage(argv[0], true);
		exit(1);
	}

	sefs_filesystem *fs = NULL;
	sefs_db *db = NULL;
	try
	{
		fs = new sefs_filesystem(dir, NULL, NULL);
		db = new sefs_db(fs, NULL, NULL);
		db->save(outfilename);
	}
	catch(...)
	{
		delete fs;
		delete db;
		exit(2);
	}

	delete fs;
	delete db;

	return 0;
}
