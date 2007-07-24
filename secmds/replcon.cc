/**
 * @file
 *
 * A tool for replacing file contexts in SELinux.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 * Copyright (C) 2003-2007 Tresys Technology, LLC
 *
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
 */

#include <config.h>

#include <sefs/filesystem.hh>
#include <sefs/query.hh>
#include <selinux/selinux.h>
#include <apol/util.h>

using namespace std;

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <iostream>
#include <stdlib.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2007 Tresys Technology, LLC"

enum OPTIONS
{
	OPTION_CONTEXT = 256
};

static struct option const longopts[] = {
	{"class", required_argument, NULL, 'c'},
	{"type", required_argument, NULL, 't'},
	{"user", required_argument, NULL, 'u'},
	{"role", required_argument, NULL, 'r'},
	{"mls-range", required_argument, NULL, 'm'},
	{"path", required_argument, NULL, 'p'},
	{"regex", no_argument, NULL, 'R'},
	{"context", required_argument, NULL, OPTION_CONTEXT},
	{"verbose", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{NULL, 0, NULL, 0}
};

extern int lsetfilecon_raw(const char *, security_context_t) __attribute__ ((weak));

/**
 * As that setools must work with older libselinux versions that may
 * not have the _raw() functions, declare them as weak.  If libselinux
 * does indeed have the new functions then use them; otherwise
 * fallback to the originals.
 */
static int replcon_lsetfilecon(const char *path, security_context_t context)
{
	if (lsetfilecon_raw != NULL)
	{
		return lsetfilecon_raw(path, context);
	}
	else
	{
		return lsetfilecon(path, context);
	}
}

struct replcon_info
{
	bool verbose, mls;
	apol_context_t *replcon;
};

static void usage(const char *program_name, bool brief)
{
	cout << "Usage: " << program_name << " NEW_CONTEXT DIR [OPTIONS] [EXPRESSION]" << endl << endl;
	if (brief)
	{
		cout << "\tTry " << program_name << " --help for more help." << endl << endl;
		return;
	}

	cout << "Replace SELinux file contexts for files matching a given context." << endl << endl;

	cout << "REQUIRED ARGUMENTS :" << endl;
	cout << "  NEW_CONTEXT                    partial or full context to relabel" << endl;
	cout << "  DIR                            starting directory to replace" << endl;
	cout << endl;
	cout << "EXPRESSION:" << endl;
	cout << "  -t TYPE,  --type=TYPE          find contexts with type TYPE" << endl;
	cout << "  -u USER,  --user=USER          find contexts with user USER" << endl;
	cout << "  -r ROLE,  --role=ROLE          find contexts with role ROLE" << endl;
	cout << "  -m RANGE, --mls-range=RANGE    find contexts with MLS range RANGE" << endl;
	cout << "  --context=CONTEXT              partial or full context to find" << endl;
	cout << "                                 (overrides expression options above)" << endl;
	cout << "  -p PATH,  --path=PATH          find files in PATH" << endl;
	cout << "  -c CLASS, --class=CLASS        find files of object class CLASS" << endl;
	cout << endl;

	cout << "OPTIONS:" << endl;
	cout << "  -R, --regex                    enable regular expressions" << endl;
	cout << "  -v, --verbose                  show context of matching files" << endl;
	cout << "  -h, --help                     print this help text and exit" << endl;
	cout << "  -V, --version                  print version information and exit" << endl;
	cout << endl;
	cout << "If the fclist does not contain MLS ranges and -m was given," << endl;
	cout << "then the search will return nothing." << endl;
	cout << endl;
	cout << "NEW_CONTEXT is as a colon separated list of user, role, type, and MLS range" << endl;
	cout << "such as follows: user_u:object_r:user_t:s0.  If a field is not specified," << endl;
	cout << "that portion of the context will not be replaced." << endl;
	cout << "Examples:" << endl;
	cout << "    replcon ::type_t: ." << endl;
	cout << "        Replace all files and subdirectories in current directory with" << endl;
	cout << "        type type_t, recursing within the directory." << endl;
	cout << "    replcon -u user_u *:role_r:* ." << endl;
	cout << "        Replace files that contain user_u with role role_r." << endl;
	cout << "    replcon --context ::type_t:so :::s0:c0 /tmp" << endl;
	cout << "        Replace files with type type_t and level s0 in /tmp with MLS" << endl;
	cout << "        range s0:c0." << endl;
}

static int replace_entry(sefs_fclist * fclist, const sefs_entry * e, void *arg)
{
	struct replcon_info *r = static_cast < struct replcon_info *>(arg);
	const apol_context_t *scon = e->context();
	const char *user, *role, *type;
	char *con_str = NULL;
	size_t len = 0;

	// determine what the new context should be
	if ((user = apol_context_get_user(r->replcon)) == NULL)
	{
		user = apol_context_get_user(scon);
	}
	if ((role = apol_context_get_role(r->replcon)) == NULL)
	{
		role = apol_context_get_role(scon);
	}
	if ((type = apol_context_get_type(r->replcon)) == NULL)
	{
		type = apol_context_get_type(scon);
	}
	if (apol_str_appendf(&con_str, &len, "%s:%s:%s", user, role, type) < 0)
	{
		return -1;
	}
	if (r->mls)
	{
		const apol_mls_range_t *apol_range = NULL;
		char *range = NULL;
		if ((apol_range = apol_context_get_range(r->replcon)) == NULL)
		{
			apol_range = apol_context_get_range(scon);
		}
		if ((range = apol_mls_range_render(NULL, apol_range)) == NULL || apol_str_appendf(&con_str, &len, ":%s", range) < 0)
		{
			free(range);
			free(con_str);
			return -1;
		}
		free(range);
	}

	if (r->verbose)
	{
		char *lcon = NULL, *rcon = NULL;
		if (r->mls)
		{
			lcon = apol_context_render(NULL, r->replcon);
			rcon = apol_context_render(NULL, scon);
		}
		else
		{
			if (asprintf(&lcon, "%s:%s:%s",
				     apol_context_get_user(r->replcon),
				     apol_context_get_role(r->replcon), apol_context_get_type(r->replcon)) < 0)
			{
				lcon = NULL;
			}
			if (asprintf(&rcon, "%s:%s:%s",
				     apol_context_get_user(scon), apol_context_get_role(scon), apol_context_get_type(scon)) < 0)
			{
				rcon = NULL;
			}
		}
		if (lcon == NULL || rcon == NULL)
		{
			free(lcon);
			free(rcon);
			return -1;
		}
		printf("%s: %s --> %s\n", e->path(), lcon, rcon);
		free(lcon);
		free(rcon);
	}

	// until there is a way to create a security_context_t from a
	// char *, simply perform the implicit cast below
	if (replcon_lsetfilecon(e->path(), con_str) != 0)
	{
		cerr << "Could not set context " << con_str << " for file " << e->path() << "." << endl;
		free(con_str);
		return -1;
	}

	free(con_str);
	return 0;
}

int main(int argc, char *argv[])
{
	int optc;
	struct replcon_info r;

	r.verbose = false;
	r.replcon = NULL;
	sefs_query *query = new sefs_query();

	apol_context_t *context = NULL;
	try
	{
		while ((optc = getopt_long(argc, argv, "t:u:r:m:p:c:RvhV", longopts, NULL)) != -1)
		{
			switch (optc)
			{
			case 't':
				if (context == NULL)
				{
					query->type(optarg, false);
				}
				break;
			case 'u':
				if (context == NULL)
				{
					query->user(optarg);
				}
				break;
			case 'r':
				if (context == NULL)
				{
					query->role(optarg);
				}
				break;
			case 'm':
				if (context == NULL)
				{
					query->range(optarg, APOL_QUERY_EXACT);
				}
				break;
			case OPTION_CONTEXT:
				if ((context = apol_context_create_from_literal(optarg)) == NULL)
				{
					cerr << "Could not create source context." << endl;
					throw runtime_error(strerror(errno));
				}
				break;
			case 'p':
				query->path(optarg);
				break;
			case 'c':
				query->objectClass(optarg);
				break;
			case 'R':
				query->regex(true);
				break;
			case 'v':
				r.verbose = true;
				break;
			case 'h':     // help
				usage(argv[0], false);
				exit(0);
			case 'V':     // version
				cout << "replcon " << VERSION << endl << COPYRIGHT_INFO << endl;
				exit(0);
			default:
				usage(argv[0], true);
				exit(1);
			}
			if (context != NULL)
			{
				query->user(apol_context_get_user(context));
				query->role(apol_context_get_role(context));
				query->type(apol_context_get_type(context), false);
				if (apol_context_get_range(context) != NULL)
				{
					char *rng = apol_mls_range_render(NULL, apol_context_get_range(context));
					query->range(rng, APOL_QUERY_EXACT);
					free(rng);
				}
				else
				{
					query->range(NULL, APOL_QUERY_EXACT);
				}
			}
		}
	}
	catch(bad_alloc)
	{
		cerr << strerror(errno) << endl;
		apol_context_destroy(&context);
		delete query;
		exit(-1);
	}
	apol_context_destroy(&context);

	if (optind + 2 != argc)
	{
		usage(argv[0], 1);
		delete query;
		exit(-1);
	}

	sefs_fclist *fclist = NULL;
	try
	{
		fclist = new sefs_filesystem(argv[optind + 1], NULL, NULL);
		r.mls = fclist->isMLS();

		if ((r.replcon = apol_context_create_from_literal(argv[optind])) == NULL)
		{
			cerr << "Could not create replacement context." << endl;
			throw runtime_error(strerror(errno));
		}

		if (fclist->runQueryMap(query, replace_entry, &r) < 0)
		{
			throw runtime_error(strerror(errno));
		}
	}
	catch(...)
	{
		delete query;
		delete fclist;
		apol_context_destroy(&(r.replcon));
		exit(-1);
	}

	delete query;
	delete fclist;
	apol_context_destroy(&(r.replcon));
	return 0;
}
