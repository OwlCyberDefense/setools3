/**
 *  @file
 *  Main program for running sediffx in a GTK+ environment.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
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

#include "sediffx.h"
#include "toplevel.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <glade/glade.h>
#include <gtk/gtk.h>

struct sediffx
{
	apol_policy_path_t *paths[SEDIFFX_POLICY_NUM];
	apol_policy_t *policies[SEDIFFX_POLICY_NUM];
	toplevel_t *top;
	poldiff_t *poldiff;
	uint32_t flags;
};

static struct option const longopts[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"run-diff", no_argument, NULL, 'd'},
	{NULL, 0, NULL, 0}
};

void sediffx_set_policy(sediffx_t * s, sediffx_policy_e which, apol_policy_t * policy, apol_policy_path_t * path)
{
	poldiff_destroy(&s->poldiff);
	if (policy != NULL) {
		apol_policy_destroy(&s->policies[which]);
		s->policies[which] = policy;
		if (path != s->paths[which]) {
			apol_policy_path_destroy(&s->paths[which]);
		}
		s->paths[which] = path;
	} else {
		apol_policy_destroy(&s->policies[which]);
		apol_policy_path_destroy(&s->paths[which]);
	}
}

const apol_policy_path_t *sediffx_get_policy_path(sediffx_t * sediffx, const sediffx_policy_e which)
{
	return sediffx->paths[which];
}

poldiff_t *sediffx_get_poldiff(sediffx_t * s, poldiff_handle_fn_t fn, void *arg)
{
	if (s->poldiff != NULL) {
		return s->poldiff;
	}
	if (s->policies[SEDIFFX_POLICY_ORIG] == NULL || s->policies[SEDIFFX_POLICY_MOD] == NULL) {
		return NULL;
	}
	s->poldiff = poldiff_create(s->policies[SEDIFFX_POLICY_ORIG], s->policies[SEDIFFX_POLICY_MOD], fn, arg);
	if (s->poldiff != NULL) {
		/* poldiff_create() took ownership of the policies */
		s->policies[SEDIFFX_POLICY_ORIG] = NULL;
		s->policies[SEDIFFX_POLICY_MOD] = NULL;
	}
	return s->poldiff;
}

void sediffx_set_poldiff_run_flags(sediffx_t * s, uint32_t flags)
{
	s->flags = flags;
}

uint32_t sediffx_get_poldiff_run_flags(sediffx_t * s)
{
	return s->flags;
}

static void print_version_info(void)
{
	printf("Semantic Policy Difference Tool version " VERSION "\n");
	printf("%s\n", COPYRIGHT_INFO);
}

static void usage(const char *program_name, int brief)
{
	printf("%s (sediffx ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
	printf("Usage: %s [-d] [ORIGINAL_POLICY ; MODIFIED_POLICY]\n", program_name);
	if (brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Semantically differentiate two policies.\n\
All supported policy elements are examined.\n\
The following options are available:\n\
", stdout);
	fputs("\n\
  -d, --diff-now   load policies and diff immediately\n\
  -h, --help       print this help text and exit\n\
  -v, --version    print version information and exit\n\n\
", stdout);
	return;
}

struct delayed_main_data
{
	apol_policy_path_t *orig_path, *mod_path;
	int run_diff;
	toplevel_t *top;
};

/*
 * We don't want to do the heavy work of loading and displaying
 * the diff before the main loop has started because it will freeze
 * the gui for too long. To solve this, the function is called from an
 * idle callback set-up in main.
 */
static gboolean delayed_main(gpointer data)
{
	struct delayed_main_data *dmd = (struct delayed_main_data *)data;
	if (toplevel_open_policies(dmd->top, dmd->orig_path, dmd->mod_path) == 0 && dmd->run_diff) {
		toplevel_run_diff(dmd->top);
	}
	return FALSE;
}

static void sediffx_destroy(sediffx_t ** sediffx)
{
	if (sediffx != NULL && *sediffx != NULL) {
		int i;
		for (i = SEDIFFX_POLICY_ORIG; i < SEDIFFX_POLICY_NUM; i++) {
			apol_policy_path_destroy(&((*sediffx)->paths[i]));
			apol_policy_destroy(&((*sediffx)->policies[i]));
		}
		poldiff_destroy(&((*sediffx)->poldiff));
		free(*sediffx);
		*sediffx = NULL;
	}
}

static void sediffx_parse_command_line(int argc, char **argv, apol_policy_path_t ** orig_path, apol_policy_path_t ** mod_path,
				       int *run_diff)
{
	int optc;
	*orig_path = NULL;
	*mod_path = NULL;
	*run_diff = 0;
	while ((optc = getopt_long(argc, argv, "hvd", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 'd':	       /* run the diff only for gui */
			*run_diff = 1;
			break;
		case 'h':	       /* help */
			usage(argv[0], 0);
			exit(EXIT_SUCCESS);
		case 'v':	       /* version */
			print_version_info();
			exit(EXIT_SUCCESS);
		default:
			usage(argv[0], 1);
			exit(EXIT_FAILURE);
		}
	}

	if (argc - optind == 0) {
		/* here we have found no missing arguments, but
		 * perhaps the user specified -d with no files */
		if (*run_diff) {
			usage(argv[0], 0);
			exit(EXIT_FAILURE);
		}
		return;
	} else if (argc - optind == 1) {
		usage(argv[0], 1);
		exit(EXIT_FAILURE);
	}
	if (argc - optind == 2) {
		/* sediffx with file names, old syntax */
		if (strcmp(argv[optind], ";") == 0 || strcmp(argv[optind + 1], ";") == 0) {
			usage(argv[0], 1);
			exit(EXIT_FAILURE);
		}
		*orig_path = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, argv[optind], NULL);
		*mod_path = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, argv[optind + 1], NULL);
		if (*orig_path == NULL || *mod_path == NULL) {
			ERR(NULL, "%s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		return;
	}

	/* module lists */
	char *orig_base_path = NULL;
	apol_vector_t *orig_module_paths = NULL;
	char *mod_base_path = NULL;
	apol_vector_t *mod_module_paths = NULL;
	apol_policy_path_type_e orig_path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	apol_policy_path_type_e mod_path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;

	orig_base_path = argv[optind++];
	if (!(orig_module_paths = apol_vector_create())) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	for (; argc - optind; optind++) {
		if (!strcmp(";", argv[optind])) {
			optind++;
			break;
		}
		char *tmp = NULL;
		if (!(tmp = strdup(argv[optind]))) {
			ERR(NULL, "Error loading module %s", argv[optind]);
			goto err;
		}
		if (apol_vector_append(orig_module_paths, (void *)tmp)) {
			ERR(NULL, "Error loading module %s", argv[optind]);
			free(tmp);
			goto err;
		}
		orig_path_type = APOL_POLICY_PATH_TYPE_MODULAR;
	}
	*orig_path = apol_policy_path_create(orig_path_type, orig_base_path, orig_module_paths);
	if (*orig_path == NULL) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	orig_module_paths = NULL;

	if (argc - optind == 0) {
		ERR(NULL, "%s", "Missing path to modified policy.");
		goto err;
	}

	mod_base_path = argv[optind++];
	if (!(mod_module_paths = apol_vector_create())) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	for (; argc - optind; optind++) {
		char *tmp = NULL;
		if (!(tmp = strdup(argv[optind]))) {
			ERR(NULL, "Error loading module %s", argv[optind]);
			goto err;
		}
		if (apol_vector_append(mod_module_paths, (void *)tmp)) {
			ERR(NULL, "Error loading module %s", argv[optind]);
			free(tmp);
			goto err;
		}
		mod_path_type = APOL_POLICY_PATH_TYPE_MODULAR;
	}
	*mod_path = apol_policy_path_create(mod_path_type, mod_base_path, mod_module_paths);
	if (*mod_path == NULL) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	return;
      err:
	apol_policy_path_destroy(orig_path);
	apol_policy_path_destroy(mod_path);
	apol_vector_destroy(&orig_module_paths, free);
	apol_vector_destroy(&mod_module_paths, free);
}

int main(int argc, char **argv)
{
	sediffx_t *app;
	apol_policy_path_t *orig_path, *mod_path;
	int run_diff;

	if (!g_thread_supported())
		g_thread_init(NULL);

	gtk_init(&argc, &argv);
	glade_init();
	if (!g_thread_supported())
		g_thread_init(NULL);
	if ((app = calloc(1, sizeof(*app))) == NULL || (app->top = toplevel_create(app)) == NULL) {
		ERR(NULL, "%s", strerror(errno));
		sediffx_destroy(&app);
		exit(EXIT_FAILURE);
	}
	sediffx_parse_command_line(argc, argv, &orig_path, &mod_path, &run_diff);
	if (orig_path != NULL && mod_path != NULL) {
		struct delayed_main_data dmd = { orig_path, mod_path, run_diff, app->top };
		g_idle_add(&delayed_main, &dmd);
	}
	gtk_main();

	sediffx_destroy(&app);
	exit(EXIT_SUCCESS);
}
