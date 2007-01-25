/**
 *  @file
 *  Main driver for the seaudit application.  This file also
 *  implements the main class seaudit_t.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "seaudit.h"
#include "toplevel.h"

#include <apol/util.h>
#include <seaudit/model.h>
#include <seaudit/parse.h>
#include <seaudit/util.h>

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <glade/glade.h>
#include <glib.h>
#include <gtk/gtk.h>

struct seaudit
{
	preferences_t *prefs;
	apol_policy_t *policy;
	apol_policy_path_t *policy_path;
	seaudit_log_t *log;
	FILE *file;
	char *log_path;
	size_t num_log_messages;
	struct tm *first, *last;
	toplevel_t *top;
};

static struct option const opts[] = {
	{"log", required_argument, NULL, 'l'},
	{"policy", required_argument, NULL, 'p'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

preferences_t *seaudit_get_prefs(seaudit_t * s)
{
	return s->prefs;
}

void seaudit_set_policy(seaudit_t * s, apol_policy_t * policy, apol_policy_path_t * path)
{
	if (policy != NULL) {
		if (preferences_add_recent_policy(s->prefs, path) < 0) {
			toplevel_ERR(s->top, "%s", strerror(errno));
			apol_policy_destroy(&policy);
			return;
		}
		apol_policy_destroy(&s->policy);
		s->policy = policy;
		if (path != s->policy_path) {
			apol_policy_path_destroy(&s->policy_path);
		}
		s->policy_path = path;
	} else {
		apol_policy_destroy(&s->policy);
		apol_policy_path_destroy(&s->policy_path);
	}
}

apol_policy_t *seaudit_get_policy(seaudit_t * s)
{
	return s->policy;
}

apol_policy_path_t *seaudit_get_policy_path(seaudit_t * s)
{
	return s->policy_path;
}

void seaudit_set_log(seaudit_t * s, seaudit_log_t * log, FILE * f, const char *filename)
{
	if (s->file != NULL) {
		fclose(s->file);
		s->file = NULL;
	}
	if (log != NULL) {
		seaudit_model_t *model = NULL;
		apol_vector_t *messages = NULL;
		char *t = NULL;
		if ((model = seaudit_model_create(NULL, log)) == NULL ||
		    (messages = seaudit_model_get_messages(log, model)) == NULL ||
		    (t = strdup(filename)) == NULL || preferences_add_recent_log(s->prefs, filename) < 0) {
			toplevel_ERR(s->top, "%s", strerror(errno));
			seaudit_log_destroy(&log);
			seaudit_model_destroy(&model);
			apol_vector_destroy(&messages, NULL);
			free(t);
			return;
		}
		/* do it in this order, for filename could be pointing to
		 * s->log_path */
		seaudit_log_destroy(&s->log);
		s->log = log;
		s->file = f;
		free(s->log_path);
		s->log_path = t;
		s->num_log_messages = apol_vector_get_size(messages);
		if (s->num_log_messages == 0) {
			s->first = s->last = NULL;
		} else {
			seaudit_message_t *message = apol_vector_get_element(messages, 0);
			s->first = seaudit_message_get_time(message);
			message = apol_vector_get_element(messages, s->num_log_messages - 1);
			s->last = seaudit_message_get_time(message);
		}
		seaudit_model_destroy(&model);
		apol_vector_destroy(&messages, NULL);
	} else {
		seaudit_log_destroy(&s->log);
		free(s->log_path);
		s->log_path = NULL;
		s->num_log_messages = 0;
		s->first = s->last = NULL;
	}
}

int seaudit_parse_log(seaudit_t * s)
{
	return seaudit_log_parse(s->log, s->file);
}

seaudit_log_t *seaudit_get_log(seaudit_t * s)
{
	return s->log;
}

char *seaudit_get_log_path(seaudit_t * s)
{
	return s->log_path;
}

apol_vector_t *seaudit_get_log_users(seaudit_t * s)
{
	if (s->log == NULL) {
		return NULL;
	} else {
		return seaudit_log_get_users(s->log);
	}
}

apol_vector_t *seaudit_get_log_roles(seaudit_t * s)
{
	if (s->log == NULL) {
		return NULL;
	} else {
		return seaudit_log_get_roles(s->log);
	}
}

apol_vector_t *seaudit_get_log_types(seaudit_t * s)
{
	if (s->log == NULL) {
		return NULL;
	} else {
		return seaudit_log_get_types(s->log);
	}
}

apol_vector_t *seaudit_get_log_classes(seaudit_t * s)
{
	if (s->log == NULL) {
		return NULL;
	} else {
		return seaudit_log_get_classes(s->log);
	}
}

size_t seaudit_get_num_log_messages(seaudit_t * s)
{
	return s->num_log_messages;
}

struct tm *seaudit_get_log_first(seaudit_t * s)
{
	return s->first;
}

struct tm *seaudit_get_log_last(seaudit_t * s)
{
	return s->last;
}

static seaudit_t *seaudit_create(preferences_t * prefs)
{
	seaudit_t *s = calloc(1, sizeof(*s));
	if (s != NULL) {
		s->prefs = prefs;
	}
	return s;
}

static void seaudit_destroy(seaudit_t ** s)
{
	if (s != NULL && *s != NULL) {
		apol_policy_destroy(&(*s)->policy);
		seaudit_log_destroy(&(*s)->log);
		if ((*s)->file != NULL) {
			fclose((*s)->file);
		}
		preferences_destroy(&(*s)->prefs);
		toplevel_destroy(&(*s)->top);
		free((*s)->policy_path);
		free((*s)->log_path);
		free(*s);
		*s = NULL;
	}
}

static void print_version_info(void)
{
	printf("Audit Log analysis tool for Security Enhanced Linux\n\n");
	printf("   GUI version %s\n", VERSION);
	printf("   libapol version %s\n", libapol_get_version());
	printf("   libseaudit version %s\n\n", libseaudit_get_version());
}

static void print_usage_info(const char *program_name, int brief)
{
	printf("Usage:%s [OPTIONS] [POLICY ...]\n", program_name);
	if (brief) {
		printf("\tTry %s --help for more help.\n", program_name);
		return;
	}
	printf("Audit Log analysis tool for Security Enhanced Linux\n\n");
	printf("   -l FILE, --log=FILE     open the log FILE\n");
	printf("   -h, --help              print this help text and exit\n");
	printf("   -v, --version           print version information and exit\n\n");
}

static void seaudit_parse_command_line(seaudit_t * seaudit, int argc, char **argv, const char **log, apol_policy_path_t ** policy)
{
	int optc;
	*log = NULL;
	*policy = NULL;
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	char *primary_path = NULL;
	apol_vector_t *modules = NULL;
	while ((optc = getopt_long(argc, argv, "l:p:hv", opts, NULL)) != -1) {
		switch (optc) {
		case 'l':{
				*log = optarg;
				break;
			}
		case 'p':{
				primary_path = optarg;
				WARN(NULL, "%s", "Use of --policy is deprecated.");
				break;
			}
		case 'h':{
				print_usage_info(argv[0], 0);
				seaudit_destroy(&seaudit);
				exit(EXIT_SUCCESS);
			}
		case 'v':{
				print_version_info();
				seaudit_destroy(&seaudit);
				exit(EXIT_SUCCESS);
			}
		case '?':
		default:{
				/* unrecognized argument give full usage */
				print_usage_info(argv[0], 1);
				seaudit_destroy(&seaudit);
				exit(EXIT_FAILURE);
			}
		}
	}
	if (optind < argc) {	       /* modules */
		if ((modules = apol_vector_create()) == NULL) {
			ERR(NULL, "%s", strerror(ENOMEM));
			seaudit_destroy(&seaudit);
			exit(EXIT_FAILURE);
		}
		path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
		primary_path = argv[optind++];
		while (argc - optind) {
			if (apol_vector_append(modules, argv[optind])) {
				ERR(NULL, "%s", strerror(ENOMEM));
				seaudit_destroy(&seaudit);
				exit(EXIT_FAILURE);
			}
			path_type = APOL_POLICY_PATH_TYPE_MODULAR;
			optind++;
		}
	}
	if (*log == NULL) {
		*log = preferences_get_log(seaudit->prefs);
	}
	if (primary_path != NULL && strcmp(primary_path, "") != 0) {
		if ((*policy = apol_policy_path_create(path_type, primary_path, modules)) == NULL) {
			ERR(NULL, "%s", strerror(ENOMEM));
			seaudit_destroy(&seaudit);
			exit(EXIT_FAILURE);
		}
	} else {
		const apol_policy_path_t *path = preferences_get_policy(seaudit->prefs);
		if (path != NULL && (*policy = apol_policy_path_create_from_policy_path(path)) == NULL) {
			ERR(NULL, "%s", strerror(ENOMEM));
			seaudit_destroy(&seaudit);
			exit(EXIT_FAILURE);
		}
	}
}

/*
 * We don't want to do the heavy work of loading and displaying the
 * log and policy before the main loop has started because it will
 * freeze the gui for too long.  To solve this, the function is called
 * from an idle callback set-up in main.
 */
struct delay_file_data
{
	toplevel_t *top;
	const char *log_filename;
	apol_policy_path_t *policy_path;
};

static gboolean delayed_main(gpointer data)
{
	struct delay_file_data *dfd = (struct delay_file_data *)data;
	if (dfd->log_filename != NULL && strcmp(dfd->log_filename, "") != 0) {
		toplevel_open_log(dfd->top, dfd->log_filename);
	}
	if (dfd->policy_path != NULL) {
		toplevel_open_policy(dfd->top, dfd->policy_path);
	}
	return FALSE;
}

int main(int argc, char **argv)
{
	preferences_t *prefs;
	seaudit_t *app;
	const char *log;
	apol_policy_path_t *policy;
	apol_vector_t *modules;
	struct delay_file_data file_data;

	gtk_init(&argc, &argv);
	glade_init();
	if (!g_thread_supported())
		g_thread_init(NULL);
	if ((prefs = preferences_create()) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		exit(EXIT_FAILURE);
	}
	if ((app = seaudit_create(prefs)) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		exit(EXIT_FAILURE);
	}
	if ((modules = apol_vector_create()) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		exit(EXIT_FAILURE);
	}
	seaudit_parse_command_line(app, argc, argv, &log, &policy);
	if ((app->top = toplevel_create(app)) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		seaudit_destroy(&app);
		exit(EXIT_FAILURE);
	}
	file_data.top = app->top;
	file_data.log_filename = log;
	file_data.policy_path = policy;
	g_idle_add(&delayed_main, &file_data);
	gtk_main();
	if (preferences_write_to_conf_file(app->prefs) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
	}
	apol_vector_destroy(&modules, NULL);
	seaudit_destroy(&app);
	exit(EXIT_SUCCESS);
}
