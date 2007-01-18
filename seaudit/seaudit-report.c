/**
 *  @file
 *  Command line tool for processing SELinux audit logs and generating
 *  a concise report containing standard information as well as
 *  customized information using seaudit views.  Reports are rendered
 *  in either HTML or plain text.  Future support will provide
 *  rendering into XML.  The HTML report can be formatted by providing
 *  an alternate stylesheet file or by configuring the default
 *  stylesheet.  This tool also provides the option for including
 *  malformed strings within the report.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#include <config.h>

#include <seaudit/log.h>
#include <seaudit/parse.h>
#include <seaudit/report.h>

#include <apol/vector.h>

#include <libxml/xmlreader.h>

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COPYRIGHT_INFO "Copyright (C) 2004-2007 Tresys Technology, LLC"

static struct option const longopts[] = {
	{"html", no_argument, NULL, 'H'},
	{"malformed", no_argument, NULL, 'm'},
	{"output", required_argument, NULL, 'o'},
	{"stylesheet", required_argument, NULL, 'S'},
	{"stdin", no_argument, NULL, 's'},
	{"config", no_argument, NULL, 'c'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

/**
 * Vector of seaudit_log_t, corresponding to each of the log files to
 * process.
 */
static apol_vector_t *logs = NULL;

/**
 * Error reporting log handler.
 */
static seaudit_log_t *first_log = NULL;

/**
 * Model that incorporates all of the logs within the logs vector.
 */
static seaudit_model_t *model = NULL;

/**
 * Report object for the above model.
 */
static seaudit_report_t *report = NULL;

/**
 * Destination file for the seaudit report, or NULL to write to
 * standard output.
 */
static char *outfile = NULL;

static void seaudit_report_info_usage(const char *program_name, int brief)
{
	printf("%s (seaudit-report ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
	printf("\nDescription: Generate a customized SELinux log report.\n");
	printf("Usage: %s [OPTIONS] LOGFILE ...\n", program_name);
	if (brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	printf("  -s, --stdin              read log data from standard input\n");
	printf("  -m, --malformed          include malformed log messages\n");
	printf("  -oFILE, --output=FILE    output to FILE\n");
	printf("  -cFILE, --config=FILE    read configuration from FILE\n");
	printf("  --html                   set output format to HTML\n");
	printf("  --stylesheet=FILE        HTML style sheet for formatting HTML report\n");
	printf("                           (ignored if --html is not given)\n");
	printf("  -v, --version            print version information and exit\n");
	printf("  -h, --help               print this help text and exit\n");
	printf("\n");
	printf("Default style sheet is at %s.\n", APOL_INSTALL_DIR);
}

static void parse_command_line_args(int argc, char **argv)
{
	int optc, i;
	int do_malformed = 0, do_style = 0, read_stdin = 0;
	seaudit_report_format_e format = SEAUDIT_REPORT_FORMAT_TEXT;
	char *configfile = NULL, *stylesheet = NULL;

	/* get option arguments */
	while ((optc = getopt_long(argc, argv, "o:c:t:msvh", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 'o':	       /* output file name */
			outfile = optarg;
			break;
		case 'c':	       /* Alternate config file path */
			configfile = optarg;
			break;
		case 'S':	       /* HTML style sheet file path */
			stylesheet = optarg;
			do_style = 1;
			break;
		case 'm':	       /* include malformed messages */
			do_malformed = 1;
			break;
		case 's':	       /* read LOGFILES from standard input */
			read_stdin = 1;
			break;
		case 'H':	       /* Set the output to format to html */
			format = SEAUDIT_REPORT_FORMAT_HTML;
			do_style = 1;
			break;
		case 'v':
			/* display version */
			printf("\n%s (seaudit-report ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
			exit(0);
		case 'h':
			/* display help */
			seaudit_report_info_usage(argv[0], 0);
			exit(0);
		default:
			/* display usage and handle error */
			seaudit_report_info_usage(argv[0], 1);
			exit(-1);
		}
	}

	/* Throw warning if a stylesheet was specified, but the --html
	 * option was not. */
	if (stylesheet != NULL && format != SEAUDIT_REPORT_FORMAT_HTML) {
		fprintf(stderr, "Warning: The --html option was not specified.\n");
		exit(-1);
	}

	if (!read_stdin && optind >= argc) {
		/* display usage and handle error */
		seaudit_report_info_usage(argv[0], 1);
		exit(-1);
	}

	if ((model = seaudit_model_create("seaudit-report", NULL)) == NULL) {
		exit(-1);
	}
	if ((first_log = seaudit_log_create(NULL, NULL)) == NULL || seaudit_model_append_log(model, first_log) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(-1);
	}
	if ((logs = apol_vector_create()) == NULL || apol_vector_append(logs, first_log) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(-1);
	}
	if (read_stdin) {
		/* Ensure that logfiles were not specified in addition
		 * to the standard-in option */
		if (optind < argc) {
			fprintf(stderr, "WARNING: %s\n", "Command line filename(s) will be ignored. Reading from stdin.");
		}
		if (seaudit_log_parse(first_log, stdin) < 0) {
			exit(-1);
		}
	} else {
		/* Parse given filenames */
		FILE *f;
		seaudit_log_t *l;
		if ((f = fopen(argv[optind], "r")) == NULL) {
			fprintf(stderr, "ERROR: %s\n", strerror(errno));
			exit(-1);
		}
		if (seaudit_log_parse(first_log, f) < 0) {
			exit(-1);
		}
		fclose(f);
		for (i = optind + 1; i < argc; i++) {
			if ((l = seaudit_log_create(NULL, NULL)) == NULL || seaudit_model_append_log(model, l) < 0) {
				exit(-1);
			}
			if (apol_vector_append(logs, l) < 0) {
				fprintf(stderr, "ERROR: %s\n", strerror(errno));
				exit(-1);
			}
			if ((f = fopen(argv[i], "r")) == NULL) {
				fprintf(stderr, "ERROR: %s\n", strerror(errno));
				exit(-1);
			}
			if (seaudit_log_parse(l, f) < 0) {
				exit(-1);
			}
			fclose(f);
		}
	}

	if ((report = seaudit_report_create(model)) == NULL ||
	    seaudit_report_set_format(first_log, report, format) < 0 ||
	    seaudit_report_set_configuration(first_log, report, configfile) < 0 ||
	    seaudit_report_set_stylesheet(first_log, report, stylesheet, do_style) < 0 ||
	    seaudit_report_set_malformed(first_log, report, do_malformed) < 0) {
		exit(-1);
	}
}

int main(int argc, char **argv)
{
	size_t i;
	parse_command_line_args(argc, argv);
	if (seaudit_report_write(first_log, report, outfile) < 0) {
		return -1;
	}
	seaudit_report_destroy(&report);
	seaudit_model_destroy(&model);
	for (i = 0; i < apol_vector_get_size(logs); i++) {
		seaudit_log_t *l = apol_vector_get_element(logs, i);
		seaudit_log_destroy(&l);
	}
	apol_vector_destroy(&logs, NULL);
	return 0;
}
