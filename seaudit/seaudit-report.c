/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: 8-17-2004
 */

/* seaudit-report: command line tool for processing SELinux audit logs and
 * generating a concise report containing standard information as well as 
 * customized information using seaudit views. Reports are rendered in either
 * HTML or plain text. Future support will provide rendering into XML. The 
 * HTML report can be formatted by providing an alternate stylesheet file
 * or by configuring the default stylesheet. This tool also provides the 
 * option for including malformed strings within the report.
 */
 
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <libxml/xmlreader.h>

/* SEREPORT_VERSION_NUM should be defined in the make environment */
#ifndef SEREPORT_VERSION_NUM
#define SEREPORT_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004 Tresys Technology, LLC"

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

void seaudit_report_info_usage(const char *program_name, bool_t brief)
{
	printf("%s (seaudit-report ver. %s)\n\n", COPYRIGHT_INFO, SEREPORT_VERSION_NUM);
	printf("\nDescription: Generate a customized SELinux log report.\n");
	printf("Usage: %s [OPTIONS] LOGFILES\n", program_name);
	if (brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	printf("  -s,  --stdin          	Read LOGFILES from standard input.\n");
	printf("  -m,  --malformed     		Include malformed log messages.\n");
	printf("  -o <file>, --output <file>  	Output to file.\n");
	printf("  -c <file>, --config <file>	Use alternate config file.\n");
	printf("  --html          		Set the output to format to HTML. Plain text is the default.\n");
	printf("  --stylesheet <file>		HTML stylesheet to be used for formatting an HTML report.\n");
	printf("  				This option is only used if --html option is also provided.\n");
	printf("				See %s/%s for example of stylesheet source to use.\n", APOL_INSTALL_DIR, STYLESHEET_FILE);
	printf("  -v,  --version        	Display version information and exit.\n");
	printf("  -h,  --help           	Display this help and exit.\n");
	printf("\n");
	
	return;
}

static void seaudit_report_parse_command_line_args(int argc, char **argv, seaudit_report_t *report_info) {
	int optc, i;

	/* get option arguments */
	while ((optc =
		getopt_long(argc, argv, "o:c:t:msvh", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 'o':
			/* File to save output to */
			if (optarg != 0) {
	  			if (seaudit_report_add_outFile_path(optarg, report_info) != 0)
	  				goto err;
	  		}
			break;
		case 'c':
			/* Alternate config file path */ 
			if (optarg != 0) {
	  			if (seaudit_report_add_configFile_path(optarg, report_info) != 0)
	  				goto err;
	  		}
			break;
		case 'S':
			/* HTML style sheet file path */ 
			if (optarg != 0) {
	  			if (seaudit_report_add_stylesheet_path(optarg, report_info) != 0)
	  				goto err;
	  		}
			break;
		case 'm':
			/* include malformed messages */	
			report_info->malformed = TRUE;
			break;
		case 's':	
			/* read LOGFILES from standard input */
			report_info->stdin = TRUE;
			break;
		case 'H':
			/* Set the output to format to html */
			report_info->html = TRUE;
			break;
		case 'v':	
			/* display version */
			printf("\n%s (seaudit-report ver. %s)\n\n", COPYRIGHT_INFO,
       					SEREPORT_VERSION_NUM);			
			seaudit_report_destroy(report_info);
			exit(0);
		case 'h':	
			/* display help */
			seaudit_report_info_usage(argv[0], FALSE);
			seaudit_report_destroy(report_info);
			exit(0);
		default:	
			/* display usage and handle error */
			seaudit_report_info_usage(argv[0], TRUE);
			goto err;
		}
	}
	
	/* Throw warning if a stylesheet was specified, but the --html option was not. */
	if (report_info->stylesheet_file != NULL && !report_info->html) {
		fprintf(stderr, "Warning: The --html option was not specified.\n");
		goto err;
	} 
		
	/* Add required filenames */
	for (i = (argc - 1); i >= optind; i--) {
		if (seaudit_report_add_logfile_to_list(report_info, argv[i])) {
			fprintf(stderr, "Unable to add specified logfile file to data structure.\n");
			goto err;
		}
	}
	
	/* Ensure that logfiles were not specified in addition to the standard-in option */
	if ((report_info->num_logfiles > 0) && report_info->stdin) {
		fprintf(stderr,
			"Warning: Command line filename(s) will be ignored. Reading from stdin.\n");
	}
	
	if ((!report_info->stdin) && (report_info->num_logfiles == 0 || (argc == optind))) {
		/* display usage and handle error */
		seaudit_report_info_usage(argv[0], TRUE);
		goto err;
	}
	
	return;

err:
	seaudit_report_destroy(report_info);
	exit(-1);
}

int main (int argc, char **argv)
{	
	seaudit_report_t *report_info;
	
	report_info = seaudit_report_create();
	if (!report_info) {
		return -1;
	}
	seaudit_report_parse_command_line_args(argc, argv, report_info);
	
	/* Load all audit messages into memory */
	if (seaudit_report_load_audit_messages_from_log_file(report_info) != 0)
		return -1;	
		
	if (seaudit_report_generate_report(report_info) != 0) {
		seaudit_report_destroy(report_info);
		return -1;
	}
	seaudit_report_destroy(report_info);
	
	return 0;
}
