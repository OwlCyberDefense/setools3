/* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: 8-17-2004
 */

/* seaudit-report: command line tool for processing SELinux audit logs and
 * generating a concide report containing standard information as well as 
 * customized information using seaudit views. Reports are rendered in either
 * HTML or plain text. Future support will provide rendering into XML. The 
 * HTML report can be formatted by providing an alternate stylesheet file
 * or by configuring the default stylesheet. This tool also provides the 
 * option for including malformed strings within the report, which a security 
 * expert would want to see.
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>

/* libapol and libseaudit headers */
#include <parse.h>
#include <multifilter.h>
#include <auditlog_view.h>
#include <util.h>

#include <libxml/xmlreader.h>

/* SEREPORT_VERSION_NUM should be defined in the make environment */
#ifndef SEREPORT_VERSION_NUM
#define SEREPORT_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004 Tresys Technology, LLC"
#define CONFIG_FILE "seaudit-report.conf"
#define STYLESHEET_FILE "seaudit-report.css"
#define DATE_STR_SIZE 256

/* seaudit_report valid node names */
const char *seaudit_report_node_names[] = { "seaudit-report", 
					    "standard-section", 
					    "custom-section", 
					    "view", 
					    NULL };
					    
const char *seaudit_standard_section_names[] = { "PolicyLoads", 
						 "EnforcementToggles", 
						 "PolicyBooleans", 
						 "Statistics", 
						 "AllowListing", 
						 "DenyListing",
						 NULL };

typedef struct seaudit_report_info {
	unsigned char stdin;
	unsigned char html;
	unsigned char malformed;
	char *configPath;
	char *outFile;
	char *stylesheet_file;
	char **logfiles;
	int num_logfiles;
	audit_log_t *log;
} seaudit_report_info_t;

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

/* Prototypes for seaudit_report_info struct */
void seaudit_report_info_init(seaudit_report_info_t *report_info)
{
	assert(report_info != NULL);
	memset(report_info, 0, sizeof(seaudit_report_info_t));
}

void seaudit_report_info_free(seaudit_report_info_t *report_info) {
	int i;
	
	assert(report_info != NULL);
	if (report_info->configPath) 
		free(report_info->configPath);
	if (report_info->outFile) 
		free(report_info->outFile);
	if (report_info->stylesheet_file) 
		free(report_info->stylesheet_file);	
	/* Free log file path strings */
	if (report_info->logfiles) {
		for (i = 0; i < report_info->num_logfiles; i++) {
			if (report_info->logfiles[i]) {
				free(report_info->logfiles[i]);
			}
		}
		free(report_info->logfiles);
	}
	if (report_info->log) 
		audit_log_destroy(report_info->log);	
}

/* Helper functions */
static bool_t seaudit_report_is_valid_node_name(const char *name)
{
	int i;

	for (i = 0; seaudit_report_node_names[i] != NULL; i++)
		if (strcmp(seaudit_report_node_names[i], name) == 0)
			return TRUE;
	return FALSE;
}

static bool_t seaudit_report_is_valid_section_name(const char *name)
{
	int i;

	for (i = 0; seaudit_standard_section_names[i] != NULL; i++)
		if (strcmp(seaudit_standard_section_names[i], name) == 0)
			return TRUE;
	return FALSE;
}

static int seaudit_report_add_file_path(char *str, char **copy_ptr) {
	int len;

	assert(str != NULL && copy_ptr != NULL);	
	len = strlen(str);
	if (len > PATH_MAX) {
		fprintf(stderr, "Invalid string length for file.\n");
		return -1;
	}
	/* Do not need to check if file exists. Will be created if it doesn't exist. */
	*copy_ptr = malloc((len * sizeof(char)) + 1);
	if (*copy_ptr == NULL) {
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}
	strncpy(*copy_ptr, str, len + 1);
	
	return 0;	
}

int seaudit_report_add_logfile_to_list(seaudit_report_info_t *report_info, const char *file)
{
	assert(report_info != NULL);
	
	report_info->logfiles =
	    realloc(report_info->logfiles,
		    sizeof (char *) * (report_info->num_logfiles + 1));
	if (!report_info->logfiles)
		goto err;
	if ((report_info->logfiles[report_info->num_logfiles] = strdup(file)) == NULL)
		goto err;
	report_info->num_logfiles++;
	return 0;

	err:
	fprintf(stderr, "Error: Out of memory\n");
	return -1;

}

static int seaudit_report_search_dflt_config_file(seaudit_report_info_t *report_info) {
	int len;
	
	assert(report_info != NULL);
	if (report_info->configPath == NULL) {
		/* a. Look in current dir */
		len = strlen(CONFIG_FILE) + 3;
		report_info->configPath = (char *)malloc(len * sizeof(char));
		if (report_info->configPath == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}	
		snprintf(report_info->configPath, len, "./%s", CONFIG_FILE);
		if (access(report_info->configPath, R_OK) == 0) {
			return 0;
		}
		free(report_info->configPath);
		
		/* b. Look in home directory */ 
	     	report_info->configPath = (char *)malloc(len * sizeof(char));
		if (report_info->configPath == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		snprintf(report_info->configPath, len, "~/%s", CONFIG_FILE);
		if (access(report_info->configPath, R_OK) == 0) {
			return 0;
		}
		free(report_info->configPath);
		
		/* c. Look in /etc directory */ 
		len = strlen("etc") + strlen(CONFIG_FILE) + 3;
	     	if ((report_info->configPath = (char *)malloc(len * sizeof(char))) == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		} 
		snprintf(report_info->configPath, len, "/etc/%s", CONFIG_FILE);
		if (access(report_info->configPath, R_OK) == 0) {
			return 0;
		}
		free(report_info->configPath);
		printf("Could not find default config file.\n");
		return -1;
	}

	return 0;
}

static int seaudit_report_search_dflt_stylesheet(seaudit_report_info_t *report_info) {
	int len;
	
	assert(report_info != NULL);
	if (report_info->stylesheet_file == NULL) {
		/* a. Look in current dir */
		len = strlen(STYLESHEET_FILE) + 3;
		report_info->stylesheet_file = (char *)malloc(len * sizeof(char));
		if (report_info->stylesheet_file == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}	
		snprintf(report_info->stylesheet_file, len, "./%s", STYLESHEET_FILE);
		if (access(report_info->stylesheet_file, R_OK) == 0) {
			return 0;
		}
		free(report_info->stylesheet_file);
		
		/* b. Look in home directory */ 
	     	report_info->stylesheet_file = (char *)malloc(len * sizeof(char));
		if (report_info->stylesheet_file == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		snprintf(report_info->stylesheet_file, len, "~/%s", STYLESHEET_FILE);
		if (access(report_info->stylesheet_file, R_OK) == 0) {
			return 0;
		}
		free(report_info->stylesheet_file);
		
		/* c. Look in /etc directory */ 
		len = strlen(APOL_INSTALL_DIR) + strlen("secmds") + strlen(STYLESHEET_FILE) + 3;
	     	if ((report_info->stylesheet_file = (char *)malloc(len * sizeof(char))) == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		} 
		snprintf(report_info->stylesheet_file, len, "%s/secmds/%s", APOL_INSTALL_DIR, STYLESHEET_FILE);
		if (access(report_info->stylesheet_file, R_OK) == 0) {
			return 0;
		}
		free(report_info->stylesheet_file);
		return -1;
	}

	return 0;
}

static int seaudit_report_load_audit_messages(seaudit_report_info_t *report_info) {
	int i, rt;
	FILE *tmp_file = NULL;
	
	report_info->log = audit_log_create();
	/* If specified STDIN, then parse STDIN, otherwise we will parse each logfile */
	/* Add a flag to parse_audit function in libseaudit to hold onto malformed strings. */
	if (report_info->stdin) {
		rt = parse_audit(stdin, report_info->log);
		if (rt == PARSE_RET_MEMORY_ERROR) {
			fprintf(stderr, "Memory error while parsing the log!\n");
				return -1;
		}
		else if (rt == PARSE_RET_NO_SELINUX_ERROR) {
			fprintf(stderr, "No SELinux messages found in log!\n");
				return -1;
		}
	} else {
		/* Load in all data into log structure */
		for (i = 0; i < report_info->num_logfiles; i++) {
			tmp_file = fopen(report_info->logfiles[i], "r");
			if (!tmp_file) {
				fprintf(stderr, "Error opening file %s\n%s\n", report_info->logfiles[i], strerror(errno));
				return -1;
			}
			
			rt = parse_audit(tmp_file, report_info->log);
			if (rt == PARSE_RET_MEMORY_ERROR) {
				fprintf(stderr, "Memory error while parsing the log!\n");
				fclose(tmp_file);
				return -1;
			} else if (rt == PARSE_RET_NO_SELINUX_ERROR) {
				fprintf(stderr, "No SELinux messages found in log!\n");
				fclose(tmp_file);
				return -1;
			}
			fclose(tmp_file);
		}
	}
	
	return 0;
}

static int seaudit_report_load_saved_view(seaudit_report_info_t report_info, 
					  xmlChar *view_filePath, 
					  audit_log_view_t **log_view) {
	seaudit_multifilter_t *multifilter = NULL;
	bool_t is_multi;
	int *deleted = NULL, num_deleted, num_kept, old_sz, new_sz;
	int rt; 
	
	assert(view_filePath != NULL && log_view != NULL && *log_view != NULL);
	num_deleted = num_kept = old_sz = new_sz = 0;
	
	rt = seaudit_multifilter_load_from_file(&multifilter, &is_multi, view_filePath);
	if (rt < 0) {
		fprintf(stderr, "Unable to import from %s\n%s", view_filePath, strerror(errno));
		goto err;
	} else if (rt > 0) {
		fprintf(stderr, "Unable to import from %s\ninvalid file.", view_filePath);
		goto err;
	}	
	if (!is_multi) {
		fprintf(stderr, "Error: The file %s does not contain all the information required for a view.\n", view_filePath);
		goto err;
	}
	audit_log_view_set_multifilter(*log_view, multifilter);
	audit_log_view_set_log(*log_view, report_info.log);
	
	old_sz = (*log_view)->num_fltr_msgs;
	audit_log_view_do_filter(*log_view, &deleted, &num_deleted);
	new_sz = (*log_view)->num_fltr_msgs;
	qsort(deleted, num_deleted, sizeof(int), &int_compare); 
	num_kept = old_sz - num_deleted;

	assert(num_kept >= 0);
	assert(num_kept <= new_sz);
	if (deleted){
		free(deleted);
	}
	seaudit_multifilter_destroy(multifilter);
				
	return 0;
err:
	if (multifilter) seaudit_multifilter_destroy(multifilter);
	return -1;
}

static int seaudit_report_print_view_results(seaudit_report_info_t report_info,
					     	 xmlChar *view_filePath,
					     	 audit_log_view_t *log_view,
					     	 FILE *outfile) {
	int i, j, indx;
	avc_msg_t *cur_msg;
	load_policy_msg_t *policy_msg;
	boolean_msg_t *boolean_msg;
	const char *cur_perm;
	const char *cur_bool;
	char date[DATE_STR_SIZE];
	
	assert(view_filePath != NULL && log_view != NULL && outfile != NULL);
	if (report_info.html) {
		fprintf(outfile, "View file: %s<br>\n", view_filePath);
		fprintf(outfile, "Number of messages: %d<br>\n<br>\n", log_view->num_fltr_msgs);
	} else {
		fprintf(outfile, "View file: %s\n", view_filePath);
		fprintf(outfile, "Number of messages: %d\n\n", log_view->num_fltr_msgs);
	}
		
	for (i = 0; i < log_view->num_fltr_msgs; i++) {
		indx = log_view->fltr_msgs[i];
		strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", log_view->my_log->msg_list[indx]->date_stamp);	
		fprintf(outfile, "%s ", date);
		fprintf(outfile, "%s ", audit_log_get_host(log_view->my_log, log_view->my_log->msg_list[indx]->host));
		
		if (log_view->my_log->msg_list[indx]->msg_type == BOOLEAN_MSG) {
	          	fprintf(outfile, "kernel: ");
			fprintf(outfile, "security: ");
	          	fprintf(outfile, "committed booleans: ");
	          	
			boolean_msg = log_view->my_log->msg_list[indx]->msg_data.boolean_msg;
			if (boolean_msg->num_bools > 0) {
				fprintf(outfile, "{ ");
				fprintf(outfile, "%s", audit_log_get_bool(log_view->my_log, boolean_msg->booleans[0]));
				fprintf(outfile, ":%d", boolean_msg->values[0]);
		
				for (j = 1; j < boolean_msg->num_bools; j++) {
				        cur_bool = audit_log_get_bool(log_view->my_log, boolean_msg->booleans[j]);
					fprintf(outfile, ", %s", cur_bool);
					fprintf(outfile, ":%d", boolean_msg->values[j]);
				}
				fprintf(outfile, "} ");
			}
		} else if (log_view->my_log->msg_list[indx]->msg_type == LOAD_POLICY_MSG) {
			policy_msg = log_view->my_log->msg_list[indx]->msg_data.load_policy_msg;
			fprintf(outfile, "kernel: security: %d users, %d roles, %d types, %d bools\n",
						policy_msg->users, policy_msg->roles, 
						policy_msg->types, policy_msg->bools);
			fprintf(outfile, "%s ", date);
			fprintf(outfile, "%s ", audit_log_get_host(log_view->my_log, log_view->my_log->msg_list[indx]->host));
			fprintf(outfile, "kernel: security: %d classes, %d rules",
						policy_msg->classes, policy_msg->rules);
		} else if (log_view->my_log->msg_list[indx]->msg_type == AVC_MSG) {
			cur_msg = log_view->my_log->msg_list[indx]->msg_data.avc_msg;
			
			fprintf(outfile, "kernel: ");
			fprintf(outfile, "audit(%lu.%03lu:%u): ", 
				cur_msg->tm_stmp_sec, 
				cur_msg->tm_stmp_nano, 
				cur_msg->serial);
			fprintf(outfile, "avc: ");
			if (cur_msg->msg == AVC_DENIED)
				fprintf(outfile, "denied ");
			else
				fprintf(outfile, "granted ");
			
			if (cur_msg->num_perms > 0) {
				fprintf(outfile, "{ ");
				for (j = 0; j < cur_msg->num_perms; j++) {
					cur_perm = audit_log_get_perm(log_view->my_log, cur_msg->perms[j]);
					fprintf(outfile, "%s ", cur_perm);
				}
				fprintf(outfile, "}");
			}
			fprintf(outfile, " for ");	
			fprintf(outfile, "pid=%d ", cur_msg->pid);
			fprintf(outfile, "exe=%s ", cur_msg->exe);
			
			if (cur_msg->path)
				fprintf(outfile, "path=%s ", cur_msg->path);
			if (cur_msg->dev)
				fprintf(outfile, "dev=%s ", cur_msg->dev);
			if (cur_msg->is_inode)
				fprintf(outfile, "ino=%lu ", cur_msg->inode);
			if (cur_msg->laddr)
				fprintf(outfile, "laddr=%s ", cur_msg->laddr);
			if (cur_msg->lport!=0)
				fprintf(outfile, "lport=%d ", cur_msg->lport);
			if (cur_msg->faddr)
				fprintf(outfile, "faddr=%s ", cur_msg->faddr);
			if (cur_msg->fport != 0)
				fprintf(outfile, "fport=%d ", cur_msg->fport);
			if (cur_msg->daddr)
				fprintf(outfile, "daddr=%s ", cur_msg->daddr);
			if (cur_msg->dest != 0)
				fprintf(outfile, "dest=%d ", cur_msg->dest);
			if (cur_msg->port != 0)
				fprintf(outfile, "port=%d ", cur_msg->port);
			if (cur_msg->saddr)
				fprintf(outfile, "saddr=%s ", cur_msg->saddr);
			if (cur_msg->source != 0)
				fprintf(outfile, "source=%d ", cur_msg->source);
			if (cur_msg->netif)
				fprintf(outfile, "netif=%s ", cur_msg->netif);
			if (cur_msg->is_key)
				fprintf(outfile, "key=%d ", cur_msg->key);
			if (cur_msg->is_capability)
				fprintf(outfile, "capability=%d ", cur_msg->capability);	
								
			fprintf(outfile, "scontext=%s:%s:%s ", 
				audit_log_get_user(log_view->my_log, cur_msg->src_user), 
				audit_log_get_role(log_view->my_log, cur_msg->src_role),
				audit_log_get_type(log_view->my_log, cur_msg->src_type));
			fprintf(outfile, "tcontext=%s:%s:%s ", 
				audit_log_get_user(log_view->my_log, cur_msg->tgt_user),
				audit_log_get_role(log_view->my_log, cur_msg->tgt_role),
				audit_log_get_type(log_view->my_log, cur_msg->tgt_type));
			fprintf(outfile, "tclass=%s ", audit_log_get_obj(log_view->my_log, cur_msg->obj_class));
		}
		if (report_info.html) 
			fprintf(outfile, "<br>\n<br>\n");
		else 
			fprintf(outfile, "\n\n");
	}
	
	return 0;
}

static int seaudit_report_import_html_stylesheet(seaudit_report_info_t report_info, FILE *outfile) {
	char line[LINE_MAX], *line_ptr = NULL;
	FILE *fp;
	
	assert(outfile != NULL);	
	if (report_info.stylesheet_file != NULL) {
		fp = fopen(report_info.stylesheet_file, "r");
		if (fp == NULL) {
			fprintf(stderr, "Cannot open stylesheet file %s", report_info.stylesheet_file);
			return -1;
		}
	
		while(fgets(line, LINE_MAX, fp) != NULL) {
			line_ptr = &line[0];
			if (trim_string(&line_ptr) != 0) {
				fclose(fp);
				return -1;
			}
			if (line_ptr[0] == '#' || str_is_only_white_space(line_ptr))  
				continue;
			fprintf(outfile, "%s\n", line_ptr);
		}
		fclose(fp);
	} 
	
	return 0;					      	  
}

static int seaudit_report_print_header(seaudit_report_info_t report_info, FILE *outfile) {
	time_t ltime;
	int rt;
	
	time(&ltime);
	if (report_info.html) {
		fprintf(outfile, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n");
		fprintf(outfile, "<html>\n<head>\n");
		rt = seaudit_report_import_html_stylesheet(report_info, outfile);
		if (rt != 0) {
			fclose(outfile);
			return -1;
		}
		fprintf(outfile, "<title>seaudit-report</title>\n</head>\n");
		fprintf(outfile, "<body>\n");
		rt = fprintf(outfile, "<bold># Report generated by seaudit-report on %s</bold><br>\n", ctime(&ltime));
	} else {
		fprintf(outfile, "# Begin\n\n");
		rt = fprintf(outfile, "# Report generated by seaudit-report on %s\n", ctime(&ltime));	
	}
	if (rt < 0)
		return -1;
	return 0;					      	  
}

static int seaudit_report_print_footer(seaudit_report_info_t report_info, FILE *outfile) {
	if (report_info.html) {
		fprintf(outfile, "</body>\n</html>\n");
	} else {
		fprintf(outfile, "# End\n");
	}
	return 0;					      	  
}

static int seaudit_report_print_print_policy_loads(seaudit_report_info_t report_info, FILE *outfile) {
	int indx;
	load_policy_msg_t *policy_msg;
	char date[DATE_STR_SIZE];
	
	assert(outfile != NULL);
	if (report_info.html) 
		fprintf(outfile, "Number of messages: %d<br>\n<br>\n", report_info.log->num_load_msgs);
	else
		fprintf(outfile, "Number of messages: %d\n\n", report_info.log->num_load_msgs);
		
	for (indx = 0; indx < report_info.log->num_msgs; indx++) {		
		if (report_info.log->msg_list[indx]->msg_type == LOAD_POLICY_MSG) {
			strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", report_info.log->msg_list[indx]->date_stamp);	
			fprintf(outfile, "%s ", date);
			fprintf(outfile, "%s ", audit_log_get_host(report_info.log, report_info.log->msg_list[indx]->host));
			
			policy_msg = report_info.log->msg_list[indx]->msg_data.load_policy_msg;						
			fprintf(outfile, "kernel: security: %d users, %d roles, %d types, %d bools\n",
						policy_msg->users, policy_msg->roles, 
						policy_msg->types, policy_msg->bools);
			fprintf(outfile, "%s ", date);
			fprintf(outfile, "%s ", audit_log_get_host(report_info.log, report_info.log->msg_list[indx]->host));
			fprintf(outfile, "kernel: security: %d classes, %d rules",
						policy_msg->classes, policy_msg->rules);
												
			if (report_info.html) 
				fprintf(outfile, "<br>\n");
			else
				fprintf(outfile, "\n");
		} 
	}
	
	return 0;					      	  	
}

static int seaudit_report_enforce_toggles_view_do_filter(seaudit_report_info_t report_info, 
						         audit_log_view_t **log_view) {
	seaudit_multifilter_t *multifilter = NULL;
	seaudit_filter_t *filter = NULL;
	int *deleted = NULL, num_deleted, num_kept, old_sz, new_sz;
	char *tgt_type = "security_t";
	char *obj_class = "security"; 
	
	assert(log_view != NULL && *log_view != NULL);
	num_deleted = num_kept = old_sz = new_sz = 0;
	multifilter = seaudit_multifilter_create();
	if (multifilter == NULL) {
		return -1;
	}
	audit_log_view_set_log(*log_view, report_info.log);
	
	seaudit_multifilter_set_match(multifilter, SEAUDIT_FILTER_MATCH_ALL);
	seaudit_multifilter_set_show_matches(multifilter, TRUE);	
	
	filter = seaudit_filter_create();
	if (filter == NULL) {
		seaudit_multifilter_destroy(multifilter);
		return -1;
	}		
	filter->tgt_type_criteria = tgt_type_criteria_create(&tgt_type, 1);
	filter->class_criteria = class_criteria_create(&obj_class, 1);
	
	seaudit_multifilter_add_filter(multifilter, filter);
	audit_log_view_set_multifilter(*log_view, multifilter);
	
	old_sz = (*log_view)->num_fltr_msgs;
	audit_log_view_do_filter(*log_view, &deleted, &num_deleted);
	new_sz = (*log_view)->num_fltr_msgs;
	qsort(deleted, num_deleted, sizeof(int), &int_compare); 
	num_kept = old_sz - num_deleted;

	assert(num_kept >= 0);
	assert(num_kept <= new_sz);
	if (deleted){
		free(deleted);
	}
	seaudit_multifilter_destroy(multifilter);
	
	return 0;
}

static int seaudit_report_print_enforce_toggles(seaudit_report_info_t report_info, FILE *outfile) {
	audit_log_view_t *log_view = NULL;
	int rt, indx, i, j, actual_num = 0; 
	avc_msg_t *cur_msg = NULL;
	char date[DATE_STR_SIZE];
	const char *cur_perm = NULL;
	bool_t setenforce_perm = FALSE;
	char *perm = "setenforce";
	
	assert(outfile != NULL);
	/* Create a log view */
	log_view = audit_log_view_create();
	if (log_view == NULL) {
		return -1;
	}
	rt = seaudit_report_enforce_toggles_view_do_filter(report_info, &log_view);
	if (rt != 0) {
		audit_log_view_destroy(log_view);
		return -1;
	}
	
	for (i = 0; i < log_view->num_fltr_msgs; i++) {		
		indx = log_view->fltr_msgs[i];
		if (log_view->my_log->msg_list[indx]->msg_type == AVC_MSG) {
			cur_msg = log_view->my_log->msg_list[indx]->msg_data.avc_msg;
			if (cur_msg->msg == AVC_DENIED)
				continue;
				
			if (cur_msg->num_perms > 0) {
				for (j = 0; j < cur_msg->num_perms; j++) {
					cur_perm = audit_log_get_perm(log_view->my_log, cur_msg->perms[j]);
					if (strncasecmp(cur_perm, perm, strlen(perm)) == 0) {
						actual_num++;
					}
				}
			}
		}
	}
	
	/* Since we cannot filter by setenforce permission within the view, we do so manually 
	 * within the following for loop. */	
	if (report_info.html) 
		fprintf(outfile, "Number of messages: %d<br>\n<br>\n", actual_num);
	else
		fprintf(outfile, "Number of messages: %d\n\n", actual_num);
		
	for (i = 0; i < log_view->num_fltr_msgs; i++) {		
		indx = log_view->fltr_msgs[i];
		if (log_view->my_log->msg_list[indx]->msg_type == AVC_MSG) {
			cur_msg = log_view->my_log->msg_list[indx]->msg_data.avc_msg;
			if (cur_msg->msg == AVC_DENIED)
				continue;
				
			setenforce_perm = FALSE;
			if (cur_msg->num_perms > 0) {
				for (j = 0; j < cur_msg->num_perms; j++) {
					cur_perm = audit_log_get_perm(log_view->my_log, cur_msg->perms[j]);
					if (strncasecmp(cur_perm, perm, strlen(perm)) == 0) {
						setenforce_perm = TRUE;
						break;
					}
				}
				if (!setenforce_perm)
					continue;
			}
			
			strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", log_view->my_log->msg_list[indx]->date_stamp);	
			fprintf(outfile, "%s ", date);
			fprintf(outfile, "%s ", audit_log_get_host(log_view->my_log, log_view->my_log->msg_list[indx]->host));
			fprintf(outfile, "kernel: ");
			fprintf(outfile, "audit(%lu.%03lu:%u): ", 
				cur_msg->tm_stmp_sec, 
				cur_msg->tm_stmp_nano, 
				cur_msg->serial);
			fprintf(outfile, "avc: ");			
			fprintf(outfile, "granted ");
			
			if (cur_msg->num_perms > 0) {
				fprintf(outfile, "{ ");
				for (j = 0; j < cur_msg->num_perms; j++) {
					cur_perm = audit_log_get_perm(log_view->my_log, cur_msg->perms[j]);
					fprintf(outfile, "%s ", cur_perm);
				}
				fprintf(outfile, "}");
			}
			fprintf(outfile, " for ");	
			fprintf(outfile, "pid=%d ", cur_msg->pid);
			fprintf(outfile, "exe=%s ", cur_msg->exe);
			
			if (cur_msg->path)
				fprintf(outfile, "path=%s ", cur_msg->path);
			if (cur_msg->dev)
				fprintf(outfile, "dev=%s ", cur_msg->dev);
			if (cur_msg->is_inode)
				fprintf(outfile, "ino=%lu ", cur_msg->inode);
			if (cur_msg->laddr)
				fprintf(outfile, "laddr=%s ", cur_msg->laddr);
			if (cur_msg->lport!=0)
				fprintf(outfile, "lport=%d ", cur_msg->lport);
			if (cur_msg->faddr)
				fprintf(outfile, "faddr=%s ", cur_msg->faddr);
			if (cur_msg->fport != 0)
				fprintf(outfile, "fport=%d ", cur_msg->fport);
			if (cur_msg->daddr)
				fprintf(outfile, "daddr=%s ", cur_msg->daddr);
			if (cur_msg->dest != 0)
				fprintf(outfile, "dest=%d ", cur_msg->dest);
			if (cur_msg->port != 0)
				fprintf(outfile, "port=%d ", cur_msg->port);
			if (cur_msg->saddr)
				fprintf(outfile, "saddr=%s ", cur_msg->saddr);
			if (cur_msg->source != 0)
				fprintf(outfile, "source=%d ", cur_msg->source);
			if (cur_msg->netif)
				fprintf(outfile, "netif=%s ", cur_msg->netif);
			if (cur_msg->is_key)
				fprintf(outfile, "key=%d ", cur_msg->key);
			if (cur_msg->is_capability)
				fprintf(outfile, "capability=%d ", cur_msg->capability);	
								
			fprintf(outfile, "scontext=%s:%s:%s ", 
				audit_log_get_user(log_view->my_log, cur_msg->src_user), 
				audit_log_get_role(log_view->my_log, cur_msg->src_role),
				audit_log_get_type(log_view->my_log, cur_msg->src_type));
			fprintf(outfile, "tcontext=%s:%s:%s ", 
				audit_log_get_user(log_view->my_log, cur_msg->tgt_user),
				audit_log_get_role(log_view->my_log, cur_msg->tgt_role),
				audit_log_get_type(log_view->my_log, cur_msg->tgt_type));
			fprintf(outfile, "tclass=%s ", audit_log_get_obj(log_view->my_log, cur_msg->obj_class));
		}
		if (report_info.html) 
			fprintf(outfile, "<br>\n");
		else
			fprintf(outfile, "\n");
	}
	audit_log_view_destroy(log_view);			
	return 0;					      	  	
}

static int seaudit_report_print_policy_booleans(seaudit_report_info_t report_info, FILE *outfile) {
	int j, indx;
	boolean_msg_t *boolean_msg;
	const char *cur_bool;
	char date[DATE_STR_SIZE];
	
	assert(outfile != NULL);
	if (report_info.html)
		fprintf(outfile, "Number of messages: %d<br>\n<br>\n", report_info.log->num_bool_msgs);
	else 
		fprintf(outfile, "Number of messages: %d\n\n", report_info.log->num_bool_msgs);
		
	for (indx = 0; indx < report_info.log->num_msgs; indx++) {
		if (report_info.log->msg_list[indx]->msg_type == BOOLEAN_MSG) {
			strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", report_info.log->msg_list[indx]->date_stamp);	
			fprintf(outfile, "%s ", date);
			fprintf(outfile, "%s ", audit_log_get_host(report_info.log, report_info.log->msg_list[indx]->host));
			
			fprintf(outfile, "kernel: ");
			fprintf(outfile, "security: ");
	          	fprintf(outfile, "committed booleans: ");
			boolean_msg = report_info.log->msg_list[indx]->msg_data.boolean_msg;
			if (boolean_msg->num_bools > 0) {
				fprintf(outfile, "{ ");
				fprintf(outfile, "%s", audit_log_get_bool(report_info.log, boolean_msg->booleans[0]));
				fprintf(outfile, ":%d", boolean_msg->values[0]);
		
				for (j = 1; j < boolean_msg->num_bools; j++) {
				        cur_bool = audit_log_get_bool(report_info.log, boolean_msg->booleans[j]);
					fprintf(outfile, ", %s", cur_bool);
					fprintf(outfile, ":%d", boolean_msg->values[j]);
				}
				fprintf(outfile, " }");
			}
			if (report_info.html)
				fprintf(outfile, "<br>\n");
			else 
				fprintf(outfile, "\n");
		}
	}
	
	return 0;					      					      	  	
}

static int seaudit_report_print_allow_listing(seaudit_report_info_t report_info, FILE *outfile) {
	
	int j, indx;
	avc_msg_t *cur_msg;
	const char *cur_perm;
	char date[DATE_STR_SIZE];
	
	assert(outfile != NULL);
	if (report_info.html) 
		fprintf(outfile, "Number of messages: %d<br>\n<br>\n", report_info.log->num_allow_msgs);
	else
		fprintf(outfile, "Number of messages: %d\n\n", report_info.log->num_allow_msgs);

			
	for (indx = 0; indx < report_info.log->num_msgs; indx++) {		
		if (report_info.log->msg_list[indx]->msg_type == AVC_MSG) {
			cur_msg = report_info.log->msg_list[indx]->msg_data.avc_msg;
			if (cur_msg->msg == AVC_DENIED) 
				continue;
			
			strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", report_info.log->msg_list[indx]->date_stamp);	
			fprintf(outfile, "%s ", date);
			fprintf(outfile, "%s ", audit_log_get_host(report_info.log, report_info.log->msg_list[indx]->host));
			fprintf(outfile, "kernel: ");
			fprintf(outfile, "audit(%lu.%03lu:%u): ", 
				cur_msg->tm_stmp_sec, 
				cur_msg->tm_stmp_nano, 
				cur_msg->serial);
			fprintf(outfile, "avc: ");
			fprintf(outfile, "granted ");
			
			if (cur_msg->num_perms > 0) {
				fprintf(outfile, "{ ");
				for (j = 0; j < cur_msg->num_perms; j++) {
					cur_perm = audit_log_get_perm(report_info.log, cur_msg->perms[j]);
					fprintf(outfile, "%s ", cur_perm);
				}
				fprintf(outfile, "}");
			}
			fprintf(outfile, " for ");	
			fprintf(outfile, "pid=%d ", cur_msg->pid);
			fprintf(outfile, "exe=%s ", cur_msg->exe);
			
			if (cur_msg->path)
				fprintf(outfile, "path=%s ", cur_msg->path);
			if (cur_msg->dev)
				fprintf(outfile, "dev=%s ", cur_msg->dev);
			if (cur_msg->is_inode)
				fprintf(outfile, "ino=%lu ", cur_msg->inode);
			if (cur_msg->laddr)
				fprintf(outfile, "laddr=%s ", cur_msg->laddr);
			if (cur_msg->lport != 0)
				fprintf(outfile, "lport=%d ", cur_msg->lport);
			if (cur_msg->faddr)
				fprintf(outfile, "faddr=%s ", cur_msg->faddr);
			if (cur_msg->fport != 0)
				fprintf(outfile, "fport=%d ", cur_msg->fport);
			if (cur_msg->daddr)
				fprintf(outfile, "daddr=%s ", cur_msg->daddr);
			if (cur_msg->dest != 0)
				fprintf(outfile, "dest=%d ", cur_msg->dest);
			if (cur_msg->port != 0)
				fprintf(outfile, "port=%d ", cur_msg->port);
			if (cur_msg->saddr)
				fprintf(outfile, "saddr=%s ", cur_msg->saddr);
			if (cur_msg->source != 0)
				fprintf(outfile, "source=%d ", cur_msg->source);
			if (cur_msg->netif)
				fprintf(outfile, "netif=%s ", cur_msg->netif);
			if (cur_msg->is_key)
				fprintf(outfile, "key=%d ", cur_msg->key);
			if (cur_msg->is_capability)
				fprintf(outfile, "capability=%d ", cur_msg->capability);	
								
			fprintf(outfile, "scontext=%s:%s:%s ", 
				audit_log_get_user(report_info.log, cur_msg->src_user), 
				audit_log_get_role(report_info.log, cur_msg->src_role),
				audit_log_get_type(report_info.log, cur_msg->src_type));
			fprintf(outfile, "tcontext=%s:%s:%s ", 
				audit_log_get_user(report_info.log, cur_msg->tgt_user),
				audit_log_get_role(report_info.log, cur_msg->tgt_role),
				audit_log_get_type(report_info.log, cur_msg->tgt_type));
			fprintf(outfile, "tclass=%s ", audit_log_get_obj(report_info.log, cur_msg->obj_class));
			if (report_info.html) 
				fprintf(outfile, "<br>\n");
			else
				fprintf(outfile, "\n");
		}
	}
	
	return 0;					      	  	
}

static int seaudit_report_print_deny_listing(seaudit_report_info_t report_info, FILE *outfile) {
	int j, indx;
	avc_msg_t *cur_msg;
	const char *cur_perm;
	char date[DATE_STR_SIZE];
	
	assert(outfile != NULL);
	if (report_info.html) 
		fprintf(outfile, "Number of messages: %d<br>\n<br>\n", report_info.log->num_deny_msgs);
	else
		fprintf(outfile, "Number of messages: %d\n\n", report_info.log->num_deny_msgs);
		
	for (indx = 0; indx < report_info.log->num_msgs; indx++) {		
		if (report_info.log->msg_list[indx]->msg_type == AVC_MSG) {
			cur_msg = report_info.log->msg_list[indx]->msg_data.avc_msg;
			if (cur_msg->msg != AVC_DENIED) 
				continue;
			
			strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", report_info.log->msg_list[indx]->date_stamp);	
			fprintf(outfile, "%s ", date);
			fprintf(outfile, "%s ", audit_log_get_host(report_info.log, report_info.log->msg_list[indx]->host));
			fprintf(outfile, "kernel: ");
			fprintf(outfile, "audit(%lu.%03lu:%u): ", 
				cur_msg->tm_stmp_sec, 
				cur_msg->tm_stmp_nano, 
				cur_msg->serial);
			fprintf(outfile, "avc: ");
			fprintf(outfile, "denied ");
			
			if (cur_msg->num_perms > 0) {
				fprintf(outfile, "{ ");
				for (j = 0; j < cur_msg->num_perms; j++) {
					cur_perm = audit_log_get_perm(report_info.log, cur_msg->perms[j]);
					fprintf(outfile, "%s ", cur_perm);
				}
				fprintf(outfile, "}");
			}
			fprintf(outfile, " for ");	
			if (cur_msg->pid)
				fprintf(outfile, "pid=%d ", cur_msg->pid);
			if (cur_msg->exe)
				fprintf(outfile, "exe=%s ", cur_msg->exe);
			if (cur_msg->path)
				fprintf(outfile, "path=%s ", cur_msg->path);
			if (cur_msg->dev)
				fprintf(outfile, "dev=%s ", cur_msg->dev);
			if (cur_msg->is_inode)
				fprintf(outfile, "ino=%lu ", cur_msg->inode);
			if (cur_msg->laddr)
				fprintf(outfile, "laddr=%s ", cur_msg->laddr);
			if (cur_msg->lport != 0)
				fprintf(outfile, "lport=%d ", cur_msg->lport);
			if (cur_msg->faddr)
				fprintf(outfile, "faddr=%s ", cur_msg->faddr);
			if (cur_msg->fport != 0)
				fprintf(outfile, "fport=%d ", cur_msg->fport);
			if (cur_msg->daddr)
				fprintf(outfile, "daddr=%s ", cur_msg->daddr);
			if (cur_msg->dest != 0)
				fprintf(outfile, "dest=%d ", cur_msg->dest);
			if (cur_msg->port != 0)
				fprintf(outfile, "port=%d ", cur_msg->port);
			if (cur_msg->saddr)
				fprintf(outfile, "saddr=%s ", cur_msg->saddr);
			if (cur_msg->source != 0)
				fprintf(outfile, "source=%d ", cur_msg->source);
			if (cur_msg->netif)
				fprintf(outfile, "netif=%s ", cur_msg->netif);
			if (cur_msg->is_key)
				fprintf(outfile, "key=%d ", cur_msg->key);
			if (cur_msg->is_capability)
				fprintf(outfile, "capability=%d ", cur_msg->capability);	
			
			if (cur_msg->src_user && cur_msg->src_role && cur_msg->src_type) {							
				fprintf(outfile, "scontext=%s:%s:%s ", 
					audit_log_get_user(report_info.log, cur_msg->src_user), 
					audit_log_get_role(report_info.log, cur_msg->src_role),
					audit_log_get_type(report_info.log, cur_msg->src_type));
			}
			if (cur_msg->tgt_user && cur_msg->tgt_role && cur_msg->tgt_type) {
				fprintf(outfile, "tcontext=%s:%s:%s ", 
					audit_log_get_user(report_info.log, cur_msg->tgt_user),
					audit_log_get_role(report_info.log, cur_msg->tgt_role),
					audit_log_get_type(report_info.log, cur_msg->tgt_type));
			}
			if (cur_msg->obj_class) 
				fprintf(outfile, "tclass=%s ", audit_log_get_obj(report_info.log, cur_msg->obj_class));
			if (report_info.html) 
				fprintf(outfile, "<br>\n");
			else
				fprintf(outfile, "\n");
		}
	}
	
	return 0;									      	  	
}

static int seaudit_report_print_stats(seaudit_report_info_t report_info, FILE *outfile) {
	assert(outfile != NULL);
	if (report_info.html) {
		fprintf(outfile, "Number of total messages: %d<br>\n", report_info.log->num_msgs);
		fprintf(outfile, "Number of policy load messages: %d<br>\n", report_info.log->num_load_msgs);
		fprintf(outfile, "Number of policy boolean messages: %d<br>\n", report_info.log->num_bool_msgs);
		fprintf(outfile, "Number of allow messages: %d<br>\n", report_info.log->num_allow_msgs);
		fprintf(outfile, "Number of denied messages: %d<br>\n", report_info.log->num_deny_msgs);
	} else {
		fprintf(outfile, "Number of total messages: %d\n", report_info.log->num_msgs);
		fprintf(outfile, "Number of policy load messages: %d\n", report_info.log->num_load_msgs);
		fprintf(outfile, "Number of policy boolean messages: %d\n", report_info.log->num_bool_msgs);
		fprintf(outfile, "Number of allow messages: %d\n", report_info.log->num_allow_msgs);
		fprintf(outfile, "Number of denied messages: %d\n", report_info.log->num_deny_msgs);
	}
	return 0;					      	  	
}

static int seaudit_report_print_standard_section(seaudit_report_info_t report_info, xmlChar *id, 
							  xmlChar *title, FILE *outfile) { 
	int sz, len, i, rt = 0;
	
	assert(id != NULL && outfile != NULL);
	if (!seaudit_report_is_valid_section_name(id)) {
		fprintf(stderr, "Invalid standard section ID.\n");
		return -1;
	}
	sz = strlen(id);
	if (title != NULL) {
		if (report_info.html) {
			fprintf(outfile, "<h2><u>%s</h2></u>\n", title);
		} else {		
			fprintf(outfile, "%s\n", title);
			len = strlen(title);
			for (i = 0; i < len; i++) {
				fprintf(outfile, "-");	
			}
			fprintf(outfile, "\n");
		}	
	}
	if (strncasecmp(id, "PolicyLoads", sz) == 0) {
		rt = seaudit_report_print_print_policy_loads(report_info, outfile);
	} else if (strncasecmp(id, "EnforcementToggles", sz) == 0) {
		rt = seaudit_report_print_enforce_toggles(report_info, outfile);
	} else if (strncasecmp(id, "PolicyBooleans", sz) == 0) {
		rt = seaudit_report_print_policy_booleans(report_info, outfile);
	} else if (strncasecmp(id, "AllowListing", sz) == 0) {
		rt = seaudit_report_print_allow_listing(report_info, outfile);
	} else if (strncasecmp(id, "DenyListing", sz) == 0) {
		rt = seaudit_report_print_deny_listing(report_info, outfile); 
	} else if (strncasecmp(id, "Statistics", sz) == 0) {
		rt = seaudit_report_print_stats(report_info, outfile);
	}
	if (rt != 0) 
		return -1;
		
	if (report_info.html) 
		fprintf(outfile, "<br>\n");
	else
		fprintf(outfile, "\n");
	
	return 0;
}

static int seaudit_report_print_custom_section_info(seaudit_report_info_t report_info,
							xmlTextReaderPtr reader,  
						        xmlChar *title, 
						        FILE *outfile) {
	int rt, len, i;
	xmlChar *view_filePath = NULL, *name = NULL;
	bool_t end_of_element = FALSE;
	audit_log_view_t *log_view = NULL;
	
	if (title != NULL) {
		if (report_info.html) {
			fprintf(outfile, "<h2><u>%s</h2></u>\n", title);
		} else {		
			fprintf(outfile, "%s\n", title);
			len = strlen(title);
			for (i = 0; i < len; i++) {
				fprintf(outfile, "-");	
			}
			fprintf(outfile, "\n");	
		}
	}
	/* Create a log view */
	log_view = audit_log_view_create();
	
	/* Moves the position of the current instance to the next node in the stream, which should be a view node */
	rt = xmlTextReaderRead(reader);
	while (rt == 1) {
		/* Read inner child view node(s) */
		name = xmlTextReaderName(reader);
		if (name == NULL) {
			fprintf(stderr, "Unavailable node name within \n");
			goto err;
		}
		/* We have reached the end-of-element for the custom-section node (indicated by 15) */
		if (strcmp(name, "custom-section") == 0 && xmlTextReaderNodeType(reader) == 15) {
			xmlFree(name);
			end_of_element = TRUE;
			break; 
		}		
		if (strcmp(name, "view") == 0 && xmlTextReaderNodeType(reader) == 1 && 
		    xmlTextReaderHasAttributes(reader)) {
			view_filePath = xmlTextReaderGetAttribute(reader, "file");
			if (view_filePath == NULL) {
				fprintf(stderr, "Error getting file attribute for view node.\n");
				goto err;
			}
			rt = seaudit_report_load_saved_view(report_info, view_filePath, &log_view);
			if (rt != 0) {
				goto err;
			}
			rt = seaudit_report_print_view_results(report_info, view_filePath, log_view, outfile);
			if (rt != 0) {
				goto err;
			}
			
			audit_log_view_destroy(log_view);
			xmlFree(view_filePath);
		}
		xmlFree(name);
		rt = xmlTextReaderRead(reader);
	}
	if (!end_of_element && rt != 0) {
		fprintf(stderr, "%s : failed to parse config file (rt:%d)\n", report_info.configPath, rt);
	}
		
	if (!end_of_element) {
		fprintf(stderr, "Encountered end of file before finding end of element for custom-section node.\n");
		goto err;	
	}
	if (report_info.html) 
		fprintf(outfile, "<br>\n");
	else 
		fprintf(outfile, "\n");
	
	return 0;
err:
	if (log_view) audit_log_view_destroy(log_view);
	if (view_filePath) xmlFree(view_filePath);
	if (name) xmlFree(name);
	return -1;
}

static int seaudit_report_parse_seaudit_report_node(seaudit_report_info_t report_info, 
						    xmlTextReaderPtr reader,
						    xmlChar **id_value,
						    xmlChar **title_value) {
	int rt;
	xmlChar *name = NULL;

	assert(id_value != NULL && title_value != NULL);
	if (xmlTextReaderNodeType(reader) == 1 && xmlTextReaderAttributeCount(reader) > 0) {
		/* Parse attributes */
		rt = xmlTextReaderMoveToNextAttribute(reader);
	        while (rt) {
	        	name = xmlTextReaderName(reader);
			if (name == NULL) {
				fprintf(stderr, "Attribute name unavailable\n");
				return -1;
			}
			if (strcmp(name, "title") == 0) {
				*title_value = xmlTextReaderValue(reader);	
			}
			
			xmlFree(name);
			rt = xmlTextReaderMoveToNextAttribute(reader);
		}
		if (rt < 0) {
			fprintf(stderr, "Error parsing attribute for seaudit-report node.\n");
		}
	}
	return 0;
}

static int seaudit_report_parse_standard_section_attributes(seaudit_report_info_t report_info, 
						       	    xmlTextReaderPtr reader,
						       	    xmlChar **id_value,
						       	    xmlChar **title_value) {
	int rt;
	xmlChar *name = NULL;

	assert(id_value != NULL && title_value != NULL);
	if (xmlTextReaderNodeType(reader) == 1 && xmlTextReaderAttributeCount(reader) > 0) {
		/* Parse attributes */
		rt = xmlTextReaderMoveToNextAttribute(reader);
	        while (rt) {
	        	name = xmlTextReaderName(reader);
			if (name == NULL) {
				fprintf(stderr, "Attribute name unavailable\n");
				return -1;
			}
			if (strcmp(name, "id") == 0) {
				*id_value = xmlTextReaderValue(reader);
			} else if (strcmp(name, "title") == 0) {
				*title_value = xmlTextReaderValue(reader);	
			}
			
			xmlFree(name);
			rt = xmlTextReaderMoveToNextAttribute(reader);
		}
		if (rt < 0) {
			fprintf(stderr, "Error parsing attribute for standard-section node.\n");
		}
	}
	return 0;
}

static int seaudit_report_parse_custom_section_attributes(seaudit_report_info_t report_info, 
						   	  xmlTextReaderPtr reader,
						   	  xmlChar **title_value) {
	int rt;
	xmlChar *name = NULL;

	assert(title_value != NULL);
	if (xmlTextReaderNodeType(reader) == 1 && xmlTextReaderAttributeCount(reader) > 0) {
		/* Parse attributes */
		rt = xmlTextReaderMoveToNextAttribute(reader);
	        while (rt) {
	        	name = xmlTextReaderName(reader);
			if (name == NULL) {
				fprintf(stderr, "Attribute name unavailable\n");
				return -1;
			}
			if (strcmp(name, "title") == 0) {
				*title_value = xmlTextReaderValue(reader);	
			}
			
			xmlFree(name);
			rt = xmlTextReaderMoveToNextAttribute(reader);
		}
		if (rt < 0) {
			fprintf(stderr, "Error parsing attribute for standard-section node.\n");
		}
	}
	return 0;
}

/* Processes each node in the tree */
static int seaudit_report_process_xmlNode(seaudit_report_info_t report_info, xmlTextReaderPtr reader, FILE *outfile) {
	xmlChar *name = NULL;
	xmlChar *id_attr = NULL, *title_attr = NULL;
	int rt;
	
	name = xmlTextReaderName(reader);
	if (name == NULL) {
		fprintf(stderr, "Unavailable node name\n");
		return -1;
	}

	if (seaudit_report_is_valid_node_name(name)) {
		if (strcmp(name, "seaudit-report") == 0 && xmlTextReaderNodeType(reader) == 1) {
			rt = seaudit_report_parse_seaudit_report_node(report_info, reader, 
								      &id_attr, &title_attr);
			if (rt != 0)
				goto err;
			if (report_info.html) {
				fprintf(outfile, "<h1>Title: %s</h1>\n", title_attr);
			} else {
				fprintf(outfile, "Title: %s\n", title_attr);
			}
		} else if (strcmp(name, "standard-section") == 0 && xmlTextReaderNodeType(reader) == 1) {
			rt = seaudit_report_parse_standard_section_attributes(report_info, reader, 
								              &id_attr, &title_attr);
			if (rt != 0)
				goto err;
			if (id_attr == NULL) {
				fprintf(stderr, "Missing required id attribute for standard section node.\n");
				goto err;
			}
			/* NOTE: If a title wasn't provided, we still continue. */
			rt = seaudit_report_print_standard_section(report_info, 
										    id_attr, 
										    title_attr, 
										    outfile);
			if (rt != 0)
				goto err;
		} else if (strcmp(name, "custom-section") == 0 && xmlTextReaderNodeType(reader) == 1) {
			rt = seaudit_report_parse_custom_section_attributes(report_info, reader, &title_attr);
			if (rt != 0)
				goto err;
			/* NOTE: If a title wasn't provided, we still continue. */
			rt = seaudit_report_print_custom_section_info(report_info, 
										  reader, 
									     	  title_attr, 
									     	  outfile);
			if (rt != 0)
				goto err;

		}
	}	
	xmlFree(name);
	xmlFree(id_attr);
	xmlFree(title_attr);
	
	return 0;
err:
	if (name) xmlFree(name);
	if (id_attr) xmlFree(id_attr);
	if (title_attr) xmlFree(title_attr);
	return -1;
}

static void seaudit_report_print_malformed_msgs(seaudit_report_info_t report_info, FILE *outfile) {
	int i, len;
	
	assert(outfile != NULL);
	if (report_info.html) {
		fprintf(outfile, "<b><u>Malformed messages</b></u>\n");
		fprintf(outfile, "<br>\n<br>\n");	
	} else {
		fprintf(outfile, "Malformed messages\n");
		len = strlen("Malformed messages\n");
		for (i = 0; i < len; i++) {
			fprintf(outfile, "-");	
		}
		fprintf(outfile, "\n");	
	}
	if ((report_info.log)->malformed_msgs->size) {
		for (i = 0; i < (report_info.log)->malformed_msgs->size; i++) {
			if (report_info.html) 
				fprintf(outfile, "%s<br>\n", (report_info.log)->malformed_msgs->list[i]);
			else
				fprintf(outfile, "%s\n", (report_info.log)->malformed_msgs->list[i]);
		}
	}
	fprintf(outfile, "\n");	
}

static int seaudit_report_generate_report(seaudit_report_info_t report_info) {
	int rt;
	xmlTextReaderPtr reader;
	FILE *outfile = NULL;
	
	assert(report_info.configPath != NULL);
	/* Load all audit messages into memory */
	rt = seaudit_report_load_audit_messages(&report_info);
	if (rt != 0)
		return -1;	

	/* Set/Open the output stream */	
	if (report_info.outFile == NULL) {
		outfile = stdout;
	} else {
		if ((outfile = fopen(report_info.outFile, "w+")) == NULL) {
			fprintf(stderr, "Write permission to save file (%s) was not permitted!", report_info.outFile);
			return -1;
		}
	}
	/* Print report header */
	if (seaudit_report_print_header(report_info, outfile) != 0) {
		fclose(outfile);
		return -1;
	}
	
	/* Parse the xml config file and output report */
	reader = xmlNewTextReaderFilename(report_info.configPath);
	if (reader != NULL) {
		rt = xmlTextReaderRead(reader);
		while (rt == 1) {
			seaudit_report_process_xmlNode(report_info, reader, outfile);
			rt = xmlTextReaderRead(reader);
		}
		xmlFreeTextReader(reader);
		if (rt != 0) {
			fprintf(stderr, "%s : failed to parse config file\n", report_info.configPath);
		}
	} else {
		fprintf(stderr, "Unable to open config file (%s)\n", report_info.configPath);
		fclose(outfile);
		return -1;
	}
	if (report_info.malformed) {
		seaudit_report_print_malformed_msgs(report_info, outfile);
	}
	seaudit_report_print_footer(report_info, outfile);
	fclose(outfile);
	
	return 0;	
}

static void seaudit_report_parse_command_line_args(int argc, char **argv, seaudit_report_info_t *report_info) {
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
	  			if (seaudit_report_add_file_path(optarg, &report_info->outFile) != 0)
	  				goto err;
	  		}
			break;
		case 'c':
			/* Alternate config file path */ 
			if (optarg != 0) {
	  			if (seaudit_report_add_file_path(optarg, &report_info->configPath) != 0)
	  				goto err;
	  		}
			break;
		case 'S':
			/* HTML style sheet file path */ 
			if (optarg != 0) {
	  			if (seaudit_report_add_file_path(optarg, &report_info->stylesheet_file) != 0)
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
			seaudit_report_info_free(report_info);
			exit(0);
		case 'h':	
			/* display help */
			seaudit_report_info_usage(argv[0], FALSE);
			seaudit_report_info_free(report_info);
			exit(0);
		default:	
			/* display usage and handle error */
			seaudit_report_info_usage(argv[0], TRUE);
			goto err;
		}
	}
	if (report_info->configPath == NULL) {
		if (seaudit_report_search_dflt_config_file(report_info) != 0) {
			goto err;
		}
	}
	
	/* Throw warning if a stylesheet was specified, but the --html option was not. */
	if (report_info->stylesheet_file != NULL && !report_info->html) {
		fprintf(stderr, "Warning: The --html option was not specified...ignoring the stylesheet argument.\n\n");
	} 
		
	if (report_info->stylesheet_file == NULL && report_info->html) {
		/* Use default stylesheet in /usr/share/setools directory. If the default  
		 * stylesheet is not found just continue. This is not an application error. */
		if (seaudit_report_search_dflt_stylesheet(report_info) < 0) {
			goto err;
		}
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
	seaudit_report_info_free(report_info);
	exit(-1);
}

int main (int argc, char **argv)
{	
	seaudit_report_info_t report_info;
	
	seaudit_report_info_init(&report_info);
	seaudit_report_parse_command_line_args(argc, argv, &report_info);
	if (seaudit_report_generate_report(report_info) != 0) {
		seaudit_report_info_free(&report_info);	
		return -1;
	}
	seaudit_report_info_free(&report_info);
	
	return 0;
}
