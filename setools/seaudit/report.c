/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information 
 * 
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 3, 2004
 */

/* This is the interface for processing SELinux audit logs and/or seaudit views
 * to generate concise reports containing standard information as well as 
 * customized information using seaudit views. Reports are rendered in either
 * HTML or plain text. Future support will provide rendering into XML. The 
 * HTML report can be formatted by providing an alternate stylesheet file
 * or by configuring the default stylesheet. 
 */
 
/* report generation back-end header */
#include "report.h"

/* libapol and libseaudit headers */
#include "../libseaudit/parse.h"
#include "../libapol/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <libxml/xmlreader.h>

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

/* Helper functions */
static bool_t seaudit_report_is_valid_node_name(const char *name)
{
	int i;
	
	assert(name != NULL);
	for (i = 0; seaudit_report_node_names[i] != NULL; i++)
		if (strcmp(seaudit_report_node_names[i], name) == 0)
			return TRUE;
	return FALSE;
}

static bool_t seaudit_report_is_valid_section_name(const char *name)
{
	int i;

	assert(name != NULL);
	for (i = 0; seaudit_standard_section_names[i] != NULL; i++)
		if (strcmp(seaudit_standard_section_names[i], name) == 0)
			return TRUE;
	return FALSE;
}

static int seaudit_report_load_saved_view(seaudit_report_t *seaudit_report, 
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
	audit_log_view_set_log(*log_view, seaudit_report->log);
	
	old_sz = (*log_view)->num_fltr_msgs;
	/* Now, perform filtering on the log */
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

static int seaudit_report_print_view_results(seaudit_report_t *seaudit_report,
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
	if (seaudit_report->html) {
		fprintf(outfile, "View file: %s<br>\n", view_filePath);
		fprintf(outfile, "<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%d</b><br>\n<br>\n", log_view->num_fltr_msgs);
	} else {
		fprintf(outfile, "View file: %s\n", view_filePath);
		fprintf(outfile, "Number of messages: %d\n\n", log_view->num_fltr_msgs);
	}
		
	for (i = 0; i < log_view->num_fltr_msgs; i++) {
		indx = log_view->fltr_msgs[i];
		if (seaudit_report->log_view != NULL && 
		    find_int_in_array(indx, seaudit_report->log_view->fltr_msgs, seaudit_report->log_view->num_fltr_msgs) < 0) {
		    	/* Skip any messages that are not in the global view (i.e. seaudit_report->log_view) */
			continue;	
		}
		strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", log_view->my_log->msg_list[indx]->date_stamp);
		if (seaudit_report->html)
			fprintf(outfile, "<font class=\"message_date\">%s </font>", date);
		else 	
			fprintf(outfile, "%s ", date);
			
		if (seaudit_report->html)
			fprintf(outfile, "<font class=\"host_name\">%s </font>", audit_log_get_host(log_view->my_log, log_view->my_log->msg_list[indx]->host));
		else 
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
						
			if (seaudit_report->html)
				fprintf(outfile, "<font class=\"message_date\">%s </font>", date);
			else 	
				fprintf(outfile, "%s ", date);
				
			if (seaudit_report->html)
				fprintf(outfile, "<font class=\"host_name\">%s </font>", audit_log_get_host(log_view->my_log, log_view->my_log->msg_list[indx]->host));
			else 
				fprintf(outfile, "%s ", audit_log_get_host(log_view->my_log, log_view->my_log->msg_list[indx]->host));
			
			fprintf(outfile, "kernel: security: %d classes, %d rules",
						policy_msg->classes, policy_msg->rules);
		} else if (log_view->my_log->msg_list[indx]->msg_type == AVC_MSG) {
			cur_msg = log_view->my_log->msg_list[indx]->msg_data.avc_msg;
			
			fprintf(outfile, "kernel: ");
			if (!(cur_msg->tm_stmp_sec == 0 && cur_msg->tm_stmp_nano == 0 && cur_msg->serial == 0)) {
				if (seaudit_report->html) {
					fprintf(outfile, "<font class=\"syscall_timestamp\">audit(%lu.%03lu:%u): </font>", 
						cur_msg->tm_stmp_sec, 
						cur_msg->tm_stmp_nano, 
						cur_msg->serial);
				} else {
					fprintf(outfile, "audit(%lu.%03lu:%u): ", 
						cur_msg->tm_stmp_sec, 
						cur_msg->tm_stmp_nano, 
						cur_msg->serial);
				}
			}
			fprintf(outfile, "avc: ");
			if (seaudit_report->html) {
				if (cur_msg->msg == AVC_DENIED)
					fprintf(outfile, "<font class=\"avc_deny\">denied </font>");
				else
					fprintf(outfile, "<font class=\"avc_grant\">granted </font>");
			} else {
				if (cur_msg->msg == AVC_DENIED)
					fprintf(outfile, "denied ");
				else
					fprintf(outfile, "granted ");
			}
			
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
			if (seaudit_report->html) 
				fprintf(outfile, "<font class=\"exe\">exe=%s </font>", cur_msg->exe);
			else 	
				fprintf(outfile, "exe=%s ", cur_msg->exe);
			
			if (cur_msg->path) {
				if (seaudit_report->html) 
					fprintf(outfile, "<font class=\"path\">path=%s </font>", cur_msg->path);
				else 	
					fprintf(outfile, "path=%s ", cur_msg->path);
			}
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
			
			if (cur_msg->is_src_con) {
				if (seaudit_report->html) {								
					fprintf(outfile, "<font class=\"src_context\">scontext=%s:%s:%s </font>", 
						audit_log_get_user(log_view->my_log, cur_msg->src_user), 
						audit_log_get_role(log_view->my_log, cur_msg->src_role),
						audit_log_get_type(log_view->my_log, cur_msg->src_type));
				} else {
					fprintf(outfile, "scontext=%s:%s:%s ", 
						audit_log_get_user(log_view->my_log, cur_msg->src_user), 
						audit_log_get_role(log_view->my_log, cur_msg->src_role),
						audit_log_get_type(log_view->my_log, cur_msg->src_type));
				}
			}
			if (cur_msg->is_tgt_con) {
				if (seaudit_report->html) {
					fprintf(outfile, "<font class=\"tgt_context\">tcontext=%s:%s:%s </font>", 
						audit_log_get_user(log_view->my_log, cur_msg->tgt_user),
						audit_log_get_role(log_view->my_log, cur_msg->tgt_role),
						audit_log_get_type(log_view->my_log, cur_msg->tgt_type));
				} else {
					fprintf(outfile, "tcontext=%s:%s:%s ", 
						audit_log_get_user(log_view->my_log, cur_msg->tgt_user),
						audit_log_get_role(log_view->my_log, cur_msg->tgt_role),
						audit_log_get_type(log_view->my_log, cur_msg->tgt_type));
				}
			}
			if (cur_msg->is_obj_class) {
				if (seaudit_report->html) 
					fprintf(outfile, "<font class=\"obj_class\">tclass=%s </font>", audit_log_get_obj(log_view->my_log, cur_msg->obj_class));
				else
					fprintf(outfile, "tclass=%s ", audit_log_get_obj(log_view->my_log, cur_msg->obj_class));
			}
		}
		if (seaudit_report->html) 
			fprintf(outfile, "<br>\n<br>\n");
		else 
			fprintf(outfile, "\n\n");
	}
	
	return 0;
}

static int seaudit_report_import_html_stylesheet(seaudit_report_t *seaudit_report, FILE *outfile) {
	char line[LINE_MAX], *line_ptr = NULL;
	FILE *fp;
	
	assert(outfile != NULL);	
	if (seaudit_report->use_stylesheet && seaudit_report->stylesheet_file != NULL) {
		fprintf(outfile, "<style type=\"text/css\">\n");
		fp = fopen(seaudit_report->stylesheet_file, "r");
		if (fp == NULL) {
			fprintf(stderr, "Cannot open stylesheet file %s", seaudit_report->stylesheet_file);
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
		fprintf(outfile, "</style>\n");
	} 
	
	return 0;					      	  
}

static int seaudit_report_print_header(seaudit_report_t *seaudit_report, FILE *outfile) {
	time_t ltime;
	int rt;
	
	time(&ltime);
	if (seaudit_report->html) {
		fprintf(outfile, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n");
		fprintf(outfile, "<html>\n<head>\n");
		rt = seaudit_report_import_html_stylesheet(seaudit_report, outfile);
		if (rt != 0) {
			return -1;
		}
		fprintf(outfile, "<title>seaudit-report</title>\n</head>\n");
		fprintf(outfile, "<body>\n");
		rt = fprintf(outfile, "<b class=\"report_date\"># Report generated by seaudit-report on %s</b><br>\n", ctime(&ltime));
	} else {
		fprintf(outfile, "# Begin\n\n");
		rt = fprintf(outfile, "# Report generated by seaudit-report on %s\n", ctime(&ltime));	
	}
	if (rt < 0)
		return -1;
	return 0;					      	  
}

static int seaudit_report_print_footer(seaudit_report_t *seaudit_report, FILE *outfile) {
	if (seaudit_report->html) {
		fprintf(outfile, "</body>\n</html>\n");
	} else {
		fprintf(outfile, "# End\n");
	}
	return 0;					      	  
}

static void seaudit_report_write_policy_load_msg(seaudit_report_t *seaudit_report, msg_t *cur_msg, FILE *outfile) {
	char date[DATE_STR_SIZE];
	load_policy_msg_t *policy_msg;
	
	assert(seaudit_report != NULL && cur_msg != NULL && outfile != NULL);
	if (cur_msg->msg_type == LOAD_POLICY_MSG) {
		strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", cur_msg->date_stamp);
		if (seaudit_report->html) 	
			fprintf(outfile, "<font class=\"message_date\">%s </font>", date);
		else 
			fprintf(outfile, "%s ", date);
			
		if (seaudit_report->html)
			fprintf(outfile, "<font class=\"host_name\">%s </font>", audit_log_get_host(seaudit_report->log, cur_msg->host));
		else 
			fprintf(outfile, "%s ", audit_log_get_host(seaudit_report->log, cur_msg->host));
		
		policy_msg = cur_msg->msg_data.load_policy_msg;						
		fprintf(outfile, "kernel: security: %d users, %d roles, %d types, %d bools",
					policy_msg->users, policy_msg->roles, 
					policy_msg->types, policy_msg->bools);
		if (seaudit_report->html) 
			fprintf(outfile, "<br>\n");
		else
			fprintf(outfile, "\n");
			
		if (seaudit_report->html) 	
			fprintf(outfile, "<font class=\"message_date\">%s </font>", date);
		else 
			fprintf(outfile, "%s ", date);
			
		if (seaudit_report->html)
			fprintf(outfile, "<font class=\"host_name\">%s </font>", audit_log_get_host(seaudit_report->log, cur_msg->host));
		else 
			fprintf(outfile, "%s ", audit_log_get_host(seaudit_report->log, cur_msg->host));
		
		fprintf(outfile, "kernel: security: %d classes, %d rules",
					policy_msg->classes, policy_msg->rules);
											
		if (seaudit_report->html) 
			fprintf(outfile, "<br>\n");
		else
			fprintf(outfile, "\n");
	} 	
}

static int seaudit_report_print_policy_loads(seaudit_report_t *seaudit_report, FILE *outfile) {
	int i, indx, num = 0;
	msg_t *cur_msg = NULL;
	
	assert(outfile != NULL);
	if (seaudit_report->log_view != NULL) 
		num = seaudit_report->log_view->num_fltr_msgs;
	else
		num = seaudit_report->log->num_load_msgs;
		
	if (seaudit_report->html) 
		fprintf(outfile, "<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%d</b><br>\n<br>\n", num);
	else
		fprintf(outfile, "Number of messages: %d\n\n", num);
	
	if (seaudit_report->log_view != NULL) {
		for (i = 0; i < seaudit_report->log_view->num_fltr_msgs; i++) {
			indx = seaudit_report->log_view->fltr_msgs[i];
			cur_msg = seaudit_report->log_view->my_log->msg_list[indx];
			seaudit_report_write_policy_load_msg(seaudit_report, cur_msg, outfile);
		}	
	} else {	
		for (indx = 0; indx < seaudit_report->log->num_msgs; indx++) {	
			cur_msg = seaudit_report->log->msg_list[indx];	
			seaudit_report_write_policy_load_msg(seaudit_report,cur_msg, outfile);
		}
	}
	
	return 0;					      	  	
}

static int seaudit_report_enforce_toggles_view_do_filter(seaudit_report_t *seaudit_report, 
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
	audit_log_view_set_log(*log_view, seaudit_report->log);
	
	seaudit_multifilter_set_match(multifilter, SEAUDIT_FILTER_MATCH_ALL);
	seaudit_multifilter_set_show_matches(multifilter, TRUE);	
	
	filter = seaudit_filter_create();
	if (filter == NULL) {
		seaudit_multifilter_destroy(multifilter);
		return -1;
	}		
	filter->tgt_type_criteria = tgt_type_criteria_create(&tgt_type, 1);
	if (filter->tgt_type_criteria == NULL) {
		fprintf(stderr, "Error creating target type filter criteria for enforcement toggles.\n");
		seaudit_filter_destroy(filter);
		seaudit_multifilter_destroy(multifilter);
		return -1;
	}
	filter->class_criteria = class_criteria_create(&obj_class, 1);
	if (filter->class_criteria == NULL) {
		fprintf(stderr, "Error creating object class filter criteria for enforcement toggles.\n");
		seaudit_filter_destroy(filter);
		seaudit_multifilter_destroy(multifilter);
		return -1;
	}
	/* Filtering for the 'setenforce' permissions is not handled here */
	
	seaudit_multifilter_add_filter(multifilter, filter);
	audit_log_view_set_multifilter(*log_view, multifilter);
	
	old_sz = (*log_view)->num_fltr_msgs;
	audit_log_view_do_filter(*log_view, &deleted, &num_deleted);
	new_sz = (*log_view)->num_fltr_msgs;
	num_kept = old_sz - num_deleted;
	
	/* Make sure that we still have messages and that it can't be <= to the new size */
	assert(num_kept >= 0 && num_kept <= new_sz);
	if (deleted){
		free(deleted);
	}
	seaudit_multifilter_destroy(multifilter);
	
	return 0;
}

static int seaudit_report_print_enforce_toggles(seaudit_report_t *seaudit_report, FILE *outfile) {
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
	rt = seaudit_report_enforce_toggles_view_do_filter(seaudit_report, &log_view);
	if (rt != 0) {
		audit_log_view_destroy(log_view);
		return -1;
	}
	
	/* Loop through and get the number of avc allow messages with the setenforce permission */
	for (i = 0; i < log_view->num_fltr_msgs; i++) {		
		indx = log_view->fltr_msgs[i];
		if (seaudit_report->log_view != NULL && 
		    find_int_in_array(indx, seaudit_report->log_view->fltr_msgs, seaudit_report->log_view->num_fltr_msgs) < 0) {
		    	/* Skip any messages that are not in the global view (i.e. seaudit_report->log_view) */
			continue;	
		}	
		if (log_view->my_log->msg_list[indx]->msg_type == AVC_MSG) {
			cur_msg = log_view->my_log->msg_list[indx]->msg_data.avc_msg;
			if (cur_msg->msg == AVC_DENIED)
				continue;
				
			if (cur_msg->num_perms > 0) {
				for (j = 0; j < cur_msg->num_perms; j++) {
					cur_perm = audit_log_get_perm(log_view->my_log, cur_msg->perms[j]);
					if (strncasecmp(cur_perm, perm, strlen(perm)) == 0) {
						/* Increment number of setenforce messages */
						actual_num++;
					}
				}
			}
		}
	}

	/* Since we cannot filter by setenforce permission within the view, we do so manually 
	 * within the following for loop. */	
	if (seaudit_report->html) 
		fprintf(outfile, "<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%d</b><br>\n<br>\n", actual_num);
	else
		fprintf(outfile, "Number of messages: %d\n\n", actual_num);
		
	for (i = 0; i < log_view->num_fltr_msgs; i++) {	
		indx = log_view->fltr_msgs[i];
		if (seaudit_report->log_view != NULL && 
		    find_int_in_array(indx, seaudit_report->log_view->fltr_msgs, seaudit_report->log_view->num_fltr_msgs) < 0) {
		    	/* Skip any messages that are not in the global view (i.e. seaudit_report->log_view) */
			continue;	
		}	
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
			if (seaudit_report->html) 
				fprintf(outfile, "<font class=\"message_date\">%s </font>", date);
			else 
				fprintf(outfile, "%s ", date);
				
			if (seaudit_report->html) 
				fprintf(outfile, "<font class=\"host_name\">%s </font>", audit_log_get_host(log_view->my_log, log_view->my_log->msg_list[indx]->host));
			else 
				fprintf(outfile, "%s ", audit_log_get_host(log_view->my_log, log_view->my_log->msg_list[indx]->host));
				
			fprintf(outfile, "kernel: ");
			if (!(cur_msg->tm_stmp_sec == 0 && cur_msg->tm_stmp_nano == 0 && cur_msg->serial == 0)) {
				if (seaudit_report->html) {
					fprintf(outfile, "<font class=\"syscall_timestamp\">audit(%lu.%03lu:%u): </font>", 
						cur_msg->tm_stmp_sec, 
						cur_msg->tm_stmp_nano, 
						cur_msg->serial);
				} else {
					fprintf(outfile, "audit(%lu.%03lu:%u): ", 
						cur_msg->tm_stmp_sec, 
						cur_msg->tm_stmp_nano, 
						cur_msg->serial);
				}
			}
			fprintf(outfile, "avc: ");
			if (seaudit_report->html)			
				fprintf(outfile, "<font class=\"avc_grant\">granted </font>");
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
			if (seaudit_report->html) 
				fprintf(outfile, "<font class=\"exe\">exe=%s </font>", cur_msg->exe);
			else 	
				fprintf(outfile, "exe=%s ", cur_msg->exe);
			
			if (cur_msg->path) {
				if (seaudit_report->html) 
					fprintf(outfile, "<font class=\"path\">path=%s </font>", cur_msg->path);
				else 	
					fprintf(outfile, "path=%s ", cur_msg->path);
			}
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
			
			if (cur_msg->is_src_con) {
				if (seaudit_report->html) {
					fprintf(outfile, "<font class=\"src_context\">scontext=%s:%s:%s </font>", 
						audit_log_get_user(log_view->my_log, cur_msg->src_user), 
						audit_log_get_role(log_view->my_log, cur_msg->src_role),
						audit_log_get_type(log_view->my_log, cur_msg->src_type));
				} else {
					fprintf(outfile, "scontext=%s:%s:%s ", 
						audit_log_get_user(log_view->my_log, cur_msg->src_user), 
						audit_log_get_role(log_view->my_log, cur_msg->src_role),
						audit_log_get_type(log_view->my_log, cur_msg->src_type));
				}
			}
			if (cur_msg->is_tgt_con) {
				if (seaudit_report->html) {
					fprintf(outfile, "<font class=\"tgt_context\">tcontext=%s:%s:%s </font>", 
						audit_log_get_user(log_view->my_log, cur_msg->tgt_user),
						audit_log_get_role(log_view->my_log, cur_msg->tgt_role),
						audit_log_get_type(log_view->my_log, cur_msg->tgt_type));
				} else {
					fprintf(outfile, "tcontext=%s:%s:%s ", 
						audit_log_get_user(log_view->my_log, cur_msg->tgt_user),
						audit_log_get_role(log_view->my_log, cur_msg->tgt_role),
						audit_log_get_type(log_view->my_log, cur_msg->tgt_type));
				}
			}
			if (cur_msg->is_obj_class) {
				if (seaudit_report->html) 
					fprintf(outfile, "<font class=\"obj_class\">tclass=%s </font>", audit_log_get_obj(log_view->my_log, cur_msg->obj_class));
				else 
					fprintf(outfile, "tclass=%s ", audit_log_get_obj(log_view->my_log, cur_msg->obj_class));
			}
		}
		if (seaudit_report->html) 
			fprintf(outfile, "<br>\n");
		else
			fprintf(outfile, "\n");
	}
	audit_log_view_destroy(log_view);			
	return 0;					      	  	
}

static void seaudit_report_write_boolean_msg(seaudit_report_t *seaudit_report, msg_t *cur_msg, FILE *outfile) {
	boolean_msg_t *boolean_msg;
	const char *cur_bool;
	char date[DATE_STR_SIZE];
	int j;
	
	assert(seaudit_report != NULL && cur_msg != NULL && outfile != NULL);
	if (cur_msg->msg_type == BOOLEAN_MSG) {
		strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", cur_msg->date_stamp);
		if (seaudit_report->html)	
			fprintf(outfile, "<font class=\"message_date\">%s </font>", date);
		else 
			fprintf(outfile, "%s ", date);
			
		if (seaudit_report->html) 
			fprintf(outfile, "<font class=\"host_name\">%s </font>", audit_log_get_host(seaudit_report->log, cur_msg->host));
		else 
			fprintf(outfile, "%s ", audit_log_get_host(seaudit_report->log, cur_msg->host));
			
		fprintf(outfile, "kernel: ");
		fprintf(outfile, "security: ");
          	fprintf(outfile, "committed booleans: ");
		boolean_msg = cur_msg->msg_data.boolean_msg;
		if (boolean_msg->num_bools > 0) {
			fprintf(outfile, "{ ");
			fprintf(outfile, "%s", audit_log_get_bool(seaudit_report->log, boolean_msg->booleans[0]));
			fprintf(outfile, ":%d", boolean_msg->values[0]);
	
			for (j = 1; j < boolean_msg->num_bools; j++) {
			        cur_bool = audit_log_get_bool(seaudit_report->log, boolean_msg->booleans[j]);
				fprintf(outfile, ", %s", cur_bool);
				fprintf(outfile, ":%d", boolean_msg->values[j]);
			}
			fprintf(outfile, " }");
		}
		if (seaudit_report->html)
			fprintf(outfile, "<br>\n");
		else 
			fprintf(outfile, "\n");
	}
}

static int seaudit_report_print_policy_booleans(seaudit_report_t *seaudit_report, FILE *outfile) {
	int i, indx, num = 0;
	msg_t *cur_msg = NULL;
	
	assert(outfile != NULL);
	if (seaudit_report->log_view != NULL) 
		num = seaudit_report->log_view->num_fltr_msgs;
	else 
		num = seaudit_report->log->num_bool_msgs;
		
	if (seaudit_report->html)
		fprintf(outfile, "<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%d</b><br>\n<br>\n", num);
	else 
		fprintf(outfile, "Number of messages: %d\n\n", num);
	
	if (seaudit_report->log_view != NULL) {
		for (i = 0; i < seaudit_report->log_view->num_fltr_msgs; i++) {
			indx = seaudit_report->log_view->fltr_msgs[i];
			cur_msg = seaudit_report->log_view->my_log->msg_list[indx];
			seaudit_report_write_boolean_msg(seaudit_report, cur_msg, outfile);
		}	
	} else {			
		for (indx = 0; indx < seaudit_report->log->num_msgs; indx++) {
			cur_msg	= seaudit_report->log->msg_list[indx];
			seaudit_report_write_boolean_msg(seaudit_report, cur_msg, outfile);
		}
	}
	
	return 0;					      					      	  	
}

static void seaudit_report_write_allow_msg(seaudit_report_t *seaudit_report, msg_t *msg, FILE *outfile) {
	avc_msg_t *cur_msg;
	const char *cur_perm;
	char date[DATE_STR_SIZE];
	int j;
	
	assert(seaudit_report != NULL && msg != NULL && outfile != NULL);
	if (msg->msg_type == AVC_MSG) {
		cur_msg = msg->msg_data.avc_msg;
		if (cur_msg->msg == AVC_DENIED) 
			return;
		
		strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", msg->date_stamp);	
		if (seaudit_report->html) 
			fprintf(outfile, "<font class=\"message_date\">%s </font>", date);
		else 
			fprintf(outfile, "%s ", date);
			
		if (seaudit_report->html) 
			fprintf(outfile, "<font class=\"host_name\">%s </font>", audit_log_get_host(seaudit_report->log, msg->host));
		else 
			fprintf(outfile, "%s ", audit_log_get_host(seaudit_report->log, msg->host));
		fprintf(outfile, "kernel: ");
		
		if (!(cur_msg->tm_stmp_sec == 0 && cur_msg->tm_stmp_nano == 0 && cur_msg->serial == 0)) {
			if (seaudit_report->html) {
				fprintf(outfile, "<font class=\"syscall_timestamp\">audit(%lu.%03lu:%u): </font>", 
					cur_msg->tm_stmp_sec, 
					cur_msg->tm_stmp_nano, 
					cur_msg->serial);
			} else {
				fprintf(outfile, "audit(%lu.%03lu:%u): ", 
					cur_msg->tm_stmp_sec, 
					cur_msg->tm_stmp_nano, 
					cur_msg->serial);
			}
		}
		fprintf(outfile, "avc: ");
		if (seaudit_report->html) 
			fprintf(outfile, "<font class=\"avc_grant\">granted </font>");
		else 
			fprintf(outfile, "granted ");
		
		if (cur_msg->num_perms > 0) {
			fprintf(outfile, "{ ");
			for (j = 0; j < cur_msg->num_perms; j++) {
				cur_perm = audit_log_get_perm(seaudit_report->log, cur_msg->perms[j]);
				fprintf(outfile, "%s ", cur_perm);
			}
			fprintf(outfile, "}");
		}
		fprintf(outfile, " for ");
		
		fprintf(outfile, "pid=%d ", cur_msg->pid);
		if (seaudit_report->html) 
			fprintf(outfile, "<font class=\"exe\">exe=%s </font>", cur_msg->exe);
		else 	
			fprintf(outfile, "exe=%s ", cur_msg->exe);
		
		if (cur_msg->path) {
			if (seaudit_report->html) 
				fprintf(outfile, "<font class=\"path\">path=%s </font>", cur_msg->path);
			else 	
				fprintf(outfile, "path=%s ", cur_msg->path);
		}
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
		
		if (cur_msg->is_src_con) {
			if (seaudit_report->html) {					
				fprintf(outfile, "<font class=\"src_context\">scontext=%s:%s:%s </font>", 
					audit_log_get_user(seaudit_report->log, cur_msg->src_user), 
					audit_log_get_role(seaudit_report->log, cur_msg->src_role),
					audit_log_get_type(seaudit_report->log, cur_msg->src_type));
			} else {
				fprintf(outfile, "scontext=%s:%s:%s ", 
					audit_log_get_user(seaudit_report->log, cur_msg->src_user), 
					audit_log_get_role(seaudit_report->log, cur_msg->src_role),
					audit_log_get_type(seaudit_report->log, cur_msg->src_type));
			}
		}
		if (cur_msg->is_tgt_con) {
			if (seaudit_report->html) {	
				fprintf(outfile, "<font class=\"tgt_context\">tcontext=%s:%s:%s </font>", 
					audit_log_get_user(seaudit_report->log, cur_msg->tgt_user),
					audit_log_get_role(seaudit_report->log, cur_msg->tgt_role),
					audit_log_get_type(seaudit_report->log, cur_msg->tgt_type));
			} else {
				fprintf(outfile, "tcontext=%s:%s:%s ", 
					audit_log_get_user(seaudit_report->log, cur_msg->tgt_user),
					audit_log_get_role(seaudit_report->log, cur_msg->tgt_role),
					audit_log_get_type(seaudit_report->log, cur_msg->tgt_type));
			}
		}
		if (cur_msg->is_obj_class) {
			if (seaudit_report->html) 
				fprintf(outfile, "<font class=\"obj_class\">tclass=%s </font>", audit_log_get_obj(seaudit_report->log, cur_msg->obj_class));
			else 
				fprintf(outfile, "tclass=%s ", audit_log_get_obj(seaudit_report->log, cur_msg->obj_class));
		}
			
		if (seaudit_report->html) 
			fprintf(outfile, "<br>\n");
		else
			fprintf(outfile, "\n");
	}
}

static int seaudit_report_print_allow_listing(seaudit_report_t *seaudit_report, FILE *outfile) {
	
	int i, indx, num = 0;
	msg_t *cur_msg = NULL;
	
	assert(outfile != NULL);
	
	if (seaudit_report->log_view != NULL) 	
		num = seaudit_report->log_view->num_fltr_msgs;
	else 
		num = seaudit_report->log->num_allow_msgs;
		
	if (seaudit_report->html) 
		fprintf(outfile, "<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%d</b><br>\n<br>\n", num);
	else
		fprintf(outfile, "Number of messages: %d\n\n", num);
			
	if (seaudit_report->log_view != NULL) {		
		for (i = 0; i < seaudit_report->log_view->num_fltr_msgs; i++) {
			indx = seaudit_report->log_view->fltr_msgs[i];
			cur_msg = seaudit_report->log_view->my_log->msg_list[indx];
			seaudit_report_write_allow_msg(seaudit_report, cur_msg, outfile);
		}	
	} else {	
		for (indx = 0; indx < seaudit_report->log->num_msgs; indx++) {		
			cur_msg	= seaudit_report->log->msg_list[indx];
			seaudit_report_write_allow_msg(seaudit_report, cur_msg, outfile);
		}
	}
	
	return 0;					      	  	
}

static void seaudit_report_write_deny_msg(seaudit_report_t *seaudit_report, msg_t *cur_msg, FILE *outfile) {
	int j;
	avc_msg_t *avc_msg;
	const char *cur_perm;
	char date[DATE_STR_SIZE];
	
	assert(seaudit_report != NULL && cur_msg != NULL && outfile != NULL);
	if (cur_msg->msg_type == AVC_MSG) {
		avc_msg = cur_msg->msg_data.avc_msg;
		if (avc_msg->msg != AVC_DENIED) 
			return;
		
		strftime(date, DATE_STR_SIZE, "%b %d %H:%M:%S", cur_msg->date_stamp);	
		if (seaudit_report->html)
			fprintf(outfile, "<font class=\"message_date\">%s </font>", date);
		else 
			fprintf(outfile, "%s ", date);
		if (seaudit_report->html)
			fprintf(outfile, "<font class=\"host_name\">%s </font>", audit_log_get_host(seaudit_report->log, cur_msg->host));
		else 
			fprintf(outfile, "%s ", audit_log_get_host(seaudit_report->log, cur_msg->host));
		fprintf(outfile, "kernel: ");
		if (!(avc_msg->tm_stmp_sec == 0 && avc_msg->tm_stmp_nano == 0 && avc_msg->serial == 0)) {
			if (seaudit_report->html) {
				fprintf(outfile, "<font class=\"syscall_timestamp\">audit(%lu.%03lu:%u): </font>", 
					avc_msg->tm_stmp_sec, 
					avc_msg->tm_stmp_nano, 
					avc_msg->serial);
			} else {
				fprintf(outfile, "audit(%lu.%03lu:%u): ", 
					avc_msg->tm_stmp_sec, 
					avc_msg->tm_stmp_nano, 
					avc_msg->serial);
			}
		}
		fprintf(outfile, "avc: ");
		if (seaudit_report->html)
			fprintf(outfile, "<font class=\"avc_deny\">denied </font>");
		else 
			fprintf(outfile, "denied ");
		
		if (avc_msg->num_perms > 0) {
			fprintf(outfile, "{ ");
			for (j = 0; j < avc_msg->num_perms; j++) {
				cur_perm = audit_log_get_perm(seaudit_report->log, avc_msg->perms[j]);
				fprintf(outfile, "%s ", cur_perm);
			}
			fprintf(outfile, "}");
		}
		fprintf(outfile, " for ");	
		if (avc_msg->pid)
			fprintf(outfile, "pid=%d ", avc_msg->pid);
		if (avc_msg->exe) {
			if (seaudit_report->html) 
				fprintf(outfile, "<font class=\"exe\">exe=%s </font>", avc_msg->exe);
			else 	
				fprintf(outfile, "exe=%s ", avc_msg->exe);
		}
		if (avc_msg->path) {
			if (seaudit_report->html) 
				fprintf(outfile, "<font class=\"path\">path=%s </font>", avc_msg->path);
			else 	
				fprintf(outfile, "path=%s ", avc_msg->path);
		}
		if (avc_msg->dev)
			fprintf(outfile, "dev=%s ", avc_msg->dev);
		if (avc_msg->is_inode)
			fprintf(outfile, "ino=%lu ", avc_msg->inode);
		if (avc_msg->laddr)
			fprintf(outfile, "laddr=%s ", avc_msg->laddr);
		if (avc_msg->lport != 0)
			fprintf(outfile, "lport=%d ", avc_msg->lport);
		if (avc_msg->faddr)
			fprintf(outfile, "faddr=%s ", avc_msg->faddr);
		if (avc_msg->fport != 0)
			fprintf(outfile, "fport=%d ", avc_msg->fport);
		if (avc_msg->daddr)
			fprintf(outfile, "daddr=%s ", avc_msg->daddr);
		if (avc_msg->dest != 0)
			fprintf(outfile, "dest=%d ", avc_msg->dest);
		if (avc_msg->port != 0)
			fprintf(outfile, "port=%d ", avc_msg->port);
		if (avc_msg->saddr)
			fprintf(outfile, "saddr=%s ", avc_msg->saddr);
		if (avc_msg->source != 0)
			fprintf(outfile, "source=%d ", avc_msg->source);
		if (avc_msg->netif)
			fprintf(outfile, "netif=%s ", avc_msg->netif);
		if (avc_msg->is_key)
			fprintf(outfile, "key=%d ", avc_msg->key);
		if (avc_msg->is_capability)
			fprintf(outfile, "capability=%d ", avc_msg->capability);	
		
		if (avc_msg->is_src_con) {
			if (seaudit_report->html) {							
				fprintf(outfile, "<font class=\"src_context\">scontext=%s:%s:%s </font>", 
					audit_log_get_user(seaudit_report->log, avc_msg->src_user), 
					audit_log_get_role(seaudit_report->log, avc_msg->src_role),
					audit_log_get_type(seaudit_report->log, avc_msg->src_type));
			} else {
				fprintf(outfile, "scontext=%s:%s:%s ", 
					audit_log_get_user(seaudit_report->log, avc_msg->src_user), 
					audit_log_get_role(seaudit_report->log, avc_msg->src_role),
					audit_log_get_type(seaudit_report->log, avc_msg->src_type));
			}
		}
		if (avc_msg->is_tgt_con) {
			if (seaudit_report->html) {	
				fprintf(outfile, "<font class=\"tgt_context\">tcontext=%s:%s:%s </font>", 
					audit_log_get_user(seaudit_report->log, avc_msg->tgt_user),
					audit_log_get_role(seaudit_report->log, avc_msg->tgt_role),
					audit_log_get_type(seaudit_report->log, avc_msg->tgt_type));
			} else {
				fprintf(outfile, "tcontext=%s:%s:%s ", 
					audit_log_get_user(seaudit_report->log, avc_msg->tgt_user),
					audit_log_get_role(seaudit_report->log, avc_msg->tgt_role),
					audit_log_get_type(seaudit_report->log, avc_msg->tgt_type));
			}
		}
		if (avc_msg->is_obj_class) {
			if (seaudit_report->html) {	
				fprintf(outfile, "<font class=\"obj_class\">tclass=%s </font>", audit_log_get_obj(seaudit_report->log, avc_msg->obj_class));
			} else {
				fprintf(outfile, "tclass=%s ", audit_log_get_obj(seaudit_report->log, avc_msg->obj_class));
			}
		}
		if (seaudit_report->html) 
			fprintf(outfile, "<br>\n");
		else
			fprintf(outfile, "\n");
	}	
}

static int seaudit_report_print_deny_listing(seaudit_report_t *seaudit_report, FILE *outfile) {
	int i, indx, num = 0;
	msg_t *cur_msg = NULL;
	
	assert(outfile != NULL);
	if (seaudit_report->log_view != NULL) 
		num = seaudit_report->log_view->num_fltr_msgs;
	else 
		num = seaudit_report->log->num_deny_msgs;
		
	if (seaudit_report->html) 
		fprintf(outfile, "<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%d</b><br>\n<br>\n", num);
	else
		fprintf(outfile, "Number of messages: %d\n\n", num);
	
	if (seaudit_report->log_view != NULL) {
		for (i = 0; i < seaudit_report->log_view->num_fltr_msgs; i++) {
			indx = seaudit_report->log_view->fltr_msgs[i];
			cur_msg = seaudit_report->log_view->my_log->msg_list[indx];
			seaudit_report_write_deny_msg(seaudit_report, cur_msg, outfile);
		}	
	} else {		
		for (i = 0; i < seaudit_report->log->num_msgs; i++) {	
			cur_msg	= seaudit_report->log->msg_list[i];
			seaudit_report_write_deny_msg(seaudit_report, cur_msg, outfile);
		}
	}
	
	return 0;									      	  	
}

static void seaudit_report_print_view_stats(seaudit_report_t *seaudit_report, FILE *outfile) {
	int i, indx;
	int num_allow, num_deny, num_bool, num_load;
	msg_t *cur_msg = NULL;
	
	assert(seaudit_report != NULL && seaudit_report->log_view != NULL && outfile != NULL);
	num_allow = num_deny = num_bool = num_load = 0;
	for (i = 0; i < seaudit_report->log_view->num_fltr_msgs; i++) {
		indx = seaudit_report->log_view->fltr_msgs[i];
		cur_msg = seaudit_report->log_view->my_log->msg_list[indx];
		
		if (cur_msg->msg_type == AVC_MSG) {
			if (cur_msg->msg_data.avc_msg->msg == AVC_DENIED) {
				num_deny++;
			} else { 
				num_allow++;
			}	
		} else if (cur_msg->msg_type == LOAD_POLICY_MSG) {
			num_load++;
		} else {
			num_bool++; 
		}
	}
	if (seaudit_report->html) {
		fprintf(outfile, "<font class=\"stats_label\">Number of total messages:</font> <b class=\"stats_count\">%d</b><br>\n", seaudit_report->log_view->num_fltr_msgs);
		fprintf(outfile, "<font class=\"stats_label\">Number of policy load messages:</font> <b class=\"stats_count\">%d</b><br>\n", num_load);
		fprintf(outfile, "<font class=\"stats_label\">Number of policy boolean messages:</font> <b class=\"stats_count\">%d</b><br>\n", num_bool);
		fprintf(outfile, "<font class=\"stats_label\">Number of allow messages:</font> <b class=\"stats_count\">%d</b><br>\n", num_allow);
		fprintf(outfile, "<font class=\"stats_label\">Number of denied messages:</font> <b class=\"stats_count\">%d</b><br>\n", num_deny);
	} else {
		fprintf(outfile, "Number of total messages: %d\n", seaudit_report->log_view->num_fltr_msgs);
		fprintf(outfile, "Number of policy load messages: %d\n", num_load);
		fprintf(outfile, "Number of policy boolean messages: %d\n", num_bool);
		fprintf(outfile, "Number of allow messages: %d\n", num_allow);
		fprintf(outfile, "Number of denied messages: %d\n", num_deny);
	}
}

static void seaudit_report_print_entire_log_stats(seaudit_report_t *seaudit_report, FILE *outfile) {
	assert(seaudit_report != NULL && outfile != NULL);
	
	if (seaudit_report->html) {
		fprintf(outfile, "<font class=\"stats_label\">Number of total messages:</font> <b class=\"stats_count\">%d</b><br>\n", seaudit_report->log->num_msgs);
		fprintf(outfile, "<font class=\"stats_label\">Number of policy load messages:</font> <b class=\"stats_count\">%d</b><br>\n", seaudit_report->log->num_load_msgs);
		fprintf(outfile, "<font class=\"stats_label\">Number of policy boolean messages:</font> <b class=\"stats_count\">%d</b><br>\n", seaudit_report->log->num_bool_msgs);
		fprintf(outfile, "<font class=\"stats_label\">Number of allow messages:</font> <b class=\"stats_count\">%d</b><br>\n", seaudit_report->log->num_allow_msgs);
		fprintf(outfile, "<font class=\"stats_label\">Number of denied messages:</font> <b class=\"stats_count\">%d</b><br>\n", seaudit_report->log->num_deny_msgs);
	} else {
		fprintf(outfile, "Number of total messages: %d\n", seaudit_report->log->num_msgs);
		fprintf(outfile, "Number of policy load messages: %d\n", seaudit_report->log->num_load_msgs);
		fprintf(outfile, "Number of policy boolean messages: %d\n", seaudit_report->log->num_bool_msgs);
		fprintf(outfile, "Number of allow messages: %d\n", seaudit_report->log->num_allow_msgs);
		fprintf(outfile, "Number of denied messages: %d\n", seaudit_report->log->num_deny_msgs);
	}
}

static int seaudit_report_print_stats(seaudit_report_t *seaudit_report, FILE *outfile) {
	assert(outfile != NULL);
	
	if (seaudit_report->log_view != NULL) {
		seaudit_report_print_view_stats(seaudit_report, outfile);
	} else {
		seaudit_report_print_entire_log_stats(seaudit_report, outfile);
	}
	return 0;					      	  	
}

static int seaudit_report_print_standard_section(seaudit_report_t *seaudit_report, xmlChar *id, 
							  xmlChar *title, FILE *outfile) { 
	int sz, len, i, rt = 0;
	
	assert(id != NULL && outfile != NULL);
	if (!seaudit_report_is_valid_section_name(id)) {
		fprintf(stderr, "Invalid standard section ID.\n");
		return -1;
	}
	sz = strlen(id);
	if (title != NULL) {
		if (seaudit_report->html) {
			fprintf(outfile, "<h2 class=\"standard_section_title\"><u>%s</h2></u>\n", title);
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
		rt = seaudit_report_print_policy_loads(seaudit_report, outfile);
	} else if (strncasecmp(id, "EnforcementToggles", sz) == 0) {
		rt = seaudit_report_print_enforce_toggles(seaudit_report, outfile);
	} else if (strncasecmp(id, "PolicyBooleans", sz) == 0) {
		rt = seaudit_report_print_policy_booleans(seaudit_report, outfile);
	} else if (strncasecmp(id, "AllowListing", sz) == 0) {
		rt = seaudit_report_print_allow_listing(seaudit_report, outfile);
	} else if (strncasecmp(id, "DenyListing", sz) == 0) {
		rt = seaudit_report_print_deny_listing(seaudit_report, outfile); 
	} else if (strncasecmp(id, "Statistics", sz) == 0) {
		rt = seaudit_report_print_stats(seaudit_report, outfile);
	}
	if (rt != 0) 
		return -1;
		
	if (seaudit_report->html) 
		fprintf(outfile, "<br>\n");
	else
		fprintf(outfile, "\n");
	
	return 0;
}

static int seaudit_report_print_custom_section(seaudit_report_t *seaudit_report,
							xmlTextReaderPtr reader,  
						        xmlChar *title, 
						        FILE *outfile) {
	int rt, len, i;
	xmlChar *view_filePath = NULL, *name = NULL;
	bool_t end_of_element = FALSE;
	audit_log_view_t *log_view = NULL;
	
	if (title != NULL) {
		if (seaudit_report->html) {
			fprintf(outfile, "<h2 class=\"custom_section_title\"><u>%s</h2></u>\n", title);
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
			rt = seaudit_report_load_saved_view(seaudit_report, view_filePath, &log_view);
			if (rt != 0) {
				goto err;
			}
			rt = seaudit_report_print_view_results(seaudit_report, view_filePath, log_view, outfile);
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
		fprintf(stderr, "%s : failed to parse config file (rt:%d)\n", seaudit_report->configPath, rt);
	}
		
	if (!end_of_element) {
		fprintf(stderr, "Encountered end of file before finding end of element for custom-section node.\n");
		goto err;	
	}
	if (seaudit_report->html) 
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

static void seaudit_report_print_malformed_msgs(seaudit_report_t *seaudit_report, FILE *outfile) {
	int i, len;
	
	assert(outfile != NULL);
	if (seaudit_report->log_view != NULL) 
		return;
	if (seaudit_report->html) {
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
	if ((seaudit_report->log)->malformed_msgs->size) {
		for (i = 0; i < (seaudit_report->log)->malformed_msgs->size; i++) {
			if (seaudit_report->html) 
				fprintf(outfile, "%s<br>\n", (seaudit_report->log)->malformed_msgs->list[i]);
			else
				fprintf(outfile, "%s\n", (seaudit_report->log)->malformed_msgs->list[i]);
		}
	}
	fprintf(outfile, "\n");	
}


static int seaudit_report_parse_seaudit_report_node(seaudit_report_t *seaudit_report, 
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

static int seaudit_report_parse_standard_section_attributes(seaudit_report_t *seaudit_report, 
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

static int seaudit_report_parse_custom_section_attributes(seaudit_report_t *seaudit_report, 
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
static int seaudit_report_process_xmlNode(seaudit_report_t *seaudit_report, xmlTextReaderPtr reader, FILE *outfile) {
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
			rt = seaudit_report_parse_seaudit_report_node(seaudit_report, reader, 
								      &id_attr, &title_attr);
			if (rt != 0)
				goto err;
			if (seaudit_report->html) {
				fprintf(outfile, "<h1 class=\"report_title\">Title: %s</h1>\n", title_attr);
			} else {
				fprintf(outfile, "Title: %s\n", title_attr);
			}
		} else if (strcmp(name, "standard-section") == 0 && xmlTextReaderNodeType(reader) == 1) {
			rt = seaudit_report_parse_standard_section_attributes(seaudit_report, reader, 
								              &id_attr, &title_attr);
			if (rt != 0)
				goto err;
			if (id_attr == NULL) {
				fprintf(stderr, "Missing required id attribute for standard section node.\n");
				goto err;
			}
			/* NOTE: If a title wasn't provided, we still continue. */
			rt = seaudit_report_print_standard_section(seaudit_report, 
										    id_attr, 
										    title_attr, 
										    outfile);
			if (rt != 0)
				goto err;
		} else if (strcmp(name, "custom-section") == 0 && xmlTextReaderNodeType(reader) == 1) {
			rt = seaudit_report_parse_custom_section_attributes(seaudit_report, reader, &title_attr);
			if (rt != 0)
				goto err;
			/* NOTE: If a title wasn't provided, we still continue. */
			rt = seaudit_report_print_custom_section(seaudit_report, 
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

static int seaudit_report_add_file_path(const char *str, char **copy_ptr) { 
	int len;
	
	if (str == NULL) 
		return 0;
		
	assert(copy_ptr != NULL);	
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
	(*copy_ptr)[len] = '\0';
	
	return 0;	
}

int seaudit_report_add_logfile_to_list(seaudit_report_t *seaudit_report, const char *file)
{
	assert(seaudit_report != NULL);

	seaudit_report->logfiles =
	    realloc(seaudit_report->logfiles, (sizeof(char *) * (seaudit_report->num_logfiles + 1)));
	if (!seaudit_report->logfiles)
		goto err;
	if ((seaudit_report->logfiles[seaudit_report->num_logfiles] = strdup(file)) == NULL)
		goto err;
	seaudit_report->num_logfiles++;
	return 0;

err:
	fprintf(stderr, "Error: Out of memory\n");
	return -1;

}

int seaudit_report_load_audit_messages_from_log_file(seaudit_report_t *seaudit_report) {
	int i;
	unsigned int rt = 0;
	FILE *tmp_file = NULL;
	
	seaudit_report->log = audit_log_create();
	/* If specified STDIN, then parse STDIN, otherwise we will parse each logfile */
	/* Add a flag to parse_audit function in libseaudit to hold onto malformed strings. */
	if (seaudit_report->stdin) {
		rt |= parse_audit(stdin, seaudit_report->log);
		if (rt & PARSE_RET_MEMORY_ERROR) {
			fprintf(stderr, "Memory error while parsing the log!\n");
				return -1;
		} else if (rt & PARSE_RET_NO_SELINUX_ERROR) {
			fprintf(stderr, "No SELinux messages found in log!\n");
				return -1;
		}
	} else {
		/* Load in all data into log structure */
		for (i = 0; i < seaudit_report->num_logfiles; i++) {
			tmp_file = fopen(seaudit_report->logfiles[i], "r");
			if (!tmp_file) {
				fprintf(stderr, "Error opening file %s\n%s\n", seaudit_report->logfiles[i], strerror(errno));
				return -1;
			}
			
			rt |= parse_audit(tmp_file, seaudit_report->log);
			if (rt & PARSE_RET_MEMORY_ERROR) {
				fprintf(stderr, "Memory error while parsing the log!\n");
				fclose(tmp_file);
				return -1;
			} else if (rt & PARSE_RET_NO_SELINUX_ERROR) {
				fprintf(stderr, "No SELinux messages found in log!\n");
				fclose(tmp_file);
				return -1;
			}
			fclose(tmp_file);
		}
	}
	
	return 0;
}

int seaudit_report_search_dflt_config_file(seaudit_report_t *seaudit_report) {
	int len;
	char *configFile_dir = NULL;
	
	assert(seaudit_report != NULL);
	if (seaudit_report->configPath == NULL) {
		configFile_dir = find_file(CONFIG_FILE);
		if (configFile_dir == NULL) {
			fprintf(stderr, "Could not find default config file.\n");
			return -1;
		}
		len = strlen(configFile_dir) + strlen(CONFIG_FILE) + 2;
		seaudit_report->configPath = (char *)malloc(len * sizeof(char));
		if (seaudit_report->configPath == NULL) {
			free(configFile_dir);
			fprintf(stderr, "out of memory");
			return -1;
		}	
	     	snprintf(seaudit_report->configPath, len, "%s/%s", configFile_dir, CONFIG_FILE);
	     	free(configFile_dir);
	     	assert(seaudit_report->configPath != NULL);
	     	
	     	/* Here we must check to see if we can read the file, or the application cannot continue. */
	     	if (access(seaudit_report->configPath, R_OK) != 0) {
	     		fprintf(stderr, "Could not read system default config file (%s).\n", 
	     			seaudit_report->configPath);
			return -1;
	     	}
	}

	return 0;
}

int seaudit_report_search_dflt_stylesheet(seaudit_report_t *seaudit_report) {
	int len;
	char *dir = NULL;
	
	assert(seaudit_report != NULL);
	if (seaudit_report->stylesheet_file == NULL) {
		dir = find_file(STYLESHEET_FILE);
		if (dir == NULL) {
			fprintf(stderr, "Could not find default stylesheet.\n");
			return -1;
		}
		len = strlen(dir) + strlen(STYLESHEET_FILE) + 2;
		seaudit_report->stylesheet_file = (char *)malloc(len * sizeof(char));
		if (seaudit_report->stylesheet_file == NULL) {
			free(dir);
			fprintf(stderr, "out of memory");
			return -1;
		}	
	     	snprintf(seaudit_report->stylesheet_file, len, "%s/%s", dir, STYLESHEET_FILE);
	     	free(dir);
	     	assert(seaudit_report->stylesheet_file != NULL);
	     	/* Here we do not return an error if we cannot read the file, b/c a stylesheet is not necessary. 
	     	 * We simply output a message to the user. */
	     	if (access(seaudit_report->configPath, R_OK) != 0) {
	     		fprintf(stderr, "Could not read system default style sheet (%s)...continuing.\n", 
	     			seaudit_report->configPath);
	     	}
	}

	return 0;
}

int seaudit_report_add_outFile_path(const char *file, seaudit_report_t *seaudit_report)
{
	return (seaudit_report_add_file_path(file, &seaudit_report->outFile));	
}

int seaudit_report_add_configFile_path(const char *file, seaudit_report_t *seaudit_report)
{
	return (seaudit_report_add_file_path(file, &seaudit_report->configPath));	
}

int seaudit_report_add_stylesheet_path(const char *file, seaudit_report_t *seaudit_report)
{
	return (seaudit_report_add_file_path(file, &seaudit_report->stylesheet_file));	
}

int seaudit_report_generate_report(seaudit_report_t *seaudit_report) {
	int rt;
	xmlTextReaderPtr reader;
	FILE *outfile = NULL;
	
	if (seaudit_report->configPath == NULL) {
		/* Search for the system default seaudit report config file to use */
		if (seaudit_report_search_dflt_config_file(seaudit_report) != 0) {
			return -1;
		}
	}
	
	if (seaudit_report->html && seaudit_report->stylesheet_file == NULL) {
		/* Try and import system default style sheet from /usr/share/setools directory. */
		if (seaudit_report_search_dflt_stylesheet(seaudit_report) < 0) {
			return -1;
		}
		seaudit_report->use_stylesheet = TRUE;
	} 
	
	/* Set/Open the output stream */	
	if (seaudit_report->outFile == NULL) {
		outfile = stdout;
	} else {
		if ((outfile = fopen(seaudit_report->outFile, "w+")) == NULL) {
			fprintf(stderr, "Write permission to save file (%s) was not permitted!", seaudit_report->outFile);
			return -1;
		}
	}

	/* Print report header */
	if (seaudit_report_print_header(seaudit_report, outfile) != 0) {
		fclose(outfile);
		return -1;
	}
	
	/* Parse the xml config file and output report */
	reader = xmlNewTextReaderFilename(seaudit_report->configPath);
	if (reader != NULL) {
		rt = xmlTextReaderRead(reader);
		while (rt == 1) {
			seaudit_report_process_xmlNode(seaudit_report, reader, outfile);
			rt = xmlTextReaderRead(reader);
		}
		xmlFreeTextReader(reader);
		if (rt != 0) {
			fprintf(stderr, "%s : failed to parse config file\n", seaudit_report->configPath);
		}
	} else {
		fprintf(stderr, "Unable to open config file (%s)\n", seaudit_report->configPath);
		fclose(outfile);
		return -1;
	}
	if (seaudit_report->malformed) {
		seaudit_report_print_malformed_msgs(seaudit_report, outfile);
	}
	seaudit_report_print_footer(seaudit_report, outfile);
	fclose(outfile);
	
	return 0;	
}

void seaudit_report_destroy(seaudit_report_t *seaudit_report) {
	int i;
	
	assert(seaudit_report != NULL);
	if (seaudit_report->configPath) 
		free(seaudit_report->configPath);
	if (seaudit_report->outFile) 
		free(seaudit_report->outFile);
	if (seaudit_report->stylesheet_file) 
		free(seaudit_report->stylesheet_file);	
	/* Free log file path strings */
	if (seaudit_report->logfiles) {
		for (i = 0; i < seaudit_report->num_logfiles; i++) {
			if (seaudit_report->logfiles[i]) {
				free(seaudit_report->logfiles[i]);
			}
		}
		free(seaudit_report->logfiles);
	}
	if (seaudit_report->log) 
		audit_log_destroy(seaudit_report->log);	
}

seaudit_report_t *seaudit_report_create() {
	seaudit_report_t *seaudit_report;
	
	seaudit_report = (seaudit_report_t*)malloc(sizeof(seaudit_report_t));
	if (!seaudit_report) {
		fprintf(stderr, "Out of memory");
		return NULL;
	}
	memset(seaudit_report, 0, sizeof(seaudit_report_t));
	
	return seaudit_report;
}
