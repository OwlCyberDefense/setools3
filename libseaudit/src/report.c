/**
 *  @file
 *  Implementation of seaudit report generator.
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

#include "seaudit_internal.h"

#include <seaudit/report.h>

#include <apol/util.h>
#include <libxml/xmlreader.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CONFIG_FILE "seaudit-report.conf"
#define STYLESHEET_FILE "seaudit-report.css"
#define LINE_MAX 1024

struct seaudit_report
{
	/** output format for the report */
	seaudit_report_format_e format;
	/** path to configuration file, or NULL to use system configuration */
	char *config;
	/** path to HTML stylesheet, or NULL to use system stylesheet */
	char *stylesheet;
	/** if non-zero, then use a stylesheet when generating HTML reports */
	int use_stylesheet;
	/** if non-zero, then print malformed messages */
	int malformed;
	/** model from which messages will be obtained */
	seaudit_model_t *model;
};

static const char *seaudit_report_node_names[] = {
	"seaudit-report",
	"standard-section",
	"custom-section",
	"view",
	NULL
};

static const char *seaudit_standard_section_names[] = {
	"PolicyLoads",
	"EnforcementToggles",
	"PolicyBooleans",
	"Statistics",
	"AllowListing",
	"DenyListing",
	NULL
};

seaudit_report_t *seaudit_report_create(seaudit_model_t * model)
{
	seaudit_report_t *r = calloc(1, sizeof(*r));
	if (r == NULL) {
		return NULL;
	}
	r->model = model;
	return r;
}

void seaudit_report_destroy(seaudit_report_t ** report)
{
	if (report == NULL || *report == NULL) {
		return;
	}
	free((*report)->config);
	free((*report)->stylesheet);
	free(*report);
	*report = NULL;
}

int seaudit_report_set_format(seaudit_log_t * log, seaudit_report_t * report, seaudit_report_format_e format)
{
	if (report == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	report->format = format;
	return 0;
}

/**
 * Set the report's configuration file to the default system file.
 */
static int report_set_default_configuration(seaudit_log_t * log, seaudit_report_t * report)
{
	char *config_dir = apol_file_find(CONFIG_FILE);
	int error;

	if (config_dir == NULL) {
		error = errno;
		ERR(log, "%s", "Could not find default configuration file.");
		errno = error;
		return -1;
	}
	if (asprintf(&report->config, "%s/%s", config_dir, CONFIG_FILE) < 0) {
		error = errno;
		report->config = NULL;
		free(config_dir);
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	free(config_dir);

	/* check if can read the file */
	if (access(report->config, R_OK) != 0) {
		error = errno;
		ERR(log, "Could not read default config file %s.", report->config);
		errno = error;
		return -1;
	}
	return 0;
}

int seaudit_report_set_configuration(seaudit_log_t * log, seaudit_report_t * report, const char *file)
{
	if (report == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	free(report->config);
	report->config = NULL;
	if (file == NULL) {
		return report_set_default_configuration(log, report);
	} else {
		if ((report->config = strdup(file)) == NULL) {
			int error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
		return 0;
	}
}

/**
 * Set the report's stylesheet to the default system stylesheet.
 */
static int report_set_default_stylesheet(seaudit_log_t * log, seaudit_report_t * report)
{
	char *dir = apol_file_find(STYLESHEET_FILE);
	int error;
	if (dir == NULL) {
		error = errno;
		ERR(log, "%s", "Could not find default stylesheet.");
		errno = error;
		return -1;
	}

	if (asprintf(&report->stylesheet, "%s/%s", dir, STYLESHEET_FILE) < 0) {
		error = errno;
		report->stylesheet = NULL;
		free(dir);
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	free(dir);

	return 0;
}

int seaudit_report_set_stylesheet(seaudit_log_t * log, seaudit_report_t * report, const char *file, const int use_stylesheet)
{
	if (report == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	free(report->stylesheet);
	report->stylesheet = NULL;
	report->use_stylesheet = use_stylesheet;
	if (file == NULL) {
		return report_set_default_stylesheet(log, report);
	} else {
		if ((report->stylesheet = strdup(file)) == NULL) {
			return -1;
			int error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
		return 0;
	}
}

int seaudit_report_set_malformed(seaudit_log_t * log, seaudit_report_t * report, const int do_malformed)
{
	if (report == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	report->malformed = do_malformed;
	return 0;
}

/**
 * Insert the contents of the stylesheet into the output file.  If it
 * is not readable then generate a warning.  This is not an error
 * because the stylesheet is not strictly necessary.
 */
static int report_import_html_stylesheet(seaudit_log_t * log, seaudit_report_t * report, FILE * outfile)
{
	char line[LINE_MAX], *line_ptr = NULL;
	FILE *fp;

	if (report->use_stylesheet) {
		fp = fopen(report->stylesheet, "r");
		if (fp == NULL) {
			WARN(log, "Cannot open stylesheet file %s.", report->stylesheet);
			return 1;
		}
		fprintf(outfile, "<style type=\"text/css\">\n");

		while (fgets(line, LINE_MAX, fp) != NULL) {
			free(line_ptr);
			line_ptr = NULL;
			if ((line_ptr = strdup(line)) == NULL || apol_str_trim(&line_ptr) < 0) {
				int error = errno;
				free(line_ptr);
				fclose(fp);
				ERR(log, "%s", strerror(error));
				errno = error;
				return -1;
			}
			if (line_ptr[0] == '#' || apol_str_is_only_white_space(line_ptr))
				continue;
			fprintf(outfile, "%s\n", line_ptr);
		}
		fprintf(outfile, "</style>\n");
		fclose(fp);
		free(line_ptr);
	}
	return 0;
}

static int report_print_header(seaudit_log_t * log, seaudit_report_t * report, FILE * outfile)
{
	time_t ltime;

	time(&ltime);
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
		fprintf(outfile, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n");
		fprintf(outfile, "<html>\n<head>\n");
		if (report_import_html_stylesheet(log, report, outfile) < 0) {
			return -1;
		}
		fprintf(outfile, "<title>seaudit-report</title>\n</head>\n");
		fprintf(outfile, "<body>\n");
		fprintf(outfile, "<b class=\"report_date\"># Report generated by seaudit-report on %s</b><br>\n", ctime(&ltime));
	} else {
		fprintf(outfile, "# Begin\n\n");
		fprintf(outfile, "# Report generated by seaudit-report on %s\n", ctime(&ltime));
	}
	return 0;
}

static int report_print_footer(seaudit_report_t * report, FILE * outfile)
{
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
		fprintf(outfile, "</body>\n</html>\n");
	} else {
		fprintf(outfile, "# End\n");
	}
	return 0;
}

static int report_is_valid_node_name(const char *name)
{
	size_t i;
	for (i = 0; seaudit_report_node_names[i] != NULL; i++)
		if (strcmp(seaudit_report_node_names[i], name) == 0)
			return 1;
	return 0;
}

static int report_is_valid_section_name(const char *name)
{
	size_t i;
	for (i = 0; seaudit_standard_section_names[i] != NULL; i++)
		if (strcmp(seaudit_standard_section_names[i], name) == 0)
			return 1;
	return 0;
}

static int report_parse_seaudit_report(seaudit_log_t * log, seaudit_report_t * report,
				       xmlTextReaderPtr reader, xmlChar ** id_value, xmlChar ** title_value)
{
	int rt, error;
	xmlChar *name = NULL;

	if (xmlTextReaderNodeType(reader) == 1 && xmlTextReaderAttributeCount(reader) > 0) {
		/* Parse attributes */
		rt = xmlTextReaderMoveToNextAttribute(reader);
		while (rt > 0) {
			name = xmlTextReaderName(reader);
			if (name == NULL) {
				error = errno;
				ERR(log, "%s", "Attribute name unavailable.");
				errno = error;
				return -1;
			}
			if (strcmp((char *)name, "title") == 0) {
				*title_value = xmlTextReaderValue(reader);
			}

			xmlFree(name);
			rt = xmlTextReaderMoveToNextAttribute(reader);
		}
		if (rt < 0) {
			error = errno;
			ERR(log, "%s", "Error parsing attribute for seaudit-report node.");
			errno = error;
			return -1;
		}
	}
	return 0;
}

static int report_parse_standard_attribs(seaudit_log_t * log, seaudit_report_t * report,
					 xmlTextReaderPtr reader, xmlChar ** id_value, xmlChar ** title_value)
{
	int rt, error;
	xmlChar *name = NULL;

	if (xmlTextReaderNodeType(reader) == 1 && xmlTextReaderAttributeCount(reader) > 0) {
		/* Parse attributes */
		rt = xmlTextReaderMoveToNextAttribute(reader);
		while (rt > 0) {
			name = xmlTextReaderName(reader);
			if (name == NULL) {
				error = errno;
				ERR(log, "%s", "Attribute name unavailable.");
				errno = error;
				return -1;
			}
			if (strcmp((char *)name, "id") == 0) {
				*id_value = xmlTextReaderValue(reader);
			} else if (strcmp((char *)name, "title") == 0) {
				*title_value = xmlTextReaderValue(reader);
			}
			xmlFree(name);
			rt = xmlTextReaderMoveToNextAttribute(reader);
		}
		if (rt < 0) {
			error = errno;
			ERR(log, "%s", "Error parsing attribute for standard-section node.");
			errno = error;
			return -1;
		}
	}
	return 0;
}

static int report_parse_custom_attribs(seaudit_log_t * log, seaudit_report_t * report,
				       xmlTextReaderPtr reader, xmlChar ** title_value)
{
	int rt, error;
	xmlChar *name = NULL;

	if (xmlTextReaderNodeType(reader) == 1 && xmlTextReaderAttributeCount(reader) > 0) {
		/* Parse attributes */
		rt = xmlTextReaderMoveToNextAttribute(reader);
		while (rt > 0) {
			name = xmlTextReaderName(reader);
			if (name == NULL) {
				error = errno;
				ERR(log, "%s", "Attribute name unavailable.");
				errno = error;
				return -1;
			}
			if (strcmp((char *)name, "title") == 0) {
				*title_value = xmlTextReaderValue(reader);
			}

			xmlFree(name);
			rt = xmlTextReaderMoveToNextAttribute(reader);
		}
		if (rt < 0) {
			error = errno;
			ERR(log, "%s", "Error parsing attribute for custom-section node.");
			errno = error;
			return -1;
		}
	}
	return 0;
}

/**
 * Allocate and return a filter for setenforce toggles.  (Actually, it
 * can't filter on permissions.)
 */
static seaudit_filter_t *report_enforce_toggle_filter_create(seaudit_log_t * log, seaudit_report_t * report)
{
	seaudit_filter_t *filter = NULL;
	apol_vector_t *type_v = NULL, *class_v;
	int retval = -1, error;
	char *tgt_type = "security_t";
	char *obj_class = "security";

	if ((filter = seaudit_filter_create(NULL)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	if ((type_v = apol_vector_create_with_capacity(1)) == NULL ||
	    apol_vector_append(type_v, tgt_type) < 0 || seaudit_filter_set_target_type(filter, type_v) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	if ((class_v = apol_vector_create_with_capacity(1)) == NULL ||
	    apol_vector_append(class_v, obj_class) < 0 || seaudit_filter_set_target_class(filter, class_v) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&type_v, NULL);
	apol_vector_destroy(&class_v, NULL);
	if (retval != 0) {
		seaudit_filter_destroy(&filter);
		errno = error;
		return NULL;
	}
	return filter;
}

static int report_print_enforce_toggles(seaudit_log_t * log, seaudit_report_t * report, FILE * outfile)
{
	seaudit_filter_t *filter = NULL;
	seaudit_model_t *dup_model = NULL;
	size_t i, j, num_setenforce = 0;
	apol_vector_t *v = NULL;
	seaudit_message_t *msg;
	seaudit_avc_message_t *avc;
	seaudit_message_type_e type;
	char *s;
	char *perm = "setenforce";
	int retval = -1, error = 0;

	if ((filter = report_enforce_toggle_filter_create(log, report)) == NULL) {
		error = errno;
		goto cleanup;
	}
	if ((dup_model = seaudit_model_create_from_model(report->model)) == NULL ||
	    seaudit_model_append_filter(dup_model, filter) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	filter = NULL;
	/* Loop through and get the number of avc allow messages with
	 * the setenforce permission. */
	v = seaudit_model_get_messages(log, dup_model);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		msg = apol_vector_get_element(v, i);
		avc = seaudit_message_get_data(msg, &type);
		if (type != SEAUDIT_MESSAGE_TYPE_AVC || avc->msg == SEAUDIT_AVC_DENIED)
			continue;
		if (apol_vector_get_index(avc->perms, perm, apol_str_strcmp, NULL, &j) == 0) {
			/* Increment number of setenforce messages */
			num_setenforce++;
		}
	}

	/* Since we cannot filter by setenforce permission within the
	 * view, we do so manually within the following for loop. */
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML)
		fprintf(outfile,
			"<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%zd</b><br>\n<br>\n",
			num_setenforce);
	else
		fprintf(outfile, "Number of messages: %zd\n\n", num_setenforce);

	for (i = 0; i < apol_vector_get_size(v); i++) {
		msg = apol_vector_get_element(v, i);
		avc = seaudit_message_get_data(msg, &type);
		if (type != SEAUDIT_MESSAGE_TYPE_AVC ||
		    avc->msg == SEAUDIT_AVC_DENIED || apol_vector_get_index(avc->perms, perm, apol_str_strcmp, NULL, &j) < 0) {
			continue;
		}
		if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
			s = seaudit_message_to_string_html(msg);
		} else {
			s = seaudit_message_to_string(msg);
		}
		if (s == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
		fputs(s, outfile);
		fputc('\n', outfile);
		free(s);
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v, NULL);
	seaudit_filter_destroy(&filter);
	seaudit_model_destroy(&dup_model);
	if (error != 0) {
		errno = error;
	}
	return retval;
}

static int report_print_policy_booleans(seaudit_log_t * log, seaudit_report_t * report, FILE * outfile)
{
	size_t i, num = seaudit_model_get_num_bools(log, report->model);
	apol_vector_t *v = seaudit_model_get_messages(log, report->model);
	seaudit_message_t *m;
	seaudit_message_type_e type;
	char *s;
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML)
		fprintf(outfile,
			"<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%zd</b><br>\n<br>\n",
			num);
	else
		fprintf(outfile, "Number of messages: %zd\n\n", num);

	for (i = 0; i < apol_vector_get_size(v); i++) {
		m = apol_vector_get_element(v, i);
		seaudit_message_get_data(m, &type);
		if (type == SEAUDIT_MESSAGE_TYPE_BOOL) {
			if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
				s = seaudit_message_to_string_html(m);
			} else {
				s = seaudit_message_to_string(m);
			}
			if (s == NULL) {
				int error = errno;
				apol_vector_destroy(&v, NULL);
				ERR(log, "%s", strerror(error));
				errno = error;
				return -1;
			}
			fputs(s, outfile);
			fputc('\n', outfile);
			free(s);
		}
	}
	apol_vector_destroy(&v, NULL);
	return 0;
}

static int report_print_policy_loads(seaudit_log_t * log, seaudit_report_t * report, FILE * outfile)
{
	size_t i, num = seaudit_model_get_num_loads(log, report->model);
	apol_vector_t *v = seaudit_model_get_messages(log, report->model);
	seaudit_message_t *m;
	seaudit_message_type_e type;
	char *s;
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML)
		fprintf(outfile,
			"<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%zd</b><br>\n<br>\n",
			num);
	else
		fprintf(outfile, "Number of messages: %zd\n\n", num);

	for (i = 0; i < apol_vector_get_size(v); i++) {
		m = apol_vector_get_element(v, i);
		seaudit_message_get_data(m, &type);
		if (type == SEAUDIT_MESSAGE_TYPE_LOAD) {
			if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
				s = seaudit_message_to_string_html(m);
			} else {
				s = seaudit_message_to_string(m);
			}
			if (s == NULL) {
				int error = errno;
				apol_vector_destroy(&v, NULL);
				ERR(log, "%s", strerror(error));
				errno = error;
				return -1;
			}
			fputs(s, outfile);
			fputc('\n', outfile);
			free(s);
		}
	}
	apol_vector_destroy(&v, NULL);
	return 0;
}

static int report_print_avc_listing(seaudit_log_t * log, seaudit_report_t * report, seaudit_avc_message_type_e avc_type,
				    FILE * outfile)
{
	size_t i, num;
	apol_vector_t *v = seaudit_model_get_messages(log, report->model);
	seaudit_message_t *m;
	seaudit_avc_message_t *avc;
	seaudit_message_type_e type;
	char *s;
	if (avc_type == SEAUDIT_AVC_GRANTED) {
		num = seaudit_model_get_num_allows(log, report->model);
	} else {
		num = seaudit_model_get_num_denies(log, report->model);
	}
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML)
		fprintf(outfile,
			"<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%zd</b><br>\n<br>\n",
			num);
	else
		fprintf(outfile, "Number of messages: %zd\n\n", num);

	for (i = 0; i < apol_vector_get_size(v); i++) {
		m = apol_vector_get_element(v, i);
		avc = seaudit_message_get_data(m, &type);
		if (type == SEAUDIT_MESSAGE_TYPE_AVC && avc->msg == avc_type) {
			if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
				s = seaudit_message_to_string_html(m);
			} else {
				s = seaudit_message_to_string(m);
			}
			if (s == NULL) {
				int error = errno;
				apol_vector_destroy(&v, NULL);
				ERR(log, "%s", strerror(error));
				errno = error;
				return -1;
			}
			fputs(s, outfile);
			fputc('\n', outfile);
			free(s);
		}
	}
	apol_vector_destroy(&v, NULL);
	return 0;
}

static int report_print_stats(seaudit_log_t * log, seaudit_report_t * report, FILE * outfile)
{
	apol_vector_t *v = seaudit_model_get_messages(log, report->model);
	size_t num_messages = apol_vector_get_size(v);
	apol_vector_destroy(&v, NULL);
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
		fprintf(outfile,
			"<font class=\"stats_label\">Number of total messages:</font> <b class=\"stats_count\">%zd</b><br>\n",
			num_messages);
		fprintf(outfile,
			"<font class=\"stats_label\">Number of policy load messages:</font> <b class=\"stats_count\">%zd</b><br>\n",
			seaudit_model_get_num_loads(log, report->model));
		fprintf(outfile,
			"<font class=\"stats_label\">Number of policy boolean messages:</font> <b class=\"stats_count\">%zd</b><br>\n",
			seaudit_model_get_num_bools(log, report->model));
		fprintf(outfile,
			"<font class=\"stats_label\">Number of allow messages:</font> <b class=\"stats_count\">%zd</b><br>\n",
			seaudit_model_get_num_allows(log, report->model));
		fprintf(outfile,
			"<font class=\"stats_label\">Number of denied messages:</font> <b class=\"stats_count\">%zd</b><br>\n",
			seaudit_model_get_num_denies(log, report->model));
	} else {
		fprintf(outfile, "Number of total messages: %zd\n", num_messages);
		fprintf(outfile, "Number of policy load messages: %zd\n", seaudit_model_get_num_loads(log, report->model));
		fprintf(outfile, "Number of policy boolean messages: %zd\n", seaudit_model_get_num_bools(log, report->model));
		fprintf(outfile, "Number of allow messages: %zd\n", seaudit_model_get_num_allows(log, report->model));
		fprintf(outfile, "Number of denied messages: %zd\n", seaudit_model_get_num_denies(log, report->model));
	}
	return 0;
}

static int report_print_standard_section(seaudit_log_t * log, seaudit_report_t * report,
					 xmlChar * id, xmlChar * title, FILE * outfile)
{
	size_t sz, len, i;
	int rt = 0;

	if (!report_is_valid_section_name((char *)id)) {
		ERR(log, "%s", "Invalid standard section ID.");
		errno = EINVAL;
		return -1;
	}
	sz = strlen((char *)id);
	if (title != NULL) {
		if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
			fprintf(outfile, "<h2 class=\"standard_section_title\"><u>%s</h2></u>\n", title);
		} else {
			fprintf(outfile, "%s\n", title);
			len = strlen((char *)title);
			for (i = 0; i < len; i++) {
				fprintf(outfile, "-");
			}
			fprintf(outfile, "\n");
		}
	}
	if (strncasecmp((char *)id, "PolicyLoads", sz) == 0) {
		rt = report_print_policy_loads(log, report, outfile);
	} else if (strncasecmp((char *)id, "EnforcementToggles", sz) == 0) {
		rt = report_print_enforce_toggles(log, report, outfile);
	} else if (strncasecmp((char *)id, "PolicyBooleans", sz) == 0) {
		rt = report_print_policy_booleans(log, report, outfile);
	} else if (strncasecmp((char *)id, "AllowListing", sz) == 0) {
		rt = report_print_avc_listing(log, report, SEAUDIT_AVC_GRANTED, outfile);
	} else if (strncasecmp((char *)id, "DenyListing", sz) == 0) {
		rt = report_print_avc_listing(log, report, SEAUDIT_AVC_DENIED, outfile);
	} else if (strncasecmp((char *)id, "Statistics", sz) == 0) {
		rt = report_print_stats(log, report, outfile);
	}
	if (rt < 0) {
		return rt;
	}

	if (report->format == SEAUDIT_REPORT_FORMAT_HTML)
		fprintf(outfile, "<br>\n");
	else
		fprintf(outfile, "\n");

	return 0;
}

static int report_print_loaded_view(seaudit_log_t * log, seaudit_report_t * report, xmlChar * view_filePath, FILE * outfile)
{
	size_t i, filters_added = 0;
	apol_vector_t *loaded_filters = NULL;
	seaudit_model_t *dup_model = NULL;
	seaudit_filter_t *filter;
	seaudit_message_t *msg;
	char *s;
	apol_vector_t *v = NULL;
	int retval = -1, error = 0;

	if ((loaded_filters = seaudit_filter_create_from_file((char *)view_filePath)) == NULL) {
		error = errno;
		ERR(log, "Error parsing file %s.", view_filePath);
		goto cleanup;
	}
	if ((dup_model = seaudit_model_create_from_model(report->model)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(loaded_filters); i++, filters_added++) {
		filter = apol_vector_get_element(loaded_filters, i);
		if (seaudit_model_append_filter(dup_model, filter) < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
	}
	if ((v = seaudit_model_get_messages(log, dup_model)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
		fprintf(outfile, "View file: %s<br>\n", view_filePath);
		fprintf(outfile,
			"<font class=\"message_count_label\">Number of messages:</font> <b class=\"message_count\">%zd</b><br>\n<br>\n",
			apol_vector_get_size(v));
	} else {
		fprintf(outfile, "View file: %s\n", view_filePath);
		fprintf(outfile, "Number of messages: %zd\n\n", apol_vector_get_size(v));
	}

	for (i = 0; i < apol_vector_get_size(v); i++) {
		msg = apol_vector_get_element(v, i);
		if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
			s = seaudit_message_to_string_html(msg);
		} else {
			s = seaudit_message_to_string(msg);
		}
		if (s == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
		fputs(s, outfile);
		fputc('\n', outfile);
		free(s);
	}
	retval = 0;
      cleanup:
	/* only destroy filters that were not added to the model
	 * (recall that model takes ownership of filters) */
	if (loaded_filters != NULL) {
		for (i = filters_added; i < apol_vector_get_size(loaded_filters); i++) {
			filter = apol_vector_get_element(loaded_filters, i);
			seaudit_filter_destroy(&filter);
		}
		apol_vector_destroy(&loaded_filters, NULL);
	}
	seaudit_model_destroy(&dup_model);
	apol_vector_destroy(&v, NULL);
	if (error != 0) {
		errno = error;
	}
	return retval;
}

static int report_print_custom_section(seaudit_log_t * log, seaudit_report_t * report,
				       xmlTextReaderPtr reader, xmlChar * title, FILE * outfile)
{
	size_t len, i;
	int rt, error = 0, retval = -1, end_of_element = 0;
	xmlChar *view_filePath = NULL, *name = NULL;

	if (title != NULL) {
		if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
			fprintf(outfile, "<h2 class=\"custom_section_title\"><u>%s</h2></u>\n", title);
		} else {
			fprintf(outfile, "%s\n", title);
			len = strlen((char *)title);
			for (i = 0; i < len; i++) {
				fprintf(outfile, "-");
			}
			fprintf(outfile, "\n");
		}
	}

	/* Moves the position of the current instance to the next node
	 * in the stream, which should be a view node */
	rt = xmlTextReaderRead(reader);
	while (rt == 1) {
		/* Read inner child view node(s) */
		name = xmlTextReaderName(reader);
		if (name == NULL) {
			error = errno;
			ERR(log, "%s", "Unavailable node name within.");
			goto cleanup;
		}
		/* We have reached the end-of-element for the
		 * custom-section node (indicated by 15) */
		if (strcmp((char *)name, "custom-section") == 0 && xmlTextReaderNodeType(reader) == 15) {
			xmlFree(name);
			end_of_element = 1;
			break;
		}
		if (strcmp((char *)name, "view") == 0 && xmlTextReaderNodeType(reader) == 1 && xmlTextReaderHasAttributes(reader)) {
			view_filePath = xmlTextReaderGetAttribute(reader, (const xmlChar *)"file");
			if (view_filePath == NULL) {
				error = errno;
				ERR(log, "%s", "Error getting file attribute for view node.");
				goto cleanup;
			}
			if (report_print_loaded_view(log, report, view_filePath, outfile) < 0) {
				error = errno;
				goto cleanup;
			}
			xmlFree(view_filePath);
		}
		xmlFree(name);
		rt = xmlTextReaderRead(reader);
	}
	if (!end_of_element && rt != 0) {
		error = EIO;
		ERR(log, "Error parsing config file %s. (rt:%d)", report->config, rt);
		goto cleanup;
	}

	if (!end_of_element) {
		error = EIO;
		ERR(log, "%s", "Encountered end of file before finding end of element for custom-section node.");
		goto cleanup;;
	}
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML)
		fprintf(outfile, "<br>\n");
	else
		fprintf(outfile, "\n");

	return 0;
      cleanup:
	if (view_filePath)
		xmlFree(view_filePath);
	if (name)
		xmlFree(name);
	if (error != 0) {
		errno = error;
	}
	return retval;
}

static int report_process_xmlNode(seaudit_log_t * log, seaudit_report_t * report, xmlTextReaderPtr reader, FILE * outfile)
{
	xmlChar *name = NULL, *id_attr = NULL, *title_attr = NULL;
	int retval = -1, error;

	if ((name = xmlTextReaderName(reader)) == NULL) {
		error = errno;
		ERR(log, "%s", "Unavailable node name.");
		goto cleanup;
	}

	if (!report_is_valid_node_name((char *)name)) {
		retval = 0;
		goto cleanup;
	}

	if (strcmp((char *)name, "seaudit-report") == 0 && xmlTextReaderNodeType(reader) == 1) {
		if (report_parse_seaudit_report(log, report, reader, &id_attr, &title_attr) < 0) {
			error = errno;
			goto cleanup;
		}
		if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
			fprintf(outfile, "<h1 class=\"report_title\">Title: %s</h1>\n", title_attr);
		} else {
			fprintf(outfile, "Title: %s\n", title_attr);
		}
	} else if (strcmp((char *)name, "standard-section") == 0 && xmlTextReaderNodeType(reader) == 1) {
		if (report_parse_standard_attribs(log, report, reader, &id_attr, &title_attr) < 0) {
			error = errno;
			goto cleanup;
		}
		if (id_attr == NULL) {
			ERR(log, "%s", "Missing required id attribute for standard section node.");
			error = EIO;
			goto cleanup;
		}
		/* NOTE: If a title wasn't provided, we still continue. */
		if (report_print_standard_section(log, report, id_attr, title_attr, outfile) < 0) {
			error = errno;
			goto cleanup;
		}
	} else if (strcmp((char *)name, "custom-section") == 0 && xmlTextReaderNodeType(reader) == 1) {
		if (report_parse_custom_attribs(log, report, reader, &title_attr) < 0) {
			error = errno;
			goto cleanup;
		}
		/* NOTE: If a title wasn't provided, we still continue. */
		if (report_print_custom_section(log, report, reader, title_attr, outfile) < 0) {
			error = errno;
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	xmlFree(name);
	xmlFree(id_attr);
	xmlFree(title_attr);
	if (retval < 0) {
		errno = error;
	}
	return retval;
}

static int report_print_malformed(seaudit_log_t * log, seaudit_report_t * report, FILE * outfile)
{
	size_t i, len;
	apol_vector_t *v = seaudit_model_get_malformed_messages(log, report->model);
	if (v == NULL) {
		return -1;
	}
	if (report->format == SEAUDIT_REPORT_FORMAT_HTML) {
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
	for (i = 0; i < apol_vector_get_size(v); i++) {
		char *malformed_msg;
		malformed_msg = apol_vector_get_element(v, i);
		if (report->format == SEAUDIT_REPORT_FORMAT_HTML)
			fprintf(outfile, "%s<br>\n", malformed_msg);
		else
			fprintf(outfile, "%s\n", malformed_msg);
	}
	fprintf(outfile, "\n");
	apol_vector_destroy(&v, NULL);
	return 0;
}

int seaudit_report_write(seaudit_log_t * log, seaudit_report_t * report, const char *out_file)
{
	xmlTextReaderPtr reader;
	FILE *outfile = NULL;
	int rt, retval = -1, error = 0;

	/* Set/Open the output stream */
	if (out_file == NULL) {
		outfile = stdout;
	} else {
		if ((outfile = fopen(out_file, "w+")) == NULL) {
			error = errno;
			ERR(log, "Could not open %s for writing.", out_file);
			goto cleanup;
		}
	}

	/* Print report header */
	if (report_print_header(log, report, outfile) < 0) {
		error = errno;
		goto cleanup;
	}

	/* Parse the xml config file and output report */
	reader = xmlNewTextReaderFilename(report->config);
	if (reader == NULL) {
		error = errno;
		ERR(log, "Unable to open config file (%s).", report->config);
		goto cleanup;
	}
	rt = xmlTextReaderRead(reader);
	while (rt == 1) {
		report_process_xmlNode(log, report, reader, outfile);
		rt = xmlTextReaderRead(reader);
	}
	error = errno;
	xmlFreeTextReader(reader);
	if (rt != 0) {
		ERR(log, "Failed to parse config file %s.", report->config);
		goto cleanup;
	}
	if (report->malformed && report_print_malformed(log, report, outfile) < 0) {
		error = errno;
		goto cleanup;
	}
	report_print_footer(report, outfile);

	retval = 0;
      cleanup:
	if (outfile != NULL) {
		fclose(outfile);
	}
	if (retval < 0) {
		errno = error;
	}
	return retval;
}
