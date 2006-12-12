/**
 *  @file report.h
 *
 *  This is the interface for processing SELinux audit logs and/or
 *  seaudit views to generate concise reports containing standard
 *  information as well as customized information using seaudit views.
 *  Reports are rendered in either HTML or plain text.  Future support
 *  will provide rendering into XML.  The HTML report can be formatted
 *  by providing an alternate stylesheet file or by configuring the
 *  default stylesheet.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2006 Tresys Technology, LLC
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

#ifndef SEAUDIT_REPORT_H
#define SEAUDIT_REPORT_H

#ifdef  __cplusplus
extern "C"
{
#endif

#include "model.h"

	typedef struct seaudit_report seaudit_report_t;

	typedef enum seaudit_report_format
	{
		SEAUDIT_REPORT_FORMAT_TEXT, SEAUDIT_REPORT_FORMAT_HTML
	} seaudit_report_format_e;

/**
 * Allocate and return a new seaudit_report_t for a particular model.
 * This will not actually write the report to disk; for that call
 * seaudit_report_write().
 *
 * @param model Model containing messages that will be written.
 * @param out_file File name for the report.  (The name will be
 * duplicated by this function.)  If this is set to NULL then write to
 * standard out.
 *
 * @return A newly allocated report, or NULL upon error.  The caller
 * must call seaudit_report_destroy() afterwards.
 */
	extern seaudit_report_t *seaudit_report_create(seaudit_model_t * model, const char *out_file);

/**
 * Destroy the referenced seaudit_report_t object.
 *
 * @param report Report to destroy.  The pointer will be set to NULL
 * afterwards.  (If pointer is already NULL then do nothing.)
 */
	extern void seaudit_report_destroy(seaudit_report_t ** report);

/**
 * Write the report with the messages currently stored in the report's
 * model.
 *
 * @param log Error handler.
 * @param report Report to write.
 *
 * @return 0 on successful write, < 0 on error.
 */
	extern int seaudit_report_write(seaudit_log_t * log, seaudit_report_t * report);

/**
 * Set the output format of the report.  The default format is plain
 * text.
 *
 * @param log Error handler.
 * @param report Report whose format to set.
 * @param format Output formate.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_report_set_format(seaudit_log_t * log, seaudit_report_t * report, seaudit_report_format_e format);

/**
 * Set the report to use a particular report configuration file.
 *
 * @param log Error handler.
 * @param report Report whose configuration to set.
 * @param file Name of the configuration report.  If NULL then use the
 * default installed file.  (The name will be duplicated by this
 * function.)
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_report_set_configuration(seaudit_log_t * log, seaudit_report_t * report, const char *file);

/**
 * Set the report to use a particular HTML stylesheet file.  Note that
 * this option is ignored if not generating an HTML report.
 *
 * @param log Error handler.
 * @param report Report whose stylesheet to set.
 * @param file Name of the stylesheet.  If NULL then use the default
 * installed file.  (The name will be duplicated by this function.)
 * @param use_stylesheet If non-zero, then use the stylesheet given by
 * the parameter 'file'.  Otherwise completely disable stylesheets.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_report_set_stylesheet(seaudit_log_t * log, seaudit_report_t * report, const char *file,
						 const int use_stylesheet);

/**
 * Set the report to print messages that did not parse cleanly (i.e.,
 * "malformed messages").
 *
 * @param log Error handler.
 * @param report Report whose malformed messagse to print.
 * @param do_malformed If non-zero then print malformed messages.
 * Otherwise do not print them.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int seaudit_report_set_malformed(seaudit_log_t * log, seaudit_report_t * report, const int do_malformed);

#ifdef  __cplusplus
}
#endif

#endif
