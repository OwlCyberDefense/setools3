/**
 *  @file sediff_progress.h
 *  Header for showing progress dialogs.
 *
 *  @author Don Patterson don.patterson@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
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
#ifndef SEDIFF_PROGRESS_H
#define SEDIFF_PROGRESS_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "sediff_gui.h"
#include <apol/policy.h>
#include <poldiff/poldiff.h>

	typedef struct sediff_progress sediff_progress_t;

	void sediff_progress_show(sediff_app_t * app, const char *title);
	void sediff_progress_hide(sediff_app_t * app);
	void sediff_progress_message(sediff_app_t * app, const char *title, const char *message);
	void sediff_progress_destroy(sediff_app_t * app);

/* the rest of these are for multi-threaded progress dialog */
	int sediff_progress_wait(sediff_app_t * app);
	void sediff_progress_done(sediff_app_t * app);
	void sediff_progress_abort(sediff_app_t * app, const char *s);
	void sediff_progress_update(sediff_app_t * app, const char *message);
	void sediff_progress_poldiff_handle_func(void *arg, poldiff_t * diff, int level, const char *fmt, va_list va_args);
	void sediff_progress_apol_handle_func(void *varg, apol_policy_t * p, int level, const char *fmt, va_list argp);

#ifdef	__cplusplus
}
#endif

#endif
