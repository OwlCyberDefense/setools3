/**
 *  @file sediff_policy_open.h
 *  Header for opening policies.
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
#ifndef SEDIFF_POLICY_OPEN_H
#define SEDIFF_POLICY_OPEN_H

#ifdef	__cplusplus
extern "C" {
#endif

void sediff_policy_stats_textview_populate(apol_policy_t * p, GtkTextView * textview, const char *filename);
int sediff_policy_file_textview_populate(sediff_file_data_t * sfd, GtkTextView * textview, apol_policy_t * policy);
void sediff_set_open_policies_gui_state(gboolean open);
void sediff_open_button_clicked(void);
int sediff_load_policies(const char *p1_file, const char *p2_file);

#ifdef	__cplusplus
}
#endif

#endif
