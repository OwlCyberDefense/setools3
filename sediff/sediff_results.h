/**
 *  @file sediff_results.h
 *  Header for showing diff results.
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
#ifndef SEDIFF_RESULTS_H
#define SEDIFF_RESULTS_H

#include "sediff_gui.h"

typedef struct sediff_results sediff_results_t;

void sediff_results_create(sediff_app_t *app);
void sediff_results_clear(sediff_app_t *app);
void sediff_results_select(sediff_app_t *app, uint32_t diffbit, poldiff_form_e form);
void sediff_results_sort_current(sediff_app_t *app, int field, int direction);
void sediff_results_update_stats(sediff_app_t *app);

#endif
