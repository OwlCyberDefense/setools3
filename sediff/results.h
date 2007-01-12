/**
 *  @file
 *  Header for showing diff results.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
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
#ifndef RESULTS_H
#define RESULTS_H

#include "toplevel.h"

#include <poldiff/poldiff.h>

typedef struct results results_t;

/**
 * Allocate and return a results object.  This object is responsible
 * for showing the results of a poldiff run, and all sorting of
 * results.
 *
 * @param top Toplevel object to contain the results object.
 *
 * @return Results object, or NULL upon error.  The caller is
 * responsible for calling results_destroy() afterwards.
 */
results_t *results_create(toplevel_t * top);

/**
 * Destroy the results object.  This does nothing if the pointer is
 * set to NULL.
 *
 * @param r Reference to a results object.  Afterwards the pointer
 * will be set to NULL.
 */
void results_destroy(results_t ** r);

/**
 * Clear all text from the results object.  This should be done prior
 * to running a new diff.
 *
 * @param r Results object to clear.
 */
void results_clear(results_t * r);

/**
 * Update the results display to match the most recent poldiff run.
 *
 * @param r Results object to update.
 */
void results_update(results_t * r);

void results_select(results_t * r, uint32_t diffbit, poldiff_form_e form);

void results_sort_current(results_t * r, int field, int direction);

#endif
